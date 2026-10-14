"""The auditor's read of the audit trail and receipts: scoped, cursor-paged, hash-chained.

One read serves a person and a SIEM alike (exit criterion 4(d)): each page
carries a cursor, and polling with it returns what was written since, in
order, without a gap and without a repeat.

**Commit order, not id order.** Rows are paged on ``(xact_id, id)``, and only
rows written by transactions older than every transaction still running are
served. Below that horizon nothing can be inserted any more, so a cursor never
passes a row that has yet to commit. Paged on ``id`` alone, a transaction that
drew a lower id and committed late would sort below a cursor already issued,
and that event would never reach the SIEM (CLAUDE.md section 5, keyset).
Residual: a transaction left open holds the horizon back, so the stream stalls
rather than skips; the lag is visible to the caller as an unchanged cursor.

**Scope.** The ISAC's auditor reads the instance. A member's auditor reads the
rows recorded against its own organisation, and of their ``details`` only the
keys that describe its own action: a detail naming another firm's circle or
certificate is withheld whole, so the existence of what it names is not
confirmed (the 404 property, applied to a field).

**Hash chain.** Each served event carries ``hash = sha256(prev || event)``,
starting from a genesis value that names the scope, and the cursor carries the
last hash. A sequence of pages is therefore one chain: an auditor can recompute
it, and a row edited, dropped or reordered between two exports breaks it. The
chain is over events as served -- redacted -- so a member's auditor can verify
exactly what it was given.

**Not its own reading.** Each page served is recorded (``audit.read``), and
the stream leaves those rows out. Served, they would hand every reader its
previous read on the next poll, so a SIEM draining the stream to empty would
never get there; the suite spun on exactly that. The rows stay in the log, for
the ISAC's review and the ``auditor_bulk_read`` rule.

Never content: neither table holds any, and a receipt's free-text ``note`` is
left out.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import (
    BigInteger,
    ColumnElement,
    Text,
    and_,
    cast,
    func,
    literal,
    select,
    tuple_,
)
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.audit.log import AuditAction
from aivs_server.db.models import Acknowledgment, AuditLog

__all__ = [
    "MAX_PAGE",
    "Cursor",
    "CursorError",
    "Page",
    "audit_events",
    "decode_cursor",
    "receipt_events",
]

MAX_PAGE: Final[int] = 1000

#: The ``details`` keys a member's auditor is shown: each describes the
#: member's own action in its own terms. Anything else may name what the
#: member cannot see, and is withheld.
_OWN_SCOPE_DETAIL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "ack_type",
        "count",
        "kind",
        "lane",
        "outcome",
        "reason",
        "roles",
        "sha256",
        "status",
        "stream",
        "verb",
    }
)
_HEX64: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
#: The shape of each stream's row key. A cursor from one stream is refused by
#: the other exactly as a malformed one is.
_ROW_KEYS: Final[Mapping[str, re.Pattern[str]]] = {
    "audit": re.compile(r"^[0-9]{1,19}$"),
    "receipts": re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
}
_NIL_UUID: Final[str] = "00000000-0000-0000-0000-000000000000"


class CursorError(ValueError):
    """A cursor this server did not issue, or one for another stream."""


@dataclass(frozen=True)
class Cursor:
    """Where a stream continues: the last row served, and the chain's last hash."""

    xact_id: int
    #: The last row's primary key as text: an integer for the audit log, a
    #: UUID for receipts. Within one transaction either orders stably, since
    #: all of a transaction's rows become visible together.
    row_key: str
    chain: str

    def encode(self) -> str:
        raw = f"{self.xact_id}.{self.row_key}.{self.chain}".encode("ascii")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class Page:
    events: Sequence[Mapping[str, Any]]
    cursor: Cursor


def decode_cursor(text: str, stream: str) -> Cursor:
    """Parse a cursor; any malformed one is the same refusal."""
    try:
        padded = text + "=" * (-len(text) % 4)
        xact_id, row_key, chain = (
            base64.urlsafe_b64decode(padded.encode("ascii")).decode("ascii").split(".")
        )
        cursor = Cursor(int(xact_id), row_key, chain)
    except (ValueError, binascii.Error, UnicodeError):
        raise CursorError(text) from None
    if (
        cursor.xact_id < -1
        or _ROW_KEYS[stream].match(row_key) is None
        or _HEX64.match(chain) is None
    ):
        raise CursorError(text)
    return cursor


def genesis(stream: str, scope: uuid.UUID | None) -> Cursor:
    """The cursor before the first event: the chain begins at a hash of the scope."""
    label = f"aivs-{stream}-chain/v1|{scope or 'instance'}"
    first_key = "0" if stream == "audit" else _NIL_UUID
    return Cursor(-1, first_key, hashlib.sha256(label.encode("utf-8")).hexdigest())


# ---------------------------------------------------------------------------
# The two streams
# ---------------------------------------------------------------------------
async def audit_events(
    session: AsyncSession, *, scope: uuid.UUID | None, after: Cursor | None, limit: int
) -> Page:
    """Audit rows in commit order, scoped and redacted."""
    not_a_read = AuditLog.action != AuditAction.AUDIT_READ
    in_scope = not_a_read if scope is None else and_(not_a_read, AuditLog.org_id == scope)
    start = after or genesis("audit", scope)
    rows = await _rows(session, AuditLog, in_scope, start, int(start.row_key), limit)
    return _chained(rows, start, _audit_event(scope))


async def receipt_events(
    session: AsyncSession, *, scope: uuid.UUID | None, after: Cursor | None, limit: int
) -> Page:
    """Receipts in commit order: the instance's, or one organisation's own."""
    in_scope = Acknowledgment.org_id == scope if scope is not None else None
    start = after or genesis("receipts", scope)
    rows = await _rows(session, Acknowledgment, in_scope, start, uuid.UUID(start.row_key), limit)
    return _chained(rows, start, _receipt_event)


# ---------------------------------------------------------------------------
# Mechanics
# ---------------------------------------------------------------------------
async def _rows(
    session: AsyncSession,
    model: type[AuditLog] | type[Acknowledgment],
    in_scope: ColumnElement[bool] | None,
    after: Cursor,
    after_key: int | uuid.UUID,
    limit: int,
) -> list[Any]:
    """The next rows past ``after``, below the horizon, in ``(xact_id, id)`` order."""
    horizon = cast(cast(func.pg_snapshot_xmin(func.pg_current_snapshot()), Text), BigInteger)
    query = (
        select(model)
        .where(
            model.xact_id < horizon,
            tuple_(model.xact_id, model.id)
            > tuple_(literal(after.xact_id), literal(after_key, type_=model.id.type)),
        )
        .order_by(model.xact_id, model.id)
        .limit(min(limit, MAX_PAGE))
    )
    if in_scope is not None:
        query = query.where(in_scope)
    return list((await session.execute(query)).scalars())


def _chained(rows: Sequence[Any], start: Cursor, render: Callable[[Any], dict[str, Any]]) -> Page:
    chain = start.chain
    events = []
    for row in rows:
        event = render(row)
        chain = _link(chain, event)
        events.append({**event, "hash": chain})
    if not rows:
        return Page(events=[], cursor=start)
    last = rows[-1]
    return Page(events=events, cursor=Cursor(last.xact_id, str(last.id), chain))


def _link(previous: str, event: Mapping[str, Any]) -> str:
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(f"{previous}\n{canonical}".encode("ascii")).hexdigest()


def _audit_event(scope: uuid.UUID | None) -> Callable[[AuditLog], dict[str, Any]]:
    def render(row: AuditLog) -> dict[str, Any]:
        details = row.details or {}
        if scope is not None:
            details = {k: v for k, v in details.items() if k in _OWN_SCOPE_DETAIL_KEYS}
        return {
            "id": row.id,
            "at": _stamp(row.at),
            "action": row.action,
            "outcome": row.outcome,
            "actor_type": row.actor_type,
            "actor_id": row.actor_id,
            "org_id": _text(row.org_id),
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "request_id": row.request_id,
            "source_ip": _text(row.source_ip),
            "details": details,
        }

    return render


def _receipt_event(row: Acknowledgment) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "at": _stamp(row.created_at),
        "org_id": str(row.org_id),
        "submission_id": str(row.submission_id),
        "ack_type": str(row.ack_type),
        "via": str(row.via),
        "actor_ref": row.actor_ref,
    }


def _stamp(value: dt.datetime) -> str:
    return value.astimezone(dt.UTC).isoformat()


def _text(value: object) -> str | None:
    return None if value is None else str(value)
