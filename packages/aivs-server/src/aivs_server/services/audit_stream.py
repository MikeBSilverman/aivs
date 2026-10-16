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

**Scope.** A member's auditor reads the rows recorded against its own
organisation, and of their ``details`` only the keys that describe its own
action: a detail naming another firm's circle or certificate is withheld
whole, so the existence of what it names is not confirmed (the 404 property,
applied to a field).

The ISAC's auditor reads the instance, but it is not intel staff, and who filed
what is intel staff's alone (Q37, SF-94). So every action is classified
(``_PROJECTIONS``). A ``CONTENT`` row -- about a submission or a contribution --
is served with ``details`` cut to keys that cannot name the filer, and with its
organisation, actor, request id and source address as null, unless its
organisation is the ISAC's own: checking which editor validated or distributed
is what an auditor is for, and that names the ISAC, never a filer. A null
therefore says "a member did this", and nothing about which. A member's row
written in the same transaction as a content row is served the same way, since
every row of one transaction shares its ``at`` and its request id. A finding
that names a filer reaches the auditor without it (``detections.ATTRIBUTION_RULES``).

**Hash chain.** Each served event carries ``hash = sha256(prev || event)``,
starting from a genesis value that names the scope, and the cursor carries the
last hash. A sequence of pages is therefore one chain: an auditor can recompute
it, and a row edited, dropped or reordered between two exports breaks it. The
chain is over events as served -- redacted -- so an auditor can verify exactly
what it was given. The genesis label is ``chain/v2`` since the instance
auditor's projection (slice 3d): an export from genesis made before it chains
v1, and differs from a fresh one on every content row by design, not by
tampering. A cursor issued before it continues its chain.

**Its own reading, by mode.** Each page served is recorded. Served
unconditionally, those rows would hand every reader its previous read on the
next poll, and a SIEM draining the stream to empty would never get there; the
suite spun on exactly that. So a page that served only reads, or nothing, is
recorded as ``audit.read.quiet`` and never served; any other page is
``audit.read``, served when the mode in force at its transaction is ``full``
and summarised instead when it is ``condensed``
(``services.audit_stream_mode``, ``services.audit_read_summary``). Every kind
stays in the log for the ``auditor_bulk_read`` rule.

Never content: a submission's title, which its creation row records, is in no
scope's keys, and a receipt's free-text ``note`` is left out.
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
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from sqlalchemy import (
    BigInteger,
    ColumnElement,
    Text,
    and_,
    cast,
    exists,
    func,
    literal,
    or_,
    select,
    tuple_,
)
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from aivs_server.audit.log import AuditAction
from aivs_server.auth.policy import ISAC_FILER_TYPES
from aivs_server.db.models import Acknowledgment, AuditLog, Organization
from aivs_server.services.audit_stream_mode import AuditStreamMode, mode_in_force_at
from aivs_server.services.detections import ATTRIBUTION_RULES, RULE_NAMES

__all__ = [
    "MAX_PAGE",
    "Cursor",
    "CursorError",
    "Page",
    "Projection",
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
        "events",
        "first_at",
        "last_at",
        "outcome",
        "pages",
        "quiet_pages",
        "reason",
        "roles",
        "sha256",
        "status",
        "stream",
        "streams",
        "verb",
    }
)
#: What the ISAC's auditor is shown of an attribution finding, or of a finding
#: from a rule this module does not know: that it was raised, and on what,
#: never the firm a filing is recorded for.
_ATTRIBUTION_FINDING_KEYS: Final[frozenset[str]] = frozenset(
    {"rule", "severity", "count", "summary", "subject"}
)


class Projection(StrEnum):
    """How the ISAC's auditor is served an action's rows."""

    #: About an organisation, a person, the instance or a reader: served whole.
    WHOLE = "whole"
    #: About a submission or a contribution: served without who did it.
    CONTENT = "content"


_WHOLE = Projection.WHOLE
_CONTENT = Projection.CONTENT
#: Every action, classified. A test holds this equal to ``AuditAction``; an
#: action missing from it is served as ``CONTENT``, so a new one fails closed.
_PROJECTIONS: Final[Mapping[str, Projection]] = MappingProxyType(
    {
        AuditAction.AUTH_SUCCESS: _WHOLE,
        AuditAction.AUTH_FAILURE: _WHOLE,
        AuditAction.LOGIN_SUCCESS: _WHOLE,
        AuditAction.SSO_LOGIN_SUCCESS: _WHOLE,
        AuditAction.SSO_LOGIN_REFUSED: _WHOLE,
        AuditAction.LOGIN_FAILURE: _WHOLE,
        AuditAction.LOGOUT: _WHOLE,
        AuditAction.SESSION_REJECTED: _WHOLE,
        AuditAction.ACCESS_DENIED: _WHOLE,
        AuditAction.ACCESS_NOT_FOUND: _WHOLE,
        # The ISAC person who revealed, and why; the reveal's answer is never
        # recorded.
        AuditAction.ANONYMITY_REVEALED: _WHOLE,
        AuditAction.ORG_CREATED: _WHOLE,
        AuditAction.OPERATOR_CREATED: _WHOLE,
        AuditAction.OPERATOR_BOOTSTRAPPED: _WHOLE,
        AuditAction.ORG_STATUS_CHANGED: _WHOLE,
        # Whole except the findings that name a filer (``_instance_details``).
        AuditAction.DETECTION_RAISED: _WHOLE,
        AuditAction.ORG_QUARANTINED: _WHOLE,
        AuditAction.ORG_OFFBOARDED: _WHOLE,
        AuditAction.LEGAL_HOLD_SET: _WHOLE,
        AuditAction.LEGAL_HOLD_LIFTED: _WHOLE,
        AuditAction.ORG_RECONNECTED: _WHOLE,
        AuditAction.ORG_MAIL_DOMAIN_ADDED: _WHOLE,
        AuditAction.ORG_MAIL_DOMAIN_REMOVED: _WHOLE,
        AuditAction.ORG_DIRECTORY_GROUP_SET: _WHOLE,
        AuditAction.CERT_REGISTERED: _WHOLE,
        AuditAction.CERT_REVOKED: _WHOLE,
        AuditAction.CIRCLE_CREATED: _WHOLE,
        AuditAction.CIRCLE_MEMBER_ADDED: _WHOLE,
        AuditAction.CIRCLE_MEMBER_REMOVED: _WHOLE,
        AuditAction.CIRCLE_MEMBER_ROLES_DEFAULTED: _WHOLE,
        AuditAction.SUBMISSION_CREATED: _CONTENT,
        AuditAction.SUBMISSION_UPDATED: _CONTENT,
        AuditAction.SUBMISSION_TRANSITIONED: _CONTENT,
        AuditAction.SUBMISSION_DISTRIBUTED: _CONTENT,
        AuditAction.SUBMISSION_ASSIGNED: _CONTENT,
        AuditAction.SUBMISSION_PRIORITY_SET: _CONTENT,
        AuditAction.SUBMISSION_BULK_VALIDATED: _CONTENT,
        AuditAction.SUBMISSION_FILED_ON_BEHALF: _CONTENT,
        AuditAction.SUBMISSION_PROXY_CONFIRMED: _CONTENT,
        AuditAction.SUBMISSION_TRIAGED: _CONTENT,
        AuditAction.SUBMISSION_MODEL_READ: _CONTENT,
        # A document's actions say which organisation shared what with whom:
        # the owner is its grantees' to know, not the instance auditor's.
        AuditAction.DOCUMENT_CREATED: _CONTENT,
        AuditAction.DOCUMENT_VERSION_SAVED: _CONTENT,
        AuditAction.DOCUMENT_COMMENTED: _CONTENT,
        AuditAction.DOCUMENT_GRANTED: _CONTENT,
        AuditAction.DOCUMENT_GRANT_REVOKED: _CONTENT,
        AuditAction.DOCUMENT_TRANSITIONED: _CONTENT,
        AuditAction.ORG_SHARING_CODE_ROTATED: _WHOLE,
        AuditAction.CONTRIBUTION_PUBLISHED: _CONTENT,
        # A refused contribution: nothing was filed, so nothing to attribute.
        AuditAction.CONTRIBUTION_RATE_LIMITED: _WHOLE,
        AuditAction.CONTRIBUTION_SENT_TO_REVIEW: _CONTENT,
        AuditAction.CONTRIBUTION_REVOKED: _CONTENT,
        AuditAction.CIRCLE_POST_MODERATION_SET: _WHOLE,
        AuditAction.CIRCLE_TAXII_INBOX_SET: _WHOLE,
        # A member's posture is its own estate, not anyone's filing.
        AuditAction.POSTURE_RECORDED: _WHOLE,
        AuditAction.POSTURE_EXPORTED: _WHOLE,
        AuditAction.TAXII_INBOX_RECEIVED: _CONTENT,
        AuditAction.DISTRIBUTION_PAUSED: _WHOLE,
        AuditAction.DISTRIBUTION_RESUMED: _WHOLE,
        AuditAction.EMBARGO_SET: _CONTENT,
        AuditAction.EMBARGO_RELEASED: _CONTENT,
        AuditAction.EMBARGO_EXTENDED: _CONTENT,
        AuditAction.EMBARGO_HELD: _CONTENT,
        AuditAction.SUBMISSION_TRANSITION_REFUSED: _CONTENT,
        # A reader, never a filer.
        AuditAction.OBJECTS_RETRIEVED: _WHOLE,
        AuditAction.EXPORT_RETRIEVED: _WHOLE,
        AuditAction.AUDIT_READ: _WHOLE,
        AuditAction.AUDIT_READ_QUIET: _WHOLE,
        AuditAction.AUDIT_READ_SUMMARY: _WHOLE,
        AuditAction.AUDIT_STREAM_MODE_CHANGED: _WHOLE,
        AuditAction.EVIDENCE_PACK_DRAWN: _WHOLE,
        # The acknowledger, never the filer.
        AuditAction.ACK_RECORDED: _WHOLE,
        AuditAction.WEBHOOK_CREATED: _WHOLE,
        AuditAction.NOTIFICATION_SETTINGS_SET: _WHOLE,
        AuditAction.SECTOR_EVENT_OPENED: _WHOLE,
        AuditAction.SECTOR_EVENT_CLOSED: _WHOLE,
        AuditAction.WEBHOOK_DELETED: _WHOLE,
        AuditAction.WEBHOOK_DELIVERY_FAILED: _WHOLE,
        # Accepted names the sender beside the draft it filed, in one transaction.
        AuditAction.EMAIL_INTAKE_ACCEPTED: _CONTENT,
        # Refused files nothing; it names an organisation only once DMARC passed.
        AuditAction.EMAIL_INTAKE_REFUSED: _WHOLE,
    }
)
_WHOLE_ACTIONS: Final[frozenset[str]] = frozenset(
    action for action, projection in _PROJECTIONS.items() if projection is _WHOLE
)
#: The ``details`` keys of a content row the ISAC's auditor is shown: states,
#: codes, counts, circles, flags and times. Not ``title`` (content), not
#: ``reason`` (a member's withdrawal or revocation reason is its own free
#: text, which can name it), not ``filed_for`` or ``for_org_id`` (the filer).
_CONTENT_DETAIL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "anonymous",
        "assignee_operator_id",
        "bundle_replaced",
        "circle_slugs",
        "circles",
        "codes",
        "collection_id",
        "date_added",
        "discovery_scope",
        "disposition",
        "early",
        "embargoed",
        "fields",
        "from",
        "lane",
        "object_count",
        "objects",
        "originally_due",
        "released_at",
        "rows_skipped",
        "rows_written",
        "rule",
        "rules_version",
        "silence_confirms",
        "submission_ids",
        "tlp",
        "to",
        "verb",
        "via",
    }
)
#: Who did it, which a content row is served without unless the ISAC did.
_IDENTITY_FIELDS: Final[tuple[str, ...]] = (
    "org_id",
    "actor_type",
    "actor_id",
    "request_id",
    "source_ip",
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
    label = f"aivs-{stream}-chain/v2|{scope or 'instance'}"
    first_key = "0" if stream == "audit" else _NIL_UUID
    return Cursor(-1, first_key, hashlib.sha256(label.encode("utf-8")).hexdigest())


# ---------------------------------------------------------------------------
# The two streams
# ---------------------------------------------------------------------------
async def audit_events(
    session: AsyncSession, *, scope: uuid.UUID | None, after: Cursor | None, limit: int
) -> Page:
    """Audit rows in commit order, scoped and redacted."""
    start = after or genesis("audit", scope)
    if scope is not None:
        own = and_(_served_rows(), AuditLog.org_id == scope)
        rows = await _rows(session, AuditLog, own, start, int(start.row_key), limit)
        return _chained(rows, start, _member_event)
    rows = await _rows(
        session,
        AuditLog,
        _served_rows(),
        start,
        int(start.row_key),
        limit,
        columns=(_isac_row(), _in_content_transaction()),
    )
    return _chained(rows, start, _instance_event)


async def receipt_events(
    session: AsyncSession, *, scope: uuid.UUID | None, after: Cursor | None, limit: int
) -> Page:
    """Receipts in commit order: the instance's, or one organisation's own."""
    in_scope = Acknowledgment.org_id == scope if scope is not None else None
    start = after or genesis("receipts", scope)
    rows = await _rows(session, Acknowledgment, in_scope, start, uuid.UUID(start.row_key), limit)
    return _chained(rows, start, lambda row: _receipt_event(row[0]))


def _served_rows() -> ColumnElement[bool]:
    """What the audit stream serves of its own reading.

    A quiet read -- a page that served only reads, or nothing -- never: that
    is what lets a poller reach an empty page in either mode. A read, when the
    mode in force at its own transaction was ``full``; judged per row, so a
    change of mode re-sorts nothing already exported.
    """
    return and_(
        AuditLog.action != AuditAction.AUDIT_READ_QUIET,
        or_(
            AuditLog.action != AuditAction.AUDIT_READ,
            mode_in_force_at(AuditLog.xact_id) == AuditStreamMode.FULL.value,
        ),
    )


def _isac_row() -> ColumnElement[bool]:
    """Whether the row's organisation is the ISAC's own or its automation's."""
    isac_orgs = select(Organization.id).where(Organization.org_type.in_(ISAC_FILER_TYPES))
    return func.coalesce(AuditLog.org_id.in_(isac_orgs), False).label("isac_row")


def _in_content_transaction() -> ColumnElement[bool]:
    """Whether the row's transaction wrote a content row, the row itself included.

    The one place a row is judged content: by its own action, or by sharing a
    transaction -- and so an ``at`` and a request id -- with one that is. An
    action the table does not classify counts as content.
    """
    other = aliased(AuditLog)
    return (
        exists()
        .where(other.xact_id == AuditLog.xact_id, other.action.not_in(_WHOLE_ACTIONS))
        .label("in_content_transaction")
    )


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
    columns: Sequence[ColumnElement[Any]] = (),
) -> list[Row[Any]]:
    """The next rows past ``after``, below the horizon, in ``(xact_id, id)`` order.

    Each result is the row, then ``columns``.
    """
    horizon = cast(cast(func.pg_snapshot_xmin(func.pg_current_snapshot()), Text), BigInteger)
    query = (
        select(model, *columns)
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
    return list((await session.execute(query)).all())


def _chained(
    rows: Sequence[Row[Any]], start: Cursor, render: Callable[[Row[Any]], dict[str, Any]]
) -> Page:
    chain = start.chain
    events = []
    for row in rows:
        event = render(row)
        chain = _link(chain, event)
        events.append({**event, "hash": chain})
    if not rows:
        return Page(events=[], cursor=start)
    last = rows[-1][0]
    return Page(events=events, cursor=Cursor(last.xact_id, str(last.id), chain))


def _link(previous: str, event: Mapping[str, Any]) -> str:
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(f"{previous}\n{canonical}".encode("ascii")).hexdigest()


def _member_event(row: Row[Any]) -> dict[str, Any]:
    entry: AuditLog = row[0]
    return _event(entry, _only(entry.details or {}, _OWN_SCOPE_DETAIL_KEYS))


def _instance_event(row: Row[Any]) -> dict[str, Any]:
    """The ISAC auditor's view of a row: whole, or a content row's projection."""
    entry: AuditLog = row[0]
    isac_row: bool = row[1]
    in_content_transaction: bool = row[2]
    if not in_content_transaction:
        return _event(entry, _instance_details(entry))
    event = _event(entry, _only(entry.details or {}, _CONTENT_DETAIL_KEYS))
    if not isac_row:
        event.update(dict.fromkeys(_IDENTITY_FIELDS))
    return event


def _instance_details(entry: AuditLog) -> dict[str, Any]:
    """A whole row's ``details``; for a finding, without a filer it may name."""
    details = entry.details or {}
    rule = details.get("rule")
    names_no_filer = rule in RULE_NAMES and rule not in ATTRIBUTION_RULES
    if entry.action == AuditAction.DETECTION_RAISED and not names_no_filer:
        return _only(details, _ATTRIBUTION_FINDING_KEYS)
    return details


def _event(entry: AuditLog, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": entry.id,
        "at": _stamp(entry.at),
        "action": entry.action,
        "outcome": entry.outcome,
        "actor_type": entry.actor_type,
        "actor_id": entry.actor_id,
        "org_id": _text(entry.org_id),
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "request_id": entry.request_id,
        "source_ip": _text(entry.source_ip),
        "details": details,
    }


def _only(details: Mapping[str, Any], keys: frozenset[str]) -> dict[str, Any]:
    return {k: v for k, v in details.items() if k in keys}


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
