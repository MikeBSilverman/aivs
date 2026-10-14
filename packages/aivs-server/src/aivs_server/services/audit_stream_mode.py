"""What the audit stream serves of its own reading: ``full`` or ``condensed`` (Mike, Q30).

Every page of the stream is recorded, and a SIEM poller is a reader too, so
the stream has to decide what it says about being read:

- ``condensed`` (the default): ``audit.read`` rows stay out of the stream, and
  the summary job (``services.audit_read_summary``) serves one row per reader
  per run instead.
- ``full``: ``audit.read`` rows are served as written. A page that served only
  reads, or nothing, is recorded as ``audit.read.quiet``, which is never
  served, so a poller still reaches an empty page (the T10 hang).

The mode is a history (``AuditStreamModeChange``), and a read row is judged
by the mode in force when *it* was written, so a change re-sorts nothing
already exported: cursors continue and the hash chain still matches.
"""

from __future__ import annotations

import enum
from typing import Final

from sqlalchemy import ColumnElement, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import AuditStreamModeChange

__all__ = [
    "DEFAULT_MODE",
    "AuditStreamMode",
    "change_audit_stream_mode",
    "current_audit_stream_mode",
    "mode_in_force_at",
]


class AuditStreamMode(enum.StrEnum):
    FULL = "full"
    CONDENSED = "condensed"


#: Before anyone chooses: the reads-out stream T10 shipped, plus summaries.
DEFAULT_MODE: Final[AuditStreamMode] = AuditStreamMode.CONDENSED

#: Serialises changes, so each one's "previous" is the mode it replaced.
_MODE_LOCK_KEY: Final[int] = 0x41495653_00000002  # "AIVS", lock 2


def mode_in_force_at(
    xact_id: ColumnElement[int] | InstrumentedAttribute[int],
) -> ColumnElement[str]:
    """The mode in force when the transaction ``xact_id`` wrote, as SQL."""
    latest = (
        select(AuditStreamModeChange.mode)
        .where(AuditStreamModeChange.xact_id <= xact_id)
        .order_by(AuditStreamModeChange.xact_id.desc(), AuditStreamModeChange.id.desc())
        .limit(1)
        .scalar_subquery()
    )
    return func.coalesce(latest, DEFAULT_MODE.value)


async def current_audit_stream_mode(session: AsyncSession) -> AuditStreamMode:
    latest = await session.scalar(
        select(AuditStreamModeChange.mode)
        .order_by(AuditStreamModeChange.xact_id.desc(), AuditStreamModeChange.id.desc())
        .limit(1)
    )
    return DEFAULT_MODE if latest is None else AuditStreamMode(latest)


async def change_audit_stream_mode(
    session: AsyncSession, ctx: AuthContext, mode: AuditStreamMode, *, reason: str
) -> bool:
    """Put ``mode`` in force from this transaction on. Does not commit.

    ``False``, and nothing written, when it is already in force. The change is
    recorded twice on purpose and for different readers: the history row is
    what the stream's filter reads, and the audit row is what the stream
    serves, in either mode, so a SIEM sees the switch where it happened.
    """
    await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _MODE_LOCK_KEY})
    previous = await current_audit_stream_mode(session)
    if previous is mode:
        return False
    session.add(
        AuditStreamModeChange(
            mode=mode.value, changed_by_operator_id=ctx.operator_id, reason=reason
        )
    )
    await record(
        session,
        action=AuditAction.AUDIT_STREAM_MODE_CHANGED,
        ctx=ctx,
        resource_type="audit_stream",
        resource_id="audit",
        details={"mode": mode.value, "previous": previous.value, "reason": reason},
    )
    return True
