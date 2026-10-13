"""The instance's stop button: pausing and resuming all distribution.

The incident runbook's first step. Pausing refuses every new publication and
withholds everything already published from every reader until resumed; see
``services.publication`` and ``auth.policy._distribution_not_paused``.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import InstanceControl

__all__ = ["distribution_is_paused", "pause_distribution", "resume_distribution"]


async def _controls(session: AsyncSession) -> InstanceControl:
    """The single controls row, locked, created on first use."""
    row = (
        await session.execute(
            select(InstanceControl).where(InstanceControl.id == 1).with_for_update()
        )
    ).scalar_one_or_none()
    if row is None:
        row = InstanceControl(id=1, distribution_paused=False)
        session.add(row)
        await session.flush()
    return row


async def distribution_is_paused(session: AsyncSession) -> bool:
    paused = await session.scalar(
        select(InstanceControl.distribution_paused).where(InstanceControl.id == 1)
    )
    return bool(paused)


async def pause_distribution(
    session: AsyncSession, ctx: AuthContext, *, reason: str, now: dt.datetime
) -> None:
    """Stop all publication and all serving. Does not commit."""
    row = await _controls(session)
    row.distribution_paused = True
    row.paused_at = now
    row.paused_by_operator_id = ctx.operator_id
    row.pause_reason = reason
    await record(
        session,
        action=AuditAction.DISTRIBUTION_PAUSED,
        ctx=ctx,
        resource_type="instance",
        resource_id="distribution",
        details={"reason": reason},
    )


async def resume_distribution(session: AsyncSession, ctx: AuthContext, *, reason: str) -> None:
    """Resume publication and serving. Does not commit."""
    row = await _controls(session)
    row.distribution_paused = False
    row.paused_at = None
    row.paused_by_operator_id = None
    row.pause_reason = None
    await record(
        session,
        action=AuditAction.DISTRIBUTION_RESUMED,
        ctx=ctx,
        resource_type="instance",
        resource_id="distribution",
        details={"reason": reason},
    )
