"""The caller's own postures: the reads, apart from the posture service's writes.

``services.member_staff_reads`` runs them on the staff login for a member's
request (Phase P slice 3e: the member login holds nothing on
``org_postures``). Kept out of ``services.posture``, which imports the
contribution path, so that module can import them without a cycle. Each is
keyed on the caller's organisation; a peer's posture is never returned.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection, Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import PostureStatus
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import OrgPosture

__all__ = ["own_posture", "own_posture_count", "own_posture_status", "own_postures"]


async def own_postures(session: AsyncSession, ctx: AuthContext) -> list[OrgPosture]:
    """Every posture the caller's organisation holds, newest change first."""
    rows = await session.execute(
        select(OrgPosture)
        .where(OrgPosture.org_id == ctx.org_id)
        .order_by(OrgPosture.updated_at.desc(), OrgPosture.id)
    )
    return list(rows.scalars().all())


async def own_posture_status(session: AsyncSession, ctx: AuthContext, stix_id: str) -> str | None:
    """The caller's own posture on one vulnerability, which only it ever sees (SF-70)."""
    status = await session.scalar(
        select(OrgPosture.status).where(
            OrgPosture.org_id == ctx.org_id, OrgPosture.vulnerability_stix_id == stix_id
        )
    )
    return None if status is None else PostureStatus(status).value


async def own_posture_count(
    session: AsyncSession,
    ctx: AuthContext,
    stix_ids: Sequence[str],
    statuses: Collection[PostureStatus],
) -> int:
    """How many of ``stix_ids`` the caller's organisation holds a posture in ``statuses`` on."""
    if not stix_ids:
        return 0
    count = await session.scalar(
        select(func.count())
        .select_from(OrgPosture)
        .where(
            OrgPosture.org_id == ctx.org_id,
            OrgPosture.vulnerability_stix_id.in_(stix_ids),
            OrgPosture.status.in_(tuple(statuses)),
        )
    )
    return int(count or 0)


async def own_posture(
    session: AsyncSession, ctx: AuthContext, posture_id: uuid.UUID
) -> OrgPosture | None:
    """The posture row, if it is the caller's own; otherwise ``None``, as if absent."""
    row = await session.get(OrgPosture, posture_id)
    if row is None or row.org_id != ctx.org_id:
        return None
    return row
