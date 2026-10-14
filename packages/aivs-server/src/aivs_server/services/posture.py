"""A member's posture on a vulnerability: private to it, aggregated for the ISAC (SF-70).

Whether a member is ``affected`` is the most sensitive fact it can hold about a
vulnerability, and an ISAC that could read it per member holds a list member
counsel will not allow to exist. So a posture row is the member's alone: only
its own organisation reads or writes it, and a request for anyone else's
answers 404 like an absent row. The ISAC sees counts, each withheld below k,
and the total withheld whenever a withheld count could be worked out from it.

The one-click records ``under_investigation``; nothing defaults a member to
``affected``. ``actioned`` -- "we did something about it" -- stays a receipt,
which is the one per-member fact the ISAC holds by design.

The audit row records that a posture was set, never which: the audit log is
read by ISAC auditors, and the status there would undo the privacy here.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import PostureStatus
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import OrgPosture
from aivs_server.services.contributions import TargetNotFoundError, resolve_target
from aivs_server.services.telemetry import K_ANONYMITY, Count

__all__ = ["PostureSummary", "own_posture", "posture_summary", "record_posture"]

_VULNERABILITY_PREFIX: Final[str] = "vulnerability--"


async def record_posture(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    vulnerability_id: str,
    status: PostureStatus,
    detection_deployed: bool,
    now: dt.datetime,
) -> OrgPosture:
    """Set the caller's own posture on a vulnerability it can see."""
    if not vulnerability_id.startswith(_VULNERABILITY_PREFIX):
        raise TargetNotFoundError(vulnerability_id)
    if await resolve_target(session, ctx, vulnerability_id, now=now) is None:
        raise TargetNotFoundError(vulnerability_id)

    row = (
        await session.execute(
            select(OrgPosture)
            .where(
                OrgPosture.org_id == ctx.org_id,
                OrgPosture.vulnerability_stix_id == vulnerability_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None:
        row = OrgPosture(org_id=ctx.org_id, vulnerability_stix_id=vulnerability_id)
        session.add(row)
    row.status = status
    row.detection_deployed = detection_deployed
    row.updated_by_operator_id = ctx.operator_id
    row.updated_at = now
    await session.flush()
    await record(
        session,
        action=AuditAction.POSTURE_RECORDED,
        ctx=ctx,
        resource_type="posture",
        resource_id=str(row.id),
        details={},
    )
    return row


async def own_posture(
    session: AsyncSession, ctx: AuthContext, posture_id: uuid.UUID
) -> OrgPosture | None:
    """The posture row, if it is the caller's own; otherwise ``None``, as if absent."""
    row = await session.get(OrgPosture, posture_id)
    if row is None or row.org_id != ctx.org_id:
        return None
    return row


class PostureSummary:
    """Counts per status for one vulnerability, each a :class:`Count`."""

    __slots__ = ("by_status", "total")

    def __init__(self, total: Count, by_status: Mapping[PostureStatus, Count]) -> None:
        self.total = total
        self.by_status = dict(by_status)


def _suppress(counts: Mapping[PostureStatus, int]) -> PostureSummary:
    total = sum(counts.values())
    if total < K_ANONYMITY:
        withheld = Count(None, f"shown once at least {K_ANONYMITY} organisations have one")
        return PostureSummary(withheld, dict.fromkeys(PostureStatus, withheld))
    by_status = {
        status: Count(None, f"fewer than {K_ANONYMITY}")
        if 0 < counts.get(status, 0) < K_ANONYMITY
        else Count(counts.get(status, 0))
        for status in PostureStatus
    }
    # A total beside one withheld count gives the withheld one away by subtraction.
    any_withheld = any(count.value is None for count in by_status.values())
    shown_total = (
        Count(None, "withheld so a small count cannot be derived") if any_withheld else Count(total)
    )
    return PostureSummary(shown_total, by_status)


async def posture_summary(session: AsyncSession, vulnerability_id: str) -> PostureSummary:
    rows = (
        await session.execute(
            select(OrgPosture.status, func.count())
            .where(OrgPosture.vulnerability_stix_id == vulnerability_id)
            .group_by(OrgPosture.status)
        )
    ).all()
    return _suppress({PostureStatus(status): int(count) for status, count in rows})
