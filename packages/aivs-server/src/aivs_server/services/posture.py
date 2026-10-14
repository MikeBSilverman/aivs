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
read by ISAC auditors, and the status there would undo the privacy here. For
the same reason no request names the vulnerability in its URI: a member's
posture is written with the id in the body, because request lines are logged
by nginx and the app beside the client's identity, and those logs leave for the
ISAC's collector. "Firm X wrote a posture on V at t", read beside the summary
before and after, is the status.

This protects a member against the ISAC *through the application*. Whoever
operates the database reads ``org_postures`` in plaintext; that is the host's
trust, not something this module can withhold (threat model, the posture row).
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping
from typing import Final

from sqlalchemy import exists, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import PostureStatus
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import Distribution, OrgPosture, StixObject
from aivs_server.services.contributions import TargetNotFoundError, resolve_target
from aivs_server.services.telemetry import K_ANONYMITY, Count, counted_organisations

__all__ = [
    "PostureSummary",
    "is_distributed_vulnerability",
    "own_posture",
    "own_postures",
    "posture_summary",
    "record_posture",
]

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

    row = await _own_row_locked(session, ctx, vulnerability_id, status=status)
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


async def _own_row_locked(
    session: AsyncSession, ctx: AuthContext, vulnerability_id: str, *, status: PostureStatus
) -> OrgPosture:
    """The caller's row for this vulnerability, created if absent, locked for update.

    Two first writes race: each finds no row, and the second insert would hit
    ``uq_org_postures_org_vuln`` and answer 500. Inserting with ``ON CONFLICT
    DO NOTHING`` lets the loser fall through to the winner's row instead.
    """
    await session.execute(
        insert(OrgPosture)
        .values(org_id=ctx.org_id, vulnerability_stix_id=vulnerability_id, status=status)
        .on_conflict_do_nothing(index_elements=["org_id", "vulnerability_stix_id"])
    )
    return (
        await session.execute(
            select(OrgPosture)
            .where(
                OrgPosture.org_id == ctx.org_id,
                OrgPosture.vulnerability_stix_id == vulnerability_id,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def own_postures(session: AsyncSession, ctx: AuthContext) -> list[OrgPosture]:
    """Every posture the caller's organisation holds, newest change first."""
    rows = await session.execute(
        select(OrgPosture)
        .where(OrgPosture.org_id == ctx.org_id)
        .order_by(OrgPosture.updated_at.desc(), OrgPosture.id)
    )
    return list(rows.scalars().all())


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


async def is_distributed_vulnerability(session: AsyncSession, vulnerability_id: str) -> bool:
    """Whether any version of this vulnerability was distributed: what a summary may be about."""
    if not vulnerability_id.startswith(_VULNERABILITY_PREFIX):
        return False
    distributed = (
        select(StixObject.id)
        .join(Distribution, Distribution.stix_object_id == StixObject.id)
        .where(StixObject.stix_id == vulnerability_id)
    )
    return bool(await session.scalar(select(exists(distributed))))


async def posture_summary(session: AsyncSession, vulnerability_id: str) -> PostureSummary | None:
    """Counts per status from members, or ``None`` for anything not a distributed vulnerability.

    Only members are counted (``counted_organisations``): the ISAC's own
    posture counted toward k would let five rows describe four firms.
    """
    if not await is_distributed_vulnerability(session, vulnerability_id):
        return None
    rows = (
        await session.execute(
            select(OrgPosture.status, func.count())
            .where(
                OrgPosture.vulnerability_stix_id == vulnerability_id,
                OrgPosture.org_id.in_(counted_organisations()),
            )
            .group_by(OrgPosture.status)
        )
    ).all()
    return _suppress({PostureStatus(status): int(count) for status, count in rows})
