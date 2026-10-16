"""A member's posture on a vulnerability: private to it, aggregated for the ISAC (SF-70).

Whether a member is ``affected`` is the most sensitive fact it can hold about a
vulnerability, and an ISAC that could read it per member holds a list member
counsel will not allow to exist. So a posture row is the member's alone: only
its own organisation reads or writes it, and a request for anyone else's
answers 404 like an absent row. The ISAC sees counts by telemetry's rule: a
count is exact only when at least k members have that status *and* at least k
of those with a posture do not. The audit log tells the ISAC which members
recorded a posture, so "6 of 6 affected", or an exact zero beside a total,
states each named firm's status. The total is withheld whenever a withheld
count could be worked out from it.

Those counts are read from a published snapshot (``services.count_snapshots``),
never live. Read live, the summary before and after one firm's audited posture
write, or around an editor suspending one firm, moved by exactly that firm
(review R-C3, R2-C1). A snapshot is replaced only once at least K members'
statuses differ from it, so what moves between two published summaries is
always the sum of at least K firms.

A posture is a VEX statement (OpenVEX / CSAF VEX): the status, and the
statements VEX requires with it -- why a product is ``not_affected``, what is
being done where it is ``affected`` -- plus the products it covers. The
database holds VEX's rules (``OrgPosture``'s checks), so the member's export is
always a valid VEX document. ``validated_at`` and ``evidence_note`` are ours.

The one-click records ``under_investigation``; nothing defaults a member to
``affected``. ``actioned`` -- "we did something about it" -- stays a receipt,
which is the one per-member fact the ISAC holds by design.

The audit row records that a posture was set, never which: the audit log is
read by ISAC auditors, and the status there would undo the privacy here. For
the same reason no request names the vulnerability in its URI: a member's
posture is written with the id in the body, because request lines are logged
by nginx and the app beside the client's identity, and those logs leave for the
ISAC's collector. "Firm X wrote a posture on V at t" is half of what a reader
needs to recover the status; the published snapshot denies it the other half.

This protects a member against the ISAC *through the application*. Whoever
operates the database reads ``org_postures`` in plaintext; that is the host's
trust, not something this module can withhold (threat model, the posture row).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from sqlalchemy import exists, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import PostureStatus, VexJustification
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import PolicyDeniedError
from aivs_server.db.models import (
    CountSnapshot,
    CountSubject,
    Distribution,
    OrgPosture,
    StixObject,
)
from aivs_server.db.org_lock import org_still_active
from aivs_server.services.contributions import TargetNotFoundError, resolve_target
from aivs_server.services.count_snapshots import publish_if_changed, published
from aivs_server.services.posture_reads import own_posture, own_postures
from aivs_server.services.telemetry import (
    K_ANONYMITY,
    Count,
    counted_organisations,
    k_anonymous,
)

__all__ = [
    "PostureError",
    "PostureSummary",
    "VexStatement",
    "is_distributed_vulnerability",
    "own_posture",
    "own_postures",
    "posture_basis",
    "posture_summary",
    "publish_postures",
    "record_posture",
    "vex_problem",
]

_VULNERABILITY_PREFIX: Final[str] = "vulnerability--"


@dataclass(frozen=True, slots=True)
class VexStatement:
    """What a member says about one vulnerability in its estate."""

    status: PostureStatus
    justification: VexJustification | None = None
    impact_statement: str | None = None
    action_statement: str | None = None
    products: tuple[str, ...] = ()
    detection_deployed: bool = False
    #: The member confirms, now, that the statement holds. The server stamps
    #: the time; a member never supplies one.
    validated: bool = False
    evidence_note: str | None = None


def vex_problem(statement: VexStatement) -> str | None:
    """Why ``statement`` is not a valid VEX statement, or ``None``.

    The database enforces the same three rules; this says which one, in words a
    member can act on, before the write.
    """
    if statement.justification is not None and statement.status is not PostureStatus.NOT_AFFECTED:
        return "a justification explains not_affected only; remove it or change the status"
    if statement.status is PostureStatus.NOT_AFFECTED and not (
        statement.justification or statement.impact_statement
    ):
        return "not_affected needs a justification or an impact statement saying why (VEX)"
    if statement.status is PostureStatus.AFFECTED and not statement.action_statement:
        return "affected needs an action statement saying what is being done (VEX)"
    return None


class PostureError(ValueError):
    """The statement breaks one of VEX's rules; the message names it."""


async def record_posture(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    vulnerability_id: str,
    statement: VexStatement,
    now: dt.datetime,
) -> OrgPosture:
    """Set the caller's own posture on a vulnerability it can see."""
    if not vulnerability_id.startswith(_VULNERABILITY_PREFIX):
        raise TargetNotFoundError(vulnerability_id)
    if await resolve_target(session, ctx, vulnerability_id, now=now) is None:
        raise TargetNotFoundError(vulnerability_id)
    problem = vex_problem(statement)
    if problem is not None:
        raise PostureError(problem)
    if not await org_still_active(session, ctx.org_id):
        denial = "posture_org_not_active"
        raise PolicyDeniedError(denial)

    row = await _own_row_locked(session, ctx, vulnerability_id, statement=statement)
    _apply(row, statement, now=now)
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


def _statement_of(row: OrgPosture) -> tuple[object, ...]:
    """What a validation vouches for: the VEX statement, not our own notes on it."""
    return (
        row.status,
        row.justification,
        row.impact_statement,
        row.action_statement,
        tuple(row.products or ()),
    )


def _statement_without_ours(statement: VexStatement) -> tuple[object, ...]:
    return (
        statement.status,
        statement.justification,
        statement.impact_statement,
        statement.action_statement,
        statement.products,
    )


def _apply(row: OrgPosture, statement: VexStatement, *, now: dt.datetime) -> None:
    """Write the statement onto the row.

    A validation was of the statement as it stood: any change to it -- status,
    justification, either statement, the products -- voids the validation
    unless the member validates again in the same write. A changed evidence
    note or detection flag does not: they are ours, not the statement.
    """
    if statement.validated:
        row.validated_at = now
    elif _statement_of(row) != _statement_without_ours(statement):
        row.validated_at = None
    row.status = statement.status
    row.justification = statement.justification
    row.impact_statement = statement.impact_statement
    row.action_statement = statement.action_statement
    row.products = list(statement.products)
    row.detection_deployed = statement.detection_deployed
    row.evidence_note = statement.evidence_note


async def _own_row_locked(
    session: AsyncSession, ctx: AuthContext, vulnerability_id: str, *, statement: VexStatement
) -> OrgPosture:
    """The caller's row for this vulnerability, created if absent, locked for update.

    Two first writes race: each finds no row, and the second insert would hit
    ``uq_org_postures_org_vuln`` and answer 500. Inserting with ``ON CONFLICT
    DO NOTHING`` lets the loser fall through to the winner's row instead.
    """
    await session.execute(
        insert(OrgPosture)
        .values(
            org_id=ctx.org_id,
            vulnerability_stix_id=vulnerability_id,
            status=statement.status,
            justification=statement.justification,
            impact_statement=statement.impact_statement,
            action_statement=statement.action_statement,
        )
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


class PostureSummary:
    """Counts per status for one vulnerability, each a :class:`Count`, as published at ``as_of``."""

    __slots__ = ("as_of", "by_status", "total")

    def __init__(
        self,
        total: Count,
        by_status: Mapping[PostureStatus, Count],
        as_of: dt.datetime | None,
    ) -> None:
        self.total = total
        self.by_status = dict(by_status)
        self.as_of = as_of


_TOO_FEW_POSTURES: Final[str] = f"shown once at least {K_ANONYMITY} organisations have one"


def _suppress(counts: Mapping[PostureStatus, int], as_of: dt.datetime | None) -> PostureSummary:
    total = sum(counts.values())
    by_status = {
        status: k_anonymous(counts.get(status, 0), population=total, too_few=_TOO_FEW_POSTURES)
        for status in PostureStatus
    }
    if total < K_ANONYMITY:
        return PostureSummary(Count(None, _TOO_FEW_POSTURES), by_status, as_of)
    # A total beside one withheld count gives the withheld one away by subtraction.
    any_withheld = any(count.value is None for count in by_status.values())
    shown_total = (
        Count(None, "withheld so a small count cannot be derived") if any_withheld else Count(total)
    )
    return PostureSummary(shown_total, by_status, as_of)


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


async def posture_basis(session: AsyncSession, vulnerability_id: str) -> dict[str, str]:
    """Each counted member with a posture on this vulnerability, mapped to its status.

    Only members are counted (``counted_organisations``): the ISAC's own
    posture counted toward k would let five rows describe four firms.
    """
    rows = await session.execute(
        select(OrgPosture.org_id, OrgPosture.status).where(
            OrgPosture.vulnerability_stix_id == vulnerability_id,
            OrgPosture.org_id.in_(counted_organisations()),
        )
    )
    return {str(org_id): PostureStatus(status).value for org_id, status in rows}


async def posture_summary(session: AsyncSession, vulnerability_id: str) -> PostureSummary | None:
    """Published counts per status, or ``None`` for anything not a distributed vulnerability."""
    if not await is_distributed_vulnerability(session, vulnerability_id):
        return None
    snapshot = await published(session, CountSubject.POSTURE, vulnerability_id)
    if snapshot is None:
        return _suppress({}, None)
    counts: dict[PostureStatus, int] = {}
    for status in snapshot.basis.values():
        counts[PostureStatus(status)] = counts.get(PostureStatus(status), 0) + 1
    return _suppress(counts, snapshot.taken_at)


async def publish_postures(session: AsyncSession, *, now: dt.datetime) -> int:
    """Republish each vulnerability's summary that K members' changes have moved. Commits.

    Examines every vulnerability that has a posture or a published summary: a
    summary whose last postures were deleted still has to be compared, or it
    would go on showing them.
    """
    with_postures = select(OrgPosture.vulnerability_stix_id)
    with_snapshot = select(CountSnapshot.subject_id).where(
        CountSnapshot.subject_kind == CountSubject.POSTURE.value
    )
    subjects = (await session.execute(with_postures.union(with_snapshot))).scalars().all()
    republished = 0
    for vulnerability_id in subjects:
        basis = await posture_basis(session, vulnerability_id)
        if await publish_if_changed(
            session, CountSubject.POSTURE, vulnerability_id, basis, now=now
        ):
            republished += 1
    await session.commit()
    return republished
