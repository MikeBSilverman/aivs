"""Telemetry back to the submitter: what happened to what you shared.

The reciprocity signal an ISAC has never had (plan, Phase E). Every retrieval
and acknowledgment is already a row; the submitter never saw any of it, which
is why members stop posting. This turns those rows into counts for the
submitter alone, with no analyst in the loop.

Counts, never lists, and never a count that points at someone -- directly or
by subtraction:
- fewer than K organisations could see it: every number is withheld;
- otherwise a count is exact only when at least K organisations did the thing
  *and* at least K did not. Reach is exact, so "6 could see it, 5 acted"
  names the one that did not as surely as "1 acted" names the one that did;
  and members can know a circle's roster, so an exact zero, or a count equal
  to reach, states every firm's action. Such counts read "fewer than K" or
  "all but fewer than K".
Reach counts only organisations that could retrieve it: active, a member when
it was released, in a circle that is active and whose collection is readable.
Anyone else would let K describe fewer than K possible readers, and an exact
count could then name every real one. The counts are of those same
organisations, so "all but fewer than K" is measured against the K it claims.

A milestone announces a count the submitter could have read, never more: it
fires only once its count is shown exactly. A milestone that stays silent says
only that the count is not yet shown at that threshold, which the count says
too. (A "first retrieval" that never fired said the count was exactly zero.)

Counts are read from a published snapshot (``services.count_snapshots``),
never live: a live count read twice says that *some* firm acted in between,
and with a known firm suspended in between it says which (review R2-C1). The
snapshot is republished once at least K organisations' contributions to it
differ, at most once per run of the telemetry job, and milestones are judged
on the snapshot alone, or the announcement would carry the live count's timing.

Counters that depend on later phases (opinions on its content, posture
outcomes, citations by an ISAC advisory) are named as not yet available rather
than shown as zero, so an early submitter does not conclude it is broken.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Select, and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import AckType, OrgStatus
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import (
    Acknowledgment,
    Circle,
    CircleMembership,
    CountSubject,
    Distribution,
    Organization,
    Submission,
    SubmissionMilestone,
    TaxiiCollection,
    Webhook,
    WebhookDelivery,
)
from aivs_server.db.webhook_lock import deliverable_webhooks
from aivs_server.services.attribution import submitter_of
from aivs_server.services.count_snapshots import K_ANONYMITY, publish_if_changed
from aivs_server.services.member_staff_reads import telemetry_snapshot
from aivs_server.services.ownership import ISAC_OWNER_TYPES

__all__ = [
    "EVENT_SUBMISSION_TELEMETRY",
    "K_ANONYMITY",
    "Count",
    "Telemetry",
    "counted_organisations",
    "k_anonymous",
    "publish_telemetry",
    "submission_telemetry",
    "telemetry_basis",
]

EVENT_SUBMISSION_TELEMETRY: Final[str] = "submission.telemetry"

#: Named so a reader knows what is coming, rather than reading a zero. Said
#: without a phase or a date: this text reaches members, and a promise of when
#: is a claim that goes stale while nobody is looking at it.
LATER: Final[tuple[str, ...]] = (
    "how many organisations agree or disagree with it",
    "how many report it fixed or not affecting them",
    "citations by an ISAC advisory",
)


@dataclass(frozen=True, slots=True)
class Count:
    """An exact number, or ``None`` with the reason it is withheld."""

    value: int | None
    withheld: str | None = None


@dataclass(frozen=True, slots=True)
class Telemetry:
    submission_id: uuid.UUID
    distributed: bool
    reach: Count
    retrieved: Count
    acknowledged: Count
    actioned: Count
    #: When the counts were published; ``None`` before the first snapshot.
    as_of: dt.datetime | None
    later: tuple[str, ...] = LATER


_TOO_FEW_READERS: Final[str] = f"shown once at least {K_ANONYMITY} organisations could see it"


def k_anonymous(value: int, *, population: int, too_few: str) -> Count:
    """``value`` organisations of ``population``, exact only if it points at nobody.

    At least K must be counted and at least K not: a reader who knows who the
    population is learns each firm's answer from an exact zero or an exact
    "all of them" as surely as from a one. Below K in all, ``too_few`` says why.
    Telemetry and posture both count through here, so the rule has one text.
    """
    if population < K_ANONYMITY:
        return Count(None, too_few)
    if value < K_ANONYMITY:
        return Count(None, f"fewer than {K_ANONYMITY}")
    if population - value < K_ANONYMITY:
        return Count(None, f"all but fewer than {K_ANONYMITY}")
    return Count(value)


def _suppressed(value: int, *, reach: int) -> Count:
    return k_anonymous(value, population=reach, too_few=_TOO_FEW_READERS)


def _reach_count(reach: int) -> Count:
    """Reach is exact from K: it says how many could see, not what any one did."""
    if reach < K_ANONYMITY:
        return Count(None, _TOO_FEW_READERS)
    return Count(reach)


def counted_organisations() -> Select[tuple[uuid.UUID]]:
    """The organisations a k-anonymous count may count: active members, never the ISAC.

    A count is about members. The ISAC's own row, or its automation's, would
    let K describe one member fewer than it says; so would an inactive
    organisation, which cannot read. Posture's summary counts through this too.
    """
    return select(Organization.id).where(
        Organization.org_type.not_in(tuple(ISAC_OWNER_TYPES)),
        Organization.status == OrgStatus.ACTIVE,
    )


def _is_counted(org_id: Any, submitter_org_id: uuid.UUID) -> Any:
    """Organisations that count here: those that may be counted, other than the submitter."""
    return and_(org_id != submitter_org_id, org_id.in_(counted_organisations()))


def _reachable(submission: Submission, submitter: uuid.UUID) -> Select[tuple[uuid.UUID]]:
    """Organisations that could retrieve it, as the TAXII read path decides.

    A member when it became visible, in a circle that is active, with an
    active collection that may be read: the same terms ``load_circle_grants``
    and the collection lookup hold a reader to. Retrieval, and so every
    acknowledgment, happens only there.
    """
    covered = and_(
        CircleMembership.circle_id == Distribution.circle_id,
        CircleMembership.joined_at <= Distribution.date_added,
        or_(
            CircleMembership.left_at.is_(None),
            CircleMembership.left_at > Distribution.date_added,
        ),
    )
    readable = and_(
        TaxiiCollection.circle_id == Distribution.circle_id,
        TaxiiCollection.is_active.is_(True),
        TaxiiCollection.can_read.is_(True),
    )
    return (
        select(CircleMembership.org_id)
        .select_from(Distribution)
        .join(CircleMembership, covered)
        .join(Circle, Circle.id == Distribution.circle_id)
        .join(TaxiiCollection, readable)
        .where(
            Distribution.submission_id == submission.id,
            Circle.is_active.is_(True),
            # A sandbox is for testing a member's connection; what reaches it
            # is no reach, and counting it would let an exercise read as
            # engagement.
            Circle.is_sandbox.is_(False),
            _is_counted(CircleMembership.org_id, submitter),
        )
    )


async def telemetry_basis(session: AsyncSession, submission: Submission) -> dict[str, str]:
    """Each organisation in reach, mapped to the receipt types it holds (sorted, comma-joined).

    The live state a snapshot is taken from. Receipts from outside reach are
    not counted: a count is a part of reach, or reach minus it lies.
    """
    reachable = _reachable(submission, await submitter_of(session, submission))
    in_reach = (await session.execute(reachable.distinct())).scalars().all()
    receipts = await session.execute(
        select(Acknowledgment.org_id, Acknowledgment.ack_type)
        .where(Acknowledgment.submission_id == submission.id, Acknowledgment.org_id.in_(reachable))
        .distinct()
    )
    held: dict[str, set[str]] = {str(org_id): set() for org_id in in_reach}
    for org_id, ack_type in receipts:
        held[str(org_id)].add(AckType(ack_type).value)
    return {org_id: ",".join(sorted(types)) for org_id, types in held.items()}


def _holding(basis: Mapping[str, str], ack_type: AckType) -> int:
    return sum(1 for types in basis.values() if ack_type.value in types.split(","))


def _telemetry_from(
    submission: Submission, basis: Mapping[str, str], as_of: dt.datetime | None
) -> Telemetry:
    reach = len(basis)
    counts = {
        ack_type: _suppressed(_holding(basis, ack_type), reach=reach)
        for ack_type in (AckType.RETRIEVED, AckType.ACKNOWLEDGED, AckType.ACTIONED)
    }
    return Telemetry(
        submission_id=submission.id,
        distributed=reach > 0 or submission.distributed_at is not None,
        reach=_reach_count(reach),
        retrieved=counts[AckType.RETRIEVED],
        acknowledged=counts[AckType.ACKNOWLEDGED],
        actioned=counts[AckType.ACTIONED],
        as_of=as_of,
    )


async def submission_telemetry(
    session: AsyncSession, ctx: AuthContext, submission: Submission
) -> Telemetry:
    """What the submitter may see about its own submission, as last published. Reads only.

    The snapshot is read staff side for a member (``member_staff_reads``): it
    says who was in reach, which leaves out the submitter.
    """
    snapshot = await telemetry_snapshot(session, ctx, submission.id)
    if snapshot is None:
        return _telemetry_from(submission, {}, None)
    return _telemetry_from(submission, snapshot.basis, snapshot.taken_at)


# ---------------------------------------------------------------------------
# Milestones: the submitter learns the same day that it mattered
# ---------------------------------------------------------------------------
#: (milestone, ack type, threshold). A milestone fires only when its count is
#: shown exactly, and an exact count is at least K, so nothing below K is a
#: milestone: "first_retrieval" and "first_actioned" were, and their silence
#: read as an exact zero.
_MILESTONES: Final[tuple[tuple[str, AckType, int], ...]] = (
    (f"retrieved_{K_ANONYMITY}", AckType.RETRIEVED, K_ANONYMITY),
    ("retrieved_10", AckType.RETRIEVED, 10),
    ("retrieved_50", AckType.RETRIEVED, 50),
    (f"actioned_{K_ANONYMITY}", AckType.ACTIONED, K_ANONYMITY),
)


async def _already_sent(session: AsyncSession, submission_id: uuid.UUID) -> set[str]:
    rows = await session.execute(
        select(SubmissionMilestone.milestone).where(
            SubmissionMilestone.submission_id == submission_id
        )
    )
    return set(rows.scalars())


async def _announce(
    session: AsyncSession, submission: Submission, milestone: str, now: dt.datetime
) -> None:
    session.add(
        SubmissionMilestone(submission_id=submission.id, milestone=milestone, reached_at=now)
    )
    hooks = (
        await session.execute(
            deliverable_webhooks().where(Webhook.org_id == await submitter_of(session, submission))
        )
    ).scalars()
    for hook in hooks:
        if hook.events and EVENT_SUBMISSION_TELEMETRY not in hook.events:
            continue
        session.add(
            WebhookDelivery(
                webhook_id=hook.id,
                event=EVENT_SUBMISSION_TELEMETRY,
                payload={
                    "event": EVENT_SUBMISSION_TELEMETRY,
                    "submission_id": str(submission.id),
                    "milestone": milestone,
                    "reached_at": now.isoformat(),
                    "detail": "see the submission's telemetry",
                },
            )
        )


async def publish_telemetry(session: AsyncSession, *, now: dt.datetime) -> int:
    """Republish each distributed submission's counts that changed enough; announce milestones.

    Returns the number of milestones announced. Commits. Every distributed
    submission is examined, because a change in reach (a firm joining a
    circle, or a circle closing) moves its counts without any receipt.
    """
    announced = 0
    distributed = await session.execute(
        select(Submission).where(Submission.distributed_at.is_not(None))
    )
    for submission in distributed.scalars().all():
        basis = await telemetry_basis(session, submission)
        if not await publish_if_changed(
            session, CountSubject.TELEMETRY, str(submission.id), basis, now=now
        ):
            continue
        sent = await _already_sent(session, submission.id)
        for milestone in _milestones_shown(basis, sent):
            await _announce(session, submission, milestone, now)
            announced += 1
    await session.commit()
    return announced


def _milestones_shown(basis: Mapping[str, str], sent: set[str]) -> list[str]:
    """Milestones not yet announced whose published count the submitter can read as theirs."""
    reach = len(basis)
    reached = []
    for milestone, ack_type, threshold in _MILESTONES:
        if milestone in sent:
            continue
        shown = _suppressed(_holding(basis, ack_type), reach=reach)
        if shown.value is not None and shown.value >= threshold:
            reached.append(milestone)
    return reached
