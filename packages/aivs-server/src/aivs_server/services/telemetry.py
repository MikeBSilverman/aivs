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

What this does not stop: reading the same count twice and seeing it move tells
the submitter that *some* firm acted in between. Which one is not shown, and a
live counter cannot avoid that much.

Counters that depend on later phases (opinions on its content, posture
outcomes, citations by an ISAC advisory) are named as not yet available rather
than shown as zero, so an early submitter does not conclude it is broken.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Select, and_, distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import AckType, OrgStatus
from aivs_server.db.models import (
    Acknowledgment,
    Circle,
    CircleMembership,
    Distribution,
    Organization,
    Submission,
    SubmissionMilestone,
    TaxiiCollection,
    Webhook,
    WebhookDelivery,
)
from aivs_server.services.ownership import ISAC_OWNER_TYPES

__all__ = [
    "EVENT_SUBMISSION_TELEMETRY",
    "K_ANONYMITY",
    "Count",
    "Telemetry",
    "counted_organisations",
    "k_anonymous",
    "queue_milestones",
    "submission_telemetry",
]

#: The smallest group a count may describe, everywhere (plan, Appendix F rule 11).
K_ANONYMITY: Final[int] = 5

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


def _reachable(submission: Submission) -> Select[tuple[uuid.UUID]]:
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
            _is_counted(CircleMembership.org_id, submission.submitter_org_id),
        )
    )


async def _reach(session: AsyncSession, submission: Submission) -> int:
    reachable = _reachable(submission).subquery()
    return int(await session.scalar(select(func.count(distinct(reachable.c.org_id)))) or 0)


async def _engaged(session: AsyncSession, submission: Submission, ack_type: AckType) -> int:
    """Organisations in reach that did this: a count is a part of reach, or reach minus it lies."""
    return int(
        await session.scalar(
            select(func.count(distinct(Acknowledgment.org_id))).where(
                Acknowledgment.submission_id == submission.id,
                Acknowledgment.ack_type == ack_type,
                Acknowledgment.org_id.in_(_reachable(submission)),
            )
        )
        or 0
    )


async def submission_telemetry(session: AsyncSession, submission: Submission) -> Telemetry:
    """What the submitter may see about its own submission. Reads only."""
    reach = await _reach(session, submission)
    counts = {
        ack_type: _suppressed(await _engaged(session, submission, ack_type), reach=reach)
        for ack_type in (AckType.RETRIEVED, AckType.ACKNOWLEDGED, AckType.ACTIONED)
    }
    return Telemetry(
        submission_id=submission.id,
        distributed=reach > 0 or submission.distributed_at is not None,
        reach=_reach_count(reach),
        retrieved=counts[AckType.RETRIEVED],
        acknowledged=counts[AckType.ACKNOWLEDGED],
        actioned=counts[AckType.ACTIONED],
    )


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


async def _recently_engaged(session: AsyncSession, since: dt.datetime) -> list[Submission]:
    ids = select(Acknowledgment.submission_id).where(Acknowledgment.created_at >= since)
    return list(
        (await session.execute(select(Submission).where(Submission.id.in_(ids)))).scalars().all()
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
            select(Webhook).where(
                Webhook.org_id == submission.submitter_org_id, Webhook.is_active.is_(True)
            )
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


async def queue_milestones(
    session: AsyncSession, *, now: dt.datetime, lookback: dt.timedelta
) -> int:
    """Announce each milestone crossed since ``lookback``, once. Commits.

    Only submissions with a receipt inside the lookback are examined, so the
    cost follows activity, not the archive.
    """
    announced = 0
    for submission in await _recently_engaged(session, now - lookback):
        for milestone in await _milestones_reached(session, submission):
            await _announce(session, submission, milestone, now)
            announced += 1
    await session.commit()
    return announced


async def _milestones_reached(session: AsyncSession, submission: Submission) -> list[str]:
    """Milestones not yet announced whose count the submitter can now read as at least theirs."""
    reach = await _reach(session, submission)
    sent = await _already_sent(session, submission.id)
    reached = []
    for milestone, ack_type, threshold in _MILESTONES:
        if milestone in sent:
            continue
        shown = _suppressed(await _engaged(session, submission, ack_type), reach=reach)
        if shown.value is not None and shown.value >= threshold:
            reached.append(milestone)
    return reached
