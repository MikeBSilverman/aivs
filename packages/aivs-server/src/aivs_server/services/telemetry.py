"""Telemetry back to the submitter: what happened to what you shared.

The reciprocity signal an ISAC has never had (plan, Phase E). Every retrieval
and acknowledgment is already a row; the submitter never saw any of it, which
is why members stop posting. This turns those rows into counts for the
submitter alone, with no analyst in the loop.

Counts, never lists, and never a count small enough to point at someone:
- fewer than K organisations could see it: every number is withheld;
- otherwise zero and any count of at least K are exact, and one to K-1 reads
  "fewer than K", which tells the submitter only that someone engaged.

Counters that depend on later phases (opinions on its content, posture
outcomes, citations by an ISAC advisory) are named as not yet available rather
than shown as zero, so an early submitter does not conclude it is broken.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import and_, distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import AckType, OrgType
from aivs_server.db.models import (
    Acknowledgment,
    CircleMembership,
    Distribution,
    Organization,
    Submission,
    SubmissionMilestone,
    Webhook,
    WebhookDelivery,
)

__all__ = [
    "EVENT_SUBMISSION_TELEMETRY",
    "K_ANONYMITY",
    "Count",
    "Telemetry",
    "queue_milestones",
    "submission_telemetry",
]

#: The smallest group a count may describe, everywhere (plan, Appendix F rule 11).
K_ANONYMITY: Final[int] = 5

EVENT_SUBMISSION_TELEMETRY: Final[str] = "submission.telemetry"

#: Named so a reader knows what is coming, rather than reading a zero.
LATER: Final[tuple[str, ...]] = (
    "opinions on the content (with contributions on public CVEs)",
    "posture outcomes such as fixed or not affected (with member posture)",
    "citations by an ISAC advisory (with text documents)",
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


def _suppressed(value: int, *, reach: int) -> Count:
    if reach < K_ANONYMITY:
        return Count(None, f"shown once at least {K_ANONYMITY} organisations could see it")
    if 0 < value < K_ANONYMITY:
        return Count(None, f"fewer than {K_ANONYMITY}")
    return Count(value)


def _is_counted(org_id: Any, submitter_org_id: uuid.UUID) -> Any:
    """Organisations that count as reach: not the submitter, not the ISAC itself."""
    return and_(
        org_id != submitter_org_id,
        org_id.in_(select(Organization.id).where(Organization.org_type != OrgType.ADMIN)),
    )


async def _reach(session: AsyncSession, submission: Submission) -> int:
    """Organisations whose membership covered the moment the content became visible."""
    covered = and_(
        CircleMembership.circle_id == Distribution.circle_id,
        CircleMembership.joined_at <= Distribution.date_added,
        or_(
            CircleMembership.left_at.is_(None),
            CircleMembership.left_at > Distribution.date_added,
        ),
    )
    return int(
        await session.scalar(
            select(func.count(distinct(CircleMembership.org_id)))
            .select_from(Distribution)
            .join(CircleMembership, covered)
            .where(
                Distribution.submission_id == submission.id,
                _is_counted(CircleMembership.org_id, submission.submitter_org_id),
            )
        )
        or 0
    )


async def _engaged(session: AsyncSession, submission: Submission, ack_type: AckType) -> int:
    return int(
        await session.scalar(
            select(func.count(distinct(Acknowledgment.org_id))).where(
                Acknowledgment.submission_id == submission.id,
                Acknowledgment.ack_type == ack_type,
                _is_counted(Acknowledgment.org_id, submission.submitter_org_id),
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
        reach=_suppressed(reach, reach=reach),
        retrieved=counts[AckType.RETRIEVED],
        acknowledged=counts[AckType.ACKNOWLEDGED],
        actioned=counts[AckType.ACTIONED],
    )


# ---------------------------------------------------------------------------
# Milestones: the submitter learns the same day that it mattered
# ---------------------------------------------------------------------------
#: (milestone, ack type, threshold). "first" milestones fire only once reach is
#: at least K, so the event itself never singles anyone out.
_MILESTONES: Final[tuple[tuple[str, AckType, int], ...]] = (
    ("first_retrieval", AckType.RETRIEVED, 1),
    ("retrieved_10", AckType.RETRIEVED, 10),
    ("retrieved_50", AckType.RETRIEVED, 50),
    ("first_actioned", AckType.ACTIONED, 1),
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
        reach = await _reach(session, submission)
        if reach < K_ANONYMITY:
            continue
        sent = await _already_sent(session, submission.id)
        for milestone, ack_type, threshold in _MILESTONES:
            if milestone in sent:
                continue
            if await _engaged(session, submission, ack_type) >= threshold:
                await _announce(session, submission, milestone, now)
                announced += 1
    await session.commit()
    return announced
