"""The ISAC's review queue, grouped by who filed it and ordered by priority.

Grouped by source identity -- the submitting organisation, and whether a
person or an automation filed it -- because that is how an analyst works a
queue: a KEV script's forty enrichments are one kind of work and a member's
pre-CVE finding another. Within a group the most urgent comes first, by the
editor's priority where one is set and CISA's SSVC decision otherwise, with the
factors beside it so the ranking can be argued with.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import SsvcPriority, SubmissionSource, SubmissionState
from aivs_server.db.models import Operator, Organization, StixObject, Submission
from aivs_server.services.priority import PriorityAssessment, assess_priority, decision_points

__all__ = ["QueueItem", "ReviewGroup", "queued_for_review"]

#: Waiting for the ISAC: filed and not yet decided, or decided and not yet sent.
_QUEUED = (SubmissionState.SUBMITTED, SubmissionState.VALIDATED)

#: Sort position of an effective priority, most urgent first; unknown last.
_URGENCY: dict[SsvcPriority | None, int] = {
    SsvcPriority.ACT: 0,
    SsvcPriority.ATTEND: 1,
    SsvcPriority.TRACK_STAR: 2,
    SsvcPriority.TRACK: 3,
    None: 4,
}


@dataclass(frozen=True)
class QueueItem:
    submission: Submission
    #: The editor's priority if set, else the SSVC default, else ``None``.
    priority: SsvcPriority | None
    #: ``"editor"`` or ``"ssvc"``; ``None`` when there is no priority.
    priority_source: str | None
    default: PriorityAssessment
    assignee: str | None


@dataclass(frozen=True)
class ReviewGroup:
    organisation: str
    source: SubmissionSource
    items: Sequence[QueueItem]


async def queued_for_review(
    session: AsyncSession, *, mission_impact: str, limit: int = 200
) -> list[ReviewGroup]:
    """Every queued submission, grouped and ordered. The ISAC's view: no filtering."""
    submissions = list(
        (
            await session.execute(
                select(Submission)
                .where(Submission.state.in_(_QUEUED))
                .order_by(Submission.created_at)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    points = await _points_by_submission(session, [s.id for s in submissions])
    names = await _organisation_names(session, {s.submitter_org_id for s in submissions})
    assignees = await _assignee_names(session, {s.assignee_operator_id for s in submissions})

    grouped: dict[tuple[str, SubmissionSource], list[QueueItem]] = defaultdict(list)
    for submission in submissions:
        default = assess_priority(points.get(submission.id, []), mission_impact=mission_impact)
        grouped[(names[submission.submitter_org_id], submission.source)].append(
            _item(submission, default, assignees)
        )
    return [
        ReviewGroup(organisation, source, sorted(items, key=_ordering))
        for (organisation, source), items in sorted(grouped.items(), key=lambda kv: kv[0])
    ]


def _item(
    submission: Submission, default: PriorityAssessment, assignees: Mapping[uuid.UUID, str]
) -> QueueItem:
    if submission.priority is not None:
        priority, source = submission.priority, "editor"
    elif default.decision is not None:
        priority, source = default.decision, "ssvc"
    else:
        priority, source = None, None
    assignee = (
        assignees.get(submission.assignee_operator_id) if submission.assignee_operator_id else None
    )
    return QueueItem(submission, priority, source, default, assignee)


def _ordering(item: QueueItem) -> tuple[int, Any]:
    return (_URGENCY[item.priority], item.submission.created_at)


async def _points_by_submission(
    session: AsyncSession, submission_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, list[dict[str, str]]]:
    rows = (
        await session.execute(
            select(StixObject.submission_id, StixObject.raw).where(
                StixObject.submission_id.in_(submission_ids), StixObject.type == "vulnerability"
            )
        )
    ).all()
    found: dict[uuid.UUID, list[dict[str, str]]] = defaultdict(list)
    for submission_id, raw in rows:
        found[submission_id].extend(decision_points([raw]))
    return found


async def _organisation_names(
    session: AsyncSession, org_ids: set[uuid.UUID]
) -> dict[uuid.UUID, str]:
    rows = (
        await session.execute(
            select(Organization.id, Organization.name).where(Organization.id.in_(org_ids))
        )
    ).all()
    return {row[0]: row[1] for row in rows}


async def _assignee_names(
    session: AsyncSession, operator_ids: set[uuid.UUID | None]
) -> dict[uuid.UUID, str]:
    wanted = {operator_id for operator_id in operator_ids if operator_id is not None}
    if not wanted:
        return {}
    rows = (
        await session.execute(
            select(Operator.id, Operator.display_name).where(Operator.id.in_(wanted))
        )
    ).all()
    return {row[0]: row[1] for row in rows}
