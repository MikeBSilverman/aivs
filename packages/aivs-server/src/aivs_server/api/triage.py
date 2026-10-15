"""Working the review queue: who has a submission, and how urgent it is.

Both change a submission, so both take its row lock (CLAUDE.md section 5), and
both are audited: a priority an editor raised or lowered is part of the record
of what the ISAC knew and did.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OperatorRole, OrgType, SsvcPriority
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.deps import AuthenticatedContext, SessionDep
from aivs_server.auth.policy import (
    can_assign_submission,
    can_review_submissions,
    can_set_priority,
    can_view_submission,
    require,
)
from aivs_server.db.clock import database_now
from aivs_server.db.models import Operator, Organization, StixObject, Submission
from aivs_server.services.bulk_validation import (
    MAX_GROUP_SIZE,
    GroupMemberNotFoundError,
    validate_group,
)
from aivs_server.services.duplicates import duplicate_candidates
from aivs_server.services.first_pass import FindingCode, first_pass
from aivs_server.services.submissions import SubmissionError, load_submission

__all__ = ["router"]

router = APIRouter(prefix="/api/v1", tags=["triage"])

#: Roles that work the queue; an assignee must hold one.
_REVIEWER_ROLES = frozenset({OperatorRole.ISAC_ANALYST, OperatorRole.ISAC_EDITOR})


class AssigneeChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: ``None`` releases the submission back to the queue.
    operator_id: uuid.UUID | None


class PriorityChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: ``None`` returns the submission to the SSVC default.
    priority: SsvcPriority | None


class DuplicateOut(BaseModel):
    match_on: str
    value: str
    stix_id: str
    submission_id: uuid.UUID | None


class GroupValidation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    submission_ids: list[uuid.UUID] = Field(min_length=1, max_length=MAX_GROUP_SIZE)


class GroupValidated(BaseModel):
    validated: list[uuid.UUID]


class TriageOut(BaseModel):
    submission_id: uuid.UUID
    assignee_operator_id: uuid.UUID | None
    priority: SsvcPriority | None


@router.put("/submissions/{submission_id}/assignee", response_model=TriageOut)
async def assign(
    submission_id: uuid.UUID,
    payload: AssigneeChange,
    ctx: AuthenticatedContext,
    session: SessionDep,
) -> TriageOut:
    submission = await _locked_visible(session, ctx, submission_id)
    require(can_assign_submission(ctx), "assign_requires_isac_reviewer")
    if payload.operator_id is not None:
        await _require_reviewer(session, payload.operator_id)
    submission.assignee_operator_id = payload.operator_id
    await record(
        session,
        action=AuditAction.SUBMISSION_ASSIGNED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={"assignee_operator_id": str(payload.operator_id) if payload.operator_id else None},
    )
    await session.commit()
    return _out(submission)


@router.put("/submissions/{submission_id}/priority", response_model=TriageOut)
async def set_priority(
    submission_id: uuid.UUID,
    payload: PriorityChange,
    ctx: AuthenticatedContext,
    session: SessionDep,
) -> TriageOut:
    submission = await _locked_visible(session, ctx, submission_id)
    require(can_set_priority(ctx), "priority_requires_isac_editor")
    previous = submission.priority
    submission.priority = payload.priority
    await record(
        session,
        action=AuditAction.SUBMISSION_PRIORITY_SET,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={
            "from": previous.value if previous else None,
            "to": payload.priority.value if payload.priority else None,
        },
    )
    await session.commit()
    return _out(submission)


@router.get("/submissions/{submission_id}/duplicates", response_model=list[DuplicateOut])
async def duplicates(
    submission_id: uuid.UUID, ctx: AuthenticatedContext, session: SessionDep
) -> list[DuplicateOut]:
    """Vulnerabilities elsewhere that share a CVE, package, platform or CWE with this one.

    The submitter sees candidates among its own submissions and what reached
    it; the ISAC's reviewers see every candidate (services.duplicates).
    """
    submission = await load_submission(session, submission_id, for_update=False)
    if submission is None or not can_view_submission(ctx, submission):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    found = await duplicate_candidates(session, ctx, submission, now=await database_now(session))
    return [
        DuplicateOut(
            match_on=c.match_on, value=c.value, stix_id=c.stix_id, submission_id=c.submission_id
        )
        for c in found
    ]


class FindingOut(BaseModel):
    code: FindingCode
    path: str
    detail: str


@router.get("/submissions/{submission_id}/first-pass", response_model=list[FindingOut])
async def first_pass_findings(
    submission_id: uuid.UUID, ctx: AuthenticatedContext, session: SessionDep
) -> list[FindingOut]:
    """The deterministic first pass over a submission, for the ISAC's reviewers (Phase O).

    Reviewers only, for now: the checks are tuned before any member is told
    anything, and anyone else gets the 404 an absent submission gets.
    """
    submission = await load_submission(session, submission_id, for_update=False)
    if submission is None or not can_review_submissions(ctx):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    objects = (
        await session.scalars(
            select(StixObject.raw).where(StixObject.submission_id == submission.id)
        )
    ).all()
    submitter = await session.get(Organization, submission.submitter_org_id)
    own_names = [submitter.name, submitter.slug] if submitter is not None else []
    return [
        FindingOut(code=finding.code, path=finding.path, detail=finding.detail)
        for finding in first_pass(objects, own_names=own_names, now=await database_now(session))
    ]


@router.post("/review/validate", response_model=GroupValidated)
async def validate_review_group(
    payload: GroupValidation, ctx: AuthenticatedContext, session: SessionDep
) -> GroupValidated:
    """Validate one review group in one audited action. An editor only.

    All or nothing: a group holding a consequential machine change, or
    submissions from two groups, is refused whole (``services.bulk_validation``).
    """
    try:
        validated = await validate_group(session, ctx, payload.submission_ids)
        await session.commit()
    except GroupMemberNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found") from None
    except SubmissionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return GroupValidated(validated=[submission.id for submission in validated])


async def _locked_visible(
    session: AsyncSession, ctx: AuthContext, submission_id: uuid.UUID
) -> Submission:
    """The submission, row-locked; 404 unless the caller may see it (SF-47)."""
    submission = await load_submission(session, submission_id, for_update=True)
    if submission is None or not can_view_submission(ctx, submission):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    return submission


async def _require_reviewer(session: AsyncSession, operator_id: uuid.UUID) -> None:
    """An assignee is an active person at the ISAC who works the queue."""
    operator = await session.get(Operator, operator_id)
    organisation = await session.get(Organization, operator.org_id) if operator else None
    is_reviewer = (
        operator is not None
        and operator.is_active
        and organisation is not None
        and organisation.org_type is OrgType.ADMIN
        and bool(_REVIEWER_ROLES & set(operator.roles))
    )
    if not is_reviewer:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="The assignee must be an active ISAC analyst or editor",
        )


def _out(submission: Submission) -> TriageOut:
    return TriageOut(
        submission_id=submission.id,
        assignee_operator_id=submission.assignee_operator_id,
        priority=submission.priority,
    )
