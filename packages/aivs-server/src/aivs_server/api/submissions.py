"""Native API: the submission workflow.

Transitions are exposed as explicit verbs -- ``/submit``, ``/validate``,
``/distribute``, ``/withdraw`` -- rather than as a generic
``PATCH {"state": ...}``. Each carries different authority and different side
effects, and a single endpoint taking a target state makes that impossible to
see at the routing layer and easy to get wrong at the policy layer. Distribution
in particular is not a state change; it writes visibility rows for every member
of every target circle.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import SubmissionState
from aivs_schemas.extension.builders import (
    BundleValidationError,
    ExtensionValidationError,
    UnknownExtensionError,
)
from aivs_schemas.models import (
    DistributeRequest,
    EmbargoOut,
    FindingOut,
    FirstPassOut,
    RevealOut,
    RevealRequest,
    RevokeOut,
    RevokeRequest,
    SubmissionCreate,
    SubmissionDetail,
    SubmissionOut,
    SubmissionUpdate,
    TransitionOut,
    TransitionRequest,
    ValidateRequest,
)
from aivs_server.audit.log import AuditAction, record, record_independently
from aivs_server.auth.attribution_key import AttributionKey
from aivs_server.auth.context import AuthContext
from aivs_server.auth.deps import AttributionKeyDep, AuthenticatedContext, SessionDep, SettingsDep
from aivs_server.auth.policy import (
    can_change_embargo,
    can_reveal_submitter,
    can_review_submissions,
    can_view_submission,
    is_isac_editor,
    require,
)
from aivs_server.db.clock import database_now
from aivs_server.db.models import (
    Distribution,
    Embargo,
    Organization,
    StixObject,
    Submission,
    SubmissionTriage,
)
from aivs_server.notify.events import (
    circle_ids_for_submission,
    queue_visibility_notifications,
)
from aivs_server.services.attribution import (
    is_submitted_by,
    submissions_filed_by,
    submitter_of,
    submitter_shown_to,
)
from aivs_server.services.contributions import submit_submission
from aivs_server.services.distribution import DistributionError, distribute_submission
from aivs_server.services.embargo import EmbargoError, extend_embargo, release_embargo_now
from aivs_server.services.member_staff_reads import first_pass_of, submission_history
from aivs_server.services.revocation import revoke_contribution
from aivs_server.services.submissions import (
    STORAGE_ERRORS,
    SubmissionError,
    apply_transition,
    create_submission,
    load_submission,
    update_submission,
)
from aivs_server.services.triage import shown_findings

__all__ = ["router"]

router = APIRouter(prefix="/api/v1/submissions", tags=["submissions"])

#: Validation failures a submitter can act on. All derive from ValueError; they
#: are surfaced as 400 with their message, which describes their own content
#: back to them and discloses nothing about anyone else's.
_CLIENT_ERRORS = (
    SubmissionError,
    DistributionError,
    EmbargoError,
    BundleValidationError,
    ExtensionValidationError,
    UnknownExtensionError,
)
# Routes commit inside their try (CLAUDE.md section 5). Only create and amend
# write what the caller sent, so only they map STORAGE_ERRORS to 400. The
# workflow verbs write a reason the schema bounds and rows built from stored
# content, so a database error there is a server fault and is reported as one.


async def _require_visible_submission(
    session: SessionDep,
    ctx: AuthenticatedContext,
    submission_id: uuid.UUID,
    *,
    for_update: bool,
    key: AttributionKey,
) -> Submission:
    """Load a submission the caller may see, or 404.

    A submission the caller may not see is reported as absent rather than
    forbidden, so that identifiers cannot be probed to learn which other firms
    have filed what.

    ``for_update`` must be set by every route that changes the submission; see
    ``load_submission`` for why an unlocked read-modify-write loses updates.
    """
    submission = await load_submission(session, submission_id, for_update=for_update)
    if submission is None or not can_view_submission(
        ctx, submission, owner_is_caller=is_submitted_by(key, submission, ctx.org_id)
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Submission not found")
    return submission


async def present_submission(
    session: AsyncSession, submission: Submission, ctx: AuthContext, key: AttributionKey
) -> SubmissionOut:
    """The submission as this caller may see it.

    The submitter comes from ``attribution.submitter_shown_to``: an anonymous
    submission's is shown to the submitter alone. Without that, any ISAC reader
    saw the identity in an ordinary GET, and an audited reveal would have been
    decoration. Built field by field, so nothing about who filed it is read
    from the submission row.
    """
    fields = {
        name: getattr(submission, name)
        for name in SubmissionOut.model_fields
        if name != "submitter_org_id"
    }
    shown = await submitter_shown_to(session, key, submission, ctx)
    return SubmissionOut.model_validate({**fields, "submitter_org_id": shown})


@router.post("", status_code=status.HTTP_201_CREATED, response_model=SubmissionOut)
async def create(
    payload: SubmissionCreate,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> SubmissionOut:
    """Create a draft submission owned by the caller's organisation."""
    try:
        submission = await create_submission(
            session,
            ctx,
            title=payload.title,
            summary=payload.summary,
            tlp=payload.tlp,
            discovery_scope=payload.discovery_scope,
            distribute_anonymously=payload.distribute_anonymously,
            bundle=payload.bundle,
            filed_for=None,
            key=key,
        )
        await session.commit()
    except _CLIENT_ERRORS as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except STORAGE_ERRORS as exc:
        await session.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="Submission content rejected by storage"
        ) from exc

    await session.refresh(submission)
    return await present_submission(session, submission, ctx, key)


@router.get("", response_model=list[SubmissionOut])
async def list_submissions(
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
    state: Annotated[SubmissionState | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[SubmissionOut]:
    """List submissions the caller may see.

    A member sees their own organisation's submissions; the hosting ISAC sees
    all of them, which is what lets it work a validation queue.
    """
    query = select(Submission).order_by(Submission.created_at.desc()).limit(limit)
    if not can_review_submissions(ctx):
        query = query.where(Submission.id.in_(await submissions_filed_by(ctx.org_id)))
    if state is not None:
        query = query.where(Submission.state == state)
    rows = (await session.execute(query)).scalars().all()
    return [await present_submission(session, row, ctx, key) for row in rows]


@router.get("/{submission_id}", response_model=SubmissionDetail)
async def get_submission(
    submission_id: uuid.UUID,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> SubmissionDetail:
    """Full view of one submission, including its workflow history."""
    submission = await _require_visible_submission(
        session, ctx, submission_id, for_update=False, key=key
    )

    stix_ids = list(
        (
            await session.execute(
                select(StixObject.stix_id)
                .where(StixObject.submission_id == submission.id)
                .order_by(StixObject.stix_id)
            )
        )
        .scalars()
        .all()
    )
    circle_ids = list(
        (
            await session.execute(
                select(Distribution.circle_id)
                .where(Distribution.submission_id == submission.id)
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    embargo = (
        await session.execute(select(Embargo).where(Embargo.submission_id == submission.id))
    ).scalar_one_or_none()

    transitions = await submission_history(session, ctx, submission.id)

    return SubmissionDetail(
        **(await present_submission(session, submission, ctx, key)).model_dump(),
        object_count=len(stix_ids),
        stix_ids=stix_ids,
        circle_ids=circle_ids,
        transitions=[TransitionOut.model_validate(t) for t in transitions],
        embargo=EmbargoOut.model_validate(embargo) if embargo else None,
        first_pass=_first_pass(ctx, await first_pass_of(session, ctx, submission.id)),
    )


def _first_pass(ctx: AuthContext, row: SubmissionTriage | None) -> FirstPassOut | None:
    """The latest read, with only the codes the caller may be shown (the oracle rule)."""
    if row is None:
        return None
    return FirstPassOut(
        disposition=row.disposition,
        findings=[
            FindingOut.model_validate(finding)
            for finding in shown_findings(row, reviewer=can_review_submissions(ctx))
        ],
        rules_version=row.rules_version,
        at=row.created_at,
    )


@router.patch("/{submission_id}", response_model=SubmissionOut)
async def amend(
    submission_id: uuid.UUID,
    payload: SubmissionUpdate,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> SubmissionOut:
    """Amend a draft. Refused once the submission has left the submitter."""
    submission = await _require_visible_submission(
        session, ctx, submission_id, for_update=True, key=key
    )
    try:
        await update_submission(
            session, ctx, submission, changes=payload.model_dump(exclude_none=True), key=key
        )
        await session.commit()
    except _CLIENT_ERRORS as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except STORAGE_ERRORS as exc:
        await session.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="Submission content rejected by storage"
        ) from exc

    await session.refresh(submission)
    return await present_submission(session, submission, ctx, key)


async def _refused(
    ctx: AuthContext, submission_id: uuid.UUID, verb: str, exc: Exception
) -> HTTPException:
    """The editor's 409, recorded with its reason.

    Independently of the request's transaction, which is rolled back: a
    content rule's refusal at validate or distribution is evidence of what the
    ISAC declined to publish and why, and a 409 alone left no trace of it.
    """
    await record_independently(
        action=AuditAction.SUBMISSION_TRANSITION_REFUSED,
        ctx=ctx,
        outcome="failure",
        resource_type="submission",
        resource_id=str(submission_id),
        details={"verb": verb, "reason": str(exc)},
    )
    return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))


async def _transition(
    session: SessionDep,
    ctx: AuthenticatedContext,
    submission_id: uuid.UUID,
    target: SubmissionState,
    reason: str | None,
    key: AttributionKey,
) -> Submission:
    submission = await _require_visible_submission(
        session, ctx, submission_id, for_update=True, key=key
    )
    try:
        await apply_transition(session, ctx, submission, target, reason=reason, key=key)
        await session.commit()
    except _CLIENT_ERRORS as exc:
        raise await _refused(ctx, submission_id, target.value, exc) from exc
    await session.refresh(submission)
    return submission


@router.post("/{submission_id}/submit", response_model=SubmissionOut)
async def submit(
    submission_id: uuid.UUID,
    payload: TransitionRequest,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
    settings: SettingsDep,
) -> SubmissionOut:
    """Hand a draft to the hosting ISAC for review.

    A short contribution on public content in a circle an editor opened to
    post-moderation is published at once instead (``services.contributions``).
    """
    submission = await _require_visible_submission(
        session, ctx, submission_id, for_update=True, key=key
    )
    try:
        await submit_submission(
            session,
            ctx,
            submission,
            reason=payload.reason,
            hourly_limit=settings.contribution_hourly_limit,
            now=await database_now(session),
            key=key,
        )
        await session.commit()
    except _CLIENT_ERRORS as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await session.refresh(submission)
    return await present_submission(session, submission, ctx, key)


@router.post("/{submission_id}/validate", response_model=SubmissionOut)
async def validate(
    submission_id: uuid.UUID,
    payload: ValidateRequest,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> SubmissionOut:
    """Accept a submission as fit to share. Hosting ISAC only.

    This is the human checkpoint that keeps AIVS clear of the
    coordinated-disclosure consent problem: content reaches members because the
    ISAC decided it should, never merely because a member uploaded it. The
    content rules (owner-only versioning, the disclosure split, TLP inheritance,
    the AI gate) are checked here and answer 409 with the reason.
    """
    submission = await _require_visible_submission(
        session, ctx, submission_id, for_update=True, key=key
    )
    try:
        await apply_transition(
            session,
            ctx,
            submission,
            SubmissionState.VALIDATED,
            reason=payload.reason,
            acknowledged_changes=frozenset(payload.acknowledge),
            key=key,
        )
        await session.commit()
    except _CLIENT_ERRORS as exc:
        raise await _refused(ctx, submission_id, "validated", exc) from exc
    await session.refresh(submission)
    return await present_submission(session, submission, ctx, key)


@router.post("/{submission_id}/withdraw", response_model=SubmissionOut)
async def withdraw(
    submission_id: uuid.UUID,
    payload: TransitionRequest,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> SubmissionOut:
    """Withdraw a submission that has not yet been distributed.

    Distributed content cannot be withdrawn: members already hold it, and
    pretending otherwise would be a false promise.
    """
    withdrawn = await _transition(
        session, ctx, submission_id, SubmissionState.WITHDRAWN, payload.reason, key=key
    )
    return await present_submission(session, withdrawn, ctx, key)


@router.post("/{submission_id}/distribute", response_model=SubmissionOut)
async def distribute(
    submission_id: uuid.UUID,
    payload: DistributeRequest,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> SubmissionOut:
    """Release a validated submission into circles. Hosting ISAC only.

    Writes visibility rows and the state change in one transaction, so a member
    polling concurrently sees the whole batch or none of it. A ``release_at`` in
    the future produces an embargo that holds without any scheduler running.
    """
    submission = await _require_visible_submission(
        session, ctx, submission_id, for_update=True, key=key
    )

    require(is_isac_editor(ctx), "distribute_requires_isac_editor")

    try:
        result = await distribute_submission(
            session,
            ctx,
            submission,
            circle_ids=payload.circle_ids,
            release_at=payload.release_at,
            key=key,
        )
        await apply_transition(
            session, ctx, submission, SubmissionState.DISTRIBUTED, reason=payload.reason, key=key
        )
        # Queued in the same transaction as the visibility rows. Nothing is
        # queued for an embargoed distribution: the content is not readable yet,
        # so the notification goes out when the embargo releases instead. The
        # instant is the distribution's stamp, on the database's clock, which
        # memberships are bounded by (see db.clock).
        if not result.embargoed:
            await queue_visibility_notifications(
                session,
                key=key,
                submission_id=submission.id,
                circle_ids=list(payload.circle_ids),
                visible_at=result.date_added,
                now=result.date_added,
            )
        # One commit for the visibility rows, the state change, the notifications,
        # and the audit trail.
        await session.commit()
    except _CLIENT_ERRORS as exc:
        raise await _refused(ctx, submission_id, "distributed", exc) from exc
    await session.refresh(submission)
    return await present_submission(session, submission, ctx, key)


@router.post("/{submission_id}/embargo/release", response_model=SubmissionOut)
async def release_embargo(
    submission_id: uuid.UUID,
    payload: TransitionRequest,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> SubmissionOut:
    """Release an embargoed submission immediately. Hosting ISAC only.

    The operational escape hatch: when a finding starts being exploited in the
    wild, waiting for a timer set days ago is the wrong answer.
    """
    submission = await _require_visible_submission(
        session, ctx, submission_id, for_update=True, key=key
    )
    require(can_change_embargo(ctx), "embargo_release_requires_isac_editor")

    try:
        await release_embargo_now(
            session, ctx, key=key, submission_id=submission.id, reason=payload.reason
        )
        # Early release is the second moment content becomes visible, and the
        # one where telling members promptly matters most: the reason to release
        # early is that something is being exploited now. On the database's
        # clock, because memberships are bounded by it (see db.clock).
        released_at = await database_now(session)
        await queue_visibility_notifications(
            session,
            key=key,
            submission_id=submission.id,
            circle_ids=await circle_ids_for_submission(session, submission.id),
            visible_at=released_at,
            now=released_at,
        )
        await session.commit()
    except _CLIENT_ERRORS as exc:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    await session.refresh(submission)
    return await present_submission(session, submission, ctx, key)


@router.post("/{submission_id}/embargo/extend", response_model=SubmissionOut)
async def extend_embargo_endpoint(
    submission_id: uuid.UUID,
    payload: DistributeRequest,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> SubmissionOut:
    """Push an embargo further out. Hosting ISAC only.

    Reuses ``DistributeRequest`` for its ``release_at`` validation; the circle
    list it carries is ignored, since extension does not change who receives.
    """
    submission = await _require_visible_submission(
        session, ctx, submission_id, for_update=True, key=key
    )
    require(can_change_embargo(ctx), "embargo_extend_requires_isac_editor")

    if payload.release_at is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="release_at is required to extend an embargo"
        )

    try:
        await extend_embargo(
            session,
            ctx,
            submission_id=submission.id,
            release_at=payload.release_at,
            reason=payload.reason,
        )
        await session.commit()
    except _CLIENT_ERRORS as exc:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    await session.refresh(submission)
    return await present_submission(session, submission, ctx, key)


@router.post("/{submission_id}/revoke", response_model=RevokeOut)
async def revoke(
    submission_id: uuid.UUID,
    payload: RevokeRequest,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> RevokeOut:
    """Revoke content that was published without review. An ISAC editor only.

    Members receive a newer, ``revoked`` version of each object
    (``services.revocation``); nothing they already hold is edited in place.
    """
    submission = await _require_visible_submission(
        session, ctx, submission_id, for_update=True, key=key
    )
    try:
        result = await revoke_contribution(session, ctx, submission, key=key, reason=payload.reason)
        await session.commit()
    except SubmissionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return RevokeOut(
        submission_id=submission.id,
        revoked_ids=result.revoked_ids,
        circle_count=result.circle_count,
        date_added=result.date_added,
    )


@router.post("/{submission_id}/reveal", response_model=RevealOut)
async def reveal_submitter(
    submission_id: uuid.UUID,
    payload: RevealRequest,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> RevealOut:
    """Name the submitter of an anonymous submission. An ISAC editor only.

    The one act that breaks the promise the platform made the submitter, so it
    is its own audited action with a stated reason, distinguishable in the log
    from routine review -- which, before this existed, it was not: any ISAC
    reader saw the identity in an ordinary GET. The audit row records the reason
    and *not* the identity revealed: the log is read by auditors whose scope
    must not include every anonymous submitter by way of the audit trail.
    """
    submission = await _require_visible_submission(
        session, ctx, submission_id, for_update=False, key=key
    )
    require(can_reveal_submitter(ctx), "reveal_requires_isac_editor")
    if not submission.distribute_anonymously:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="This submission is not anonymous; its submitter is in the ordinary record",
        )

    organisation = await session.get(Organization, await submitter_of(session, submission))
    if organisation is None:  # pragma: no cover - foreign key guarantees it
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

    await record(
        session,
        action=AuditAction.ANONYMITY_REVEALED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={"reason": payload.reason},
    )
    await session.commit()
    return RevealOut(
        submission_id=submission.id,
        submitter_org_id=organisation.id,
        submitter_slug=organisation.slug,
    )
