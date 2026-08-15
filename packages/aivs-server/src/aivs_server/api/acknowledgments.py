"""Native API: acknowledgments and receipts.

The evidentiary surface. Retrieval receipts are written by the server when
content is actually delivered; acknowledgments are explicit member assertions on
top of that. Together they answer the question an ISAC exists to be able to
answer -- "we warned you, and here is when your systems collected it" -- which is
a compliance artefact a member firm can use, not merely telemetry the ISAC keeps.

Two rules shape this module:

**A member cannot assert that they retrieved something.** ``retrieved`` is
written only by the server, on actual delivery. Accepting it here would let a
firm manufacture evidence of a delivery that never happened, which is precisely
the record this table exists to be trustworthy about.

**Receipts are visible to the submitter and the hosting ISAC, and to nobody
else.** Which firms are paying attention to which threats is an inference other
members must not be able to draw about each other.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from aivs_schemas.enums import AckType, AckVia
from aivs_schemas.models import AcknowledgmentCreate, AcknowledgmentOut, ReceiptOut
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.deps import AuthenticatedContext, SessionDep
from aivs_server.auth.policy import can_view_submission_receipts, require
from aivs_server.db.models import Acknowledgment, Organization
from aivs_server.services.submissions import load_submission

__all__ = ["router"]

router = APIRouter(prefix="/api/v1", tags=["acknowledgments"])


@router.post(
    "/acknowledgments",
    status_code=status.HTTP_201_CREATED,
    response_model=AcknowledgmentOut,
)
async def acknowledge(
    payload: AcknowledgmentCreate, ctx: AuthenticatedContext, session: SessionDep
) -> Acknowledgment:
    """Record that the caller's organisation acknowledged or actioned a submission.

    Repeatable by design: a firm that acknowledges a warning and later actions it
    should be able to say both, and the timeline of those assertions is part of
    the record. Only automatic retrieval receipts are collapsed to one row per
    day, and those are written by the server rather than here.
    """
    submission = await load_submission(session, payload.submission_id)
    if submission is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Submission not found")

    # A member may acknowledge only content that has actually been distributed to
    # them. Acknowledging a draft they cannot see would be evidence of nothing,
    # and permitting it by id would leak that the id exists.
    visible = await session.scalar(
        select(func.count())
        .select_from(Acknowledgment)
        .where(
            Acknowledgment.submission_id == submission.id,
            Acknowledgment.org_id == ctx.org_id,
            Acknowledgment.ack_type == AckType.RETRIEVED,
        )
    )
    if not visible and submission.submitter_org_id != ctx.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Submission not found")

    acknowledgment = Acknowledgment(
        org_id=ctx.org_id,
        submission_id=submission.id,
        ack_type=payload.ack_type,
        via=AckVia.API,
        actor_ref=ctx.actor_id,
        note=payload.note,
        # Null so the daily-dedupe constraint does not apply: explicit member
        # assertions are deliberately repeatable, unlike retrieval receipts.
        dedupe_day=None,
    )
    session.add(acknowledgment)

    await record(
        session,
        action=AuditAction.ACK_RECORDED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={"ack_type": payload.ack_type.value},
    )
    await session.commit()
    await session.refresh(acknowledgment)
    return acknowledgment


@router.get("/submissions/{submission_id}/receipts", response_model=list[ReceiptOut])
async def receipts(
    submission_id: uuid.UUID, ctx: AuthenticatedContext, session: SessionDep
) -> list[ReceiptOut]:
    """Who received, acknowledged, and actioned a submission.

    Aggregated per organisation and engagement type: first occurrence, latest,
    and a count. That shape answers the regulatory question ("when did they first
    have it") without reproducing every individual poll.
    """
    submission = await load_submission(session, submission_id)
    if submission is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Submission not found")

    require(
        can_view_submission_receipts(ctx, submission),
        "receipts_visible_to_submitter_and_isac_only",
    )

    rows = (
        await session.execute(
            select(
                Acknowledgment.org_id,
                Organization.slug,
                Acknowledgment.ack_type,
                Acknowledgment.via,
                func.min(Acknowledgment.created_at).label("first_at"),
                func.max(Acknowledgment.created_at).label("latest_at"),
                func.count().label("occurrences"),
            )
            .join(Organization, Organization.id == Acknowledgment.org_id)
            .where(Acknowledgment.submission_id == submission_id)
            .group_by(
                Acknowledgment.org_id,
                Organization.slug,
                Acknowledgment.ack_type,
                Acknowledgment.via,
            )
            .order_by(Organization.slug, Acknowledgment.ack_type)
        )
    ).all()

    return [
        ReceiptOut(
            org_id=row.org_id,
            org_slug=row.slug,
            ack_type=row.ack_type,
            via=row.via,
            first_at=row.first_at,
            latest_at=row.latest_at,
            occurrences=row.occurrences,
        )
        for row in rows
    ]
