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

**Receipts are visible to the ISAC's reviewers, and to nobody else.** Which
firms are paying attention to which threats is an inference members must not be
able to draw about each other, and the submitter is a member: it gets
k-suppressed telemetry (``services/telemetry.py``).
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from aivs_schemas.enums import AckType, AckVia
from aivs_schemas.models import AcknowledgmentCreate, AcknowledgmentOut, ReceiptOut
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.deps import AuthenticatedContext, SessionDep
from aivs_server.auth.policy import (
    can_acknowledge_own_submission,
    can_view_submission_receipts,
    require,
)
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

    A firm that acknowledges a warning and later actions it can say both --
    the two types are recorded separately. Each is collapsed to one row per
    organisation, per submission, per day, so the timeline is preserved without
    the record being paddable. Repeating the same assertion on the same day is
    idempotent and returns the existing row.
    """
    # Unlocked: an acknowledgment is a row of its own; the submission is only read.
    submission = await load_submission(session, payload.submission_id, for_update=False)
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
    if submission.submitter_org_id == ctx.org_id:
        # 403, not 404: the submitter knows the submission exists.
        require(can_acknowledge_own_submission(ctx), "acknowledge_own_submission")
    elif not visible:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Submission not found")

    now = dt.datetime.now(dt.UTC)
    acknowledgment = Acknowledgment(
        org_id=ctx.org_id,
        submission_id=submission.id,
        ack_type=payload.ack_type,
        via=AckVia.API,
        actor_ref=ctx.actor_id,
        note=payload.note,
        # Deduplicated per day, like retrieval receipts.
        #
        # An earlier version left this null so that explicit assertions would be
        # freely repeatable. PostgreSQL treats nulls as distinct in a unique
        # constraint, so that made the constraint inert and let one member write
        # unbounded rows into two tables that have no delete path -- inflating
        # the occurrence counts in the submitter's own receipts view, which is
        # the artefact this data exists to be trusted as.
        #
        # One `acknowledged` and one `actioned` per organisation per submission
        # per day still records the timeline that matters ("when did they first
        # say they had acted"), without letting the record be padded.
        dedupe_day=now.date(),
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
    try:
        await session.commit()
    except IntegrityError:
        # Already asserted today. Idempotent rather than an error: a collector
        # retrying after a timeout should not see a failure for something it
        # successfully recorded.
        await session.rollback()
        return (
            await session.execute(
                select(Acknowledgment).where(
                    Acknowledgment.org_id == ctx.org_id,
                    Acknowledgment.submission_id == submission.id,
                    Acknowledgment.ack_type == payload.ack_type,
                    Acknowledgment.dedupe_day == now.date(),
                )
            )
        ).scalar_one()

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
    submission = await load_submission(session, submission_id, for_update=False)
    # Absent and not-permitted are reported identically, matching
    # `_require_visible_submission` and the acknowledgment gate below. Answering
    # 403 for a real id and 404 for an invented one would make this endpoint an
    # existence oracle over the submission namespace for any authenticated
    # member -- the one thing those sibling paths take care to avoid, and which
    # this endpoint would otherwise undo for the whole namespace.
    if submission is None or not can_view_submission_receipts(ctx):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Submission not found")

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
