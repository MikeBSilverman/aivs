"""A member's own assertion about a submission: acknowledged, or actioned.

One function for every door that writes one -- the API and the portal's
"we've acted on this" -- so the rule about who may assert what about which
submission is written once (CLAUDE.md section 5, "a shortcut inherits every
check of the path it shortcuts").

The rule: a member asserts only about content the server has recorded
reaching it (a server-written ``retrieved`` receipt), or about its own
submission when it is ISAC staff. ``retrieved`` itself is never asserted: the
server writes it on delivery, and accepting it from a member would let a firm
manufacture evidence of a delivery that never happened.

One row per organisation, submission, type, channel and day; a repeat is
idempotent and returns the row already there.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import AckType, AckVia
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import can_acknowledge_own_submission, require
from aivs_server.db.models import Acknowledgment, Submission
from aivs_server.services.attribution import is_submitted_by

__all__ = ["AssertionNotFoundError", "assert_receipt", "retrieved_submission_ids"]


class AssertionNotFoundError(LookupError):
    """Nothing the caller may assert about: absent, or never delivered to it."""


async def assert_receipt(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    *,
    ack_type: AckType,
    via: AckVia,
    note: str | None,
    now: dt.datetime,
) -> Acknowledgment:
    """Record ``ack_type`` for the caller's organisation, or return today's. Commits.

    Commits because the idempotent path needs a rollback to recover from the
    unique key, and a rollback would discard a caller's other pending work.
    """
    if ack_type is AckType.RETRIEVED:
        msg = "retrieved is written by the server on delivery, never asserted"
        raise ValueError(msg)
    await _require_assertable(session, ctx, submission)
    # Held before the write: the rollback on a repeat expires every loaded
    # object, and reading an attribute after it would be a lazy load.
    submission_id = submission.id
    acknowledgment = Acknowledgment(
        org_id=ctx.org_id,
        submission_id=submission_id,
        ack_type=ack_type,
        via=via,
        actor_ref=ctx.actor_id,
        note=note,
        dedupe_day=now.date(),
    )
    session.add(acknowledgment)
    try:
        # The audit write flushes the row, so the unique key can fire here as
        # well as at commit; both are the same repeat.
        await record(
            session,
            action=AuditAction.ACK_RECORDED,
            ctx=ctx,
            resource_type="submission",
            resource_id=str(submission_id),
            details={"ack_type": ack_type.value},
        )
        await session.commit()
    except IntegrityError:
        # Already asserted today through this channel. A collector retrying
        # after a timeout should not see a failure for something it recorded.
        await session.rollback()
        return await _todays(session, ctx.org_id, submission_id, ack_type, via, now)
    await session.refresh(acknowledgment)
    return acknowledgment


async def retrieved_submission_ids(
    session: AsyncSession, org_id: uuid.UUID, submission_ids: frozenset[uuid.UUID]
) -> frozenset[uuid.UUID]:
    """Which of ``submission_ids`` the server has recorded reaching ``org_id``."""
    if not submission_ids:
        return frozenset()
    rows = await session.scalars(
        select(Acknowledgment.submission_id)
        .where(
            Acknowledgment.org_id == org_id,
            Acknowledgment.submission_id.in_(submission_ids),
            Acknowledgment.ack_type == AckType.RETRIEVED,
        )
        .distinct()
    )
    return frozenset(rows)


async def _require_assertable(
    session: AsyncSession, ctx: AuthContext, submission: Submission
) -> None:
    if await is_submitted_by(session, submission, ctx.org_id):
        # 403, not 404: the submitter knows the submission exists.
        require(can_acknowledge_own_submission(ctx), "acknowledge_own_submission")
        return
    retrieved = await session.scalar(
        select(func.count())
        .select_from(Acknowledgment)
        .where(
            Acknowledgment.submission_id == submission.id,
            Acknowledgment.org_id == ctx.org_id,
            Acknowledgment.ack_type == AckType.RETRIEVED,
        )
    )
    if not retrieved:
        raise AssertionNotFoundError(submission.id)


async def _todays(
    session: AsyncSession,
    org_id: uuid.UUID,
    submission_id: uuid.UUID,
    ack_type: AckType,
    via: AckVia,
    now: dt.datetime,
) -> Acknowledgment:
    # `via` is part of the key: without it, a portal assertion and an API one
    # on the same day were two rows here and this read failed with a 500.
    return (
        await session.execute(
            select(Acknowledgment).where(
                Acknowledgment.org_id == org_id,
                Acknowledgment.submission_id == submission_id,
                Acknowledgment.ack_type == ack_type,
                Acknowledgment.via == via,
                Acknowledgment.dedupe_day == now.date(),
            )
        )
    ).scalar_one()
