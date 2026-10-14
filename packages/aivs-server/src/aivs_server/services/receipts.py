"""Retrieval receipts -- the evidence that a member actually collected a warning.

When a member's client pulls content, AIVS records that it did. This is the
table an ISAC points at to answer "we warned you, and here is when your systems
collected it", and it is a large part of why a member firm would pay for the
service at all: it is a compliance artefact, not just telemetry.

Receipts are deduplicated to one row per organisation, per submission, per
channel (TAXII, API, portal), per day. The channel is in the key because a
person reading a warning in the portal is a different fact from the member's
collector having polled it, and an auditor asks about both (SF-51).
A member polling every minute would otherwise write over a thousand rows a day
per object, which costs storage forever (the table is append-only) and buries
the signal an auditor is looking for. Daily granularity answers "did they
collect it, and when did they first do so" -- which is the question that matters
-- without recording every poll.

The insert uses ``ON CONFLICT DO NOTHING`` against the deduplication constraint,
so concurrent polls from the same member race harmlessly rather than raising.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterable

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import AckType, AckVia
from aivs_server.db.models import Acknowledgment

__all__ = ["record_retrievals"]


async def record_retrievals(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    submission_ids: Iterable[uuid.UUID],
    via: AckVia,
    actor_ref: str | None,
    now: dt.datetime | None = None,
) -> int:
    """Record that ``org_id`` retrieved content from the given submissions.

    Returns the number of rows actually written, which is the number of
    submissions this organisation had not already been recorded as retrieving
    today. Callers do not need to deduplicate beforehand.
    """
    unique_ids = sorted(set(submission_ids))
    if not unique_ids:
        return 0

    now = now or dt.datetime.now(dt.UTC)
    today = now.date()

    rows = [
        {
            "org_id": org_id,
            "submission_id": submission_id,
            "ack_type": AckType.RETRIEVED,
            "via": via,
            "actor_ref": actor_ref,
            "dedupe_day": today,
        }
        for submission_id in unique_ids
    ]

    statement = (
        insert(Acknowledgment)
        .values(rows)
        .on_conflict_do_nothing(constraint="uq_acknowledgments_daily_dedupe")
    )
    # RETURNING id makes the count exact and dialect-independent, rather than
    # relying on a driver-specific rowcount after ON CONFLICT DO NOTHING.
    result = await session.execute(statement.returning(Acknowledgment.id))
    return len(result.scalars().all())
