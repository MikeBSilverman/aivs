"""Contentless notifications: "there is something for you; come and get it".

Latency is most of what pre-CVE sharing is for. A member who learns about an
actively exploited finding on their next fifteen-minute poll has a materially
worse product than one that is told. But a notification is an outbound message
to an endpoint outside the ISAC's control, and that shapes what it may say.

**Notifications carry identifiers and nothing else.** No title, no TLP marking,
no summary, no object content. The member is told that submission *X* became
visible to them in collection *Y*, and polls TAXII to collect it. Three things
follow from that, and they are the reason for the design rather than
consequences of it:

* Nothing that lands in a third-party log, an email-to-webhook bridge, or a
  chat integration carries intelligence. The worst case for a leaked or
  misrouted notification is that someone learns a submission exists.
* There are no TLP handling obligations on the notification itself, because it
  conveys nothing markable. A payload carrying "TLP:RED — credential theft in
  X" would need the same handling as the finding, delivered to an endpoint the
  ISAC cannot audit.
* The retrieval receipt still comes from a real TAXII collect. That record is
  the regulatory artefact — "we warned you, and here is when you fetched it" —
  and a notification that delivered the content itself would quietly become an
  undocumented second delivery channel that no receipt describes.

**Notifications fire when content becomes visible, not when it is distributed.**
A submission distributed under embargo is not yet readable; telling a member
about it then is either useless or an early disclosure of the fact that
something is coming. The two moments that make content visible are distribution
without an embargo, and embargo release.

**Queued inside the transaction that made the content visible.** A row in
``webhook_deliveries`` with no ``delivered_at`` is a promise to deliver. A
process that dies before sending has still recorded the debt, and the dispatcher
picks it up on restart -- which matters because a crash mid-distribution is
exactly when a member most needs telling.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.db.models import (
    CircleMembership,
    Distribution,
    Submission,
    TaxiiCollection,
    Webhook,
    WebhookDelivery,
)

__all__ = [
    "EVENT_SUBMISSION_VISIBLE",
    "circle_ids_for_submission",
    "queue_visibility_notifications",
]

logger = logging.getLogger(__name__)

#: The only event AIVS emits today. Named for what happened to the *member*
#: ("this became visible to you") rather than for what the ISAC did
#: ("distributed"), because the two differ whenever an embargo is involved and
#: the member's view is the one the notification is about.
EVENT_SUBMISSION_VISIBLE: Final[str] = "submission.visible"


async def circle_ids_for_submission(
    session: AsyncSession, submission_id: uuid.UUID
) -> list[uuid.UUID]:
    """Return every circle a submission was distributed into.

    Used where the circles are not an input to the operation -- releasing an
    embargo names a submission, not a set of circles, and the audience is
    whatever it was distributed to.
    """
    return list(
        (
            await session.execute(
                select(Distribution.circle_id)
                .where(Distribution.submission_id == submission_id)
                .distinct()
            )
        )
        .scalars()
        .all()
    )


async def queue_visibility_notifications(
    session: AsyncSession,
    *,
    submission_id: uuid.UUID,
    circle_ids: list[uuid.UUID],
    visible_at: dt.datetime,
    now: dt.datetime | None = None,
) -> int:
    """Queue a contentless notification for every member entitled to one.

    Entitled means: a member of one of ``circle_ids``, with an active webhook
    subscribed to this event, whose membership began at or before the content
    became visible. That last condition matters -- an organisation that joined
    after the fact cannot read the content, and notifying them would advertise
    the existence of something they are not entitled to.

    The submitting organisation is not notified about its own submission.

    Does not commit. The caller owns the transaction, so the promise to notify
    lands atomically with the change that created it.
    """
    now = now or dt.datetime.now(dt.UTC)
    if not circle_ids or visible_at > now:
        # Nothing to announce yet. An embargoed distribution is notified when
        # the embargo releases, not when the rows are written.
        return 0

    submitter_org_id = await session.scalar(
        select(Submission.submitter_org_id).where(Submission.id == submission_id)
    )

    rows = (
        await session.execute(
            select(Webhook, TaxiiCollection.id)
            .join(CircleMembership, CircleMembership.org_id == Webhook.org_id)
            .join(TaxiiCollection, TaxiiCollection.circle_id == CircleMembership.circle_id)
            .where(
                CircleMembership.circle_id.in_(circle_ids),
                # The open interval only. A member that has left cannot read the
                # content, so announcing it would tell a former member what was
                # shared after it went -- an embargo releasing after a firm left
                # did exactly that.
                CircleMembership.left_at.is_(None),
                CircleMembership.joined_at <= visible_at,
                Webhook.is_active.is_(True),
                TaxiiCollection.is_active.is_(True),
                TaxiiCollection.can_read.is_(True),
            )
        )
    ).all()

    queued = 0
    for webhook, collection_id in rows:
        # An empty `events` list means "subscribe to everything".
        if webhook.events and EVENT_SUBMISSION_VISIBLE not in webhook.events:
            continue
        if webhook.org_id == submitter_org_id:
            # They filed it; being told about their own submission is noise, and
            # for an anonymous submission it would be a small confirmation that
            # the anonymised item is theirs.
            continue
        session.add(
            WebhookDelivery(
                webhook_id=webhook.id,
                event=EVENT_SUBMISSION_VISIBLE,
                payload={
                    "event": EVENT_SUBMISSION_VISIBLE,
                    "submission_id": str(submission_id),
                    "collection_id": str(collection_id),
                    "visible_at": visible_at.isoformat(),
                    # Says out loud that this is a pointer, so an integrator does
                    # not go looking for content that is deliberately absent.
                    "detail": "poll the collection to collect this content",
                },
            )
        )
        queued += 1

    if queued:
        logger.info("queued %d visibility notification(s) for submission %s", queued, submission_id)
    return queued
