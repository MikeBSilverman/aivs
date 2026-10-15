"""Contentless notifications: "there is something for you; come and get it".

Latency is most of what pre-CVE sharing is for. A member who learns about an
actively exploited finding on their next fifteen-minute poll has a materially
worse product than one that is told. But a notification is an outbound message
to an endpoint outside the ISAC's control, and that shapes what it may say.

**Notifications carry identifiers, and product names for routing.** No title,
no TLP marking, no summary, no object content. The member is told that
submission *X* became visible to them in collection *Y*, and which products it
concerns (below RED), and polls TAXII to collect it. The product names are
there because a member's ticketing system routes on them; they come from a
controlled field, not prose, and the content members collect carries them too.
Three things follow from that, and they are the reason for the design rather
than consequences of it:

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
from dataclasses import dataclass
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import TLP, NotificationCadence, OrgStatus
from aivs_server.db.models import (
    Circle,
    CircleMembership,
    Distribution,
    Organization,
    PendingNotice,
    StixObject,
    Submission,
    TaxiiCollection,
    Webhook,
    WebhookDelivery,
)
from aivs_server.db.webhook_lock import deliverable_webhooks
from aivs_server.services.attribution import submitter_of
from aivs_server.services.guidance import affected_product_names
from aivs_server.services.sector_events import subjects_in_open_events

__all__ = [
    "EVENT_SUBMISSION_VISIBLE",
    "NoticeFacts",
    "circle_ids_for_submission",
    "entitled_readers",
    "notice_facts",
    "queue_visibility_notifications",
]

logger = logging.getLogger(__name__)

#: At most this many product names on a notice: enough to route on, and a
#: bound on a list a submitter writes.
_MAX_PRODUCTS: Final[int] = 20

#: The visibility event. Named for what happened to the *member*
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

    Entitled means: a member of one of ``circle_ids`` whose membership began at
    or before the content became visible. That last condition matters -- an
    organisation that joined after the fact cannot read the content, and
    notifying them would advertise the existence of something they are not
    entitled to. The submitting organisation is not notified about its own
    submission.

    An organisation on ``immediate`` cadence is told at once, on each webhook
    subscribed to this event. One on ``hourly`` or ``daily`` has the notice held
    for its next digest (``notify.digest``), which re-checks entitlement when
    it is sent.

    Returns how many notices were queued or held. Does not commit. The caller
    owns the transaction, so the promise to notify lands atomically with the
    change that created it.
    """
    now = now or dt.datetime.now(dt.UTC)
    if not circle_ids or visible_at > now:
        # Nothing to announce yet. An embargoed distribution is notified when
        # the embargo releases, not when the rows are written.
        return 0

    submission = await session.get(Submission, submission_id)
    if submission is None:
        return 0
    facts = await notice_facts(session, submission)
    submitter = await submitter_of(session, submission)
    queued = 0
    for org, collection_id in await entitled_readers(session, circle_ids, visible_at):
        if org.id == submitter:
            # They filed it; being told about their own submission is noise, and
            # for an anonymous submission it would be a small confirmation that
            # the anonymised item is theirs.
            continue
        if org.notification_cadence is NotificationCadence.IMMEDIATE:
            queued += await _deliver_now(
                session, org.id, submission_id, collection_id, visible_at, facts
            )
        else:
            await _hold_for_digest(
                session, org.id, submission_id, collection_id, visible_at, facts, now
            )
            queued += 1

    if queued:
        logger.info("queued %d visibility notification(s) for submission %s", queued, submission_id)
    return queued


@dataclass(frozen=True)
class NoticeFacts:
    """What a notice about one submission may say beyond its identifiers."""

    #: The vulnerability the submission versions, if any: versions of one
    #: advisory coalesce in a digest under it.
    subject: str
    #: Affected product names, for a member's routing. Empty for RED: a
    #: notification reaches endpoints the ISAC cannot audit, and RED's audience
    #: is named people.
    products: list[str]
    #: The subject is pinned as a sector event (``services.sector_events``).
    sector_event: bool


async def notice_facts(session: AsyncSession, submission: Submission) -> NoticeFacts:
    vulnerabilities = (
        await session.scalars(
            select(StixObject.raw)
            .where(StixObject.submission_id == submission.id, StixObject.type == "vulnerability")
            .order_by(StixObject.stix_id)
        )
    ).all()
    subject = str(vulnerabilities[0]["id"]) if vulnerabilities else f"submission:{submission.id}"
    products: list[str] = []
    if submission.tlp is not TLP.RED:
        for raw in vulnerabilities:
            products.extend(name for name in affected_product_names(raw) if name not in products)
    pinned = await subjects_in_open_events(session, [subject])
    return NoticeFacts(
        subject=subject, products=products[:_MAX_PRODUCTS], sector_event=subject in pinned
    )


async def entitled_readers(
    session: AsyncSession, circle_ids: list[uuid.UUID], visible_at: dt.datetime
) -> list[tuple[Organization, uuid.UUID]]:
    """Each organisation that may read content made visible at ``visible_at`` in these
    circles, with a collection it reads it through. One pair per readable collection."""
    rows = (
        await session.execute(
            select(Organization, TaxiiCollection.id)
            .join(CircleMembership, CircleMembership.org_id == Organization.id)
            .join(TaxiiCollection, TaxiiCollection.circle_id == CircleMembership.circle_id)
            .join(Circle, Circle.id == CircleMembership.circle_id)
            .where(
                # Only organisations that could read it. A quarantined member's
                # endpoint is the one whose credentials may be in someone
                # else's hands; a suspended one has no access to announce; and a
                # deactivated circle grants no read.
                Organization.status == OrgStatus.ACTIVE,
                Circle.is_active.is_(True),
                CircleMembership.circle_id.in_(circle_ids),
                # The open interval only. A member that has left cannot read the
                # content, so announcing it would tell a former member what was
                # shared after it went -- an embargo releasing after a firm left
                # did exactly that.
                CircleMembership.left_at.is_(None),
                CircleMembership.joined_at <= visible_at,
                TaxiiCollection.is_active.is_(True),
                TaxiiCollection.can_read.is_(True),
            )
            .order_by(Organization.id, TaxiiCollection.id)
        )
    ).all()
    return [(org, collection_id) for org, collection_id in rows]


async def _deliver_now(
    session: AsyncSession,
    org_id: uuid.UUID,
    submission_id: uuid.UUID,
    collection_id: uuid.UUID,
    visible_at: dt.datetime,
    facts: NoticeFacts,
) -> int:
    webhooks = (await session.scalars(deliverable_webhooks().where(Webhook.org_id == org_id))).all()
    queued = 0
    for webhook in webhooks:
        # An empty `events` list means "subscribe to everything".
        if webhook.events and EVENT_SUBMISSION_VISIBLE not in webhook.events:
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
                    "affected_products": facts.products,
                    "sector_event": facts.sector_event,
                    # Says out loud that this is a pointer, so an integrator does
                    # not go looking for content that is deliberately absent.
                    "detail": "poll the collection to collect this content",
                },
            )
        )
        queued += 1
    return queued


async def _hold_for_digest(
    session: AsyncSession,
    org_id: uuid.UUID,
    submission_id: uuid.UUID,
    collection_id: uuid.UUID,
    visible_at: dt.datetime,
    facts: NoticeFacts,
    now: dt.datetime,
) -> None:
    """Hold the notice for the organisation's next digest, coalescing by subject."""
    statement = insert(PendingNotice).values(
        org_id=org_id,
        subject=facts.subject,
        submission_id=submission_id,
        collection_id=collection_id,
        visible_at=visible_at,
        versions=1,
        created_at=now,
    )
    await session.execute(
        statement.on_conflict_do_update(
            constraint="uq_pending_notices_org_subject",
            set_={
                "submission_id": statement.excluded.submission_id,
                "collection_id": statement.excluded.collection_id,
                "visible_at": func.greatest(
                    PendingNotice.visible_at, statement.excluded.visible_at
                ),
                "versions": PendingNotice.versions + 1,
            },
        )
    )
