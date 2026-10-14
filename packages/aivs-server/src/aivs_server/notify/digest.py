"""The contentless digest: one message per window instead of one per submission.

An organisation on ``hourly`` or ``daily`` cadence has its visibility notices
held (``notify.events``) and sent here, once per window, to each subscribed
webhook and, if it names one, to its digest mailbox. During a sector event the
ISAC revises one advisory many times in an afternoon; a member told once per
revision stops reading, and one told once per window, with "updated 6 times"
beside the advisory, does not.

**Still contentless, with one argued exception.** A digest says how many items
of each TLP marking became visible, links each to the collection that serves it
(a pointer the member's certificate fetches), names the affected products below
RED for routing, and names the *title* only of CLEAR and GREEN items. A title is
content: it is the submitter's own one-line statement of the finding, often its
most valuable sentence. CLEAR and GREEN are shareable across the community by
their own definition; AMBER and above are not, and a digest reaches a mail
relay and an endpoint the ISAC cannot audit. So for those the digest says "an
AMBER item about Acme Gateway", never what it says. Content email (SF-36)
stays unbuilt, and with it the controls it would need.

**Entitlement is checked again when the digest is sent.** A notice held at noon
for a member that left the circle at two is not sent at five: the former member
cannot read it, and being told it exists is what the open-interval rule in
``notify.events`` forbids. Nothing is sent while distribution is paused; the
notices wait, as the content does.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import TLP, NotificationCadence, OrgStatus
from aivs_schemas.tlp import TLP_NAMES
from aivs_server.db.models import (
    Circle,
    CircleMembership,
    EmailDelivery,
    Organization,
    PendingNotice,
    Submission,
    TaxiiCollection,
    Webhook,
    WebhookDelivery,
)
from aivs_server.db.webhook_lock import deliverable_webhooks
from aivs_server.notify.events import EVENT_SUBMISSION_VISIBLE, notice_facts
from aivs_server.services.publication import publication_paused

__all__ = [
    "EVENT_DIGEST",
    "TITLED_MARKINGS",
    "DigestItem",
    "digest_due",
    "render_email",
    "send_due_digests",
    "summary_line",
]

logger = logging.getLogger(__name__)

EVENT_DIGEST: Final[str] = "submission.digest"

#: The markings whose titles a digest may carry. See the module docstring.
TITLED_MARKINGS: Final[frozenset[TLP]] = frozenset({TLP.CLEAR, TLP.GREEN})

_HOUR: Final[dt.timedelta] = dt.timedelta(hours=1)
_DAY: Final[dt.timedelta] = dt.timedelta(days=1)


@dataclass(frozen=True)
class DigestItem:
    submission_id: uuid.UUID
    collection_id: uuid.UUID
    visible_at: dt.datetime
    updates: int
    marking: TLP
    title: str | None
    products: list[str]
    sector_event: bool = False


# ---------------------------------------------------------------------------
# Pure: when a window closes, and what the message says
# ---------------------------------------------------------------------------
def digest_due(
    cadence: NotificationCadence, oldest: dt.datetime, now: dt.datetime, *, daily_hour: int
) -> bool:
    """Whether the window holding a notice queued at ``oldest`` has closed.

    Windows are aligned to the clock, not to the first notice: an hourly digest
    goes on the hour after the oldest notice, a daily one at ``daily_hour`` UTC.
    ``immediate`` is always due -- an organisation that switched back from a
    digest gets what was held at once.
    """
    if cadence is NotificationCadence.IMMEDIATE:
        return True
    if cadence is NotificationCadence.HOURLY:
        return now >= oldest.replace(minute=0, second=0, microsecond=0) + _HOUR
    send_at = oldest.replace(hour=daily_hour, minute=0, second=0, microsecond=0)
    if send_at <= oldest:
        send_at += _DAY
    return now >= send_at


def summary_line(items: Sequence[DigestItem]) -> str:
    """ "3 new TLP:AMBER items, 1 new TLP:GREEN item" -- most restrictive first."""
    counts = Counter(item.marking for item in items)
    order = (TLP.RED, TLP.AMBER_STRICT, TLP.AMBER, TLP.GREEN, TLP.CLEAR)
    parts = [
        f"{counts[marking]} new {TLP_NAMES[marking]} item{'' if counts[marking] == 1 else 's'}"
        for marking in order
        if counts[marking]
    ]
    return ", ".join(parts) or "nothing new"


def _link(base_url: str, collection_id: uuid.UUID) -> str:
    return f"{base_url.rstrip('/')}/taxii2/aivs/collections/{collection_id}/objects/"


def _line(item: DigestItem, base_url: str) -> str:
    about = item.title or (
        f"an item about {', '.join(item.products)}" if item.products else "an item"
    )
    updated = f" (updated {item.updates} times)" if item.updates > 1 else ""
    pinned = "SECTOR EVENT: " if item.sector_event else ""
    return (
        f"- [{TLP_NAMES[item.marking]}] {pinned}{about}{updated}: "
        f"{_link(base_url, item.collection_id)}"
    )


def render_email(instance_name: str, items: Sequence[DigestItem], base_url: str) -> tuple[str, str]:
    """The digest email's subject and plain-text body. Nothing but what the webhook says."""
    summary = summary_line(items)
    body = "\n".join(
        [
            f"{instance_name}: {summary}.",
            "",
            *(_line(item, base_url) for item in items),
            "",
            "Collect each item through your TAXII client or the portal. This message",
            "carries no content beyond the titles of TLP:CLEAR and TLP:GREEN items.",
        ]
    )
    return f"{instance_name}: {summary}", body


def _webhook_payload(
    cadence: NotificationCadence, items: Sequence[DigestItem], base_url: str
) -> dict[str, Any]:
    return {
        "event": EVENT_DIGEST,
        "window": cadence.value,
        "summary": summary_line(items),
        "items": [
            {
                "submission_id": str(item.submission_id),
                "collection_id": str(item.collection_id),
                "visible_at": item.visible_at.isoformat(),
                "updates": item.updates,
                "marking": TLP_NAMES[item.marking],
                **({"title": item.title} if item.title else {}),
                "affected_products": item.products,
                "sector_event": item.sector_event,
                "link": _link(base_url, item.collection_id),
            }
            for item in items
        ],
        "detail": "poll the collections to collect this content",
    }


# ---------------------------------------------------------------------------
# The job
# ---------------------------------------------------------------------------
async def send_due_digests(
    session: AsyncSession,
    *,
    now: dt.datetime,
    daily_hour: int,
    base_url: str,
    instance_name: str,
    email_enabled: bool,
) -> int:
    """Queue every digest whose window has closed. Returns how many organisations got one.

    Commits once. While distribution is paused nothing is sent and nothing is
    dropped: the notices wait, as the content does.
    """
    if await publication_paused(session):
        return 0
    org_ids = (await session.scalars(select(PendingNotice.org_id).distinct())).all()
    sent = 0
    for org_id in org_ids:
        if await _digest_for(
            session,
            org_id,
            now=now,
            daily_hour=daily_hour,
            base_url=base_url,
            instance_name=instance_name,
            email_enabled=email_enabled,
        ):
            sent += 1
    await session.commit()
    return sent


async def _digest_for(
    session: AsyncSession,
    org_id: uuid.UUID,
    *,
    now: dt.datetime,
    daily_hour: int,
    base_url: str,
    instance_name: str,
    email_enabled: bool,
) -> bool:
    org = await session.get(Organization, org_id)
    notices = (
        await session.scalars(
            select(PendingNotice)
            .where(PendingNotice.org_id == org_id)
            .order_by(PendingNotice.visible_at, PendingNotice.id)
        )
    ).all()
    if org is None or not notices:
        return False
    if org.status is OrgStatus.ACTIVE and not digest_due(
        org.notification_cadence,
        min(notice.created_at for notice in notices),
        now,
        daily_hour=daily_hour,
    ):
        return False
    # Inactive, or due: either way these notices are spent now. An organisation
    # that cannot read is not owed a later digest of what it could not read.
    entitled = await _still_entitled(session, org, notices)
    await session.execute(
        delete(PendingNotice).where(PendingNotice.id.in_([n.id for n in notices]))
    )
    if not entitled:
        return False
    items = [await _item(session, notice) for notice in entitled]
    queued = await _queue_webhooks(session, org, items, base_url)
    if email_enabled and org.digest_email:
        subject, body = render_email(instance_name, items, base_url)
        session.add(
            EmailDelivery(org_id=org.id, recipient=org.digest_email, subject=subject, body=body)
        )
        queued += 1
    logger.info("digest of %d item(s) for organisation %s", len(items), org.id)
    return queued > 0


async def _still_entitled(
    session: AsyncSession, org: Organization, notices: Sequence[PendingNotice]
) -> list[PendingNotice]:
    """The notices ``org`` may still be told about: the same rule as when they were held."""
    if org.status is not OrgStatus.ACTIVE:
        return []
    rows = (
        await session.execute(
            select(TaxiiCollection.id, CircleMembership.joined_at)
            .join(CircleMembership, CircleMembership.circle_id == TaxiiCollection.circle_id)
            .join(Circle, Circle.id == TaxiiCollection.circle_id)
            .where(
                CircleMembership.org_id == org.id,
                CircleMembership.left_at.is_(None),
                Circle.is_active.is_(True),
                TaxiiCollection.is_active.is_(True),
                TaxiiCollection.can_read.is_(True),
                TaxiiCollection.id.in_([notice.collection_id for notice in notices]),
            )
        )
    ).tuples()
    joined = dict(rows.all())
    return [
        notice
        for notice in notices
        if notice.collection_id in joined and joined[notice.collection_id] <= notice.visible_at
    ]


async def _item(session: AsyncSession, notice: PendingNotice) -> DigestItem:
    submission = await session.get(Submission, notice.submission_id)
    if submission is None:  # pragma: no cover - the foreign key cascades
        msg = f"pending notice {notice.id} names a missing submission"
        raise LookupError(msg)
    facts = await notice_facts(session, submission)
    return DigestItem(
        submission_id=submission.id,
        collection_id=notice.collection_id,
        visible_at=notice.visible_at,
        updates=notice.versions,
        marking=submission.tlp,
        title=submission.title if submission.tlp in TITLED_MARKINGS else None,
        products=facts.products,
        sector_event=facts.sector_event,
    )


async def _queue_webhooks(
    session: AsyncSession, org: Organization, items: Sequence[DigestItem], base_url: str
) -> int:
    webhooks = (await session.scalars(deliverable_webhooks().where(Webhook.org_id == org.id))).all()
    subscribed = [
        webhook
        for webhook in webhooks
        if not webhook.events
        or EVENT_DIGEST in webhook.events
        or EVENT_SUBMISSION_VISIBLE in webhook.events
    ]
    payload = _webhook_payload(org.notification_cadence, items, base_url)
    for webhook in subscribed:
        session.add(WebhookDelivery(webhook_id=webhook.id, event=EVENT_DIGEST, payload=payload))
    return len(subscribed)
