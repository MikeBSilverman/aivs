"""Is a member's connection working? Its own view, and the ISAC's.

A member that stopped collecting does not notice: nothing arrives, which looks
exactly like nothing being shared. The member's page answers "are we
connected?" per collection -- when its client last collected content, and
whether newer content is waiting (never counting what it filed itself, which it
already holds) -- with its webhooks' delivery state and its
certificates' expiry beside it. The ISAC's view lists connections where
content has been waiting longer than a threshold: the members to call before
an incident, not after.

"Last collected" is the last TAXII page that returned content to the
organisation (the ``taxii.objects_retrieved`` audit row, which names the
collection). A poll that found nothing new is no evidence either way, and is
not recorded, so "waiting" is judged against content, never against silence.
Identifiers, counts and times only: no content, and webhook hosts rather than
URLs, since a path can carry a member's routing token.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlsplit

from sqlalchemy import String, and_, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from aivs_schemas.enums import VISIBLE_SUBMISSION_STATES, CertStatus, OrgStatus, OrgType
from aivs_server.audit.log import AuditAction
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import distribution_visibility_clause, readable_circle_ids
from aivs_server.db.models import (
    AuditLog,
    Circle,
    CircleMembership,
    ClientCertificate,
    Distribution,
    Organization,
    Submission,
    TaxiiCollection,
    Webhook,
    WebhookDelivery,
)
from aivs_server.services.attribution import submissions_filed_by, submitter_column

__all__ = [
    "CERTIFICATE_WARNING",
    "STALE_AFTER",
    "CertificateHealth",
    "CollectionHealth",
    "MemberHealth",
    "StaleConnection",
    "WebhookHealth",
    "member_health",
    "readable_collections",
    "stale_connections",
]

_AUDIT_AT = AuditLog.at


def _retrieval(org_id: Any, collection_id: Any) -> ColumnElement[bool]:
    """An audit row recording that ``org_id`` collected content from ``collection_id``."""
    return and_(
        AuditLog.org_id == org_id,
        AuditLog.action == AuditAction.OBJECTS_RETRIEVED,
        AuditLog.resource_type == "collection",
        AuditLog.resource_id == collection_id,
    )


#: Content waiting longer than this on a member's connection is shown to the ISAC.
STALE_AFTER: Final[dt.timedelta] = dt.timedelta(days=3)

#: A certificate expiring within this is flagged on the member's page.
CERTIFICATE_WARNING: Final[dt.timedelta] = dt.timedelta(days=30)


@dataclass(frozen=True)
class CollectionHealth:
    collection_id: uuid.UUID
    title: str
    is_sandbox: bool
    last_collected: dt.datetime | None
    newest_available: dt.datetime | None

    @property
    def waiting(self) -> bool:
        """Whether content newer than the last collection is there to collect."""
        if self.newest_available is None:
            return False
        return self.last_collected is None or self.newest_available > self.last_collected


@dataclass(frozen=True)
class WebhookHealth:
    host: str
    is_active: bool
    consecutive_failures: int
    last_delivered_at: dt.datetime | None
    undelivered: int


@dataclass(frozen=True)
class CertificateHealth:
    label: str
    fingerprint_prefix: str
    not_after: dt.datetime
    expires_soon: bool


@dataclass(frozen=True)
class MemberHealth:
    collections: tuple[CollectionHealth, ...]
    webhooks: tuple[WebhookHealth, ...]
    certificates: tuple[CertificateHealth, ...]


@dataclass(frozen=True)
class StaleConnection:
    org: str
    collection: str
    last_collected: dt.datetime | None
    waiting_since: dt.datetime


# ---------------------------------------------------------------------------
# The member's own view
# ---------------------------------------------------------------------------
async def member_health(session: AsyncSession, ctx: AuthContext, now: dt.datetime) -> MemberHealth:
    """The caller's own organisation's connection, as the caller may see it."""
    return MemberHealth(
        collections=await _collections(session, ctx, now),
        webhooks=await _webhooks(session, ctx.org_id),
        certificates=await _certificates(session, ctx.org_id, now),
    )


async def readable_collections(
    session: AsyncSession, ctx: AuthContext
) -> list[tuple[uuid.UUID, str, uuid.UUID, bool]]:
    """``(collection id, title, circle id, is_sandbox)`` for each collection ``ctx`` reads."""
    circles = sorted(readable_circle_ids(ctx), key=str)
    if not circles:
        return []
    rows = (
        await session.execute(
            select(
                TaxiiCollection.id,
                TaxiiCollection.title,
                TaxiiCollection.circle_id,
                Circle.is_sandbox,
            )
            .join(Circle, Circle.id == TaxiiCollection.circle_id)
            .where(
                TaxiiCollection.circle_id.in_(circles),
                TaxiiCollection.is_active.is_(True),
                TaxiiCollection.can_read.is_(True),
                Circle.is_active.is_(True),
            )
            .order_by(TaxiiCollection.title)
        )
    ).all()
    return [(cid, title, circle_id, sandbox) for cid, title, circle_id, sandbox in rows]


async def _collections(
    session: AsyncSession, ctx: AuthContext, now: dt.datetime
) -> tuple[CollectionHealth, ...]:
    health = []
    for collection_id, title, circle_id, is_sandbox in await readable_collections(session, ctx):
        health.append(
            CollectionHealth(
                collection_id=collection_id,
                title=title,
                is_sandbox=is_sandbox,
                last_collected=await _last_collected(session, ctx.org_id, collection_id),
                newest_available=await _newest_available(session, ctx, circle_id, now),
            )
        )
    return tuple(health)


async def _last_collected(
    session: AsyncSession, org_id: uuid.UUID, collection_id: uuid.UUID
) -> dt.datetime | None:
    last: dt.datetime | None = await session.scalar(
        select(func.max(_AUDIT_AT)).where(_retrieval(org_id, str(collection_id)))
    )
    return last


async def _newest_available(
    session: AsyncSession, ctx: AuthContext, circle_id: uuid.UUID, now: dt.datetime
) -> dt.datetime | None:
    newest: dt.datetime | None = await session.scalar(
        select(func.max(Distribution.date_added))
        .join(Submission, Submission.id == Distribution.submission_id)
        .where(
            Distribution.circle_id == circle_id,
            distribution_visibility_clause(ctx, now),
            # Its own filings it has already; they are never "waiting".
            Submission.id.not_in(await submissions_filed_by(ctx.org_id)),
        )
    )
    return newest


async def _webhooks(session: AsyncSession, org_id: uuid.UUID) -> tuple[WebhookHealth, ...]:
    delivered = func.max(WebhookDelivery.delivered_at)
    undelivered = func.count(WebhookDelivery.id).filter(WebhookDelivery.delivered_at.is_(None))
    rows = (
        await session.execute(
            select(Webhook, delivered, undelivered)
            .outerjoin(WebhookDelivery, WebhookDelivery.webhook_id == Webhook.id)
            .where(Webhook.org_id == org_id)
            .group_by(Webhook.id)
            .order_by(Webhook.created_at)
        )
    ).all()
    return tuple(
        WebhookHealth(
            host=urlsplit(webhook.url).hostname or "",
            is_active=webhook.is_active,
            consecutive_failures=webhook.consecutive_failures,
            last_delivered_at=last,
            undelivered=int(pending),
        )
        for webhook, last, pending in rows
    )


async def _certificates(
    session: AsyncSession, org_id: uuid.UUID, now: dt.datetime
) -> tuple[CertificateHealth, ...]:
    certificates = (
        await session.scalars(
            select(ClientCertificate)
            .where(
                ClientCertificate.org_id == org_id, ClientCertificate.status == CertStatus.ACTIVE
            )
            .order_by(ClientCertificate.not_after)
        )
    ).all()
    return tuple(
        CertificateHealth(
            label=certificate.label or "",
            fingerprint_prefix=certificate.fingerprint_sha256[:16],
            not_after=certificate.not_after,
            expires_soon=certificate.not_after <= now + CERTIFICATE_WARNING,
        )
        for certificate in certificates
    )


# ---------------------------------------------------------------------------
# The ISAC's view
# ---------------------------------------------------------------------------
async def stale_connections(
    session: AsyncSession, now: dt.datetime, *, after: dt.timedelta = STALE_AFTER
) -> list[StaleConnection]:
    """Member connections where content has waited, uncollected, longer than ``after``.

    For each active member's open membership of an active circle with a
    readable collection: the oldest content made visible to it since its last
    collection from that collection. Sandbox circles are included: a member
    whose sandbox is not being collected is exactly what a day-one check is for.
    """
    last = (
        select(func.max(_AUDIT_AT))
        .where(_retrieval(Organization.id, cast(TaxiiCollection.id, String)))
        .correlate(Organization, TaxiiCollection)
        .scalar_subquery()
    )
    waiting_since = (
        select(func.min(Distribution.date_added))
        .join(Submission, Submission.id == Distribution.submission_id)
        .where(
            Distribution.circle_id == CircleMembership.circle_id,
            Distribution.date_added >= CircleMembership.joined_at,
            Distribution.date_added <= now,
            Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)),
            submitter_column(Submission) != CircleMembership.org_id,
            last.is_(None) | (Distribution.date_added > last),
        )
        .correlate(CircleMembership)
        .scalar_subquery()
    )
    rows = (
        await session.execute(
            select(Organization.slug, TaxiiCollection.title, last, waiting_since)
            .join(CircleMembership, CircleMembership.org_id == Organization.id)
            .join(Circle, Circle.id == CircleMembership.circle_id)
            .join(TaxiiCollection, TaxiiCollection.circle_id == Circle.id)
            .where(
                Organization.status == OrgStatus.ACTIVE,
                Organization.org_type.not_in((OrgType.ADMIN, OrgType.AUTOMATION)),
                CircleMembership.left_at.is_(None),
                Circle.is_active.is_(True),
                TaxiiCollection.is_active.is_(True),
                TaxiiCollection.can_read.is_(True),
            )
            .order_by(Organization.slug, TaxiiCollection.title)
        )
    ).all()
    return [
        StaleConnection(org=slug, collection=title, last_collected=last_at, waiting_since=since)
        for slug, title, last_at, since in rows
        if since is not None and since <= now - after
    ]
