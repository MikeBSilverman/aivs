"""Everything an operator needs to know the instance is working, in one place.

The admin status page renders this; ``/metrics`` and ``/readyz`` read the same
queue counts and the same heartbeat registry, so the page, the probe and the
scrape cannot disagree about whether something is healthy (plan, exit
criterion 5: a component is not monitorable until it appears here).

Identifiers, counts and times only -- never content. The ``isac_membership``
role reads this page, and it holds no content right.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlsplit

from sqlalchemy import String, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import AckType, CertStatus, EmbargoStatus, OrgStatus, OrgType
from aivs_server.audit.log import AuditAction
from aivs_server.auth.secretbox import SecretBox
from aivs_server.db.models import (
    Acknowledgment,
    AuditLog,
    ClientCertificate,
    Distribution,
    Embargo,
    InstanceControl,
    Operator,
    Organization,
    Submission,
    Webhook,
    WebhookDelivery,
)
from aivs_server.observability import HEARTBEATS, ComponentReport

__all__ = [
    "CERTIFICATE_WARNING",
    "STALE_RETRIEVAL",
    "InstanceStatus",
    "gather_status",
    "pending_deliveries",
    "pending_embargoes",
]

#: Rotation starts 60 days out (runbook section 9); the page warns at 30, when it is late.
CERTIFICATE_WARNING: Final[dt.timedelta] = dt.timedelta(days=30)
#: A member that has retrieved nothing for this long may not be receiving warnings.
STALE_RETRIEVAL: Final[dt.timedelta] = dt.timedelta(days=14)
_USAGE_DAYS: Final[int] = 7
_DETECTION_LOOKBACK: Final[dt.timedelta] = dt.timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class InstanceStatus:
    now: dt.datetime
    components: list[ComponentReport]
    distribution_paused: bool
    paused_at: dt.datetime | None
    pending_deliveries: int
    pending_embargoes: int
    next_release_at: dt.datetime | None
    usage: list[dict[str, Any]]
    organisations: dict[str, int]
    quarantined: list[dict[str, Any]]
    expiring_certificates: list[dict[str, Any]]
    silent_members: list[dict[str, Any]]
    failing_webhooks: list[dict[str, Any]]
    detections: list[dict[str, Any]]
    proposed_quarantines: list[dict[str, Any]]
    key_fingerprint: str
    key_algorithm: str
    secrets_needing_rewrap: int


async def pending_deliveries(session: AsyncSession) -> int:
    return int(
        await session.scalar(
            select(func.count())
            .select_from(WebhookDelivery)
            .where(WebhookDelivery.delivered_at.is_(None))
        )
        or 0
    )


def _unreleased() -> Any:
    return Embargo.status.in_((EmbargoStatus.PENDING, EmbargoStatus.EXTENDED))


async def pending_embargoes(session: AsyncSession) -> int:
    return int(
        await session.scalar(select(func.count()).select_from(Embargo).where(_unreleased())) or 0
    )


async def _next_release(session: AsyncSession) -> dt.datetime | None:
    return await session.scalar(select(func.min(Embargo.release_at)).where(_unreleased()))


async def _daily_counts(
    session: AsyncSession, column: Any, since: dt.datetime, *conditions: Any
) -> dict[dt.date, int]:
    day = func.date_trunc("day", func.timezone("UTC", column))
    rows = await session.execute(
        select(day, func.count()).where(column >= since, *conditions).group_by(day),
    )
    return {bucket.date(): int(total) for bucket, total in rows.all()}


async def _usage(session: AsyncSession, now: dt.datetime) -> list[dict[str, Any]]:
    """Submissions, distributions and retrievals per day, newest first."""
    today = now.date()
    since = dt.datetime.combine(
        today - dt.timedelta(days=_USAGE_DAYS - 1), dt.time.min, tzinfo=dt.UTC
    )
    submissions = await _daily_counts(session, Submission.created_at, since)
    distributions = await _daily_counts(session, Distribution.date_added, since)
    retrievals = await _daily_counts(
        session, Acknowledgment.created_at, since, Acknowledgment.ack_type == AckType.RETRIEVED
    )
    days = [today - dt.timedelta(days=offset) for offset in range(_USAGE_DAYS)]
    return [
        {
            "day": day,
            "submissions": submissions.get(day, 0),
            "distributions": distributions.get(day, 0),
            "retrievals": retrievals.get(day, 0),
        }
        for day in days
    ]


async def _organisation_counts(session: AsyncSession) -> dict[str, int]:
    rows = await session.execute(
        select(Organization.status, func.count()).group_by(Organization.status)
    )
    counts = {status.value: 0 for status in OrgStatus}
    counts.update({status.value: int(total) for status, total in rows.all()})
    return counts


async def _quarantined(session: AsyncSession) -> list[dict[str, Any]]:
    rows = await session.execute(
        select(Organization.slug, Organization.quarantined_at)
        .where(Organization.status == OrgStatus.QUARANTINED)
        .order_by(Organization.quarantined_at)
    )
    return [{"slug": slug, "since": since} for slug, since in rows.all()]


async def _expiring_certificates(session: AsyncSession, now: dt.datetime) -> list[dict[str, Any]]:
    rows = await session.execute(
        select(Organization.slug, ClientCertificate.label, ClientCertificate.not_after)
        .join(Organization, Organization.id == ClientCertificate.org_id)
        .where(
            ClientCertificate.status == CertStatus.ACTIVE,
            ClientCertificate.not_after <= now + CERTIFICATE_WARNING,
        )
        .order_by(ClientCertificate.not_after)
    )
    return [
        {"org": slug, "label": label or "", "not_after": not_after, "expired": not_after <= now}
        for slug, label, not_after in rows.all()
    ]


async def _silent_members(session: AsyncSession, now: dt.datetime) -> list[dict[str, Any]]:
    """Active members whose last retrieval is older than STALE_RETRIEVAL, or never."""
    last_retrieval = (
        select(Acknowledgment.org_id, func.max(Acknowledgment.created_at).label("last_at"))
        .where(Acknowledgment.ack_type == AckType.RETRIEVED)
        .group_by(Acknowledgment.org_id)
        .subquery()
    )
    rows = await session.execute(
        select(Organization.slug, last_retrieval.c.last_at)
        .outerjoin(last_retrieval, last_retrieval.c.org_id == Organization.id)
        .where(
            Organization.status == OrgStatus.ACTIVE,
            Organization.org_type != OrgType.ADMIN,
            (last_retrieval.c.last_at.is_(None))
            | (last_retrieval.c.last_at < now - STALE_RETRIEVAL),
        )
        .order_by(last_retrieval.c.last_at.asc().nulls_first(), Organization.slug)
    )
    return [{"org": slug, "last_retrieval": last_at} for slug, last_at in rows.all()]


async def _failing_webhooks(session: AsyncSession) -> list[dict[str, Any]]:
    rows = await session.execute(
        select(Organization.slug, Webhook.url, Webhook.consecutive_failures, Webhook.is_active)
        .join(Organization, Organization.id == Webhook.org_id)
        .where(Webhook.consecutive_failures > 0)
        .order_by(Webhook.consecutive_failures.desc())
    )
    # The host only: a webhook path can carry a member's routing token.
    return [
        {"org": slug, "host": urlsplit(url).hostname or "", "failures": failures, "active": active}
        for slug, url, failures, active in rows.all()
    ]


async def _recent_detections(session: AsyncSession, now: dt.datetime) -> list[dict[str, Any]]:
    rows = await session.execute(
        select(AuditLog.at, AuditLog.details)
        .where(
            AuditLog.action == AuditAction.DETECTION_RAISED,
            AuditLog.at >= now - _DETECTION_LOOKBACK,
        )
        .order_by(AuditLog.at.desc())
    )
    return [
        {
            "at": at,
            "rule": details.get("rule", ""),
            "severity": details.get("severity", ""),
            "summary": details.get("summary", ""),
        }
        for at, details in rows.all()
    ]


async def _proposed_quarantines(session: AsyncSession, now: dt.datetime) -> list[dict[str, Any]]:
    """Quarantines a detection recommended for an organisation still active.

    Only under the ``propose`` policy is a human asked; under ``enforce`` the
    organisation is already quarantined and drops out of this list.
    """
    proposed_org = AuditLog.details["proposed_org"].astext
    rows = await session.execute(
        select(AuditLog.at, AuditLog.details["rule"].astext, Organization.id, Organization.slug)
        .join(Organization, func.cast(Organization.id, String) == proposed_org)
        .where(
            AuditLog.action == AuditAction.DETECTION_RAISED,
            AuditLog.at >= now - _DETECTION_LOOKBACK,
            AuditLog.details["proposed_action"].astext == "quarantine",
            Organization.status == OrgStatus.ACTIVE,
        )
        .order_by(AuditLog.at.desc())
    )
    return [
        {"at": at, "rule": rule, "org_id": str(org_id), "org": slug}
        for at, rule, org_id, slug in rows.all()
    ]


async def _secrets_needing_rewrap(session: AsyncSession, box: SecretBox) -> int:
    """Sealed values not on the active key and algorithm. Reads headers only."""
    seeds = (
        await session.execute(
            select(Operator.totp_secret_encrypted).where(
                Operator.totp_secret_encrypted.is_not(None)
            )
        )
    ).scalars()
    signing_keys = (await session.execute(select(Webhook.hmac_secret_encrypted))).scalars()
    return sum(box.needs_rewrap(blob) for blob in [*seeds, *signing_keys])


async def _pause_state(session: AsyncSession) -> InstanceControl | None:
    return await session.get(InstanceControl, 1)


async def gather_status(
    session: AsyncSession, *, now: dt.datetime, box: SecretBox
) -> InstanceStatus:
    """Read every fact the status page shows. Writes nothing."""
    control = await _pause_state(session)
    return InstanceStatus(
        now=now,
        components=HEARTBEATS.report(now=now),
        distribution_paused=bool(control and control.distribution_paused),
        paused_at=control.paused_at if control else None,
        pending_deliveries=await pending_deliveries(session),
        pending_embargoes=await pending_embargoes(session),
        next_release_at=await _next_release(session),
        usage=await _usage(session, now),
        organisations=await _organisation_counts(session),
        quarantined=await _quarantined(session),
        expiring_certificates=await _expiring_certificates(session, now),
        silent_members=await _silent_members(session, now),
        failing_webhooks=await _failing_webhooks(session),
        detections=await _recent_detections(session, now),
        proposed_quarantines=await _proposed_quarantines(session, now),
        key_fingerprint=box.active_fingerprint,
        key_algorithm=box.algorithm.name,
        secrets_needing_rewrap=await _secrets_needing_rewrap(session, box),
    )
