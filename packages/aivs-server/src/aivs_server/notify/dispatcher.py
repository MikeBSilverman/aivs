"""Drains queued notifications to member endpoints.

Separate from :mod:`aivs_server.notify.events`, which decides *who* is owed a
notification, and from :mod:`aivs_server.notify.webhooks`, which owns the
address checks and the signing. This module is only the loop: take what is due,
try it, record what happened, back off.

Three properties are load-bearing:

**Delivery never runs inside the transaction that caused it.** A member endpoint
that accepts a connection and then stalls would otherwise hold a database
transaction -- and the row it holds is a distribution, so the whole batch waits
on the slowest member's server. The queue exists to break that coupling.

**A failing endpoint costs a bounded amount.** Attempts back off exponentially
and stop at ``webhook_max_attempts``. A member whose endpoint has been down for
a week does not accumulate an unbounded retry backlog, and the delivery record
says why it stopped.

**Nothing is retried forever, and nothing is silently dropped.** A delivery that
exhausts its attempts keeps its row with the last error on it, so an operator
answering "did they get told?" has an answer either way.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
from typing import Final

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgStatus, OrgType
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.secretbox import SecretBox, SecretPurpose
from aivs_server.config import Settings
from aivs_server.db.models import InstanceControl, Organization, Webhook, WebhookDelivery
from aivs_server.notify.webhooks import (
    SIGNATURE_HEADER,
    WebhookRejectedError,
    resolve_delivery_target,
    sign_payload,
)

__all__ = ["KEY_UNAVAILABLE_ERROR", "dispatch_pending"]

logger = logging.getLogger(__name__)

#: How many deliveries one pass will attempt. Bounds the work a single tick does
#: so a large backlog is drained steadily rather than in one long transaction.
_BATCH_SIZE: Final[int] = 50

#: Backoff base. Attempt n waits roughly ``_BACKOFF_BASE ** n`` seconds, so a
#: member endpoint that is down is retried over hours rather than seconds.
_BACKOFF_BASE: Final[int] = 5

#: How long a delivery waits when the signing key cannot be opened. Fixed
#: rather than backed off: the cause is a configuration on our side, and the
#: retry should pick up the fix promptly without hammering the log meanwhile.
_KEY_UNAVAILABLE_RETRY: Final[dt.timedelta] = dt.timedelta(minutes=5)

#: Recorded on a delivery held for that reason. The ``signing_key_unavailable``
#: detection and the status page read it: a delivery deferred forever with no
#: alert was the silent failure this module had.
KEY_UNAVAILABLE_ERROR: Final[str] = "signing key could not be opened"

_SUCCESS_FLOOR: Final[int] = 200
_SUCCESS_CEILING: Final[int] = 300


def _next_attempt_delay(attempts: int) -> dt.timedelta:
    """Exponential backoff, capped at an hour."""
    seconds = min(_BACKOFF_BASE**attempts, 3600)
    return dt.timedelta(seconds=seconds)


async def dispatch_pending(
    session: AsyncSession, settings: Settings, *, now: dt.datetime | None = None
) -> int:
    """Attempt every notification that is due. Returns the number delivered.

    Commits once at the end: the outcomes of one batch land together, and a
    delivery that was attempted is never left looking un-attempted.
    """
    now = now or dt.datetime.now(dt.UTC)
    # While paused, members' deliveries are held, not dropped: a pause means
    # members are told nothing exists, and their queue resumes with
    # distribution. The ISAC's own endpoints still hear -- among other things,
    # the detection alert that someone pressed the stop button.
    recipients = Organization.org_type.in_(
        _receiving_types(
            paused=await _distribution_paused(session),
            automation_webhooks_enabled=settings.automation_webhooks_enabled,
        )
    )

    due = (
        await session.execute(
            select(WebhookDelivery, Webhook)
            .join(Webhook, Webhook.id == WebhookDelivery.webhook_id)
            .join(Organization, Organization.id == Webhook.org_id)
            .where(
                # Queued before a quarantine or suspension, held until the
                # organisation is active again.
                Organization.status == OrgStatus.ACTIVE,
                recipients,
                WebhookDelivery.delivered_at.is_(None),
                WebhookDelivery.attempts < settings.webhook_max_attempts,
                Webhook.is_active.is_(True),
                (WebhookDelivery.next_attempt_at.is_(None))
                | (WebhookDelivery.next_attempt_at <= now),
            )
            .order_by(WebhookDelivery.id)
            .limit(_BATCH_SIZE)
        )
    ).all()
    if not due:
        return 0

    delivered = 0
    async with httpx.AsyncClient(
        timeout=settings.webhook_timeout_seconds,
        # An allowed host redirecting to a forbidden one would defeat the
        # address check, and a 30x is not a delivery.
        follow_redirects=False,
    ) as client:
        for delivery, webhook in due:
            sent = await _attempt(
                session, settings, client, delivery=delivery, webhook=webhook, now=now
            )
            if sent:
                delivered += 1

    await session.commit()
    return delivered


def _receiving_types(*, paused: bool, automation_webhooks_enabled: bool) -> frozenset[OrgType]:
    """Whose deliveries go out on this pass; the rest are held, never dropped.

    The automation's are held while the instance does not offer it webhooks
    (``automation_webhooks_enabled``), so switching the option off stops them
    whatever was registered before.
    """
    if paused:
        return frozenset({OrgType.ADMIN})
    if automation_webhooks_enabled:
        return frozenset(OrgType)
    return frozenset(OrgType) - {OrgType.AUTOMATION}


async def _distribution_paused(session: AsyncSession) -> bool:
    paused = await session.scalar(
        select(InstanceControl.distribution_paused).where(InstanceControl.id == 1)
    )
    return bool(paused)


async def _attempt(
    session: AsyncSession,
    settings: Settings,
    client: httpx.AsyncClient,
    *,
    delivery: WebhookDelivery,
    webhook: Webhook,
    now: dt.datetime,
) -> bool:
    """Make one delivery attempt, recording the outcome either way."""
    timestamp = now.isoformat()
    body = json.dumps(delivery.payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    try:
        target = resolve_delivery_target(
            webhook.url, allow_private=settings.dev_allow_private_webhook_targets
        )
    except WebhookRejectedError as exc:
        # The address became unacceptable after registration -- DNS now resolves
        # it inside the network, say. Not retryable by waiting, so it is spent
        # immediately rather than occupying the queue.
        delivery.error = f"target rejected: {exc.reason}"
        delivery.attempts = settings.webhook_max_attempts
        webhook.consecutive_failures += 1
        await _record_failure(session, webhook, delivery, reason=exc.reason)
        return False

    secret = (
        SecretBox.from_settings(settings).unseal(
            webhook.hmac_secret_encrypted,
            purpose=SecretPurpose.WEBHOOK_HMAC,
            subject=webhook.id,
        )
        or ""
    )
    if not secret:
        # Our fault, not the member's: a key rotated away without keeping the
        # old one configured, or the key-encryption key missing. This used to
        # spend every remaining attempt on the reasoning that waiting would not
        # fix it -- true of waiting, false of the remedy: fixing the key makes the
        # delivery sendable, and spending it had already discarded it, along
        # with a further batch on every pass until someone noticed. So the
        # attempt is not counted, the delivery is deferred and retried, and it
        # goes out on its own once the key is right.
        #
        # `consecutive_failures` is not incremented either: it describes the
        # member's endpoint, which was never at fault.
        delivery.error = KEY_UNAVAILABLE_ERROR
        delivery.next_attempt_at = now + _KEY_UNAVAILABLE_RETRY
        logger.error(
            "webhook signing key could not be opened; check AIVS_SECRET_ENCRYPTION_KEY",
            extra={"webhook_id": str(webhook.id), "delivery_id": delivery.id},
        )
        return False

    delivery.attempts += 1
    headers = {
        "content-type": "application/json",
        SIGNATURE_HEADER: sign_payload(secret.encode("utf-8"), body, timestamp),
        "x-aivs-timestamp": timestamp,
        "x-aivs-event": delivery.event,
        "user-agent": f"aivs/{settings.instance_name}",
        "Host": target.hostname,
    }

    try:
        literal = f"[{target.address}]" if ":" in target.address else target.address
        pinned = webhook.url.replace(f"//{target.hostname}", f"//{literal}:{target.port}", 1)
        response = await client.post(
            pinned,
            content=body,
            headers=headers,
            extensions={"sni_hostname": target.hostname},
        )
        delivery.response_code = response.status_code
        if _SUCCESS_FLOOR <= response.status_code < _SUCCESS_CEILING:
            delivery.delivered_at = now
            delivery.error = None
            webhook.consecutive_failures = 0
            return True
        delivery.error = f"endpoint returned {response.status_code}"
    except httpx.HTTPError as exc:
        # Deliberately broad within httpx's own hierarchy: timeouts, TLS
        # failures and connection errors are all "their endpoint did not accept
        # it", and none should propagate out of the dispatcher loop.
        delivery.error = type(exc).__name__

    webhook.consecutive_failures += 1
    delivery.next_attempt_at = now + _next_attempt_delay(delivery.attempts)
    if delivery.attempts >= settings.webhook_max_attempts:
        await _record_failure(session, webhook, delivery, reason=delivery.error or "unknown")
    return False


async def _record_failure(
    session: AsyncSession, webhook: Webhook, delivery: WebhookDelivery, *, reason: str
) -> None:
    """Audit a delivery that has run out of attempts."""
    await record(
        session,
        action=AuditAction.WEBHOOK_DELIVERY_FAILED,
        actor_type="system",
        org_id=webhook.org_id,
        resource_type="webhook",
        resource_id=str(webhook.id),
        details={
            "event": delivery.event,
            "attempts": delivery.attempts,
            "response_code": delivery.response_code,
            "error": reason,
            "consecutive_failures": webhook.consecutive_failures,
        },
    )
