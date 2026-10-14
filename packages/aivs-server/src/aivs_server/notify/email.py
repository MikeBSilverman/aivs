"""Drains queued digest emails to the ISAC's SMTP relay.

The relay is a subprocessor the ISAC names to its members, and it only ever
sees the contentless digest (``notify.digest``). Three rules, each one a way
this kind of code usually goes wrong:

* **STARTTLS is required, with the certificate verified.** There is no setting
  for plaintext and none for skipping verification: a digest names products
  and links, and a relay reached in the clear, or through a man in the middle,
  is a third party reading which products a member runs.
* **Delivery never runs inside the transaction that queued it,** for the reason
  the webhook dispatcher gives: a stalled relay would hold the digest's rows.
* **Bounded retries, recorded outcomes.** A delivery that exhausts its attempts
  keeps its row and its last error, so "were they emailed?" has an answer.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgStatus
from aivs_server.config import Settings
from aivs_server.db.models import EmailDelivery, Organization
from aivs_server.services.publication import publication_paused

__all__ = ["dispatch_pending_email", "send_email"]

logger = logging.getLogger(__name__)

_BATCH_SIZE: Final[int] = 20
_BACKOFF_BASE: Final[int] = 5


def send_email(settings: Settings, *, recipient: str, subject: str, body: str) -> None:
    """Send one message through the configured relay, over verified STARTTLS. Blocking.

    ``EmailMessage`` refuses a header value containing a line break, so a
    recipient or subject cannot inject headers whatever wrote it.
    """
    if settings.smtp_host is None or settings.smtp_from is None:
        msg = "no SMTP relay is configured"
        raise RuntimeError(msg)
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    context = ssl.create_default_context()
    with smtplib.SMTP(
        settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_seconds
    ) as relay:
        relay.starttls(context=context)
        if settings.smtp_username and settings.smtp_password is not None:
            relay.login(settings.smtp_username, settings.smtp_password.get_secret_value())
        relay.send_message(message)


async def dispatch_pending_email(
    session: AsyncSession, settings: Settings, *, now: dt.datetime | None = None
) -> int:
    """Attempt every digest email that is due. Returns the number sent. Commits once."""
    if settings.smtp_host is None or await publication_paused(session):
        return 0
    now = now or dt.datetime.now(dt.UTC)
    due = (
        await session.scalars(
            select(EmailDelivery)
            .join(Organization, Organization.id == EmailDelivery.org_id)
            .where(
                Organization.status == OrgStatus.ACTIVE,
                EmailDelivery.delivered_at.is_(None),
                EmailDelivery.attempts < settings.email_max_attempts,
                (EmailDelivery.next_attempt_at.is_(None)) | (EmailDelivery.next_attempt_at <= now),
            )
            .order_by(EmailDelivery.id)
            .limit(_BATCH_SIZE)
        )
    ).all()
    sent = 0
    for delivery in due:
        if await _attempt(settings, delivery, now):
            sent += 1
    await session.commit()
    return sent


async def _attempt(settings: Settings, delivery: EmailDelivery, now: dt.datetime) -> bool:
    delivery.attempts += 1
    try:
        await asyncio.to_thread(
            send_email,
            settings,
            recipient=delivery.recipient,
            subject=delivery.subject,
            body=delivery.body,
        )
    except (OSError, smtplib.SMTPException, ValueError) as exc:
        # The error class and message describe our relay, not the digest; the
        # recipient is the member's own routing address.
        delivery.error = f"{type(exc).__name__}: {exc}"[:500]
        delivery.next_attempt_at = now + dt.timedelta(
            seconds=min(_BACKOFF_BASE**delivery.attempts, 3600)
        )
        logger.warning("digest email %s not sent: %s", delivery.id, type(exc).__name__)
        return False
    delivery.delivered_at = now
    delivery.error = None
    return True
