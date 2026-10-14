"""Digest email: verified STARTTLS, bounded retries, no header injection.

The relay is replaced by a recorder at ``smtplib.SMTP``, so the tests see
exactly what the dispatcher asked of the connection and in what order.
"""

from __future__ import annotations

import datetime as dt
import ssl
from email.message import EmailMessage
from typing import Any, ClassVar

import pytest
from pydantic import SecretStr
from sqlalchemy import select

from aivs_schemas.enums import OrgType
from aivs_server.db.models import EmailDelivery
from aivs_server.notify.email import dispatch_pending_email

pytestmark = pytest.mark.db

NOW = dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.UTC)


class Relay:
    """A stand-in for ``smtplib.SMTP`` that records the conversation."""

    conversations: ClassVar[list[list[tuple[str, Any]]]] = []
    fail_with: ClassVar[Exception | None] = None

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.calls: list[tuple[str, Any]] = [("connect", (host, port, timeout))]
        Relay.conversations.append(self.calls)

    def __enter__(self) -> Relay:
        return self

    def __exit__(self, *exc: object) -> None:
        self.calls.append(("quit", None))

    def starttls(self, context: ssl.SSLContext) -> None:
        self.calls.append(("starttls", (context.verify_mode, context.check_hostname)))
        if Relay.fail_with is not None:
            raise Relay.fail_with

    def login(self, user: str, password: str) -> None:
        self.calls.append(("login", (user, bool(password))))

    def send_message(self, message: EmailMessage) -> None:
        self.calls.append(("send", message))


@pytest.fixture
def relay(monkeypatch):
    Relay.conversations = []
    Relay.fail_with = None
    monkeypatch.setattr("aivs_server.notify.email.smtplib.SMTP", Relay)
    return Relay


@pytest.fixture
def smtp_settings(settings):
    return settings.model_copy(
        update={
            "smtp_host": "relay.isac.example",
            "smtp_from": "digest@isac.example",
            "smtp_username": "aivs",
            "smtp_password": SecretStr("relay-password-for-tests-only"),
        }
    )


@pytest.fixture
async def queued(session, make_org):
    org = await make_org("email-firm", org_type=OrgType.GSIB)

    async def _queue(subject: str = "Sector ISAC: 1 new TLP:AMBER item") -> EmailDelivery:
        delivery = EmailDelivery(
            org_id=org.id, recipient="soc@email-firm.example", subject=subject, body="digest"
        )
        session.add(delivery)
        await session.commit()
        return delivery

    return _queue


async def _stored(session, delivery_id: int) -> EmailDelivery:
    session.expire_all()
    return (
        await session.scalars(select(EmailDelivery).where(EmailDelivery.id == delivery_id))
    ).one()


@pytest.mark.requirement("SF-74")
async def test_a_digest_is_sent_only_after_verified_starttls(session, relay, smtp_settings, queued):
    delivery = await queued()
    assert await dispatch_pending_email(session, smtp_settings, now=NOW) == 1

    [calls] = relay.conversations
    names = [name for name, _ in calls]
    assert names.index("starttls") < names.index("login") < names.index("send")
    verify_mode, check_hostname = dict(calls)["starttls"]
    assert verify_mode is ssl.CERT_REQUIRED
    assert check_hostname is True
    message = dict(calls)["send"]
    assert message["To"] == "soc@email-firm.example"
    assert message["From"] == "digest@isac.example"
    assert (await _stored(session, delivery.id)).delivered_at == NOW


async def test_without_a_relay_nothing_is_sent_and_nothing_is_lost(
    session, relay, settings, queued
):
    delivery = await queued()
    assert await dispatch_pending_email(session, settings, now=NOW) == 0
    assert relay.conversations == []
    stored = await _stored(session, delivery.id)
    assert (stored.attempts, stored.delivered_at) == (0, None)


async def test_a_failing_relay_is_retried_later_with_the_reason_kept(
    session, relay, smtp_settings, queued
):
    relay.fail_with = ConnectionRefusedError("relay down")
    delivery = await queued()
    assert await dispatch_pending_email(session, smtp_settings, now=NOW) == 0

    stored = await _stored(session, delivery.id)
    assert stored.delivered_at is None
    assert stored.attempts == 1
    assert stored.next_attempt_at is not None
    assert stored.next_attempt_at > NOW
    assert stored.error is not None
    assert "ConnectionRefusedError" in stored.error


@pytest.mark.requirement("SF-74")
async def test_a_header_with_a_line_break_is_refused_not_sent(
    session, relay, smtp_settings, queued
):
    delivery = await queued("Sector ISAC\r\nBcc: someone@elsewhere.example")
    assert await dispatch_pending_email(session, smtp_settings, now=NOW) == 0
    assert all(name != "send" for calls in relay.conversations for name, _ in calls)
    assert (await _stored(session, delivery.id)).error is not None


async def test_nothing_is_emailed_while_distribution_is_paused(
    client, session, relay, smtp_settings, queued, isac
):
    _isac_org, isac_headers = isac
    paused = await client.post(
        "/api/v1/instance/distribution/pause",
        json={"reason": "digest email test: incident drill"},
        headers=isac_headers,
    )
    assert paused.status_code == 200, paused.text
    await queued()
    assert await dispatch_pending_email(session, smtp_settings, now=NOW) == 0
    assert relay.conversations == []
