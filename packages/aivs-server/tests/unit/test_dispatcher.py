"""Draining the notification queue.

The dispatcher is the part that runs unattended, so these tests are about what
happens when things go wrong rather than when they go right: a member endpoint
that is down, one that has become unreachable, one that answers with an error.
A dispatcher that handled only the happy path would be a dispatcher that stops
delivering to everybody the first time one member's server has a bad day.

Delivery is driven directly rather than through the background loop, which is a
``while True`` with a sleep in it and nothing to assert against.
"""

from __future__ import annotations

import datetime as dt
import uuid

import httpx
import pytest
from sqlalchemy import select

from aivs_schemas.enums import OrgType
from aivs_server.db.models import Webhook, WebhookDelivery
from aivs_server.notify.dispatcher import _next_attempt_delay, dispatch_pending

pytestmark = pytest.mark.db


@pytest.fixture
async def queued(make_org, session):
    """One webhook with one notification waiting to go out.

    The URL uses a hostname that really resolves. The dispatcher resolves and
    judges the address *before* it connects, so a stand-in transport is never
    reached for a name that does not exist -- the delivery is spent on
    ``dns_resolution_failed`` instead, which is not what these tests are about.
    """

    async def _build(
        url: str = "https://example.com/hook",
    ) -> tuple[Webhook, WebhookDelivery]:
        org = await make_org(f"firm-{uuid.uuid4().hex[:8]}", org_type=OrgType.GSIB)
        webhook = Webhook(
            org_id=org.id,
            url=url,
            hmac_secret_encrypted=b"c2VjcmV0",
            events=[],
        )
        session.add(webhook)
        await session.flush()
        delivery = WebhookDelivery(
            webhook_id=webhook.id,
            event="submission.visible",
            payload={"event": "submission.visible", "submission_id": str(uuid.uuid4())},
        )
        session.add(delivery)
        await session.commit()
        return webhook, delivery

    return _build


class _Transport(httpx.AsyncBaseTransport):
    """Stands in for a member's endpoint."""

    def __init__(self, *, status_code: int = 204, raises: Exception | None = None) -> None:
        self.status_code = status_code
        self.raises = raises
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raises is not None:
            raise self.raises
        return httpx.Response(self.status_code, request=request)


@pytest.fixture
def member_endpoint(monkeypatch):
    """Point the dispatcher's client at a stand-in endpoint."""

    def _install(transport: _Transport) -> _Transport:
        real = httpx.AsyncClient

        def _factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return real(*args, **kwargs)

        monkeypatch.setattr("aivs_server.notify.dispatcher.httpx.AsyncClient", _factory)
        return transport

    return _install


async def test_a_successful_delivery_is_recorded_once(session, settings, queued, member_endpoint):
    _webhook, delivery = await queued()
    endpoint = member_endpoint(_Transport(status_code=204))

    assert await dispatch_pending(session, settings) == 1

    await session.refresh(delivery)
    assert delivery.delivered_at is not None
    assert delivery.attempts == 1
    assert delivery.error is None
    assert len(endpoint.requests) == 1

    # A delivered notification is not sent again on the next pass.
    assert await dispatch_pending(session, settings) == 0
    assert len(endpoint.requests) == 1


async def test_the_payload_is_signed_and_the_host_is_preserved(
    session, settings, queued, member_endpoint
):
    """The signature is what tells a receiver the message came from their ISAC.

    The connection is pinned to a checked address, so the Host header and SNI
    are what keep TLS verification meaningful.
    """
    _webhook, _delivery = await queued()
    endpoint = member_endpoint(_Transport(status_code=200))

    await dispatch_pending(session, settings)

    request = endpoint.requests[0]
    assert request.headers["x-aivs-signature"].startswith("v1=")
    assert request.headers["x-aivs-timestamp"]
    assert request.headers["x-aivs-event"] == "submission.visible"
    assert request.headers["host"] == "example.com"


async def test_a_failing_endpoint_is_retried_with_backoff(
    session, settings, queued, member_endpoint
):
    """Not delivered, not given up on, and not retried immediately."""
    _webhook, delivery = await queued()
    member_endpoint(_Transport(status_code=503))

    assert await dispatch_pending(session, settings) == 0

    await session.refresh(delivery)
    assert delivery.delivered_at is None
    assert delivery.attempts == 1
    assert delivery.response_code == 503
    assert delivery.next_attempt_at is not None, "backed off rather than spun on"

    # Not due yet, so a pass right now does nothing.
    assert await dispatch_pending(session, settings) == 0
    await session.refresh(delivery)
    assert delivery.attempts == 1


async def test_a_connection_failure_is_recorded_not_raised(
    session, settings, queued, member_endpoint
):
    """One member's unreachable endpoint must not end the loop for everyone."""
    _webhook, delivery = await queued()
    member_endpoint(_Transport(raises=httpx.ConnectError("refused")))

    assert await dispatch_pending(session, settings) == 0

    await session.refresh(delivery)
    assert delivery.error == "ConnectError"
    assert delivery.delivered_at is None


async def test_attempts_are_bounded(session, settings, queued, member_endpoint):
    """A member down for a week does not accumulate an unbounded backlog."""
    _webhook, delivery = await queued()
    member_endpoint(_Transport(status_code=500))

    now = dt.datetime.now(dt.UTC)
    for attempt in range(settings.webhook_max_attempts):
        # Step past each backoff rather than waiting for it.
        await dispatch_pending(session, settings, now=now + dt.timedelta(hours=attempt + 1))

    await session.refresh(delivery)
    assert delivery.attempts == settings.webhook_max_attempts

    # Spent: further passes leave it alone, and the row keeps the last error so
    # an operator asking "did they get told?" has an answer.
    assert await dispatch_pending(session, settings, now=now + dt.timedelta(days=7)) == 0
    await session.refresh(delivery)
    assert delivery.attempts == settings.webhook_max_attempts
    assert delivery.error is not None


async def test_an_unroutable_target_is_spent_immediately(
    session, settings, queued, member_endpoint
):
    """A URL that now resolves inside the network is not retryable by waiting."""
    _webhook, delivery = await queued(url="https://127.0.0.1/hook")
    endpoint = member_endpoint(_Transport(status_code=204))

    assert await dispatch_pending(session, settings) == 0

    await session.refresh(delivery)
    assert delivery.delivered_at is None
    assert "address_not_routable" in (delivery.error or "")
    assert delivery.attempts == settings.webhook_max_attempts, "not left occupying the queue"
    assert endpoint.requests == [], "and never connected to"


async def test_a_deactivated_webhook_is_not_delivered_to(
    session, settings, queued, member_endpoint
):
    webhook, _delivery = await queued()
    endpoint = member_endpoint(_Transport(status_code=204))

    webhook.is_active = False
    await session.commit()

    assert await dispatch_pending(session, settings) == 0
    assert endpoint.requests == []


def test_backoff_grows_and_is_capped():
    """Retries stretch over hours, not seconds, and stop stretching at an hour."""
    delays = [_next_attempt_delay(n).total_seconds() for n in range(1, 8)]
    assert delays == sorted(delays), "monotonic"
    assert delays[0] < delays[-1]
    assert max(delays) <= 3600


async def test_nothing_due_is_a_cheap_no_op(session, settings, member_endpoint):
    endpoint = member_endpoint(_Transport(status_code=204))
    assert await dispatch_pending(session, settings) == 0
    assert endpoint.requests == []


async def test_a_delivery_for_a_removed_webhook_is_ignored(session, settings, queued):
    """The join means an orphaned delivery simply stops being due."""
    webhook, _delivery = await queued()
    await session.delete(webhook)
    await session.commit()

    assert await dispatch_pending(session, settings) == 0
    remaining = (await session.execute(select(WebhookDelivery))).scalars().all()
    assert remaining == [], "cascade removes the deliveries with the registration"
