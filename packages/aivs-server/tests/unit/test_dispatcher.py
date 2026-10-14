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

import base64
import datetime as dt
import uuid

import httpx
import pytest
from sqlalchemy import select

from aivs_schemas.enums import OrgType
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db.models import Webhook, WebhookDelivery
from aivs_server.notify.dispatcher import _next_attempt_delay, dispatch_pending
from aivs_server.notify.webhooks import SIGNATURE_HEADER, sign_payload
from aivs_server.services.detections import RULES
from tests.conftest import StubEndpoint, proxy_headers

pytestmark = pytest.mark.db


@pytest.fixture
async def queued(make_org, session, secret_box):
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
        # Explicit id: the signing key is sealed against it, and the column
        # default is not applied until flush.
        webhook_id = uuid.uuid4()
        webhook = Webhook(
            id=webhook_id,
            org_id=org.id,
            url=url,
            hmac_secret_encrypted=secret_box.seal(
                "webhook-signing-secret",
                purpose=SecretPurpose.WEBHOOK_HMAC,
                subject=webhook_id,
            ),
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


async def test_a_successful_delivery_is_recorded_once(session, settings, queued, member_endpoint):
    _webhook, delivery = await queued()
    endpoint = member_endpoint(StubEndpoint(status_code=204))

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
    endpoint = member_endpoint(StubEndpoint(status_code=200))

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
    member_endpoint(StubEndpoint(status_code=503))

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
    member_endpoint(StubEndpoint(raises=httpx.ConnectError("refused")))

    assert await dispatch_pending(session, settings) == 0

    await session.refresh(delivery)
    assert delivery.error == "ConnectError"
    assert delivery.delivered_at is None


async def test_attempts_are_bounded(session, settings, queued, member_endpoint):
    """A member down for a week does not accumulate an unbounded backlog."""
    _webhook, delivery = await queued()
    member_endpoint(StubEndpoint(status_code=500))

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
    endpoint = member_endpoint(StubEndpoint(status_code=204))

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
    endpoint = member_endpoint(StubEndpoint(status_code=204))

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
    endpoint = member_endpoint(StubEndpoint(status_code=204))
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


async def _key_alerts(session, now):
    rule = next(r for r in RULES if r.name == "signing_key_unavailable")
    return await rule.check(session, now, rule.window, rule.threshold)


async def test_an_unopenable_signing_key_defers_the_delivery_until_it_is_fixed(
    session, settings, queued, member_endpoint
):
    """Finding #6: a key we cannot open used to spend the delivery outright.

    The realistic cause is our own misconfiguration -- a key-encryption key
    rotated away without keeping the previous one. The member's endpoint must
    not be contacted with a signature it is obliged to reject, nor charged a
    failure for it. But the delivery must not be discarded either: fixing the
    key makes it sendable, and spending it (as this test used to require)
    meant each pass discarded another batch of warnings members were owed.
    The pair: not sent and not spent while the key is broken; sent, on its own,
    once it is fixed.
    """
    webhook, delivery = await queued()
    sealed = webhook.hmac_secret_encrypted
    # A well-formed envelope -- current magic, version and algorithm -- sealed
    # under a key fingerprint nothing matches: what a rotation that dropped the
    # previous key too early leaves behind.
    webhook.hmac_secret_encrypted = b"AIVS" + bytes((1, 1)) + b"\xde\xad\xbe\xef" + b"\x00" * 28
    await session.commit()
    endpoint = member_endpoint(StubEndpoint(status_code=204))
    now = dt.datetime.now(dt.UTC)

    assert await dispatch_pending(session, settings, now=now) == 0
    await session.refresh(delivery)
    await session.refresh(webhook)
    assert endpoint.requests == [], "never sent unsigned"
    assert delivery.attempts == 0, "the attempt is not charged"
    assert delivery.next_attempt_at is not None
    assert delivery.next_attempt_at > now, "deferred, to be retried"
    assert webhook.consecutive_failures == 0, "not held against the member's endpoint"
    # Held, but not silently: the ISAC is alerted (it was not, before review).
    assert [f.subject for f in await _key_alerts(session, now)] == [str(webhook.id)]

    webhook.hmac_secret_encrypted = sealed
    await session.commit()
    later = delivery.next_attempt_at + dt.timedelta(seconds=1)

    assert await dispatch_pending(session, settings, now=later) == 1
    await session.refresh(delivery)
    assert delivery.delivered_at is not None
    assert len(endpoint.requests) == 1
    assert await _key_alerts(session, later) == [], "nothing held once delivered"


# ---------------------------------------------------------------------------
# The two halves of the signing secret, joined
# ---------------------------------------------------------------------------
async def test_the_signature_verifies_against_the_secret_the_member_was_given(
    client, session, settings, make_org, make_cert, member_endpoint
):
    """Registration and delivery are tested end to end, through the API.

    Both halves were previously tested apart: registration asserted a secret was
    returned, delivery asserted the header started with "v1=", and `sign_payload`
    was exercised on its own. Nothing joined them, so signing every payload with
    a hardcoded constant passed the entire suite -- and verifiability is the only
    reason this secret has to be reversible at all, and therefore the only
    justification for sealing it rather than hashing it.

    This is also the test that fails if the seal is ever bypassed: the plaintext
    handed to the member at registration must be exactly what comes back out of
    the sealed column at delivery time.
    """
    org = await make_org(f"firm-{uuid.uuid4().hex[:8]}", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)

    created = await client.post(
        "/api/v1/webhooks",
        json={"url": "https://example.com/aivs-hook"},
        headers=proxy_headers(pem),
    )
    assert created.status_code == 201, created.text
    member_secret = created.json()["signing_secret"]

    webhook = (await session.execute(select(Webhook).where(Webhook.org_id == org.id))).scalar_one()
    session.add(
        WebhookDelivery(
            webhook_id=webhook.id,
            event="submission.visible",
            payload={"event": "submission.visible", "submission_id": str(uuid.uuid4())},
        )
    )
    await session.commit()

    endpoint = member_endpoint(StubEndpoint(status_code=204))
    assert await dispatch_pending(session, settings) == 1

    request = endpoint.requests[0]
    expected = sign_payload(
        member_secret.encode("utf-8"),
        request.content,
        request.headers["x-aivs-timestamp"],
    )
    assert request.headers[SIGNATURE_HEADER] == expected, (
        "the delivered signature is not the one the member's own secret produces"
    )


@pytest.mark.db
async def test_the_stored_signing_key_is_not_recoverable_from_the_column(
    client, session, make_org, make_cert
):
    """A database read must not yield the member's signing key.

    The whole point of `auth/secretbox.py`. Asserted against the column the
    application actually writes, through the API that writes it -- the unit
    tests exercise the primitive in isolation, which stays green even if the
    application stores plaintext.
    """
    org = await make_org(f"firm-{uuid.uuid4().hex[:8]}", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)

    created = await client.post(
        "/api/v1/webhooks",
        json={"url": "https://example.com/aivs-hook"},
        headers=proxy_headers(pem),
    )
    assert created.status_code == 201, created.text
    member_secret = created.json()["signing_secret"]

    stored = (
        await session.execute(select(Webhook.hmac_secret_encrypted).where(Webhook.org_id == org.id))
    ).scalar_one()

    assert stored.startswith(b"AIVS"), "not in the sealed envelope format"
    assert member_secret.encode("utf-8") not in stored
    assert member_secret.encode("ascii") not in base64.b64decode(base64.b64encode(stored)), (
        "not merely encoded"
    )
