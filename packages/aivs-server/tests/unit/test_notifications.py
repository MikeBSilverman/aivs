"""Contentless notifications: who gets told, when, and what the message may say.

The tests are organised around the three properties that make this feature safe
to have at all. Every one of them is a thing that would be tempting to "improve"
later by putting more in the payload or firing it sooner, so each says why.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import OrgType
from aivs_server.auth.secretbox import SecretBox, SecretPurpose
from aivs_server.db.models import CircleMembership, Webhook, WebhookDelivery
from aivs_server.notify.events import EVENT_SUBMISSION_VISIBLE
from tests.conftest import proxy_headers


def _seal(secret_box: SecretBox, webhook_id: uuid.UUID) -> bytes:
    """Seal a signing key the way the application does.

    These fixtures used to write ``b"c2VjcmV0"`` -- the base64 form the sealing
    migration exists to remove. They stayed green because none of them
    dispatches, but they were registrations no delivery could ever have been
    signed for, and they are exactly the shape the ``secret_box`` fixture's
    docstring warns against.
    """
    return secret_box.seal(
        "webhook-signing-secret", purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook_id
    )


pytestmark = pytest.mark.db

API = "/api/v1"


def bundle() -> dict:
    stamp = "2026-08-01T00:00:00.000Z"
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{uuid.uuid4()}",
                "created": stamp,
                "modified": stamp,
                "name": "Prompt injection in agent runtime",
            }
        ],
    }


@pytest.fixture
async def subscriber(make_org, make_cert, make_circle, join_circle, session, secret_box):
    """A member of a circle with an active webhook."""

    async def _build(circle, slug: str = "subscriber-firm"):
        org = await make_org(slug, org_type=OrgType.GSIB)
        pem, _ = await make_cert(org)
        await join_circle(org, circle)
        webhook_id = uuid.uuid4()
        webhook = Webhook(
            id=webhook_id,
            org_id=org.id,
            url="https://member.example/aivs-hook",
            hmac_secret_encrypted=_seal(secret_box, webhook_id),
            events=[],
        )
        session.add(webhook)
        await session.commit()
        return org, pem, webhook

    return _build


async def deliveries(session) -> list[WebhookDelivery]:
    return list((await session.execute(select(WebhookDelivery))).scalars().all())


async def distribute(client, isac_headers, member_pem, circle, *, release_at=None):
    """Drive a submission all the way to distributed. Returns its id."""
    created = await client.post(
        f"{API}/submissions",
        json={
            "title": "AI-discovered chain in agent runtime",
            "discovery_scope": "ai_system",
            "bundle": bundle(),
        },
        headers=proxy_headers(member_pem),
    )
    assert created.status_code == 201, created.text
    submission_id = created.json()["id"]

    for verb, headers in (("submit", proxy_headers(member_pem)), ("validate", isac_headers)):
        step = await client.post(
            f"{API}/submissions/{submission_id}/{verb}", json={}, headers=headers
        )
        assert step.status_code == 200, step.text

    body: dict = {"circle_ids": [str(circle.id)]}
    if release_at is not None:
        body["release_at"] = release_at.isoformat()
    sent = await client.post(
        f"{API}/submissions/{submission_id}/distribute",
        json=body,
        headers=isac_headers,
    )
    assert sent.status_code == 200, sent.text
    return submission_id


# ---------------------------------------------------------------------------
# What the message may say
# ---------------------------------------------------------------------------
async def test_the_notification_carries_no_content(
    client,
    isac,
    subscriber,
    make_circle,
    make_collection,
    make_org,
    make_cert,
    join_circle,
    session,
):
    """Identifiers and nothing else.

    No title, no TLP, no summary. A notification reaches an endpoint the ISAC
    cannot audit and may be relayed into a chat integration or a third-party log;
    the worst case for a leaked one must be that somebody learns a submission
    exists.
    """
    _isac_org, isac_headers = isac
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    _sub_org, _sub_pem, webhook = await subscriber(circle)

    submitter = await make_org("submitting-firm", org_type=OrgType.GSIB)
    submitter_pem, _ = await make_cert(submitter)
    await join_circle(submitter, circle)

    submission_id = await distribute(client, isac_headers, submitter_pem, circle)

    queued = await deliveries(session)
    assert len(queued) == 1
    payload = queued[0].payload

    assert payload["submission_id"] == submission_id
    assert payload["collection_id"] == str(collection.id)
    assert queued[0].event == EVENT_SUBMISSION_VISIBLE
    assert queued[0].webhook_id == webhook.id

    serialised = str(payload).lower()
    for leaked in ("prompt injection", "agent runtime", "tlp", "amber", "submitting-firm"):
        assert leaked not in serialised, f"{leaked!r} must not appear in a notification"


async def test_a_submitter_is_not_notified_about_their_own_submission(
    client,
    isac,
    make_circle,
    make_collection,
    make_org,
    make_cert,
    join_circle,
    session,
    secret_box,
):
    """Noise at best; for an anonymous submission, a small confirmation."""
    _isac_org, isac_headers = isac
    circle = await make_circle("section9")
    await make_collection(circle)

    submitter = await make_org("submitting-firm", org_type=OrgType.GSIB)
    submitter_pem, _ = await make_cert(submitter)
    await join_circle(submitter, circle)
    webhook_id = uuid.uuid4()
    session.add(
        Webhook(
            id=webhook_id,
            org_id=submitter.id,
            url="https://submitter.example/hook",
            hmac_secret_encrypted=_seal(secret_box, webhook_id),
            events=[],
        )
    )
    await session.commit()

    await distribute(client, isac_headers, submitter_pem, circle)
    assert await deliveries(session) == []


# ---------------------------------------------------------------------------
# When it fires
# ---------------------------------------------------------------------------
async def test_an_embargoed_distribution_notifies_nobody_yet(
    client,
    isac,
    subscriber,
    make_circle,
    make_collection,
    make_org,
    make_cert,
    join_circle,
    session,
):
    """Visibility, not distribution.

    Telling a member about content they cannot read is either useless or an
    early disclosure that something is coming.
    """
    _isac_org, isac_headers = isac
    circle = await make_circle("section9")
    await make_collection(circle)
    await subscriber(circle)

    submitter = await make_org("submitting-firm", org_type=OrgType.GSIB)
    submitter_pem, _ = await make_cert(submitter)
    await join_circle(submitter, circle)

    await distribute(
        client,
        isac_headers,
        submitter_pem,
        circle,
        release_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=2),
    )
    assert await deliveries(session) == [], "an embargo is not yet an event"


async def test_releasing_an_embargo_early_notifies(
    client,
    isac,
    subscriber,
    make_circle,
    make_collection,
    make_org,
    make_cert,
    join_circle,
    session,
):
    """The case where prompt notification matters most.

    An operator releases early because something is being exploited now.
    """
    _isac_org, isac_headers = isac
    circle = await make_circle("section9")
    await make_collection(circle)
    await subscriber(circle)

    submitter = await make_org("submitting-firm", org_type=OrgType.GSIB)
    submitter_pem, _ = await make_cert(submitter)
    await join_circle(submitter, circle)

    submission_id = await distribute(
        client,
        isac_headers,
        submitter_pem,
        circle,
        release_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=2),
    )
    assert await deliveries(session) == []

    released = await client.post(
        f"{API}/submissions/{submission_id}/embargo/release",
        json={},
        headers=isac_headers,
    )
    assert released.status_code == 200, released.text

    queued = await deliveries(session)
    assert len(queued) == 1
    assert queued[0].payload["submission_id"] == submission_id


# ---------------------------------------------------------------------------
# Who gets told
# ---------------------------------------------------------------------------
async def test_an_organisation_that_joined_later_is_not_notified(
    client,
    isac,
    make_circle,
    make_collection,
    make_org,
    make_cert,
    join_circle,
    session,
    secret_box,
):
    """Notification follows visibility exactly.

    An organisation that joined after the content was shared cannot read it, so
    telling them it exists would advertise something they are not entitled to --
    and would be the back-catalogue leak reappearing as metadata.
    """
    _isac_org, isac_headers = isac
    circle = await make_circle("section9")
    await make_collection(circle)

    submitter = await make_org("submitting-firm", org_type=OrgType.GSIB)
    submitter_pem, _ = await make_cert(submitter)
    await join_circle(submitter, circle)

    latecomer = await make_org("late-firm", org_type=OrgType.GSIB)
    await make_cert(latecomer)
    await join_circle(latecomer, circle, joined_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=1))
    webhook_id = uuid.uuid4()
    session.add(
        Webhook(
            id=webhook_id,
            org_id=latecomer.id,
            url="https://late.example/hook",
            hmac_secret_encrypted=_seal(secret_box, webhook_id),
            events=[],
        )
    )
    await session.commit()

    await distribute(client, isac_headers, submitter_pem, circle)
    assert await deliveries(session) == []


async def test_a_webhook_subscribed_to_other_events_is_skipped(
    client,
    isac,
    make_circle,
    make_collection,
    make_org,
    make_cert,
    join_circle,
    session,
    secret_box,
):
    _isac_org, isac_headers = isac
    circle = await make_circle("section9")
    await make_collection(circle)

    submitter = await make_org("submitting-firm", org_type=OrgType.GSIB)
    submitter_pem, _ = await make_cert(submitter)
    await join_circle(submitter, circle)

    other = await make_org("selective-firm", org_type=OrgType.GSIB)
    await make_cert(other)
    await join_circle(other, circle)
    webhook_id = uuid.uuid4()
    session.add(
        Webhook(
            id=webhook_id,
            org_id=other.id,
            url="https://selective.example/hook",
            hmac_secret_encrypted=_seal(secret_box, webhook_id),
            events=["something.else"],
        )
    )
    await session.commit()

    await distribute(client, isac_headers, submitter_pem, circle)
    assert await deliveries(session) == []


async def test_a_queued_notification_starts_undelivered(
    client,
    isac,
    subscriber,
    make_circle,
    make_collection,
    make_org,
    make_cert,
    join_circle,
    session,
):
    """The row is a promise, not a record of something already sent.

    That is what makes delivery survive a restart: a process that dies before
    sending has still written down that it owes one.
    """
    _isac_org, isac_headers = isac
    circle = await make_circle("section9")
    await make_collection(circle)
    await subscriber(circle)

    submitter = await make_org("submitting-firm", org_type=OrgType.GSIB)
    submitter_pem, _ = await make_cert(submitter)
    await join_circle(submitter, circle)

    await distribute(client, isac_headers, submitter_pem, circle)

    queued = (await deliveries(session))[0]
    assert queued.delivered_at is None
    assert queued.attempts == 0
    assert queued.next_attempt_at is None, "due immediately"


@pytest.mark.requirement("SF-61")
async def test_a_former_member_is_not_notified_and_a_current_one_is(
    client, isac, make_circle, make_collection, make_org, make_cert, subscriber, session, secret_box
):
    """SF-61: a released embargo used to notify an organisation that had left.

    The notification query bounded by ``joined_at`` alone, so any interval that
    had ever covered the moment of release qualified -- and a former member was
    told what was shared after it went. The current subscriber is the control.
    """
    _isac_org, isac_headers = isac
    circle = await make_circle("section9")
    await make_collection(circle)
    _current_org, _pem, current_hook = await subscriber(circle)

    submitter = await make_org("submitting-firm", org_type=OrgType.GSIB)
    submitter_pem, _ = await make_cert(submitter)
    session.add(CircleMembership(circle_id=circle.id, org_id=submitter.id))

    former = await make_org("former-member", org_type=OrgType.GSIB)
    now = dt.datetime.now(dt.UTC)
    session.add(
        CircleMembership(
            circle_id=circle.id,
            org_id=former.id,
            joined_at=now - dt.timedelta(days=30),
            left_at=now - dt.timedelta(days=1),
            ended_by="operator",
        )
    )
    former_hook_id = uuid.uuid4()
    session.add(
        Webhook(
            id=former_hook_id,
            org_id=former.id,
            url="https://former.example/hook",
            hmac_secret_encrypted=_seal(secret_box, former_hook_id),
            events=[],
        )
    )
    await session.commit()

    await distribute(client, isac_headers, submitter_pem, circle)

    notified = {delivery.webhook_id for delivery in await deliveries(session)}
    assert former_hook_id not in notified
    assert current_hook.id in notified
