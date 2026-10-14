"""Notification cadence and the contentless digest.

The windows and the wording are pure and tabled; the rest drives the real
workflow and reads the queue it fills, because a digest is only as right as
the notices the distribution path held (CLAUDE.md section 2).
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select, update

from aivs_schemas.enums import TLP, NotificationCadence, OrgType
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db.models import (
    CircleMembership,
    EmailDelivery,
    Organization,
    PendingNotice,
    Webhook,
    WebhookDelivery,
)
from aivs_server.notify.digest import (
    EVENT_DIGEST,
    DigestItem,
    digest_due,
    render_email,
    send_due_digests,
    summary_line,
)
from aivs_server.notify.events import EVENT_SUBMISSION_VISIBLE
from tests.conftest import proxy_headers
from tests.unit.sharing import sdo, share, stamp, vulnerability_intel

H, D, NOW_ = NotificationCadence.HOURLY, NotificationCadence.DAILY, NotificationCadence.IMMEDIATE
NOON = dt.datetime(2026, 10, 14, 12, 20, tzinfo=dt.UTC)


# ---------------------------------------------------------------------------
# The windows, and the wording, as pure functions
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("cadence", "now", "due"),
    [
        (NOW_, NOON, True),
        (H, NOON.replace(minute=59), False),
        (H, NOON.replace(hour=13, minute=0), True),
        (D, NOON.replace(hour=23), False),
        (D, NOON + dt.timedelta(days=1, hours=-5, minutes=-20), True),
        (D, NOON + dt.timedelta(days=1, hours=-5, minutes=-21), False),
    ],
)
def test_a_window_closes_on_the_clock_not_on_the_first_notice(cadence, now, due):
    assert digest_due(cadence, NOON, now, daily_hour=7) is due


def test_a_daily_window_opened_before_the_hour_closes_the_same_day():
    early = NOON.replace(hour=3)
    assert digest_due(D, early, early.replace(hour=7), daily_hour=7)


def item(marking: TLP, *, title: str | None = None, products=(), updates: int = 1) -> DigestItem:
    return DigestItem(
        submission_id=uuid.uuid4(),
        collection_id=uuid.uuid4(),
        visible_at=NOON,
        updates=updates,
        marking=marking,
        title=title,
        products=list(products),
    )


def test_the_summary_counts_by_marking_most_restrictive_first():
    items = [item(TLP.GREEN), item(TLP.AMBER), item(TLP.AMBER), item(TLP.AMBER)]
    assert summary_line(items) == "3 new TLP:AMBER items, 1 new TLP:GREEN item"


def test_an_email_names_a_green_title_and_only_the_products_of_an_amber_item():
    subject, body = render_email(
        "Sector ISAC",
        [
            item(TLP.GREEN, title="Gateway patch released"),
            item(TLP.AMBER, products=["Acme Gateway"], updates=3),
        ],
        "https://aivs.example",
    )
    assert subject == "Sector ISAC: 1 new TLP:AMBER item, 1 new TLP:GREEN item"
    assert "[TLP:GREEN] Gateway patch released:" in body
    assert "[TLP:AMBER] an item about Acme Gateway (updated 3 times):" in body
    assert "https://aivs.example/taxii2/aivs/collections/" in body


# ---------------------------------------------------------------------------
# Through the workflow
# ---------------------------------------------------------------------------
@pytest.fixture
async def world(
    client,
    isac,
    make_org,
    make_cert,
    make_circle,
    make_collection,
    join_circle,
    session,
    secret_box,
):
    _isac_org, isac_headers = isac
    vendor = await make_org("digest-vendor", org_type=OrgType.GSIB)
    vendor_pem, _ = await make_cert(vendor)
    reader = await make_org("digest-reader", org_type=OrgType.GSIB)
    circle = await make_circle("digest")
    # A floor that admits GREEN, so the title rule can be shown on both sides.
    circle.minimum_tlp = TLP.CLEAR
    collection = await make_collection(circle)
    for org in (vendor, reader):
        await join_circle(org, circle)
    webhook_id = uuid.uuid4()
    session.add(
        Webhook(
            id=webhook_id,
            org_id=reader.id,
            url="https://reader.example/hook",
            hmac_secret_encrypted=secret_box.seal(
                "webhook-signing-secret", purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook_id
            ),
            events=[],
        )
    )
    await session.commit()
    return {
        "isac": isac_headers,
        "vendor_pem": vendor_pem,
        "reader": reader,
        "circle": circle,
        "collection": collection,
        "webhook_id": webhook_id,
    }


async def _set_cadence(
    session, org, cadence: NotificationCadence, email: str | None = None
) -> None:
    await session.execute(
        update(Organization)
        .where(Organization.id == org.id)
        .values(notification_cadence=cadence, digest_email=email)
    )
    await session.commit()


def _vulnerability(name: str = "Gateway auth bypass", **extra: object) -> dict:
    return sdo("vulnerability", name=name, extensions=vulnerability_intel(**extra))


async def _share(client, world, objects, *, tlp="amber", title="Gateway advisory") -> str:
    return await share(
        client,
        world["vendor_pem"],
        world["isac"],
        objects,
        [world["circle"].id],
        tlp=tlp,
        title=title,
    )


async def _deliveries(session, event: str) -> list[WebhookDelivery]:
    session.expire_all()
    return list(
        (await session.scalars(select(WebhookDelivery).where(WebhookDelivery.event == event))).all()
    )


async def _digest(session, now, *, email_enabled=False) -> int:
    return await send_due_digests(
        session,
        now=now,
        daily_hour=7,
        base_url="https://aivs.example",
        instance_name="Sector ISAC",
        email_enabled=email_enabled,
    )


@pytest.mark.requirement("SF-74")
async def test_an_immediate_member_is_told_at_once_with_the_products_to_route_on(
    client, session, world
):
    await _share(client, world, [_vulnerability()])
    [delivery] = await _deliveries(session, EVENT_SUBMISSION_VISIBLE)
    assert delivery.payload["affected_products"] == ["Acme Gateway"]
    assert await session.scalar(select(PendingNotice.id)) is None


@pytest.mark.requirement("SF-74")
async def test_a_red_notice_names_no_products(client, session, world):
    await _share(client, world, [_vulnerability()], tlp="red")
    [delivery] = await _deliveries(session, EVENT_SUBMISSION_VISIBLE)
    assert delivery.payload["affected_products"] == []


async def test_an_hourly_member_is_held_and_versions_of_one_advisory_coalesce(
    client, session, world
):
    await _set_cadence(session, world["reader"], H)
    advisory = _vulnerability()
    await _share(client, world, [advisory])
    revised = advisory | {"modified": stamp(dt.datetime.now(dt.UTC).replace(microsecond=0))}
    await _share(client, world, [revised])

    assert await _deliveries(session, EVENT_SUBMISSION_VISIBLE) == []
    [notice] = (await session.scalars(select(PendingNotice))).all()
    assert (notice.subject, notice.versions) == (advisory["id"], 2)


@pytest.mark.requirement("SF-74")
async def test_a_digest_waits_for_its_window_then_says_what_became_visible(client, session, world):
    await _set_cadence(session, world["reader"], H)
    await _share(client, world, [_vulnerability()], title="Pre-auth RCE in Acme Gateway")
    now = dt.datetime.now(dt.UTC)

    assert await _digest(session, now) == 0
    assert await _digest(session, now + dt.timedelta(hours=1)) == 1

    [delivery] = await _deliveries(session, EVENT_DIGEST)
    assert delivery.webhook_id == world["webhook_id"]
    [entry] = delivery.payload["items"]
    assert entry["marking"] == "TLP:AMBER"
    assert entry["affected_products"] == ["Acme Gateway"]
    assert "title" not in entry, "an AMBER title is content"
    assert "Pre-auth RCE" not in str(delivery.payload)
    assert await session.scalar(select(PendingNotice.id)) is None


@pytest.mark.requirement("SF-74")
async def test_a_green_title_is_in_the_digest(client, session, world):
    await _set_cadence(session, world["reader"], H)
    await _share(
        client, world, [_vulnerability()], tlp="green", title="Acme Gateway 4.2.1 released"
    )
    await _digest(session, dt.datetime.now(dt.UTC) + dt.timedelta(hours=1))
    [delivery] = await _deliveries(session, EVENT_DIGEST)
    assert delivery.payload["items"][0]["title"] == "Acme Gateway 4.2.1 released"


@pytest.mark.requirement("SF-61")
async def test_a_member_that_left_before_the_digest_is_not_told(client, session, world):
    await _set_cadence(session, world["reader"], H)
    await _share(client, world, [_vulnerability()])
    await session.execute(
        update(CircleMembership)
        .where(CircleMembership.org_id == world["reader"].id)
        .values(left_at=dt.datetime.now(dt.UTC), ended_by="operator")
    )
    await session.commit()

    assert await _digest(session, dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)) == 0
    assert await _deliveries(session, EVENT_DIGEST) == []
    assert await session.scalar(select(PendingNotice.id)) is None, "spent, not kept for later"


@pytest.mark.requirement("SF-74")
async def test_nothing_is_sent_while_paused_and_the_notices_wait(client, session, world):
    await _set_cadence(session, world["reader"], H)
    await _share(client, world, [_vulnerability()])
    paused = await client.post(
        "/api/v1/instance/distribution/pause",
        json={"reason": "digest test: incident drill"},
        headers=world["isac"],
    )
    assert paused.status_code == 200, paused.text

    assert await _digest(session, dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)) == 0
    assert await session.scalar(select(PendingNotice.id)) is not None


@pytest.mark.parametrize(("email_enabled", "queued"), [(True, 1), (False, 0)])
async def test_a_digest_mailbox_gets_the_same_digest_when_a_relay_is_configured(
    client, session, world, email_enabled, queued
):
    await _set_cadence(session, world["reader"], D, email="soc-queue@reader.example")
    await _share(client, world, [_vulnerability()])
    await _digest(
        session,
        dt.datetime.now(dt.UTC) + dt.timedelta(days=1, hours=1),
        email_enabled=email_enabled,
    )
    emails = (await session.scalars(select(EmailDelivery))).all()
    assert len(emails) == queued
    if emails:
        assert emails[0].recipient == "soc-queue@reader.example"
        assert "1 new TLP:AMBER item" in emails[0].subject


# ---------------------------------------------------------------------------
# The organisation's own settings
# ---------------------------------------------------------------------------
async def test_a_member_sets_its_own_cadence_and_mailbox(client, session, make_org, make_cert):
    org = await make_org("settings-firm", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    changed = await client.put(
        "/api/v1/notification-settings",
        json={"cadence": "daily", "digest_email": "soc@settings.example"},
        headers=proxy_headers(pem),
    )
    assert changed.status_code == 200, changed.text
    read = await client.get("/api/v1/notification-settings", headers=proxy_headers(pem))
    assert read.json() == {"cadence": "daily", "digest_email": "soc@settings.example"}


@pytest.mark.requirement("SF-74")
@pytest.mark.parametrize(
    "body",
    [
        {"cadence": "immediate", "digest_email": "soc@settings.example"},
        {"cadence": "daily", "digest_email": "not a mailbox\r\nBcc: x@y.example"},
    ],
)
async def test_a_mailbox_needs_a_digest_cadence_and_must_be_a_mailbox(
    client, session, make_org, make_cert, body
):
    org = await make_org("settings-refused", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    refused = await client.put(
        "/api/v1/notification-settings", json=body, headers=proxy_headers(pem)
    )
    assert refused.status_code == 400
    stored = tuple(
        (
            await session.execute(
                select(Organization.notification_cadence, Organization.digest_email).where(
                    Organization.id == org.id
                )
            )
        ).one()
    )
    assert stored == (NOW_, None)


async def test_offboarding_deletes_held_notices_queued_email_and_the_mailbox(
    client, session, world
):
    """Operational data of a departed member goes (NFR-S10). These tables postdate
    offboarding, which lists what it deletes; the inventory test cannot see them
    while its fixture writes no rows to them."""
    reader = world["reader"]
    reader_id, reader_slug = reader.id, reader.slug
    await _set_cadence(session, reader, D, email="soc-queue@reader.example")
    await _share(client, world, [_vulnerability()])
    session.add(
        EmailDelivery(org_id=reader_id, recipient="soc-queue@reader.example", subject="s", body="b")
    )
    await session.commit()

    response = await client.post(
        f"/api/v1/orgs/{reader_id}/offboard",
        json={"reason": "digest test: member left the ISAC", "confirm_slug": reader_slug},
        headers=world["isac"],
    )

    assert response.status_code == 200, response.text
    session.expire_all()
    assert await session.scalar(select(PendingNotice.id)) is None
    assert await session.scalar(select(EmailDelivery.id)) is None
    mailbox = await session.scalar(
        select(Organization.digest_email).where(Organization.id == reader_id)
    )
    assert mailbox is None
