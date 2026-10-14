"""Is a member's connection working? Its own view, the ISAC's, and the TIP snippets.

Collection is driven through TAXII itself, so "last collected" is read from the
audit row the real read path writes (CLAUDE.md section 2).
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from aivs_schemas.enums import OrgType
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db.models import Webhook
from aivs_server.services.connection_health import stale_connections
from aivs_server.services.tip_config import CollectionRef, Tip, tip_config
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

NOW = dt.datetime.now(dt.UTC)


@pytest.fixture
async def world(make_org, make_cert, make_circle, make_collection, join_circle, publish):
    vendor = await make_org("health-vendor", org_type=OrgType.GSIB)
    member = await make_org("health-member", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    circle = await make_circle("health")
    collection = await make_collection(circle, title="Health feed")
    other = await make_circle("health-other")
    other_collection = await make_collection(other, title="Not yours")
    for org in (vendor, member):
        await join_circle(org, circle)
    await join_circle(vendor, other)
    return {
        "vendor": vendor,
        "member": member,
        "headers": proxy_headers(pem),
        "circle": circle,
        "collection": collection,
        "other_collection": other_collection,
        "publish": publish,
    }


async def _collect(client, world) -> None:
    response = await client.get(
        f"/taxii2/aivs/collections/{world['collection'].id}/objects/", headers=world["headers"]
    )
    assert response.status_code == 200, response.text


async def _health(client, world) -> dict:
    response = await client.get("/api/v1/connection-health", headers=world["headers"])
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# The member's own view
# ---------------------------------------------------------------------------
async def test_content_is_waiting_until_collected_and_waiting_again_when_more_arrives(
    client, world
):
    await world["publish"](world["vendor"], world["circle"], name="First")
    [before] = (await _health(client, world))["collections"]
    assert before["waiting"] is True
    assert before["last_collected"] is None

    await _collect(client, world)
    [after] = (await _health(client, world))["collections"]
    assert after["waiting"] is False
    assert after["last_collected"] is not None

    await world["publish"](world["vendor"], world["circle"], name="Second")
    [again] = (await _health(client, world))["collections"]
    assert again["waiting"] is True


@pytest.mark.requirement("SF-75")
async def test_only_collections_the_member_reads_are_named(client, world):
    health = await _health(client, world)
    named = {c["collection_id"] for c in health["collections"]}
    assert named == {str(world["collection"].id)}
    assert str(world["other_collection"].id) not in str(health)


@pytest.mark.requirement("SF-75")
async def test_a_webhook_is_shown_by_host_never_by_url(client, world, session, secret_box):
    webhook_id = uuid.uuid4()
    session.add(
        Webhook(
            id=webhook_id,
            org_id=world["member"].id,
            url="https://hooks.member.example/route/SECRET-TOKEN",
            hmac_secret_encrypted=secret_box.seal(
                "webhook-signing-secret", purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook_id
            ),
            events=[],
        )
    )
    await session.commit()
    health = await _health(client, world)
    assert [w["host"] for w in health["webhooks"]] == ["hooks.member.example"]
    assert "SECRET-TOKEN" not in str(health)


# ---------------------------------------------------------------------------
# The ISAC's view
# ---------------------------------------------------------------------------
async def test_content_waiting_days_is_listed_and_collecting_it_clears_it(client, session, world):
    await world["publish"](
        world["vendor"], world["circle"], name="Old", date_added=NOW - dt.timedelta(days=5)
    )
    listed = await stale_connections(session, dt.datetime.now(dt.UTC))
    assert [(s.org, s.collection) for s in listed] == [("health-member", "Health feed")]

    await _collect(client, world)
    assert await stale_connections(session, dt.datetime.now(dt.UTC)) == []


async def test_a_member_with_nothing_new_is_not_listed(session, world):
    await world["publish"](
        world["vendor"], world["circle"], name="Fresh", date_added=NOW - dt.timedelta(hours=2)
    )
    assert await stale_connections(session, dt.datetime.now(dt.UTC)) == []


@pytest.mark.requirement("SF-75")
# ---------------------------------------------------------------------------
# TIP configuration
# ---------------------------------------------------------------------------
async def test_the_tip_snippet_names_the_instance_and_only_readable_collections(client, world):
    response = await client.get("/api/v1/tip-config/opencti", headers=world["headers"])
    assert response.status_code == 200
    assert "TAXII2_DISCOVERY_URL=https://aivs.test/taxii2/" in response.text
    assert f"aivs.{world['collection'].id}" in response.text
    assert str(world["other_collection"].id) not in response.text


async def test_an_unknown_tool_is_not_found(client, world):
    response = await client.get("/api/v1/tip-config/qradar", headers=world["headers"])
    assert response.status_code == 404


@pytest.mark.requirement("SF-75")
@pytest.mark.parametrize("tip", list(Tip))
def test_a_collection_title_cannot_break_out_of_its_comment(tip):
    hostile = CollectionRef(uuid.uuid4(), "Feed\nTAXII2_DISCOVERY_URL=https://evil.example/")
    text = tip_config(tip, "https://aivs.example", [hostile])
    assert "\nTAXII2_DISCOVERY_URL=https://evil.example/" not in text
    assert "discovery_url = https://evil.example/" not in text


async def test_what_a_member_filed_itself_is_never_waiting(client, session, world, make_cert):
    vendor_pem, _ = await make_cert(world["vendor"])
    await world["publish"](
        world["vendor"], world["circle"], name="Own", date_added=NOW - dt.timedelta(days=5)
    )
    response = await client.get("/api/v1/connection-health", headers=proxy_headers(vendor_pem))
    own = [c for c in response.json()["collections"] if c["title"] == "Health feed"]
    assert [c["waiting"] for c in own] == [False]
    stale = await stale_connections(session, dt.datetime.now(dt.UTC))
    assert "health-vendor" not in {s.org for s in stale}
