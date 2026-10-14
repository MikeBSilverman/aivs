"""The incident stop button: pausing all distribution (SF-63).

Each test is a pair across the pause: the same read or write before or after,
and during. The case that motivated serving nothing rather than only refusing
writes is an embargo whose time arrives while paused -- it would otherwise
become visible by the clock with no writer involved.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from aivs_schemas.enums import OperatorRole, OrgType
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1"
REASON = {"reason": "Suspected compromise of the proxy host, ticket INC-42"}


@pytest.fixture
async def reader(make_org, make_cert, make_circle, make_collection, join_circle):
    """A member of a circle with a collection: ``(pem, org, circle, collection)``."""
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    await join_circle(org, circle)
    return pem, org, circle, collection


async def _names(client, collection, pem) -> set[str]:
    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )
    assert response.status_code == 200
    return {item["name"] for item in response.json().get("objects", [])}


@pytest.mark.requirement("SF-63")
async def test_pausing_withholds_everything_until_resumed(client, isac, reader, publish):
    _isac_org, isac_headers = isac
    pem, org, circle, collection = reader
    now = dt.datetime.now(dt.UTC)
    await publish(org, circle, name="already out", date_added=now - dt.timedelta(hours=1))
    # An embargo stamped long ago that comes due during the pause.
    await publish(org, circle, name="comes due", date_added=now + dt.timedelta(seconds=1))

    assert await _names(client, collection, pem) == {"already out"}
    paused = await client.post(
        f"{API}/instance/distribution/pause", json=REASON, headers=isac_headers
    )
    assert paused.status_code == 200
    await _wait_until(now + dt.timedelta(seconds=1.5))

    assert await _names(client, collection, pem) == set(), "nothing is served while paused"

    resumed = await client.post(
        f"{API}/instance/distribution/resume", json=REASON, headers=isac_headers
    )
    assert resumed.status_code == 200
    assert await _names(client, collection, pem) == {"already out", "comes due"}


async def _wait_until(moment: dt.datetime) -> None:
    import asyncio  # noqa: PLC0415 - local to this helper

    delay = (moment - dt.datetime.now(dt.UTC)).total_seconds()
    if delay > 0:
        await asyncio.sleep(delay)


@pytest.mark.requirement("NFR-S12")
async def test_distribution_is_refused_while_paused_and_works_after(
    client, isac, make_org, make_cert, make_circle, make_collection
):
    _isac_org, isac_headers = isac
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    circle = await make_circle("section9")
    await make_collection(circle)
    stamp = "2026-08-01T00:00:00.000Z"
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{uuid.uuid4()}",
                "created": stamp,
                "modified": stamp,
                "name": "Held during an incident",
            }
        ],
    }
    created = await client.post(
        f"{API}/submissions",
        json={"title": "During an incident", "discovery_scope": "ai_system", "bundle": bundle},
        headers=proxy_headers(pem),
    )
    submission_id = created.json()["id"]
    await client.post(
        f"{API}/submissions/{submission_id}/submit", json={}, headers=proxy_headers(pem)
    )
    await client.post(f"{API}/submissions/{submission_id}/validate", json={}, headers=isac_headers)

    await client.post(f"{API}/instance/distribution/pause", json=REASON, headers=isac_headers)
    refused = await client.post(
        f"{API}/submissions/{submission_id}/distribute",
        json={"circle_ids": [str(circle.id)]},
        headers=isac_headers,
    )
    await client.post(f"{API}/instance/distribution/resume", json=REASON, headers=isac_headers)
    accepted = await client.post(
        f"{API}/submissions/{submission_id}/distribute",
        json={"circle_ids": [str(circle.id)]},
        headers=isac_headers,
    )

    assert refused.status_code == 409
    assert "paused" in refused.text
    assert accepted.status_code == 200


async def test_who_may_press_and_release_the_button(
    client, make_org, make_cert, make_operator, human_headers
):
    """Stopping is the safe direction, so the people who run the instance may
    do it; starting again is an editorial decision. An ISAC analyst and a
    member may do neither."""
    isac_org = await make_org("hosting-isac", org_type=OrgType.ADMIN)
    isac_pem, _ = await make_cert(isac_org)

    async def person(*roles: OperatorRole) -> dict[str, str]:
        operator, _seed = await make_operator(isac_org, roles=roles)
        return await human_headers(operator, isac_pem)

    system_admin = await person(OperatorRole.SYSTEM_ADMIN)
    analyst = await person(OperatorRole.ISAC_ANALYST)
    editor = await person(OperatorRole.ISAC_EDITOR)
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    member_pem, _ = await make_cert(member)

    pause = f"{API}/instance/distribution/pause"
    resume = f"{API}/instance/distribution/resume"
    assert (await client.post(pause, json=REASON, headers=analyst)).status_code == 403
    assert (
        await client.post(pause, json=REASON, headers=proxy_headers(member_pem))
    ).status_code == 403
    assert (await client.post(pause, json=REASON, headers=system_admin)).status_code == 200
    assert (await client.post(resume, json=REASON, headers=system_admin)).status_code == 403
    assert (await client.post(resume, json=REASON, headers=editor)).status_code == 200
