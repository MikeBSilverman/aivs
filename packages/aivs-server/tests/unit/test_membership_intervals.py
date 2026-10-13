"""Circle membership is a set of intervals (finding #3, SF-43).

A member that leaves and rejoins must keep what it had and must not receive
what was shared while it was out. Every visibility test here reads the same
collection once and asserts both halves -- the content inside an interval is
served, the content in the gap is not -- so neither can pass by the read being
broken.
"""

from __future__ import annotations

import datetime as dt

import pytest

from aivs_server.db.models import CircleMembership
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1"
DAY = dt.timedelta(days=1)


@pytest.fixture
def isac_headers(isac) -> dict[str, str]:
    return isac[1]


async def _objects(client, collection, pem) -> set[str]:
    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )
    assert response.status_code == 200
    return {item["name"] for item in response.json().get("objects", [])}


async def test_a_rejoining_member_reads_both_intervals_and_not_the_gap(
    client, make_org, make_cert, make_circle, make_collection, publish, session
):
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    publisher = await make_org("publisher")
    member = await make_org("rejoiner")
    pem, _ = await make_cert(member)

    now = dt.datetime.now(dt.UTC)
    first_joined, left, rejoined = now - 30 * DAY, now - 20 * DAY, now - 10 * DAY
    session.add_all(
        [
            CircleMembership(
                circle_id=circle.id,
                org_id=member.id,
                joined_at=first_joined,
                left_at=left,
                ended_by="operator",
            ),
            CircleMembership(circle_id=circle.id, org_id=member.id, joined_at=rejoined),
        ]
    )
    await session.commit()

    await publish(publisher, circle, name="before joining", date_added=now - 40 * DAY)
    await publish(publisher, circle, name="first interval", date_added=now - 25 * DAY)
    await publish(publisher, circle, name="in the gap", date_added=now - 15 * DAY)
    await publish(publisher, circle, name="second interval", date_added=now - 5 * DAY)

    assert await _objects(client, collection, pem) == {"first interval", "second interval"}


async def test_a_member_that_has_left_reads_nothing(
    client, make_org, make_cert, make_circle, make_collection, publish, session, join_circle
):
    """Leaving closes access to the circle, history included; a peer is the control."""
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    publisher = await make_org("publisher")
    leaver = await make_org("leaver")
    leaver_pem, _ = await make_cert(leaver)
    stayer = await make_org("stayer")
    stayer_pem, _ = await make_cert(stayer)
    await join_circle(stayer, circle)

    now = dt.datetime.now(dt.UTC)
    session.add(
        CircleMembership(
            circle_id=circle.id,
            org_id=leaver.id,
            joined_at=now - 30 * DAY,
            left_at=now - DAY,
            ended_by="operator",
        )
    )
    await session.commit()
    await publish(publisher, circle, name="while both were in", date_added=now - 5 * DAY)

    refused = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(leaver_pem)
    )
    assert refused.status_code == 404
    assert await _objects(client, collection, stayer_pem) == {"while both were in"}


async def test_joined_at_repairs_an_existing_member(
    client, isac_headers, make_org, make_circle, join_circle, session
):
    """Finding #3: the repair was skipped for an organisation already present.

    The "already a member" check ran before ``joined_at`` was applied, so the
    documented fix for a membership started too late could not reach it.
    """
    circle = await make_circle("section9")
    member = await make_org("restored")
    membership = await join_circle(member, circle, joined_at=dt.datetime.now(dt.UTC))
    restored_to = dt.datetime(2024, 1, 1, tzinfo=dt.UTC)

    response = await client.post(
        f"{API}/circles/{circle.id}/members",
        json={"org_ids": [str(member.id)], "joined_at": restored_to.isoformat()},
        headers=isac_headers,
    )

    assert response.status_code in (200, 201, 204)
    await session.refresh(membership)
    assert membership.joined_at == restored_to


async def test_a_repair_cannot_overlap_an_earlier_interval(
    client, isac_headers, make_org, make_circle, session
):
    """The exclusion constraint refuses an interval overlapping an earlier one.

    Without it, backdating a rejoined member's start would hand over exactly the
    content shared while it was out. The control is a repair that stays clear of
    the earlier interval, which succeeds.
    """
    circle = await make_circle("section9")
    member = await make_org("rejoiner")
    now = dt.datetime.now(dt.UTC)
    left = now - 20 * DAY
    session.add_all(
        [
            CircleMembership(
                circle_id=circle.id,
                org_id=member.id,
                joined_at=now - 30 * DAY,
                left_at=left,
                ended_by="operator",
            ),
            CircleMembership(circle_id=circle.id, org_id=member.id, joined_at=now - 10 * DAY),
        ]
    )
    await session.commit()

    into_the_gap = await client.post(
        f"{API}/circles/{circle.id}/members",
        json={"org_ids": [str(member.id)], "joined_at": (left - DAY).isoformat()},
        headers=isac_headers,
    )
    clear_of_it = await client.post(
        f"{API}/circles/{circle.id}/members",
        json={"org_ids": [str(member.id)], "joined_at": (left + DAY).isoformat()},
        headers=isac_headers,
    )

    assert into_the_gap.status_code == 409
    assert clear_of_it.status_code in (200, 201, 204)
