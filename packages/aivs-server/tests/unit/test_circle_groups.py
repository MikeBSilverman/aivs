"""Selecting a known group instead of enumerating members.

An ISAC thinks in communities -- "the Section 9 firms", "the GSIBs" -- not in
individual organisations. Two mechanisms serve that, and the tests are grouped by
which one they exercise, because the two differ in exactly one respect that
matters: bulk addition is the same deliberate act performed once, while a rule
keeps acting after the operator has walked away.

The property every test here ultimately protects is the one from
``test_review_regressions``: joining a circle grants participation, never the
back catalogue. A rule that quietly handed a newly enrolled firm years of other
members' embargoed intelligence would be a worse feature than no feature.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import CircleRole, OrgType
from aivs_server.db.models import CircleMembership
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1"


@pytest.fixture
async def isac(make_org, make_cert):
    org = await make_org("hosting-isac", org_type=OrgType.ADMIN)
    pem, _ = await make_cert(org)
    return org, pem


async def members_of(session, circle_id: uuid.UUID) -> list[CircleMembership]:
    return list(
        (
            await session.execute(
                select(CircleMembership).where(CircleMembership.circle_id == circle_id)
            )
        )
        .scalars()
        .all()
    )


# ---------------------------------------------------------------------------
# Bulk addition
# ---------------------------------------------------------------------------
async def test_a_roster_can_be_applied_in_one_call(client, isac, make_org, make_circle, session):
    """Thirty firms should be one call, not thirty."""
    _isac_org, isac_pem = isac
    circle = await make_circle("gsib")
    orgs = [await make_org(f"firm-{index}", org_type=OrgType.GSIB) for index in range(5)]

    response = await client.post(
        f"{API}/circles/{circle.id}/members",
        json={"org_ids": [str(org.id) for org in orgs], "role": "contributor"},
        headers=proxy_headers(isac_pem),
    )
    assert response.status_code == 204, response.text

    rows = await members_of(session, circle.id)
    assert {row.org_id for row in rows} == {org.id for org in orgs}
    assert all(row.role is CircleRole.CONTRIBUTOR for row in rows)


async def test_a_roster_can_be_given_as_slugs(client, isac, make_org, make_circle, session):
    """Slugs, because that is the form the list exists in already.

    An operator copying a regulator's roster or an existing community sheet has
    names, not UUIDs. Making them resolve thirty identifiers first is how a bulk
    endpoint goes unused.
    """
    _isac_org, isac_pem = isac
    circle = await make_circle("section9")
    for slug in ("atlantic-clearing", "meridian-global"):
        await make_org(slug, org_type=OrgType.SECTION9)

    response = await client.post(
        f"{API}/circles/{circle.id}/members",
        json={"org_slugs": ["atlantic-clearing", "meridian-global"]},
        headers=proxy_headers(isac_pem),
    )
    assert response.status_code == 204, response.text
    assert len(await members_of(session, circle.id)) == 2


async def test_an_unknown_name_fails_the_whole_batch(client, isac, make_org, make_circle, session):
    """All or nothing.

    A partial application would leave the operator believing a distribution list
    was complete when it was not, which for embargoed intelligence is the
    failure that matters.
    """
    _isac_org, isac_pem = isac
    circle = await make_circle("section9")
    await make_org("real-firm", org_type=OrgType.SECTION9)

    response = await client.post(
        f"{API}/circles/{circle.id}/members",
        json={"org_slugs": ["real-firm", "no-such-firm"]},
        headers=proxy_headers(isac_pem),
    )
    assert response.status_code == 404
    assert "no-such-firm" in response.text
    assert await members_of(session, circle.id) == []


async def test_naming_nobody_is_refused(client, isac, make_circle):
    _isac_org, isac_pem = isac
    circle = await make_circle("section9")
    response = await client.post(
        f"{API}/circles/{circle.id}/members", json={}, headers=proxy_headers(isac_pem)
    )
    assert response.status_code == 400


async def test_a_membership_can_be_restored_with_its_original_date(
    client, isac, make_org, make_circle, session
):
    """Re-adding after an administrative mistake keeps the history it had.

    Without this the only ways to restore an organisation are to give it a fresh
    start date -- losing access it legitimately had -- or to edit the database,
    which is worse. It is a deliberate act, and the audit record says so.
    """
    _isac_org, isac_pem = isac
    circle = await make_circle("section9")
    org = await make_org("restored-firm", org_type=OrgType.SECTION9)
    original = dt.datetime(2024, 3, 1, tzinfo=dt.UTC)

    response = await client.post(
        f"{API}/circles/{circle.id}/members",
        json={"org_ids": [str(org.id)], "joined_at": original.isoformat()},
        headers=proxy_headers(isac_pem),
    )
    assert response.status_code == 204, response.text

    row = (await members_of(session, circle.id))[0]
    assert row.joined_at == original


async def test_a_member_cannot_read_another_firm_into_a_circle(
    client, make_org, make_cert, make_circle, join_circle, session
):
    """Admission is the hosting ISAC's alone, over the API as over the portal.

    A circle carries other members' embargoed intelligence. Letting a member
    firm admit another firm to it is letting a cleared participant read in the
    next one, which is not how a programme with an obligation behind it works.
    Holding CIRCLE_ADMIN does not change this; that role no longer administers.
    """
    circle = await make_circle("section9")
    insider = await make_org("insider-firm", org_type=OrgType.GSIB)
    insider_pem, _ = await make_cert(insider)
    await join_circle(insider, circle, role=CircleRole.CIRCLE_ADMIN)

    outsider = await make_org("outsider-firm", org_type=OrgType.GSIB)

    response = await client.post(
        f"{API}/circles/{circle.id}/members",
        json={"org_ids": [str(outsider.id)]},
        headers=proxy_headers(insider_pem),
    )
    assert response.status_code == 403

    members = await members_of(session, circle.id)
    assert [row.org_id for row in members] == [insider.id]


async def test_a_member_cannot_remove_another_firm_from_a_circle(
    client, make_org, make_cert, make_circle, join_circle, session
):
    """The same rule in the other direction: nor can they read anyone *out*."""
    circle = await make_circle("section9")
    insider = await make_org("insider-firm", org_type=OrgType.GSIB)
    insider_pem, _ = await make_cert(insider)
    await join_circle(insider, circle, role=CircleRole.CIRCLE_ADMIN)

    peer = await make_org("peer-firm", org_type=OrgType.GSIB)
    await join_circle(peer, circle)

    response = await client.delete(
        f"{API}/circles/{circle.id}/members/{peer.id}", headers=proxy_headers(insider_pem)
    )
    assert response.status_code == 403
    assert len(await members_of(session, circle.id)) == 2


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
async def test_a_rule_populates_the_circle_when_it_is_created(client, isac, make_org, session):
    """A circle created with a rule is not empty until someone else enrols."""
    _isac_org, isac_pem = isac
    for slug in ("firm-a", "firm-b"):
        org = await make_org(slug, org_type=OrgType.SECTION9)
        del org
    await make_org("a-gsib", org_type=OrgType.GSIB)

    created = await client.post(
        f"{API}/circles",
        json={
            "slug": "section9",
            "name": "Section 9",
            "auto_member_org_types": ["section9"],
        },
        headers=proxy_headers(isac_pem),
    )
    assert created.status_code == 201, created.text
    circle_id = uuid.UUID(created.json()["id"])

    rows = await members_of(session, circle_id)
    assert len(rows) == 2, "both Section 9 firms, and not the GSIB"
    assert all(row.managed_by_rule for row in rows)


async def test_activating_an_organisation_puts_it_in_its_circles(client, isac, make_org, session):
    """The point of the feature: covered from day one, not from when someone remembers."""
    _isac_org, isac_pem = isac
    created = await client.post(
        f"{API}/circles",
        json={"slug": "section9", "name": "Section 9", "auto_member_org_types": ["section9"]},
        headers=proxy_headers(isac_pem),
    )
    circle_id = uuid.UUID(created.json()["id"])
    assert await members_of(session, circle_id) == []

    enrolled = await client.post(
        f"{API}/orgs",
        json={"slug": "newly-enrolled", "name": "Newly Enrolled", "org_type": "section9"},
        headers=proxy_headers(isac_pem),
    )
    assert enrolled.status_code == 201
    org_id = uuid.UUID(enrolled.json()["id"])

    # Pending, so not yet a participant.
    assert await members_of(session, circle_id) == [], "enrolment alone is not participation"

    activated = await client.post(f"{API}/orgs/{org_id}/activate", headers=proxy_headers(isac_pem))
    assert activated.status_code == 200

    rows = await members_of(session, circle_id)
    assert [row.org_id for row in rows] == [org_id]


async def test_a_rule_added_member_starts_now_not_at_the_beginning(
    client, isac, make_org, make_collection, make_circle, publish, make_cert, session
):
    """The reason this feature had to wait for the membership-start bound.

    Without it, enrolling an organisation would hand it the circle's entire
    history -- which turns a convenience into the largest disclosure in the
    product.
    """
    _isac_org, isac_pem = isac
    circle = await make_circle("section9")
    circle.auto_member_org_types = ["section9"]
    collection = await make_collection(circle)
    incumbent = await make_org("incumbent", org_type=OrgType.SECTION9)
    await session.commit()

    await publish(
        incumbent,
        circle,
        name="Shared before they joined",
        date_added=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
    )

    enrolled = await client.post(
        f"{API}/orgs",
        json={"slug": "late-joiner", "name": "Late Joiner", "org_type": "section9"},
        headers=proxy_headers(isac_pem),
    )
    org_id = uuid.UUID(enrolled.json()["id"])
    await client.post(f"{API}/orgs/{org_id}/activate", headers=proxy_headers(isac_pem))

    newcomer = await session.get(type(incumbent), org_id)
    assert newcomer is not None
    newcomer_pem, _ = await make_cert(newcomer)

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/",
        headers=proxy_headers(newcomer_pem),
    )
    assert feed.status_code == 200, feed.text
    assert feed.json().get("objects", []) == [], "a rule must not grant the back catalogue"


async def test_suspension_withdraws_a_rule_managed_membership(client, isac, make_org, session):
    _isac_org, isac_pem = isac
    created = await client.post(
        f"{API}/circles",
        json={"slug": "section9", "name": "Section 9", "auto_member_org_types": ["section9"]},
        headers=proxy_headers(isac_pem),
    )
    circle_id = uuid.UUID(created.json()["id"])

    org = await make_org("temporarily-in", org_type=OrgType.SECTION9)
    await client.post(f"{API}/orgs/{org.id}/activate", headers=proxy_headers(isac_pem))
    assert len(await members_of(session, circle_id)) == 1

    await client.post(f"{API}/orgs/{org.id}/suspend", headers=proxy_headers(isac_pem))
    assert await members_of(session, circle_id) == []


async def test_a_rule_never_removes_a_hand_added_member(client, isac, make_org, session):
    """Reconciliation owns only the rows it created.

    An operator who named an organisation explicitly has made a decision the
    rule does not get to reverse -- and a feature that silently undid operator
    intent is one operators route around.
    """
    _isac_org, isac_pem = isac
    created = await client.post(
        f"{API}/circles",
        json={"slug": "section9", "name": "Section 9", "auto_member_org_types": ["section9"]},
        headers=proxy_headers(isac_pem),
    )
    circle_id = uuid.UUID(created.json()["id"])

    # A GSIB the rule does not match, added deliberately.
    guest = await make_org("invited-guest", org_type=OrgType.GSIB)
    await client.post(
        f"{API}/circles/{circle_id}/members",
        json={"org_ids": [str(guest.id)]},
        headers=proxy_headers(isac_pem),
    )

    # Something that triggers a reconcile.
    other = await make_org("a-section9-firm", org_type=OrgType.SECTION9)
    await client.post(f"{API}/orgs/{other.id}/activate", headers=proxy_headers(isac_pem))

    rows = await members_of(session, circle_id)
    by_org = {row.org_id: row for row in rows}
    assert guest.id in by_org, "the hand-added guest survives reconciliation"
    assert by_org[guest.id].managed_by_rule is False
    assert by_org[other.id].managed_by_rule is True


async def test_a_circle_without_a_rule_is_untouched(client, isac, make_org, make_circle, session):
    """Rules are opt-in; every existing circle keeps behaving as it did."""
    _isac_org, isac_pem = isac
    circle = await make_circle("manual-circle")

    org = await make_org("some-firm", org_type=OrgType.SECTION9)
    await client.post(f"{API}/orgs/{org.id}/activate", headers=proxy_headers(isac_pem))

    assert await members_of(session, circle.id) == []
