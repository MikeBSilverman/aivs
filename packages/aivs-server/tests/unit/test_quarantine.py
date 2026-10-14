"""Quarantine: cut a member off during an incident, and reconnect it.

Every test is a pair across the quarantine or across the choice being tested.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import CertStatus, OperatorRole, OrgStatus, OrgType
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.policy import can_reconnect_org
from aivs_server.db.models import CircleMembership, ClientCertificate
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1"
REASON = {"reason": "Collector host compromised, member ticket 8812"}


@pytest.fixture
async def member_in_circle(make_org, make_cert, make_circle, make_collection, join_circle):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    await join_circle(org, circle)
    return org, pem, circle, collection


@pytest.mark.requirement("NFR-S2")
async def test_quarantine_refuses_the_members_credentials_and_keeps_its_membership(
    client, isac, member_in_circle, session
):
    _isac_org, isac_headers = isac
    org, pem, _circle, _collection = member_in_circle
    org_id = org.id

    before = await client.get(f"{API}/whoami", headers=proxy_headers(pem))
    quarantined = await client.post(
        f"{API}/orgs/{org.id}/quarantine", json=REASON, headers=isac_headers
    )
    after = await client.get(f"{API}/whoami", headers=proxy_headers(pem))

    assert before.status_code == 200
    assert quarantined.status_code == 200
    assert quarantined.json()["status"] == "quarantined"
    assert after.status_code == 401
    session.expire_all()
    statuses = set(
        (
            await session.execute(
                select(ClientCertificate.status).where(ClientCertificate.org_id == org_id)
            )
        ).scalars()
    )
    assert statuses == {CertStatus.REVOKED}
    open_memberships = (
        (
            await session.execute(
                select(CircleMembership).where(
                    CircleMembership.org_id == org_id, CircleMembership.left_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(open_memberships) == 1, "quarantine is not removal"


async def test_a_member_may_quarantine_itself_but_not_another_firm(
    client, make_org, make_cert, make_operator, human_headers
):
    """'We are compromised, cut us off' needs no one's approval."""
    own = await make_org("meridian-global", org_type=OrgType.GSIB)
    own_pem, _ = await make_cert(own)
    other = await make_org("atlantic-clearing", org_type=OrgType.GSIB)
    admin, _seed = await make_operator(own, roles=(OperatorRole.ORG_ADMIN,))
    headers = await human_headers(admin, own_pem)

    refused = await client.post(f"{API}/orgs/{other.id}/quarantine", json=REASON, headers=headers)
    accepted = await client.post(f"{API}/orgs/{own.id}/quarantine", json=REASON, headers=headers)

    assert refused.status_code == 403
    assert accepted.status_code == 200


async def test_reconnection_needs_a_fresh_certificate_and_never_revives_the_old(
    client, isac, member_in_circle, ca
):
    _isac_org, isac_headers = isac
    org, old_pem, _circle, _collection = member_in_circle
    await client.post(f"{API}/orgs/{org.id}/quarantine", json=REASON, headers=isac_headers)

    too_soon = await client.post(
        f"{API}/orgs/{org.id}/reconnect", json=REASON, headers=isac_headers
    )
    new_pem, _fp, _cert = ca.issue("meridian-global-after-incident")
    registered = await client.post(
        f"{API}/orgs/{org.id}/certificates",
        json={"certificate_pem": new_pem, "label": "post-incident"},
        headers=isac_headers,
    )
    reconnected = await client.post(
        f"{API}/orgs/{org.id}/reconnect", json=REASON, headers=isac_headers
    )

    assert too_soon.status_code == 409
    assert registered.status_code == 201
    assert reconnected.status_code == 200
    assert (await client.get(f"{API}/whoami", headers=proxy_headers(new_pem))).status_code == 200
    assert (await client.get(f"{API}/whoami", headers=proxy_headers(old_pem))).status_code == 401


@pytest.mark.parametrize("backlog", ["deliver", "new_interval"])
async def test_the_backlog_choice_decides_whether_the_gap_reaches_the_member(
    client, isac, member_in_circle, publish, ca, backlog
):
    """Delivered by default -- the member was protected, not penalised. Withheld
    when the ISAC chooses a new interval. Content from before the quarantine is
    kept either way."""
    _isac_org, isac_headers = isac
    org, _old_pem, circle, collection = member_in_circle
    publisher = org  # any distribution into the circle will do
    now = dt.datetime.now(dt.UTC)
    await publish(publisher, circle, name="before", date_added=now - dt.timedelta(hours=2))

    await client.post(f"{API}/orgs/{org.id}/quarantine", json=REASON, headers=isac_headers)
    await publish(publisher, circle, name="during", date_added=dt.datetime.now(dt.UTC))
    new_pem, _fp, _cert = ca.issue(f"after-{uuid.uuid4().hex[:6]}")
    await client.post(
        f"{API}/orgs/{org.id}/certificates",
        json={"certificate_pem": new_pem},
        headers=isac_headers,
    )
    reconnected = await client.post(
        f"{API}/orgs/{org.id}/reconnect", json={**REASON, "backlog": backlog}, headers=isac_headers
    )
    assert reconnected.status_code == 200

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(new_pem)
    )
    names = {item["name"] for item in feed.json().get("objects", [])}
    expected = {"before", "during"} if backlog == "deliver" else {"before"}
    assert names == expected


def test_a_member_can_never_reconnect_itself():
    """Whoever holds its compromised credentials could do the same."""
    org_admin = AuthContext(
        org_id=uuid.uuid4(),
        org_slug="meridian-global",
        org_type=OrgType.GSIB,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.PORTAL_SESSION,
        operator_id=uuid.uuid4(),
        operator_roles=frozenset({OperatorRole.ORG_ADMIN}),
    )
    isac_membership = AuthContext(
        org_id=uuid.uuid4(),
        org_slug="hosting-isac",
        org_type=OrgType.ADMIN,
        org_status=org_admin.org_status,
        auth_method=AuthMethod.PORTAL_SESSION,
        operator_id=uuid.uuid4(),
        operator_roles=frozenset({OperatorRole.ISAC_MEMBERSHIP}),
    )
    assert can_reconnect_org(org_admin) is False
    assert can_reconnect_org(isac_membership) is True
