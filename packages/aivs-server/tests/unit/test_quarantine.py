"""Quarantine: cut a member off during an incident, and reconnect it.

Every test is a pair across the quarantine or across the choice being tested.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy import text as sqlalchemy_text

from aivs_schemas.enums import (
    CertStatus,
    OperatorRole,
    OrgStatus,
    OrgType,
    QuarantineBacklog,
)
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.policy import PolicyDeniedError, can_reconnect_org
from aivs_server.db.models import CircleMembership, ClientCertificate, Organization
from aivs_server.services.certificates import register_certificate
from aivs_server.services.org_status import load_org_for_update
from aivs_server.services.quarantine import quarantine_org, reconnect_org
from tests.conftest import is_blocked, proxy_headers

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


# ---------------------------------------------------------------------------
# A registration racing the quarantine (identity-lifecycle review, L-C1)
# ---------------------------------------------------------------------------
def _person(org_id: uuid.UUID, org_type: OrgType, role: OperatorRole) -> AuthContext:
    return AuthContext(
        org_id=org_id,
        org_slug="caller",
        org_type=org_type,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.PORTAL_SESSION,
        operator_id=uuid.uuid4(),
        operator_roles=frozenset({role}),
    )


async def _quarantine_held_open(open_session, org, now: dt.datetime):
    """A quarantine that has run and holds the row lock, not yet committed."""
    quarantiner = open_session()
    locked = await load_org_for_update(quarantiner, org.id)
    await quarantine_org(
        quarantiner,
        _person(uuid.uuid4(), OrgType.ADMIN, OperatorRole.ISAC_MEMBERSHIP),
        organisation=locked,
        reason=REASON["reason"],
        now=now,
    )
    return quarantiner


async def _register(session, ctx, organisation, ca, now: dt.datetime):
    pem, _fp, _cert = ca.issue(f"racing-{uuid.uuid4().hex[:6]}")
    return await register_certificate(
        session,
        ctx,
        organisation=organisation,
        certificate_pem=pem,
        label=None,
        issuing_ca=None,
        now=now,
    )


@pytest.mark.requirement("NFR-S2")
@pytest.mark.parametrize("caller", ["member_admin", "isac_membership"])
async def test_a_registration_queued_behind_a_quarantine_is_decided_on_the_locked_status(
    open_session, make_org, ca, caller
):
    """The member's own admin is refused once the quarantine commits; the ISAC is not.

    ``can_manage_org`` is decided on a context resolved before the row lock, so
    a registration waiting on the quarantine inserted an ACTIVE certificate
    the quarantine never saw. The ISAC must still be able to register: that
    is how a quarantined member gets the fresh certificate reconnection needs.
    """
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    ctx = (
        _person(org.id, OrgType.GSIB, OperatorRole.ORG_ADMIN)
        if caller == "member_admin"
        else _person(uuid.uuid4(), OrgType.ADMIN, OperatorRole.ISAC_MEMBERSHIP)
    )
    registrar = open_session()
    # As resolve_session does: the request read the organisation, active, first.
    await registrar.get(Organization, org.id)
    quarantiner = await _quarantine_held_open(open_session, org, dt.datetime.now(dt.UTC))

    waited, task = await is_blocked(load_org_for_update(registrar, org.id))
    await quarantiner.commit()
    organisation = await asyncio.wait_for(task, timeout=5)

    assert waited is True
    if caller == "member_admin":
        with pytest.raises(PolicyDeniedError):
            await _register(registrar, ctx, organisation, ca, dt.datetime.now(dt.UTC))
    else:
        row = await _register(registrar, ctx, organisation, ca, dt.datetime.now(dt.UTC))
        assert row.status is CertStatus.ACTIVE


async def test_a_certificate_registered_after_the_quarantine_committed_is_fresh(
    open_session, make_org, ca
):
    """However early its transaction began: freshness is one clock, read under the lock.

    The certificate's ``created_at`` was the database's transaction start and
    ``quarantined_at`` the application's clock. A registration whose
    transaction opened before the quarantine, then waited on it, was stamped
    earlier than the quarantine it followed -- and with the clocks the other way
    round, a registration on the compromised side would have counted as fresh.
    """
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    isac_staff = _person(uuid.uuid4(), OrgType.ADMIN, OperatorRole.ISAC_MEMBERSHIP)
    registrar = open_session()
    await registrar.execute(sqlalchemy_text("SELECT 1"))  # its transaction starts now
    await asyncio.sleep(0.01)
    quarantiner = await _quarantine_held_open(open_session, org, dt.datetime.now(dt.UTC))

    _waited, task = await is_blocked(load_org_for_update(registrar, org.id))
    await quarantiner.commit()
    organisation = await asyncio.wait_for(task, timeout=5)
    await _register(registrar, isac_staff, organisation, ca, dt.datetime.now(dt.UTC))
    await registrar.commit()

    reconnecting = open_session()
    target = await load_org_for_update(reconnecting, org.id)
    await reconnect_org(
        reconnecting,
        isac_staff,
        organisation=target,
        backlog=QuarantineBacklog.DELIVER,
        reason=REASON["reason"],
        now=dt.datetime.now(dt.UTC),
    )
    assert target.status is OrgStatus.ACTIVE


@pytest.mark.requirement("NFR-S2")
async def test_reconnection_revokes_every_certificate_older_than_the_quarantine(
    client, isac, member_in_circle, ca, session, make_cert
):
    """Only the fresh certificate survives reconnection; the pair is that it does.

    A certificate left active from before the quarantine -- what a
    registration committing beside the quarantine used to leave -- would
    otherwise be returned to service with the organisation.
    """
    _isac_org, isac_headers = isac
    org, _old_pem, _circle, _collection = member_in_circle
    await client.post(f"{API}/orgs/{org.id}/quarantine", json=REASON, headers=isac_headers)
    await session.refresh(org)
    stale_pem, stale = await make_cert(org)
    stale.created_at = org.quarantined_at - dt.timedelta(seconds=1)
    await session.commit()
    fresh_pem, _fp, _cert = ca.issue("meridian-global-after-incident")
    registered = await client.post(
        f"{API}/orgs/{org.id}/certificates",
        json={"certificate_pem": fresh_pem},
        headers=isac_headers,
    )

    reconnected = await client.post(
        f"{API}/orgs/{org.id}/reconnect", json=REASON, headers=isac_headers
    )

    assert registered.status_code == 201
    assert reconnected.status_code == 200, reconnected.text
    assert (await client.get(f"{API}/whoami", headers=proxy_headers(fresh_pem))).status_code == 200
    assert (await client.get(f"{API}/whoami", headers=proxy_headers(stale_pem))).status_code == 401


# ---------------------------------------------------------------------------
# Reconnection goes through the rules, and its withheld gap stays withheld
# ---------------------------------------------------------------------------
async def test_reconnection_reconciles_circle_rules_like_any_activation(
    client, isac, member_in_circle, ca, session, make_circle
):
    """A rule written while the member was out takes effect when it is reconnected.

    Reconciliation skips a quarantined organisation; ``change_org_status``
    reconciles on activation, and reconnection -- the other writer of
    ``active`` -- did not.
    """
    _isac_org, isac_headers = isac
    org, _pem, _circle, _collection = member_in_circle
    org_id = org.id
    await client.post(f"{API}/orgs/{org.id}/quarantine", json=REASON, headers=isac_headers)
    ruled = await make_circle("all-gsibs")
    ruled.auto_member_org_types = [OrgType.GSIB.value]
    await session.commit()
    ruled_id = ruled.id
    fresh_pem, _fp, _cert = ca.issue("meridian-global-after-incident")
    await client.post(
        f"{API}/orgs/{org.id}/certificates",
        json={"certificate_pem": fresh_pem},
        headers=isac_headers,
    )

    async def members_of_rule_circle() -> set[uuid.UUID]:
        session.expire_all()
        return set(
            (
                await session.execute(
                    select(CircleMembership.org_id).where(
                        CircleMembership.circle_id == ruled_id,
                        CircleMembership.left_at.is_(None),
                    )
                )
            ).scalars()
        )

    before = await members_of_rule_circle()
    reconnected = await client.post(
        f"{API}/orgs/{org_id}/reconnect", json=REASON, headers=isac_headers
    )

    assert reconnected.status_code == 200, reconnected.text
    assert org_id not in before
    assert org_id in await members_of_rule_circle()

