"""What the review of Phase A found in the identity lifecycle.

Each test is a pair. The defects: activation returned a quarantined member to
service without any of reconnection's conditions; the ISAC could quarantine or
suspend itself out of reach; a second admin-type organisation was a second
ISAC; the bootstrap minted operators on a live instance; a certificate
registered beside a quarantine counted as fresh; and a "new interval"
reconnection still delivered gap content through intervals changed during the
quarantine.
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from aivs_schemas.enums import OperatorRole, OrgStatus, OrgType
from aivs_server.audit.log import AuditAction
from aivs_server.bootstrap_operator import BootstrapError, bootstrap
from aivs_server.db.models import AuditLog, CircleMembership, ClientCertificate, Organization
from aivs_server.services.detections import RULES, run_detections
from tests.conftest import TEST_OPERATOR_PASSWORD

pytestmark = pytest.mark.db

API = "/api/v1"
REASON = {"reason": "collector host compromised, ticket 8812"}


@pytest.fixture
async def member(make_org, make_cert):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    await make_cert(org)
    return org


async def test_activation_cannot_stand_in_for_reconnection(client, isac, member, make_org):
    _org, headers = isac
    suspended = await make_org("lapsed-renewal", org_type=OrgType.GSIB)
    await client.post(f"{API}/orgs/{suspended.id}/suspend", headers=headers)
    await client.post(f"{API}/orgs/{member.id}/quarantine", json=REASON, headers=headers)

    from_quarantine = await client.post(f"{API}/orgs/{member.id}/activate", headers=headers)
    from_suspension = await client.post(f"{API}/orgs/{suspended.id}/activate", headers=headers)

    assert from_quarantine.status_code == 409
    assert "reconnect" in from_quarantine.json()["title"]
    assert from_suspension.status_code == 200


async def test_suspending_a_quarantined_member_is_refused(client, isac, member):
    _org, headers = isac
    await client.post(f"{API}/orgs/{member.id}/quarantine", json=REASON, headers=headers)

    response = await client.post(f"{API}/orgs/{member.id}/suspend", headers=headers)

    assert response.status_code == 409


@pytest.mark.parametrize("verb", ["suspend", "quarantine"])
async def test_the_isac_cannot_lock_itself_out_and_can_act_on_a_member(client, isac, member, verb):
    isac_org, headers = isac
    body = REASON if verb == "quarantine" else None

    itself = await client.post(f"{API}/orgs/{isac_org.id}/{verb}", json=body, headers=headers)
    a_member = await client.post(f"{API}/orgs/{member.id}/{verb}", json=body, headers=headers)

    assert itself.status_code == 409
    assert a_member.status_code == 200


async def test_a_second_isac_cannot_be_enrolled_or_stored(client, isac, session):
    _org, headers = isac

    second = await client.post(
        f"{API}/orgs",
        json={"slug": "rival-isac", "name": "Rival", "org_type": "admin"},
        headers=headers,
    )
    ordinary = await client.post(
        f"{API}/orgs",
        json={"slug": "new-member", "name": "New", "org_type": "gsib"},
        headers=headers,
    )
    assert second.status_code == 400
    assert ordinary.status_code == 201

    session.add(
        Organization(
            slug="direct-insert",
            name="Direct",
            org_type=OrgType.ADMIN,
            status=OrgStatus.ACTIVE,
            stix_identity_id="identity--00000000-0000-4000-8000-000000000001",
        )
    )
    with pytest.raises(IntegrityError):
        await session.commit()
    await session.rollback()


async def test_the_bootstrap_on_a_live_instance_needs_an_explicit_flag_and_is_recorded(
    session, settings
):
    def run(email: str, *, additional: bool):
        return bootstrap(
            session,
            settings,
            org_slug="example-isac",
            org_name="Example ISAC",
            email=email,
            display_name="Ops",
            password=TEST_OPERATOR_PASSWORD,
            roles=[OperatorRole.SYSTEM_ADMIN],
            certificate_pem=None,
            role_expires_at=None,
            additional=additional,
        )

    await run("first@example-isac.org", additional=False)
    with pytest.raises(BootstrapError, match="already has 1 active system admin"):
        await run("second@example-isac.org", additional=False)
    await session.rollback()
    recovered = await run("recovery@example-isac.org", additional=True)

    rows = (
        (
            await session.execute(
                select(AuditLog).where(AuditLog.action == AuditAction.OPERATOR_BOOTSTRAPPED)
            )
        )
        .scalars()
        .all()
    )
    assert [(r.actor_id, r.details["additional"]) for r in rows] == [
        ("bootstrap_operator", False),
        ("bootstrap_operator", True),
    ]
    assert rows[1].resource_id == str(recovered.operator_id)

    alerted = await run_detections(
        session,
        quarantine_policy="propose",
        now=dt.datetime.now(dt.UTC),
        rules=[r for r in RULES if r.name == "operator_bootstrapped"],
    )
    assert len(alerted) == 2, "every operator minted from the host is announced"


async def test_only_a_certificate_registered_after_the_quarantine_reconnects(
    client, isac, member, ca, session
):
    _org, headers = isac
    member_id = member.id
    await client.post(f"{API}/orgs/{member_id}/quarantine", json=REASON, headers=headers)
    # A registration that committed beside the quarantine's revocation: active,
    # but on the compromised side of the line.
    pem, _fp, _cert = ca.issue("raced-registration")
    await client.post(
        f"{API}/orgs/{member_id}/certificates", json={"certificate_pem": pem}, headers=headers
    )
    session.expire_all()
    quarantined_at = (await session.get(Organization, member_id)).quarantined_at
    raced = (
        (
            await session.execute(
                select(ClientCertificate)
                .where(ClientCertificate.org_id == member_id)
                .order_by(ClientCertificate.created_at.desc())
            )
        )
        .scalars()
        .first()
    )
    raced.created_at = quarantined_at - dt.timedelta(milliseconds=1)
    await session.commit()

    too_early = await client.post(f"{API}/orgs/{member_id}/reconnect", json=REASON, headers=headers)
    fresh_pem, _fp, _cert = ca.issue("after-the-incident")
    await client.post(
        f"{API}/orgs/{member_id}/certificates",
        json={"certificate_pem": fresh_pem},
        headers=headers,
    )
    in_time = await client.post(f"{API}/orgs/{member_id}/reconnect", json=REASON, headers=headers)

    assert too_early.status_code == 409
    assert in_time.status_code == 200


async def test_membership_cannot_change_during_a_quarantine_or_start_in_the_future(
    client, isac, member, make_org, make_circle
):
    _org, headers = isac
    circle = await make_circle("section9")
    other = await make_org("atlantic-clearing", org_type=OrgType.GSIB)
    await client.post(f"{API}/orgs/{member.id}/quarantine", json=REASON, headers=headers)
    members = f"{API}/circles/{circle.id}/members"
    tomorrow = (dt.datetime.now(dt.UTC) + dt.timedelta(days=1)).isoformat()

    quarantined = await client.post(members, json={"org_ids": [str(member.id)]}, headers=headers)
    future = await client.post(
        members, json={"org_ids": [str(other.id)], "joined_at": tomorrow}, headers=headers
    )
    ordinary = await client.post(members, json={"org_ids": [str(other.id)]}, headers=headers)

    assert quarantined.status_code >= 400
    assert future.status_code >= 400
    assert ordinary.status_code == 204


async def test_a_new_interval_reconnection_clips_an_interval_closed_during_the_quarantine(
    client, isac, member, make_circle, join_circle, ca, session
):
    """Removed mid-quarantine, the row ended at the removal and so still covered
    part of the gap; a later rejoin would have delivered it."""
    _org, headers = isac
    member_id = member.id
    removed_circle, kept_circle = await make_circle("removed"), await make_circle("kept")
    kept_circle_id = kept_circle.id
    for circle in (removed_circle, kept_circle):
        await join_circle(member, circle)
    await client.post(f"{API}/orgs/{member_id}/quarantine", json=REASON, headers=headers)
    await client.delete(f"{API}/circles/{removed_circle.id}/members/{member_id}", headers=headers)
    pem, _fp, _cert = ca.issue("after")
    await client.post(
        f"{API}/orgs/{member_id}/certificates", json={"certificate_pem": pem}, headers=headers
    )
    session.expire_all()
    quarantined_at = (await session.get(Organization, member_id)).quarantined_at

    reconnected = await client.post(
        f"{API}/orgs/{member_id}/reconnect",
        json={**REASON, "backlog": "new_interval"},
        headers=headers,
    )

    assert reconnected.status_code == 200
    session.expire_all()
    rows = (
        (
            await session.execute(
                select(CircleMembership).where(CircleMembership.org_id == member_id)
            )
        )
        .scalars()
        .all()
    )
    covering_gap = [
        r
        for r in rows
        if r.joined_at < quarantined_at and (r.left_at is None or r.left_at > quarantined_at)
    ]
    assert covering_gap == []
    reopened = {r.circle_id for r in rows if r.left_at is None}
    assert reopened == {kept_circle_id}, "only what was open is reopened"
