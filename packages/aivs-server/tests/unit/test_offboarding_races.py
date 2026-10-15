"""A request in flight when its organisation is offboarded writes nothing back (SF-72).

A request authenticates first and writes later. Offboarding committing in
between used to leave the write to land after its deletions: a webhook with
its sealed secret, a posture, a portal session, an inbox status, or an open
circle membership for a firm that has left, which nothing ever removes. Each
test here hands a writer the context a request resolved before the
offboarding committed -- exactly what an in-flight request holds -- and shows
the writer refuses. The last runs the race itself: a rule reconciling while
offboarding holds the organisation's row waits for it, and then leaves the
firm out.
"""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import func, select

from aivs_schemas.enums import CircleRole, OrgStatus, OrgType, PostureStatus
from aivs_server.api import admin as admin_api
from aivs_server.auth.context import AuthContext, AuthMethod, CircleGrant, MembershipInterval
from aivs_server.auth.policy import PolicyDeniedError
from aivs_server.auth.sessions import SessionRejectedError, establish_session
from aivs_server.db import models
from aivs_server.services.circles import (
    CircleMembershipError,
    add_circle_members,
    reconcile_circle,
)
from aivs_server.services.inbox import receive_envelope
from aivs_server.services.posture import VexStatement, record_posture
from tests.authz_matrix.world import inbox_note
from tests.conftest import TEST_ATTRIBUTION_KEY, is_blocked
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world

pytestmark = pytest.mark.db

LONG_AGO = dt.datetime(2000, 1, 1, tzinfo=dt.UTC)


@pytest.fixture
async def world(
    session,
    isac,
    isac_org,
    make_org,
    make_cert,
    make_operator,
    make_circle,
    make_collection,
    join_circle,
    human_headers,
) -> SharingWorld:
    return await build_sharing_world(
        session,
        isac,
        isac_org,
        make_org=make_org,
        make_cert=make_cert,
        make_operator=make_operator,
        make_circle=make_circle,
        make_collection=make_collection,
        join_circle=join_circle,
        human_headers=human_headers,
    )


def _resolved_before(world: SharingWorld) -> AuthContext:
    """The member's context as a request resolved it, while the member was active."""
    member = world.member
    grant = CircleGrant(CircleRole.CONTRIBUTOR, (MembershipInterval(LONG_AGO),))
    return AuthContext(
        org_id=member.org.id,
        org_slug=member.org.slug,
        org_type=member.org.org_type,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.MTLS,
        circles={world.circle.id: grant},
        cert_fingerprint="a" * 64,
    )


async def _offboard(client, world: SharingWorld) -> None:
    response = await client.post(
        f"{API}/orgs/{world.member.org.id}/offboard",
        json={"reason": "Membership ended at renewal.", "confirm_slug": world.member.org.slug},
        headers=world.editor,
    )
    assert response.status_code == 200, response.text


@pytest.mark.requirement("SF-72")
async def test_a_posture_in_flight_is_refused_after_offboarding(client, session, world):
    ctx = _resolved_before(world)
    await _offboard(client, world)

    with pytest.raises(PolicyDeniedError):
        await record_posture(
            session,
            ctx,
            vulnerability_id=world.published,
            statement=VexStatement(PostureStatus.FIXED),
            now=dt.datetime.now(dt.UTC),
        )
    await session.rollback()
    assert await session.scalar(select(func.count()).select_from(models.OrgPosture)) == 0


@pytest.mark.requirement("SF-72")
async def test_a_webhook_in_flight_is_refused_after_offboarding(
    client, session, settings, world, monkeypatch
):
    monkeypatch.setattr(admin_api, "resolve_delivery_target", lambda *_a, **_k: None)
    ctx = _resolved_before(world)
    await _offboard(client, world)

    with pytest.raises(PolicyDeniedError):
        await admin_api.register_webhook(
            admin_api.WebhookRegister(url="https://member.example/aivs"), ctx, session, settings
        )
    await session.rollback()
    assert await session.scalar(select(func.count()).select_from(models.Webhook)) == 0


@pytest.mark.requirement("SF-72")
async def test_a_login_in_flight_gets_no_session_after_offboarding(
    client, session, settings, world
):
    operator_id = world.member.operator.id
    org_id = world.member.org.id
    certificate = x509.load_pem_x509_certificate(world.member.pem.encode("ascii"))
    sessions_before = await session.scalar(select(func.count()).select_from(models.PortalSession))
    await _offboard(client, world)
    # As the login request read it: credentials checked a moment earlier.
    operator = await session.get(models.Operator, operator_id, populate_existing=True)

    with pytest.raises(SessionRejectedError, match="org_not_active"):
        await establish_session(
            session,
            settings,
            operator=operator,
            cert_fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
        )
    await session.rollback()
    assert sessions_before >= 1, "the world's analyst signed in before"
    assert (
        await session.scalar(
            select(func.count())
            .select_from(models.PortalSession)
            .where(models.PortalSession.org_id == org_id)
        )
        == 0
    )


@pytest.mark.requirement("SF-72")
async def test_an_inbox_post_in_flight_is_refused_after_offboarding(client, session, world):
    ctx = _resolved_before(world)
    await _offboard(client, world)

    with pytest.raises(PolicyDeniedError):
        await receive_envelope(
            session,
            ctx,
            collection=world.collection,
            circle=world.circle,
            envelope={"objects": [inbox_note(world.published)]},
            hourly_limit=10,
            now=dt.datetime.now(dt.UTC),
            key=TEST_ATTRIBUTION_KEY,
        )
    await session.rollback()
    assert await session.scalar(select(func.count()).select_from(models.TaxiiStatus)) == 0


@pytest.mark.requirement("SF-72")
async def test_a_roster_read_before_offboarding_adds_no_membership(
    client, session, world, isac_ctx, make_circle
):
    elsewhere = await make_circle("elsewhere")
    roster = [await session.get(models.Organization, world.member.org.id)]
    await _offboard(client, world)

    with pytest.raises(CircleMembershipError, match="offboarded"):
        await add_circle_members(
            session,
            isac_ctx,
            circle=elsewhere,
            organisations=roster,
            role=CircleRole.MEMBER,
            joined_at=None,
            now=dt.datetime.now(dt.UTC),
        )
    await session.rollback()


@pytest.mark.requirement("SF-72")
async def test_a_rule_reconciling_during_offboarding_waits_and_leaves_the_firm_out(
    session, open_session, isac_ctx, make_org, make_circle
):
    """The race itself. Without the shared lock the rule read the firm as active,
    and its insert waited only on the foreign key, then opened an interval for a
    firm offboarded a moment before."""
    leaver = await make_org("leaving-bank", org_type=OrgType.GSIB)
    circle = await make_circle("sector-rule")
    circle.auto_member_org_types = [OrgType.GSIB.value]
    await session.commit()

    offboarding = open_session()
    held = await offboarding.get(
        models.Organization, leaver.id, with_for_update=True, populate_existing=True
    )
    held.status = OrgStatus.OFFBOARDED
    await offboarding.flush()

    reconciling = open_session()
    rule_circle = await reconciling.get(models.Circle, circle.id)
    blocked, task = await is_blocked(
        reconcile_circle(reconciling, isac_ctx, circle=rule_circle, now=dt.datetime.now(dt.UTC))
    )
    await offboarding.commit()
    await task
    await reconciling.commit()

    assert blocked, "the rule must wait for the offboarding, not read past it"
    open_intervals = await session.scalar(
        select(func.count())
        .select_from(models.CircleMembership)
        .where(
            models.CircleMembership.org_id == leaver.id,
            models.CircleMembership.left_at.is_(None),
        )
    )
    assert open_intervals == 0
