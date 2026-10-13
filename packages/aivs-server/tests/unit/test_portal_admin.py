"""The hosting ISAC's administrative screens.

These exist because "administer it over the REST API" is a reasonable thing to
say about a library and an unreasonable thing to say about a product an
organisation is meant to operate. The tests care about two things: that the
screens do the same thing the API does, and that they are not a softer door to
it.
"""

from __future__ import annotations

import re
import uuid

import pyotp
import pytest
from sqlalchemy import select

from aivs_schemas.enums import OperatorRole, OrgStatus, OrgType
from aivs_server.auth.passwords import hash_password
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db.models import Circle, CircleMembership, Operator, Organization
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

ADMIN = "/portal/admin"
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
async def signed_in_admin(client, make_org, make_cert, session, secret_box):
    """An operator at the hosting ISAC, signed in to the portal."""
    org = await make_org("hosting-isac", org_type=OrgType.ADMIN)
    pem, _ = await make_cert(org)
    secret = pyotp.random_base32()
    # Explicit id: the seal is bound to it, before the column default applies.
    operator_id = uuid.uuid4()
    operator = Operator(
        id=operator_id,
        org_id=org.id,
        email="isac-admin@example.test",
        display_name="ISAC Admin",
        role=OperatorRole.SYSTEM_ADMIN,
        password_hash=hash_password(PASSWORD),
        totp_secret_encrypted=secret_box.seal(
            secret, purpose=SecretPurpose.TOTP, subject=operator_id
        ),
    )
    session.add(operator)
    await session.commit()

    await sign_in(client, operator, secret, pem)
    return org, pem


async def sign_in(client, operator, secret, pem) -> None:
    """Complete the sign-in flow, leaving the session cookies on the client.

    The login form's token comes from the rendered page; the cookie holds only
    its digest, which is the point of the double-submit pair.
    """
    form = await client.get("/portal/login", headers=proxy_headers(pem))
    assert form.status_code == 200
    token = re.search(r'name="csrf_token" value="([^"]+)"', form.text).group(1)

    response = await client.post(
        "/portal/login",
        data={
            "email": operator.email,
            "password": PASSWORD,
            "totp_code": pyotp.TOTP(secret).now(),
            "csrf_token": token,
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 303, response.text


def csrf(client) -> str:
    """The session CSRF token, which the portal sets as a readable cookie."""
    return client.cookies.get("aivs_csrf", "")


# ---------------------------------------------------------------------------
# The screens are the ISAC's alone
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path",
    [f"{ADMIN}/orgs", f"{ADMIN}/circles"],
)
async def test_the_screens_redirect_an_anonymous_browser_to_sign_in(client, path):
    """The portal refuses differently from the API: a 401 in a browser is a dead end."""
    response = await client.get(path)
    assert response.status_code == 303
    assert response.headers["location"] == "/portal/login"


async def test_a_member_analyst_cannot_reach_the_screens(
    client, make_org, make_cert, session, secret_box
):
    """Same policy predicate as the API, checked before anything happens."""
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    secret = pyotp.random_base32()
    # Explicit id: the seal is bound to it, before the column default applies.
    operator_id = uuid.uuid4()
    operator = Operator(
        id=operator_id,
        org_id=org.id,
        email="analyst@example.test",
        display_name="Analyst",
        role=OperatorRole.ANALYST,
        password_hash=hash_password(PASSWORD),
        totp_secret_encrypted=secret_box.seal(
            secret, purpose=SecretPurpose.TOTP, subject=operator_id
        ),
    )
    session.add(operator)
    await session.commit()

    await sign_in(client, operator, secret, pem)

    refused = await client.get(f"{ADMIN}/orgs", headers=proxy_headers(pem))
    assert refused.status_code == 403


# ---------------------------------------------------------------------------
# Organisations
# ---------------------------------------------------------------------------
async def test_an_operator_can_enrol_and_activate_an_organisation(client, signed_in_admin, session):
    """Enrolment and activation stay two steps, exactly as over the API."""
    _org, pem = signed_in_admin

    enrolled = await client.post(
        f"{ADMIN}/orgs",
        data={
            "csrf_token": csrf(client),
            "slug": "atlantic-clearing",
            "name": "Atlantic Clearing",
            "org_type": "section9",
        },
        headers=proxy_headers(pem),
    )
    assert enrolled.status_code == 303, enrolled.text

    created = (
        await session.execute(select(Organization).where(Organization.slug == "atlantic-clearing"))
    ).scalar_one()
    assert created.status is OrgStatus.PENDING, "enrolment alone is not access"

    activated = await client.post(
        f"{ADMIN}/orgs/{created.id}/activate",
        data={"csrf_token": csrf(client)},
        headers=proxy_headers(pem),
    )
    assert activated.status_code == 303
    await session.refresh(created)
    assert created.status is OrgStatus.ACTIVE


async def test_enrolling_without_a_csrf_token_is_refused(client, signed_in_admin):
    _org, pem = signed_in_admin
    response = await client.post(
        f"{ADMIN}/orgs",
        data={
            "csrf_token": "forged",
            "slug": "rogue-firm",
            "name": "Rogue",
            "org_type": "gsib",
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Circles
# ---------------------------------------------------------------------------
async def test_an_operator_can_create_a_circle_with_a_rule(client, signed_in_admin, session):
    """The rule populates the circle on creation, as it does over the API."""
    _org, pem = signed_in_admin

    existing = Organization(
        slug="a-section9-firm",
        name="A Section 9 Firm",
        org_type=OrgType.SECTION9,
        status=OrgStatus.ACTIVE,
        stix_identity_id=f"identity--{uuid.uuid4()}",
    )
    session.add(existing)
    await session.commit()

    created = await client.post(
        f"{ADMIN}/circles",
        data={
            "csrf_token": csrf(client),
            "slug": "section9",
            "name": "Section 9",
            "minimum_tlp": "amber",
            "auto_member_org_types": ["section9"],
        },
        headers=proxy_headers(pem),
    )
    assert created.status_code == 303, created.text

    circle = (await session.execute(select(Circle).where(Circle.slug == "section9"))).scalar_one()
    assert circle.auto_member_org_types == ["section9"]

    members = (
        (
            await session.execute(
                select(CircleMembership).where(CircleMembership.circle_id == circle.id)
            )
        )
        .scalars()
        .all()
    )
    assert [row.org_id for row in members] == [existing.id]
    assert members[0].managed_by_rule is True


async def test_a_pasted_roster_adds_members(client, signed_in_admin, make_circle, session):
    """Slugs, one per line -- the form an operator already has the list in."""
    _org, pem = signed_in_admin
    circle = await make_circle("gsib")
    for slug in ("firm-one", "firm-two"):
        session.add(
            Organization(
                slug=slug,
                name=slug.title(),
                org_type=OrgType.GSIB,
                status=OrgStatus.ACTIVE,
                stix_identity_id=f"identity--{uuid.uuid4()}",
            )
        )
    await session.commit()

    added = await client.post(
        f"{ADMIN}/circles/{circle.id}/members",
        data={
            "csrf_token": csrf(client),
            "roster": "firm-one\nfirm-two",
            "role": "member",
        },
        headers=proxy_headers(pem),
    )
    assert added.status_code == 303, added.text

    members = (
        (
            await session.execute(
                select(CircleMembership).where(CircleMembership.circle_id == circle.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(members) == 2


async def test_an_unknown_slug_in_a_roster_adds_nobody(
    client, signed_in_admin, make_circle, session
):
    """All or nothing, so an operator is never told a group is complete when it is not."""
    _org, pem = signed_in_admin
    circle = await make_circle("gsib")
    session.add(
        Organization(
            slug="firm-one",
            name="Firm One",
            org_type=OrgType.GSIB,
            status=OrgStatus.ACTIVE,
            stix_identity_id=f"identity--{uuid.uuid4()}",
        )
    )
    await session.commit()

    response = await client.post(
        f"{ADMIN}/circles/{circle.id}/members",
        data={
            "csrf_token": csrf(client),
            "roster": "firm-one, no-such-firm",
            "role": "member",
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 303, "the operator is redirected with a notice"

    members = (
        (
            await session.execute(
                select(CircleMembership).where(CircleMembership.circle_id == circle.id)
            )
        )
        .scalars()
        .all()
    )
    assert members == [], "a partial roster must not be partially applied"


async def test_the_circle_screen_shows_membership_start(
    client, signed_in_admin, make_circle, make_org, join_circle
):
    """Join date is on the page because it bounds what the member can read.

    An operator answering "why can they not see this?" needs it in front of
    them, not in a database.
    """
    _org, pem = signed_in_admin
    circle = await make_circle("section9")
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    await join_circle(member, circle)

    page = await client.get(f"{ADMIN}/circles/{circle.id}", headers=proxy_headers(pem))
    assert page.status_code == 200
    assert "meridian-global" in page.text
    assert "Member since" in page.text
