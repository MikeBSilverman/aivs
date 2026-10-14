"""Circle readers contribute by default, unless a vendor or government body.

A firm that could read a circle but not post to it is why nothing was shared,
and the fast lane publishes only into circles the member contributes to. So a
membership opened with no role named takes its organisation type's default
(``default_circle_role``): a sector member contributes, a vendor or government
body reads. A role an operator names is kept, whatever the type. Each write
path that opens a membership is tested here, because a default enforced on
one path is a default the others skip.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import CircleRole, OrgType, default_circle_role
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog, CircleMembership
from tests.unit.contribution_world import seed, vulnerability_raw
from tests.unit.sharing_world import one_click

pytestmark = pytest.mark.db

API = "/api/v1"


async def role_of(session, circle_id: uuid.UUID, org_id: uuid.UUID) -> CircleRole:
    row = await session.scalar(
        select(CircleMembership).where(
            CircleMembership.circle_id == circle_id,
            CircleMembership.org_id == org_id,
            CircleMembership.left_at.is_(None),
        )
    )
    assert row is not None
    await session.refresh(row)
    return row.role


async def add(client, headers, circle_id, orgs, **body: object):
    response = await client.post(
        f"{API}/circles/{circle_id}/members",
        json={"org_ids": [str(org.id) for org in orgs], **body},
        headers=headers,
    )
    assert response.status_code == 204, response.text


def test_sector_members_contribute_and_vendors_and_government_read():
    assert default_circle_role(OrgType.GSIB) is CircleRole.CONTRIBUTOR
    assert default_circle_role(OrgType.SECTION9) is CircleRole.CONTRIBUTOR
    assert default_circle_role(OrgType.CRIT_INFRA) is CircleRole.CONTRIBUTOR
    assert default_circle_role(OrgType.VENDOR) is CircleRole.MEMBER
    assert default_circle_role(OrgType.GOVERNMENT) is CircleRole.MEMBER
    assert default_circle_role(OrgType.ADMIN) is CircleRole.MEMBER


# ---------------------------------------------------------------------------
# Each path that opens a membership
# ---------------------------------------------------------------------------
async def test_a_roster_with_no_role_gives_each_organisation_its_types_default(
    client, session, isac, make_org, make_circle
):
    _isac_org, headers = isac
    circle = await make_circle("coordination")
    bank = await make_org("meridian-global", org_type=OrgType.GSIB)
    vendor = await make_org("acme-software", org_type=OrgType.VENDOR)
    regulator = await make_org("prudential-authority", org_type=OrgType.GOVERNMENT)

    await add(client, headers, circle.id, [bank, vendor, regulator])

    assert await role_of(session, circle.id, bank.id) is CircleRole.CONTRIBUTOR
    assert await role_of(session, circle.id, vendor.id) is CircleRole.MEMBER
    assert await role_of(session, circle.id, regulator.id) is CircleRole.MEMBER


async def test_a_role_the_operator_names_is_kept_whatever_the_type(
    client, session, isac, make_org, make_circle
):
    _isac_org, headers = isac
    circle = await make_circle("coordination")
    bank = await make_org("meridian-global", org_type=OrgType.GSIB)
    vendor = await make_org("acme-software", org_type=OrgType.VENDOR)

    await add(client, headers, circle.id, [bank], role="member")
    await add(client, headers, circle.id, [vendor], role="contributor")

    assert await role_of(session, circle.id, bank.id) is CircleRole.MEMBER
    assert await role_of(session, circle.id, vendor.id) is CircleRole.CONTRIBUTOR


async def test_the_audit_row_says_which_role_each_organisation_joined_with(
    client, session, isac, make_org, make_circle
):
    _isac_org, headers = isac
    circle = await make_circle("coordination")
    bank = await make_org("meridian-global", org_type=OrgType.GSIB)
    vendor = await make_org("acme-software", org_type=OrgType.VENDOR)

    await add(client, headers, circle.id, [bank, vendor])

    row = await session.scalar(
        select(AuditLog).where(AuditLog.action == AuditAction.CIRCLE_MEMBER_ADDED)
    )
    assert row.details["roles"] == {str(bank.id): "contributor", str(vendor.id): "member"}


async def test_a_membership_rule_adds_sector_members_as_contributors(
    client, session, isac, make_org
):
    _isac_org, headers = isac
    firm = await make_org("trust-company", org_type=OrgType.SECTION9)

    created = await client.post(
        f"{API}/circles",
        json={"slug": "section9", "name": "Section 9", "auto_member_org_types": ["section9"]},
        headers=headers,
    )

    assert created.status_code == 201, created.text
    circle_id = uuid.UUID(created.json()["id"])
    assert await role_of(session, circle_id, firm.id) is CircleRole.CONTRIBUTOR


# ---------------------------------------------------------------------------
# What it is for
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-66")
async def test_a_bank_added_with_no_role_named_takes_the_fast_lane(
    client, session, isac, isac_org, make_org, make_cert, make_operator, make_circle, human_headers
):
    _isac_org, headers = isac
    circle = await make_circle("coordination")
    bank = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(bank)
    operator, _seed = await make_operator(bank)
    person = await human_headers(operator, pem)
    # Backdated so the bank reads the record seeded below: a membership grants
    # nothing distributed before it began.
    await add(client, headers, circle.id, [bank], joined_at="2020-01-01T00:00:00Z")
    record = f"vulnerability--{uuid.uuid4()}"
    await seed(session, isac_org, vulnerability_raw(record, cve_status="published"), circle=circle)

    clicked = await one_click(client, person, record)

    assert clicked.status_code == 201, clicked.text
    assert clicked.json()["lane"] == "fast"
