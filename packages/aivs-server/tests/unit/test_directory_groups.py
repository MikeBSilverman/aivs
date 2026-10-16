"""Which directory group signs in as which organisation: written by membership staff (SF-65).

``services.sso`` matched a sign-in's groups against
``organizations.directory_object_id`` from the start, and nothing in the
application wrote that column. These are the writer's tests; the reader's
are in ``test_member_sso``, and the last test here drives one through the other.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from aivs_schemas.enums import OperatorRole, OrgStatus, OrgType
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog
from tests.conftest import proxy_headers

API = "/api/v1"


@pytest.fixture
async def bank(make_org):
    return await make_org("bank", org_type=OrgType.GSIB)


async def map_group(client, headers, org, group):
    return await client.put(
        f"{API}/orgs/{org.id}/directory-group",
        json={"directory_object_id": group},
        headers=headers,
    )


@pytest.mark.requirement("SF-65")
async def test_membership_staff_map_change_and_unmap_a_group_each_audited_with_the_previous(
    client, session, isac, bank
):
    _isac_org, headers = isac

    for group in ("grp-bank-analysts", "grp-bank-all", None):
        answered = await map_group(client, headers, bank, group)
        assert answered.status_code == 200, answered.text
        assert answered.json() == {"directory_object_id": group}

    await session.refresh(bank)
    assert bank.directory_object_id is None
    rows = (
        await session.scalars(
            select(AuditLog)
            .where(AuditLog.action == AuditAction.ORG_DIRECTORY_GROUP_SET)
            .order_by(AuditLog.id)
        )
    ).all()
    assert [(row.details["previous"], row.details["directory_object_id"]) for row in rows] == [
        (None, "grp-bank-analysts"),
        ("grp-bank-analysts", "grp-bank-all"),
        ("grp-bank-all", None),
    ]
    assert {row.resource_id for row in rows} == {"bank"}


@pytest.mark.requirement("SF-65")
async def test_a_group_is_one_organisations(client, session, isac, bank, make_org):
    """A person in a group two members held would be refused as ambiguous at every
    sign-in; the second mapping is refused instead, where staff can see why."""
    _isac_org, headers = isac
    meridian = await make_org("meridian", org_type=OrgType.GSIB)
    assert (await map_group(client, headers, bank, "grp-shared")).status_code == 200

    refused = await map_group(client, headers, meridian, "grp-shared")

    assert refused.status_code == 409
    await session.refresh(meridian)
    assert meridian.directory_object_id is None


async def test_an_offboarded_organisation_is_mapped_to_nothing(client, session, isac, bank):
    _isac_org, headers = isac
    bank.status = OrgStatus.OFFBOARDED
    await session.commit()

    refused = await map_group(client, headers, bank, "grp-bank")

    assert refused.status_code == 409
    assert "offboarded" in refused.json()["title"]


@pytest.mark.parametrize("group", ["", "grp bank", "grp\tbank", "g" * 201])
async def test_a_group_id_with_spaces_control_characters_or_no_length_is_refused(
    client, isac, bank, group
):
    _isac_org, headers = isac

    assert (await map_group(client, headers, bank, group)).status_code == 400


@pytest.mark.requirement("SF-65")
async def test_a_member_org_admin_cannot_map_its_own_group(
    client, bank, make_cert, make_operator, human_headers
):
    """Whoever sets the mapping decides which firm a member-tenant person acts for."""
    pem, _ = await make_cert(bank)
    admin, _seed = await make_operator(bank, roles=(OperatorRole.ORG_ADMIN,))

    for headers in (await human_headers(admin, pem), proxy_headers(pem)):
        assert (await map_group(client, headers, bank, "grp-bank")).status_code == 403
