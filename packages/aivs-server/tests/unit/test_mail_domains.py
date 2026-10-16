"""Which mail domains are which member's: recorded by membership staff, one firm each (Q41).

The readers (the email intake, the SSO link) are tested where they live; this
is the list itself: its one normalisation, its writer and its guarantees.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from aivs_schemas.enums import OperatorRole, OrgStatus, OrgType
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog, OrgMailDomain
from aivs_server.services.mail_domains import (
    MailDomainError,
    address_domain,
    parse_mail_domain,
)
from tests.conftest import proxy_headers

API = "/api/v1"


# ---------------------------------------------------------------------------
# The one normalisation
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-104")
@pytest.mark.parametrize(
    ("typed", "stored"),
    [
        ("bank.example", "bank.example"),
        ("  Bank.EXAMPLE.  ", "bank.example"),
        ("mail.bank.example", "mail.bank.example"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
    ],
)
def test_a_domain_is_stored_in_one_form(typed, stored):
    assert parse_mail_domain(typed) == stored


@pytest.mark.requirement("SF-104")
@pytest.mark.parametrize(
    "typed",
    [
        "example",
        "*.bank.example",
        "alice@bank.example",
        "10.0.0.1",
        "-bank.example",
        "bank-.example",
        "bank..example",
        "bank example.com",
        f"{'a' * 64}.example",
        ".".join(["abcdefghi"] * 26),
    ],
)
def test_anything_but_a_host_name_is_refused_not_repaired(typed):
    with pytest.raises(MailDomainError):
        parse_mail_domain(typed)


@pytest.mark.parametrize(
    ("address", "domain"),
    [
        ("alice@Bank.Example", "bank.example"),
        ('"a@b"@bank.example', "bank.example"),
        ("alice@", None),
        ("@bank.example", None),
        ("no-at-sign", None),
        ("alice@[10.0.0.1]", None),
    ],
)
def test_an_addresss_domain_is_normalised_as_recorded_ones_are(address, domain):
    assert address_domain(address) == domain


@pytest.mark.requirement("SF-104")
async def test_a_row_written_by_hand_cannot_hold_a_form_nothing_compares_equal(
    session, make_org, make_operator
):
    org = await make_org("bank", org_type=OrgType.GSIB)
    staff, _seed = await make_operator(org)
    session.add(
        OrgMailDomain(
            domain="Bank.Example",
            org_id=org.id,
            added_at=staff.created_at,
            added_by_operator_id=staff.id,
        )
    )
    with pytest.raises(IntegrityError, match="domain_format"):
        await session.commit()


# ---------------------------------------------------------------------------
# The writer, over the API
# ---------------------------------------------------------------------------
@pytest.fixture
async def bank(make_org):
    return await make_org("bank", org_type=OrgType.GSIB)


async def domains(client, headers, org) -> list[str]:
    listed = await client.get(f"{API}/orgs/{org.id}/mail-domains", headers=headers)
    assert listed.status_code == 200, listed.text
    return listed.json()["domains"]


async def add(client, headers, org, domain: str):
    return await client.post(
        f"{API}/orgs/{org.id}/mail-domains", json={"domain": domain}, headers=headers
    )


async def remove(client, headers, org, domain: str):
    return await client.post(
        f"{API}/orgs/{org.id}/mail-domains/remove", json={"domain": domain}, headers=headers
    )


@pytest.mark.requirement("SF-104")
async def test_membership_staff_record_and_remove_a_domain_and_each_is_audited(
    client, session, isac, bank
):
    _isac_org, headers = isac

    added = await add(client, headers, bank, "Bank.Example")
    assert added.status_code == 201, added.text
    assert added.json()["domains"] == ["bank.example"]
    removed = await remove(client, headers, bank, "bank.example")
    assert removed.status_code == 200, removed.text

    assert await domains(client, headers, bank) == []
    rows = (
        await session.scalars(
            select(AuditLog).where(AuditLog.action.like("org.mail_domain.%")).order_by(AuditLog.id)
        )
    ).all()
    assert [(row.action, row.resource_id, row.details["domain"]) for row in rows] == [
        (AuditAction.ORG_MAIL_DOMAIN_ADDED, "bank", "bank.example"),
        (AuditAction.ORG_MAIL_DOMAIN_REMOVED, "bank", "bank.example"),
    ]


@pytest.mark.requirement("SF-104")
async def test_a_domain_is_one_firms_and_a_second_claim_names_the_first(
    client, isac, bank, make_org
):
    """Two members claiming a domain is for the ISAC to settle; the server never picks."""
    _isac_org, headers = isac
    meridian = await make_org("meridian", org_type=OrgType.GSIB)
    assert (await add(client, headers, bank, "bank.example")).status_code == 201

    claimed = await add(client, headers, meridian, "BANK.example")

    assert claimed.status_code == 409
    assert "recorded for bank" in claimed.json()["title"]
    assert await domains(client, headers, meridian) == []
    assert await domains(client, headers, bank) == ["bank.example"]


@pytest.mark.requirement("SF-104")
async def test_removing_a_domain_another_firm_holds_removes_nothing(client, isac, bank, make_org):
    _isac_org, headers = isac
    meridian = await make_org("meridian", org_type=OrgType.GSIB)
    assert (await add(client, headers, bank, "bank.example")).status_code == 201

    refused = await remove(client, headers, meridian, "bank.example")

    assert refused.status_code == 409
    assert await domains(client, headers, bank) == ["bank.example"]


@pytest.mark.requirement("SF-104")
async def test_an_offboarded_firm_is_given_no_domain(client, session, isac, bank):
    """Offboarding freed its domains for another member; adding one back would hold
    a domain for a firm that is gone."""
    _isac_org, headers = isac
    bank.status = OrgStatus.OFFBOARDED
    await session.commit()

    refused = await add(client, headers, bank, "bank.example")

    assert refused.status_code == 409
    assert "offboarded" in refused.json()["title"]


async def test_a_malformed_domain_is_refused_with_the_rule(client, isac, bank):
    _isac_org, headers = isac

    refused = await add(client, headers, bank, "*.bank.example")

    assert refused.status_code == 409
    assert "domain name" in refused.json()["title"]


@pytest.mark.requirement("SF-104")
async def test_a_member_org_admin_cannot_extend_its_own_list(
    client, bank, make_cert, make_operator, human_headers
):
    """The list bounds what a member's addresses and IdP may claim; a member able
    to extend it could claim another firm's domain."""
    pem, _ = await make_cert(bank)
    admin, _seed = await make_operator(bank, roles=(OperatorRole.ORG_ADMIN,))
    headers = await human_headers(admin, pem)

    refused = await add(client, headers, bank, "bank.example")

    assert refused.status_code == 403
    listed = await client.get(f"{API}/orgs/{bank.id}/mail-domains", headers=headers)
    assert listed.status_code == 403
    machine = await add(client, proxy_headers(pem), bank, "bank.example")
    assert machine.status_code == 403
