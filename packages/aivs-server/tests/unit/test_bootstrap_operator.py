"""The first operator on a fresh instance (open finding: "no operator can exist").

Every ISAC power needs a signed-in human, and enrolling an organisation,
registering a certificate and creating an operator are themselves ISAC powers --
so before this command a fresh deployment's portal was unreachable until
someone hand-crafted rows, which since secrets-at-rest also meant hand-building
an AEAD envelope bound to the operator's own id.
"""

from __future__ import annotations

import pyotp
import pytest
from cryptography.hazmat.primitives import serialization
from sqlalchemy import func, select

from aivs_schemas.enums import OperatorRole, OrgType
from aivs_server.auth.secretbox import SecretBox
from aivs_server.auth.sessions import authenticate_operator
from aivs_server.bootstrap_operator import BootstrapError, bootstrap
from aivs_server.db.models import AuditLog, ClientCertificate, Operator, Organization
from aivs_server.services.operators import OperatorError, create_operator
from tests.conftest import TEST_OPERATOR_PASSWORD
from tests.unit.test_issuing_ca_pin import _forged

pytestmark = pytest.mark.db

EDITOR_AND_ADMIN = [OperatorRole.SYSTEM_ADMIN, OperatorRole.ISAC_EDITOR]


async def _count(session, model) -> int:
    return await session.scalar(select(func.count()).select_from(model)) or 0


async def test_a_fresh_instance_gets_an_isac_a_certificate_and_an_operator_who_can_sign_in(
    session, settings, secret_box, ca
):
    pem, _fingerprint, _cert = ca.issue("example-isac-ops")

    result = await bootstrap(
        session,
        settings,
        org_slug="example-isac",
        org_name="Example ISAC",
        email="Ops@Example-ISAC.org",
        display_name="Ops Lead",
        password=TEST_OPERATOR_PASSWORD,
        roles=EDITOR_AND_ADMIN,
        certificate_pem=pem,
        additional=False,
    )

    organisation = await session.get(Organization, result.organisation_id)
    assert organisation is not None
    assert organisation.org_type is OrgType.ADMIN
    assert await _count(session, ClientCertificate) == 1

    signed_in = await authenticate_operator(
        session,
        email="ops@example-isac.org",
        password=TEST_OPERATOR_PASSWORD,
        totp_code=pyotp.TOTP(result.totp_seed).now(),
        org_id=result.organisation_id,
        secret_box=SecretBox.from_settings(settings),
    )
    assert set(signed_in.roles) == set(EDITOR_AND_ADMIN)


async def test_it_refuses_a_member_organisation_and_accepts_the_isacs_own(
    session, settings, make_org
):
    """Not a way round the portal for creating anyone else's operators."""
    await make_org("member-bank", org_type=OrgType.GSIB)
    isac = await make_org("the-isac", org_type=OrgType.ADMIN)

    with pytest.raises(BootstrapError, match="member organisation"):
        await bootstrap(
            session,
            settings,
            org_slug="member-bank",
            org_name=None,
            email="someone@member.test",
            display_name="Someone",
            password=TEST_OPERATOR_PASSWORD,
            roles=[OperatorRole.ANALYST],
            certificate_pem=None,
            additional=False,
        )
    await session.rollback()

    result = await bootstrap(
        session,
        settings,
        org_slug="the-isac",
        org_name=None,
        email="second@isac.test",
        display_name="Second Editor",
        password=TEST_OPERATOR_PASSWORD,
        roles=[OperatorRole.ISAC_EDITOR],
        certificate_pem=None,
        additional=False,
    )
    assert result.organisation_id == isac.id
    assert result.created_organisation is False


async def test_it_refuses_a_second_isac_organisation(session, settings, make_org):
    await make_org("the-isac", org_type=OrgType.ADMIN)

    with pytest.raises(BootstrapError, match="already has an ISAC organisation"):
        await bootstrap(
            session,
            settings,
            org_slug="another-isac",
            org_name="Another ISAC",
            email="ops@another.test",
            display_name="Ops",
            password=TEST_OPERATOR_PASSWORD,
            roles=[OperatorRole.SYSTEM_ADMIN],
            certificate_pem=None,
            additional=False,
        )


async def test_a_forged_certificate_refuses_the_whole_bootstrap(session, settings, ca):
    """One transaction: a refused certificate leaves no organisation or operator."""
    forged_pem = _forged(ca, "forged-isac").public_bytes(serialization.Encoding.PEM).decode()

    with pytest.raises(ValueError, match="not issued by this instance"):
        await bootstrap(
            session,
            settings,
            org_slug="example-isac",
            org_name="Example ISAC",
            email="ops@example-isac.org",
            display_name="Ops Lead",
            password=TEST_OPERATOR_PASSWORD,
            roles=[OperatorRole.SYSTEM_ADMIN],
            certificate_pem=forged_pem,
            additional=False,
        )
    await session.rollback()

    assert await _count(session, Organization) == 0
    assert await _count(session, Operator) == 0


async def test_org_admin_is_refused_at_the_hosting_isac(session, secret_box, make_org):
    """A member firm's role grants nothing at the ISAC; an inert grant reads as real."""
    isac = await make_org("hosting-isac", org_type=OrgType.ADMIN)

    with pytest.raises(OperatorError, match="member firm's role"):
        await create_operator(
            session,
            None,
            organisation=isac,
            email="admin@isac.test",
            display_name="Admin",
            password=TEST_OPERATOR_PASSWORD,
            roles=[OperatorRole.ORG_ADMIN],
            secret_box=secret_box,
        )


async def test_isac_roles_are_refused_at_a_member_firm_and_member_roles_are_not(
    session, secret_box, make_org
):
    """An inert grant would read as real to anyone auditing who holds what."""
    member = await make_org("member-bank", org_type=OrgType.GSIB)

    with pytest.raises(OperatorError, match="only be held at the hosting ISAC"):
        await create_operator(
            session,
            None,
            organisation=member,
            email="analyst@member.test",
            display_name="Analyst",
            password=TEST_OPERATOR_PASSWORD,
            roles=[OperatorRole.ISAC_EDITOR],
            secret_box=secret_box,
        )

    operator, _seed = await create_operator(
        session,
        None,
        organisation=member,
        email="analyst@member.test",
        display_name="Analyst",
        password=TEST_OPERATOR_PASSWORD,
        roles=[OperatorRole.ORG_ADMIN],
        secret_box=secret_box,
    )
    assert operator.roles == [OperatorRole.ORG_ADMIN]


async def test_the_audit_record_names_roles_not_the_person(session, settings):
    """The audit log is immutable; an address in it could never be removed."""
    await bootstrap(
        session,
        settings,
        org_slug="example-isac",
        org_name="Example ISAC",
        email="ops@example-isac.org",
        display_name="Ops Lead",
        password=TEST_OPERATOR_PASSWORD,
        roles=[OperatorRole.SYSTEM_ADMIN],
        certificate_pem=None,
        additional=False,
    )
    rows = (await session.execute(select(AuditLog))).scalars().all()
    created = [row for row in rows if row.action == "operator.created"]
    assert len(created) == 1
    assert created[0].details == {"roles": ["system_admin"]}
    assert all("example-isac.org" not in str(row.details) for row in rows)


async def _bootstrap_with(session, settings, *, email: str, pem: str | None, additional: bool):
    return await bootstrap(
        session,
        settings,
        org_slug="example-isac",
        org_name="Example ISAC",
        email=email,
        display_name="Ops",
        password=TEST_OPERATOR_PASSWORD,
        roles=[OperatorRole.SYSTEM_ADMIN],
        certificate_pem=pem,
        additional=additional,
    )


async def test_an_additional_operator_with_a_registered_certificate_is_refused_by_name(
    session, settings, ca
):
    """A refusal that says what to do, not a constraint violation; and nothing is created.

    Refused even though the certificate is the ISAC's own: re-registering it
    would add nothing, and a revoked one must not come back this way.
    """
    pem, _fingerprint, _cert = ca.issue("example-isac-ops")
    await _bootstrap_with(
        session, settings, email="first@example-isac.org", pem=pem, additional=False
    )

    with pytest.raises(BootstrapError, match="already registered; omit --certificate"):
        await _bootstrap_with(
            session, settings, email="second@example-isac.org", pem=pem, additional=True
        )
    await session.rollback()

    assert await _count(session, Operator) == 1
    assert await _count(session, ClientCertificate) == 1


async def test_an_additional_operator_without_a_certificate_is_created(session, settings, ca):
    pem, _fingerprint, _cert = ca.issue("example-isac-ops")
    await _bootstrap_with(
        session, settings, email="first@example-isac.org", pem=pem, additional=False
    )

    await _bootstrap_with(
        session, settings, email="second@example-isac.org", pem=None, additional=True
    )

    assert await _count(session, Operator) == 2
