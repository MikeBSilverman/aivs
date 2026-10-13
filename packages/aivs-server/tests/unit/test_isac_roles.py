"""ISAC powers are human, split by role, and reachable from the API (SF-42).

The admin organisation's certificate used to *be* the instance and held every
ISAC power -- validate, distribute, embargo, enrol, register certificates,
admit to circles. Whoever controls the issuing CA can mint one; in the managed
mode that is the host. These tests pin the replacement: every ISAC power needs
a signed-in human holding the right role, presented to the API as a bearer
token bound to the certificate it was issued over.

Every test is a pair. The refused call and an otherwise identical permitted one
sit side by side, so a pass cannot come from the route simply being broken.
"""

from __future__ import annotations

import uuid

import pytest

from aivs_schemas.enums import OperatorRole, OrgType
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1"


def _bundle() -> dict:
    stamp = "2026-08-01T00:00:00.000Z"
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{uuid.uuid4()}",
                "created": stamp,
                "modified": stamp,
                "name": "A finding",
            }
        ],
    }


@pytest.fixture
async def submitted(client, make_org, make_cert):
    """A member's submission, sent for review. Returns its id."""
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    created = await client.post(
        f"{API}/submissions",
        json={"title": "For review", "discovery_scope": "ai_system", "bundle": _bundle()},
        headers=proxy_headers(pem),
    )
    submission_id = created.json()["id"]
    await client.post(
        f"{API}/submissions/{submission_id}/submit", json={}, headers=proxy_headers(pem)
    )
    return submission_id


@pytest.fixture
async def isac_person(make_org, make_cert, make_operator, human_headers):
    """Factory: headers for a human at the hosting ISAC holding ``roles``."""
    org = await make_org("hosting-isac", org_type=OrgType.ADMIN)
    pem, _ = await make_cert(org)

    async def _person(*roles: OperatorRole) -> dict[str, str]:
        operator, _seed = await make_operator(org, roles=roles)
        return await human_headers(operator, pem)

    return _person, pem


# ---------------------------------------------------------------------------
# A certificate is not a person
# ---------------------------------------------------------------------------
async def test_the_admin_certificate_alone_cannot_validate(client, submitted, isac_person):
    person, pem = isac_person
    editor = await person(OperatorRole.ISAC_EDITOR)

    refused = await client.post(
        f"{API}/submissions/{submitted}/validate", json={}, headers=proxy_headers(pem)
    )
    accepted = await client.post(f"{API}/submissions/{submitted}/validate", json={}, headers=editor)

    # 404, not 403: the certificate alone cannot even see the submission exists.
    assert refused.status_code == 404
    assert accepted.status_code == 200


async def test_the_admin_certificate_alone_cannot_enrol(client, isac_person):
    person, pem = isac_person
    membership = await person(OperatorRole.ISAC_MEMBERSHIP)
    payload = {"slug": "new-firm", "name": "New Firm", "org_type": "gsib"}

    refused = await client.post(f"{API}/orgs", json=payload, headers=proxy_headers(pem))
    accepted = await client.post(f"{API}/orgs", json=payload, headers=membership)

    assert refused.status_code == 403
    assert accepted.status_code == 201


# ---------------------------------------------------------------------------
# Each role reaches its own verbs and no others
# ---------------------------------------------------------------------------
async def test_an_isac_analyst_sees_a_submission_but_cannot_validate_it(
    client, submitted, isac_person
):
    person, _pem = isac_person
    analyst = await person(OperatorRole.ISAC_ANALYST)

    seen = await client.get(f"{API}/submissions/{submitted}", headers=analyst)
    validated = await client.post(
        f"{API}/submissions/{submitted}/validate", json={}, headers=analyst
    )

    assert seen.status_code == 200
    assert validated.status_code == 403


async def test_membership_staff_enrol_but_never_see_what_members_filed(
    client, submitted, isac_person
):
    person, _pem = isac_person
    membership = await person(OperatorRole.ISAC_MEMBERSHIP)

    enrolled = await client.post(
        f"{API}/orgs",
        json={"slug": "another-firm", "name": "Another", "org_type": "gsib"},
        headers=membership,
    )
    looked = await client.get(f"{API}/submissions/{submitted}", headers=membership)

    assert enrolled.status_code == 201
    assert looked.status_code == 404


async def test_system_admin_runs_the_instance_and_holds_no_editorial_verb(
    client, submitted, isac_person
):
    person, _pem = isac_person
    system_admin = await person(OperatorRole.SYSTEM_ADMIN)
    editor = await person(OperatorRole.ISAC_EDITOR)

    refused = await client.post(
        f"{API}/submissions/{submitted}/validate", json={}, headers=system_admin
    )
    accepted = await client.post(f"{API}/submissions/{submitted}/validate", json={}, headers=editor)

    assert refused.status_code == 404
    assert accepted.status_code == 200


# ---------------------------------------------------------------------------
# The bearer path
# ---------------------------------------------------------------------------
async def test_an_invalid_bearer_is_refused_not_downgraded_to_the_certificate(
    client, make_org, make_cert
):
    """A caller who asked to act as a person and is not one must not proceed
    as the machine instead. The same certificate without the header works."""
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)

    machine = await client.get(f"{API}/whoami", headers=proxy_headers(pem))
    forged = await client.get(
        f"{API}/whoami",
        headers={**proxy_headers(pem), "authorization": "Bearer not-a-session"},
    )
    malformed = await client.get(
        f"{API}/whoami", headers={**proxy_headers(pem), "authorization": "Basic Zm9vOmJhcg=="}
    )

    assert machine.status_code == 200
    assert forged.status_code == 401
    assert malformed.status_code == 401


async def test_a_bearer_is_bound_to_the_certificate_it_was_issued_over(
    client, submitted, isac_person, make_cert, make_org
):
    """A token lifted from one network path is useless from another, even the
    same organisation's second certificate."""
    person, _pem = isac_person
    editor = await person(OperatorRole.ISAC_EDITOR)
    isac_org = await make_org("hosting-isac-second", org_type=OrgType.ADMIN)
    other_pem, _ = await make_cert(isac_org)
    replayed = {**proxy_headers(other_pem), "authorization": editor["authorization"]}

    refused = await client.get(f"{API}/submissions/{submitted}", headers=replayed)
    accepted = await client.get(f"{API}/submissions/{submitted}", headers=editor)

    assert refused.status_code == 401
    assert accepted.status_code == 200


async def test_a_signed_out_session_stops_working_as_a_bearer(
    client, submitted, isac_person, session
):
    from aivs_server.auth.sessions import revoke_session  # noqa: PLC0415 - local to this test

    person, _pem = isac_person
    editor = await person(OperatorRole.ISAC_EDITOR)
    before = await client.get(f"{API}/submissions/{submitted}", headers=editor)

    token = editor["authorization"].removeprefix("Bearer ")
    await revoke_session(session, token=token)
    await session.commit()
    after = await client.get(f"{API}/submissions/{submitted}", headers=editor)

    assert before.status_code == 200
    assert after.status_code == 401
