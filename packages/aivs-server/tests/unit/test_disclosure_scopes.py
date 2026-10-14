"""The two disclosure scopes exist in storage and are admitted by nothing.

``disclosed_third_party`` and ``coordinated_disclosure`` are Postgres enum values
from Phase D, and become fileable only in Phase E, with the rule that checks the
*target* vulnerability's state. Until then every way in -- the API body, the
portal form, a PATCH, the bundle's own extension, the service itself -- refuses
them exactly as it refuses a value nobody has heard of. A refusal that differed
would announce a capability that does not exist.

Each surface is tested in pairs: the reserved value refused like an unknown one,
and every accepted value still filed.
"""

from __future__ import annotations

import re
import uuid

import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import ACCEPTED_DISCOVERY_SCOPES, DiscoveryScope, OrgType
from aivs_schemas.extension.builders import AIVS_EXTENSION_ID
from aivs_schemas.models import DISCOVERY_SCOPE_REFUSAL
from aivs_server.db.models import StixObject, Submission
from aivs_server.services.submissions import (
    SubmissionError,
    create_submission,
    update_submission,
)
from tests.conftest import proxy_headers
from tests.unit.test_portal import bundle as portal_bundle
from tests.unit.test_portal import csrf_of, make_operator, sign_in

pytestmark = pytest.mark.db

API = "/api/v1/submissions"
STAMP = "2026-08-01T00:00:00.000Z"
UNKNOWN = "never_heard_of_it"

ACCEPTED = sorted(ACCEPTED_DISCOVERY_SCOPES)
RESERVED = sorted(set(DiscoveryScope) - ACCEPTED_DISCOVERY_SCOPES)


@pytest.fixture
async def member(make_org, make_cert):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    return org, pem


def vulnerability(scope: str | None = None) -> dict:
    obj: dict = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "name": "A finding",
    }
    if scope is not None:
        obj["extensions"] = {
            AIVS_EXTENSION_ID: {
                "extension_type": "property-extension",
                "aivs_schema_version": "1.0",
                "discovery_scope": scope,
                "cve_status": "pre-cve",
                "affected_products": [{"vendor": "Acme", "product": "Gateway"}],
            }
        }
    return obj


def stix_bundle(*objects: dict) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(objects)}


async def file(client, pem, scope: str, objects: tuple[dict, ...] = ()):
    payload = {
        "title": "Disclosure scope probe",
        "discovery_scope": scope,
        "bundle": stix_bundle(*(objects or (vulnerability(),))),
    }
    return await client.post(API, json=payload, headers=proxy_headers(pem))


async def submission_count(session) -> int:
    return await session.scalar(select(func.count()).select_from(Submission))


# ---------------------------------------------------------------------------
# API: the request body
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("scope", ACCEPTED, ids=str)
async def test_the_api_files_every_accepted_scope(client, member, scope):
    _org, pem = member

    response = await file(client, pem, scope.value)

    assert response.status_code == 201, response.text
    assert response.json()["discovery_scope"] == scope.value


@pytest.mark.parametrize("reserved", RESERVED, ids=str)
async def test_the_api_refuses_a_reserved_scope_exactly_as_an_unknown_one(
    client, member, session, reserved
):
    _org, pem = member

    refused = await file(client, pem, reserved.value)
    unknown = await file(client, pem, UNKNOWN)

    assert refused.status_code == unknown.status_code == 400
    assert refused.json() == unknown.json()
    assert DISCOVERY_SCOPE_REFUSAL in refused.text
    assert await submission_count(session) == 0


@pytest.mark.parametrize("reserved", RESERVED, ids=str)
async def test_an_edit_cannot_move_a_draft_into_a_reserved_scope(client, member, reserved):
    _org, pem = member
    created = await file(client, pem, DiscoveryScope.AI_SYSTEM.value)
    draft = f"{API}/{created.json()['id']}"

    refused = await client.patch(
        draft, json={"discovery_scope": reserved.value}, headers=proxy_headers(pem)
    )
    unknown = await client.patch(
        draft, json={"discovery_scope": UNKNOWN}, headers=proxy_headers(pem)
    )
    current = await client.get(draft, headers=proxy_headers(pem))

    assert refused.status_code == unknown.status_code == 400
    assert refused.json() == unknown.json()
    assert current.json()["discovery_scope"] == DiscoveryScope.AI_SYSTEM.value


async def test_an_edit_can_move_a_draft_between_accepted_scopes(client, member):
    _org, pem = member
    created = await file(client, pem, DiscoveryScope.AI_SYSTEM.value)
    draft = f"{API}/{created.json()['id']}"

    moved = await client.patch(
        draft, json={"discovery_scope": DiscoveryScope.OWN_ESTATE.value}, headers=proxy_headers(pem)
    )

    assert moved.status_code == 200, moved.text
    assert moved.json()["discovery_scope"] == DiscoveryScope.OWN_ESTATE.value


# ---------------------------------------------------------------------------
# API: the bundle's own extension
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("reserved", RESERVED, ids=str)
async def test_a_bundle_whose_extension_declares_a_reserved_scope_is_refused(
    client, member, session, reserved
):
    _org, pem = member

    probe = vulnerability(reserved.value)
    refused = await file(client, pem, "ai_system", (probe,))
    probe["extensions"][AIVS_EXTENSION_ID]["discovery_scope"] = UNKNOWN
    unknown = await file(client, pem, "ai_system", (probe,))

    assert refused.status_code == unknown.status_code == 400
    assert refused.text.replace(reserved.value, "<v>") == unknown.text.replace(UNKNOWN, "<v>")
    assert await submission_count(session) == 0


@pytest.mark.requirement("SF-24")
async def test_one_object_with_a_refused_scope_refuses_the_whole_bundle(client, member, session):
    """Mixed-scope bundles: nothing is stored, including the object that was fine."""
    _org, pem = member
    objects = (vulnerability("own_product"), vulnerability(RESERVED[0].value))

    response = await file(client, pem, "own_product", objects)

    assert response.status_code == 400
    assert await submission_count(session) == 0
    assert await session.scalar(select(func.count()).select_from(StixObject)) == 0


@pytest.mark.requirement("SF-24")
async def test_a_bundle_whose_objects_all_declare_accepted_scopes_is_stored(
    client, member, session
):
    _org, pem = member
    objects = (vulnerability("own_product"), vulnerability("ai_system"))

    response = await file(client, pem, "own_product", objects)

    assert response.status_code == 201, response.text
    assert await session.scalar(select(func.count()).select_from(StixObject)) == 2


# ---------------------------------------------------------------------------
# Portal: the form
# ---------------------------------------------------------------------------
@pytest.fixture
async def analyst(session, secret_box, make_org, make_cert):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _cert = await make_cert(org)
    operator, secret = await make_operator(session, secret_box, org)
    return operator, secret, pem


async def submit_form(client, pem, scope: str):
    return await client.post(
        "/portal/submit",
        data={
            "title": "Disclosure scope probe",
            "discovery_scope": scope,
            "tlp": "amber",
            "bundle": portal_bundle(),
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )


def form_error(html: str) -> str:
    match = re.search(r'class="notice notice-error">(.*?)</div>', html, re.S)
    assert match, "the form was not re-rendered with an error"
    return match.group(1)


@pytest.mark.parametrize("scope", ACCEPTED, ids=str)
async def test_the_portal_files_every_accepted_scope(client, analyst, scope):
    operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    response = await submit_form(client, pem, scope.value)

    assert response.status_code == 303, response.text


@pytest.mark.parametrize("reserved", RESERVED, ids=str)
async def test_the_portal_refuses_a_reserved_scope_exactly_as_an_unknown_one(
    client, analyst, session, reserved
):
    operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    refused = await submit_form(client, pem, reserved.value)
    unknown = await submit_form(client, pem, UNKNOWN)

    assert refused.status_code == unknown.status_code == 400
    assert form_error(refused.text) == form_error(unknown.text)
    assert await submission_count(session) == 0


# ---------------------------------------------------------------------------
# The service: the one function every writer goes through
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("reserved", RESERVED, ids=str)
async def test_the_service_refuses_a_reserved_scope_from_a_caller_that_skips_the_models(
    session, isac_ctx, reserved
):
    with pytest.raises(SubmissionError, match="discovery_scope"):
        await create_submission(
            session,
            isac_ctx,
            title="Scripted filing",
            summary=None,
            tlp="amber",
            discovery_scope=reserved,
            distribute_anonymously=False,
            bundle=stix_bundle(vulnerability()),
        )


async def test_the_service_files_an_accepted_scope_from_the_same_caller(session, isac_ctx):
    submission = await create_submission(
        session,
        isac_ctx,
        title="Scripted filing",
        summary=None,
        tlp="amber",
        discovery_scope=DiscoveryScope.OWN_ESTATE,
        distribute_anonymously=False,
        bundle=stix_bundle(vulnerability()),
    )

    assert submission.discovery_scope == DiscoveryScope.OWN_ESTATE


@pytest.mark.parametrize("reserved", RESERVED, ids=str)
async def test_the_service_refuses_an_edit_into_a_reserved_scope(session, isac_ctx, reserved):
    draft = await create_submission(
        session,
        isac_ctx,
        title="Scripted filing",
        summary=None,
        tlp="amber",
        discovery_scope=DiscoveryScope.AI_SYSTEM,
        distribute_anonymously=False,
        bundle=stix_bundle(vulnerability()),
    )

    with pytest.raises(SubmissionError, match="discovery_scope"):
        await update_submission(session, isac_ctx, draft, changes={"discovery_scope": reserved})


async def test_the_service_applies_an_edit_between_accepted_scopes(session, isac_ctx):
    draft = await create_submission(
        session,
        isac_ctx,
        title="Scripted filing",
        summary=None,
        tlp="amber",
        discovery_scope=DiscoveryScope.AI_SYSTEM,
        distribute_anonymously=False,
        bundle=stix_bundle(vulnerability()),
    )

    await update_submission(
        session, isac_ctx, draft, changes={"discovery_scope": DiscoveryScope.OWN_PRODUCT}
    )

    assert draft.discovery_scope == DiscoveryScope.OWN_PRODUCT
