"""Rejection paths for inbound member content.

Every branch here decides whether something a member sent is stored and then
redistributed to a whole circle. They are all reachable from a single POST, and
each one previously had no test — so the module's promise ("a malformed bundle
is rejected while the submitter is still editing a draft") rested on code that
had never run.

The assertions check the *message* as well as the status, because these errors
are the only guidance a submitter gets. A 400 that does not name the offending
object is a support ticket.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import OrgType
from aivs_server.db.models import StixObject
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1/submissions"
STAMP = "2026-08-01T00:00:00.000Z"


@pytest.fixture
async def member(make_org, make_cert):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    return org, pem


def object_bundle(*objects: dict) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(objects)}


def vulnerability(**overrides: object) -> dict:
    base = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "name": "A finding",
    }
    base.update(overrides)
    return base


async def post(client, pem, bundle: dict, **extra: object):
    payload = {
        "title": "Inbound validation probe",
        "discovery_scope": "ai_system",
        "bundle": bundle,
    }
    payload.update(extra)
    return await client.post(API, json=payload, headers=proxy_headers(pem))


# ---------------------------------------------------------------------------
# Object identity and shape
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("bad_id", "reason"),
    [
        (None, "missing"),
        ("no-double-dash", "malformed"),
        (12345, "malformed"),
    ],
)
async def test_a_malformed_object_id_is_refused(client, member, bad_id, reason):
    """An object without a usable identity cannot be versioned or referenced."""
    _org, pem = member
    obj = vulnerability()
    if bad_id is None:
        del obj["id"]
    else:
        obj["id"] = bad_id

    response = await post(client, pem, object_bundle(obj))
    assert response.status_code == 400
    assert "id" in response.text


async def test_a_missing_type_is_refused(client, member):
    _org, pem = member
    obj = vulnerability()
    del obj["type"]

    response = await post(client, pem, object_bundle(obj))
    assert response.status_code == 400
    assert "type" in response.text


async def test_an_oversized_type_is_refused(client, member):
    """Bounded at ingest so the error names the object, not the column."""
    _org, pem = member
    response = await post(client, pem, object_bundle(vulnerability(type="x" * 100)))
    assert response.status_code == 400
    # The docstring's claim, asserted: storage would also refuse it, as a
    # generic 400 that names nothing. Found by a mutation that dropped the
    # ingest bound and left this test green.
    assert "longer than" in response.json()["title"]


async def test_a_foreign_spec_version_is_refused(client, member):
    """AIVS stores STIX 2.1 only, and says so rather than failing a constraint."""
    _org, pem = member
    response = await post(client, pem, object_bundle(vulnerability(spec_version="2.0")))
    assert response.status_code == 400
    assert "2.1" in response.text


async def test_a_cyber_observable_is_refused_for_what_it_is(client, member, session):
    """Refused by type, not for the ``created`` an observable never has."""
    _org, pem = member
    artifact = {
        "type": "artifact",
        "spec_version": "2.1",
        "id": f"artifact--{uuid.uuid4()}",
        "mime_type": "text/plain",
        "payload_bin": "aGVsbG8=",
    }

    response = await post(client, pem, object_bundle(vulnerability(), artifact))

    assert response.status_code == 400
    assert "cyber observables are not accepted" in response.text
    assert artifact["id"] in response.text
    assert (await session.scalars(select(StixObject))).all() == []


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------
async def test_a_missing_created_is_refused(client, member):
    """Inventing a timestamp would silently corrupt an object's ordering."""
    _org, pem = member
    obj = vulnerability()
    del obj["created"]
    del obj["modified"]

    response = await post(client, pem, object_bundle(obj))
    assert response.status_code == 400
    assert "created" in response.text


@pytest.mark.parametrize("value", ["not-a-timestamp", "2026-13-45T99:99:99Z", 1234567890])
async def test_an_unparseable_timestamp_is_refused(client, member, value):
    _org, pem = member
    response = await post(client, pem, object_bundle(vulnerability(created=value)))
    assert response.status_code == 400


async def test_a_timestamp_without_a_timezone_is_refused(client, member):
    """A naive timestamp would be assumed UTC, which is a guess about ordering."""
    _org, pem = member
    response = await post(client, pem, object_bundle(vulnerability(created="2026-08-01T00:00:00")))
    assert response.status_code == 400
    assert "timezone" in response.text


async def test_modified_defaults_to_created_when_absent(client, member):
    """Marking definitions and meta objects legitimately carry no `modified`."""
    _org, pem = member
    obj = vulnerability()
    del obj["modified"]

    response = await post(client, pem, object_bundle(obj))
    assert response.status_code == 201


# ---------------------------------------------------------------------------
# Bundle-level
# ---------------------------------------------------------------------------
async def test_the_same_version_twice_in_one_bundle_is_refused(client, member):
    """Reported as the client error it is, not surfaced as a constraint violation."""
    _org, pem = member
    stix_id = f"vulnerability--{uuid.uuid4()}"
    response = await post(
        client,
        pem,
        object_bundle(vulnerability(id=stix_id), vulnerability(id=stix_id)),
    )
    assert response.status_code == 400
    assert "more than once" in response.text


async def test_a_bundle_whose_objects_are_not_objects_is_refused(client, member):
    _org, pem = member
    bundle = object_bundle()
    bundle["objects"] = ["not-an-object"]

    response = await post(client, pem, bundle)
    assert response.status_code == 400


async def test_a_bundle_with_a_non_list_objects_key_is_refused(client, member):
    _org, pem = member
    bundle = object_bundle()
    bundle["objects"] = {"not": "a list"}

    response = await post(client, pem, bundle)
    assert response.status_code == 400


async def test_an_empty_bundle_is_accepted_but_cannot_be_distributed(
    client, member, isac_and_circle
):
    """An empty bundle is legal STIX; it simply carries nothing to release."""
    _org, pem = member
    created = await post(client, pem, object_bundle())
    assert created.status_code == 201

    isac_headers, circle = isac_and_circle
    submission_id = created.json()["id"]
    await client.post(f"{API}/{submission_id}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{submission_id}/validate", json={}, headers=isac_headers)

    response = await client.post(
        f"{API}/{submission_id}/distribute",
        json={"circle_ids": [str(circle.id)]},
        headers=isac_headers,
    )
    assert response.status_code == 409
    assert "no STIX objects" in response.text


# ---------------------------------------------------------------------------
# Indexed-field extraction
# ---------------------------------------------------------------------------
async def test_a_cve_reference_is_extracted_for_search(client, member, session):
    """Extraction reads external_references, which members legitimately supply."""
    _org, pem = member
    created = await post(
        client,
        pem,
        object_bundle(
            vulnerability(
                external_references=[
                    {"source_name": "cve", "external_id": "CVE-2026-12345"},
                ]
            )
        ),
    )
    assert created.status_code == 201

    stored = (
        await session.execute(
            select(StixObject).where(StixObject.submission_id == uuid.UUID(created.json()["id"]))
        )
    ).scalar_one()
    assert stored.cve_id == "CVE-2026-12345"


async def test_a_malformed_external_reference_does_not_break_ingest(client, member):
    """A wrong extracted value is worse than a missing one, so it is skipped."""
    _org, pem = member
    response = await post(
        client,
        pem,
        object_bundle(
            vulnerability(
                external_references=[
                    "not-a-dict",
                    {"source_name": "vendor", "url": "https://example.test"},
                    {"source_name": "cve"},
                ]
            )
        ),
    )
    assert response.status_code == 201


async def test_a_long_name_is_truncated_rather_than_refused(client, member, session):
    """`name` is a search convenience; `raw` keeps the full value.

    Refusing a vulnerability report over a long title would be the wrong trade.
    """
    _org, pem = member
    long_name = "N" * 500
    created = await post(client, pem, object_bundle(vulnerability(name=long_name)))
    assert created.status_code == 201

    stored = (
        await session.execute(
            select(StixObject).where(StixObject.submission_id == uuid.UUID(created.json()["id"]))
        )
    ).scalar_one()
    assert len(stored.name) == 300
    assert stored.raw["name"] == long_name, "the canonical form keeps everything"


@pytest.fixture
async def isac_and_circle(isac, make_circle, make_collection):
    circle = await make_circle("section9")
    await make_collection(circle)
    return isac[1], circle
