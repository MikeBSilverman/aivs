"""A version is stored at the precision it is advertised at (CLAUDE.md section 5).

TAXII carries milliseconds and `match[version]` compares for exact equality. An
object filed with a sub-millisecond `modified` was stored at microseconds while
the manifest advertised milliseconds, so asking for exactly the version just
advertised matched nothing. Every version test used the `publish` fixture, which
bypasses ingest, so removing the truncation left the whole suite green (M51).
The pair: a microsecond-precise object and a millisecond-precise one are each
found by the version string the manifest gives for it.
"""

from __future__ import annotations

import uuid

import pytest

from aivs_schemas.enums import OrgType
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1"


async def _distribute_object(client, isac_headers, pem, circle, modified: str) -> str:
    stix_id = f"vulnerability--{uuid.uuid4()}"
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": stix_id,
                "created": "2026-08-01T00:00:00.000Z",
                "modified": modified,
                "name": "Version precision",
            }
        ],
    }
    created = await client.post(
        f"{API}/submissions",
        json={"title": "Precision", "discovery_scope": "ai_system", "bundle": bundle},
        headers=proxy_headers(pem),
    )
    assert created.status_code == 201, created.text
    submission = created.json()["id"]
    for verb, headers in (("submit", proxy_headers(pem)), ("validate", isac_headers)):
        step = await client.post(f"{API}/submissions/{submission}/{verb}", json={}, headers=headers)
        assert step.status_code == 200, step.text
    sent = await client.post(
        f"{API}/submissions/{submission}/distribute",
        json={"circle_ids": [str(circle.id)]},
        headers=isac_headers,
    )
    assert sent.status_code == 200, sent.text
    return stix_id


@pytest.mark.parametrize(
    ("filed", "advertised"),
    [
        ("2026-08-01T00:00:00.123456Z", "2026-08-01T00:00:00.123Z"),
        ("2026-08-01T00:00:00.123Z", "2026-08-01T00:00:00.123Z"),
    ],
)
async def test_the_advertised_version_finds_the_object(
    client, isac, make_org, make_cert, make_circle, make_collection, join_circle, filed, advertised
):
    _isac_org, isac_headers = isac
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    await join_circle(member, circle)
    stix_id = await _distribute_object(client, isac_headers, pem, circle, filed)
    base = f"/taxii2/aivs/collections/{collection.id}"

    manifest = await client.get(f"{base}/manifest/", headers=proxy_headers(pem))
    [entry] = [e for e in manifest.json()["objects"] if e["id"] == stix_id]
    found = await client.get(
        f"{base}/objects/{stix_id}/",
        params={"match[version]": entry["version"]},
        headers=proxy_headers(pem),
    )

    assert entry["version"] == advertised
    assert found.status_code == 200
    assert [obj["id"] for obj in found.json()["objects"]] == [stix_id]


@pytest.mark.parametrize("version", ["last", "all"])
async def test_one_version_filed_twice_by_its_owner_is_served_once(
    client, make_org, make_cert, make_circle, make_collection, join_circle, publish, version
):
    """A TIP that resends a whole bundle files the same version in a second
    submission; both copies reach the circle. Objects and the manifest served
    both, while the versions endpoint listed one (review R2-P3)."""
    import datetime as dt  # noqa: PLC0415 - one test

    member = await make_org("resender", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    await join_circle(member, circle)
    stix_id = f"vulnerability--{uuid.uuid4()}"
    modified = dt.datetime(2026, 8, 1, tzinfo=dt.UTC)
    now = dt.datetime.now(dt.UTC)
    for offset in (2, 1):
        await publish(
            member,
            circle,
            stix_id=stix_id,
            modified=modified,
            date_added=now - dt.timedelta(seconds=offset),
        )
    base = f"/taxii2/aivs/collections/{collection.id}"
    query = {"match[id]": stix_id, "match[version]": version}

    objects = await client.get(f"{base}/objects/", params=query, headers=proxy_headers(pem))
    manifest = await client.get(f"{base}/manifest/", params=query, headers=proxy_headers(pem))

    assert objects.status_code == manifest.status_code == 200, objects.text
    assert len(objects.json()["objects"]) == 1
    assert len(manifest.json()["objects"]) == 1
