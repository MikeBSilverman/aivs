"""Duplicate candidates at intake are scoped to what the caller could already see (SF-47).

The pair that matters: the same CVE filed by another member is a candidate when
it was distributed to the caller, and absent when it was not -- while the
ISAC's reviewers see both.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1/submissions"
STAMP = "2026-08-01T00:00:00.000Z"
CVE = "CVE-2026-50001"


def vulnerability(
    *, purl: str | None = None, cwe: str | None = None, cve: str | None = CVE
) -> dict[str, Any]:
    product: dict[str, Any] = {"vendor": "Acme", "product": "Gateway"}
    if purl:
        product["purl"] = purl
    references = [{"source_name": "cwe", "external_id": cwe}] if cwe else []
    body: dict[str, Any] = {
        "extension_type": "property-extension",
        "aivs_schema_version": "2.0",
        "discovery_scope": "own_product",
        "cve_status": "assigned" if cve else "pre-cve",
        "affected_products": [product],
    }
    if cve:
        body["cve_id"] = cve
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "name": "Gateway auth bypass",
        "external_references": references,
        "extensions": {AIVS_INTEL_EXTENSION_ID: body},
    }


async def _file(client, pem, obj) -> str:
    created = await client.post(
        API,
        json={
            "title": "Duplicate check",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [obj]},
        },
        headers=proxy_headers(pem),
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


async def _distribute(client, pem, isac_headers, submission_id, circle) -> None:
    await client.post(f"{API}/{submission_id}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{submission_id}/validate", json={}, headers=isac_headers)
    distributed = await client.post(
        f"{API}/{submission_id}/distribute",
        json={"circle_ids": [str(circle.id)]},
        headers=isac_headers,
    )
    assert distributed.status_code == 200, distributed.text


@pytest.fixture
async def world(client, isac, make_org, make_cert, make_circle, join_circle):
    _org, isac_headers = isac
    orgs = {}
    for name in ("filer", "peer", "stranger"):
        org = await make_org(f"dup-{name}")
        orgs[name] = (org, (await make_cert(org))[0])
    shared = await make_circle("dup-shared")
    private = await make_circle("dup-private")
    await join_circle(orgs["filer"][0], shared)
    await join_circle(orgs["peer"][0], shared)
    await join_circle(orgs["stranger"][0], private)

    received = vulnerability(purl="pkg:npm/acme-gateway@4.2.0", cwe="CWE-287")
    unseen = vulnerability()
    peer_id = await _file(client, orgs["peer"][1], received)
    await _distribute(client, orgs["peer"][1], isac_headers, peer_id, shared)
    stranger_id = await _file(client, orgs["stranger"][1], unseen)
    await _distribute(client, orgs["stranger"][1], isac_headers, stranger_id, private)
    earlier_own = await _file(client, orgs["filer"][1], vulnerability(cve=None, cwe="CWE-287"))

    new = await _file(
        client, orgs["filer"][1], vulnerability(purl="pkg:npm/acme-gateway@4.2.0", cwe="CWE-287")
    )
    return {
        "url": f"{API}/{new}/duplicates",
        "filer": proxy_headers(orgs["filer"][1]),
        "isac": isac_headers,
        "received": received["id"],
        "unseen": unseen["id"],
        "earlier_own": earlier_own,
    }


def _by_key(response) -> set[tuple[str, str]]:
    return {(c["match_on"], c["stix_id"]) for c in response.json()}


@pytest.mark.requirement("SF-47")
async def test_a_member_is_shown_only_duplicates_it_could_already_see(client, world):
    found = await client.get(world["url"], headers=world["filer"])
    assert found.status_code == 200, found.text
    stix_ids = {c["stix_id"] for c in found.json()}
    assert world["received"] in stix_ids
    assert world["unseen"] not in stix_ids


@pytest.mark.requirement("SF-47")
async def test_the_isac_compares_against_everything(client, world):
    found = await client.get(world["url"], headers=world["isac"])
    stix_ids = {c["stix_id"] for c in found.json()}
    assert {world["received"], world["unseen"]} <= stix_ids
    assert all(c["submission_id"] for c in found.json())


async def test_each_candidate_says_which_key_matched(client, world):
    found = _by_key(await client.get(world["url"], headers=world["filer"]))
    assert ("cve_id", world["received"]) in found
    assert ("purl", world["received"]) in found
    assert ("cwe", world["received"]) in found


async def test_only_the_callers_own_records_are_linked(client, world):
    candidates = (await client.get(world["url"], headers=world["filer"])).json()
    links = {c["submission_id"] for c in candidates if c["submission_id"]}
    assert links == {world["earlier_own"]}
