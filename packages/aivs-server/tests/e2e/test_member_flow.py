"""One member flow, end to end, through nginx.

A member files a finding with its certificate; the ISAC's operator, signed in
through the portal and holding that session as a bearer, validates and
distributes it; the member collects it over TAXII. The middle of the flow is
the pair: the object is absent from the member's feed until it is distributed.
"""

from __future__ import annotations

import uuid

import httpx
import pytest

from tests.e2e.stack import TAXII_ACCEPT, Stack, requires_stack

pytestmark = [pytest.mark.e2e, requires_stack]

API = "/api/v1/submissions"
STAMP = "2026-10-01T00:00:00.000Z"


def finding() -> tuple[str, dict]:
    vulnerability_id = f"vulnerability--{uuid.uuid4()}"
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": vulnerability_id,
                "created": STAMP,
                "modified": STAMP,
                "name": "End-to-end probe finding",
            }
        ],
    }
    return vulnerability_id, bundle


def member_feed(stack: Stack, member: httpx.Client) -> set[str]:
    headers = {"accept": TAXII_ACCEPT}
    collections = member.get("/taxii2/aivs/collections/", headers=headers)
    assert collections.status_code == 200, collections.text
    seen: set[str] = set()
    for collection in collections.json().get("collections", []):
        objects = member.get(
            f"/taxii2/aivs/collections/{collection['id']}/objects/", headers=headers
        )
        assert objects.status_code == 200, objects.text
        seen.update(obj["id"] for obj in objects.json().get("objects", []))
    return seen


def test_a_finding_reaches_the_member_only_once_the_isac_distributes_it(stack, isac_bearer):
    vulnerability_id, bundle = finding()
    with stack.client(stack.member) as member, stack.client(stack.isac) as isac:
        created = member.post(
            API,
            json={
                "title": "End-to-end probe",
                "discovery_scope": "ai_system",
                "tlp": "amber",
                "bundle": bundle,
            },
        )
        assert created.status_code == 201, created.text
        submission = f"{API}/{created.json()['id']}"
        assert member.post(f"{submission}/submit", json={}).status_code == 200

        validated = isac.post(f"{submission}/validate", json={}, headers=isac_bearer)
        assert validated.status_code == 200, validated.text
        assert vulnerability_id not in member_feed(stack, member)

        distributed = isac.post(
            f"{submission}/distribute",
            json={"circle_ids": [stack.raw["circle_id"]]},
            headers=isac_bearer,
        )
        assert distributed.status_code == 200, distributed.text
        assert vulnerability_id in member_feed(stack, member)
