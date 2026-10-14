"""Abuse of the contribution path, as the sequence an adversary would run.

Two adversaries Phase E introduces (docs/threat-model.md, "Cross-cutting:
contributions about another party's object"): a vendor that
wants a member's workaround for its product to stop circulating, and a
contributor that wants its own content to stand where another firm's does. Both
work by publishing a newer version of an object they do not own, which every
consumer's TIP would take as the current one. Each scenario asserts the step
that refuses it, and that the owner's content is still what members receive.
"""

from __future__ import annotations

import uuid

import pytest

from aivs_schemas.enums import OrgType
from tests.conftest import proxy_headers
from tests.unit.contribution_world import (
    LATER,
    STAMP,
    course_of_action_about,
    distribute,
    file,
    opinion_about,
    submit_and_validate,
)

pytestmark = [pytest.mark.db, pytest.mark.abuse]


@pytest.fixture
async def world(make_org, make_cert, make_circle, make_collection, join_circle, isac):
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    member_pem, _ = await make_cert(member)
    vendor = await make_org("acme-software", org_type=OrgType.VENDOR)
    vendor_pem, _ = await make_cert(vendor)
    rival = await make_org("atlantic-clearing", org_type=OrgType.GSIB)
    rival_pem, _ = await make_cert(rival)
    for org in (member, vendor, rival):
        await join_circle(org, circle)
    _isac_org, editor = isac
    return {
        "circle": circle,
        "collection": collection,
        "member_pem": member_pem,
        "vendor_pem": vendor_pem,
        "rival_pem": rival_pem,
        "editor": editor,
    }


async def published(client, world, pem, objects) -> str:
    filed = await file(client, pem, objects)
    assert filed.status_code == 201, filed.text
    validated = await submit_and_validate(client, pem, filed.json()["id"], world["editor"])
    assert validated.status_code == 200, validated.text
    distributed = await distribute(client, filed.json()["id"], world["editor"], world["circle"])
    assert distributed.status_code == 200, distributed.text
    return filed.json()["id"]


async def feed(client, world, pem) -> list[dict]:
    response = await client.get(
        f"/taxii2/aivs/collections/{world['collection'].id}/objects/",
        headers=proxy_headers(pem),
    )
    return list(response.json().get("objects", []))


@pytest.mark.requirement("SF-48")
async def test_a_vendor_cannot_mark_a_members_workaround_fixed_by_versioning_it(client, world):
    """The vendor files a newer version of the member's workaround saying it is no
    longer needed. Refused at validate; the vendor may say so in an opinion, which
    sits beside the workaround and replaces nothing."""
    vulnerability = f"vulnerability--{uuid.uuid4()}"
    workaround, relationship = course_of_action_about(vulnerability)
    await published(client, world, world["member_pem"], [workaround, relationship])

    rewritten = {
        **workaround,
        "modified": LATER,
        "name": "Not needed: fixed in 4.2.1",
        "revoked": True,
    }
    filed = await file(client, world["vendor_pem"], [rewritten])
    assert filed.status_code == 201, "ingest cannot refuse: it would confirm whose id it is"
    refused = await submit_and_validate(
        client, world["vendor_pem"], filed.json()["id"], world["editor"]
    )
    assert refused.status_code == 409
    assert workaround["id"] in refused.json()["title"]

    await published(
        client, world, world["vendor_pem"], [opinion_about(workaround["id"], opinion="disagree")]
    )
    delivered = {obj["id"]: obj for obj in await feed(client, world, world["member_pem"])}
    assert delivered[workaround["id"]]["name"] == workaround["name"]
    assert "revoked" not in delivered[workaround["id"]]


@pytest.mark.requirement("SF-48")
async def test_a_contributor_cannot_stand_its_finding_in_another_firms_place(client, world):
    """The rival re-files the member's finding id with a later ``modified`` twice:
    once after the member distributed (refused at validate), once raced ahead of
    the member's distribution (validated, then refused at distribution)."""
    finding = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "name": "Member's finding",
    }
    raced = await file(
        client, world["rival_pem"], [{**finding, "modified": LATER, "name": "Raced"}]
    )
    raced_validated = await submit_and_validate(
        client, world["rival_pem"], raced.json()["id"], world["editor"]
    )
    assert raced_validated.status_code == 200, "nobody had distributed the id yet"

    await published(client, world, world["member_pem"], [finding])

    after = await file(
        client, world["rival_pem"], [{**finding, "modified": LATER, "name": "After"}]
    )
    refused_at_validate = await submit_and_validate(
        client, world["rival_pem"], after.json()["id"], world["editor"]
    )
    refused_at_distribution = await distribute(
        client, raced.json()["id"], world["editor"], world["circle"]
    )

    assert refused_at_validate.status_code == 409
    assert refused_at_distribution.status_code == 409
    names = [obj["name"] for obj in await feed(client, world, world["member_pem"])]
    assert names == ["Member's finding"]
