"""Only the owner versions an object; `last` is its latest visible version (SF-48, SF-27).

A newer ``modified`` under an id replaces the older one in every consumer's TIP,
so publishing a version of another firm's object is rewriting its content. Each
refusal is paired with the case the rule must allow: the owner's own newer
version, which supersedes the older in the default feed.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.exc import IntegrityError

from aivs_schemas.enums import OrgType
from tests.conftest import proxy_headers
from tests.unit.contribution_world import (
    LATER,
    STAMP,
    distribute,
    file,
    seed,
    submit_and_validate,
    vulnerability_raw,
)

pytestmark = pytest.mark.db


def finding(stix_id: str, *, modified: str, name: str) -> dict:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id,
        "created": STAMP,
        "modified": modified,
        "name": name,
    }


@pytest.fixture
async def world(make_org, make_cert, make_circle, make_collection, join_circle, isac):
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    orgs = {}
    for slug in ("meridian-global", "atlantic-clearing"):
        org = await make_org(slug, org_type=OrgType.GSIB)
        pem, _ = await make_cert(org)
        await join_circle(org, circle)
        orgs[slug] = (org, pem)
    _isac_org, editor = isac
    return {"circle": circle, "collection": collection, "editor": editor, **orgs}


async def filed_and_validated(client, pem, editor, objects, *, sender=None):
    filed = await file(client, pem, objects)
    assert filed.status_code == 201, filed.text
    return filed.json()["id"], await submit_and_validate(
        client, pem, filed.json()["id"], editor, sender=sender
    )


async def feed_names(client, world, pem, **params: str):
    response = await client.get(
        f"/taxii2/aivs/collections/{world['collection'].id}/objects/",
        params=params,
        headers=proxy_headers(pem),
    )
    assert response.status_code == 200, response.text
    return sorted(obj["name"] for obj in response.json().get("objects", []))


@pytest.mark.requirement("SF-48")
async def test_a_newer_version_of_another_firms_object_is_refused_at_validate(client, world):
    shared = f"vulnerability--{uuid.uuid4()}"
    _owner, owner_pem = world["meridian-global"]
    _other, other_pem = world["atlantic-clearing"]
    first, validated = await filed_and_validated(
        client, owner_pem, world["editor"], [finding(shared, modified=STAMP, name="owner's")]
    )
    assert validated.status_code == 200
    assert (await distribute(client, first, world["editor"], world["circle"])).status_code == 200

    _second, refused = await filed_and_validated(
        client, other_pem, world["editor"], [finding(shared, modified=LATER, name="takeover")]
    )

    assert refused.status_code == 409
    assert shared in refused.json()["title"]


@pytest.mark.requirement("SF-48")
async def test_the_owners_own_newer_version_supersedes_the_older_in_the_default_feed(client, world):
    shared = f"vulnerability--{uuid.uuid4()}"
    _owner, pem = world["meridian-global"]
    for modified, name in ((STAMP, "first version"), (LATER, "second version")):
        submission, validated = await filed_and_validated(
            client, pem, world["editor"], [finding(shared, modified=modified, name=name)]
        )
        assert validated.status_code == 200, validated.text
        distributed = await distribute(client, submission, world["editor"], world["circle"])
        assert distributed.status_code == 200, distributed.text

    assert await feed_names(client, world, pem) == ["second version"]
    assert await feed_names(client, world, pem, **{"match[version]": "all"}) == [
        "first version",
        "second version",
    ]


@pytest.mark.requirement("SF-48")
async def test_a_takeover_validated_before_the_owner_distributed_is_refused_at_distribution(
    client, world
):
    """Validation passed because nobody had distributed the id yet; by the time the
    taker is distributed, someone has. The last check is the one that holds."""
    shared = f"vulnerability--{uuid.uuid4()}"
    _owner, owner_pem = world["meridian-global"]
    _other, other_pem = world["atlantic-clearing"]
    taker, taker_validated = await filed_and_validated(
        client, other_pem, world["editor"], [finding(shared, modified=LATER, name="takeover")]
    )
    owner, owner_validated = await filed_and_validated(
        client, owner_pem, world["editor"], [finding(shared, modified=STAMP, name="owner's")]
    )
    assert taker_validated.status_code == owner_validated.status_code == 200
    assert (await distribute(client, owner, world["editor"], world["circle"])).status_code == 200

    refused = await distribute(client, taker, world["editor"], world["circle"])

    assert refused.status_code == 409
    assert await feed_names(client, world, owner_pem) == ["owner's"]


@pytest.mark.requirement("SF-27")
async def test_last_is_the_newest_version_the_caller_may_see_not_the_newest_stored(
    client, session, world, make_circle, make_collection, join_circle, make_org, make_cert, isac_org
):
    """The newest version went only to a circle the reader is not in. The reader
    still gets the version it may see as ``last`` -- an empty answer would tell it
    a newer one exists and is being withheld."""
    shared = f"vulnerability--{uuid.uuid4()}"
    inner = await make_circle("inner-circle")
    _reader, reader_pem = world["meridian-global"]
    insider = await make_org("insider-bank", org_type=OrgType.GSIB)
    insider_pem, _ = await make_cert(insider)
    await join_circle(insider, world["circle"])
    await join_circle(insider, inner)
    inner_collection = await make_collection(inner)
    older = vulnerability_raw(shared, cve_status="published", modified=STAMP)
    newer = vulnerability_raw(shared, cve_status="published", modified=LATER, name="withheld")
    await seed(session, isac_org, older, circle=world["circle"])
    await seed(session, isac_org, newer, circle=inner)

    assert await feed_names(client, world, reader_pem) == ["The ISAC's record"]
    inner_feed = await client.get(
        f"/taxii2/aivs/collections/{inner_collection.id}/objects/",
        headers=proxy_headers(insider_pem),
    )
    assert [obj["name"] for obj in inner_feed.json()["objects"]] == ["withheld"]


# ---------------------------------------------------------------------------
# The ISAC's automation is the ISAC
# ---------------------------------------------------------------------------
@pytest.fixture
async def automation(make_org, make_cert):
    org = await make_org("isac-automation", org_type=OrgType.AUTOMATION)
    pem, _ = await make_cert(org)
    return org, pem


@pytest.mark.requirement("SF-48")
async def test_the_isacs_automation_versions_the_isacs_record(
    client, session, world, isac_org, automation
):
    """What the KEV enrichment does: a newer version of the ISAC's canonical record."""
    record = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session, isac_org, vulnerability_raw(record, cve_status="published"), circle=world["circle"]
    )
    _org, pem = automation

    _id, validated = await filed_and_validated(
        client,
        pem,
        world["editor"],
        [finding(record, modified=LATER, name="with KEV dates")],
        sender=world["editor"],
    )

    assert validated.status_code == 200, validated.text


@pytest.mark.requirement("SF-48")
async def test_the_isacs_automation_cannot_version_a_members_object(client, world, automation):
    shared = f"vulnerability--{uuid.uuid4()}"
    _owner, owner_pem = world["meridian-global"]
    first, validated = await filed_and_validated(
        client, owner_pem, world["editor"], [finding(shared, modified=STAMP, name="member's")]
    )
    assert validated.status_code == 200
    assert (await distribute(client, first, world["editor"], world["circle"])).status_code == 200
    _org, pem = automation

    _id, refused = await filed_and_validated(
        client,
        pem,
        world["editor"],
        [finding(shared, modified=LATER, name="automation's")],
        sender=world["editor"],
    )

    assert refused.status_code == 409
    assert shared in refused.json()["title"]


@pytest.mark.requirement("SF-48")
async def test_a_kev_version_supersedes_the_isacs_record_in_the_default_feed(
    client, session, world, isac_org, automation
):
    """The automation's version and the ISAC's are one owner's, so `last` is one row.

    Resolved per raw submitting organisation, the feed served both as "last",
    and a TIP saw two current versions of the ISAC's canonical record.
    """
    record = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session, isac_org, vulnerability_raw(record, cve_status="published"), circle=world["circle"]
    )
    _org, pem = automation
    submission, validated = await filed_and_validated(
        client,
        pem,
        world["editor"],
        [finding(record, modified=LATER, name="with KEV dates")],
        sender=world["editor"],
    )
    assert validated.status_code == 200, validated.text
    distributed = await distribute(client, submission, world["editor"], world["circle"])
    assert distributed.status_code == 200, distributed.text

    _reader, reader_pem = world["meridian-global"]
    assert await feed_names(client, world, reader_pem) == ["with KEV dates"]
    assert await feed_names(client, world, reader_pem, **{"match[version]": "all"}) == [
        "The ISAC's record",
        "with KEV dates",
    ]


def relationship(stix_id: str, *, modified: str, source: str, target: str, **extra: Any) -> dict:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": stix_id,
        "created": STAMP,
        "modified": modified,
        "relationship_type": "related-to",
        "source_ref": source,
        "target_ref": target,
        **extra,
    }


@pytest.mark.requirement("SF-48")
async def test_a_relationship_is_owned_like_anything_else(client, world):
    """Another firm's relationship id is not free to version; one's own is.

    The exemption that let any organisation publish a newer version under
    another's relationship id let a member revoke a peer's statement in every
    TIP. Relating someone else's objects needs no exemption: it is a new id.
    """
    _owner, owner_pem = world["meridian-global"]
    _other, other_pem = world["atlantic-clearing"]
    a, b = (f"vulnerability--{uuid.uuid4()}" for _ in range(2))
    rel_id = f"relationship--{uuid.uuid4()}"
    objects = [
        finding(a, modified=STAMP, name="a"),
        finding(b, modified=STAMP, name="b"),
        relationship(rel_id, modified=STAMP, source=a, target=b),
    ]
    first, validated = await filed_and_validated(client, owner_pem, world["editor"], objects)
    assert validated.status_code == 200, validated.text
    assert (await distribute(client, first, world["editor"], world["circle"])).status_code == 200

    revoked = relationship(rel_id, modified=LATER, source=a, target=b, revoked=True)
    _taken, refused = await filed_and_validated(client, other_pem, world["editor"], [revoked])
    _own, accepted = await filed_and_validated(client, owner_pem, world["editor"], [revoked])

    assert refused.status_code == 409
    assert rel_id in refused.json()["title"]
    assert accepted.status_code == 200, accepted.text


@pytest.mark.requirement("SF-48")
async def test_an_instance_has_one_automation_organisation(make_org, automation):
    """Ownership counts the automation organisation as the ISAC by type, so there is one.

    A second, enrolled from the portal like any organisation, would be a second
    identity able to version the ISAC's canonical records. The pair is the
    ``automation`` fixture itself, which enrolled the first.
    """
    with pytest.raises(IntegrityError, match="uq_organizations_one_automation"):
        await make_org("second-robot", org_type=OrgType.AUTOMATION)
