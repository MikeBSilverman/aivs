"""TLP markings are stamped, not trusted; a contribution inherits its referents' TLP (SF-49)."""

from __future__ import annotations

import uuid

import pytest

from aivs_schemas.enums import TLP, OrgType
from aivs_schemas.tlp import marking_id_for
from tests.conftest import proxy_headers
from tests.unit.contribution_world import (
    LATER,
    STAMP,
    distribute,
    file,
    opinion_about,
    seed,
    submit_and_validate,
    vulnerability_raw,
)

pytestmark = pytest.mark.db


@pytest.fixture
async def world(make_org, make_cert, make_circle, make_collection, join_circle, isac, isac_org):
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    await join_circle(member, circle)
    elsewhere = await make_circle("red-room")
    _isac_org, editor = isac
    return {
        "circle": circle,
        "collection": collection,
        "elsewhere": elsewhere,
        "member": member,
        "pem": pem,
        "editor": editor,
        "isac_org": isac_org,
    }


def finding(**extra: object) -> dict:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "name": "A finding",
        **extra,
    }


async def delivered_markings(client, world, tlp: str, *, objects) -> list[str] | int:
    filed = await file(client, world["pem"], objects, tlp=tlp)
    assert filed.status_code == 201, filed.text
    validated = await submit_and_validate(client, world["pem"], filed.json()["id"], world["editor"])
    assert validated.status_code == 200, validated.text
    distributed = await distribute(client, filed.json()["id"], world["editor"], world["circle"])
    if distributed.status_code != 200:
        return distributed.status_code
    feed = await client.get(
        f"/taxii2/aivs/collections/{world['collection'].id}/objects/",
        headers=proxy_headers(world["pem"]),
    )
    return feed.json()["objects"][0]["object_marking_refs"]


# ---------------------------------------------------------------------------
# Stamped at distribution
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-49")
@pytest.mark.parametrize("tlp", [TLP.AMBER, TLP.AMBER_STRICT])
async def test_every_distributed_object_carries_its_submissions_tlp_marking(client, world, tlp):
    assert await delivered_markings(client, world, tlp.value, objects=[finding()]) == [
        marking_id_for(tlp)
    ]


@pytest.mark.requirement("SF-49")
async def test_an_object_marked_with_a_different_tlp_is_refused_at_distribution(client, world):
    """Marked CLEAR inside an AMBER submission: the server will not choose for it."""
    clear = finding(object_marking_refs=[marking_id_for(TLP.CLEAR)])

    assert await delivered_markings(client, world, "amber", objects=[clear]) == 409


@pytest.mark.requirement("SF-49")
async def test_an_object_already_marked_with_the_same_tlp_is_distributed(client, world):
    same = finding(object_marking_refs=[marking_id_for(TLP.AMBER)])

    assert await delivered_markings(client, world, "amber", objects=[same]) == [
        marking_id_for(TLP.AMBER)
    ]


# ---------------------------------------------------------------------------
# A contribution inherits its referents' TLP
# ---------------------------------------------------------------------------
async def strict_record(session, world, circle_key: str, tlp: TLP) -> str:
    target = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session,
        world["isac_org"],
        vulnerability_raw(target, cve_status="published"),
        circle=world[circle_key],
        tlp=tlp,
    )
    return target


@pytest.mark.requirement("SF-49")
async def test_a_looser_opinion_on_a_visible_stricter_object_is_refused_at_ingest(
    client, session, world
):
    target = await strict_record(session, world, "circle", TLP.AMBER_STRICT)

    refused = await file(client, world["pem"], [opinion_about(target)], tlp="clear")

    assert refused.status_code == 400
    assert "looser than objects it references" in refused.json()["title"]


@pytest.mark.requirement("SF-49")
async def test_an_opinion_at_its_referents_tlp_is_accepted(client, session, world):
    target = await strict_record(session, world, "circle", TLP.AMBER_STRICT)

    accepted = await file(client, world["pem"], [opinion_about(target)], tlp="amber_strict")

    assert accepted.status_code == 201, accepted.text


@pytest.mark.requirement("SF-49")
async def test_a_stricter_referent_the_member_cannot_see_passes_ingest_and_is_refused_at_validate(
    client, session, world, make_org
):
    """Refusing at ingest would confirm the unseen object exists and how it is
    marked; the ISAC refuses it at validate instead, from its view of everything
    -- not the editor's own circles, which the referent never reached."""
    third = await make_org("third-bank", org_type=OrgType.GSIB)
    target = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session,
        third,
        vulnerability_raw(target, cve_status="published"),
        circle=world["elsewhere"],
        tlp=TLP.RED,
    )

    filed = await file(client, world["pem"], [opinion_about(target)], tlp="amber")
    assert filed.status_code == 201, filed.text
    validated = await submit_and_validate(client, world["pem"], filed.json()["id"], world["editor"])

    assert validated.status_code == 409
    assert "looser than objects it references" in validated.json()["title"]


async def tightened_after_validation(client, session, world, tlp: str):
    """An opinion validated on an AMBER record, then an AMBER+STRICT version is distributed.

    Returns the distribution's response: the referent changed between the
    editor's check and publication, and distribution is the last place to see it.
    """
    target = await strict_record(session, world, "circle", TLP.AMBER)
    filed = await file(client, world["pem"], [opinion_about(target)], tlp=tlp)
    assert filed.status_code == 201, filed.text
    validated = await submit_and_validate(client, world["pem"], filed.json()["id"], world["editor"])
    assert validated.status_code == 200, validated.text
    await seed(
        session,
        world["isac_org"],
        vulnerability_raw(target, cve_status="published", modified=LATER),
        circle=world["circle"],
        tlp=TLP.AMBER_STRICT,
    )
    return await distribute(client, filed.json()["id"], world["editor"], world["circle"])


@pytest.mark.requirement("SF-49")
async def test_a_contribution_its_referent_has_since_outgrown_is_refused_at_distribution(
    client, session, world
):
    """Validated AMBER on an AMBER record; the record is AMBER+STRICT by distribution."""
    refused = await tightened_after_validation(client, session, world, "amber")

    assert refused.status_code == 409
    assert "looser than objects it references" in refused.json()["title"]


@pytest.mark.requirement("SF-49")
async def test_a_contribution_as_strict_as_its_strictest_referent_is_distributed(
    client, session, world
):
    """The pair: AMBER+STRICT equals the new version and is stricter than the old one."""
    distributed = await tightened_after_validation(client, session, world, "amber_strict")

    assert distributed.status_code == 200, distributed.text
