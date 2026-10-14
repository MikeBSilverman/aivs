"""An anonymous submission cannot name its submitter through structure (SF-50).

The pipeline rewrites ``created_by_ref`` and serves everything else verbatim, so
a sighting that says where it was seen, or an opinion that lists its authors,
names the submitter whatever the envelope says. Each refusal is paired with the
same structure where it is legitimate.
"""

from __future__ import annotations

import uuid

import pytest

from aivs_schemas.enums import OrgType
from tests.conftest import proxy_headers
from tests.unit.contribution_world import API, STAMP, file, opinion_about

pytestmark = pytest.mark.db


@pytest.fixture
async def member(make_org, make_cert):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    return org, pem


def sighting(*where: str) -> dict:
    obj: dict = {
        "type": "sighting",
        "spec_version": "2.1",
        "id": f"sighting--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "sighting_of_ref": f"indicator--{uuid.uuid4()}",
    }
    if where:
        obj["where_sighted_refs"] = list(where)
    return obj


def note_by(*authors: str) -> dict:
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": f"note--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "content": "Seen in our estate this morning.",
        "object_refs": [f"indicator--{uuid.uuid4()}"],
        "authors": list(authors),
    }


@pytest.mark.requirement("SF-50")
async def test_an_anonymous_sighting_that_says_where_it_was_seen_is_refused(client, member):
    """Any location: a subsidiary's or a site's identity names the submitter as
    surely as its own, and the server cannot tell which identities those are."""
    _org, pem = member

    refused = await file(client, pem, [sighting(f"identity--{uuid.uuid4()}")], anonymous=True)

    assert refused.status_code == 400
    assert "where_sighted_refs" in refused.json()["title"]


@pytest.mark.requirement("SF-50")
async def test_an_anonymous_sighting_that_says_nothing_of_where_is_accepted(client, member):
    _org, pem = member

    assert (await file(client, pem, [sighting()], anonymous=True)).status_code == 201


@pytest.mark.requirement("SF-50")
@pytest.mark.parametrize(
    "authored",
    [
        lambda: note_by("J. Analyst"),
        lambda: opinion_about(f"indicator--{uuid.uuid4()}", authors=["J. Analyst"]),
    ],
    ids=["note", "opinion"],
)
async def test_an_anonymous_note_or_opinion_naming_authors_is_refused(client, member, authored):
    _org, pem = member

    refused = await file(client, pem, [authored()], anonymous=True)

    assert refused.status_code == 400
    assert "authors" in refused.json()["title"]


@pytest.mark.requirement("SF-50")
async def test_an_attributed_note_may_name_its_authors(client, member):
    _org, pem = member

    assert (await file(client, pem, [note_by("J. Analyst")])).status_code == 201


@pytest.mark.requirement("SF-50")
async def test_an_attributed_sighting_may_not_say_it_was_seen_at_another_firm(client, member):
    _org, pem = member
    peer = f"identity--{uuid.uuid4()}"

    refused = await file(client, pem, [sighting(peer)])

    assert refused.status_code == 400
    assert "only the organisation filing it" in refused.json()["title"]


@pytest.mark.requirement("SF-50")
async def test_an_attributed_sighting_may_say_it_was_seen_at_the_filer(client, member):
    org, pem = member

    assert (await file(client, pem, [sighting(org.stix_identity_id)])).status_code == 201


@pytest.mark.requirement("SF-50")
async def test_turning_anonymity_on_over_stored_authors_is_refused(client, member):
    """Checked against the submission as it stands, not only where a bundle arrives."""
    _org, pem = member
    filed = await file(client, pem, [note_by("J. Analyst")])

    refused = await client.patch(
        f"{API}/{filed.json()['id']}",
        json={"distribute_anonymously": True},
        headers=proxy_headers(pem),
    )

    assert refused.status_code == 400
    assert "authors" in refused.json()["title"]
