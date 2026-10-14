"""TAXII 2.1 specification conformance.

Each test names the section of the OASIS TAXII 2.1 standard it enforces. The
point is not that AIVS behaves reasonably, but that it behaves exactly as a
member's off-the-shelf TAXII client expects -- including the parts of the spec
that look like pedantry, such as omitting an empty ``collections`` key entirely
rather than emitting an empty array.

Interleaved with the conformance checks are the access-control properties that
happen to be observable through this surface: an embargoed object is invisible,
a non-member gets 404 rather than 403, and retrieving content writes a receipt.
Those live here rather than in the authorization matrix because they are
properties of the TAXII responses specifically.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import AckType, CircleRole
from aivs_server.db.models import Acknowledgment
from aivs_server.taxii import resources
from tests.conftest import proxy_headers

pytestmark = [pytest.mark.db, pytest.mark.conformance, pytest.mark.requirement("NFR-I1")]

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"


@pytest.fixture
async def member(make_org, make_cert, make_circle, join_circle, make_collection):
    """An active organisation in one circle, with a collection over it."""

    async def _build(slug: str = "meridian-global", role: CircleRole = CircleRole.MEMBER):
        org = await make_org(slug)
        pem, _ = await make_cert(org)
        circle = await make_circle(f"{slug}-circle")
        await join_circle(org, circle, role)
        collection = await make_collection(circle)
        return org, pem, circle, collection

    return _build


# ---------------------------------------------------------------------------
# Discovery and API root (sections 4.1, 4.2)
# ---------------------------------------------------------------------------
async def test_discovery_shape_and_media_type(client, member):
    _org, pem, _circle, _collection = await member()

    response = await client.get("/taxii2/", headers=proxy_headers(pem))

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/taxii+json")
    assert "version=2.1" in response.headers["content-type"]
    body = response.json()
    assert "title" in body, "title is the only required discovery property"
    assert body["default"] in body["api_roots"], "default MUST be one of api_roots"


async def test_api_root_required_properties(client, member):
    _org, pem, _circle, _collection = await member()

    response = await client.get("/taxii2/aivs/", headers=proxy_headers(pem))

    assert response.status_code == 200
    body = response.json()
    assert set(body) >= {"title", "versions", "max_content_length"}
    assert TAXII_MEDIA_TYPE in body["versions"]
    assert isinstance(body["max_content_length"], int)
    assert body["max_content_length"] > 0


async def test_unacceptable_accept_header_is_406(client, member):
    """Section 1.6.8: the server returns 406 when it cannot satisfy Accept."""
    _org, pem, _circle, _collection = await member()

    response = await client.get(
        "/taxii2/", headers={**proxy_headers(pem), "accept": "application/xml"}
    )
    assert response.status_code == 406


# ---------------------------------------------------------------------------
# Collections (sections 5.1, 5.2)
# ---------------------------------------------------------------------------
async def test_collections_lists_only_readable_circles(
    client, member, make_circle, make_collection
):
    _org, pem, _circle, collection = await member()
    # A circle the caller does not belong to, with its own collection.
    other = await make_circle("someone-elses-circle")
    await make_collection(other)

    response = await client.get("/taxii2/aivs/collections/", headers=proxy_headers(pem))

    assert response.status_code == 200
    listed = {entry["id"] for entry in response.json()["collections"]}
    assert listed == {str(collection.id)}


async def test_empty_collections_omits_the_key(client, make_org, make_cert):
    """Section 5.1.1: an empty result omits ``collections`` entirely."""
    org = await make_org("no-circles")
    pem, _ = await make_cert(org)

    response = await client.get("/taxii2/aivs/collections/", headers=proxy_headers(pem))

    assert response.status_code == 200
    assert response.json() == {}, "empty listing must be {} and not {'collections': []}"


async def test_collection_required_properties(client, member):
    _org, pem, _circle, collection = await member()

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/", headers=proxy_headers(pem)
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) >= {"id", "title", "can_read", "can_write"}
    assert body["id"] == str(collection.id)


async def test_can_write_reflects_the_caller_not_the_collection(client, member):
    """``can_write`` answers "may *you* write here", which differs per caller."""
    _org, reader_pem, _circle, collection = await member("read-only-firm", CircleRole.MEMBER)
    reader = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/", headers=proxy_headers(reader_pem)
    )
    assert reader.json()["can_write"] is False

    _org2, writer_pem, _c2, collection2 = await member("contributing-firm", CircleRole.CONTRIBUTOR)
    writer = await client.get(
        f"/taxii2/aivs/collections/{collection2.id}/", headers=proxy_headers(writer_pem)
    )
    assert writer.json()["can_write"] is True


async def test_non_member_gets_404_not_403(client, member, make_org, make_cert):
    """A collection the caller cannot read is reported as absent.

    Deliberate: distinguishing "exists but forbidden" from "does not exist"
    would let any member enumerate every circle on the instance.
    """
    _org, _pem, _circle, collection = await member()
    outsider = await make_org("outsider-firm")
    outsider_pem, _ = await make_cert(outsider)

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/", headers=proxy_headers(outsider_pem)
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Objects (sections 3.7, 5.4)
# ---------------------------------------------------------------------------
async def test_objects_envelope_and_date_added_headers(client, member, publish):
    org, pem, circle, collection = await member()
    await publish(org, circle, name="First finding")

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["objects"]) == 1
    assert body["objects"][0]["name"] == "First finding"
    # Section 3.2: both headers are required on a 200 from this endpoint.
    assert "X-TAXII-Date-Added-First" in response.headers
    assert "X-TAXII-Date-Added-Last" in response.headers


async def test_empty_collection_returns_empty_envelope(client, member):
    """Section 3.7: an empty result is an empty envelope, not a 404."""
    _org, pem, _circle, collection = await member()

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )

    assert response.status_code == 200
    assert response.json() == {}


async def test_objects_are_sorted_by_date_added_ascending(client, member, publish):
    """Section 3.3: most recently added is last."""
    org, pem, circle, collection = await member()
    base = dt.datetime.now(dt.UTC) - dt.timedelta(hours=3)
    for index in range(3):
        await publish(
            org, circle, name=f"finding-{index}", date_added=base + dt.timedelta(minutes=index)
        )

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )

    names = [obj["name"] for obj in response.json()["objects"]]
    assert names == ["finding-0", "finding-1", "finding-2"]


async def test_added_after_is_exclusive(client, member, publish):
    org, pem, circle, collection = await member()
    base = dt.datetime.now(dt.UTC) - dt.timedelta(hours=3)
    await publish(org, circle, name="older", date_added=base)
    await publish(org, circle, name="newer", date_added=base + dt.timedelta(minutes=5))

    cutoff = base.strftime("%Y-%m-%dT%H:%M:%S.") + f"{base.microsecond // 1000:03d}Z"
    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/",
        params={"added_after": cutoff},
        headers=proxy_headers(pem),
    )

    names = [obj["name"] for obj in response.json()["objects"]]
    assert names == ["newer"], "added_after is exclusive, so 'older' must not reappear"


async def test_limit_paging_with_next_cursor(client, member, publish):
    """Section 3.4: truncation sets ``more`` and may supply ``next``."""
    org, pem, circle, collection = await member()
    base = dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)
    for index in range(5):
        await publish(
            org, circle, name=f"item-{index}", date_added=base + dt.timedelta(seconds=index)
        )

    first = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/",
        params={"limit": 2},
        headers=proxy_headers(pem),
    )
    assert first.status_code == 200
    first_body = first.json()
    assert first_body["more"] is True
    assert len(first_body["objects"]) == 2

    second = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/",
        params={"limit": 2, "next": first_body["next"]},
        headers=proxy_headers(pem),
    )
    second_body = second.json()
    assert [obj["name"] for obj in second_body["objects"]] == ["item-2", "item-3"]

    # Paging must neither skip nor duplicate.
    seen = [obj["name"] for obj in first_body["objects"]] + [
        obj["name"] for obj in second_body["objects"]
    ]
    assert seen == ["item-0", "item-1", "item-2", "item-3"]


async def test_cursor_from_another_collection_is_rejected(
    client, member, publish, make_circle, join_circle, make_collection
):
    """A cursor is bound to the collection it was issued for."""
    org, pem, circle, collection = await member()
    for index in range(3):
        await publish(org, circle, name=f"a-{index}")

    other_circle = await make_circle("second-circle")
    await join_circle(org, other_circle)
    other_collection = await make_collection(other_circle)

    first = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/",
        params={"limit": 1},
        headers=proxy_headers(pem),
    )
    cursor = first.json()["next"]

    response = await client.get(
        f"/taxii2/aivs/collections/{other_collection.id}/objects/",
        params={"next": cursor},
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400


async def test_match_type_filter(client, member, publish):
    org, pem, circle, collection = await member()
    await publish(org, circle, stix_type="vulnerability", name="a vuln")
    await publish(org, circle, stix_type="course-of-action", name="a fix")

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/",
        params={"match[type]": "course-of-action"},
        headers=proxy_headers(pem),
    )

    objects = response.json()["objects"]
    assert [obj["name"] for obj in objects] == ["a fix"]


async def test_match_id_filter(client, member, publish):
    org, pem, circle, collection = await member()
    _s, wanted, _d = await publish(org, circle, name="wanted")
    await publish(org, circle, name="unwanted")

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/",
        params={"match[id]": wanted.stix_id},
        headers=proxy_headers(pem),
    )

    assert [obj["name"] for obj in response.json()["objects"]] == ["wanted"]


async def test_version_defaults_to_last(client, member, publish):
    """Section 3.4.1: absent ``match[version]`` means ``last``, not ``all``."""
    org, pem, circle, collection = await member()
    stix_id = "vulnerability--11111111-1111-4111-8111-111111111111"
    older = dt.datetime.now(dt.UTC) - dt.timedelta(days=2)
    newer = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    submission, _obj, _dist = await publish(org, circle, stix_id=stix_id, name="v1", modified=older)
    await publish(org, circle, stix_id=stix_id, name="v2", modified=newer, submission=submission)

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )

    names = [obj["name"] for obj in response.json()["objects"]]
    assert names == ["v2"], "default must return only the latest version"


async def test_match_version_all_returns_every_version(client, member, publish):
    org, pem, circle, collection = await member()
    stix_id = "vulnerability--22222222-2222-4222-8222-222222222222"
    older = dt.datetime.now(dt.UTC) - dt.timedelta(days=2)
    newer = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    submission, _o, _d = await publish(org, circle, stix_id=stix_id, name="v1", modified=older)
    await publish(org, circle, stix_id=stix_id, name="v2", modified=newer, submission=submission)

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/",
        params={"match[version]": "all"},
        headers=proxy_headers(pem),
    )

    assert sorted(obj["name"] for obj in response.json()["objects"]) == ["v1", "v2"]


@pytest.mark.parametrize(
    "params",
    [
        {"limit": "0"},
        {"limit": "-5"},
        {"limit": "not-a-number"},
        {"added_after": "yesterday"},
        {"added_after": "2026-01-01"},
        {"match[version]": "all,last"},
        {"match[id]": "not-a-stix-id"},
        {"match[type]": "Not A Type"},
        {"next": "forged-cursor-value"},
    ],
)
async def test_malformed_filters_return_400(client, member, params):
    """Section 5.4: malformed query parameters are HTTP 400."""
    _org, pem, _circle, collection = await member()

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/",
        params=params,
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400, f"{params} should be rejected"


async def test_repeated_parameter_is_rejected(client, member):
    """A field must not occur more than once; it is malformed, not a union."""
    _org, pem, _circle, collection = await member()

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/?match[type]=vulnerability"
        "&match[type]=course-of-action",
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Embargo visibility
# ---------------------------------------------------------------------------
async def test_embargoed_object_is_invisible(client, member, publish):
    """An object whose ``date_added`` is in the future must not be returned.

    This is the authoritative embargo gate: enforcement is at read time, so
    nothing leaks early even when the release scheduler is not running.
    """
    org, pem, circle, collection = await member()
    future = dt.datetime.now(dt.UTC) + dt.timedelta(hours=6)
    await publish(org, circle, name="still embargoed", date_added=future)

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )

    assert response.status_code == 200
    assert response.json() == {}, "embargoed content must not appear"


async def test_embargoed_object_appears_once_its_time_arrives(client, member, publish):
    org, pem, circle, collection = await member()
    just_past = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
    await publish(org, circle, name="released", date_added=just_past)

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )

    assert [obj["name"] for obj in response.json()["objects"]] == ["released"]


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------
async def test_retrieval_writes_a_receipt(client, member, publish, session):
    """Collecting content records that this organisation collected it."""
    org, pem, circle, collection = await member()
    submission, _obj, _dist = await publish(org, circle)

    await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )

    count = await session.scalar(
        select(func.count())
        .select_from(Acknowledgment)
        .where(
            Acknowledgment.org_id == org.id,
            Acknowledgment.submission_id == submission.id,
            Acknowledgment.ack_type == AckType.RETRIEVED,
        )
    )
    assert count == 1


async def test_repeated_polling_writes_one_receipt_per_day(client, member, publish, session):
    """A member polling repeatedly must not write a row per poll."""
    org, pem, circle, collection = await member()
    await publish(org, circle)

    for _ in range(4):
        await client.get(
            f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
        )

    count = await session.scalar(
        select(func.count()).select_from(Acknowledgment).where(Acknowledgment.org_id == org.id)
    )
    assert count == 1


async def test_manifest_does_not_write_a_receipt(client, member, publish, session):
    """A manifest tells a member content exists, not what it says.

    Recording that as a retrieval would let an ISAC tell a regulator a firm
    "received" a warning on the strength of a metadata listing.
    """
    org, pem, circle, collection = await member()
    await publish(org, circle)

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/manifest/", headers=proxy_headers(pem)
    )
    assert response.status_code == 200

    count = await session.scalar(
        select(func.count()).select_from(Acknowledgment).where(Acknowledgment.org_id == org.id)
    )
    assert count == 0


# ---------------------------------------------------------------------------
# Manifest and versions (sections 5.3, 5.8)
# ---------------------------------------------------------------------------
async def test_manifest_record_shape(client, member, publish):
    org, pem, circle, collection = await member()
    _s, obj, _d = await publish(org, circle)

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/manifest/", headers=proxy_headers(pem)
    )

    assert response.status_code == 200
    records = response.json()["objects"]
    assert len(records) == 1
    assert set(records[0]) >= {"id", "date_added", "version"}
    assert records[0]["id"] == obj.stix_id


async def test_empty_manifest_omits_the_key(client, member):
    _org, pem, _circle, collection = await member()

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/manifest/", headers=proxy_headers(pem)
    )
    assert response.json() == {}


async def test_versions_endpoint_lists_visible_versions(client, member, publish):
    org, pem, circle, collection = await member()
    stix_id = "vulnerability--33333333-3333-4333-8333-333333333333"
    older = dt.datetime.now(dt.UTC) - dt.timedelta(days=2)
    newer = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    submission, _o, _d = await publish(org, circle, stix_id=stix_id, modified=older)
    await publish(org, circle, stix_id=stix_id, modified=newer, submission=submission)

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/{stix_id}/versions/",
        headers=proxy_headers(pem),
    )

    assert response.status_code == 200
    assert len(response.json()["versions"]) == 2


async def _versions_whose_modified_and_date_added_disagree(org, circle, publish):
    """V1 (modified 1, added t3), V2 (modified 2, added t1), V3 (modified 3, added t2).

    Modification order and distribution order are opposite enough that a page
    cut by one and continued by the other loses a version.
    """
    stix_id = f"vulnerability--{uuid.uuid4()}"
    base = dt.datetime.now(dt.UTC) - dt.timedelta(days=3)
    modified = [base + dt.timedelta(hours=hour) for hour in (1, 2, 3)]
    added = [base + dt.timedelta(days=1, hours=hour) for hour in (3, 1, 2)]
    for version, date_added in zip(modified, added, strict=True):
        await publish(org, circle, stix_id=stix_id, modified=version, date_added=date_added)
    return stix_id, [resources.to_taxii_timestamp(version) for version in modified]


async def test_paging_versions_by_added_after_skips_no_version(client, member, publish):
    """Section 3.4: a client continues with ``added_after`` = ``X-TAXII-Date-Added-Last``.

    Ordered by ``modified`` and cut at ``limit``, the first page was [V1, V2]
    with Last = t3, and ``added_after=t3`` then never listed V3.
    """
    org, pem, circle, collection = await member()
    stix_id, versions = await _versions_whose_modified_and_date_added_disagree(org, circle, publish)
    url = f"/taxii2/aivs/collections/{collection.id}/objects/{stix_id}/versions/"

    first = await client.get(url, params={"limit": 2}, headers=proxy_headers(pem))
    rest = await client.get(
        url,
        params={"limit": 2, "added_after": first.headers["X-TAXII-Date-Added-Last"]},
        headers=proxy_headers(pem),
    )

    received = first.json()["versions"] + rest.json()["versions"]
    assert sorted(received) == versions, "every version exactly once"
    assert first.json()["more"] is True
    assert "more" not in rest.json()


async def test_paging_versions_by_next_skips_no_version(client, member, publish):
    org, pem, circle, collection = await member()
    stix_id, versions = await _versions_whose_modified_and_date_added_disagree(org, circle, publish)
    url = f"/taxii2/aivs/collections/{collection.id}/objects/{stix_id}/versions/"

    first = await client.get(url, params={"limit": 2}, headers=proxy_headers(pem))
    rest = await client.get(
        url, params={"limit": 2, "next": first.json()["next"]}, headers=proxy_headers(pem)
    )

    received = first.json()["versions"] + rest.json()["versions"]
    assert sorted(received) == versions, "every version exactly once"


async def test_a_version_distributed_twice_is_listed_once_at_its_first_date_added(
    client, member, publish
):
    """Two submissions carrying one version are one version, not two entries.

    ``DISTINCT (modified, date_added)`` kept both rows, and ``added_after``
    between the two stamps re-listed a version the client already held.
    """
    org, pem, circle, collection = await member()
    stix_id = f"vulnerability--{uuid.uuid4()}"
    version = dt.datetime.now(dt.UTC) - dt.timedelta(days=3)
    first_added = dt.datetime.now(dt.UTC) - dt.timedelta(days=2)
    again_added = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    await publish(org, circle, stix_id=stix_id, modified=version, date_added=first_added)
    await publish(org, circle, stix_id=stix_id, modified=version, date_added=again_added)
    url = f"/taxii2/aivs/collections/{collection.id}/objects/{stix_id}/versions/"

    everything = await client.get(url, headers=proxy_headers(pem))
    since_the_first = await client.get(
        url,
        params={"added_after": resources.to_taxii_timestamp(first_added)},
        headers=proxy_headers(pem),
    )

    assert everything.json()["versions"] == [resources.to_taxii_timestamp(version)]
    assert everything.headers["X-TAXII-Date-Added-Last"] == resources.to_taxii_timestamp(
        first_added
    )
    assert "versions" not in since_the_first.json(), "nothing new since it was first added"


async def test_unknown_object_is_404(client, member):
    _org, pem, _circle, collection = await member()

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/"
        "vulnerability--44444444-4444-4444-8444-444444444444/",
        headers=proxy_headers(pem),
    )
    assert response.status_code == 404
