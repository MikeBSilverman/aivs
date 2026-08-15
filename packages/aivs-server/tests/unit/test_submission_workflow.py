"""The submission workflow, end to end through the native API.

The write path: how content enters AIVS and becomes something every member of a
circle receives. The tests are organised around the two properties that make the
workflow defensible rather than merely functional —

* the hosting ISAC, not the submitter, decides what is distributed, and
* nothing is visible until its release time, whether or not a scheduler ran.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import TLP, CircleRole, OrgType
from aivs_server.db.models import AuditLog, Distribution, StixObject, SubmissionTransition
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1/submissions"


def bundle(*, stix_id: str | None = None, name: str = "Prompt injection in agent runtime") -> dict:
    """A minimal, valid STIX bundle carrying one vulnerability."""
    stix_id = stix_id or f"vulnerability--{uuid.uuid4()}"
    stamp = "2026-08-01T00:00:00.000Z"
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": stix_id,
                "created": stamp,
                "modified": stamp,
                "name": name,
            }
        ],
    }


@pytest.fixture
async def member(make_org, make_cert):
    async def _build(slug: str = "meridian-global"):
        org = await make_org(slug, org_type=OrgType.GSIB)
        pem, _ = await make_cert(org)
        return org, pem

    return _build


@pytest.fixture
async def isac(make_org, make_cert):
    """The hosting ISAC's own machine identity."""
    org = await make_org("hosting-isac", org_type=OrgType.ADMIN)
    pem, _ = await make_cert(org)
    return org, pem


@pytest.fixture
async def circle(make_circle, make_collection):
    async def _build(slug: str = "section9", minimum_tlp: TLP = TLP.AMBER):
        c = await make_circle(slug)
        c.minimum_tlp = minimum_tlp
        collection = await make_collection(c)
        return c, collection

    return _build


async def create_draft(client, pem, **overrides: object) -> dict:
    payload = {
        "title": "AI-discovered chain in agent runtime",
        "discovery_scope": "ai_system",
        "tlp": "amber",
        "bundle": bundle(),
    }
    payload.update(overrides)
    response = await client.post(API, json=payload, headers=proxy_headers(pem))
    assert response.status_code == 201, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Creation and validation of inbound content
# ---------------------------------------------------------------------------
async def test_create_draft_stores_objects_and_history(client, member, session):
    org, pem = await member()
    created = await create_draft(client, pem)

    assert created["state"] == "draft"
    assert created["submitter_org_id"] == str(org.id)

    stored = await session.scalar(
        select(func.count())
        .select_from(StixObject)
        .where(StixObject.submission_id == uuid.UUID(created["id"]))
    )
    assert stored == 1

    transitions = await session.scalar(
        select(func.count())
        .select_from(SubmissionTransition)
        .where(SubmissionTransition.submission_id == uuid.UUID(created["id"]))
    )
    assert transitions == 1, "creation itself is recorded"


async def test_submitter_is_taken_from_the_certificate_not_the_body(client, member, make_org):
    """A member must not be able to file content in another firm's name."""
    _org, pem = await member()
    other = await make_org("someone-else")

    response = await client.post(
        API,
        json={
            "title": "Attempted impersonation",
            "discovery_scope": "own_product",
            "bundle": bundle(),
            "submitter_org_id": str(other.id),  # not an accepted field
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400, "unknown fields are refused, not ignored"


async def test_bundle_with_an_unknown_extension_is_refused(client, member):
    """The allowlist runs on the way in, not at distribution time."""
    _org, pem = await member()
    payload_bundle = bundle()
    payload_bundle["objects"][0]["extensions"] = {
        "extension-definition--00000000-0000-4000-8000-000000000000": {
            "extension_type": "property-extension"
        }
    }
    response = await client.post(
        API,
        json={
            "title": "Carries an unknown extension",
            "discovery_scope": "ai_system",
            "bundle": payload_bundle,
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400


async def test_non_bundle_is_refused(client, member):
    _org, pem = await member()
    response = await client.post(
        API,
        json={
            "title": "Not actually a bundle",
            "discovery_scope": "ai_system",
            "bundle": {"type": "vulnerability"},
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Who may move a submission
# ---------------------------------------------------------------------------
async def test_a_member_cannot_validate_their_own_submission(client, member):
    """The ISAC checkpoint is the point; a submitter must not be able to skip it."""
    _org, pem = await member()
    created = await create_draft(client, pem)

    submitted = await client.post(
        f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem)
    )
    assert submitted.status_code == 200
    assert submitted.json()["state"] == "submitted"

    validated = await client.post(
        f"{API}/{created['id']}/validate", json={}, headers=proxy_headers(pem)
    )
    assert validated.status_code == 403


async def test_a_member_cannot_distribute(client, member, isac, circle):
    _org, pem = await member()
    _isac_org, isac_pem = isac
    target, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=proxy_headers(isac_pem))

    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=proxy_headers(pem),
    )
    assert response.status_code == 403


async def test_another_member_cannot_see_a_submission(client, member):
    """Identifiers must not be probeable to learn what other firms have filed."""
    _org, pem = await member("meridian-global")
    created = await create_draft(client, pem)

    _other, other_pem = await member("atlantic-clearing")
    response = await client.get(f"{API}/{created['id']}", headers=proxy_headers(other_pem))
    assert response.status_code == 404, "reported absent, not forbidden"


async def test_the_isac_sees_every_submission(client, member, isac):
    _org, pem = await member()
    await create_draft(client, pem)
    _isac_org, isac_pem = isac

    response = await client.get(API, headers=proxy_headers(isac_pem))
    assert response.status_code == 200
    assert len(response.json()) == 1


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------
async def test_illegal_transition_is_refused(client, member):
    """A draft cannot jump straight to validated."""
    _org, pem = await member()
    created = await create_draft(client, pem)

    response = await client.post(
        f"{API}/{created['id']}/validate", json={}, headers=proxy_headers(pem)
    )
    assert response.status_code == 409


async def test_a_submitted_submission_can_no_longer_be_edited(client, member):
    """Content approved by the ISAC must be the content distributed."""
    _org, pem = await member()
    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))

    response = await client.patch(
        f"{API}/{created['id']}",
        json={"title": "Changed after review began"},
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400


async def test_a_draft_can_be_edited(client, member):
    _org, pem = await member()
    created = await create_draft(client, pem)

    response = await client.patch(
        f"{API}/{created['id']}", json={"title": "Revised title"}, headers=proxy_headers(pem)
    )
    assert response.status_code == 200
    assert response.json()["title"] == "Revised title"


async def test_distributed_content_cannot_be_withdrawn(client, member, isac, circle):
    """Members already hold it; withdrawal would be a false promise."""
    _org, pem = await member()
    _isac_org, isac_pem = isac
    target, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=proxy_headers(isac_pem))
    await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=proxy_headers(isac_pem),
    )

    response = await client.post(
        f"{API}/{created['id']}/withdraw", json={}, headers=proxy_headers(pem)
    )
    assert response.status_code == 409


# ---------------------------------------------------------------------------
# Distribution
# ---------------------------------------------------------------------------
async def test_distribution_makes_content_visible_over_taxii(
    client, member, isac, circle, join_circle
):
    """The whole point, proved end to end: submit here, collect there."""
    org, pem = await member()
    _isac_org, isac_pem = isac
    target, collection = await circle()
    await join_circle(org, target, CircleRole.MEMBER)

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=proxy_headers(isac_pem))
    distributed = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=proxy_headers(isac_pem),
    )
    assert distributed.status_code == 200, distributed.text
    assert distributed.json()["state"] == "distributed"

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )
    assert feed.status_code == 200
    objects = feed.json()["objects"]
    assert len(objects) == 1
    assert objects[0]["name"] == "Prompt injection in agent runtime"


async def test_a_future_release_time_holds_content_back(client, member, isac, circle, join_circle):
    """Embargo is a timestamp, so it holds with no scheduler running at all."""
    org, pem = await member()
    _isac_org, isac_pem = isac
    target, collection = await circle()
    await join_circle(org, target)

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=proxy_headers(isac_pem))

    release_at = dt.datetime.now(dt.UTC) + dt.timedelta(days=3)
    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)], "release_at": release_at.isoformat()},
        headers=proxy_headers(isac_pem),
    )
    assert response.status_code == 200

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )
    assert feed.json() == {}, "embargoed content must not be readable"


async def test_a_naive_release_time_is_refused(client, member, isac, circle):
    """Guessing a timezone on an embargo boundary publishes content early."""
    _org, pem = await member()
    _isac_org, isac_pem = isac
    target, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=proxy_headers(isac_pem))

    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)], "release_at": "2026-12-01T00:00:00"},
        headers=proxy_headers(isac_pem),
    )
    assert response.status_code == 400


async def test_tlp_floor_is_enforced_per_circle(client, member, isac, circle):
    """A circle's minimum restrictiveness is a commitment to its members."""
    _org, pem = await member()
    _isac_org, isac_pem = isac
    strict, _collection = await circle("section9", minimum_tlp=TLP.RED)

    created = await create_draft(client, pem, tlp="green")
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=proxy_headers(isac_pem))

    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(strict.id)]},
        headers=proxy_headers(isac_pem),
    )
    assert response.status_code == 409
    assert "tighter" in response.text


async def test_distribution_to_an_unknown_circle_fails_wholly(
    client, member, isac, circle, session
):
    """A partial distribution is the worst outcome: some members silently unwarned."""
    _org, pem = await member()
    _isac_org, isac_pem = isac
    good, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=proxy_headers(isac_pem))

    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(good.id), str(uuid.uuid4())]},
        headers=proxy_headers(isac_pem),
    )
    assert response.status_code == 409

    written = await session.scalar(select(func.count()).select_from(Distribution))
    assert written == 0, "the good circle must not have been served either"


async def test_anonymous_distribution_rewrites_attribution(
    client, member, isac, circle, join_circle, session
):
    """The consumer-visible attribution becomes the ISAC; the ISAC still knows."""
    org, pem = await member()
    isac_org, isac_pem = isac
    target, collection = await circle()
    await join_circle(org, target)

    created = await create_draft(client, pem, distribute_anonymously=True)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=proxy_headers(isac_pem))
    await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=proxy_headers(isac_pem),
    )

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )
    served = feed.json()["objects"][0]
    assert served["created_by_ref"] == isac_org.stix_identity_id

    # Internally, attribution survives -- this is what lets the ISAC answer
    # questions its members cannot.
    detail = await client.get(f"{API}/{created['id']}", headers=proxy_headers(isac_pem))
    assert detail.json()["submitter_org_id"] == str(org.id)


async def test_distribution_is_recorded_in_the_audit_trail(client, member, isac, circle, session):
    _org, pem = await member()
    _isac_org, isac_pem = isac
    target, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=proxy_headers(isac_pem))
    await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=proxy_headers(isac_pem),
    )

    actions = set((await session.execute(select(AuditLog.action))).scalars().all())
    assert "submission.created" in actions
    assert "submission.distributed" in actions
    assert "submission.transitioned" in actions
