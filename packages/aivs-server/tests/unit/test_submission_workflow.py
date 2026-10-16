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

from aivs_schemas.enums import TLP, CircleRole, OperatorRole, OrgType
from aivs_server.db.models import AuditLog, Distribution, StixObject, SubmissionTransition
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1/submissions"


STAMP = "2026-08-01T00:00:00.000Z"


def bundle(
    *,
    stix_id: str | None = None,
    name: str = "Prompt injection in agent runtime",
    modified: str = STAMP,
) -> dict:
    """A minimal, valid STIX bundle carrying one vulnerability."""
    stix_id = stix_id or f"vulnerability--{uuid.uuid4()}"
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": stix_id,
                "created": STAMP,
                "modified": modified,
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
        # Credited unless a test asks otherwise: stated, because the server's
        # default for a member is anonymous (Mike, Q16), and the identity
        # tests here are about what an attributed filing may carry.
        "distribute_anonymously": False,
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
    _isac_org, isac_headers = isac
    target, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)

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


@pytest.mark.requirement("SF-91")
async def test_a_peer_cannot_amend_submit_or_withdraw_a_members_draft(client, member):
    """Each is written staff side, keyed on the caller's own filing (slice 3g): a
    peer is told there is no such submission, as when it asks to read one."""
    _org, pem = await member("meridian-global")
    created = await create_draft(client, pem)
    _other, other_pem = await member("atlantic-clearing")
    peer = proxy_headers(other_pem)

    amended = await client.patch(f"{API}/{created['id']}", json={"title": "A peer's"}, headers=peer)
    submitted = await client.post(f"{API}/{created['id']}/submit", json={}, headers=peer)
    withdrawn = await client.post(f"{API}/{created['id']}/withdraw", json={}, headers=peer)

    assert (amended.status_code, submitted.status_code, withdrawn.status_code) == (404, 404, 404)
    own = (await client.get(f"{API}/{created['id']}", headers=proxy_headers(pem))).json()
    assert (own["state"], own["title"]) == ("draft", created["title"])


async def test_the_isac_sees_every_submission(client, member, isac):
    _org, pem = await member()
    await create_draft(client, pem)
    _isac_org, isac_headers = isac

    response = await client.get(API, headers=isac_headers)
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
    _isac_org, isac_headers = isac
    target, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)
    await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=isac_headers,
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
    _isac_org, isac_headers = isac
    target, collection = await circle()
    await join_circle(org, target, CircleRole.MEMBER)

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)
    distributed = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=isac_headers,
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
    _isac_org, isac_headers = isac
    target, collection = await circle()
    await join_circle(org, target)

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)

    release_at = dt.datetime.now(dt.UTC) + dt.timedelta(days=3)
    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)], "release_at": release_at.isoformat()},
        headers=isac_headers,
    )
    assert response.status_code == 200

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )
    assert feed.json() == {}, "embargoed content must not be readable"


async def test_a_naive_release_time_is_refused(client, member, isac, circle):
    """Guessing a timezone on an embargo boundary publishes content early."""
    _org, pem = await member()
    _isac_org, isac_headers = isac
    target, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)

    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)], "release_at": "2026-12-01T00:00:00"},
        headers=isac_headers,
    )
    assert response.status_code == 400


@pytest.mark.requirement("NFR-D3")
async def test_tlp_floor_is_enforced_per_circle(client, member, isac, circle):
    """A circle's minimum restrictiveness is a commitment to its members."""
    _org, pem = await member()
    _isac_org, isac_headers = isac
    strict, _collection = await circle("section9", minimum_tlp=TLP.RED)

    created = await create_draft(client, pem, tlp="green")
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)

    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(strict.id)]},
        headers=isac_headers,
    )
    assert response.status_code == 409
    assert "tighter" in response.text


async def test_distribution_to_an_unknown_circle_fails_wholly(
    client, member, isac, circle, session
):
    """A partial distribution is the worst outcome: some members silently unwarned."""
    _org, pem = await member()
    _isac_org, isac_headers = isac
    good, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)

    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(good.id), str(uuid.uuid4())]},
        headers=isac_headers,
    )
    assert response.status_code == 409

    written = await session.scalar(select(func.count()).select_from(Distribution))
    assert written == 0, "the good circle must not have been served either"


async def test_anonymous_distribution_rewrites_attribution(
    client, member, isac, circle, join_circle, session
):
    """The consumer-visible attribution becomes the ISAC; the ISAC still knows."""
    org, pem = await member()
    isac_org, isac_headers = isac
    target, collection = await circle()
    await join_circle(org, target)

    created = await create_draft(client, pem, distribute_anonymously=True)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)
    await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=isac_headers,
    )

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )
    served = feed.json()["objects"][0]
    assert served["created_by_ref"] == isac_org.stix_identity_id

    # Internally, attribution survives -- but an ordinary read withholds it from
    # everyone except the submitter (SF-44). Naming the submitter is the audited
    # reveal action, tested below.
    seen_by_isac = await client.get(f"{API}/{created['id']}", headers=isac_headers)
    seen_by_submitter = await client.get(f"{API}/{created['id']}", headers=proxy_headers(pem))
    assert seen_by_isac.json()["submitter_org_id"] is None
    assert seen_by_submitter.json()["submitter_org_id"] == str(org.id)


async def test_distribution_is_recorded_in_the_audit_trail(client, member, isac, circle, session):
    _org, pem = await member()
    _isac_org, isac_headers = isac
    target, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)
    await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=isac_headers,
    )

    actions = set((await session.execute(select(AuditLog.action))).scalars().all())
    assert "submission.created" in actions
    assert "submission.distributed" in actions
    assert "submission.transitioned" in actions


# ---------------------------------------------------------------------------
# Regressions from the write-path review
# ---------------------------------------------------------------------------
async def test_one_members_object_cannot_suppress_anothers(
    client, member, isac, circle, join_circle, session
):
    """A second organisation cannot take over, or silence, the first one's object.

    Duplicate suppression was once keyed on (circle, stix_id, modified) across
    every submission: the second organisation's object was skipped as "already
    delivered". Then both were delivered under one id, which let the later
    ``modified`` win in every consumer's TIP. Now only the owner versions an id
    (SF-48): the second firm's validation is refused, and the first firm's
    object is delivered untouched.
    """
    shared_id = "vulnerability--aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
    target, collection = await circle()

    first_org, first_pem = await member("meridian-global")
    await join_circle(first_org, target)
    _isac_org, isac_headers = isac

    second_org, second_pem = await member("atlantic-clearing")
    await join_circle(second_org, target)

    async def file_and_validate(pem, name, modified):
        created = await create_draft(
            client,
            pem,
            title=name,
            bundle=bundle(stix_id=shared_id, name=name, modified=modified),
        )
        await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
        validated = await client.post(
            f"{API}/{created['id']}/validate", json={}, headers=isac_headers
        )
        return created["id"], validated

    first_id, first = await file_and_validate(first_pem, "first-firms-finding", STAMP)
    assert first.status_code == 200, first.text
    distributed = await client.post(
        f"{API}/{first_id}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=isac_headers,
    )
    assert distributed.status_code == 200, distributed.text

    _second_id, second = await file_and_validate(
        second_pem, "second-firms-finding", "2026-09-01T00:00:00.000Z"
    )
    assert second.status_code == 409
    assert shared_id in second.json()["title"]

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/",
        params={"match[version]": "all"},
        headers=proxy_headers(first_pem),
    )
    assert {obj["name"] for obj in feed.json()["objects"]} == {"first-firms-finding"}


async def test_a_backdated_release_time_is_refused(client, member, isac, circle):
    """A backdated date_added sorts below cursors members have already passed.

    `added_after` polling never looks backwards, so the content would be
    permanently invisible to exactly the members collecting correctly, while the
    receipts table showed they simply never fetched it.
    """
    _org, pem = await member()
    _isac_org, isac_headers = isac
    target, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)

    past = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)], "release_at": past.isoformat()},
        headers=isac_headers,
    )
    assert response.status_code == 409
    assert "backdated" in response.text


@pytest.mark.requirement("SF-7")
@pytest.mark.parametrize(
    ("release_at", "reason"),
    [
        ("9999-12-31T23:59:00-01:00", "latest time an embargo can hold"),
        ("9999-06-01T00:00:00+00:00", "must be before 9999-01-01"),
    ],
    ids=["past-pythons-range-in-utc", "at-the-hold-sentinel"],
)
async def test_a_release_time_past_the_latest_release_is_refused_at_distribution(
    client, member, isac, circle, release_at, reason
):
    """Stored, the first could not be loaded back, failing every later read of
    the embargo; the second would read to the sweeper as a hold, not a timer."""
    _org, pem = await member()
    _isac_org, isac_headers = isac
    target, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)

    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)], "release_at": release_at},
        headers=isac_headers,
    )
    assert response.status_code == 409, response.text
    assert reason in response.text


async def test_redistributing_the_same_submission_reports_nothing_to_do(
    client, member, isac, circle
):
    """Reporting success for a distribution that delivered nothing misleads the operator."""
    _org, pem = await member()
    _isac_org, isac_headers = isac
    target, _collection = await circle()

    created = await create_draft(client, pem)
    await client.post(f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem))
    await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)
    first = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=isac_headers,
    )
    assert first.status_code == 200

    # Already distributed, so the state guard refuses before reaching the
    # nothing-to-deliver check; either refusal is correct, a 2xx is not.
    again = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=isac_headers,
    )
    assert again.status_code == 409


async def test_modified_before_created_is_refused(client, member):
    """Invalid STIX, and it inverts `match[version]=last` for the submitter."""
    _org, pem = await member()
    payload_bundle = bundle()
    payload_bundle["objects"][0]["created"] = "2026-08-01T00:00:00.000Z"
    payload_bundle["objects"][0]["modified"] = "2020-01-01T00:00:00.000Z"

    response = await client.post(
        API,
        json={
            "title": "Backwards timestamps",
            "discovery_scope": "ai_system",
            "bundle": payload_bundle,
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400
    assert "modified" in response.text


async def test_oversized_content_is_a_client_error_not_a_server_fault(client, member):
    """A value too long for its column means the bundle is malformed, not that we broke."""
    _org, pem = await member()
    payload_bundle = bundle()
    payload_bundle["objects"][0]["id"] = "vulnerability--" + "a" * 200

    response = await client.post(
        API,
        json={
            "title": "Oversized identifier",
            "discovery_scope": "ai_system",
            "bundle": payload_bundle,
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400, "must not surface as 500"


async def test_anonymous_submission_refuses_an_identity_object(client, member):
    """Anonymity is a promise; an identity SDO would deliver the name anyway.

    `created_by_ref` is the only attribution the pipeline rewrites. An identity
    object riding along in the same bundle is redistributed verbatim, in the
    same envelope, naming the submitter the server promised to withhold.
    """
    _org, pem = await member()
    payload_bundle = bundle()
    payload_bundle["objects"].append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
            "created": "2026-08-01T00:00:00.000Z",
            "modified": "2026-08-01T00:00:00.000Z",
            "name": "Meridian Global Bank",
        }
    )

    response = await client.post(
        API,
        json={
            "title": "Anonymous but self-identifying",
            "discovery_scope": "ai_system",
            "distribute_anonymously": True,
            "bundle": payload_bundle,
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400
    assert "identity" in response.text


async def test_identity_objects_are_fine_when_not_anonymous(client, member):
    """The restriction applies only where anonymity was promised."""
    _org, pem = await member()
    payload_bundle = bundle()
    payload_bundle["objects"].append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--cccccccc-3333-4333-8333-cccccccccccc",
            "created": "2026-08-01T00:00:00.000Z",
            "modified": "2026-08-01T00:00:00.000Z",
            "name": "Meridian Global Bank",
        }
    )

    response = await client.post(
        API,
        json={
            "title": "Attributed submission",
            "discovery_scope": "ai_system",
            "distribute_anonymously": False,
            "bundle": payload_bundle,
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 201


def identity_bundle(name: str = "Meridian Global Bank") -> dict:
    """A bundle carrying the submitter's own identity SDO alongside the finding."""
    payload = bundle()
    payload["objects"].append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{uuid.uuid4()}",
            "created": "2026-08-01T00:00:00.000Z",
            "modified": "2026-08-01T00:00:00.000Z",
            "name": name,
        }
    )
    return payload


async def test_turning_on_anonymity_later_rechecks_the_stored_objects(client, member):
    """The check is a property of the submission, not of the write that carried a bundle.

    Storing an identity SDO is legal while the submission is attributed, so a
    draft can hold one before anyone asks for anonymity. Amending only the flag
    used to skip the check entirely, because it ran solely inside the
    store-a-bundle path -- and the name then rode out to every circle member in
    the same envelope as a finding the submitter was told was anonymous.
    """
    _org, pem = await member()
    created = await create_draft(client, pem, bundle=identity_bundle())

    response = await client.patch(
        f"{API}/{created['id']}",
        json={"distribute_anonymously": True},
        headers=proxy_headers(pem),
    )

    assert response.status_code == 400, response.text
    assert "identity" in response.text


async def test_turning_on_anonymity_is_allowed_when_nothing_identifies_the_submitter(
    client, member, session
):
    """The re-check must not refuse the ordinary case."""
    _org, pem = await member()
    created = await create_draft(client, pem)

    response = await client.patch(
        f"{API}/{created['id']}",
        json={"distribute_anonymously": True},
        headers=proxy_headers(pem),
    )

    assert response.status_code == 200, response.text
    assert response.json()["distribute_anonymously"] is True


async def test_amending_the_flag_and_the_bundle_together_still_checks(client, member):
    """The path that always worked keeps working: the flag is applied before the check."""
    _org, pem = await member()
    created = await create_draft(client, pem)

    response = await client.patch(
        f"{API}/{created['id']}",
        json={"distribute_anonymously": True, "bundle": identity_bundle()},
        headers=proxy_headers(pem),
    )

    assert response.status_code == 400, response.text
    assert "identity" in response.text


async def test_distribution_refuses_an_anonymous_submission_that_names_its_submitter(
    client, member, isac, circle, session
):
    """The last gate. Distribution is where the promise is finally kept or broken.

    Reached by writing the flag straight to the row, bypassing the API guards
    above on purpose: the point of this gate is that it holds regardless of how
    the flag came to be set.
    """
    from aivs_server.db.models import Submission  # noqa: PLC0415 - local to this test

    _org, pem = await member()
    _isac_org, isac_headers = isac
    circle_row, _collection = await circle()

    created = await create_draft(client, pem, bundle=identity_bundle())
    submission_id = uuid.UUID(created["id"])

    submitted = await client.post(
        f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem)
    )
    assert submitted.status_code == 200, submitted.text
    validated = await client.post(f"{API}/{created['id']}/validate", json={}, headers=isac_headers)
    assert validated.status_code == 200, validated.text

    row = await session.get(Submission, submission_id)
    assert row is not None
    row.distribute_anonymously = True
    await session.commit()

    response = await client.post(
        f"{API}/{created['id']}/distribute",
        json={"circle_ids": [str(circle_row.id)]},
        headers=isac_headers,
    )

    # 409, like every other refusal to distribute: the submission is in a state
    # that forbids the verb, rather than the request being malformed.
    assert response.status_code == 409, response.text
    assert "identity" in response.text

    delivered = await session.scalar(
        select(func.count())
        .select_from(Distribution)
        .where(Distribution.submission_id == submission_id)
    )
    assert delivered == 0, "nothing may be delivered when the gate refuses"


def _identity(identity_id: str, name: str) -> dict:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": "2026-08-01T00:00:00.000Z",
        "modified": "2026-08-01T00:00:00.000Z",
        "name": name,
    }


async def test_an_identity_object_cannot_use_a_peers_registered_identifier(
    client, member, make_org
):
    """Finding #4: a member could publish an object as another firm.

    Distribution rewrites only ``created_by_ref``; the rest of the bundle is
    served verbatim, so an identity SDO carrying a peer's registered
    ``stix_identity_id`` reached every recipient's TIP as that peer. A
    third party's identity that is not registered here -- a vendor's -- is the
    control, and is still accepted.
    """
    _org, pem = await member()
    peer = await make_org("peer-bank")

    impersonating = bundle()
    impersonating["objects"].append(_identity(peer.stix_identity_id, "Peer Bank, says us"))
    vendor = bundle()
    vendor["objects"].append(_identity(f"identity--{uuid.uuid4()}", "Example Vendor"))

    refused = await client.post(
        API,
        json={
            "title": "As someone else",
            "discovery_scope": "ai_system",
            "distribute_anonymously": False,
            "bundle": impersonating,
        },
        headers=proxy_headers(pem),
    )
    accepted = await client.post(
        API,
        json={
            "title": "Naming a vendor",
            "discovery_scope": "ai_system",
            "distribute_anonymously": False,
            "bundle": vendor,
        },
        headers=proxy_headers(pem),
    )

    assert refused.status_code == 400
    assert peer.stix_identity_id in refused.text
    assert accepted.status_code == 201


async def test_distribution_refuses_an_identity_registered_after_ingest(
    client, member, isac, circle, make_org, session
):
    """Checked again at distribution: an organisation can be enrolled with that
    identifier after the bundle was stored, and distribution is the last point at
    which the bundle can still be refused. The submission is otherwise identical
    to one that distributes, which is the control below.
    """
    _org, pem = await member()
    _isac_org, isac_headers = isac
    target, _collection = await circle()
    later_identity = f"identity--{uuid.uuid4()}"

    staged = bundle()
    staged["objects"].append(_identity(later_identity, "Enrolled later"))
    held = await create_draft(client, pem, bundle=staged)
    clean = await create_draft(client, pem)

    peer = await make_org("enrolled-later")
    peer.stix_identity_id = later_identity
    await session.commit()

    for submission in (held, clean):
        for verb in ("submit", "validate"):
            who = proxy_headers(pem) if verb == "submit" else isac_headers
            response = await client.post(f"{API}/{submission['id']}/{verb}", json={}, headers=who)
            assert response.status_code == 200, response.text

    refused = await client.post(
        f"{API}/{held['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=isac_headers,
    )
    distributed = await client.post(
        f"{API}/{clean['id']}/distribute",
        json={"circle_ids": [str(target.id)]},
        headers=isac_headers,
    )

    assert refused.status_code in (400, 409, 422)
    assert later_identity in refused.text
    assert distributed.status_code == 200


async def test_a_member_may_carry_its_own_identity(client, member):
    """The refusal is for someone else's identifier, never your own."""
    org, pem = await member()
    own = bundle()
    own["objects"].append(_identity(org.stix_identity_id, "Meridian Global Bank"))

    response = await client.post(
        API,
        json={
            "title": "Signed as ourselves",
            "discovery_scope": "ai_system",
            "distribute_anonymously": False,
            "bundle": own,
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 201


@pytest.mark.requirement("SF-44")
async def test_revealing_an_anonymous_submitter_is_an_audited_editorial_act(
    client, member, isac, session, make_org, make_cert, make_operator, human_headers
):
    """SF-44. Before this, any ISAC reader saw the identity in an ordinary GET,
    so "reveal" was indistinguishable from routine review. Now: an editor names
    the submitter with a stated reason, the audit row records the reason and
    not the identity, and an ISAC analyst -- who can read the submission -- may
    not reveal it.
    """
    org, pem = await member()
    _isac_org, isac_headers = isac
    created = await create_draft(client, pem, distribute_anonymously=True)
    attributed = await create_draft(client, pem)
    reason = "Law-enforcement request, case 2026-117, approved by counsel"

    revealed = await client.post(
        f"{API}/{created['id']}/reveal", json={"reason": reason}, headers=isac_headers
    )
    assert revealed.status_code == 200
    assert revealed.json()["submitter_org_id"] == str(org.id)

    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "anonymity.reveal")))
        .scalars()
        .all()
    )
    assert [row.details for row in rows] == [{"reason": reason}]

    isac_org, _headers = isac
    analyst_pem, _ = await make_cert(isac_org)
    analyst, _seed = await make_operator(isac_org, roles=(OperatorRole.ISAC_ANALYST,))
    analyst_headers = await human_headers(analyst, analyst_pem)
    refused = await client.post(
        f"{API}/{created['id']}/reveal", json={"reason": reason}, headers=analyst_headers
    )
    assert refused.status_code == 403

    not_anonymous = await client.post(
        f"{API}/{attributed['id']}/reveal", json={"reason": reason}, headers=isac_headers
    )
    assert not_anonymous.status_code == 409
