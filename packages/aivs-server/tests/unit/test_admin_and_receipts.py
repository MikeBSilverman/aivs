"""Administration and the evidentiary surface.

Two things are proved here. First, that the hosting ISAC's operational endpoints
are reachable only by the hosting ISAC -- these are the endpoints that enrol
members and issue their access, so a member reaching them would be a full
compromise of the trust model. Second, that receipts say what an ISAC would need
to tell a regulator, and are visible only to the parties entitled to see them.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import AckType, OrgType
from aivs_server.db.models import ClientCertificate, TaxiiCollection
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1"


@pytest.fixture
async def isac(make_org, make_cert):
    org = await make_org("hosting-isac", org_type=OrgType.ADMIN)
    pem, _ = await make_cert(org)
    return org, pem


@pytest.fixture
async def member(make_org, make_cert):
    async def _build(slug: str = "meridian-global"):
        org = await make_org(slug, org_type=OrgType.GSIB)
        pem, _ = await make_cert(org)
        return org, pem

    return _build


# ---------------------------------------------------------------------------
# Enrolment is the ISAC's alone
# ---------------------------------------------------------------------------
async def test_member_cannot_enrol_an_organisation(client, member):
    """The endpoint that creates members must not be reachable by a member."""
    _org, pem = await member()
    response = await client.post(
        f"{API}/orgs",
        json={"slug": "rogue-firm", "name": "Rogue", "org_type": "gsib"},
        headers=proxy_headers(pem),
    )
    assert response.status_code == 403


async def test_isac_enrols_an_organisation_as_pending(client, isac, session):
    """Enrolment and activation are separate, so a half-finished onboarding
    cannot authenticate."""
    _org, pem = isac
    response = await client.post(
        f"{API}/orgs",
        json={"slug": "atlantic-clearing", "name": "Atlantic Clearing", "org_type": "section9"},
        headers=proxy_headers(pem),
    )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "pending"
    assert body["stix_identity_id"].startswith("identity--")


async def test_duplicate_slug_is_a_conflict_not_a_500(client, isac):
    _org, pem = isac
    payload = {"slug": "atlantic-clearing", "name": "Atlantic", "org_type": "section9"}
    first = await client.post(f"{API}/orgs", json=payload, headers=proxy_headers(pem))
    assert first.status_code == 201
    second = await client.post(f"{API}/orgs", json=payload, headers=proxy_headers(pem))
    assert second.status_code == 409


async def test_member_listing_shows_only_itself(client, isac, member):
    """A member must not be able to enumerate the instance's membership."""
    org, pem = await member()
    await client.post(
        f"{API}/orgs",
        json={"slug": "another-firm", "name": "Another", "org_type": "gsib"},
        headers=proxy_headers(isac[1]),
    )

    response = await client.get(f"{API}/orgs", headers=proxy_headers(pem))
    assert response.status_code == 200
    assert [entry["id"] for entry in response.json()] == [str(org.id)]


async def test_suspension_takes_effect_on_the_next_request(client, isac, member, session):
    """Suspending an organisation is a single field change with immediate effect."""
    org, member_pem = await member()
    _isac_org, isac_pem = isac

    assert (await client.get(f"{API}/whoami", headers=proxy_headers(member_pem))).status_code == 200

    suspended = await client.post(f"{API}/orgs/{org.id}/suspend", headers=proxy_headers(isac_pem))
    assert suspended.status_code == 200
    assert suspended.json()["status"] == "suspended"

    after = await client.get(f"{API}/whoami", headers=proxy_headers(member_pem))
    assert after.status_code == 401


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------
async def test_registering_a_certificate_derives_the_fingerprint(client, isac, member, ca, session):
    """The fingerprint is computed from the certificate, never accepted as a parameter.

    A caller-supplied fingerprint that did not match would bind an identity to
    material nobody holds.
    """
    org, _member_pem = await member()
    _isac_org, isac_pem = isac
    pem, expected_fingerprint, _cert = ca.issue("meridian-global-second-key")

    response = await client.post(
        f"{API}/orgs/{org.id}/certificates",
        json={"certificate_pem": pem, "label": "rotation key"},
        headers=proxy_headers(isac_pem),
    )
    assert response.status_code == 201
    assert response.json()["fingerprint_sha256"] == expected_fingerprint


async def test_an_expired_certificate_is_refused_at_registration(client, isac, member, ca):
    org, _pem = await member()
    _isac_org, isac_pem = isac
    now = dt.datetime.now(dt.UTC)
    pem, _fp, _cert = ca.issue(
        "already-expired",
        not_before=now - dt.timedelta(days=400),
        not_after=now - dt.timedelta(days=1),
    )

    response = await client.post(
        f"{API}/orgs/{org.id}/certificates",
        json={"certificate_pem": pem},
        headers=proxy_headers(isac_pem),
    )
    assert response.status_code == 400


async def test_unparseable_certificate_is_a_400_not_a_traceback(client, isac, member):
    org, _pem = await member()
    _isac_org, isac_pem = isac

    response = await client.post(
        f"{API}/orgs/{org.id}/certificates",
        json={"certificate_pem": "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"},
        headers=proxy_headers(isac_pem),
    )
    assert response.status_code == 400


async def test_revocation_locks_the_holder_out_immediately(client, isac, member, session):
    """Revocation is authoritative in the database; no CRL round trip."""
    org, member_pem = await member()
    _isac_org, isac_pem = isac

    certificate = (
        await session.execute(select(ClientCertificate).where(ClientCertificate.org_id == org.id))
    ).scalar_one()

    assert (await client.get(f"{API}/whoami", headers=proxy_headers(member_pem))).status_code == 200

    revoked = await client.post(
        f"{API}/certificates/{certificate.id}/revoke", headers=proxy_headers(isac_pem)
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    after = await client.get(f"{API}/whoami", headers=proxy_headers(member_pem))
    assert after.status_code == 401


async def test_a_member_cannot_revoke_another_firms_certificate(client, isac, member, session):
    """Absent and forbidden answer alike, so certificate ids cannot be probed.

    404 rather than 403 deliberately: a 403 would confirm that the id names a
    real certificate, which is the existence oracle every other id-addressable
    endpoint here takes care to avoid.
    """
    victim, _victim_pem = await member("victim-firm")
    _attacker, attacker_pem = await member("attacker-firm")

    certificate = (
        await session.execute(
            select(ClientCertificate).where(ClientCertificate.org_id == victim.id)
        )
    ).scalar_one()

    response = await client.post(
        f"{API}/certificates/{certificate.id}/revoke", headers=proxy_headers(attacker_pem)
    )
    assert response.status_code == 404

    unknown = await client.post(
        f"{API}/certificates/{uuid.uuid4()}/revoke", headers=proxy_headers(attacker_pem)
    )
    assert unknown.status_code == response.status_code, "the two must be indistinguishable"
    assert unknown.text == response.text


# ---------------------------------------------------------------------------
# Circles
# ---------------------------------------------------------------------------
async def test_creating_a_circle_creates_its_collection(client, isac, session):
    """A circle with no collection is invisible over TAXII -- a confusing
    half-configured state for members to hit."""
    _org, pem = isac
    response = await client.post(
        f"{API}/circles",
        json={"slug": "section9", "name": "Section 9", "minimum_tlp": "amber_strict"},
        headers=proxy_headers(pem),
    )
    assert response.status_code == 201
    circle_id = uuid.UUID(response.json()["id"])

    collection = (
        await session.execute(select(TaxiiCollection).where(TaxiiCollection.circle_id == circle_id))
    ).scalar_one_or_none()
    assert collection is not None


async def test_member_cannot_create_a_circle(client, member):
    _org, pem = await member()
    response = await client.post(
        f"{API}/circles",
        json={"slug": "self-serve", "name": "Self Serve"},
        headers=proxy_headers(pem),
    )
    assert response.status_code == 403


async def test_member_sees_only_circles_it_belongs_to(
    client, isac, member, make_circle, join_circle
):
    """Which communities exist, and who convenes around what, is itself sensitive."""
    org, pem = await member()
    mine = await make_circle("mine")
    await make_circle("not-mine")
    await join_circle(org, mine)

    response = await client.get(f"{API}/circles", headers=proxy_headers(pem))
    assert response.status_code == 200
    assert [entry["slug"] for entry in response.json()] == ["mine"]


async def test_isac_can_add_and_remove_circle_members(client, isac, member, make_circle, session):
    org, member_pem = await member()
    _isac_org, isac_pem = isac
    circle = await make_circle("section9")

    added = await client.post(
        f"{API}/circles/{circle.id}/members",
        json={"org_id": str(org.id), "role": "contributor"},
        headers=proxy_headers(isac_pem),
    )
    assert added.status_code == 204

    seen = await client.get(f"{API}/whoami", headers=proxy_headers(member_pem))
    assert [c["role"] for c in seen.json()["circles"]] == ["contributor"]

    removed = await client.delete(
        f"{API}/circles/{circle.id}/members/{org.id}", headers=proxy_headers(isac_pem)
    )
    assert removed.status_code == 204

    after = await client.get(f"{API}/whoami", headers=proxy_headers(member_pem))
    assert after.json()["circles"] == []


async def test_duplicate_membership_is_a_conflict(client, isac, member, make_circle):
    org, _pem = await member()
    _isac_org, isac_pem = isac
    circle = await make_circle("section9")
    body = {"org_id": str(org.id)}

    first = await client.post(
        f"{API}/circles/{circle.id}/members", json=body, headers=proxy_headers(isac_pem)
    )
    assert first.status_code == 204
    second = await client.post(
        f"{API}/circles/{circle.id}/members", json=body, headers=proxy_headers(isac_pem)
    )
    assert second.status_code == 409


# ---------------------------------------------------------------------------
# Acknowledgments and receipts
# ---------------------------------------------------------------------------
async def test_a_member_cannot_assert_that_they_retrieved_something(
    client, member, make_circle, join_circle, publish
):
    """`retrieved` is written by the server on actual delivery.

    Accepting it here would let a firm manufacture evidence of a delivery that
    never happened -- exactly the record this table exists to be trusted about.
    """
    org, pem = await member()
    circle = await make_circle("section9")
    await join_circle(org, circle)
    submission, _obj, _dist = await publish(org, circle)

    response = await client.post(
        f"{API}/acknowledgments",
        json={"submission_id": str(submission.id), "ack_type": "retrieved"},
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400, "retrieved is not an accepted value"


async def test_a_member_cannot_acknowledge_content_never_delivered_to_them(
    client, member, make_circle, publish
):
    """Acknowledging by id must not confirm that the id exists."""
    owner, _owner_pem = await member("meridian-global")
    circle = await make_circle("section9")
    submission, _obj, _dist = await publish(owner, circle)

    _outsider, outsider_pem = await member("outsider-firm")
    response = await client.post(
        f"{API}/acknowledgments",
        json={"submission_id": str(submission.id), "ack_type": "acknowledged"},
        headers=proxy_headers(outsider_pem),
    )
    assert response.status_code == 404


async def test_receipts_record_retrieval_then_action(
    client, member, make_circle, join_circle, make_collection, publish
):
    """The regulatory artefact, end to end: delivered, then acted on."""
    org, pem = await member()
    circle = await make_circle("section9")
    await join_circle(org, circle)
    collection = await make_collection(circle)
    submission, _obj, _dist = await publish(org, circle)

    # Collecting the content writes the retrieval receipt.
    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )
    assert feed.status_code == 200

    actioned = await client.post(
        f"{API}/acknowledgments",
        json={
            "submission_id": str(submission.id),
            "ack_type": "actioned",
            "note": "Patched across the estate",
        },
        headers=proxy_headers(pem),
    )
    assert actioned.status_code == 201

    receipts = await client.get(
        f"{API}/submissions/{submission.id}/receipts", headers=proxy_headers(pem)
    )
    assert receipts.status_code == 200
    by_type = {entry["ack_type"]: entry for entry in receipts.json()}
    assert by_type[AckType.RETRIEVED.value]["via"] == "taxii"
    assert by_type[AckType.ACTIONED.value]["via"] == "api"
    assert by_type[AckType.RETRIEVED.value]["org_slug"] == "meridian-global"


async def test_receipts_are_not_visible_to_other_members(
    client, member, make_circle, join_circle, publish
):
    """Which firms attend to which threats is not an inference members may draw
    about each other.

    Reported as 404, not 403, and identically to an id that does not exist.
    Distinguishing the two would make this endpoint an existence oracle over the
    whole submission namespace for any authenticated member -- undoing the care
    the sibling endpoints take to collapse both cases.
    """
    owner, _owner_pem = await member("meridian-global")
    circle = await make_circle("section9")
    await join_circle(owner, circle)
    submission, _obj, _dist = await publish(owner, circle)

    other, other_pem = await member("atlantic-clearing")
    await join_circle(other, circle)

    real = await client.get(
        f"{API}/submissions/{submission.id}/receipts", headers=proxy_headers(other_pem)
    )
    assert real.status_code == 404

    invented = await client.get(
        f"{API}/submissions/{uuid.uuid4()}/receipts", headers=proxy_headers(other_pem)
    )
    assert invented.status_code == 404
    assert real.text == invented.text, "a real id must be indistinguishable from an invented one"


async def test_the_isac_can_read_receipts(client, isac, member, make_circle, join_circle, publish):
    """The ISAC must be able to answer 'prove we warned member X'."""
    org, _pem = await member()
    _isac_org, isac_pem = isac
    circle = await make_circle("section9")
    await join_circle(org, circle)
    submission, _obj, _dist = await publish(org, circle)

    response = await client.get(
        f"{API}/submissions/{submission.id}/receipts", headers=proxy_headers(isac_pem)
    )
    assert response.status_code == 200
