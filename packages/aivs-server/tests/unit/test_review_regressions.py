"""Regressions from the sharded security review.

Each test here is a defect that was found, confirmed and fixed. They are grouped
by the property that was broken rather than by the module that broke it, because
the property is what a future change has to keep.

Where a fix changed behaviour that another test already covered, the change was
made there instead; this file is for properties that had no test at all.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import CertStatus, OrgStatus, OrgType
from aivs_schemas.extension.builders import UnknownExtensionError, validate_bundle
from aivs_schemas.tlp import TLP_MARKING_IDS
from aivs_server.db.models import ClientCertificate, Organization
from tests.conftest import proxy_headers

API = "/api/v1"


# ---------------------------------------------------------------------------
# Inbound content cannot redefine what other content means
# ---------------------------------------------------------------------------
def _bundle(*objects: dict) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(objects)}


def _vulnerability() -> dict:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": "2026-08-01T00:00:00.000Z",
        "modified": "2026-08-01T00:00:00.000Z",
        "name": "Prompt injection in agent runtime",
    }


def test_a_submitted_extension_definition_is_refused():
    """AIVS publishes its own definition; a submitted one redefines it.

    An extension-definition SDO carries no `extensions` property of its own, so
    it passed the allowlist untouched and was stored and served verbatim. One
    re-declaring the AIVS extension id with a `schema` URL of the submitter's
    choosing would put that address into every consuming platform in the circle.
    """
    forged = {
        "type": "extension-definition",
        "spec_version": "2.1",
        "id": "extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6",
        "created": "2026-08-01T00:00:00.000Z",
        "modified": "2026-08-01T00:00:00.000Z",
        "name": "AIVS Pre-CVE AI Vulnerability Extension",
        "schema": "https://attacker.example/schema.json",
        "extension_types": ["property-extension"],
    }
    with pytest.raises(UnknownExtensionError, match="extension-definition"):
        validate_bundle(_bundle(_vulnerability(), forged))


@pytest.mark.parametrize("marking_id", sorted(TLP_MARKING_IDS.values()))
def test_a_marking_definition_reusing_a_tlp_identifier_is_refused(marking_id):
    """TLP identifiers mean one thing everywhere; that is the whole point of them.

    An object claiming the TLP:RED identifier with a TLP:CLEAR body would turn
    the most restrictive handling instruction into the least restrictive one, on
    content already distributed under it.
    """
    forged = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": "2022-10-01T00:00:00.000Z",
        "name": "TLP:CLEAR",
    }
    with pytest.raises(UnknownExtensionError, match="specification-fixed"):
        validate_bundle(_bundle(_vulnerability(), forged))


def test_an_extension_nested_inside_an_object_is_refused():
    """The allowlist reaches nested objects, not only the top level.

    An observed-data SDO's `objects` property holds embedded SCOs, each of which
    may declare extensions of its own. Checking only the top level meant such a
    bundle passed untouched and was redistributed verbatim -- the delivery
    mechanism the allowlist exists to prevent, reached one level down.
    """
    observed = {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": f"observed-data--{uuid.uuid4()}",
        "created": "2026-08-01T00:00:00.000Z",
        "modified": "2026-08-01T00:00:00.000Z",
        "first_observed": "2026-08-01T00:00:00.000Z",
        "last_observed": "2026-08-01T00:00:00.000Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "file",
                "name": "payload.bin",
                "extensions": {
                    "extension-definition--99999999-9999-4999-8999-999999999999": {
                        "anything": "at all"
                    }
                },
            }
        },
    }
    with pytest.raises(UnknownExtensionError, match="nested"):
        validate_bundle(_bundle(observed))


def test_an_ordinary_nested_object_still_validates():
    """The recursion must not refuse content that carries no extension."""
    observed = {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": f"observed-data--{uuid.uuid4()}",
        "created": "2026-08-01T00:00:00.000Z",
        "modified": "2026-08-01T00:00:00.000Z",
        "first_observed": "2026-08-01T00:00:00.000Z",
        "last_observed": "2026-08-01T00:00:00.000Z",
        "number_observed": 1,
        "objects": {"0": {"type": "file", "name": "payload.bin"}},
    }
    assert validate_bundle(_bundle(observed)) == 1


# ---------------------------------------------------------------------------
# Portal login is not a credential oracle for a revoked certificate
# ---------------------------------------------------------------------------
@pytest.mark.db
class TestPortalLoginChecksStatus:
    """A revoked certificate must not reach the credential check.

    nginx has no CRL -- revocation is authoritative in the database -- so the
    holder of a revoked certificate still completes the TLS handshake. The login
    route resolved the organisation without consulting either status, so it ran
    the full password and TOTP check and could distinguish a correct credential
    from a wrong one by the 303 it returned: an oracle for precisely the
    compromised-certificate case revocation exists for.
    """

    LOGIN = "/portal/login"

    async def _post(self, client, pem):
        page = await client.get(self.LOGIN, headers=proxy_headers(pem))
        assert page.status_code == 200
        return await client.post(
            self.LOGIN,
            data={
                "email": "analyst@example.test",
                "password": "whatever",
                "totp_code": "000000",
                "csrf_token": "irrelevant",
            },
            headers=proxy_headers(pem),
        )

    async def test_a_revoked_certificate_cannot_reach_the_credential_check(
        self, client, make_org, make_cert, session
    ):
        org = await make_org("revoked-firm", org_type=OrgType.GSIB)
        pem, _ = await make_cert(org)

        row = (
            await session.execute(
                select(ClientCertificate).where(ClientCertificate.org_id == org.id)
            )
        ).scalar_one()
        row.status = CertStatus.REVOKED
        # ck_client_certificates_revocation_consistent requires the timestamp
        # and the status to agree, so a revoked row always says when.
        row.revoked_at = dt.datetime.now(dt.UTC)
        row.revoked_reason = "stolen"
        await session.commit()

        response = await self._post(client, pem)
        assert response.status_code != 303, "a revoked certificate must not establish a session"

    async def test_a_suspended_organisation_cannot_reach_the_credential_check(
        self, client, make_org, make_cert, session
    ):
        org = await make_org("suspended-firm", org_type=OrgType.GSIB)
        pem, _ = await make_cert(org)

        row = await session.get(Organization, org.id)
        assert row is not None
        row.status = OrgStatus.SUSPENDED
        await session.commit()

        response = await self._post(client, pem)
        assert response.status_code != 303


# ---------------------------------------------------------------------------
# One member's object cannot suppress another's
# ---------------------------------------------------------------------------
@pytest.mark.db
async def test_a_peer_cannot_take_over_the_default_feed_for_a_shared_stix_id(
    client, make_org, make_cert, make_circle, make_collection, join_circle, publish
):
    """`match[version]=last` resolves per submission, not across the circle.

    stix_objects uniqueness is deliberately per submission -- two organisations
    may legitimately hold the same stix_id, which is why the write path keys its
    dedupe on the concrete object id. Resolving max(modified) across every
    submission undid that on the read side, and since `last` is the default when
    match[version] is absent, a member who re-submitted a peer's stix_id with a
    later timestamp took over the default feed and the peer's warning stopped
    being delivered.
    """
    victim = await make_org("victim-firm", org_type=OrgType.GSIB)
    rival = await make_org("rival-firm", org_type=OrgType.GSIB)
    reader = await make_org("reader-firm", org_type=OrgType.GSIB)
    reader_pem, _ = await make_cert(reader)

    circle = await make_circle("section9")
    collection = await make_collection(circle)
    for org in (victim, rival, reader):
        await join_circle(org, circle)

    shared_id = f"vulnerability--{uuid.uuid4()}"
    earlier = dt.datetime(2026, 8, 1, 12, 0, tzinfo=dt.UTC)

    await publish(victim, circle, stix_id=shared_id, name="Victim warning", modified=earlier)
    await publish(
        rival,
        circle,
        stix_id=shared_id,
        name="Rival overwrite",
        modified=earlier + dt.timedelta(seconds=1),
    )

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(reader_pem)
    )
    assert feed.status_code == 200, feed.text

    names = {obj.get("name") for obj in feed.json()["objects"]}
    assert "Victim warning" in names, "a peer's later object must not suppress this one"
    assert "Rival overwrite" in names


# ---------------------------------------------------------------------------
# Joining a circle grants participation, not the archive
# ---------------------------------------------------------------------------
@pytest.mark.db
async def test_a_new_member_does_not_receive_the_circles_back_catalogue(
    client, make_org, make_cert, make_circle, make_collection, join_circle, publish
):
    """Membership start bounds visibility.

    Without it, adding an organisation to a circle handed them every object ever
    distributed there -- years of other firms' embargoed intelligence, at that
    circle's TLP floor, retroactively and in one call. "Add them to the group"
    must not silently mean "give them the archive".
    """
    incumbent = await make_org("incumbent-firm", org_type=OrgType.GSIB)
    newcomer = await make_org("newcomer-firm", org_type=OrgType.GSIB)
    newcomer_pem, _ = await make_cert(newcomer)

    circle = await make_circle("section9")
    collection = await make_collection(circle)
    await join_circle(incumbent, circle)

    # History, then the moment the newcomer joins, then new content.
    await publish(
        incumbent,
        circle,
        name="Historic warning",
        date_added=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
    )
    joined = dt.datetime(2026, 6, 1, tzinfo=dt.UTC)
    await join_circle(newcomer, circle, joined_at=joined)
    await publish(
        incumbent,
        circle,
        name="Current warning",
        date_added=dt.datetime(2026, 7, 1, tzinfo=dt.UTC),
    )

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(newcomer_pem)
    )
    assert feed.status_code == 200, feed.text
    names = {obj.get("name") for obj in feed.json()["objects"]}

    assert "Current warning" in names, "content shared after they joined"
    assert "Historic warning" not in names, "the back catalogue is not theirs"


@pytest.mark.db
async def test_content_distributed_exactly_at_the_join_moment_is_included(
    client, make_org, make_cert, make_circle, make_collection, join_circle, publish
):
    """The bound is inclusive, so a member does not miss the batch they joined for.

    An organisation is often added to a circle precisely so it receives
    something being distributed right then; an exclusive bound would drop it.
    """
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    circle = await make_circle("section9")
    collection = await make_collection(circle)

    moment = dt.datetime(2026, 6, 1, tzinfo=dt.UTC)
    await join_circle(org, circle, joined_at=moment)
    await publish(org, circle, name="Joined for this", date_added=moment)

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )
    assert [obj["name"] for obj in feed.json()["objects"]] == ["Joined for this"]


@pytest.mark.db
async def test_each_circle_is_bounded_by_its_own_join_time(
    client, make_org, make_cert, make_circle, make_collection, join_circle, publish
):
    """An early membership in one circle must not unlock another's history."""
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)

    old_circle = await make_circle("gsib")
    new_circle = await make_circle("section9")
    old_collection = await make_collection(old_circle)
    new_collection = await make_collection(new_circle)

    await join_circle(org, old_circle, joined_at=dt.datetime(2020, 1, 1, tzinfo=dt.UTC))
    await join_circle(org, new_circle, joined_at=dt.datetime(2026, 6, 1, tzinfo=dt.UTC))

    old_content = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    await publish(org, old_circle, name="Long-standing circle", date_added=old_content)
    await publish(org, new_circle, name="Newly joined circle", date_added=old_content)

    long_standing = await client.get(
        f"/taxii2/aivs/collections/{old_collection.id}/objects/", headers=proxy_headers(pem)
    )
    assert [o["name"] for o in long_standing.json()["objects"]] == ["Long-standing circle"]

    newly_joined = await client.get(
        f"/taxii2/aivs/collections/{new_collection.id}/objects/", headers=proxy_headers(pem)
    )
    assert newly_joined.json().get("objects", []) == [], (
        "the earlier membership must not widen this circle"
    )


@pytest.mark.db
async def test_a_collection_marked_unreadable_serves_nothing(
    client, make_org, make_cert, make_circle, make_collection, join_circle, publish
):
    """can_read is enforced, not merely reported.

    The flag was stored and advertised in the collection resource while nothing
    consulted it, so a collection marked unreadable served its circle's full
    content anyway.
    """
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    circle = await make_circle("section9")
    collection = await make_collection(circle, can_read=False)
    await join_circle(org, circle)
    await publish(org, circle, name="Should not be served")

    response = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )
    assert response.status_code == 404, "absent, exactly as a circle the caller is not in"


# ---------------------------------------------------------------------------
# Attribution is the server's to assign
# ---------------------------------------------------------------------------
@pytest.mark.db
async def test_a_member_cannot_publish_under_another_firms_identity(
    isac, client, make_org, make_cert, make_circle, make_collection, join_circle, session
):
    """created_by_ref is rewritten to the submitter on the attributed path too.

    Ingest never inspected the field, so a member could name any identity they
    liked -- including a peer's, which is readable from any object that peer has
    shared into a common circle. Every member of the target circles would receive
    the finding attributed to a firm that never filed it, and because no
    consumer-facing surface exposes submitter_org_id, the named firm could
    neither see nor contest it.
    """
    submitter = await make_org("actual-submitter", org_type=OrgType.GSIB)
    submitter_pem, _ = await make_cert(submitter)
    victim = await make_org("impersonated-firm", org_type=OrgType.GSIB)
    _isac_org, isac_headers = isac

    circle = await make_circle("section9")
    collection = await make_collection(circle)
    await join_circle(submitter, circle)

    obj = _vulnerability()
    obj["created_by_ref"] = victim.stix_identity_id

    created = await client.post(
        f"{API}/submissions",
        json={
            "title": "Filed in someone else's name",
            "discovery_scope": "ai_system",
            "bundle": _bundle(obj),
        },
        headers=proxy_headers(submitter_pem),
    )
    assert created.status_code == 201, created.text
    submission_id = created.json()["id"]

    for verb, headers in (("submit", proxy_headers(submitter_pem)), ("validate", isac_headers)):
        step = await client.post(
            f"{API}/submissions/{submission_id}/{verb}", json={}, headers=headers
        )
        assert step.status_code == 200, step.text

    distributed = await client.post(
        f"{API}/submissions/{submission_id}/distribute",
        json={"circle_ids": [str(circle.id)]},
        headers=isac_headers,
    )
    assert distributed.status_code == 200, distributed.text

    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(submitter_pem)
    )
    served = feed.json()["objects"][0]
    assert served["created_by_ref"] == submitter.stix_identity_id
    assert served["created_by_ref"] != victim.stix_identity_id


# ---------------------------------------------------------------------------
# An elapsed embargo cannot be reinstated
# ---------------------------------------------------------------------------
@pytest.mark.db
async def test_an_embargo_whose_time_has_passed_cannot_be_extended(
    isac, client, make_org, make_cert, make_circle, make_collection, join_circle, session
):
    """Visibility is the timestamp; status is only what the sweeper wrote.

    Between the release moment passing and the sweeper's next pass, an embargo is
    still PENDING while its content is already being served. Testing only the
    status let an extension in that window move content members had already
    retrieved back into the future.
    """
    from aivs_server.db.models import Distribution, Embargo  # noqa: PLC0415 - local to this test

    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    member_pem, _ = await make_cert(member)
    _isac_org, isac_headers = isac
    circle = await make_circle("section9")
    await make_collection(circle)
    await join_circle(member, circle)

    created = await client.post(
        f"{API}/submissions",
        json={
            "title": "Embargoed finding",
            "discovery_scope": "ai_system",
            "bundle": _bundle(_vulnerability()),
        },
        headers=proxy_headers(member_pem),
    )
    submission_id = created.json()["id"]

    for verb, headers in (("submit", proxy_headers(member_pem)), ("validate", isac_headers)):
        assert (
            await client.post(f"{API}/submissions/{submission_id}/{verb}", json={}, headers=headers)
        ).status_code == 200

    release_at = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)
    distributed = await client.post(
        f"{API}/submissions/{submission_id}/distribute",
        json={"circle_ids": [str(circle.id)], "release_at": release_at.isoformat()},
        headers=isac_headers,
    )
    assert distributed.status_code == 200, distributed.text

    # The release moment passes, but the sweeper has not run: status is still
    # pending while the content is already readable.
    elapsed = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
    embargo = (
        await session.execute(
            select(Embargo).where(Embargo.submission_id == uuid.UUID(submission_id))
        )
    ).scalar_one()
    embargo.release_at = elapsed
    for row in (
        (
            await session.execute(
                select(Distribution).where(Distribution.submission_id == uuid.UUID(submission_id))
            )
        )
        .scalars()
        .all()
    ):
        row.date_added = elapsed
    await session.commit()

    extended = await client.post(
        f"{API}/submissions/{submission_id}/embargo/extend",
        json={"release_at": (dt.datetime.now(dt.UTC) + dt.timedelta(days=7)).isoformat()},
        headers=isac_headers,
    )
    assert extended.status_code >= 400, "already-readable content cannot be retracted"

    still_visible = (
        (
            await session.execute(
                select(Distribution.date_added).where(
                    Distribution.submission_id == uuid.UUID(submission_id)
                )
            )
        )
        .scalars()
        .all()
    )
    assert all(stamp <= dt.datetime.now(dt.UTC) for stamp in still_visible), (
        "no row may have been pushed back into the future"
    )
