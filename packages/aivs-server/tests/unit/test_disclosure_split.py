"""The disclosure split: contributions about another party's vulnerability (SF-7, SF-47, SF-24).

``disclosed_third_party`` is legal once the ISAC's canonical record says the
vulnerability is public; ``coordinated_disclosure`` while its vendor is a party
to the case or a CERT case covers it. Every rule is decided by the canonical
target's current state, never by the submitter's bundle. Each property is
tested in pairs, and the refusals that could leak a pre-CVE finding are
compared byte for byte.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy import func, select, update

from aivs_schemas.enums import OrgType, SubmissionState
from aivs_schemas.extension.builders import AIVS_EXTENSION_ID
from aivs_server.db.models import Distribution, StixObject, Submission
from tests.unit.contribution_world import (
    LATER,
    STAMP,
    course_of_action_about,
    distribute,
    file,
    opinion_about,
    seed,
    submit_and_validate,
    vulnerability_raw,
)

pytestmark = pytest.mark.db


def new_vulnerability_id() -> str:
    return f"vulnerability--{uuid.uuid4()}"


@pytest.fixture
async def world(make_org, make_cert, make_circle, join_circle, isac, isac_org):
    """A member and a vendor in one circle with the ISAC; a member outside it."""
    circle = await make_circle("coordination")
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    member_pem, _ = await make_cert(member)
    outsider = await make_org("atlantic-clearing", org_type=OrgType.GSIB)
    outsider_pem, _ = await make_cert(outsider)
    vendor = await make_org("acme-software", org_type=OrgType.VENDOR)
    vendor_pem, _ = await make_cert(vendor)
    for org in (member, isac_org):
        await join_circle(org, circle)
    _isac_org, editor = isac
    return {
        "circle": circle,
        "member": (member, member_pem),
        "outsider": (outsider, outsider_pem),
        "vendor": (vendor, vendor_pem),
        "editor": editor,
        "isac_org": isac_org,
        "join_circle": join_circle,
    }


async def canonical(session, world, *, cve_status: str, **extra: Any) -> str:
    stix_id = new_vulnerability_id()
    await seed(
        session,
        world["isac_org"],
        vulnerability_raw(stix_id, cve_status=cve_status, **extra),
        circle=world["circle"],
    )
    return stix_id


async def submission_count(session) -> int:
    return await session.scalar(select(func.count()).select_from(Submission))


# ---------------------------------------------------------------------------
# disclosed_third_party
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-7")
async def test_a_workaround_on_a_public_vulnerability_is_filed_validated_and_distributed(
    client, session, world
):
    target = await canonical(session, world, cve_status="published")
    _member, pem = world["member"]

    filed = await file(client, pem, course_of_action_about(target), scope="disclosed_third_party")
    assert filed.status_code == 201, filed.text
    validated = await submit_and_validate(client, pem, filed.json()["id"], world["editor"])
    assert validated.status_code == 200, validated.text
    distributed = await distribute(client, filed.json()["id"], world["editor"], world["circle"])

    assert distributed.status_code == 200, distributed.text


@pytest.mark.requirement("SF-7")
async def test_a_contribution_on_a_vulnerability_not_yet_public_is_refused(client, session, world):
    target = await canonical(session, world, cve_status="pre-cve")
    _member, pem = world["member"]

    filed = await file(client, pem, course_of_action_about(target), scope="disclosed_third_party")

    assert filed.status_code == 400
    assert "not public yet" in filed.json()["title"]


@pytest.mark.requirement("SF-7")
async def test_a_target_withdrawn_from_disclosure_after_validation_stops_the_distribution(
    client, session, world
):
    """Checked against the target's current state at distribution, not at filing."""
    target = await canonical(session, world, cve_status="published")
    _member, pem = world["member"]
    filed = await file(client, pem, course_of_action_about(target), scope="disclosed_third_party")
    validated = await submit_and_validate(client, pem, filed.json()["id"], world["editor"])
    assert validated.status_code == 200, validated.text

    await seed(
        session,
        world["isac_org"],
        vulnerability_raw(target, cve_status="requested", modified=LATER),
        circle=world["circle"],
    )
    refused = await distribute(client, filed.json()["id"], world["editor"], world["circle"])

    assert refused.status_code == 409
    assert "not public yet" in refused.json()["title"]


async def test_a_third_party_contribution_may_not_carry_a_vulnerability_of_its_own(
    client, session, world
):
    target = await canonical(session, world, cve_status="published")
    _member, pem = world["member"]
    own = vulnerability_raw(new_vulnerability_id(), cve_status="published")
    del own["extensions"]

    filed = await file(
        client, pem, [own, *course_of_action_about(target)], scope="disclosed_third_party"
    )

    assert filed.status_code == 400
    assert "carries no vulnerability of its own" in filed.json()["title"]


# ---------------------------------------------------------------------------
# The uniform refusal (SF-47)
# ---------------------------------------------------------------------------
async def refusal_for(client, pem, target):
    response = await file(
        client, pem, course_of_action_about(target), scope="disclosed_third_party"
    )
    assert response.status_code == 400
    return response.content


@pytest.mark.requirement("SF-47")
async def test_an_invisible_target_and_an_absent_one_are_refused_identically(
    client, session, world
):
    """Seen only by the circle the outsider is not in: the refusal must not tell."""
    target = await canonical(session, world, cve_status="published")
    _outsider, pem = world["outsider"]

    assert await refusal_for(client, pem, target) == await refusal_for(
        client, pem, new_vulnerability_id()
    )
    assert target.encode() not in await refusal_for(client, pem, target)


@pytest.mark.requirement("SF-47")
async def test_the_same_target_is_accepted_from_a_member_that_can_see_it(client, session, world):
    target = await canonical(session, world, cve_status="published")
    _member, pem = world["member"]

    filed = await file(client, pem, course_of_action_about(target), scope="disclosed_third_party")

    assert filed.status_code == 201, filed.text


@pytest.mark.requirement("SF-47")
async def test_a_members_own_record_of_an_id_is_not_the_canonical_target(client, session, world):
    """A member's pre-CVE finding under an id is not the ISAC's record of it."""
    member, pem = world["member"]
    target = new_vulnerability_id()
    await seed(
        session, member, vulnerability_raw(target, cve_status="published"), circle=world["circle"]
    )

    assert await refusal_for(client, pem, target) == await refusal_for(
        client, pem, new_vulnerability_id()
    )


# ---------------------------------------------------------------------------
# coordinated_disclosure
# ---------------------------------------------------------------------------
async def coordinated(client, pem, target):
    return await file(client, pem, course_of_action_about(target), scope="coordinated_disclosure")


async def test_a_coordinated_contribution_with_no_case_is_refused(client, session, world):
    target = await canonical(session, world, cve_status="pre-cve")
    _member, pem = world["member"]

    filed = await coordinated(client, pem, target)

    assert filed.status_code == 400
    assert "no coordination case" in filed.json()["title"]


async def test_a_cert_case_on_the_canonical_record_admits_a_coordinated_contribution(
    client, session, world
):
    target = await canonical(
        session,
        world,
        cve_status="pre-cve",
        external_references=[{"source_name": "vince", "external_id": "VU#123456"}],
    )
    _member, pem = world["member"]

    assert (await coordinated(client, pem, target)).status_code == 201


async def vendor_says(session, world, target, opinion):
    vendor, _pem = world["vendor"]
    await seed(session, vendor, opinion_about(target, opinion=opinion), circle=world["circle"])


async def test_a_vendor_party_that_agreed_admits_a_coordinated_contribution(
    client, session, world, join_circle
):
    target = await canonical(session, world, cve_status="pre-cve")
    vendor, _pem = world["vendor"]
    await join_circle(vendor, world["circle"])
    await vendor_says(session, world, target, "agree")
    _member, pem = world["member"]

    assert (await coordinated(client, pem, target)).status_code == 201


async def _ingest_answer_before_and_after(client, session, world, place_the_opinion):
    """The member's ingest answer for one target, without an opinion and then with one."""
    target = await canonical(session, world, cve_status="pre-cve")
    vendor, _pem = world["vendor"]
    await join_circle_of(world, vendor)
    _member, pem = world["member"]

    before = await coordinated(client, pem, target)
    await place_the_opinion(target)
    after = await coordinated(client, pem, target)
    return before, after


async def join_circle_of(world, org):
    await world["join_circle"](org, world["circle"])


@pytest.mark.requirement("SF-47")
async def test_an_embargoed_vendor_opinion_gives_the_ingest_answer_no_opinion_gives(
    client, session, world
):
    """At ingest the vendor's agreement counts only once the member could read it.

    Counted globally, an agreeing opinion still under embargo admitted the
    member's coordinated contribution, and the acceptance itself told the member
    that the vendor had agreed before the ISAC released it.
    """

    async def embargoed(target):
        vendor, _pem = world["vendor"]
        submission = await seed(
            session, vendor, opinion_about(target, opinion="agree"), circle=world["circle"]
        )
        await session.execute(
            update(Distribution)
            .where(Distribution.submission_id == submission.id)
            .values(date_added=dt.datetime.now(dt.UTC) + dt.timedelta(days=7))
        )
        await session.commit()

    before, after = await _ingest_answer_before_and_after(client, session, world, embargoed)

    assert before.status_code == 400
    assert after.content == before.content


@pytest.mark.requirement("SF-47")
async def test_a_vendor_opinion_outside_the_members_circles_gives_the_answer_none_gives(
    client, session, world, make_circle
):
    elsewhere = await make_circle("vendor-and-isac-only")

    async def in_another_circle(target):
        vendor, _pem = world["vendor"]
        await world["join_circle"](vendor, elsewhere)
        await seed(session, vendor, opinion_about(target, opinion="agree"), circle=elsewhere)

    before, after = await _ingest_answer_before_and_after(client, session, world, in_another_circle)

    assert before.status_code == 400
    assert after.content == before.content


@pytest.mark.requirement("SF-47")
async def test_a_vendor_placed_only_where_the_member_cannot_read_gives_the_answer_none_gives(
    client, session, world, make_circle
):
    """The vendor is a party through a circle the target reached that the member reads.

    The member can read the vendor's agreement here; what it cannot see is the
    circle that makes the vendor a party, and acceptance must not tell it that.
    """
    target = await canonical(session, world, cve_status="pre-cve")
    elsewhere = await make_circle("vendor-and-isac-only")
    vendor, _pem = world["vendor"]
    await world["join_circle"](vendor, elsewhere)
    canonical_row = await session.scalar(select(StixObject).where(StixObject.stix_id == target))
    session.add(
        Distribution(
            stix_object_id=canonical_row.id,
            circle_id=elsewhere.id,
            submission_id=canonical_row.submission_id,
            date_added=dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1),
        )
    )
    await session.commit()
    _member, pem = world["member"]

    before = await coordinated(client, pem, target)
    await vendor_says(session, world, target, "agree")
    after = await coordinated(client, pem, target)

    assert before.status_code == 400
    assert after.content == before.content


@pytest.mark.requirement("SF-47")
async def test_a_vendor_opinion_the_member_can_read_admits_the_coordinated_contribution(
    client, session, world
):
    async def readable(target):
        await vendor_says(session, world, target, "agree")

    before, after = await _ingest_answer_before_and_after(client, session, world, readable)

    assert before.status_code == 400
    assert after.status_code == 201, after.text


async def test_a_vendor_that_disputes_is_not_an_acknowledging_party(
    client, session, world, join_circle
):
    target = await canonical(session, world, cve_status="pre-cve")
    vendor, _pem = world["vendor"]
    await join_circle(vendor, world["circle"])
    await vendor_says(session, world, target, "disagree")
    _member, pem = world["member"]

    assert (await coordinated(client, pem, target)).status_code == 400


async def test_a_vendor_opinion_without_the_editor_placing_the_vendor_does_not_count(
    client, session, world
):
    """The vendor is a party because an editor put it in the case's circle."""
    target = await canonical(session, world, cve_status="pre-cve")
    await vendor_says(session, world, target, "agree")
    _member, pem = world["member"]

    assert (await coordinated(client, pem, target)).status_code == 400


async def test_a_case_the_submitter_writes_into_its_own_bundle_does_not_count(
    client, session, world
):
    target = await canonical(session, world, cve_status="pre-cve")
    _member, pem = world["member"]
    claims = [
        *course_of_action_about(target),
        opinion_about(target, opinion="strongly-agree"),
    ]
    claims[0]["external_references"] = [{"source_name": "vince", "external_id": "VU#999999"}]

    filed = await file(client, pem, claims, scope="coordinated_disclosure")

    assert filed.status_code == 400


# ---------------------------------------------------------------------------
# A finder's own scopes need no target; one bad object refuses the bundle (SF-24)
# ---------------------------------------------------------------------------
def finding(scope: str) -> dict:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": new_vulnerability_id(),
        "created": STAMP,
        "modified": STAMP,
        "name": "A finding",
        "extensions": {
            AIVS_EXTENSION_ID: {
                "extension_type": "property-extension",
                "aivs_schema_version": "1.0",
                "discovery_scope": scope,
                "cve_status": "pre-cve",
                "affected_products": [{"vendor": "Acme", "product": "Gateway"}],
            }
        },
    }


@pytest.mark.parametrize("scope", ["own_product", "own_estate", "ai_system"])
async def test_a_finders_own_scopes_need_no_target(client, world, scope):
    _member, pem = world["member"]

    assert (await file(client, pem, [finding(scope)], scope=scope)).status_code == 201


async def test_an_unknown_scope_is_refused_by_the_request_model(client, world):
    _member, pem = world["member"]

    assert (
        await file(client, pem, [finding("own_product")], scope="never_heard_of_it")
    ).status_code == 400


@pytest.mark.requirement("SF-24")
async def test_one_object_with_a_refused_scope_refuses_the_whole_bundle(client, session, world):
    """A vulnerability's own extension may declare only a finder's scope; one that
    declares a third-party scope refuses the bundle, including the object that was fine."""
    _member, pem = world["member"]

    filed = await file(
        client, pem, [finding("own_product"), finding("disclosed_third_party")], scope="own_product"
    )

    assert filed.status_code == 400
    assert await submission_count(session) == 0
    assert await session.scalar(select(func.count()).select_from(StixObject)) == 0


@pytest.mark.requirement("SF-24")
async def test_a_bundle_whose_objects_all_declare_accepted_scopes_is_stored(client, session, world):
    _member, pem = world["member"]

    filed = await file(
        client, pem, [finding("own_product"), finding("ai_system")], scope="own_product"
    )

    assert filed.status_code == 201, filed.text
    assert await session.scalar(select(func.count()).select_from(StixObject)) == 2


async def test_the_state_machine_still_owns_the_lifecycle(client, session, world):
    """The rules gate validation; they do not add a state."""
    target = await canonical(session, world, cve_status="published")
    _member, pem = world["member"]
    filed = await file(client, pem, course_of_action_about(target), scope="disclosed_third_party")
    await submit_and_validate(client, pem, filed.json()["id"], world["editor"])

    stored = await session.get(Submission, uuid.UUID(filed.json()["id"]))
    await session.refresh(stored)
    assert stored.state is SubmissionState.VALIDATED
