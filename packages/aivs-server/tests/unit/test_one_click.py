"""One-click contributions and the lane rule (SF-66).

A click builds the STIX on the server and is published at once only when it
carries no prose, is about public content, comes from a person, goes into a
circle the member contributes to, and is not a vendor's opinion. Every other
click is filed for review. Each property is a pair: the click that takes the
fast lane, and the one changed in exactly that respect that does not.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import TLP, OrgType, SubmissionLane, SubmissionState
from aivs_server.db.models import Distribution, StixObject, Submission, SubmissionTransition
from aivs_server.services.contributions import NEEDS_AN_EDITOR
from tests.unit.contribution_world import LATER, seed, vulnerability_raw
from tests.unit.sharing_world import SharingWorld, build_sharing_world, one_click

pytestmark = pytest.mark.db


@pytest.fixture
async def world(
    session,
    isac,
    isac_org,
    make_org,
    make_cert,
    make_operator,
    make_circle,
    make_collection,
    join_circle,
    human_headers,
) -> SharingWorld:
    return await build_sharing_world(
        session,
        isac,
        isac_org,
        make_org=make_org,
        make_cert=make_cert,
        make_operator=make_operator,
        make_circle=make_circle,
        make_collection=make_collection,
        join_circle=join_circle,
        human_headers=human_headers,
    )


async def _filed(session, response) -> Submission:
    assert response.status_code == 201, response.text
    submission = await session.get(Submission, uuid.UUID(response.json()["submission_id"]))
    await session.refresh(submission)
    return submission


async def _distributed_to(session, submission: Submission) -> set[uuid.UUID]:
    rows = await session.execute(
        select(Distribution.circle_id)
        .join(StixObject, StixObject.id == Distribution.stix_object_id)
        .where(StixObject.submission_id == submission.id)
    )
    return set(rows.scalars().all())


# ---------------------------------------------------------------------------
# The fast lane
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-66")
async def test_a_person_seeing_a_public_vulnerability_is_published_at_once(client, session, world):
    submission = await _filed(
        session, await one_click(client, world.member.person, world.published)
    )

    assert submission.state is SubmissionState.DISTRIBUTED
    assert submission.lane is SubmissionLane.FAST
    assert await _distributed_to(session, submission) == {world.circle.id}


@pytest.mark.requirement("SF-66")
async def test_the_same_click_from_a_machine_certificate_waits_for_review(client, session, world):
    submission = await _filed(
        session, await one_click(client, world.member.machine, world.published)
    )

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW
    assert await _distributed_to(session, submission) == set()


@pytest.mark.requirement("SF-66")
async def test_a_click_on_a_vulnerability_not_yet_public_waits_for_review(client, session, world):
    submission = await _filed(session, await one_click(client, world.member.person, world.pre_cve))

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW


@pytest.mark.requirement("SF-66", "SF-49")
async def test_a_click_on_red_content_waits_for_review_and_is_red_itself(client, session, world):
    submission = await _filed(
        session, await one_click(client, world.member.person, world.published_red)
    )

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.tlp is TLP.RED


@pytest.mark.requirement("SF-66")
async def test_a_vendors_opinion_waits_for_review_though_its_sighting_does_not(
    client, session, world
):
    """A vendor arguing about a product -- possibly its own -- is what an editor is for."""
    assert world.vendor.org.org_type is OrgType.VENDOR
    opinion = await _filed(
        session, await one_click(client, world.vendor.person, world.published, "fails")
    )
    sighting = await _filed(
        session, await one_click(client, world.vendor.person, world.published, "seen")
    )

    assert opinion.state is SubmissionState.SUBMITTED
    assert sighting.state is SubmissionState.DISTRIBUTED


@pytest.mark.requirement("SF-66")
async def test_the_isacs_automation_waits_for_review_even_with_a_person_signed_in(
    client, session, world
):
    submission = await _filed(
        session, await one_click(client, world.automation.person, world.published)
    )

    assert submission.state is SubmissionState.SUBMITTED


@pytest.mark.requirement("SF-66")
async def test_a_reader_only_member_waits_for_review(client, session, world):
    """The circle's contributor role is not bypassed by the fast lane."""
    submission = await _filed(
        session, await one_click(client, world.reader.person, world.published)
    )

    assert submission.state is SubmissionState.SUBMITTED
    assert await _distributed_to(session, submission) == set()


# ---------------------------------------------------------------------------
# What the click builds
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-50")
async def test_a_click_is_anonymous_and_its_sighting_says_nowhere(client, session, world):
    submission = await _filed(
        session, await one_click(client, world.member.person, world.published)
    )
    raw = await session.scalar(
        select(StixObject.raw).where(StixObject.submission_id == submission.id)
    )

    assert submission.distribute_anonymously is True
    assert raw["type"] == "sighting"
    assert raw["sighting_of_ref"] == world.published
    assert "where_sighted_refs" not in raw


async def test_works_and_fails_are_agreeing_and_disagreeing_opinions(client, session, world):
    works = await _filed(
        session, await one_click(client, world.member.person, world.published, "works")
    )
    fails = await _filed(
        session, await one_click(client, world.member.person, world.published, "fails")
    )
    opinions = [
        await session.scalar(select(StixObject.raw).where(StixObject.submission_id == s.id))
        for s in (works, fails)
    ]

    assert [raw["opinion"] for raw in opinions] == ["agree", "disagree"]
    assert all(raw["object_refs"] == [world.published] for raw in opinions)


# ---------------------------------------------------------------------------
# An object the caller cannot see
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-47")
async def test_a_click_on_an_object_outside_the_callers_circles_reads_as_absent(
    client, world, make_org, make_cert, make_operator, human_headers
):
    outsider = await make_org("harbour-trust", org_type=OrgType.GSIB)
    pem, _ = await make_cert(outsider)
    operator, _seed = await make_operator(outsider)
    headers = await human_headers(operator, pem)

    hidden = await one_click(client, headers, world.published)
    absent = await one_click(client, headers, f"vulnerability--{uuid.uuid4()}")

    assert hidden.status_code == absent.status_code == 404
    assert hidden.text == absent.text


# ---------------------------------------------------------------------------
# What the ISAC sees and the member does not
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-66", "SF-49")
async def test_a_stricter_version_the_member_cannot_see_sends_the_click_to_review_unexplained(
    client, session, isac_org, make_circle, world
):
    """The ISAC's view refuses; the member is told only that an editor will look.

    A newer AMBER+STRICT version of the record sits in a circle the member is
    not in. The click, AMBER from what the member sees, is looser than it, so
    it may not be published unread -- and answering with that reason told the
    member the version existed, and its TLP. The pair is the first test in
    this module: without the hidden version the same click is published.
    """
    staff_only = await make_circle("staff-only")
    await seed(
        session,
        isac_org,
        vulnerability_raw(world.published, cve_status="published", modified=LATER),
        circle=staff_only,
        tlp=TLP.AMBER_STRICT,
    )

    response = await one_click(client, world.member.person, world.published)
    submission = await _filed(session, response)

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW
    assert "strict" not in response.text.lower()
    reasons = (
        (
            await session.execute(
                select(SubmissionTransition.reason).where(
                    SubmissionTransition.submission_id == submission.id
                )
            )
        )
        .scalars()
        .all()
    )
    assert reasons[-1] == NEEDS_AN_EDITOR
    assert not any("strict" in (reason or "") for reason in reasons)


@pytest.mark.requirement("SF-66")
async def test_a_members_own_record_saying_published_does_not_open_the_fast_lane(
    client, session, world
):
    """Public means the ISAC's record says so, as the disclosure split reads it.

    Read from whoever's version was latest, a member's own vulnerability,
    distributed with ``cve_status: published``, opened the fast lane on itself.
    The pair is the ISAC's published record, which does (first test above).
    """
    own = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session,
        world.member.org,
        vulnerability_raw(own, cve_status="published"),
        circle=world.circle,
    )

    submission = await _filed(session, await one_click(client, world.member.person, own))

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW
