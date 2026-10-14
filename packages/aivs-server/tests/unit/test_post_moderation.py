"""Post-moderated circles and the hourly allowance (SF-66).

An editor may let a circle take short contributions -- a note, opinion,
sighting or RFI grouping -- on public content without review. Everything else
in the lane rule still holds, and everything published without review counts
against one per-organisation hourly allowance.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select, update
from sqlalchemy import text as sqlalchemy_text
from sqlalchemy.exc import DBAPIError

from aivs_schemas.enums import OrgType, SubmissionLane, SubmissionState
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog, Circle, Submission, SubmissionTransition
from aivs_server.services.contributions import within_hourly_allowance
from tests.unit.contribution_world import STAMP, bundle_of, course_of_action_about, seed
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world, one_click

pytestmark = pytest.mark.db

HOURLY_LIMIT = 2


@pytest.fixture
def app(app):
    """The suite's application, with a small allowance so tests can spend it."""
    app.state.settings = app.state.settings.model_copy(
        update={"contribution_hourly_limit": HOURLY_LIMIT}
    )
    return app


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


def note_about(target: str) -> dict:
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": f"note--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "content": "Exploitation attempts seen against our gateway since Tuesday.",
        "object_refs": [target],
    }


async def post_moderation(client, world: SharingWorld, *, enabled: bool) -> None:
    response = await client.put(
        f"{API}/circles/{world.circle.id}/post-moderation",
        json={"enabled": enabled},
        headers=world.editor,
    )
    assert response.status_code == 204, response.text


async def file_and_submit(
    client, session, headers, objects: list[dict], *, tlp: str = "amber"
) -> Submission:
    filed = await draft(client, headers, objects, tlp=tlp)
    return await submit(client, session, headers, filed)


async def draft(client, headers, objects: list[dict], *, tlp: str = "amber"):
    filed = await client.post(
        f"{API}/submissions",
        json={
            "title": "A short contribution",
            "discovery_scope": "own_estate",
            "tlp": tlp,
            "distribute_anonymously": True,
            "bundle": bundle_of(*objects),
        },
        headers=headers,
    )
    assert filed.status_code == 201, filed.text
    return filed


async def submit(client, session, headers, filed) -> Submission:
    submitted = await client.post(
        f"{API}/submissions/{filed.json()['id']}/submit", json={}, headers=headers
    )
    assert submitted.status_code == 200, submitted.text
    submission = await session.get(Submission, uuid.UUID(filed.json()["id"]))
    await session.refresh(submission)
    return submission


# ---------------------------------------------------------------------------
# The circle's choice
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-66")
async def test_a_note_on_public_content_in_a_post_moderated_circle_is_published_on_submit(
    client, session, world
):
    await post_moderation(client, world, enabled=True)

    submission = await file_and_submit(
        client, session, world.member.person, [note_about(world.published)]
    )

    assert submission.state is SubmissionState.DISTRIBUTED
    assert submission.lane is SubmissionLane.POST_MODERATED


@pytest.mark.requirement("SF-66")
async def test_the_same_note_in_a_circle_without_post_moderation_waits_for_review(
    client, session, world
):
    submission = await file_and_submit(
        client, session, world.member.person, [note_about(world.published)]
    )

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW


async def test_post_moderation_is_off_until_an_editor_turns_it_on_and_is_audited(
    client, session, world
):
    assert world.circle.post_moderated is False
    await post_moderation(client, world, enabled=True)

    await session.refresh(world.circle)
    audited = await session.scalar(
        select(AuditLog).where(
            AuditLog.action == AuditAction.CIRCLE_POST_MODERATION_SET,
            AuditLog.resource_id == str(world.circle.id),
        )
    )
    assert (await session.get(Circle, world.circle.id)).post_moderated is True
    assert audited is not None
    assert audited.details == {"enabled": True}


@pytest.mark.requirement("SF-66")
async def test_a_workaround_is_not_a_post_moderated_type_and_waits_for_review(
    client, session, world
):
    await post_moderation(client, world, enabled=True)

    submission = await file_and_submit(
        client, session, world.member.person, course_of_action_about(world.published)
    )

    assert submission.state is SubmissionState.SUBMITTED


@pytest.mark.requirement("SF-66")
async def test_a_note_on_a_vulnerability_not_yet_public_waits_for_review(client, session, world):
    await post_moderation(client, world, enabled=True)

    submission = await file_and_submit(
        client, session, world.member.person, [note_about(world.pre_cve)]
    )

    assert submission.state is SubmissionState.SUBMITTED


@pytest.mark.requirement("SF-66")
async def test_a_note_submitted_by_a_machine_certificate_waits_for_review(client, session, world):
    await post_moderation(client, world, enabled=True)

    submission = await file_and_submit(
        client, session, world.member.machine, [note_about(world.published)]
    )

    assert submission.state is SubmissionState.SUBMITTED


@pytest.mark.requirement("SF-66")
async def test_a_grouping_is_post_moderated_only_as_a_request_for_information(
    client, session, world
):
    await post_moderation(client, world, enabled=True)

    def grouping(context: str) -> dict:
        return {
            "type": "grouping",
            "spec_version": "2.1",
            "id": f"grouping--{uuid.uuid4()}",
            "created": STAMP,
            "modified": STAMP,
            "context": context,
            "object_refs": [world.published],
        }

    rfi = await file_and_submit(client, session, world.member.person, [grouping("rfi")])
    campaign = await file_and_submit(
        client, session, world.member.person, [grouping("suspicious-activity")]
    )

    assert rfi.state is SubmissionState.DISTRIBUTED
    assert campaign.state is SubmissionState.SUBMITTED


# ---------------------------------------------------------------------------
# The hourly allowance
# ---------------------------------------------------------------------------
async def _rate_limited_rows(session, org_id) -> list[AuditLog]:
    rows = await session.execute(
        select(AuditLog).where(
            AuditLog.action == AuditAction.CONTRIBUTION_RATE_LIMITED, AuditLog.org_id == org_id
        )
    )
    return list(rows.scalars().all())


@pytest.mark.requirement("SF-66")
async def test_post_moderated_contributions_past_the_allowance_wait_for_review(
    client, session, world
):
    await post_moderation(client, world, enabled=True)

    published = [
        await file_and_submit(client, session, world.member.person, [note_about(world.published)])
        for _ in range(HOURLY_LIMIT)
    ]
    over = await file_and_submit(
        client, session, world.member.person, [note_about(world.published)]
    )

    assert {s.state for s in published} == {SubmissionState.DISTRIBUTED}
    assert over.state is SubmissionState.SUBMITTED
    assert [
        row.details["lane"] for row in await _rate_limited_rows(session, world.member.org.id)
    ] == ["post_moderated"]


@pytest.mark.requirement("SF-66")
async def test_a_one_click_past_the_allowance_is_refused_and_the_refusal_is_kept(
    client, session, world
):
    for _ in range(HOURLY_LIMIT):
        allowed = await one_click(client, world.member.person, world.published)
        assert allowed.status_code == 201, allowed.text

    refused = await one_click(client, world.member.person, world.published)

    assert refused.status_code == 429
    assert len(await _rate_limited_rows(session, world.member.org.id)) == 1


@pytest.mark.requirement("SF-66")
async def test_the_allowance_is_per_organisation(client, session, world):
    for _ in range(HOURLY_LIMIT):
        await one_click(client, world.member.person, world.published)

    other = await one_click(client, world.vendor.person, world.published)

    assert other.status_code == 201, other.text


async def test_clicks_filed_for_review_do_not_spend_the_allowance(client, session, world):
    """Review is the safe lane; only what skips it is counted."""
    for _ in range(HOURLY_LIMIT + 1):
        reviewed = await one_click(client, world.member.person, world.pre_cve)
        assert reviewed.status_code == 201, reviewed.text

    published = await one_click(client, world.member.person, world.published)

    assert published.status_code == 201, published.text
    assert published.json()["lane"] == "fast"


@pytest.mark.requirement("SF-66")
async def test_drafts_made_earlier_still_spend_the_allowance_when_published(client, session, world):
    """The allowance counts publications, not drafts.

    Counted by creation, drafts made an hour before and submitted together
    met an empty allowance: all of them were published, and nothing was
    refused for the flood detection to see.
    """
    await post_moderation(client, world, enabled=True)
    drafts = [
        await draft(client, world.member.person, [note_about(world.published)])
        for _ in range(HOURLY_LIMIT + 1)
    ]
    ids = [uuid.UUID(filed.json()["id"]) for filed in drafts]
    await session.execute(
        update(Submission)
        .where(Submission.id.in_(ids))
        .values(created_at=dt.datetime.now(dt.UTC) - dt.timedelta(hours=2))
    )
    await session.commit()

    states = [(await submit(client, session, world.member.person, filed)).state for filed in drafts]

    assert states == [SubmissionState.DISTRIBUTED] * HOURLY_LIMIT + [SubmissionState.SUBMITTED]


@pytest.mark.requirement("SF-66")
async def test_the_allowance_is_counted_under_the_organisations_lock(session, open_session, world):
    """A second count for the same organisation waits for the first transaction.

    Without the lock, parallel requests each counted limit - 1 and all went
    through. The pair: another organisation's count does not wait.
    """
    now = dt.datetime.now(dt.UTC)
    first = open_session()
    await within_hourly_allowance(first, world.member.org.id, limit=HOURLY_LIMIT, now=now)

    other_org = open_session()
    await other_org.execute(sqlalchemy_text("SET LOCAL lock_timeout = '200ms'"))
    await within_hourly_allowance(other_org, world.vendor.org.id, limit=HOURLY_LIMIT, now=now)

    same_org = open_session()
    await same_org.execute(sqlalchemy_text("SET LOCAL lock_timeout = '200ms'"))
    with pytest.raises(DBAPIError, match="lock timeout"):
        await within_hourly_allowance(same_org, world.member.org.id, limit=HOURLY_LIMIT, now=now)


@pytest.mark.requirement("SF-66")
async def test_a_red_note_waits_for_review_though_its_target_is_not_red(client, session, world):
    """RED is never published unread. The pair is the AMBER note above."""
    await post_moderation(client, world, enabled=True)

    submission = await file_and_submit(
        client, session, world.member.person, [note_about(world.published)], tlp="red"
    )

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW


@pytest.mark.requirement("SF-48", "SF-66")
async def test_a_note_reusing_another_firms_id_waits_without_being_told_whose(
    client, session, world, make_org, make_circle
):
    """The ownership check runs from the ISAC's view; its reason never reaches the member.

    Another firm's note, in a circle the member is not in, has the id the
    member's note reuses. The member learns only that an editor will look.
    """
    await post_moderation(client, world, enabled=True)
    elsewhere = await make_circle("elsewhere")
    other_firm = await make_org("harbour-trust", org_type=OrgType.GSIB)
    theirs = note_about(world.published)
    await seed(session, other_firm, theirs, circle=elsewhere)
    ours = {**note_about(world.published), "id": theirs["id"]}

    filed = await draft(client, world.member.person, [ours])
    response = await client.post(
        f"{API}/submissions/{filed.json()['id']}/submit", json={}, headers=world.member.person
    )

    assert response.status_code == 200, response.text
    assert theirs["id"] not in response.text.replace(f'"{filed.json()["id"]}"', "")
    submission = await session.get(Submission, uuid.UUID(filed.json()["id"]))
    await session.refresh(submission)
    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW
    reasons = (
        await session.execute(
            select(SubmissionTransition.reason).where(
                SubmissionTransition.submission_id == submission.id
            )
        )
    ).scalars()
    assert "only the organisation" not in " ".join(reason or "" for reason in reasons)
