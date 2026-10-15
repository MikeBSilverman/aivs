"""The TAXII inbox: a member's platform contributes by sync (SF-69).

A machine write path into the review queue. Each POST is an ordinary submission
filed for review as ``system`` -- never published, whoever sent it -- and the
rules every filing meets apply to it: anonymity, the disclosure split, the
circle's TLP floor, and the hourly allowance.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import (
    TLP,
    DiscoveryScope,
    OperatorRole,
    SubmissionLane,
    SubmissionSource,
    SubmissionState,
)
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog, Circle, Submission, TaxiiCollection, TaxiiStatus
from tests.authz_matrix.world import inbox_note
from tests.conftest import proxy_headers
from tests.unit.contribution_world import STAMP
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world

pytestmark = pytest.mark.db

TAXII_TYPE = "application/taxii+json;version=2.1"
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
        "content": "Seen against our gateway.",
        "object_refs": [target],
    }


async def post(client, world: SharingWorld, headers, objects, *, content_type=TAXII_TYPE):
    return await client.post(
        f"/taxii2/aivs/collections/{world.collection.id}/objects/",
        content=json.dumps({"objects": objects}),
        headers={**headers, "content-type": content_type},
    )


async def _switch(client, world: SharingWorld, headers, *, enabled: bool):
    return await client.put(
        f"{API}/circles/{world.circle.id}/taxii-inbox", json={"enabled": enabled}, headers=headers
    )


async def _filed(session, org_id) -> list[Submission]:
    rows = await session.execute(select(Submission).where(Submission.submitter_org_id == org_id))
    return list(rows.scalars().all())


# ---------------------------------------------------------------------------
# What a POST becomes
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-69")
async def test_a_post_lands_as_a_submitted_system_submission_not_a_distributed_one(
    client, session, world
):
    response = await post(client, world, world.member.machine, [note_about(world.published)])

    assert response.status_code == 202, response.text
    assert response.json()["status"] == "complete"
    [submission] = await _filed(session, world.member.org.id)
    assert submission.state is SubmissionState.SUBMITTED
    assert submission.source is SubmissionSource.SYSTEM
    assert submission.lane is SubmissionLane.REVIEW
    assert submission.distribute_anonymously is True
    assert submission.discovery_scope is DiscoveryScope.DISCLOSED_THIRD_PARTY
    assert submission.tlp is TLP(world.circle.minimum_tlp)


@pytest.mark.requirement("SF-69", "SF-66")
async def test_a_post_from_a_person_into_a_post_moderated_circle_still_waits_for_review(
    client, session, world
):
    """A post-moderated circle takes a person's note on submit, and never the inbox's."""
    enabled = await client.put(
        f"{API}/circles/{world.circle.id}/post-moderation",
        json={"enabled": True},
        headers=world.editor,
    )
    assert enabled.status_code == 204

    response = await post(client, world, world.member.person, [note_about(world.published)])

    assert response.status_code == 202, response.text
    [submission] = await _filed(session, world.member.org.id)
    assert submission.state is SubmissionState.SUBMITTED


@pytest.mark.requirement("SF-69", "SF-7")
async def test_the_disclosure_split_applies_to_the_inbox(client, session, world):
    response = await post(client, world, world.member.machine, [note_about(world.pre_cve)])

    assert response.status_code == 400
    assert await _filed(session, world.member.org.id) == []


@pytest.mark.requirement("SF-69")
async def test_a_finding_of_the_members_own_is_refused_at_the_inbox(client, session, world):
    """Beside a note on a published record, so only the own-vulnerability rule refuses it.

    Alone, the vulnerability would reference no ISAC record and fall to the
    unknown-target refusal, which is a 400 as well: the test would pass with
    this rule deleted.
    """
    vulnerability = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "name": "Our own pre-CVE finding",
    }

    response = await post(
        client, world, world.member.machine, [vulnerability, note_about(world.published)]
    )

    assert response.status_code == 400
    assert "native API" in response.text
    assert await _filed(session, world.member.org.id) == []


@pytest.mark.requirement("SF-69", "SF-50")
async def test_an_identity_object_is_refused_because_the_inbox_files_anonymously(
    client, session, world
):
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "name": "Meridian Global SOC",
        "identity_class": "organization",
    }

    response = await post(
        client, world, world.member.machine, [identity, note_about(world.published)]
    )

    assert response.status_code == 400
    assert await _filed(session, world.member.org.id) == []


# ---------------------------------------------------------------------------
# Who may POST
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-69")
async def test_a_reader_of_the_circle_is_refused_with_taxiis_403(client, session, world):
    response = await post(client, world, world.reader.machine, [note_about(world.published)])

    assert response.status_code == 403
    assert await _filed(session, world.reader.org.id) == []


@pytest.mark.requirement("SF-69")
async def test_a_contributor_is_refused_with_taxiis_403_where_the_collection_takes_no_writes(
    client, session, world
):
    """``can_write`` is the collection's half of the rule; the circle role is the other.

    The member contributes to the circle, so only the flag refuses it here.
    """
    await _switch(client, world, world.editor, enabled=False)

    response = await post(client, world, world.member.machine, [note_about(world.published)])

    assert response.status_code == 403
    assert await _filed(session, world.member.org.id) == []


@pytest.mark.requirement("SF-69", "SF-47")
async def test_an_outsider_gets_the_404_an_absent_collection_gets(
    client, world, make_org, make_cert
):
    outsider = await make_org("harbour-trust")
    pem, _ = await make_cert(outsider)
    body = json.dumps({"objects": [note_about(world.published)]})
    headers = {**proxy_headers(pem), "content-type": TAXII_TYPE}

    hidden = await post(client, world, proxy_headers(pem), [note_about(world.published)])
    absent = await client.post(
        f"/taxii2/aivs/collections/{uuid.uuid4()}/objects/", content=body, headers=headers
    )
    wrong_type = await post(client, world, proxy_headers(pem), [], content_type="application/json")

    assert hidden.status_code == absent.status_code == wrong_type.status_code == 404
    assert hidden.text == absent.text


async def test_a_post_that_does_not_say_it_is_taxii_is_refused(client, world):
    response = await post(
        client,
        world,
        world.member.machine,
        [note_about(world.published)],
        content_type="application/json",
    )

    assert response.status_code == 415


# ---------------------------------------------------------------------------
# The status resource
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-69")
async def test_the_status_is_readable_by_the_poster_alone(client, world):
    posted = await post(client, world, world.member.machine, [note_about(world.published)])
    path = f"/taxii2/aivs/status/{posted.json()['id']}/"

    own = await client.get(path, headers=world.member.machine)
    other = await client.get(path, headers=world.reader.machine)
    by_isac = await client.get(path, headers=world.editor)
    absent = await client.get(f"/taxii2/aivs/status/{uuid.uuid4()}/", headers=world.reader.machine)

    assert own.status_code == 200
    assert own.json()["success_count"] == 1
    assert other.status_code == by_isac.status_code == absent.status_code == 404
    assert other.text == absent.text


# ---------------------------------------------------------------------------
# The allowance
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-69", "SF-66")
async def test_posts_past_the_hourly_allowance_are_refused_and_the_refusal_is_kept(
    client, session, world
):
    for _ in range(HOURLY_LIMIT):
        accepted = await post(client, world, world.member.machine, [note_about(world.published)])
        assert accepted.status_code == 202, accepted.text

    refused = await post(client, world, world.member.machine, [note_about(world.published)])

    assert refused.status_code == 429
    assert len(await _filed(session, world.member.org.id)) == HOURLY_LIMIT
    statuses = await session.execute(
        select(TaxiiStatus).where(TaxiiStatus.org_id == world.member.org.id)
    )
    assert len(statuses.scalars().all()) == HOURLY_LIMIT
    refusal = await session.scalar(
        select(AuditLog).where(AuditLog.action == AuditAction.CONTRIBUTION_RATE_LIMITED)
    )
    assert refusal is not None
    assert refusal.org_id == world.member.org.id
    assert refusal.details["lane"] == "taxii_inbox"


@pytest.mark.requirement("SF-69")
async def test_an_envelope_the_database_cannot_store_is_the_platforms_400(client, session, world):
    """A NUL reached PostgreSQL as a server error; every other ingest path answers 400."""
    note = inbox_note(world.published)
    note["content"] = "seen\u0000here"

    response = await post(client, world, world.member.machine, [note])

    assert response.status_code == 400
    assert await _filed(session, world.member.org.id) == []


# ---------------------------------------------------------------------------
# The switch (Mike, Q19)
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-69")
async def test_a_circle_made_through_the_api_starts_with_its_inbox_closed(client, session, world):
    made = await client.post(
        f"{API}/circles", json={"slug": "new-circle", "name": "New circle"}, headers=world.editor
    )
    assert made.status_code == 201, made.text
    can_write = await session.scalar(
        select(TaxiiCollection.can_write)
        .join(Circle, Circle.id == TaxiiCollection.circle_id)
        .where(Circle.slug == "new-circle")
    )
    assert can_write is False


@pytest.mark.requirement("SF-69")
async def test_an_editor_opens_and_closes_the_inbox_and_each_post_follows_it(
    client, session, world
):
    """Closed refuses with TAXII's 403, as the inbox refuses any unwritable
    collection; open files the post for review; closed again refuses again."""
    closed = await _switch(client, world, world.editor, enabled=False)
    refused = await post(client, world, world.member.machine, [note_about(world.published)])
    opened = await _switch(client, world, world.editor, enabled=True)
    accepted = await post(client, world, world.member.machine, [note_about(world.published)])
    await _switch(client, world, world.editor, enabled=False)
    refused_again = await post(client, world, world.member.machine, [note_about(world.published)])

    assert (closed.status_code, opened.status_code) == (204, 204)
    reader_refused = await post(client, world, world.reader.machine, [note_about(world.published)])
    assert refused.status_code == 403
    assert refused.content == reader_refused.content, "the inbox's one refusal"
    assert accepted.status_code == 202, accepted.text
    assert refused_again.status_code == 403
    assert [s.state for s in await _filed(session, world.member.org.id)] == [
        SubmissionState.SUBMITTED
    ]


@pytest.mark.requirement("SF-69")
async def test_the_audit_row_names_who_switched_the_inbox_and_which_way(client, session, world):
    await _switch(client, world, world.editor, enabled=False)
    await _switch(client, world, world.editor, enabled=True)
    rows = (
        await session.scalars(
            select(AuditLog)
            .where(AuditLog.action == AuditAction.CIRCLE_TAXII_INBOX_SET)
            .order_by(AuditLog.id)
        )
    ).all()
    assert [(row.details["enabled"], row.details["previous"]) for row in rows] == [
        (False, True),
        (True, False),
    ]
    assert {row.actor_type for row in rows} == {"operator"}
    assert all(row.actor_id for row in rows)
    assert {row.resource_id for row in rows} == {str(world.circle.id)}


@pytest.mark.requirement("SF-69")
@pytest.mark.parametrize("who", ["member machine", "member person", "isac analyst"])
async def test_only_an_editor_switches_the_inbox(
    client, session, world, who, isac_org, make_operator, make_cert, human_headers
):
    if who == "isac analyst":
        analyst, _ = await make_operator(isac_org, roles=(OperatorRole.ISAC_ANALYST,))
        pem, _ = await make_cert(isac_org)
        headers = await human_headers(analyst, pem)
    else:
        headers = world.member.machine if who == "member machine" else world.member.person
    refused = await _switch(client, world, headers, enabled=False)
    reasons = [
        row.details["reason"]
        for row in await session.scalars(
            select(AuditLog).where(AuditLog.action == AuditAction.ACCESS_DENIED)
        )
    ]
    still_open = await post(client, world, world.member.machine, [note_about(world.published)])

    assert refused.status_code == 403
    assert reasons == ["taxii_inbox_requires_isac_editor"]
    assert still_open.status_code == 202, "the refused switch changed nothing"


async def test_switching_an_unknown_circles_inbox_is_not_found(client, world):
    response = await client.put(
        f"{API}/circles/{uuid.uuid4()}/taxii-inbox", json={"enabled": True}, headers=world.editor
    )
    assert response.status_code == 404
