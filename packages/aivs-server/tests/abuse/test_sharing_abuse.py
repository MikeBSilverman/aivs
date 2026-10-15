"""Abuse of the lanes that skip review, as the sequence an adversary would run.

Phase E lets some contributions reach members without an editor: one-clicks on
public content, post-moderated circles, and -- into review, but by machine --
the TAXII inbox. Each is a flood path for a script or a stolen certificate
(docs/threat-model.md, "Contributions published without review"), and the
analyst-proxy filing is a path for content in a member's name it never sent.
Each scenario asserts the step that refuses it and what the ISAC is told.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json

import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import SubmissionState
from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.services.attribution import submitted_by
from aivs_server.services.detections import RULES, run_detections
from tests.authz_matrix.world import inbox_note
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world, one_click

pytestmark = [pytest.mark.db, pytest.mark.abuse]

HOURLY_LIMIT = 3
FLOOD = [rule for rule in RULES if rule.name == "contribution_flood"]


@pytest.fixture
def app(app):
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


async def _published_count(session, org_id) -> int:
    return await session.scalar(
        select(func.count(func.distinct(Submission.id)))
        .join(StixObject, StixObject.submission_id == Submission.id)
        .join(Distribution, Distribution.stix_object_id == StixObject.id)
        .where(Submission.id.in_(submitted_by(org_id)))
    )


@pytest.mark.requirement("SF-66")
async def test_a_scripted_session_flooding_one_clicks_is_cut_off_and_noticed(
    client, session, world
):
    """Rule ``contribution_flood``. Each click is authorised; what gives the
    script away is the allowance biting, and what limits the damage is that
    nothing past it reaches members."""
    responses = [await one_click(client, world.member.person, world.published) for _ in range(10)]

    assert [r.status_code for r in responses] == [201] * HOURLY_LIMIT + [429] * 7
    assert await _published_count(session, world.member.org.id) == HOURLY_LIMIT
    raised = await run_detections(
        session, quarantine_policy="propose", now=dt.datetime.now(dt.UTC), rules=FLOOD
    )
    assert [(f.rule, f.subject) for f in raised] == [
        ("contribution_flood", str(world.member.org.id))
    ]


@pytest.mark.requirement("SF-69", "SF-66")
async def test_a_platform_flooding_the_inbox_is_cut_off_and_noticed(client, session, world):
    """Rule ``contribution_flood``, reached through TAXII: the inbox spends the
    same allowance, so a sync loop cannot fill the review queue unseen."""
    statuses = []
    for _ in range(HOURLY_LIMIT + 2):
        response = await client.post(
            f"/taxii2/aivs/collections/{world.collection.id}/objects/",
            content=json.dumps({"objects": [inbox_note(world.published)]}),
            headers={
                **world.member.machine,
                "content-type": "application/taxii+json;version=2.1",
            },
        )
        statuses.append(response.status_code)

    assert statuses == [202] * HOURLY_LIMIT + [429] * 2
    raised = await run_detections(
        session, quarantine_policy="propose", now=dt.datetime.now(dt.UTC), rules=FLOOD
    )
    assert [f.subject for f in raised] == [str(world.member.org.id)]


async def test_a_member_clicking_normally_raises_nothing(client, session, world):
    for _ in range(HOURLY_LIMIT):
        assert (await one_click(client, world.member.person, world.published)).status_code == 201

    raised = await run_detections(
        session, quarantine_policy="propose", now=dt.datetime.now(dt.UTC), rules=FLOOD
    )

    assert raised == []


@pytest.mark.requirement("SF-68")
async def test_a_proxy_filing_the_member_never_sent_is_stopped_before_it_reaches_members(
    client, session, world
):
    """The analyst holds a consent hash for mail the member never sent. The
    member is told at once; the filing cannot be distributed inside the window;
    the member withdraws it with its ordinary stop button."""
    filed = await client.post(
        f"{API}/submissions/on-behalf",
        json={
            "title": "Not something we sent",
            "discovery_scope": "own_estate",
            "tlp": "amber",
            "bundle": {
                "type": "bundle",
                "id": "bundle--0f0f0f0f-0000-4000-8000-000000000000",
                "objects": [
                    {
                        "type": "vulnerability",
                        "spec_version": "2.1",
                        "id": "vulnerability--0f0f0f0f-0000-4000-8000-000000000001",
                        "created": "2026-08-01T00:00:00.000Z",
                        "modified": "2026-08-01T00:00:00.000Z",
                        "name": "Attributed to the member",
                    }
                ],
            },
            "on_behalf_of": str(world.member.org.id),
            "consent_sha256": "ab" * 32,
        },
        headers=world.editor,
    )
    assert filed.status_code == 201, filed.text
    path = f"{API}/submissions/{filed.json()['id']}"
    validated = await client.post(f"{path}/validate", json={}, headers=world.editor)
    assert validated.status_code == 200, validated.text

    pushed = await client.post(
        f"{path}/distribute",
        json={"circle_ids": [str(world.circle.id)]},
        headers=world.editor,
    )
    withdrawn = await client.post(f"{path}/withdraw", json={}, headers=world.member.person)

    assert pushed.status_code == 409
    assert withdrawn.status_code == 200, withdrawn.text
    submission = await session.get(Submission, filed.json()["id"])
    await session.refresh(submission)
    assert submission.state is SubmissionState.WITHDRAWN
    assert await _published_count(session, world.member.org.id) == 0


@pytest.mark.requirement("SF-70")
async def test_a_stolen_certificate_taking_the_posture_list_is_noticed_without_the_list(
    client, session, world
):
    """Rule ``posture_export_burst``. The export is the firm's own, so every
    request is authorised; what gives a stolen certificate away is repetition,
    and what the ISAC is told names the firm, never a statement."""
    statement = "Isolating the gateways at the Frankfurt site until patched."
    await client.put(
        f"{API}/postures",
        json={
            "vulnerability": world.published,
            "status": "affected",
            "action_statement": statement,
        },
        headers=world.member.person,
    )
    rule = next(rule for rule in RULES if rule.name == "posture_export_burst")

    for _ in range(rule.threshold - 1):
        assert (
            await client.get(f"{API}/postures/openvex", headers=world.member.machine)
        ).status_code == 200
    quiet = await run_detections(
        session, quarantine_policy="propose", now=dt.datetime.now(dt.UTC), rules=[rule]
    )
    taken = await client.get(f"{API}/postures/openvex", headers=world.member.machine)
    raised = await run_detections(
        session, quarantine_policy="propose", now=dt.datetime.now(dt.UTC), rules=[rule]
    )

    assert statement in taken.text, "the export itself is the member's, and works"
    assert quiet == []
    assert [(f.rule, f.subject) for f in raised] == [
        ("posture_export_burst", str(world.member.org.id))
    ]
    assert statement not in json.dumps([dataclasses.asdict(f) for f in raised], default=str)
