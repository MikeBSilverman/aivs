"""Releasing an embargo re-checks the content rules distribution checked (W-P1).

Distribution checks owner-only versioning, the disclosure split and TLP
inheritance against the state of the world at that moment. An embargo can run
for days, and the world moves: the ISAC moves the target back out of
disclosure, a referent is re-marked stricter, an organisation is enrolled under
an identifier the bundle used. Release used to make the content visible on the
strength of the check at distribution.

Two paths release. An operator's early release re-checks and refuses. A timer
releases by the clock (NFR-A3: no job has to run), so the sweeper re-checks
every embargo still on its timer on each pass and *holds* one that no longer
passes before its time arrives: its rows move out of reach of the clock, the
embargo waits for an operator, and the ISAC is told. Each is tested with its
pair, the same content with the rules still holding.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy import func, select, update

from aivs_schemas.enums import TLP, EmbargoPolicy, EmbargoStatus, OrgType
from aivs_server.db.models import AuditLog, Distribution, Embargo, Submission
from aivs_server.services.distribution import distribute_submission
from aivs_server.services.embargo import sweep_due_embargoes
from tests.conftest import proxy_headers
from tests.unit.contribution_world import (
    LATER,
    course_of_action_about,
    file,
    seed,
    submit_and_validate,
    vulnerability_raw,
)

pytestmark = pytest.mark.db

API = "/api/v1/submissions"
DAY = dt.timedelta(days=1)


@pytest.fixture
async def world(make_org, make_cert, make_circle, make_collection, join_circle, isac, isac_org):
    """A contributor and a reader in one circle with the ISAC."""
    circle = await make_circle("coordination")
    collection = await make_collection(circle)
    contributor = await make_org("meridian-global", org_type=OrgType.GSIB)
    contributor_pem, _ = await make_cert(contributor)
    reader = await make_org("atlantic-clearing", org_type=OrgType.GSIB)
    reader_pem, _ = await make_cert(reader)
    for org in (contributor, reader, isac_org):
        await join_circle(org, circle)
    _isac_org, editor = isac
    return {
        "circle": circle,
        "collection": collection,
        "contributor_pem": contributor_pem,
        "reader_pem": reader_pem,
        "editor": editor,
        "isac_org": isac_org,
    }


@pytest.fixture
async def held(client, session, world) -> dict[str, Any]:
    """A workaround on a public vulnerability, distributed under a three-day embargo."""
    target = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session,
        world["isac_org"],
        vulnerability_raw(target, cve_status="published"),
        circle=world["circle"],
    )
    pem = world["contributor_pem"]
    filed = await file(client, pem, course_of_action_about(target), scope="disclosed_third_party")
    assert filed.status_code == 201, filed.text
    validated = await submit_and_validate(client, pem, filed.json()["id"], world["editor"])
    assert validated.status_code == 200, validated.text
    release_at = dt.datetime.now(dt.UTC) + 3 * DAY
    distributed = await client.post(
        f"{API}/{filed.json()['id']}/distribute",
        json={"circle_ids": [str(world["circle"].id)], "release_at": release_at.isoformat()},
        headers=world["editor"],
    )
    assert distributed.status_code == 200, distributed.text
    return {"submission_id": uuid.UUID(filed.json()["id"]), "target": target}


async def withdraw_disclosure(session, world, target: str) -> None:
    """The ISAC's newer record says the vulnerability is no longer public."""
    await seed(
        session,
        world["isac_org"],
        vulnerability_raw(target, cve_status="requested", modified=LATER),
        circle=world["circle"],
    )


async def reader_sees(client, world) -> set[str]:
    response = await client.get(
        f"/taxii2/aivs/collections/{world['collection'].id}/objects/",
        headers=proxy_headers(world["reader_pem"]),
    )
    assert response.status_code == 200
    return {item["type"] for item in response.json().get("objects", [])}


async def embargo_of(session, submission_id: uuid.UUID) -> Embargo:
    return (
        await session.execute(
            select(Embargo)
            .where(Embargo.submission_id == submission_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def rows_readable_by(session, submission_id: uuid.UUID, when: dt.datetime) -> int:
    return await session.scalar(
        select(func.count())
        .select_from(Distribution)
        .where(Distribution.submission_id == submission_id, Distribution.date_added <= when)
    )


async def audit_rows(session, action: str) -> list[AuditLog]:
    return list(
        (await session.execute(select(AuditLog).where(AuditLog.action == action))).scalars()
    )


# ---------------------------------------------------------------------------
# Early release
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-7")
async def test_early_release_refuses_content_whose_target_left_disclosure(
    client, session, world, held
):
    await withdraw_disclosure(session, world, held["target"])

    refused = await client.post(
        f"{API}/{held['submission_id']}/embargo/release", json={}, headers=world["editor"]
    )

    assert refused.status_code == 409
    assert "not public yet" in refused.json()["title"]
    assert "course-of-action" not in await reader_sees(client, world)
    assert (await embargo_of(session, held["submission_id"])).status is EmbargoStatus.PENDING


async def test_early_release_of_content_that_still_passes_releases_it(client, session, world, held):
    released = await client.post(
        f"{API}/{held['submission_id']}/embargo/release", json={}, headers=world["editor"]
    )

    assert released.status_code == 200, released.text
    assert "course-of-action" in await reader_sees(client, world)


# ---------------------------------------------------------------------------
# The timer
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-7")
async def test_the_sweeper_holds_an_embargo_whose_content_no_longer_passes(
    client, session, world, held
):
    due = (await embargo_of(session, held["submission_id"])).release_at
    await withdraw_disclosure(session, world, held["target"])

    await sweep_due_embargoes(session)

    embargo = await embargo_of(session, held["submission_id"])
    assert embargo.policy is EmbargoPolicy.MANUAL, "still on its timer"
    assert embargo.status is EmbargoStatus.PENDING
    assert await rows_readable_by(session, held["submission_id"], due + DAY) == 0
    [told] = await audit_rows(session, "embargo.held")
    assert told.resource_id == str(held["submission_id"])
    assert "not public yet" in told.details["reason"]


async def test_the_sweeper_leaves_an_embargo_that_still_passes_on_its_timer(session, world, held):
    due = (await embargo_of(session, held["submission_id"])).release_at

    await sweep_due_embargoes(session)

    embargo = await embargo_of(session, held["submission_id"])
    assert embargo.policy is EmbargoPolicy.TIMER
    assert embargo.release_at == due
    assert await rows_readable_by(session, held["submission_id"], due) > 0
    assert await audit_rows(session, "embargo.held") == []


async def test_a_held_embargo_does_not_stop_the_sweeper_releasing_another(
    session, world, held, isac_ctx, make_validated
):
    other_id = await make_validated("due today")
    other = await session.get(Submission, other_id)
    await distribute_submission(
        session,
        isac_ctx,
        other,
        circle_ids=[world["circle"].id],
        release_at=dt.datetime.now(dt.UTC) + DAY,
    )
    await session.commit()
    elapsed = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
    await session.execute(
        update(Distribution)
        .where(Distribution.submission_id == other_id)
        .values(date_added=elapsed)
    )
    await session.execute(
        update(Embargo).where(Embargo.submission_id == other_id).values(release_at=elapsed)
    )
    await session.commit()
    await withdraw_disclosure(session, world, held["target"])

    released = await sweep_due_embargoes(session)

    assert released == 1
    assert (await embargo_of(session, other_id)).status is EmbargoStatus.RELEASED
    assert (await embargo_of(session, held["submission_id"])).policy is EmbargoPolicy.MANUAL


@pytest.mark.requirement("SF-63")
async def test_a_pause_does_not_postpone_a_hold(client, session, world, held):
    """Resuming makes every elapsed timer visible at once, before the next pass
    could hold it; so the hold runs while paused, as an extension may."""
    paused = await client.post(
        "/api/v1/instance/distribution/pause",
        json={"reason": "incident under review"},
        headers=world["editor"],
    )
    assert paused.status_code == 200, paused.text
    await withdraw_disclosure(session, world, held["target"])

    await sweep_due_embargoes(session)

    assert (await embargo_of(session, held["submission_id"])).policy is EmbargoPolicy.MANUAL


async def test_extending_a_held_embargo_puts_it_back_on_a_timer(client, session, world, held):
    await withdraw_disclosure(session, world, held["target"])
    await sweep_due_embargoes(session)
    later = dt.datetime.now(dt.UTC) + 10 * DAY

    extended = await client.post(
        f"{API}/{held['submission_id']}/embargo/extend",
        json={"circle_ids": [str(uuid.uuid4())], "release_at": later.isoformat()},
        headers=world["editor"],
    )

    assert extended.status_code == 200, extended.text
    embargo = await embargo_of(session, held["submission_id"])
    assert embargo.policy is EmbargoPolicy.TIMER
    assert embargo.release_at is not None
    assert await rows_readable_by(session, held["submission_id"], embargo.release_at) > 0


async def test_an_elapsed_embargo_whose_content_no_longer_passes_is_reported(session, world, held):
    """Already visible by the clock, so not retracted -- but the ISAC is told."""
    elapsed = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
    submission_id = held["submission_id"]
    await session.execute(
        update(Distribution)
        .where(Distribution.submission_id == submission_id)
        .values(date_added=elapsed)
    )
    await session.execute(
        update(Embargo).where(Embargo.submission_id == submission_id).values(release_at=elapsed)
    )
    await session.commit()
    await withdraw_disclosure(session, world, held["target"])

    await sweep_due_embargoes(session)

    [released] = await audit_rows(session, "embargo.released")
    assert "not public yet" in released.details["content_problem"]


@pytest.mark.requirement("SF-49")
async def test_the_sweeper_holds_an_embargo_whose_referent_was_re_marked_stricter(
    client, session, world
):
    """A second rule, so the hold is not about the disclosure split alone."""
    target = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session,
        world["isac_org"],
        vulnerability_raw(target, cve_status="published"),
        circle=world["circle"],
        tlp=TLP.AMBER,
    )
    pem = world["contributor_pem"]
    filed = await file(client, pem, course_of_action_about(target), scope="ai_system", tlp="amber")
    assert filed.status_code == 201, filed.text
    submission_id = uuid.UUID(filed.json()["id"])
    validated = await submit_and_validate(client, pem, str(submission_id), world["editor"])
    assert validated.status_code == 200, validated.text
    distributed = await client.post(
        f"{API}/{submission_id}/distribute",
        json={
            "circle_ids": [str(world["circle"].id)],
            "release_at": (dt.datetime.now(dt.UTC) + 3 * DAY).isoformat(),
        },
        headers=world["editor"],
    )
    assert distributed.status_code == 200, distributed.text
    await seed(
        session,
        world["isac_org"],
        vulnerability_raw(target, cve_status="published", modified=LATER),
        circle=world["circle"],
        tlp=TLP.RED,
    )

    await sweep_due_embargoes(session)

    assert (await embargo_of(session, submission_id)).policy is EmbargoPolicy.MANUAL
    [told] = await audit_rows(session, "embargo.held")
    assert "looser than objects it references" in told.details["reason"]
