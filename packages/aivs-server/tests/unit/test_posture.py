"""A member's posture on a vulnerability: its own, and counts for the ISAC (SF-70).

Whether a firm is ``affected`` is the fact its counsel will not let the ISAC
hold per firm. A posture row is therefore read and written by its own
organisation alone -- anyone else, the ISAC included, gets the 404 an absent
row gets -- and the ISAC sees counts, each exact only when at least k have
that status and at least k do not.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy import func, select, update

from aivs_schemas.enums import CircleRole, OrgStatus, PostureStatus
from aivs_server.api import contributions as contributions_api
from aivs_server.audit.log import AuditAction
from aivs_server.auth.context import AuthContext, AuthMethod, CircleGrant, MembershipInterval
from aivs_server.db.models import AuditLog, Distribution, OrgPosture, StixObject
from aivs_server.services.posture import VexStatement, _suppress, publish_postures, record_posture
from aivs_server.services.telemetry import K_ANONYMITY
from tests.authz_matrix.test_authz_matrix import walk_routes
from tests.conftest import proxy_headers
from tests.unit.contribution_world import STAMP, seed
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world
from tests.unit.test_one_clock import skew_clock

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


async def seed_visible_indicator(session, world) -> str:
    """An indicator in the circle: an object the member can read that is not a vulnerability."""
    stix_id = f"indicator--{uuid.uuid4()}"
    raw = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": STAMP,
        "modified": STAMP,
        "pattern": "[file:name = 'agent.so']",
        "pattern_type": "stix",
        "valid_from": STAMP,
    }
    await seed(session, world.isac_org, raw, circle=world.circle)
    return stix_id


#: The statements VEX requires with each status, so tests about who may read a
#: posture are not refused for leaving one out (test_vex.py is about those rules).
_VEX_REQUIRES: dict[str, dict[str, str]] = {
    "affected": {"action_statement": "Patching the affected gateways this week."},
    "not_affected": {"justification": "component_not_present"},
}


async def set_posture(client, headers, vulnerability: str, **body: Any):
    required = _VEX_REQUIRES.get(str(body.get("status")), {})
    return await client.put(
        f"{API}/postures",
        json={"vulnerability": vulnerability, **required, **body},
        headers=headers,
    )


async def read_posture(client, headers, posture_id):
    return await client.get(f"{API}/postures/{posture_id}", headers=headers)


# ---------------------------------------------------------------------------
# The member's own
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-70")
async def test_a_member_records_its_posture_and_the_default_is_under_investigation(client, world):
    recorded = await set_posture(client, world.member.person, world.published)

    assert recorded.status_code == 200, recorded.text
    assert recorded.json()["status"] == "under_investigation"
    assert recorded.json()["detection_deployed"] is False
    read = await read_posture(client, world.member.machine, recorded.json()["id"])
    assert read.status_code == 200
    assert read.json() == recorded.json()


@pytest.mark.requirement("SF-70")
async def test_the_isac_reading_a_members_posture_gets_the_404_an_absent_row_gets(client, world):
    recorded = await set_posture(client, world.member.person, world.published, status="affected")

    by_isac = await read_posture(client, world.editor, recorded.json()["id"])
    by_peer = await read_posture(client, world.reader.person, recorded.json()["id"])
    absent = await read_posture(client, world.editor, uuid.uuid4())

    assert by_isac.status_code == by_peer.status_code == absent.status_code == 404
    assert by_isac.text == absent.text


@pytest.mark.requirement("SF-70")
async def test_a_second_click_changes_the_one_row(client, world):
    first = await set_posture(client, world.member.person, world.published)
    second = await set_posture(
        client, world.member.person, world.published, status="fixed", detection_deployed=True
    )

    assert second.json()["id"] == first.json()["id"]
    assert second.json()["status"] == "fixed"
    assert second.json()["detection_deployed"] is True


@pytest.mark.requirement("SF-70", "SF-47")
async def test_a_posture_on_a_vulnerability_the_member_cannot_see_reads_as_absent(
    client, world, make_org, make_cert
):
    outsider = await make_org("harbour-trust")
    pem, _ = await make_cert(outsider)

    hidden = await set_posture(client, proxy_headers(pem), world.published)
    absent = await set_posture(client, proxy_headers(pem), f"vulnerability--{uuid.uuid4()}")

    assert hidden.status_code == absent.status_code == 404
    assert hidden.text == absent.text


async def test_a_posture_is_on_a_vulnerability_only(client, session, world):
    """Refused for an object the member *can* read, so the type check is what refuses."""
    indicator = await seed_visible_indicator(session, world)

    response = await set_posture(client, world.member.person, indicator)

    assert response.status_code == 404
    assert await session.scalar(select(func.count()).select_from(OrgPosture)) == 0


@pytest.mark.requirement("SF-70")
async def test_a_member_lists_its_own_postures_and_nobody_elses(client, world):
    mine = await set_posture(client, world.member.person, world.published)
    await set_posture(client, world.reader.person, world.published, status="affected")

    listed = await client.get(f"{API}/postures", headers=world.member.machine)
    by_isac = await client.get(f"{API}/postures", headers=world.editor)

    assert [row["id"] for row in listed.json()] == [mine.json()["id"]]
    assert by_isac.status_code == 200
    assert by_isac.json() == []


@pytest.mark.requirement("SF-70")
def test_no_member_posture_route_carries_a_vulnerability_id_in_its_path(app):
    """Request lines are logged with the caller's identity and leave the platform.

    "Firm X wrote a posture on V at t", beside the summary read before and
    after, is the status. Only the ISAC's summary may name a vulnerability in
    its path: the ISAC is the caller there, and it says nothing of a member.
    """
    posture_paths = {path for path, _method in walk_routes(app.routes) if "posture" in path}

    member_paths = posture_paths - {"/api/v1/vulnerabilities/{stix_id}/posture-summary"}
    assert member_paths == {
        "/api/v1/postures",
        "/api/v1/postures/openvex",
        "/api/v1/postures/{posture_id}",
        # The portal's form on the vulnerability page: the id is in the body.
        "/portal/vulnerabilities/posture",
    }


@pytest.mark.requirement("SF-70")
async def test_two_first_writes_of_one_posture_make_one_row(world, open_session):
    """The second first write waits for the first, then updates its row.

    It used to find no row, insert one, and meet ``uq_org_postures_org_vuln``
    as a 500 once the first committed.
    """
    ctx = _member_context(world)
    now = dt.datetime.now(dt.UTC)
    first, second = open_session(), open_session()
    winner = await record_posture(
        first,
        ctx,
        vulnerability_id=world.published,
        statement=VexStatement(PostureStatus.UNDER_INVESTIGATION),
        now=now,
    )
    loser = asyncio.create_task(
        record_posture(
            second,
            ctx,
            vulnerability_id=world.published,
            statement=VexStatement(
                PostureStatus.AFFECTED,
                action_statement="Patched the gateway",
                detection_deployed=True,
            ),
            now=now,
        )
    )
    await asyncio.sleep(0.3)
    assert not loser.done(), "the second write must wait for the first, not race past it"

    await first.commit()
    updated = await loser
    await second.commit()

    assert updated.id == winner.id
    assert updated.status is PostureStatus.AFFECTED


def _member_context(world) -> AuthContext:
    member = world.member.org
    grant = CircleGrant(
        CircleRole.CONTRIBUTOR, (MembershipInterval(dt.datetime(2000, 1, 1, tzinfo=dt.UTC)),)
    )
    return AuthContext(
        org_id=member.id,
        org_slug=member.slug,
        org_type=member.org_type,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.MTLS,
        circles={world.circle.id: grant},
    )


@pytest.mark.requirement("SF-70")
async def test_the_audit_row_says_a_posture_was_set_never_which(client, session, world):
    recorded = await set_posture(client, world.member.person, world.published, status="affected")

    row = await session.scalar(
        select(AuditLog).where(
            AuditLog.action == AuditAction.POSTURE_RECORDED,
            AuditLog.resource_id == recorded.json()["id"],
        )
    )
    assert row is not None
    assert "affected" not in str(vars(row))


# ---------------------------------------------------------------------------
# The ISAC's counts
# ---------------------------------------------------------------------------
async def _members_with_posture(world, client, make_org, make_cert, join_circle, statuses):
    orgs = []
    for index, status in enumerate(statuses):
        org = await make_org(f"posture-bank-{index}")
        pem, _ = await make_cert(org)
        await join_circle(org, world.circle)
        response = await set_posture(client, proxy_headers(pem), world.published, status=status)
        assert response.status_code == 200, response.text
        orgs.append(org)
    return orgs


@pytest.fixture
def summary(client, session):
    """The posture summary as a reviewer reads it once the publishing job has run."""

    async def _read(headers, vulnerability):
        await publish_postures(session, now=dt.datetime.now(dt.UTC))
        return await client.get(
            f"{API}/vulnerabilities/{vulnerability}/posture-summary", headers=headers
        )

    return _read


SPLIT = ["affected"] * K_ANONYMITY + ["not_affected"] * K_ANONYMITY


@pytest.mark.requirement("SF-70")
async def test_the_isac_sees_a_count_that_k_have_and_k_do_not(
    summary, client, world, make_org, make_cert, join_circle
):
    await _members_with_posture(world, client, make_org, make_cert, join_circle, SPLIT)

    summary = await summary(world.editor, world.published)

    assert summary.status_code == 200, summary.text
    by_status = summary.json()["by_status"]
    assert by_status["affected"]["value"] == by_status["not_affected"]["value"] == K_ANONYMITY
    assert by_status["fixed"] == {"value": None, "withheld": "fewer than 5"}
    assert summary.json()["total"]["value"] is None


@pytest.mark.requirement("SF-70")
async def test_a_unanimous_status_is_withheld(
    summary, client, world, make_org, make_cert, join_circle
):
    """Six of six affected, beside its audit rows, names six affected firms.

    The ISAC's audit log says which organisations recorded *a* posture; a
    count equal to the total, or an exact zero beside it, then states each
    one's status. The pair is the split above, where both counts are exact.
    """
    await _members_with_posture(
        world, client, make_org, make_cert, join_circle, ["affected"] * (K_ANONYMITY + 1)
    )

    summary = (await summary(world.editor, world.published)).json()

    assert summary["by_status"]["affected"] == {"value": None, "withheld": "all but fewer than 5"}
    assert summary["by_status"]["not_affected"] == {"value": None, "withheld": "fewer than 5"}
    assert summary["total"]["value"] is None


@pytest.mark.parametrize(("suspended", "affected"), [(True, None), (False, K_ANONYMITY)])
@pytest.mark.requirement("SF-70")
async def test_only_active_members_are_counted(
    summary, client, session, world, make_org, make_cert, join_circle, suspended, affected
):
    """A suspended firm's posture is not counted; the pair is the same firm active.

    Suspended before the count is first published: a suspension *after* it
    must move nothing, which the snapshot tests below pin.
    """
    orgs = await _members_with_posture(world, client, make_org, make_cert, join_circle, SPLIT)
    if suspended:
        orgs[0].status = OrgStatus.SUSPENDED
        await session.commit()

    counted = (await summary(world.editor, world.published)).json()

    assert counted["by_status"]["affected"]["value"] == affected


@pytest.mark.requirement("SF-70")
async def test_below_k_the_isac_sees_nothing(
    summary, client, world, make_org, make_cert, join_circle
):
    await _members_with_posture(
        world, client, make_org, make_cert, join_circle, ["affected"] * (K_ANONYMITY - 1)
    )

    summary = (await summary(world.editor, world.published)).json()

    too_few = {"value": None, "withheld": "shown once at least 5 organisations have one"}
    assert summary["total"] == too_few
    assert all(count == too_few for count in summary["by_status"].values())


async def test_the_counts_are_for_the_isacs_reviewers_only(summary, client, world):
    for headers in (world.member.person, world.reader.person):
        assert (await summary(headers, world.published)).status_code == 404


@pytest.mark.requirement("SF-70")
async def test_the_isacs_own_posture_does_not_count_toward_k(
    summary, client, world, make_org, make_cert, join_circle, isac
):
    """k-1 members and the ISAC are k rows and k-1 firms: still withheld.

    Ten members beside them, so the four are a count the two-sided rule
    would otherwise show; the five affected are the pair, shown exactly.
    """
    await join_circle(world.isac_org, world.circle)
    _isac_org, editor = isac
    isac_posture = await set_posture(client, editor, world.published, status="not_affected")
    assert isac_posture.status_code == 200
    await _members_with_posture(
        world,
        client,
        make_org,
        make_cert,
        join_circle,
        ["affected"] * K_ANONYMITY + ["not_affected"] * (K_ANONYMITY - 1) + ["fixed"],
    )

    summary = (await summary(world.editor, world.published)).json()

    assert summary["by_status"]["affected"]["value"] == K_ANONYMITY
    assert summary["by_status"]["not_affected"] == {"value": None, "withheld": "fewer than 5"}


@pytest.mark.requirement("SF-70")
async def test_counts_are_only_for_a_distributed_vulnerability(summary, client, session, world):
    """The pair is ``world.published``, which answers 200 above."""
    indicator = await seed_visible_indicator(session, world)

    for stix_id in (f"vulnerability--{uuid.uuid4()}", indicator):
        assert (await summary(world.editor, stix_id)).status_code == 404


def test_a_small_count_is_withheld_and_so_is_the_total_that_would_reveal_it():
    summary = _suppress(
        {
            PostureStatus.AFFECTED: K_ANONYMITY,
            PostureStatus.NOT_AFFECTED: K_ANONYMITY,
            PostureStatus.FIXED: 1,
        },
        None,
    )

    assert summary.by_status[PostureStatus.FIXED].value is None
    assert summary.by_status[PostureStatus.AFFECTED].value == K_ANONYMITY
    assert summary.total.value is None, "total minus the shown count is the withheld one"


def test_the_total_is_shown_only_when_every_count_is():
    """Every status between K and total-K: the total is their sum, and derives nothing."""
    summary = _suppress(dict.fromkeys(PostureStatus, K_ANONYMITY), None)

    assert {count.value for count in summary.by_status.values()} == {K_ANONYMITY}
    assert summary.total.value == K_ANONYMITY * len(PostureStatus)


@pytest.mark.requirement("SF-10")
async def test_a_fast_app_clock_does_not_show_a_member_an_embargo_early(
    client, session, world, monkeypatch
):
    """The posture's visibility check reads the database's clock, as the TAXII readers do.

    On a replica two hours fast, an app-clock "now" passed an embargo that is
    still an hour away, and the member could record a posture on it -- which
    told it the embargoed record existed.
    """
    embargoed = f"vulnerability--{uuid.uuid4()}"
    submission = await seed(
        session,
        world.isac_org,
        {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": embargoed,
            "created": STAMP,
            "modified": STAMP,
            "name": "Still under embargo",
        },
        circle=world.circle,
    )
    await session.execute(
        update(Distribution)
        .where(Distribution.submission_id == submission.id)
        .values(date_added=func.now() + dt.timedelta(hours=1))
    )
    await session.commit()
    skew_clock(monkeypatch, contributions_api, dt.timedelta(hours=2))

    response = await set_posture(client, world.member.person, embargoed)

    assert response.status_code == 404
    assert await session.scalar(select(StixObject.id).where(StixObject.stix_id == embargoed))


# ---------------------------------------------------------------------------
# Published, not live: one firm's change moves nothing (R-C3, R2-C1)
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-80")
async def test_one_firms_posture_write_moves_no_published_count(
    summary, client, session, world, make_org, make_cert, join_circle
):
    """The audit log names the firm that wrote; the summary must not then say what.

    Read live, the summary before and after one firm moved from affected to
    fixed went from 5 affected to "fewer than 5": that firm was fixed. So
    was suspending one firm, which an editor can do at will.
    """
    orgs = await _members_with_posture(world, client, make_org, make_cert, join_circle, SPLIT)
    before = (await summary(world.editor, world.published)).json()
    pem, _ = await make_cert(orgs[0])
    await set_posture(client, proxy_headers(pem), world.published, status="fixed")
    orgs[1].status = OrgStatus.SUSPENDED
    await session.commit()

    after = (await summary(world.editor, world.published)).json()

    assert after == before
    assert after["as_of"] is not None


@pytest.mark.requirement("SF-80")
async def test_k_firms_changing_republishes_the_summary(
    summary, client, world, make_org, make_cert, join_circle
):
    """The pair: once K firms have changed, the counts move, all together."""
    orgs = await _members_with_posture(world, client, make_org, make_cert, join_circle, SPLIT)
    before = (await summary(world.editor, world.published)).json()
    for org in orgs[:K_ANONYMITY]:
        pem, _ = await make_cert(org)
        await set_posture(client, proxy_headers(pem), world.published, status="fixed")

    after = (await summary(world.editor, world.published)).json()

    assert before["by_status"]["fixed"]["value"] is None
    assert after["by_status"]["fixed"]["value"] == K_ANONYMITY
    assert after["by_status"]["affected"] == {"value": None, "withheld": "fewer than 5"}
    assert after["as_of"] > before["as_of"]
