"""A member's posture on a vulnerability: its own, and counts for the ISAC (SF-70).

Whether a firm is ``affected`` is the fact its counsel will not let the ISAC
hold per firm. A posture row is therefore read and written by its own
organisation alone -- anyone else, the ISAC included, gets the 404 an absent
row gets -- and the ISAC sees counts, each withheld below k.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select

from aivs_schemas.enums import PostureStatus
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog
from aivs_server.services.posture import _suppress
from aivs_server.services.telemetry import K_ANONYMITY
from tests.conftest import proxy_headers
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world

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


async def set_posture(client, headers, vulnerability: str, **body: Any):
    return await client.put(
        f"{API}/vulnerabilities/{vulnerability}/posture", json=body, headers=headers
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


async def test_a_posture_is_on_a_vulnerability_only(client, world):
    response = await set_posture(client, world.member.person, f"indicator--{uuid.uuid4()}")

    assert response.status_code == 404


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
    for index, status in enumerate(statuses):
        org = await make_org(f"posture-bank-{index}")
        pem, _ = await make_cert(org)
        await join_circle(org, world.circle)
        response = await set_posture(client, proxy_headers(pem), world.published, status=status)
        assert response.status_code == 200, response.text


async def _summary(client, headers, vulnerability):
    return await client.get(
        f"{API}/vulnerabilities/{vulnerability}/posture-summary", headers=headers
    )


@pytest.mark.requirement("SF-70")
async def test_the_isac_sees_counts_at_or_above_k(client, world, make_org, make_cert, join_circle):
    await _members_with_posture(
        world, client, make_org, make_cert, join_circle, ["affected"] * K_ANONYMITY
    )

    summary = await _summary(client, world.editor, world.published)

    assert summary.status_code == 200, summary.text
    assert summary.json()["total"]["value"] == K_ANONYMITY
    assert summary.json()["by_status"]["affected"]["value"] == K_ANONYMITY
    assert summary.json()["by_status"]["fixed"]["value"] == 0


@pytest.mark.requirement("SF-70")
async def test_below_k_the_isac_sees_nothing(client, world, make_org, make_cert, join_circle):
    await _members_with_posture(
        world, client, make_org, make_cert, join_circle, ["affected"] * (K_ANONYMITY - 1)
    )

    summary = (await _summary(client, world.editor, world.published)).json()

    assert summary["total"]["value"] is None
    assert {count["value"] for count in summary["by_status"].values()} == {None}


async def test_the_counts_are_for_the_isacs_reviewers_only(client, world):
    for headers in (world.member.person, world.reader.person):
        assert (await _summary(client, headers, world.published)).status_code == 404


def test_a_small_count_is_withheld_and_so_is_the_total_that_would_reveal_it():
    summary = _suppress({PostureStatus.AFFECTED: K_ANONYMITY + 2, PostureStatus.FIXED: 1})

    assert summary.by_status[PostureStatus.FIXED].value is None
    assert summary.by_status[PostureStatus.AFFECTED].value == K_ANONYMITY + 2
    assert summary.total.value is None, "total minus the shown count is the withheld one"


def test_a_zero_is_shown_and_does_not_withhold_the_total():
    summary = _suppress({PostureStatus.AFFECTED: K_ANONYMITY})

    assert summary.by_status[PostureStatus.FIXED].value == 0
    assert summary.total.value == K_ANONYMITY
