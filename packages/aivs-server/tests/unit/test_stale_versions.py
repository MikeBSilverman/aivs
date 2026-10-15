"""Newest-version-only (SF-82): a version that would not be the newest is refused.

Members' TIPs keep the version with the latest ``modified``. A correction
published with a ``modified`` no later than a version its owner already
distributed reaches every member and is shown by none: the warning a member
would swear it never received (CLAUDE.md section 5). So validate, distribution
and embargo release each refuse it, and say why where the ISAC will see it.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy import select

from aivs_schemas.enums import OrgType
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog, Distribution, Embargo
from aivs_server.services.embargo import HELD_UNTIL_RELEASED, sweep_due_embargoes
from aivs_server.services.instance_status import gather_status
from aivs_server.services.ownership import STALE_VERSION
from tests.conftest import ISAC_STAFF_ROLES, proxy_headers
from tests.unit.contribution_world import (
    LATER,
    STAMP,
    distribute,
    file,
    seed,
    submit_and_validate,
    vulnerability_raw,
)
from tests.unit.test_portal import csrf_of, sign_in
from tests.unit.test_portal import make_operator as portal_make_operator

pytestmark = pytest.mark.db

API = "/api/v1/submissions"
#: Between STAMP and LATER: a correction written before the newer version.
BETWEEN = "2026-08-15T00:00:00.000Z"


def _vulnerability(stix_id: str, modified: str, name: str) -> dict[str, Any]:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id,
        "created": STAMP,
        "modified": modified,
        "name": name,
    }


@pytest.fixture
async def world(isac, make_org, make_cert, make_circle, join_circle):
    _isac_org, editor = isac
    vendor = await make_org("stale-vendor")
    pem, _ = await make_cert(vendor)
    circle = await make_circle("stale-circle")
    await join_circle(vendor, circle)
    return {
        "editor": editor,
        "pem": pem,
        "circle": circle,
        "stix_id": f"vulnerability--{uuid.uuid4()}",
    }


async def _filed(client, world, modified: str, name: str) -> str:
    filed = await file(client, world["pem"], [_vulnerability(world["stix_id"], modified, name)])
    assert filed.status_code == 201, filed.text
    return str(filed.json()["id"])


async def _published(client, world, modified: str, name: str, **distribute_body: Any) -> str:
    submission_id = await _filed(client, world, modified, name)
    validated = await submit_and_validate(client, world["pem"], submission_id, world["editor"])
    assert validated.status_code == 200, validated.text
    body = {"circle_ids": [str(world["circle"].id)], **distribute_body}
    published = await client.post(
        f"{API}/{submission_id}/distribute", json=body, headers=world["editor"]
    )
    assert published.status_code == 200, published.text
    return submission_id


async def _refusals(session) -> list[dict[str, Any]]:
    rows = await session.scalars(
        select(AuditLog).where(AuditLog.action == AuditAction.SUBMISSION_TRANSITION_REFUSED)
    )
    return [row.details for row in rows]


# ---------------------------------------------------------------------------
# Validate and distribution
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-82")
@pytest.mark.parametrize("correction", [BETWEEN, LATER], ids=["older", "equal"])
async def test_a_version_no_later_than_a_distributed_one_is_refused_at_validate(
    client, session, world, correction
):
    """An equal ``modified`` too: a TIP takes it for the version it already
    holds and keeps whichever it saw first."""
    await _published(client, world, LATER, "Gateway bypass, as first published")
    correction_id = await _filed(client, world, correction, "Gateway bypass, corrected")

    refused = await submit_and_validate(client, world["pem"], correction_id, world["editor"])

    assert refused.status_code == 409, refused.text
    assert STALE_VERSION in refused.text
    [refusal] = await _refusals(session)
    assert refusal["verb"] == "validated"
    assert refusal["reason"].startswith(STALE_VERSION)
    assert world["stix_id"] in refusal["reason"]


@pytest.mark.requirement("SF-82")
async def test_a_version_overtaken_after_validate_is_refused_at_distribution(
    client, session, world
):
    """Validated while it was the newest; a newer version is distributed before
    it is. The last moment it can still be refused is its own distribution."""
    correction_id = await _filed(client, world, BETWEEN, "Gateway bypass, corrected")
    validated = await submit_and_validate(client, world["pem"], correction_id, world["editor"])
    assert validated.status_code == 200, validated.text
    await _published(client, world, LATER, "Gateway bypass, revised again")

    refused = await distribute(client, correction_id, world["editor"], world["circle"])

    assert refused.status_code == 409, refused.text
    [refusal] = await _refusals(session)
    assert refusal["verb"] == "distributed"
    assert refusal["reason"].startswith(STALE_VERSION)


@pytest.mark.requirement("SF-82")
async def test_a_later_version_is_accepted(client, world):
    await _published(client, world, BETWEEN, "Gateway bypass")
    await _published(client, world, LATER, "Gateway bypass, revised")


@pytest.mark.requirement("SF-82")
async def test_an_embargoed_newer_version_counts(client, session, world):
    """Not yet readable, but every member's TIP will hold it at release."""
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=2)
    await _published(client, world, LATER, "Gateway bypass", release_at=later.isoformat())
    correction_id = await _filed(client, world, BETWEEN, "Gateway bypass, corrected")

    refused = await submit_and_validate(client, world["pem"], correction_id, world["editor"])

    assert refused.status_code == 409, refused.text


# ---------------------------------------------------------------------------
# Embargo release
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-82")
async def test_an_embargoed_version_overtaken_before_release_is_held_and_shown(
    client, session, world, secret_box
):
    """The timer would release a version no TIP will show. It is held, its
    content stays hidden, and the hold is on the status page with its reason:
    a silently held timer is the failure this guards against."""
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=2)
    held_id = await _published(
        client, world, BETWEEN, "Gateway bypass, corrected", release_at=later.isoformat()
    )
    await _published(client, world, LATER, "Gateway bypass, revised again")

    await sweep_due_embargoes(session)

    stamps = await session.scalars(
        select(Distribution.date_added).where(Distribution.submission_id == uuid.UUID(held_id))
    )
    assert set(stamps) == {HELD_UNTIL_RELEASED}, "still hidden"
    held = await session.scalar(
        select(AuditLog).where(
            AuditLog.action == AuditAction.EMBARGO_HELD, AuditLog.resource_id == held_id
        )
    )
    assert held is not None
    assert held.details["reason"].startswith(STALE_VERSION)
    status = await gather_status(
        session, now=dt.datetime.now(dt.UTC), box=secret_box, email_max_attempts=5
    )
    assert [
        (h["submission_id"], h["reason"][: len(STALE_VERSION)]) for h in status.held_embargoes
    ] == [(held_id, STALE_VERSION)]


@pytest.mark.requirement("SF-82")
async def test_an_embargo_is_not_refused_against_its_own_versions(client, session, world):
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=2)
    embargoed_id = await _published(
        client, world, LATER, "Gateway bypass", release_at=later.isoformat()
    )

    await sweep_due_embargoes(session)

    embargo = await session.scalar(
        select(Embargo).where(Embargo.submission_id == uuid.UUID(embargoed_id))
    )
    await session.refresh(embargo)
    assert embargo.release_at is not None, "still on its timer"


# ---------------------------------------------------------------------------
# The case that found it (R2-P2): a KEV version filed over an ISAC draft
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-82")
async def test_an_isac_draft_correction_overtaken_by_a_kev_version_is_refused(
    client, session, isac, isac_org, make_org, make_cert, make_circle
):
    """The KEV script skips records with a version in review, not drafts, so a
    forgotten draft cannot hold it back. The draft correction, written before
    the KEV version, is then refused when an editor sends it on, rather than
    published and outranked. The ISAC and its automation are one owner."""
    _org, editor = isac
    circle = await make_circle("kev-over-draft")
    record_id = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session,
        isac_org,
        vulnerability_raw(record_id, cve_status="published"),
        circle=circle,
    )
    correction = _vulnerability(record_id, BETWEEN, "Corrected by an editor")
    drafted = await client.post(
        API,
        json={
            "title": "Correction",
            "discovery_scope": "ai_system",
            "tlp": "amber",
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [correction]},
        },
        headers=editor,
    )
    assert drafted.status_code == 201, drafted.text
    automation = await make_org("isac-automation", org_type=OrgType.AUTOMATION)
    automation_pem, _ = await make_cert(automation)
    kev_version = _vulnerability(record_id, LATER, "Known exploited")
    kev = await file(client, automation_pem, [kev_version], scope="ai_system")
    assert kev.status_code == 201, kev.text
    kev_id = kev.json()["id"]
    sent = await submit_and_validate(client, automation_pem, kev_id, editor, sender=editor)
    assert sent.status_code == 200
    assert (await distribute(client, kev_id, editor, circle)).status_code == 200

    draft_id = drafted.json()["id"]
    submitted = await client.post(f"{API}/{draft_id}/submit", json={}, headers=editor)
    refused = await client.post(f"{API}/{draft_id}/validate", json={}, headers=editor)

    assert submitted.status_code == 200, submitted.text
    assert refused.status_code == 409, refused.text
    assert STALE_VERSION in refused.text


@pytest.mark.requirement("SF-82")
async def test_the_portal_records_the_same_refusal_and_no_authorization_failure(
    client, session, world, secret_box, make_cert, isac_org
):
    """The refusal through the other door is the same row: a content rule
    declining a verb is not an authorization failure, and recording it as one
    put editors' everyday refusals beside real denials."""
    await _published(client, world, LATER, "Gateway bypass, as first published")
    correction_id = await _filed(client, world, BETWEEN, "Gateway bypass, corrected")
    submitted = await client.post(
        f"{API}/{correction_id}/submit", json={}, headers=proxy_headers(world["pem"])
    )
    assert submitted.status_code == 200, submitted.text
    pem, _ = await make_cert(isac_org)
    operator, secret = await portal_make_operator(
        session, secret_box, isac_org, roles=ISAC_STAFF_ROLES, email="stale-editor@isac.test"
    )
    await sign_in(client, operator, secret, pem)

    await client.post(
        f"/portal/submissions/{correction_id}/validate",
        data={"csrf_token": csrf_of(client)},
        headers=proxy_headers(pem),
    )

    [refusal] = await _refusals(session)
    assert (refusal["verb"], refusal["reason"][: len(STALE_VERSION)]) == ("validate", STALE_VERSION)
    denied = await session.scalars(
        select(AuditLog).where(AuditLog.action == AuditAction.ACCESS_DENIED)
    )
    assert list(denied) == []
