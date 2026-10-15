"""Anonymous by default, and kept by an object's first distribution (Mike, Q16; W2-C1).

A member's filing is anonymous to other members unless it asks for credit, on
every door: the API, the portal, the CLI and the TAXII inbox. The ISAC's own
filings are the ISAC's whatever the flag says, so asking for anonymity there is
refused rather than stored.

Only the owner versions an object, so the anonymity of one version tells
members about every other: an attributed version followed by an anonymous one
names the anonymous one's submitter. Once a version is distributed, later
versions keep its choice (SF-85), refused at ingest, at validate and at
distribution.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select

from aivs_schemas.enums import OperatorRole
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog, Submission
from aivs_server.services.submissions import ISAC_FILINGS_ARE_ATTRIBUTED
from tests.conftest import proxy_headers
from tests.unit.contribution_world import (
    LATER,
    STAMP,
    distribute,
    submit_and_validate,
)
from tests.unit.test_portal import bundle as portal_bundle
from tests.unit.test_portal import csrf_of, sign_in
from tests.unit.test_portal import make_operator as portal_make_operator

pytestmark = pytest.mark.db

API = "/api/v1/submissions"
PIN_RULE = "an object keeps the anonymity of its first distributed version"


def _vulnerability(stix_id: str, modified: str) -> dict[str, Any]:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id,
        "created": STAMP,
        "modified": modified,
        "name": f"Gateway bypass ({modified})",
    }


def _body(objects: list[dict[str, Any]], anonymous: bool | None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "title": "A finding",
        "discovery_scope": "own_product",
        "tlp": "amber",
        "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects},
    }
    if anonymous is not None:
        body["distribute_anonymously"] = anonymous
    return body


@pytest.fixture
async def world(isac, make_org, make_cert, make_circle, join_circle):
    _isac_org, editor = isac
    vendor = await make_org("anonymity-vendor")
    pem, _ = await make_cert(vendor)
    peer = await make_org("anonymity-peer")
    peer_pem, _ = await make_cert(peer)
    circle = await make_circle("anonymity-circle")
    await join_circle(vendor, circle)
    await join_circle(peer, circle)
    return {
        "editor": editor,
        "member": proxy_headers(pem),
        "pem": pem,
        "peer": proxy_headers(peer_pem),
        "circle": circle,
        "stix_id": f"vulnerability--{uuid.uuid4()}",
    }


async def _filed(client, world, modified: str, *, anonymous: bool | None, as_peer=False):
    headers = world["peer"] if as_peer else world["member"]
    return await client.post(
        API, json=_body([_vulnerability(world["stix_id"], modified)], anonymous), headers=headers
    )


async def _filed_id(client, world, modified: str, *, anonymous: bool | None) -> str:
    filed = await _filed(client, world, modified, anonymous=anonymous)
    assert filed.status_code == 201, filed.text
    return str(filed.json()["id"])


async def _validated(client, world, submission_id: str) -> None:
    validated = await submit_and_validate(client, world["pem"], submission_id, world["editor"])
    assert validated.status_code == 200, validated.text


async def _published(client, world, modified: str, *, anonymous: bool) -> str:
    submission_id = await _filed_id(client, world, modified, anonymous=anonymous)
    await _validated(client, world, submission_id)
    published = await distribute(client, submission_id, world["editor"], world["circle"])
    assert published.status_code == 200, published.text
    return submission_id


async def _refusal_reasons(session) -> list[str]:
    rows = await session.scalars(
        select(AuditLog).where(AuditLog.action == AuditAction.SUBMISSION_TRANSITION_REFUSED)
    )
    return [str(row.details["reason"]) for row in rows]


# ---------------------------------------------------------------------------
# The default, on every door
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-85")
@pytest.mark.parametrize(
    ("asked", "anonymous"), [(None, True), (False, False), (True, True)], ids=str
)
async def test_a_members_filing_is_anonymous_unless_it_asks_for_credit(
    client, world, asked, anonymous
):
    filed = await _filed(client, world, STAMP, anonymous=asked)

    assert filed.status_code == 201, filed.text
    assert filed.json()["distribute_anonymously"] is anonymous


@pytest.mark.requirement("SF-85")
async def test_the_isacs_own_filing_is_attributed_and_cannot_ask_for_anonymity(client, world):
    objects = [_vulnerability(world["stix_id"], STAMP)]

    defaulted = await client.post(API, json=_body(objects, None), headers=world["editor"])
    asked = await client.post(API, json=_body(objects, True), headers=world["editor"])

    assert defaulted.status_code == 201, defaulted.text
    assert defaulted.json()["distribute_anonymously"] is False
    assert asked.status_code == 400
    assert ISAC_FILINGS_ARE_ATTRIBUTED in asked.text


async def test_the_isacs_draft_cannot_be_patched_anonymous(client, world):
    filed = await client.post(
        API, json=_body([_vulnerability(world["stix_id"], STAMP)], None), headers=world["editor"]
    )
    patched = await client.patch(
        f"{API}/{filed.json()['id']}",
        json={"distribute_anonymously": True},
        headers=world["editor"],
    )

    assert patched.status_code == 400
    assert ISAC_FILINGS_ARE_ATTRIBUTED in patched.text


async def _portal_member(client, session, secret_box, make_org, make_cert):
    org = await make_org("portal-filer")
    pem, _ = await make_cert(org)
    operator, secret = await portal_make_operator(session, secret_box, org)
    await sign_in(client, operator, secret, pem)
    return pem


@pytest.mark.requirement("SF-85")
@pytest.mark.parametrize(("ticked", "anonymous"), [(False, True), (True, False)], ids=str)
async def test_the_portal_files_anonymously_unless_credit_is_ticked(
    client, session, secret_box, make_org, make_cert, ticked, anonymous
):
    pem = await _portal_member(client, session, secret_box, make_org, make_cert)
    form = await client.get("/portal/submit", headers=proxy_headers(pem))
    assert "data-credit-my-firm" in form.text

    data = {
        "title": "Filed from the portal",
        "discovery_scope": "ai_system",
        "tlp": "amber",
        "bundle": portal_bundle(),
        "csrf_token": csrf_of(client),
    }
    if ticked:
        data["credit_my_firm"] = "1"
    filed = await client.post("/portal/submit", data=data, headers=proxy_headers(pem))

    assert filed.status_code == 303, filed.text
    stored = await session.scalar(select(Submission.distribute_anonymously))
    assert stored is anonymous


async def test_the_portal_offers_isac_staff_no_anonymity_choice(
    client, session, secret_box, isac_org, make_cert
):
    pem, _ = await make_cert(isac_org)
    operator, secret = await portal_make_operator(
        session, secret_box, isac_org, roles=(OperatorRole.ISAC_EDITOR,), email="ed@isac.test"
    )
    await sign_in(client, operator, secret, pem)

    form = await client.get("/portal/submit", headers=proxy_headers(pem))

    assert form.status_code == 200, form.text
    assert "data-credit-my-firm" not in form.text


# ---------------------------------------------------------------------------
# An object keeps its first distribution's choice
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-85")
@pytest.mark.parametrize("first_anonymous", [True, False], ids=["anonymous", "credited"])
async def test_a_later_version_cannot_change_a_distributed_objects_anonymity(
    client, world, first_anonymous
):
    await _published(client, world, STAMP, anonymous=first_anonymous)

    changed = await _filed(client, world, LATER, anonymous=not first_anonymous)
    kept = await _filed(client, world, LATER, anonymous=first_anonymous)

    assert changed.status_code == 400, changed.text
    assert PIN_RULE in changed.text
    assert world["stix_id"] in changed.text
    assert kept.status_code == 201, kept.text


@pytest.mark.requirement("SF-85")
async def test_patching_the_flag_alone_is_checked_against_the_first_distribution(client, world):
    """The property is checked against the submission as it stands, not only
    the write that carried a bundle (CLAUDE.md section 5)."""
    await _published(client, world, STAMP, anonymous=True)
    later = await _filed_id(client, world, LATER, anonymous=True)

    patched = await client.patch(
        f"{API}/{later}", json={"distribute_anonymously": False}, headers=world["member"]
    )

    assert patched.status_code == 400, patched.text
    assert PIN_RULE in patched.text


@pytest.mark.requirement("SF-85")
async def test_an_undistributed_version_pins_nothing(client, world):
    """A draft, or a version withdrawn before distribution, reached no member."""
    first = await _filed_id(client, world, STAMP, anonymous=True)
    withdrawn = await client.post(f"{API}/{first}/withdraw", json={}, headers=world["member"])
    assert withdrawn.status_code == 200, withdrawn.text

    other_choice = await _filed(client, world, LATER, anonymous=False)

    assert other_choice.status_code == 201, other_choice.text


@pytest.mark.requirement("SF-85")
async def test_a_version_filed_before_the_first_distribution_is_refused_at_validate(
    client, session, world
):
    """Accepted at ingest, when nothing was distributed yet; by validate the
    first version has gone out with the other choice."""
    later = await _filed_id(client, world, LATER, anonymous=False)
    sent = await client.post(f"{API}/{later}/submit", json={}, headers=world["member"])
    assert sent.status_code == 200, sent.text
    await _published(client, world, STAMP, anonymous=True)

    refused = await client.post(f"{API}/{later}/validate", json={}, headers=world["editor"])

    assert refused.status_code == 409, refused.text
    [reason] = await _refusal_reasons(session)
    assert reason.startswith(PIN_RULE)


@pytest.mark.requirement("SF-85")
async def test_a_version_validated_before_the_first_distribution_is_refused_at_distribution(
    client, session, world
):
    later = await _filed_id(client, world, LATER, anonymous=False)
    await _validated(client, world, later)
    await _published(client, world, STAMP, anonymous=True)

    refused = await distribute(client, later, world["editor"], world["circle"])

    assert refused.status_code == 409, refused.text
    [reason] = await _refusal_reasons(session)
    assert reason.startswith(PIN_RULE)


async def test_another_firms_object_is_not_the_members_to_be_told_about(client, world):
    """Only the filer's own versions are compared, so the refusal is no oracle
    over who distributed which id and how: a peer filing under the member's id
    is not refused at ingest by this rule (owner-only versioning refuses it at
    validate, where the actor is the ISAC)."""
    await _published(client, world, STAMP, anonymous=True)

    filed = await _filed(client, world, LATER, anonymous=False, as_peer=True)

    assert filed.status_code == 201, filed.text
