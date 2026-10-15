"""The ISAC's auditor is served the instance, but not who filed what (Phase P slice 3d, SF-94).

Who filed a submission is ISAC intel staff's alone (Q37). The auditor reads
every row, so a row about a submission or a contribution is served without
its organisation, actor, request id and source address, and with only the
``details`` keys that cannot name the filer -- unless the ISAC itself acted,
which is what the auditor is there to check. Each test drives the real writer
(the API, the triage job, the on-behalf filing, the one-click lane) and reads
what the auditor's stream serves of it. Where a test hand-builds rows, it is
testing the reader's rule about transactions or unknown values, which no
writer produces on purpose.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import uuid
from collections.abc import Callable

import pytest

from aivs_schemas.enums import OperatorRole
from aivs_server.audit.log import AuditAction, record
from aivs_server.services.audit_stream import genesis
from aivs_server.services.triage import triage_pending
from tests.conftest import TEST_ATTRIBUTION_KEY, proxy_headers
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world, one_click
from tests.unit.test_auditor import _all, _link
from tests.unit.test_proxy_filing import file_for

pytestmark = [pytest.mark.db, pytest.mark.horizon, pytest.mark.requirement("SF-94")]

EVENTS = "/api/v1/audit/events"
TITLE = "Meridian's agent gateway leaks its tool tokens"
IDENTITY = ("org_id", "actor_type", "actor_id", "request_id", "source_ip")


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


@pytest.fixture
async def auditor(isac_org, make_cert, make_operator, human_headers) -> dict[str, str]:
    pem, _ = await make_cert(isac_org)
    person, _ = await make_operator(
        isac_org,
        roles=(OperatorRole.AUDITOR,),
        role_expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=30),
    )
    return await human_headers(person, pem)


async def _served(client, headers, wanted: Callable[[list[dict]], bool]) -> list[dict]:
    """Every event the auditor is served, once ``wanted`` holds of them.

    Bounded: the horizon stalls the stream while another transaction is open
    anywhere on the cluster, and a row that never arrives fails here.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 60
    while True:
        events = await _all(client, EVENTS, headers)
        if wanted(events):
            return events
        assert loop.time() < deadline, events
        await asyncio.sleep(0.5)


def _about(events: list[dict], resource_id: str) -> list[dict]:
    return [event for event in events if event["resource_id"] == resource_id]


def _has(*actions: str, resource_id: str) -> Callable[[list[dict]], bool]:
    return lambda events: set(actions) <= {e["action"] for e in _about(events, resource_id)}


async def _filed(client, pem: str) -> str:
    created = await client.post(
        f"{API}/submissions",
        json={
            "title": TITLE,
            "discovery_scope": "own_estate",
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": []},
        },
        headers=proxy_headers(pem),
    )
    assert created.status_code == 201, created.text
    submission_id = created.json()["id"]
    submitted = await client.post(
        f"{API}/submissions/{submission_id}/submit", json={}, headers=proxy_headers(pem)
    )
    assert submitted.status_code == 200, submitted.text
    return submission_id


def _names(events: list[dict], *identifiers: str) -> list[str]:
    served = json.dumps(events)
    return [identifier for identifier in identifiers if identifier in served]


# ---------------------------------------------------------------------------
# A member's own acts on its filing
# ---------------------------------------------------------------------------
async def test_a_members_filing_reaches_the_isacs_auditor_without_who_filed_it(
    client, session, world, auditor
):
    member = world.member
    submission_id = await _filed(client, member.pem)
    await triage_pending(session, TEST_ATTRIBUTION_KEY, now=dt.datetime.now(dt.UTC))
    await session.commit()

    wanted = _has(
        AuditAction.SUBMISSION_CREATED,
        AuditAction.SUBMISSION_TRANSITIONED,
        AuditAction.SUBMISSION_TRIAGED,
        resource_id=submission_id,
    )
    about = _about(await _served(client, auditor, wanted), submission_id)

    assert all(event[field] is None for event in about for field in IDENTITY), about
    assert _names(about, str(member.org.id), member.org.slug, str(member.operator.id), TITLE) == []


async def test_a_contribution_reaches_the_isacs_auditor_without_its_contributor(
    client, world, auditor
):
    contributed = await one_click(client, world.member.person, world.published)
    assert contributed.status_code == 201, contributed.text
    submission_id = contributed.json()["submission_id"]

    wanted = _has(AuditAction.CONTRIBUTION_PUBLISHED, resource_id=submission_id)
    about = _about(await _served(client, auditor, wanted), submission_id)

    assert all(event[field] is None for event in about for field in IDENTITY), about
    assert _names(about, str(world.member.org.id), world.member.org.slug) == []


# ---------------------------------------------------------------------------
# The ISAC's own acts on content keep who did them
# ---------------------------------------------------------------------------
async def test_an_editors_validation_names_the_editor_and_never_the_filer(client, world, auditor):
    member = world.member
    submission_id = await _filed(client, member.pem)
    validated = await client.post(
        f"{API}/submissions/{submission_id}/validate", json={}, headers=world.editor
    )
    assert validated.status_code == 200, validated.text

    def editor_moved(event: dict) -> bool:
        return (
            event["action"] == AuditAction.SUBMISSION_TRANSITIONED
            and event["details"].get("to") == "validated"
        )

    events = await _served(
        client, auditor, lambda served: any(map(editor_moved, _about(served, submission_id)))
    )
    about = _about(events, submission_id)
    by_editor = next(event for event in about if editor_moved(event))

    assert by_editor["org_id"] == str(world.isac_org.id)
    assert by_editor["actor_id"] is not None
    assert _names(about, str(member.org.id), member.org.slug) == []


async def test_a_filing_on_a_members_behalf_names_the_editor_and_never_the_member(
    client, world, auditor
):
    member = world.member
    filed = await file_for(client, world, member.org.id)
    assert filed.status_code == 201, filed.text
    submission_id = filed.json()["id"]

    wanted = _has(AuditAction.SUBMISSION_FILED_ON_BEHALF, resource_id=submission_id)
    about = _about(await _served(client, auditor, wanted), submission_id)
    on_behalf = next(e for e in about if e["action"] == AuditAction.SUBMISSION_FILED_ON_BEHALF)

    assert on_behalf["org_id"] == str(world.isac_org.id)
    assert _names(about, str(member.org.id), member.org.slug) == []


# ---------------------------------------------------------------------------
# The reader's rules: a transaction, an unknown action, an unknown rule
# ---------------------------------------------------------------------------
async def _row(session, action: str, org_id: uuid.UUID, marker: str, **details: object) -> None:
    await record(
        session,
        action=action,
        actor_type="operator",
        actor_id=f"operator:{marker}",
        org_id=org_id,
        resource_type="test",
        resource_id=marker,
        request_id=f"request-{marker}",
        details=details,
    )


async def test_a_members_row_in_a_content_rows_transaction_is_served_as_content(
    client, session, world, auditor
):
    """Every row of one transaction shares its ``at`` and its request id, so a
    member's row beside a content row would say who wrote the content row."""
    org_id = world.member.org.id
    await _row(session, AuditAction.SUBMISSION_UPDATED, org_id, "beside-content")
    await _row(session, AuditAction.WEBHOOK_CREATED, org_id, "beside-webhook")
    await session.commit()
    await _row(session, AuditAction.WEBHOOK_CREATED, org_id, "alone-webhook")
    await session.commit()

    markers = ("beside-content", "beside-webhook", "alone-webhook")
    events = await _served(
        client, auditor, lambda served: all(_about(served, marker) for marker in markers)
    )
    beside, alone = _about(events, "beside-webhook")[0], _about(events, "alone-webhook")[0]

    assert [beside[field] for field in IDENTITY] == [None] * len(IDENTITY)
    assert alone["org_id"] == str(org_id)


async def test_an_action_nobody_classified_is_served_as_content(client, session, world, auditor):
    await _row(session, "made.up", world.member.org.id, "unclassified")
    await session.commit()

    events = await _served(client, auditor, lambda served: bool(_about(served, "unclassified")))

    assert _about(events, "unclassified")[0]["org_id"] is None


async def test_a_finding_from_a_rule_nobody_classified_is_served_without_its_details(
    client, session, world, auditor
):
    await record(
        session,
        action=AuditAction.DETECTION_RAISED,
        resource_type="detection",
        resource_id="made_up_rule",
        details={
            "rule": "made_up_rule",
            "summary": "s",
            "recorded_filer": str(world.member.org.id),
        },
    )
    await session.commit()

    events = await _served(client, auditor, lambda served: bool(_about(served, "made_up_rule")))

    assert "recorded_filer" not in _about(events, "made_up_rule")[0]["details"]


# ---------------------------------------------------------------------------
# The chain is over what was served
# ---------------------------------------------------------------------------
async def test_the_chain_verifies_over_a_page_that_holds_content_rows(client, world, auditor):
    submission_id = await _filed(client, world.member.pem)
    events = await _served(
        client, auditor, _has(AuditAction.SUBMISSION_CREATED, resource_id=submission_id)
    )

    chain = genesis("audit", None).chain
    for event in events:
        chain = _link(chain, {key: value for key, value in event.items() if key != "hash"})
        assert chain == event["hash"], event


def test_the_chain_version_is_two():
    label = "aivs-audit-chain/v2|instance"
    assert genesis("audit", None).chain == hashlib.sha256(label.encode()).hexdigest()
