"""The auditor reads the audit trail and receipts, in scope, in commit order, chained.

Each property is a pair: what the auditor is given, and what it is not.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import (
    TLP,
    AckType,
    AckVia,
    DiscoveryScope,
    OperatorRole,
    OrgStatus,
    OrgType,
    SubmissionState,
)
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.policy import can_hold_evidence_pack, can_read_audit, can_view_submission
from aivs_server.db.models import Acknowledgment, AuditLog, Submission
from aivs_server.services.audit_stream import genesis
from aivs_server.services.operators import OperatorError, create_operator
from tests.conftest import seed_filing

pytestmark = pytest.mark.db

EVENTS = "/api/v1/audit/events"
RECEIPTS = "/api/v1/audit/receipts"


def _later(days: int = 30) -> dt.datetime:
    return dt.datetime.now(dt.UTC) + dt.timedelta(days=days)


@pytest.fixture
async def world(make_org, make_cert, make_operator, human_headers, isac_org):
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    peer = await make_org("harbour-trust", org_type=OrgType.GSIB)
    isac_pem, _ = await make_cert(isac_org)
    member_pem, _ = await make_cert(member)
    isac_auditor, _ = await make_operator(
        isac_org, roles=(OperatorRole.AUDITOR,), role_expires_at=_later()
    )
    member_auditor, _ = await make_operator(
        member, roles=(OperatorRole.AUDITOR,), role_expires_at=_later()
    )
    return {
        "member": member,
        "peer": peer,
        "isac_auditor": await human_headers(isac_auditor, isac_pem),
        "member_auditor": await human_headers(member_auditor, member_pem),
        "member_pem": member_pem,
    }


async def _audit(session, org_id, action, **details: object) -> None:
    await record(
        session,
        action=action,
        actor_type="system",
        org_id=org_id,
        resource_type="test",
        resource_id="r",
        details=details,
    )
    await session.commit()


async def _all(client, url, headers) -> list[dict]:
    """Every event the caller may read, following the cursor to the end.

    Bounded, because "to the end" is the property under test: a stream that
    feeds a reader its own reads has no end, and this loop once spun for an
    hour on exactly that instead of failing.
    """
    events, cursor = [], None
    for _ in range(500):
        params = {"limit": 2, **({"cursor": cursor} if cursor else {})}
        page = await client.get(url, params=params, headers=headers)
        assert page.status_code == 200, page.text
        body = page.json()
        if not body["events"]:
            return events
        events += body["events"]
        cursor = body["cursor"]
    pytest.fail(f"the stream never ran out after 500 pages; last page: {body['events']}")


async def _settled(client, url, headers, *, wanted: int) -> list[dict]:
    """Every event, once at least ``wanted`` of this test's own are served.

    The horizon is the cluster's oldest running transaction, so on a test
    cluster shared with other suites another database's open transaction holds
    it back for a while. The stream stalls rather than skips, so waiting is
    correct; a row that was skipped would never arrive, and the wait fails.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 60
    while True:
        events = await _all(client, url, headers)
        if sum(e.get("resource_type", "test") == "test" for e in events) >= wanted:
            return events
        assert loop.time() < deadline, events
        await asyncio.sleep(0.5)


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-78")
async def test_the_isacs_auditor_reads_the_whole_instance(client, session, world):
    await _audit(session, world["member"].id, AuditAction.ACK_RECORDED, ack_type="actioned")
    await _audit(session, world["peer"].id, AuditAction.ACK_RECORDED, ack_type="retrieved")
    events = await _settled(client, EVENTS, world["isac_auditor"], wanted=2)
    orgs = {e["org_id"] for e in events if e["resource_type"] == "test"}
    assert orgs == {str(world["member"].id), str(world["peer"].id)}


@pytest.mark.requirement("SF-78")
async def test_a_members_auditor_reads_only_its_own_organisations_rows(client, session, world):
    await _audit(session, world["member"].id, AuditAction.ACK_RECORDED, ack_type="actioned")
    await _audit(session, world["peer"].id, AuditAction.ACK_RECORDED, ack_type="retrieved")
    await _settled(client, EVENTS, world["isac_auditor"], wanted=2)
    events = await _all(client, EVENTS, world["member_auditor"])
    assert {e["org_id"] for e in events} == {str(world["member"].id)}


@pytest.mark.requirement("SF-78")
async def test_a_members_auditor_is_not_shown_details_that_name_what_it_cannot_see(
    client, session, world
):
    """A distribution row names circles; the member is shown its verb, not them."""
    circle = str(uuid.uuid4())
    await _audit(
        session, world["member"].id, AuditAction.SUBMISSION_DISTRIBUTED, circles=[circle], verb="x"
    )
    settled = await _settled(client, EVENTS, world["isac_auditor"], wanted=1)
    isac_view = [e for e in settled if e["resource_type"] == "test"]
    member_view = [
        e
        for e in await _all(client, EVENTS, world["member_auditor"])
        if e["resource_type"] == "test"
    ]
    assert member_view[0]["details"] == {"verb": "x"}
    assert isac_view[0]["details"] == {"circles": [circle], "verb": "x"}


async def test_receipts_are_scoped_like_the_trail(client, session, world):
    submission = await _own_submission(session, world["member"])
    for org in (world["member"], world["peer"]):
        session.add(
            Acknowledgment(
                org_id=org.id,
                submission_id=submission.id,
                ack_type=AckType.RETRIEVED,
                via=AckVia.TAXII,
                dedupe_day=dt.datetime.now(dt.UTC).date(),
            )
        )
    await session.commit()
    isac_view = await _settled(client, RECEIPTS, world["isac_auditor"], wanted=2)
    member_view = await _all(client, RECEIPTS, world["member_auditor"])
    assert {e["org_id"] for e in member_view} == {str(world["member"].id)}
    assert {e["org_id"] for e in isac_view} == {str(world["member"].id), str(world["peer"].id)}


async def _own_submission(session, org) -> Submission:
    submission = Submission(
        state=SubmissionState.SUBMITTED,
        tlp=TLP.AMBER,
        discovery_scope=DiscoveryScope.AI_SYSTEM,
        title="The firm's own filing",
    )
    await seed_filing(session, submission, org)
    await session.commit()
    return submission


# ---------------------------------------------------------------------------
# Who may read, and when
# ---------------------------------------------------------------------------
def _auditor_ctx(expires: dt.datetime | None) -> AuthContext:
    return AuthContext(
        org_id=uuid.uuid4(),
        org_slug="isac",
        org_type=OrgType.ADMIN,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.PORTAL_SESSION,
        operator_id=uuid.uuid4(),
        operator_roles=frozenset({OperatorRole.AUDITOR}),
        role_expires_at=expires,
    )


def test_an_auditor_reads_until_its_access_ends_and_not_at_or_after():
    end = dt.datetime(2026, 11, 1, tzinfo=dt.UTC)
    ctx = _auditor_ctx(end)
    assert can_read_audit(ctx, end - dt.timedelta(seconds=1))
    assert not can_read_audit(ctx, end)


@pytest.mark.parametrize(
    "roles", [(OperatorRole.ISAC_EDITOR,), (OperatorRole.SYSTEM_ADMIN,), (OperatorRole.ANALYST,)]
)
async def test_nobody_but_an_auditor_reads_the_trail(
    client, world, isac_org, make_cert, make_operator, human_headers, roles
):
    org = isac_org if roles[0] is not OperatorRole.ANALYST else world["member"]
    pem, _ = await make_cert(org)
    operator, _ = await make_operator(org, roles=roles)
    refused = await client.get(EVENTS, headers=await human_headers(operator, pem))
    assert refused.status_code == 403


@pytest.mark.requirement("SF-78")
async def test_a_session_outliving_the_auditors_access_is_refused(
    client, session, world, make_cert, make_operator, human_headers, isac_org
):
    """The session is established while access holds; the end passes; the next
    request is refused by name, at session resolution."""
    pem, _ = await make_cert(isac_org)
    operator, _ = await make_operator(
        isac_org, roles=(OperatorRole.AUDITOR,), role_expires_at=_later()
    )
    headers = await human_headers(operator, pem)
    operator.role_expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
    await session.commit()
    refused = await client.get(EVENTS, headers=headers)
    assert refused.status_code == 401
    reasons = (
        await session.scalars(
            select(AuditLog.details["reason"].astext).where(
                AuditLog.action == AuditAction.AUTH_FAILURE
            )
        )
    ).all()
    assert "bearer_operator_access_ended" in reasons


async def test_a_refused_caller_is_refused_before_its_cursor_is_read(
    client, world, make_operator, make_cert, human_headers
):
    """Authorization before format: a malformed cursor from a non-auditor is a
    403, from an auditor a 400."""
    pem, _ = await make_cert(world["member"])
    analyst, _ = await make_operator(world["member"])
    not_auditor = await client.get(
        EVENTS, params={"cursor": "!!"}, headers=await human_headers(analyst, pem)
    )
    auditor = await client.get(EVENTS, params={"cursor": "!!"}, headers=world["isac_auditor"])
    assert not_auditor.status_code == 403
    assert auditor.status_code == 400


@pytest.mark.requirement("SF-78")
async def test_an_auditor_reads_no_content(client, session, world):
    """Its own firm's submission is refused at the door, by name, before any
    route runs -- not by the route, which for a member reads by organisation."""
    submission = await _own_submission(session, world["member"])
    refused = await client.get(
        f"/api/v1/submissions/{submission.id}", headers=world["member_auditor"]
    )
    assert refused.status_code == 403
    reasons = (
        await session.scalars(
            select(AuditLog.details["reason"].astext).where(
                AuditLog.action == AuditAction.ACCESS_DENIED
            )
        )
    ).all()
    assert "auditor_outside_audit" in reasons


@pytest.mark.requirement("SF-78")
async def test_an_auditor_cannot_read_its_firms_own_postures(client, world):
    """The pair to the stream: a route that reads the firm's records by
    organisation, and asks no policy, is closed to the auditor all the same."""
    refused = await client.get("/api/v1/postures/openvex", headers=world["member_auditor"])
    assert refused.status_code == 403


# ---------------------------------------------------------------------------
# Commit order, the chain, and the trace a read leaves
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-78")
async def test_a_row_committing_late_with_a_lower_id_is_served_not_skipped(
    client, session, world, open_session
):
    """Transaction A draws the lower id and stays open; B draws a higher one and
    commits. The SIEM polls, then A commits, then the SIEM polls again. Paged on
    id, or on commit without the horizon, A's row falls behind the cursor."""
    early = open_session()
    await _audit_uncommitted(early, world["peer"].id, "early")
    await _audit(session, world["peer"].id, AuditAction.ACK_RECORDED, marker="late")

    first = await client.get(EVENTS, params={"limit": 1000}, headers=world["isac_auditor"])
    seen = [e["details"].get("marker") for e in first.json()["events"]]
    await early.commit()
    cursor = first.json()["cursor"]
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 60
    while len([m for m in seen if m]) < 2 and loop.time() < deadline:
        await asyncio.sleep(0.5)
        page = await client.get(
            EVENTS, params={"limit": 1000, "cursor": cursor}, headers=world["isac_auditor"]
        )
        seen += [e["details"].get("marker") for e in page.json()["events"]]
        cursor = page.json()["cursor"]
    assert [m for m in seen if m] == ["early", "late"]


async def _audit_uncommitted(session, org_id, marker) -> None:
    await record(
        session,
        action=AuditAction.ACK_RECORDED,
        actor_type="system",
        org_id=org_id,
        resource_type="test",
        resource_id="r",
        details={"marker": marker},
    )
    await session.flush()


@pytest.mark.requirement("SF-78")
async def test_the_hash_chain_runs_across_pages_and_breaks_on_an_edit(client, session, world):
    for n in range(5):
        await _audit(session, world["member"].id, AuditAction.ACK_RECORDED, n=n)
    events = await _settled(client, EVENTS, world["isac_auditor"], wanted=5)
    chain = genesis("audit", None).chain
    for event in events:
        body = {k: v for k, v in event.items() if k != "hash"}
        chain = _link(chain, body)
        assert chain == event["hash"]
    edited = {**events[1], "action": "something.else"}
    assert (
        _link(events[0]["hash"], {k: v for k, v in edited.items() if k != "hash"})
        != (events[1]["hash"])
    )


def _link(previous: str, event: dict) -> str:
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(f"{previous}\n{canonical}".encode("ascii")).hexdigest()


@pytest.mark.requirement("SF-78")
async def test_reading_the_trail_leaves_a_trace_in_it(client, session, world):
    await client.get(EVENTS, headers=world["isac_auditor"])
    # A read, or a quiet one when the page held only reads or nothing
    # (services.audit_stream_mode): either way, a trace.
    reads = (
        await session.scalars(
            select(AuditLog).where(
                AuditLog.action.in_((AuditAction.AUDIT_READ, AuditAction.AUDIT_READ_QUIET))
            )
        )
    ).all()
    assert [row.details["stream"] for row in reads] == ["audit"]


@pytest.mark.requirement("SF-78")
async def test_a_reader_is_not_served_the_trace_of_its_own_reading(client, session, world):
    """Polling until a page comes back empty has to end.

    Every page served is recorded, so a stream that served those records would
    hand each reader its previous read on the next poll: a SIEM draining the
    stream never drains it, and the suite hung on exactly this once nothing
    else held the horizon back. The trace stays in the log for the ISAC's own
    review and the ``auditor_bulk_read`` rule; the stream leaves it out.
    """
    # Reading a page that holds a row: recorded as `audit.read`, the kind a
    # stream could serve. (A read of an empty page is quiet, and never served
    # in any mode, so it cannot show the defect; this test once passed under
    # it whenever the horizon lagged and the first page came back empty.)
    await _audit(session, world["member"].id, AuditAction.ACK_RECORDED, ack_type="actioned")
    await _settled(client, EVENTS, world["isac_auditor"], wanted=1)
    # Committed after those reads, so serving it means they are below the horizon.
    await _audit(session, world["member"].id, AuditAction.ACK_RECORDED, ack_type="retrieved")
    events = await _settled(client, EVENTS, world["isac_auditor"], wanted=2)
    assert AuditAction.AUDIT_READ not in {e["action"] for e in events}


# ---------------------------------------------------------------------------
# What an auditor is
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("roles", "expires", "refusal"),
    [
        ((OperatorRole.AUDITOR, OperatorRole.ISAC_EDITOR), _later(), "no other role"),
        ((OperatorRole.AUDITOR,), None, "end date in the future"),
        ((OperatorRole.AUDITOR,), _later(-1), "end date in the future"),
        ((OperatorRole.ISAC_EDITOR,), _later(), "only an auditor"),
    ],
)
async def test_an_auditor_is_created_alone_and_expiring(
    session, secret_box, isac_org, roles, expires, refusal
):
    with pytest.raises(OperatorError, match=refusal):
        await create_operator(
            session,
            None,
            organisation=isac_org,
            email=f"{uuid.uuid4().hex[:8]}@isac.test",
            display_name="Auditor",
            password="a long enough password for the test",
            roles=roles,
            secret_box=secret_box,
            role_expires_at=expires,
            now=dt.datetime.now(dt.UTC),
        )


async def test_an_auditor_with_an_end_date_is_created(session, secret_box, isac_org):
    operator, _ = await create_operator(
        session,
        None,
        organisation=isac_org,
        email="auditor@isac.test",
        display_name="Auditor",
        password="a long enough password for the test",
        roles=(OperatorRole.AUDITOR,),
        secret_box=secret_box,
        role_expires_at=_later(),
        now=dt.datetime.now(dt.UTC),
    )
    await session.commit()
    assert operator.roles == [OperatorRole.AUDITOR]


@pytest.mark.requirement("SF-78")
def test_policy_refuses_an_auditor_what_its_firms_people_may_do():
    """Behind the door, every predicate refuses an auditor at ``is_active``: a
    later route that forgot the door would still be closed. The pair is the
    same firm's analyst, who may."""
    org_id = uuid.uuid4()
    own = Submission(tlp=TLP.AMBER)

    def ctx(role: OperatorRole) -> AuthContext:
        return AuthContext(
            org_id=org_id,
            org_slug="meridian",
            org_type=OrgType.GSIB,
            org_status=OrgStatus.ACTIVE,
            auth_method=AuthMethod.PORTAL_SESSION,
            operator_id=uuid.uuid4(),
            operator_roles=frozenset({role}),
            role_expires_at=_later() if role is OperatorRole.AUDITOR else None,
        )

    assert can_view_submission(ctx(OperatorRole.ANALYST), own, owner_is_caller=True)
    assert not can_view_submission(ctx(OperatorRole.AUDITOR), own, owner_is_caller=True)
    assert not can_hold_evidence_pack(ctx(OperatorRole.AUDITOR))
