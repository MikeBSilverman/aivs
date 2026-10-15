"""The first pass on every submit: route, annotate, return; never decide (plan, Phase O).

A return costs a member time and the ISAC a contribution, so each condition
on it has a test of its own, beside the case that is returned. The rule
itself is a table; the job is driven through the real submit, since a reader
tested on hand-built rows proves the fixture (CLAUDE.md section 2).
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy import func, select, update

from aivs_schemas.enums import (
    OperatorRole,
    OrgType,
    SubmissionSource,
    SubmissionState,
    TriageDisposition,
)
from aivs_server.db.models import (
    AuditLog,
    InstanceControl,
    Submission,
    SubmissionTransition,
    SubmissionTriage,
)
from aivs_server.services.first_pass import Finding, FindingCode
from aivs_server.services.submissions import SubmissionError, record_transition
from aivs_server.services.triage import (
    MEMBER_FACING,
    content_digest,
    decide,
    triage_pending,
)
from tests.conftest import proxy_headers
from tests.unit.sharing import intel as sharing_intel
from tests.unit.test_vulnerability_page import _get, _reader

API = "/api/v1/submissions"
NOW = dt.datetime(2026, 10, 15, 12, 0, tzinfo=dt.UTC)
STAMP = "2026-08-01T00:00:00.000Z"


# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------
BLOCKING = Finding(FindingCode.PRODUCT_NOT_MACHINE_READABLE, "vulnerability--1.p", "d")
NOTE_ONLY = Finding(FindingCode.NO_SEVERITY, "vulnerability--1.cvss", "d")


@pytest.mark.requirement("SF-87")
@pytest.mark.parametrize(
    ("findings", "returnable", "urgent", "returned_before", "expected"),
    [
        ([BLOCKING], True, False, False, TriageDisposition.NEEDS_CHANGES),
        ([NOTE_ONLY], True, False, False, TriageDisposition.READY_FOR_REVIEW),
        ([], True, False, False, TriageDisposition.READY_FOR_REVIEW),
        ([BLOCKING], False, False, False, TriageDisposition.READY_FOR_REVIEW),
        ([BLOCKING], True, True, False, TriageDisposition.READY_FOR_REVIEW),
        ([BLOCKING], True, False, True, TriageDisposition.READY_FOR_REVIEW),
    ],
    ids=["returned", "notes-only", "clean", "not-a-members-own", "urgent", "returned-before"],
)
def test_a_submission_is_returned_only_when_every_condition_holds(
    findings, returnable, urgent, returned_before, expected
):
    assert (
        decide(findings, returnable=returnable, urgent=urgent, returned_before=returned_before)
        is expected
    )


def test_the_same_objects_in_any_order_have_one_digest():
    a, b = {"id": "x", "n": 1}, {"id": "y", "n": 2}

    assert content_digest([a, b]) == content_digest([b, a])
    assert content_digest([a]) != content_digest([a, b])


@pytest.mark.requirement("SF-87")
def test_every_finding_code_is_classed_for_who_may_read_it():
    """The oracle rule's list. A new code is added here deliberately: one that
    reads the ISAC's view is analyst-only, or its presence tells a member
    what exists that it cannot see."""
    analyst_only: set[FindingCode] = set()

    assert set(FindingCode) == set(MEMBER_FACING) | analyst_only
    assert not set(MEMBER_FACING) & analyst_only


# ---------------------------------------------------------------------------
# The job, through the real submit
# ---------------------------------------------------------------------------
def _bundle(**intel: Any) -> dict[str, Any]:
    vulnerability = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "name": "Gateway auth bypass",
        "extensions": sharing_intel(
            discovery_scope="own_product", cve_status="pre-cve", **{**UNMATCHABLE, **intel}
        ),
    }
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [vulnerability]}


#: An affected product no tool can match: the finding that returns.
UNMATCHABLE: dict[str, Any] = {"affected_products": [{"vendor": "Acme", "product": "Gateway"}]}
MATCHABLE = {
    "affected_products": [
        {"vendor": "Acme", "product": "Gateway", "purl": "pkg:generic/acme/gateway"}
    ]
}


@pytest.fixture
async def member(make_org, make_cert):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    return org, pem


async def _submitted(client, pem: str, bundle: dict[str, Any]) -> str:
    created = await client.post(
        API,
        json={
            "title": "Gateway",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": bundle,
        },
        headers=proxy_headers(pem),
    )
    assert created.status_code == 201, created.text
    submission_id = created.json()["id"]
    await _submit(client, pem, submission_id)
    return submission_id


async def _filed_for_the_member(client, isac, org) -> str:
    """An ISAC editor files for the member on its consent (SF-68): submitted as it is filed."""
    _isac_org, editor = isac
    filed = await client.post(
        f"{API}/on-behalf",
        json={
            "title": "Forwarded by the member",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": _bundle(**UNMATCHABLE),
            "on_behalf_of": str(org.id),
            "consent_sha256": "c0" * 32,
        },
        headers=editor,
    )
    assert filed.status_code == 201, filed.text
    assert filed.json()["state"] == "submitted"
    return str(filed.json()["id"])


async def _submit(client, pem: str, submission_id: str) -> None:
    submitted = await client.post(
        f"{API}/{submission_id}/submit", json={}, headers=proxy_headers(pem)
    )
    assert submitted.status_code == 200, submitted.text


async def _detail(client, pem: str, submission_id: str) -> dict[str, Any]:
    response = await client.get(f"{API}/{submission_id}", headers=proxy_headers(pem))
    assert response.status_code == 200, response.text
    return response.json()


pytestdb = pytest.mark.db


@pytestdb
@pytest.mark.requirement("SF-87")
async def test_a_member_is_told_what_to_change_and_nothing_else_happens(client, session, member):
    _org, pem = member
    submission_id = await _submitted(client, pem, _bundle(**UNMATCHABLE))

    assert await triage_pending(session, now=NOW) == 1

    detail = await _detail(client, pem, submission_id)
    assert detail["state"] == "returned"
    assert detail["first_pass"]["disposition"] == "needs_changes"
    codes = {finding["code"] for finding in detail["first_pass"]["findings"]}
    assert "product_not_machine_readable" in codes
    (returned,) = [t for t in detail["transitions"] if t["to_state"] == "returned"]
    assert returned["from_state"] == "submitted"
    assert "product_not_machine_readable" in returned["reason"]
    actor = await session.scalar(
        select(SubmissionTransition.actor_org_id).where(
            SubmissionTransition.submission_id == uuid.UUID(submission_id),
            SubmissionTransition.to_state == "returned",
        )
    )
    assert actor is None, "a return is the rules', never a person's"


@pytestdb
@pytest.mark.requirement("SF-87")
async def test_the_audit_row_names_the_rules_and_codes_and_quotes_no_content(
    client, session, member
):
    _org, pem = member
    submission_id = await _submitted(client, pem, _bundle(**UNMATCHABLE))

    await triage_pending(session, now=NOW)

    row = await session.scalar(
        select(AuditLog).where(
            AuditLog.action == "submission.triaged", AuditLog.resource_id == submission_id
        )
    )
    assert row is not None
    assert row.details["disposition"] == "needs_changes"
    assert row.details["rules_version"] == "first-pass/1"
    assert "product_not_machine_readable" in row.details["codes"]
    assert "Gateway" not in str(row.details)


@pytestdb
@pytest.mark.requirement("SF-87")
async def test_resubmitted_unchanged_it_goes_to_review_and_is_not_returned_again(
    client, session, member
):
    _org, pem = member
    submission_id = await _submitted(client, pem, _bundle(**UNMATCHABLE))
    await triage_pending(session, now=NOW)

    await _submit(client, pem, submission_id)
    await triage_pending(session, now=NOW)

    detail = await _detail(client, pem, submission_id)
    assert detail["state"] == "submitted"
    assert detail["first_pass"]["disposition"] == "ready_for_review"
    assert detail["first_pass"]["findings"], "the notes go to review with it"


@pytestdb
@pytest.mark.requirement("SF-87")
async def test_a_returned_submission_can_be_fixed_and_resubmitted(client, session, member):
    _org, pem = member
    submission_id = await _submitted(client, pem, _bundle(**UNMATCHABLE))
    await triage_pending(session, now=NOW)

    amended = await client.patch(
        f"{API}/{submission_id}", json={"bundle": _bundle(**MATCHABLE)}, headers=proxy_headers(pem)
    )
    assert amended.status_code == 200, amended.text
    await _submit(client, pem, submission_id)
    await triage_pending(session, now=NOW)

    detail = await _detail(client, pem, submission_id)
    assert (detail["state"], detail["first_pass"]["disposition"]) == (
        "submitted",
        "ready_for_review",
    )


@pytestdb
@pytest.mark.requirement("SF-87")
async def test_urgent_content_goes_to_review_with_its_notes(client, session, member):
    _org, pem = member
    submission_id = await _submitted(
        client, pem, _bundle(kev_listed=True, kev_date_added="2026-10-01")
    )

    await triage_pending(session, now=NOW)

    detail = await _detail(client, pem, submission_id)
    assert detail["state"] == "submitted"
    assert detail["first_pass"]["disposition"] == "ready_for_review"


@pytestdb
@pytest.mark.requirement("SF-87")
@pytest.mark.parametrize("filed_as", ["system", "proxy"])
async def test_only_a_members_own_filing_is_sent_back_to_its_writer(
    client, session, member, isac, filed_as
):
    """A proxy filing is filed through the editor's own route, so the row is the
    one the writer produces: the triage reads whatever marks it as filed for the
    member, not a pair of columns a test set by hand."""
    org, pem = member
    if filed_as == "system":
        submission_id = await _submitted(client, pem, _bundle(**UNMATCHABLE))
        await session.execute(
            update(Submission)
            .where(Submission.id == uuid.UUID(submission_id))
            .values(source=SubmissionSource.SYSTEM)
        )
        await session.commit()
    else:
        submission_id = await _filed_for_the_member(client, isac, org)

    await triage_pending(session, now=NOW)

    state = await session.scalar(
        select(Submission.state).where(Submission.id == uuid.UUID(submission_id))
    )
    assert state == "submitted"


@pytestdb
@pytest.mark.requirement("SF-87")
async def test_each_submit_is_read_once(client, session, member):
    _org, pem = member
    submission_id = await _submitted(client, pem, _bundle(**MATCHABLE))

    await triage_pending(session, now=NOW)
    await triage_pending(session, now=NOW)

    reads = await session.scalar(
        select(func.count()).where(SubmissionTriage.submission_id == uuid.UUID(submission_id))
    )
    assert reads == 1


@pytestdb
@pytest.mark.requirement("SF-87")
async def test_nothing_is_read_or_returned_while_the_instance_is_paused(client, session, member):
    """A return tells a member something: a stop button stops that too."""
    _org, pem = member
    submission_id = await _submitted(client, pem, _bundle(**UNMATCHABLE))
    await session.merge(InstanceControl(id=1, distribution_paused=True))
    await session.commit()

    assert await triage_pending(session, now=NOW) == 0

    assert (await _detail(client, pem, submission_id))["state"] == "submitted"


@pytestdb
@pytest.mark.requirement("SF-87")
async def test_a_move_with_no_caller_is_a_return_and_nothing_else(client, session, member):
    _org, pem = member
    submission_id = await _submitted(client, pem, _bundle(**MATCHABLE))
    submission = await session.get(Submission, uuid.UUID(submission_id))
    assert submission is not None

    with pytest.raises(SubmissionError, match="needs a caller"):
        await record_transition(session, None, submission, SubmissionState.WITHDRAWN, reason=None)


@pytestdb
@pytest.mark.requirement("SF-87")
async def test_the_member_reads_needs_changes_on_its_page(
    client, session, settings, member, make_operator
):
    org, pem = member
    submission_id = await _submitted(client, pem, _bundle(**UNMATCHABLE))
    await triage_pending(session, now=NOW)
    reader = await _reader(
        session, settings, make_operator, org, pem, roles=(OperatorRole.ANALYST,)
    )

    page = await _get(client, reader, f"/portal/submissions/{submission_id}")

    assert page.status_code == 200, page.text
    assert 'data-first-pass="returned"' in page.text
    assert "neither a purl nor a CPE" in page.text
