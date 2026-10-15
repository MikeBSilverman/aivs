"""Triage: CISA's SSVC table as the default priority, an editor's override, an assignee.

The table is CISA's own data, read verbatim, so the tests pin how it is read
(every row reachable, the poc spelling mapped) rather than restating its 36
rows. The routes are pairs: the role that may, beside the one that may not.
"""

from __future__ import annotations

import csv
import uuid
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from aivs_schemas.enums import OperatorRole, SsvcPriority, SubmissionState
from aivs_schemas.extension.builders import AIVS_EXTENSION_ID, AIVS_INTEL_EXTENSION_ID
from aivs_server.audit.log import AuditAction
from aivs_server.auth.sessions import establish_session
from aivs_server.db.models import AuditLog, Organization, Submission
from aivs_server.services.attribution import submitter_of
from aivs_server.services.priority import assess_priority, cisa_table, decision_points
from aivs_server.services.review_queue import queued_for_review
from tests.conftest import proxy_headers, seed_filing

pytestmark = pytest.mark.db

TABLE = (
    Path(__file__).resolve().parents[2]
    / "src/aivs_server/services/ssvc_data/cisa_coordinator_2_0_3.csv"
)


def points(exploitation: str, automatable: str, impact: str) -> dict[str, str]:
    return {
        "ssvc_exploitation": exploitation,
        "ssvc_automatable": automatable,
        "ssvc_technical_impact": impact,
    }


def test_every_row_of_cisas_table_is_read_as_written():
    with TABLE.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))[1:]
    assert len(rows) == 36
    for _row, exploitation, automatable, impact, mission, decision in rows:
        assert cisa_table()[(exploitation, automatable, impact, mission)] == SsvcPriority(decision)


@pytest.mark.parametrize(
    ("given", "mission", "expected"),
    [
        (points("active", "yes", "total"), "high", SsvcPriority.ACT),
        (points("none", "no", "partial"), "high", SsvcPriority.TRACK),
        (points("poc", "no", "total"), "high", SsvcPriority.ATTEND),  # vulnrichment's spelling
        (points("active", "no", "total"), "medium", SsvcPriority.ATTEND),
    ],
)
def test_the_default_is_cisas_decision_for_the_stated_points(given, mission, expected):
    assessed = assess_priority([given], mission_impact=mission)
    assert assessed.decision is expected
    assert assessed.factors["mission_impact"] == mission
    assert assessed.missing == ()


def test_the_most_urgent_vulnerability_sets_the_default():
    assessed = assess_priority(
        [points("none", "no", "partial"), points("active", "yes", "total")], mission_impact="high"
    )
    assert assessed.decision is SsvcPriority.ACT


def test_incomplete_points_give_no_default_and_say_what_is_missing():
    assessed = assess_priority([{"ssvc_exploitation": "active"}], mission_impact="high")
    assert assessed.decision is None
    assert assessed.missing == ("ssvc_automatable", "ssvc_technical_impact")
    assert assess_priority([], mission_impact="high").decision is None


def test_decision_points_come_only_from_a_vulnerabilitys_2_0_body():
    two = {
        "type": "vulnerability",
        "extensions": {AIVS_INTEL_EXTENSION_ID: points("active", "yes", "total")},
    }
    one = {
        "type": "vulnerability",
        "extensions": {AIVS_EXTENSION_ID: points("active", "yes", "total")},
    }
    coa = {
        "type": "course-of-action",
        "extensions": {AIVS_INTEL_EXTENSION_ID: points("active", "yes", "total")},
    }
    assert decision_points([two, one, coa]) == [points("active", "yes", "total")]


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------
@pytest.fixture
async def queued(session, make_org, make_cert):
    org = await make_org("triage-member")
    submission = Submission(
        state=SubmissionState.SUBMITTED,
        tlp="amber",
        discovery_scope="own_product",
        title="Triage me",
    )
    await seed_filing(session, submission, org)
    await session.commit()
    return submission


@pytest.fixture
async def isac_person(isac_org, make_cert, make_operator, human_headers):
    async def _make(*roles: OperatorRole):
        pem, _ = await make_cert(isac_org)
        operator, _seed = await make_operator(isac_org, roles=roles)
        return operator, await human_headers(operator, pem)

    return _make


async def test_an_editor_sets_a_priority_and_an_analyst_may_not(
    client, session, queued, isac_person
):
    _editor, editor = await isac_person(OperatorRole.ISAC_EDITOR)
    _analyst, analyst = await isac_person(OperatorRole.ISAC_ANALYST)
    url = f"/api/v1/submissions/{queued.id}/priority"

    assert (await client.put(url, json={"priority": "act"}, headers=analyst)).status_code == 403
    set_ = await client.put(url, json={"priority": "act"}, headers=editor)
    assert set_.status_code == 200, set_.text
    await session.refresh(queued)
    assert queued.priority is SsvcPriority.ACT

    audited = (
        await session.execute(
            select(AuditLog).where(AuditLog.action == AuditAction.SUBMISSION_PRIORITY_SET)
        )
    ).scalar_one()
    assert audited.details == {"from": None, "to": "act"}


async def test_a_reviewer_assigns_and_the_assignee_must_be_a_reviewer(
    client, session, queued, isac_person
):
    analyst, analyst_headers = await isac_person(OperatorRole.ISAC_ANALYST)
    membership, _ = await isac_person(OperatorRole.ISAC_MEMBERSHIP)
    url = f"/api/v1/submissions/{queued.id}/assignee"

    refused = await client.put(
        url, json={"operator_id": str(membership.id)}, headers=analyst_headers
    )
    assert refused.status_code == 400
    taken = await client.put(url, json={"operator_id": str(analyst.id)}, headers=analyst_headers)
    assert taken.status_code == 200, taken.text
    await session.refresh(queued)
    assert queued.assignee_operator_id == analyst.id


async def test_a_member_cannot_see_whether_a_submission_exists_to_triage(
    client, queued, make_org, make_cert
):
    outsider = await make_org("triage-outsider")
    pem, _ = await make_cert(outsider)
    for path, body in (("priority", {"priority": "act"}), ("assignee", {"operator_id": None})):
        here = await client.put(
            f"/api/v1/submissions/{queued.id}/{path}", json=body, headers=proxy_headers(pem)
        )
        absent = await client.put(
            f"/api/v1/submissions/{uuid.uuid4()}/{path}", json=body, headers=proxy_headers(pem)
        )
        assert here.status_code == absent.status_code == 404


async def test_the_queue_puts_an_editors_priority_before_the_default(session, queued, make_org):
    later = Submission(
        state=SubmissionState.SUBMITTED,
        tlp="amber",
        discovery_scope="own_product",
        title="Raised by an editor",
        priority=SsvcPriority.ACT,
    )
    queued_by = await session.get(Organization, await submitter_of(session, queued))
    await seed_filing(session, later, queued_by)
    await session.commit()

    (group,) = await queued_for_review(session, mission_impact="high")
    assert [item.submission.title for item in group.items] == ["Raised by an editor", "Triage me"]
    assert group.items[0].priority_source == "editor"
    assert group.items[1].priority is None


async def test_the_review_page_shows_priority_assignee_and_what_ssvc_needs(
    app, session, settings, queued, isac_org, make_cert, make_operator
):
    pem, _ = await make_cert(isac_org)
    operator, _seed = await make_operator(isac_org, roles=(OperatorRole.ISAC_ANALYST,))
    fingerprint = x509.load_pem_x509_certificate(pem.encode()).fingerprint(hashes.SHA256()).hex()
    established = await establish_session(
        session, settings, operator=operator, cert_fingerprint=fingerprint
    )
    await session.commit()

    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    async with AsyncClient(
        transport=transport,
        base_url="https://aivs.test",
        cookies={settings.session_cookie_name: established.token},
    ) as browser:
        page = await browser.get("/portal/review", headers=proxy_headers(pem))

    assert page.status_code == 200, page.text
    assert "Triage me" in page.text
    assert "unassigned" in page.text
    assert "SSVC needs: exploitation, automatable, technical impact" in page.text
