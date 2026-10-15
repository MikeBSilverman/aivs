"""An editor validates a review group in one audited action, all or nothing.

Driven through the API with filings made the way members and automations make
them, because the rule that matters -- a consequential machine change never
rides along in a group -- lives in ``apply_transition`` and is only as good as
the submissions the writers produce.
"""

from __future__ import annotations

import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select

from aivs_schemas.enums import OperatorRole, OrgType, SubmissionState
from aivs_server.audit.log import AuditAction
from aivs_server.auth.sessions import establish_session
from aivs_server.db.models import AuditLog, Submission
from tests.conftest import ISAC_STAFF_ROLES, proxy_headers
from tests.unit.contribution_world import file
from tests.unit.test_provenance_gate import workaround

pytestmark = pytest.mark.db

GROUP = "/api/v1/review/validate"


@pytest.fixture
async def filers(make_org, make_cert, isac):
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    other = await make_org("harbour-trust", org_type=OrgType.GSIB)
    robot = await make_org("kev-enrichment", org_type=OrgType.AUTOMATION)
    pems = {
        name: (await make_cert(org))[0]
        for name, org in [("member", member), ("other", other), ("robot", robot)]
    }
    _isac_org, editor = isac
    return {"pems": pems, "editor": editor}


async def _submitted(client, pem, objects, *, sender=None) -> str:
    """Filed, then sent for review: by the filer, or by the editor for the
    automation's filing, whose verbs are an editor's (Q35)."""
    filed = await file(client, pem, objects)
    assert filed.status_code == 201, filed.text
    submission_id = filed.json()["id"]
    sent = await client.post(
        f"/api/v1/submissions/{submission_id}/submit",
        json={},
        headers=sender or proxy_headers(pem),
    )
    assert sent.status_code == 200, sent.text
    return submission_id


async def _states(session, ids) -> set[SubmissionState]:
    session.expire_all()
    rows = await session.scalars(
        select(Submission.state).where(Submission.id.in_([uuid.UUID(i) for i in ids]))
    )
    return set(rows)


async def test_an_editor_validates_a_group_in_one_audited_action(client, session, filers):
    pem = filers["pems"]["robot"]
    ids = [await _submitted(client, pem, [workaround()], sender=filers["editor"]) for _ in range(3)]

    validated = await client.post(GROUP, json={"submission_ids": ids}, headers=filers["editor"])

    assert validated.status_code == 200, validated.text
    assert sorted(validated.json()["validated"]) == sorted(ids)
    assert await _states(session, ids) == {SubmissionState.VALIDATED}
    audit = (
        await session.scalars(
            select(AuditLog).where(AuditLog.action == AuditAction.SUBMISSION_BULK_VALIDATED)
        )
    ).one()
    assert sorted(audit.details["submission_ids"]) == sorted(ids)


@pytest.mark.requirement("SF-6")
async def test_a_consequential_machine_change_stops_the_whole_group(client, session, filers):
    """The pair: the same group with one disruptive restart in it validates nothing."""
    pem = filers["pems"]["robot"]
    routine = await _submitted(client, pem, [workaround()], sender=filers["editor"])
    disruptive_coa = workaround(restart_required="system")
    disruptive = await _submitted(client, pem, [disruptive_coa], sender=filers["editor"])

    refused = await client.post(
        GROUP, json={"submission_ids": [routine, disruptive]}, headers=filers["editor"]
    )

    assert refused.status_code == 409
    assert f"{disruptive_coa['id']}:restart_required" in refused.json()["title"]
    assert await _states(session, [routine, disruptive]) == {SubmissionState.SUBMITTED}


async def test_two_organisations_filings_are_not_one_group(client, session, filers):
    first = await _submitted(client, filers["pems"]["member"], [workaround()])
    second = await _submitted(client, filers["pems"]["other"], [workaround()])

    refused = await client.post(
        GROUP, json={"submission_ids": [first, second]}, headers=filers["editor"]
    )

    assert refused.status_code == 409
    assert await _states(session, [first, second]) == {SubmissionState.SUBMITTED}


async def test_an_unknown_submission_validates_nothing(client, session, filers):
    real = await _submitted(client, filers["pems"]["member"], [workaround()])

    refused = await client.post(
        GROUP, json={"submission_ids": [real, str(uuid.uuid4())]}, headers=filers["editor"]
    )

    assert refused.status_code == 404
    assert await _states(session, [real]) == {SubmissionState.SUBMITTED}


async def test_the_portal_says_when_a_group_was_not_validated(
    client, session, settings, filers, isac_org, make_cert, make_operator
):
    """A refused group redirects to the queue like a validated one; the notice is
    the only difference the editor sees, so it has to say nothing happened."""
    pem = filers["pems"]["robot"]
    routine = await _submitted(client, pem, [workaround()], sender=filers["editor"])
    disruptive = await _submitted(
        client, pem, [workaround(restart_required="system")], sender=filers["editor"]
    )
    editor_pem, _ = await make_cert(isac_org)
    editor, _seed = await make_operator(isac_org, roles=ISAC_STAFF_ROLES)
    certificate = x509.load_pem_x509_certificate(editor_pem.encode("ascii"))
    established = await establish_session(
        session,
        settings,
        operator=editor,
        cert_fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
    )
    await session.commit()
    client.cookies.set(settings.session_cookie_name, established.token)

    posted = await client.post(
        "/portal/review/validate",
        data={"submission_ids": [routine, disruptive], "csrf_token": established.csrf_token},
        headers=proxy_headers(editor_pem),
    )
    assert posted.status_code == 303
    queue = await client.get("/portal/review", headers=proxy_headers(editor_pem))
    assert "Nothing was validated" in queue.text
    assert await _states(session, [routine, disruptive]) == {SubmissionState.SUBMITTED}


async def test_an_analyst_is_refused_before_the_group_is_examined(
    client, session, filers, isac_org, make_cert, make_operator, human_headers
):
    """Authorization before format: a mixed group from an analyst is a 403, not
    the 409 that would tell it what was wrong with the request it may not make."""
    first = await _submitted(client, filers["pems"]["member"], [workaround()])
    second = await _submitted(client, filers["pems"]["other"], [workaround()])
    pem, _ = await make_cert(isac_org)
    analyst, _seed = await make_operator(isac_org, roles=(OperatorRole.ISAC_ANALYST,))

    refused = await client.post(
        GROUP,
        json={"submission_ids": [first, second, str(uuid.uuid4())]},
        headers=await human_headers(analyst, pem),
    )

    assert refused.status_code == 403
    assert await _states(session, [first, second]) == {SubmissionState.SUBMITTED}
