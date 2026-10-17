"""A finished document becomes a report (Phase I, slice I3; SF-101).

Driven through the API as members and the ISAC use it: the owner finishes, an
editor validates and distributes, and the circle fetches the body from the link
the report carries. Each refusal is shown beside the same caller, or the same
document, succeeding where it should.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import CircleRole, OperatorRole, OrgStatus, OrgType, SubmissionState
from aivs_server.db.models import DocumentGrant, DocumentRead, StixObject, Submission
from aivs_server.services.document_reports import PAUSED
from aivs_server.services.instance import pause_distribution
from aivs_server.services.org_status import change_org_status, load_org_for_update
from tests.conftest import proxy_headers
from tests.unit.contribution_world import distribute, seed, vulnerability_raw

pytestmark = [pytest.mark.db, pytest.mark.requirement("SF-101")]

API = "/api/v1/documents"
SUBMISSIONS = "/api/v1/submissions"
BODY = "BLUF: patch the gateway before Friday."
DOCUMENT = {"title": "Gateway advisory", "abstract": "Patch it.", "tlp": "amber", "body": BODY}


@pytest.fixture
async def firms(
    session, make_org, make_cert, make_operator, make_circle, join_circle, human_headers
):
    """An owner and a peer in one circle, an outsider in none, and one object the
    peer distributed there for the owner to cite; another, the outsider's, it cannot."""
    circle = await make_circle("document-reports")
    elsewhere = await make_circle("document-reports-elsewhere")
    found: dict = {"circle": circle}
    for name, joins in (("owner", circle), ("peer", circle), ("outsider", elsewhere)):
        org = await make_org(f"{name}-reports", org_type=OrgType.GSIB)
        await join_circle(org, joins, role=CircleRole.MEMBER)
        pem, _ = await make_cert(org)
        person, _seed = await make_operator(org, roles=(OperatorRole.ANALYST,))
        colleague, _seed = await make_operator(org, roles=(OperatorRole.ANALYST,))
        admin, _seed = await make_operator(org, roles=(OperatorRole.ORG_ADMIN,))
        found[name] = {
            "org": org,
            "machine": proxy_headers(pem),
            "person": await human_headers(person, pem),
            "colleague_id": colleague.id,
            "colleague": await human_headers(colleague, pem),
            "admin": await human_headers(admin, pem),
        }
    cited = vulnerability_raw(f"vulnerability--{uuid.uuid4()}", cve_status="pre-cve")
    await seed(session, found["peer"]["org"], cited, circle=circle)
    unseen = vulnerability_raw(f"vulnerability--{uuid.uuid4()}", cve_status="pre-cve")
    await seed(session, found["outsider"]["org"], unseen, circle=elsewhere)
    found["cited"], found["unseen"] = cited["id"], unseen["id"]
    return found


async def drafted(client, firms) -> str:
    response = await client.post(API, json=DOCUMENT, headers=firms["owner"]["person"])
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def reviewed(client, firms) -> str:
    """A draft sent to review, the state a document is finished from."""
    document_id = await drafted(client, firms)
    moved = await client.post(
        f"{API}/{document_id}/transition",
        json={"to": "in_review"},
        headers=firms["owner"]["person"],
    )
    assert moved.status_code == 204, moved.text
    return document_id


async def finish(client, headers, document_id, cited, *, credit: bool = False):
    return await client.post(
        f"{API}/{document_id}/finish",
        json={"discovery_scope": "ai_system", "cited": list(cited), "credit": credit},
        headers=headers,
    )


async def finished(client, firms, *, credit: bool = False) -> tuple[str, str]:
    """Finished by its author, citing the peer's object: (document, report submission)."""
    document_id = await reviewed(client, firms)
    response = await finish(
        client, firms["owner"]["person"], document_id, [firms["cited"]], credit=credit
    )
    assert response.status_code == 201, response.text
    return document_id, response.json()["report_submission_id"]


async def stored_report(session, submission_id: str) -> dict:
    raw = await session.scalar(
        select(StixObject.raw).where(
            StixObject.submission_id == uuid.UUID(submission_id), StixObject.type == "report"
        )
    )
    assert raw is not None
    return raw


async def share_with_peer(client, firms, document_id: str) -> None:
    code = await client.post(f"{API}/sharing-code", headers=firms["peer"]["admin"])
    granted = await client.post(
        f"{API}/{document_id}/grants",
        json={
            "principal_type": "organization",
            "sharing_code": code.json()["code"],
            "permission": "edit",
        },
        headers=firms["owner"]["person"],
    )
    assert granted.status_code == 201, granted.text


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------
async def test_finishing_files_an_anonymous_report_that_links_the_finished_body_by_its_hash(
    client, session, settings, firms
):
    document_id, submission_id = await finished(client, firms)

    report = await stored_report(session, submission_id)
    filing = await client.get(f"{SUBMISSIONS}/{submission_id}", headers=firms["owner"]["person"])

    assert (filing.json()["state"], filing.json()["distribute_anonymously"]) == ("submitted", True)
    assert report["name"] == DOCUMENT["title"]
    assert report["object_refs"] == [firms["cited"]]
    assert report["external_references"] == [
        {
            "source_name": "aivs-document",
            "description": "the finished document, version 1",
            "url": f"{settings.public_base_url.rstrip('/')}{API}/artifact?id={document_id}",
            "hashes": {"SHA-256": hashlib.sha256(BODY.encode()).hexdigest()},
        }
    ]


async def test_asking_for_credit_names_the_owner(client, firms):
    _document_id, submission_id = await finished(client, firms, credit=True)

    filing = await client.get(f"{SUBMISSIONS}/{submission_id}", headers=firms["owner"]["person"])

    assert filing.json()["distribute_anonymously"] is False


async def test_finishing_closes_every_grant_outside_the_owner_firm(client, session, firms):
    document_id = await reviewed(client, firms)
    await share_with_peer(client, firms, document_id)
    colleague = await client.post(
        f"{API}/{document_id}/grants",
        json={
            "principal_type": "operator",
            "principal_id": str(firms["owner"]["colleague_id"]),
            "permission": "view",
        },
        headers=firms["owner"]["person"],
    )
    assert colleague.status_code == 201, colleague.text
    assert (
        await client.get(f"{API}/{document_id}", headers=firms["peer"]["person"])
    ).status_code == 200

    finishing = await finish(client, firms["owner"]["person"], document_id, [firms["cited"]])

    assert finishing.status_code == 201, finishing.text
    assert (
        await client.get(f"{API}/{document_id}", headers=firms["peer"]["person"])
    ).status_code == 404
    kept = await client.get(f"{API}/{document_id}", headers=firms["owner"]["colleague"])
    assert (kept.status_code, kept.json()["state"]) == (200, "finished")
    ended = (
        await session.scalars(
            select(DocumentGrant.revoked_by).where(
                DocumentGrant.document_id == uuid.UUID(document_id)
            )
        )
    ).all()
    assert sorted(ended, key=str) == sorted(["finished", None], key=str)


async def test_a_second_finish_is_refused_and_files_nothing_more(client, session, firms):
    document_id, _submission_id = await finished(client, firms)

    again = await finish(client, firms["owner"]["person"], document_id, [firms["cited"]])

    assert again.status_code == 409
    assert "cannot become finished" in again.text
    reports = (
        await session.scalars(select(StixObject.id).where(StixObject.type == "report"))
    ).all()
    assert len(reports) == 1


async def test_a_plain_transition_does_not_finish(client, firms):
    document_id = await reviewed(client, firms)

    moved = await client.post(
        f"{API}/{document_id}/transition", json={"to": "finished"}, headers=firms["owner"]["person"]
    )

    assert moved.status_code == 409
    assert "use finish" in moved.text


# ---------------------------------------------------------------------------
# Who finishes, and what it may cite
# ---------------------------------------------------------------------------
async def test_only_the_owners_people_finish(client, firms):
    """A grantee elsewhere holding edit is refused, its certificate 403, a stranger 404."""
    document_id = await reviewed(client, firms)
    await share_with_peer(client, firms, document_id)
    cited = [firms["cited"]]

    by_peer = await finish(client, firms["peer"]["person"], document_id, cited)
    by_certificate = await finish(client, firms["owner"]["machine"], document_id, cited)
    by_stranger = await finish(client, firms["outsider"]["person"], document_id, cited)
    by_owner = await finish(client, firms["owner"]["person"], document_id, cited)

    assert (by_peer.status_code, by_peer.json()["title"]) == (
        409,
        "only the owner finishes a document",
    )
    assert by_certificate.status_code == 403
    assert by_stranger.status_code == 404
    assert by_owner.status_code == 201, by_owner.text


async def test_a_report_cites_something_and_only_what_its_owner_can_read(client, session, firms):
    """Absent and unreadable are refused alike, each named back as given; nothing is filed."""
    document_id = await reviewed(client, firms)
    owner = firms["owner"]["person"]
    absent = f"vulnerability--{uuid.uuid4()}"

    nothing = await finish(client, owner, document_id, [])
    unknown = await finish(client, owner, document_id, [absent])
    unseen = await finish(client, owner, document_id, [firms["unseen"]])

    assert (nothing.status_code, unknown.status_code, unseen.status_code) == (409, 409, 409)
    assert "cites at least one object" in nothing.text
    assert unknown.text.replace(absent, "<id>") == unseen.text.replace(firms["unseen"], "<id>")
    assert (
        await session.scalars(select(StixObject.id).where(StixObject.type == "report"))
    ).all() == []
    read = await client.get(f"{API}/{document_id}", headers=owner)
    assert read.json()["state"] == "in_review"
    assert (await finish(client, owner, document_id, [firms["cited"]])).status_code == 201


# ---------------------------------------------------------------------------
# The body behind the link
# ---------------------------------------------------------------------------
async def test_the_body_is_read_by_the_reviewers_before_validate_and_the_circle_after(
    client, session, firms, isac
):
    document_id, submission_id = await finished(client, firms)
    _isac_org, editor = isac
    link = f"{API}/artifact?id={document_id}"

    before = {
        name: (await client.get(link, headers=headers)).status_code
        for name, headers in (
            ("editor", editor),
            ("author", firms["owner"]["person"]),
            ("owner's certificate", firms["owner"]["machine"]),
            ("peer", firms["peer"]["machine"]),
            ("outsider", firms["outsider"]["machine"]),
        )
    }
    validated = await client.post(
        f"{SUBMISSIONS}/{submission_id}/validate", json={}, headers=editor
    )
    assert validated.status_code == 200, validated.text
    distributed = await distribute(client, submission_id, editor, firms["circle"])
    assert distributed.status_code == 200, distributed.text
    peer_read = await client.get(link, headers=firms["peer"]["machine"])
    outsider_read = await client.get(link, headers=firms["outsider"]["machine"])

    # The author holds the document; its firm's certificate holds no grant on it (SF-98).
    assert before == {
        "editor": 200,
        "author": 200,
        "owner's certificate": 404,
        "peer": 404,
        "outsider": 404,
    }
    assert (peer_read.status_code, peer_read.text) == (200, BODY)
    assert peer_read.headers["x-content-sha256"] == hashlib.sha256(BODY.encode()).hexdigest()
    assert peer_read.headers["content-type"].startswith("text/plain")
    assert outsider_read.status_code == 404
    receipts = (
        await session.scalars(
            select(DocumentRead.org_id).where(DocumentRead.document_id == uuid.UUID(document_id))
        )
    ).all()
    assert firms["peer"]["org"].id in receipts


async def test_an_absent_an_unfinished_and_an_unreadable_body_are_one_404(client, firms):
    finished_id, _submission_id = await finished(client, firms)
    draft_id = await drafted(client, firms)
    outsider = firms["outsider"]["machine"]

    answers = [
        await client.get(f"{API}/artifact?id={uuid.uuid4()}", headers=outsider),
        await client.get(f"{API}/artifact?id={draft_id}", headers=firms["owner"]["machine"]),
        await client.get(f"{API}/artifact?id={finished_id}", headers=outsider),
    ]

    assert {response.status_code for response in answers} == {404}
    assert len({response.content for response in answers}) == 1


# ---------------------------------------------------------------------------
# Validate checks the citations again, from the owner's view then
# ---------------------------------------------------------------------------
async def test_validate_refuses_a_report_whose_owner_can_no_longer_read_what_it_cites(
    client, session, firms, isac, isac_ctx
):
    """Suspended while its report waited: a suspended firm reads nothing. (Leaving
    the circle would not do: what arrived while it belonged stays readable.)"""
    _document_id, submission_id = await finished(client, firms)
    _isac_org, editor = isac
    owner = await load_org_for_update(session, firms["owner"]["org"].id)
    assert owner is not None
    await change_org_status(
        session, isac_ctx, organisation=owner, target=OrgStatus.SUSPENDED, via="test"
    )
    await session.commit()

    refused = await client.post(f"{SUBMISSIONS}/{submission_id}/validate", json={}, headers=editor)

    assert refused.status_code == 409, refused.text
    assert f"its owner cannot read now: {firms['cited']}" in refused.text
    state = await session.scalar(
        select(Submission.state).where(Submission.id == uuid.UUID(submission_id))
    )
    assert state is SubmissionState.SUBMITTED


async def test_validate_during_a_pause_names_the_pause(client, session, firms, isac, isac_ctx):
    """A pause hides everything from the owner, so the check says so instead of
    calling every citation unreadable."""
    _document_id, submission_id = await finished(client, firms)
    _isac_org, editor = isac
    await pause_distribution(session, isac_ctx, reason="drill", now=dt.datetime.now(dt.UTC))
    await session.commit()

    refused = await client.post(f"{SUBMISSIONS}/{submission_id}/validate", json={}, headers=editor)

    assert refused.status_code == 409, refused.text
    assert PAUSED in refused.json()["title"]


# ---------------------------------------------------------------------------
# Nobody else writes the link
# ---------------------------------------------------------------------------
async def test_a_filer_cannot_write_the_document_link_into_a_bundle(client, firms):
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": f"report--{uuid.uuid4()}",
        "created": "2026-08-01T00:00:00.000Z",
        "modified": "2026-08-01T00:00:00.000Z",
        "published": "2026-08-01T00:00:00.000Z",
        "name": "A report",
        "object_refs": [firms["cited"]],
        "external_references": [
            {"source_name": "aivs-document", "url": "https://elsewhere.example/a.txt"}
        ],
    }

    filed = await client.post(
        SUBMISSIONS,
        json={
            "title": "Forged link",
            "discovery_scope": "ai_system",
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [report]},
        },
        headers=firms["owner"]["machine"],
    )

    assert filed.status_code == 400
    assert "only the server writes" in filed.text
