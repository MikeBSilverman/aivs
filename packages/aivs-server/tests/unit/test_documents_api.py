"""Text documents over the API (Phase I, slice I2; SF-99).

The doors onto ``services.documents``: a person writes, a certificate alone
reads what is shared with its firm, and every refusal that could say whether a
document or a firm exists is one byte-identical 404.
"""

from __future__ import annotations

import uuid

import pytest

from aivs_schemas.enums import CircleRole, OperatorRole, OrgType
from aivs_server.portal.shared import NOTICE_COOKIE
from tests.conftest import proxy_headers
from tests.unit.test_vulnerability_page import _get, _post, _reader

pytestmark = [pytest.mark.db, pytest.mark.requirement("SF-99")]

API = "/api/v1/documents"
BODY = {"title": "Gateway advisory", "abstract": "Patch it.", "tlp": "amber", "body": "BLUF."}


@pytest.fixture
async def firms(make_org, make_cert, make_operator, make_circle, join_circle, human_headers):
    """An owner and a peer sharing a circle, an outsider sharing none; a person and
    an org admin at each, and the owner's bare certificate."""
    circle = await make_circle("documents-api")
    found = {}
    for name, in_circle in (("owner", True), ("peer", True), ("outsider", False)):
        org = await make_org(f"{name}-firm", org_type=OrgType.GSIB)
        if in_circle:
            await join_circle(org, circle, role=CircleRole.MEMBER)
        pem, _ = await make_cert(org)
        person, _seed = await make_operator(org, roles=(OperatorRole.ANALYST,))
        admin, _seed = await make_operator(org, roles=(OperatorRole.ORG_ADMIN,))
        found[name] = {
            "org": org,
            "machine": proxy_headers(pem),
            "person": await human_headers(person, pem),
            "admin": await human_headers(admin, pem),
        }
    return found


async def created(client, headers) -> str:
    response = await client.post(API, json=BODY, headers=headers)
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def code_of(client, firm) -> str:
    response = await client.post(f"{API}/sharing-code", headers=firm["admin"])
    assert response.status_code == 201, response.text
    return str(response.json()["code"])


async def test_a_person_writes_reads_and_saves_and_a_stale_save_is_a_409(client, firms):
    owner = firms["owner"]["person"]
    document_id = await created(client, owner)

    read = await client.get(f"{API}/{document_id}", headers=owner)
    stale = await client.put(
        f"{API}/{document_id}/body", json={"body": "v2", "expected_version": 9}, headers=owner
    )
    saved = await client.put(
        f"{API}/{document_id}/body", json={"body": "v2", "expected_version": 1}, headers=owner
    )

    assert (read.status_code, read.json()["body"]) == (200, "BLUF.")
    assert stale.status_code == 409
    assert "changed since you read it" in stale.text
    assert (saved.status_code, saved.json()) == (200, {"number": 2})


async def test_a_certificate_alone_writes_nothing(client, firms):
    machine = firms["owner"]["machine"]
    document_id = await created(client, firms["owner"]["person"])

    for method, path, body in (
        ("POST", API, BODY),
        ("PUT", f"{API}/{document_id}/body", {"body": "x", "expected_version": 1}),
        ("POST", f"{API}/{document_id}/comments", {"version_number": 1, "body": "x"}),
        ("POST", f"{API}/sharing-code", None),
    ):
        response = await client.request(method, path, json=body, headers=machine)
        assert response.status_code == 403, (method, path, response.text)


async def test_a_firm_shared_by_its_code_reads_and_its_certificate_reads_too(client, firms):
    document_id = await created(client, firms["owner"]["person"])
    code = await code_of(client, firms["peer"])

    granted = await client.post(
        f"{API}/{document_id}/grants",
        json={"principal_type": "organization", "sharing_code": code, "permission": "view"},
        headers=firms["owner"]["person"],
    )

    assert granted.status_code == 201, granted.text
    for headers in (firms["peer"]["person"], firms["peer"]["machine"]):
        assert (await client.get(f"{API}/{document_id}", headers=headers)).status_code == 200


@pytest.mark.requirement("SF-99")
async def test_a_wrong_an_unknown_and_an_out_of_bound_code_are_one_404_byte_for_byte(client, firms):
    """Main's check: the answer says nothing about whether a code or a firm exists."""
    document_id = await created(client, firms["owner"]["person"])
    peer_code = await code_of(client, firms["peer"])
    outsider_code = await code_of(client, firms["outsider"])
    owner = firms["owner"]["person"]

    async def grant(code: str, target: str = document_id):
        return await client.post(
            f"{API}/{target}/grants",
            json={"principal_type": "organization", "sharing_code": code, "permission": "view"},
            headers=owner,
        )

    answers = [
        await grant(peer_code[:-1] + ("A" if peer_code[-1] != "A" else "B")),
        await grant("AIVS-SHARE-" + "A" * 32),
        await grant(outsider_code),
        await grant(peer_code, target=str(uuid.uuid4())),
    ]

    assert {response.status_code for response in answers} == {404}
    assert len({response.content for response in answers}) == 1
    assert (await grant(peer_code)).status_code == 201, "the right code, in bound, names it"


async def test_another_firm_named_by_its_id_is_the_same_404(client, firms):
    document_id = await created(client, firms["owner"]["person"])

    by_id = await client.post(
        f"{API}/{document_id}/grants",
        json={
            "principal_type": "organization",
            "principal_id": str(firms["peer"]["org"].id),
            "permission": "view",
        },
        headers=firms["owner"]["person"],
    )
    absent = await client.post(
        f"{API}/{uuid.uuid4()}/grants",
        json={
            "principal_type": "organization",
            "principal_id": str(firms["peer"]["org"].id),
            "permission": "view",
        },
        headers=firms["owner"]["person"],
    )

    assert by_id.status_code == absent.status_code == 404
    assert by_id.content == absent.content


async def test_only_an_org_admin_rotates_and_the_status_never_shows_the_code(client, firms):
    refused = await client.post(f"{API}/sharing-code", headers=firms["peer"]["person"])
    code = await code_of(client, firms["peer"])
    status = await client.get(f"{API}/sharing-code", headers=firms["peer"]["admin"])

    assert refused.status_code == 403
    assert status.status_code == 200
    assert status.json()["rotated_at"] is not None
    assert code not in status.text


async def test_unshared_documents_are_404_to_another_firm_and_listed_to_nobody_else(client, firms):
    document_id = await created(client, firms["owner"]["person"])

    unshared = await client.get(f"{API}/{document_id}", headers=firms["peer"]["person"])
    absent = await client.get(f"{API}/{uuid.uuid4()}", headers=firms["peer"]["person"])
    listing = await client.get(API, headers=firms["peer"]["person"])

    assert unshared.status_code == absent.status_code == 404
    assert unshared.content == absent.content
    assert listing.json() == []
    owners = await client.get(API, headers=firms["owner"]["person"])
    assert [item["id"] for item in owners.json()] == [document_id]


# ---------------------------------------------------------------------------
# The portal
# ---------------------------------------------------------------------------
@pytest.fixture
async def portal(session, settings, make_org, make_cert, make_operator):
    org = await make_org("portal-firm", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    other = await make_org("portal-other", org_type=OrgType.GSIB)
    other_pem, _ = await make_cert(other)
    return {
        "author": await _reader(
            session, settings, make_operator, org, pem, roles=(OperatorRole.ANALYST,)
        ),
        "admin": await _reader(
            session, settings, make_operator, org, pem, roles=(OperatorRole.ORG_ADMIN,)
        ),
        "stranger": await _reader(
            session, settings, make_operator, other, other_pem, roles=(OperatorRole.ANALYST,)
        ),
    }


async def test_the_portal_writes_a_draft_and_shows_its_text_escaped(client, portal):
    created_page = await _post(
        client,
        portal["author"],
        "/portal/documents",
        {"title": "Portal note", "tlp": "amber", "body": "<script>alert(1)</script>\nline two"},
    )
    assert created_page.status_code == 303, created_page.text
    page_path = created_page.headers["location"]

    page = await _get(client, portal["author"], page_path)

    assert page.status_code == 200
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    unshared = await _get(client, portal["stranger"], page_path)
    absent = await _get(client, portal["stranger"], f"/portal/documents/{uuid.uuid4()}")
    assert unshared.status_code == absent.status_code == 404
    assert unshared.content == absent.content


async def test_the_portal_shows_a_new_sharing_code_once_and_never_in_a_cookie(client, portal):
    rotated = await _post(client, portal["admin"], "/portal/documents/sharing-code", {})

    assert rotated.status_code == 200, rotated.text
    [code] = [line.strip() for line in rotated.text.splitlines() if "AIVS-SHARE-" in line]
    code = code.split(">")[1].split("<")[0]
    assert code.startswith("AIVS-SHARE-")
    # The notice cookie is signed, not encrypted, and base64: a code in it would
    # not show as itself, so the rotation sets no notice at all.
    cookies = rotated.headers.get_list("set-cookie")
    assert not any(cookie.startswith(f"{NOTICE_COOKIE}=") for cookie in cookies)
    assert not any(code in cookie for cookie in cookies)
    later = await _get(client, portal["admin"], "/portal/documents")
    assert code not in later.text
    assert "Last rotated" in later.text
    refused = await _post(client, portal["author"], "/portal/documents/sharing-code", {})
    assert refused.status_code == 403


async def test_the_share_form_lists_only_the_owners_own_firm(client, session, portal):
    """Another firm is named by code alone: listing firms would show the membership graph."""
    created_page = await _post(
        client,
        portal["author"],
        "/portal/documents",
        {"title": "Form", "tlp": "amber", "body": "Text."},
    )
    page = await _get(client, portal["author"], created_page.headers["location"])

    assert "Portal Firm (everyone)" in page.text
    assert "Portal Other" not in page.text
