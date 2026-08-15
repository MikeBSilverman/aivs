"""The analyst portal, driven the way a browser drives it.

Covers the whole signed-in path: sign in, see the dashboard, file a finding,
move it through review, and read the receipts. The security properties get their
own section — CSRF, the certificate binding, and the review screen being the
hosting ISAC's alone.

These go through HTTP rather than calling the route functions, because the parts
most likely to be wrong are the parts a unit call skips: cookie flags, redirects,
form parsing, and template rendering.
"""

from __future__ import annotations

import json
import re
import uuid

import pyotp
import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import OperatorRole, OrgType
from aivs_server.auth.passwords import encode_secret, generate_totp_secret, hash_password
from aivs_server.db.models import Operator, Submission, SubmissionTransition
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

PASSWORD = "correct-horse-battery-staple"
STAMP = "2026-08-01T00:00:00.000Z"


def bundle(name: str = "Prompt injection in agent runtime") -> str:
    return json.dumps(
        {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [
                {
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": f"vulnerability--{uuid.uuid4()}",
                    "created": STAMP,
                    "modified": STAMP,
                    "name": name,
                }
            ],
        }
    )


async def make_operator(session, org, *, role=OperatorRole.ANALYST, email=None):
    secret = generate_totp_secret()
    operator = Operator(
        org_id=org.id,
        email=email or f"analyst@{org.slug}.test",
        display_name="Test Analyst",
        role=role,
        password_hash=hash_password(PASSWORD),
        totp_secret_encrypted=encode_secret(secret),
        is_active=True,
    )
    session.add(operator)
    await session.commit()
    await session.refresh(operator)
    return operator, secret


@pytest.fixture
async def analyst(session, make_org, make_cert):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _cert = await make_cert(org)
    operator, secret = await make_operator(session, org)
    return org, operator, secret, pem


@pytest.fixture
async def isac_operator(session, make_org, make_cert):
    org = await make_org("hosting-isac", org_type=OrgType.ADMIN)
    pem, _cert = await make_cert(org)
    operator, secret = await make_operator(
        session, org, role=OperatorRole.SYSTEM_ADMIN, email="ops@isac.test"
    )
    return org, operator, secret, pem


async def sign_in(client, operator, secret, pem) -> None:
    """Complete the sign-in flow, leaving the session cookies on the client."""
    form = await client.get("/portal/login", headers=proxy_headers(pem))
    assert form.status_code == 200
    token = re.search(r'name="csrf_token" value="([^"]+)"', form.text).group(1)

    response = await client.post(
        "/portal/login",
        data={
            "email": operator.email,
            "password": PASSWORD,
            "totp_code": pyotp.TOTP(secret).now(),
            "csrf_token": token,
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 303, response.text
    assert response.headers["location"] == "/portal/"


def csrf_of(client) -> str:
    return client.cookies["aivs_csrf"]


# ---------------------------------------------------------------------------
# Sign in
# ---------------------------------------------------------------------------
async def test_an_analyst_can_sign_in_and_see_their_dashboard(client, analyst):
    org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    dashboard = await client.get("/portal/", headers=proxy_headers(pem))
    assert dashboard.status_code == 200
    assert org.name in dashboard.text
    assert operator.display_name in dashboard.text


async def test_the_session_cookie_is_hardened(client, analyst):
    """HttpOnly, Secure, SameSite=Strict, scoped to /portal."""
    _org, operator, secret, pem = analyst
    form = await client.get("/portal/login", headers=proxy_headers(pem))
    token = re.search(r'name="csrf_token" value="([^"]+)"', form.text).group(1)

    response = await client.post(
        "/portal/login",
        data={
            "email": operator.email,
            "password": PASSWORD,
            "totp_code": pyotp.TOTP(secret).now(),
            "csrf_token": token,
        },
        headers=proxy_headers(pem),
    )
    cookie_headers = " ".join(
        value for key, value in response.headers.items() if key.lower() == "set-cookie"
    ).lower()
    assert "httponly" in cookie_headers
    assert "secure" in cookie_headers
    assert "samesite=strict" in cookie_headers


@pytest.mark.parametrize(
    ("password", "code_valid"),
    [("wrong-password-here", True), (PASSWORD, False)],
)
async def test_a_failed_sign_in_says_only_that_it_failed(client, analyst, password, code_valid):
    """One message for every cause: which input was wrong is half the credential."""
    _org, operator, secret, pem = analyst
    form = await client.get("/portal/login", headers=proxy_headers(pem))
    token = re.search(r'name="csrf_token" value="([^"]+)"', form.text).group(1)

    response = await client.post(
        "/portal/login",
        data={
            "email": operator.email,
            "password": password,
            "totp_code": pyotp.TOTP(secret).now() if code_valid else "000000",
            "csrf_token": token,
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 401
    body = response.text.lower()
    assert "not accepted" in body
    for leaked in ("password", "code", "locked", "unknown"):
        assert f"{leaked} was" not in body


async def test_sign_in_requires_the_form_token(client, analyst):
    _org, operator, secret, pem = analyst
    await client.get("/portal/login", headers=proxy_headers(pem))

    response = await client.post(
        "/portal/login",
        data={
            "email": operator.email,
            "password": PASSWORD,
            "totp_code": pyotp.TOTP(secret).now(),
            "csrf_token": "forged",
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 403


async def test_signing_out_ends_the_session(client, analyst):
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    out = await client.post(
        "/portal/logout",
        data={"csrf_token": client.cookies.get("aivs_csrf", "")},
        headers=proxy_headers(pem),
    )
    assert out.status_code == 303, out.text

    after = await client.get("/portal/", headers=proxy_headers(pem))
    assert after.status_code == 303
    assert after.headers["location"] == "/portal/login"


async def test_signing_out_is_not_reachable_by_a_get(client, analyst):
    """Revoking a session is a write, so it takes a POST with a token.

    Previously a GET, which meant the only thing standing between a cross-site
    request and an analyst's session was the SameSite attribute on the cookie --
    a protection that happened to hold rather than one this route performed.
    """
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    assert (await client.get("/portal/logout", headers=proxy_headers(pem))).status_code == 405
    still_in = await client.get("/portal/", headers=proxy_headers(pem))
    assert still_in.status_code == 200, "the session must survive a refused logout"


async def test_signing_out_requires_a_valid_csrf_token(client, analyst):
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    refused = await client.post(
        "/portal/logout", data={"csrf_token": "forged"}, headers=proxy_headers(pem)
    )
    assert refused.status_code == 403
    assert (await client.get("/portal/", headers=proxy_headers(pem))).status_code == 200


# ---------------------------------------------------------------------------
# Filing and workflow
# ---------------------------------------------------------------------------
async def test_an_analyst_can_file_a_finding(client, analyst, session):
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    form = await client.get("/portal/submit", headers=proxy_headers(pem))
    assert form.status_code == 200

    response = await client.post(
        "/portal/submit",
        data={
            "title": "AI-discovered chain in agent runtime",
            "summary": "Three chained weaknesses.",
            "discovery_scope": "ai_system",
            "tlp": "amber",
            "bundle": bundle(),
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/portal/submissions/")

    count = await session.scalar(select(func.count()).select_from(Submission))
    assert count == 1


async def test_a_malformed_bundle_is_reported_on_the_form(client, analyst):
    """The submitter sees what to fix, on the page they were already on."""
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    response = await client.post(
        "/portal/submit",
        data={
            "title": "Not valid JSON",
            "discovery_scope": "ai_system",
            "tlp": "amber",
            "bundle": "{not json",
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400
    assert "not valid JSON" in response.text


async def test_filing_requires_the_form_token(client, analyst, session):
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    response = await client.post(
        "/portal/submit",
        data={
            "title": "Cross-site attempt",
            "discovery_scope": "ai_system",
            "tlp": "amber",
            "bundle": bundle(),
            "csrf_token": "forged",
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 403
    assert (await session.scalar(select(func.count()).select_from(Submission))) == 0


async def test_the_submission_list_shows_the_firms_own_findings(client, analyst):
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)
    await client.post(
        "/portal/submit",
        data={
            "title": "A distinctive finding title",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": bundle(),
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )

    listing = await client.get("/portal/submissions", headers=proxy_headers(pem))
    assert listing.status_code == 200
    assert "A distinctive finding title" in listing.text


async def test_an_analyst_can_send_a_draft_for_review(client, analyst, session):
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)
    created = await client.post(
        "/portal/submit",
        data={
            "title": "Ready for review",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": bundle(),
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )
    submission_id = created.headers["location"].rsplit("/", 1)[-1]

    response = await client.post(
        f"/portal/submissions/{submission_id}/submit",
        data={"csrf_token": csrf_of(client)},
        headers=proxy_headers(pem),
    )
    assert response.status_code == 303

    submission = await session.get(Submission, uuid.UUID(submission_id))
    await session.refresh(submission)
    assert str(submission.state) == "submitted"


async def test_a_workflow_action_requires_the_form_token(client, analyst, session):
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)
    created = await client.post(
        "/portal/submit",
        data={
            "title": "Protected by a token",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": bundle(),
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )
    submission_id = created.headers["location"].rsplit("/", 1)[-1]
    before = await session.scalar(select(func.count()).select_from(SubmissionTransition))

    response = await client.post(
        f"/portal/submissions/{submission_id}/submit",
        data={"csrf_token": "forged"},
        headers=proxy_headers(pem),
    )
    assert response.status_code == 403
    after = await session.scalar(select(func.count()).select_from(SubmissionTransition))
    assert after == before, "a rejected action must not write history"


async def test_the_detail_screen_shows_history_and_receipts(client, analyst):
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)
    created = await client.post(
        "/portal/submit",
        data={
            "title": "Has a history",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": bundle(),
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )

    detail = await client.get(created.headers["location"], headers=proxy_headers(pem))
    assert detail.status_code == 200
    assert "History" in detail.text
    assert "Receipts" in detail.text, "the submitter may see who collected their finding"


async def test_another_firms_submission_is_not_found(client, analyst, make_org, make_cert, session):
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)
    created = await client.post(
        "/portal/submit",
        data={
            "title": "Private to Meridian",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": bundle(),
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )
    path = created.headers["location"]

    other_org = await make_org("atlantic-clearing")
    other_pem, _cert = await make_cert(other_org)
    other_operator, other_secret = await make_operator(session, other_org)

    await client.get("/portal/logout", headers=proxy_headers(pem))
    await sign_in(client, other_operator, other_secret, other_pem)

    response = await client.get(path, headers=proxy_headers(other_pem))
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# The review queue
# ---------------------------------------------------------------------------
async def test_the_review_queue_is_the_isacs_alone(client, analyst):
    """Reported as absent rather than forbidden, like every other gated screen."""
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    response = await client.get("/portal/review", headers=proxy_headers(pem))
    assert response.status_code == 404


async def test_the_isac_sees_the_review_queue(client, isac_operator, analyst):
    org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)
    await client.post(
        "/portal/submit",
        data={
            "title": "Waiting for the ISAC",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": bundle(),
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )
    listing = await client.get("/portal/submissions", headers=proxy_headers(pem))
    submission_id = re.search(r"/portal/submissions/([0-9a-f-]{36})", listing.text).group(1)
    await client.post(
        f"/portal/submissions/{submission_id}/submit",
        data={"csrf_token": csrf_of(client)},
        headers=proxy_headers(pem),
    )
    await client.get("/portal/logout", headers=proxy_headers(pem))

    _isac_org, isac_op, isac_secret, isac_pem = isac_operator
    await sign_in(client, isac_op, isac_secret, isac_pem)

    queue = await client.get("/portal/review", headers=proxy_headers(isac_pem))
    assert queue.status_code == 200
    assert "Waiting for the ISAC" in queue.text
    del org


async def test_a_member_cannot_validate_from_the_portal(client, analyst, session):
    """The portal must not become a second, weaker door to the same operation."""
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)
    created = await client.post(
        "/portal/submit",
        data={
            "title": "Self-validation attempt",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": bundle(),
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )
    submission_id = created.headers["location"].rsplit("/", 1)[-1]
    await client.post(
        f"/portal/submissions/{submission_id}/submit",
        data={"csrf_token": csrf_of(client)},
        headers=proxy_headers(pem),
    )

    await client.post(
        f"/portal/submissions/{submission_id}/validate",
        data={"csrf_token": csrf_of(client)},
        headers=proxy_headers(pem),
    )

    submission = await session.get(Submission, uuid.UUID(submission_id))
    await session.refresh(submission)
    assert str(submission.state) == "submitted", "a member cannot validate their own submission"


# ---------------------------------------------------------------------------
# The certificate binding, through HTTP
# ---------------------------------------------------------------------------
async def test_a_session_cookie_does_not_work_from_another_certificate(client, analyst, ca):
    """The property that makes the portal's two factors independent.

    The cookies are on the client; only the certificate changes.
    """
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)
    assert (await client.get("/portal/", headers=proxy_headers(pem))).status_code == 200

    other_pem, _fingerprint, _cert = ca.issue("somewhere-else")
    response = await client.get("/portal/", headers=proxy_headers(other_pem))
    assert response.status_code == 303
    assert response.headers["location"] == "/portal/login"


async def test_signing_in_needs_a_certificate_at_all(client, analyst):
    """Without one there is no organisation to attribute the credential to."""
    _org, operator, secret, _pem = analyst
    response = await client.post(
        "/portal/login",
        data={
            "email": operator.email,
            "password": PASSWORD,
            "totp_code": pyotp.TOTP(secret).now(),
            "csrf_token": "irrelevant",
        },
    )
    assert response.status_code in (401, 403)
