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
from sqlalchemy.exc import DataError

from aivs_schemas.enums import OperatorRole, OrgType
from aivs_server.audit.log import AuditAction
from aivs_server.auth.passwords import generate_totp_secret, hash_password
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db.models import (
    AuditLog,
    Operator,
    Submission,
    SubmissionTransition,
    Webhook,
    WebhookDelivery,
)
from aivs_server.portal import routes as portal_routes
from tests.conftest import ISAC_STAFF_ROLES, proxy_headers

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


async def make_operator(session, secret_box, org, *, roles=(OperatorRole.ANALYST,), email=None):
    secret = generate_totp_secret()
    # Explicit id: the seal is bound to it, and the column default is not
    # applied until flush.
    operator_id = uuid.uuid4()
    operator = Operator(
        id=operator_id,
        org_id=org.id,
        email=email or f"analyst@{org.slug}.test",
        display_name="Test Analyst",
        roles=list(roles),
        password_hash=hash_password(PASSWORD),
        totp_secret_encrypted=secret_box.seal(
            secret, purpose=SecretPurpose.TOTP, subject=operator_id
        ),
        is_active=True,
    )
    session.add(operator)
    await session.commit()
    await session.refresh(operator)
    return operator, secret


@pytest.fixture
async def analyst(session, secret_box, make_org, make_cert):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _cert = await make_cert(org)
    operator, secret = await make_operator(session, secret_box, org)
    return org, operator, secret, pem


@pytest.fixture
async def isac_operator(session, secret_box, make_org, make_cert):
    org = await make_org("hosting-isac", org_type=OrgType.ADMIN)
    pem, _cert = await make_cert(org)
    operator, secret = await make_operator(
        session, secret_box, org, roles=ISAC_STAFF_ROLES, email="ops@isac.test"
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


async def make_org_with_webhook(session, secret_box, make_org, join_circle, circle):
    """A member of `circle` with a registered webhook, sealed the way the app does."""
    org = await make_org("subscriber-firm", org_type=OrgType.GSIB)
    await join_circle(org, circle)
    webhook_id = uuid.uuid4()
    webhook = Webhook(
        id=webhook_id,
        org_id=org.id,
        url="https://subscriber.example/hook",
        hmac_secret_encrypted=secret_box.seal(
            "webhook-signing-secret", purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook_id
        ),
        events=[],
    )
    session.add(webhook)
    await session.commit()
    return webhook


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


async def test_signing_out_names_who_signed_out(client, session, analyst):
    """The audit row was anonymous: a sign-out could not be tied to anyone."""
    org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    await client.post(
        "/portal/logout",
        data={"csrf_token": client.cookies.get("aivs_csrf", "")},
        headers=proxy_headers(pem),
    )

    row = await session.scalar(select(AuditLog).where(AuditLog.action == AuditAction.LOGOUT))
    assert row is not None
    assert row.org_id == org.id
    assert row.actor_id == str(operator.id)


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


@pytest.mark.requirement("NFR-O2")
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


@pytest.mark.requirement("SF-15")
async def test_the_detail_screen_shows_history_but_not_receipts_to_the_submitter(client, analyst):
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
    assert "Receipts" not in detail.text, "firm-by-firm receipts are the ISAC's alone"


@pytest.mark.requirement("SF-15")
async def test_the_isac_reads_receipts_on_the_detail_screen(
    client, analyst, isac_operator, make_org, make_circle, join_circle, publish
):
    """The pair to the submitter's refusal: the same screen, an ISAC reviewer.

    Another firm is in the circle, so the submission has reach and the
    submitter would see telemetry: the reviewer must not.
    """
    org, _operator, _secret, _pem = analyst
    _isac_org, isac, isac_secret, isac_pem = isac_operator
    circle = await make_circle("section9")
    await join_circle(org, circle)
    await join_circle(await make_org("atlantic-clearing"), circle)
    submission, _obj, _dist = await publish(org, circle)
    await sign_in(client, isac, isac_secret, isac_pem)

    detail = await client.get(
        f"/portal/submissions/{submission.id}", headers=proxy_headers(isac_pem)
    )
    assert detail.status_code == 200
    assert "Receipts" in detail.text
    assert "What happened to it" not in detail.text, "telemetry is the submitter's"


@pytest.mark.requirement("SF-15")
async def test_the_submitter_sees_counts_withheld_below_k(
    client, analyst, make_org, make_circle, join_circle, publish
):
    org, operator, secret, pem = analyst
    circle = await make_circle("section9")
    await join_circle(org, circle)
    for slug in ("atlantic-clearing", "harbour-mutual"):
        await join_circle(await make_org(slug), circle)
    submission, _obj, _dist = await publish(org, circle)
    await sign_in(client, operator, secret, pem)

    detail = await client.get(f"/portal/submissions/{submission.id}", headers=proxy_headers(pem))
    assert "What happened to it" in detail.text
    assert "shown once at least 5 organisations could see it" in detail.text
    assert "atlantic-clearing" not in detail.text
    assert "harbour-mutual" not in detail.text


async def test_a_draft_points_at_text_that_may_identify_the_submitter(client, analyst):
    """The lint, on the draft page, while the submitter can still change it."""
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)
    created = await client.post(
        "/portal/submit",
        data={
            "title": "Seen on our gateway",
            "summary": "First seen on 10.20.0.7 at Meridian-Global",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": bundle(),
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )

    detail = await client.get(created.headers["location"], headers=proxy_headers(pem))
    assert "Before you submit" in detail.text
    assert "an internal address" in detail.text
    assert "your organisation&#39;s name" in detail.text


async def test_another_firms_submission_is_not_found(
    client, analyst, make_org, make_cert, session, secret_box
):
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
    other_operator, other_secret = await make_operator(session, secret_box, other_org)

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


# ---------------------------------------------------------------------------
# The portal and the API must distribute identically
# ---------------------------------------------------------------------------
async def test_distributing_from_the_portal_queues_the_same_notifications(
    client,
    session,
    analyst,
    isac_operator,
    make_org,
    make_circle,
    make_collection,
    join_circle,
    secret_box,
):
    """The screen the ISAC actually works in must notify, exactly as the API does.

    `queue_visibility_notifications` was called from the two API routes and the
    embargo sweeper, and from nowhere in the portal -- so a distribution made
    here wrote the visibility rows, moved the state, and told nobody. Members
    with registered webhooks learned of the finding on their next poll instead,
    which is most of what the notification exists to avoid.

    The asymmetry was worst in the urgent case: an *embargoed* portal
    distribution was still announced, because the sweeper queues at release, so
    only the immediate ones went unannounced.
    """
    org, operator, secret, pem = analyst
    circle = await make_circle("section9")
    await make_collection(circle)
    await join_circle(org, circle)

    subscriber = await make_org_with_webhook(session, secret_box, make_org, join_circle, circle)

    await sign_in(client, operator, secret, pem)
    created = await client.post(
        "/portal/submit",
        data={
            "title": "Portal-distributed finding",
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
        "/portal/logout", data={"csrf_token": csrf_of(client)}, headers=proxy_headers(pem)
    )

    _isac_org, isac_op, isac_secret, isac_pem = isac_operator
    await sign_in(client, isac_op, isac_secret, isac_pem)
    await client.post(
        f"/portal/submissions/{submission_id}/validate",
        data={"csrf_token": csrf_of(client)},
        headers=proxy_headers(isac_pem),
    )
    distributed = await client.post(
        f"/portal/submissions/{submission_id}/distribute",
        data={"circle_ids": str(circle.id), "csrf_token": csrf_of(client)},
        headers=proxy_headers(isac_pem),
    )
    assert distributed.status_code == 303, distributed.text

    queued = (
        (
            await session.execute(
                select(WebhookDelivery).where(WebhookDelivery.webhook_id == subscriber.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(queued) == 1, "the portal distribution notified nobody"
    assert queued[0].payload["submission_id"] == submission_id
    assert "title" not in queued[0].payload, "notifications stay contentless"


@pytest.mark.parametrize(
    ("field", "value"),
    [("title", "T" * 400), ("summary", "S" * 20_000)],
    ids=["title", "summary"],
)
async def test_an_over_long_field_returns_the_form_not_a_500(
    client, analyst, session, field, value
):
    """Finding #7: the portal had no length bounds, so the database refused it.

    The flush raised a DataError -- not a ValueError -- which escaped the
    handler, and the member got an opaque 500 instead of their form back. The
    portal now validates through the API's own request model. The control is
    ``test_an_analyst_can_file_a_finding`` above, the same form with a normal
    value.
    """
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)
    data = {
        "title": "A normal title",
        "summary": "",
        "discovery_scope": "ai_system",
        "tlp": "amber",
        "bundle": bundle(),
        "csrf_token": csrf_of(client),
    }
    data[field] = value

    response = await client.post("/portal/submit", data=data, headers=proxy_headers(pem))

    assert response.status_code == 400
    assert field in response.text
    assert (await session.scalar(select(func.count()).select_from(Submission))) == 0


@pytest.mark.requirement("NFR-O2")
async def test_content_the_database_refuses_returns_the_form_not_a_500(
    client, analyst, monkeypatch
):
    """A storage-level refusal is the member's malformed input, not our fault.

    The API mapped these to 400; the portal did not catch them at all. Ingest
    now bounds or truncates every column it writes, so no valid form reaches
    one -- this is defence in depth, exercised by making the service raise
    exactly what the database raises when a value does not fit.
    """
    _org, operator, secret, pem = analyst
    await sign_in(client, operator, secret, pem)

    async def refused_by_storage(*_args: object, **_kwargs: object) -> None:
        statement = "INSERT INTO stix_objects ..."
        raise DataError(statement, {}, Exception("value too long for type"))

    monkeypatch.setattr(portal_routes, "create_submission", refused_by_storage)

    response = await client.post(
        "/portal/submit",
        data={
            "title": "Refused by storage",
            "discovery_scope": "ai_system",
            "tlp": "amber",
            "bundle": bundle(),
            "csrf_token": csrf_of(client),
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 400
    assert "value too long" not in response.text, "storage detail is not echoed"


async def _fail_sign_in(client, pem, email: str) -> None:
    form = await client.get("/portal/login", headers=proxy_headers(pem))
    token = re.search(r'name="csrf_token" value="([^"]+)"', form.text).group(1)
    response = await client.post(
        "/portal/login",
        data={"email": email, "password": "wrong", "totp_code": "000000", "csrf_token": token},
        headers=proxy_headers(pem),
    )
    assert response.status_code == 401


async def test_a_failed_sign_in_audits_a_reference_to_the_account_not_the_address(
    client, analyst, session
):
    """The audit log is immutable; an address written into it could never be
    removed, so a departed operator could not be pseudonymised. A keyed
    reference still shows that repeated failures hit the *same* account, which
    is what credential-stuffing detection needs -- the pair below.
    """
    _org, operator, _secret, pem = analyst
    await _fail_sign_in(client, pem, operator.email)
    await _fail_sign_in(client, pem, operator.email.upper())
    await _fail_sign_in(client, pem, "someone-else@example.test")

    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "portal.login.failure")))
        .scalars()
        .all()
    )
    assert len(rows) == 3
    assert all(operator.email not in str(row.details) for row in rows)
    assert all("someone-else" not in str(row.details) for row in rows)
    references = [row.details["account"] for row in rows]
    assert references[0] == references[1], "the same account correlates"
    assert references[2] != references[0], "a different account does not"
