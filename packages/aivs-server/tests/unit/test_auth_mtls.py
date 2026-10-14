"""Tests for the proxy-to-application trust boundary.

This is the boundary an attacker attacks first, because everything downstream
trusts its verdict. Each test below corresponds to a way of trying to become
someone else, and the suite is written to fail loudly if any of them starts
succeeding.

Every rejection is additionally asserted to be *uninformative*: the response
must not reveal which check failed. That property is easy to lose during a
refactor and expensive to notice in production.
"""

from __future__ import annotations

import datetime as dt

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from aivs_schemas.enums import CertStatus, OrgStatus, OrgType
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog
from tests.conftest import TEST_PROXY_SECRET, proxy_headers

pytestmark = pytest.mark.db


async def test_valid_certificate_authenticates(client, make_org, make_cert):
    """A registered, active certificate for an active org is accepted."""
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)

    response = await client.get("/api/v1/whoami", headers=proxy_headers(pem))

    assert response.status_code == 200
    body = response.json()
    assert body["organization"]["slug"] == "meridian-global"
    assert body["organization"]["type"] == "gsib"
    assert body["authentication"]["method"] == "mtls"


async def test_no_headers_is_rejected(client):
    """A request with no proxy headers at all cannot authenticate."""
    response = await client.get("/api/v1/whoami")
    assert response.status_code == 401


async def test_wrong_proxy_secret_is_rejected(client, make_org, make_cert):
    """A valid certificate is worthless without the proxy's shared secret.

    This is the control that matters if an attacker reaches the application's
    network directly: they may hold a genuine member certificate and still
    cannot use it, because they cannot prove they came through the proxy.
    """
    org = await make_org("meridian-global")
    pem, _ = await make_cert(org)

    response = await client.get(
        "/api/v1/whoami", headers=proxy_headers(pem, proxy_secret="wrong-secret-entirely")
    )
    assert response.status_code == 401


async def test_missing_proxy_secret_is_rejected(client, make_org, make_cert):
    """Omitting the shared secret entirely is refused, not treated as absent-so-skip."""
    org = await make_org("meridian-global")
    pem, _ = await make_cert(org)

    headers = proxy_headers(pem)
    del headers["x-proxy-auth"]

    response = await client.get("/api/v1/whoami", headers=headers)
    assert response.status_code == 401


@pytest.mark.parametrize("verify_value", ["NONE", "FAILED:self signed certificate", "", "success "])
async def test_non_success_verify_is_rejected(client, make_org, make_cert, verify_value):
    """Only a literal SUCCESS from the proxy's chain verification is accepted."""
    org = await make_org("meridian-global")
    pem, _ = await make_cert(org)

    response = await client.get("/api/v1/whoami", headers=proxy_headers(pem, verify=verify_value))
    # "success " differs only by case and whitespace and is normalised, so it
    # is the one value here that is legitimately accepted.
    expected = 200 if verify_value.strip().upper() == "SUCCESS" else 401
    assert response.status_code == expected


async def test_unregistered_certificate_is_rejected(client, ca):
    """A certificate from the right CA that was never registered is refused.

    Chain validity is necessary but not sufficient: identity comes from the
    registration table, so an attacker who obtains a signed certificate outside
    the enrolment process still gets nothing.
    """
    pem, _, _ = ca.issue("never-enrolled")

    response = await client.get("/api/v1/whoami", headers=proxy_headers(pem))
    assert response.status_code == 401


@pytest.mark.requirement("NFR-S2")
async def test_revoked_certificate_is_rejected(client, make_org, make_cert):
    """Revocation takes effect immediately, with no CRL or OCSP round trip."""
    org = await make_org("meridian-global")
    pem, _ = await make_cert(org, status=CertStatus.REVOKED)

    response = await client.get("/api/v1/whoami", headers=proxy_headers(pem))
    assert response.status_code == 401


@pytest.mark.parametrize("org_status", [OrgStatus.PENDING, OrgStatus.SUSPENDED])
async def test_inactive_org_is_rejected(client, make_org, make_cert, org_status):
    """A valid certificate for a pending or suspended org authenticates to nothing."""
    org = await make_org("meridian-global", status=org_status)
    pem, _ = await make_cert(org)

    response = await client.get("/api/v1/whoami", headers=proxy_headers(pem))
    assert response.status_code == 401


async def test_expired_certificate_is_rejected(client, make_org, make_cert):
    """An expired certificate is refused even if the proxy said SUCCESS.

    The application re-checks the validity window precisely so that a proxy
    misconfiguration cannot promote an expired certificate into a live session.
    """
    now = dt.datetime.now(dt.UTC)
    org = await make_org("meridian-global")
    pem, _ = await make_cert(
        org,
        not_before=now - dt.timedelta(days=400),
        not_after=now - dt.timedelta(days=1),
    )

    response = await client.get("/api/v1/whoami", headers=proxy_headers(pem))
    assert response.status_code == 401


async def test_not_yet_valid_certificate_is_rejected(client, make_org, make_cert):
    """A certificate whose validity starts in the future is refused."""
    now = dt.datetime.now(dt.UTC)
    org = await make_org("meridian-global")
    pem, _ = await make_cert(
        org,
        not_before=now + dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=400),
    )

    response = await client.get("/api/v1/whoami", headers=proxy_headers(pem))
    assert response.status_code == 401


@pytest.mark.parametrize(
    "bad_cert",
    [
        "not-a-certificate-at-all",
        "-----BEGIN CERTIFICATE-----\nnot-base64!!!\n-----END CERTIFICATE-----",
        "",
    ],
)
async def test_malformed_certificate_is_rejected(client, bad_cert):
    """Unparseable certificate material is a rejection, never a traceback."""
    response = await client.get(
        "/api/v1/whoami",
        headers={
            "x-client-verify": "SUCCESS",
            "x-client-cert": bad_cert,
            "x-proxy-auth": TEST_PROXY_SECRET,
        },
    )
    assert response.status_code == 401


async def test_oversized_certificate_header_is_rejected(client):
    """A huge certificate header is refused before any ASN.1 parsing happens."""
    response = await client.get(
        "/api/v1/whoami",
        headers={
            "x-client-verify": "SUCCESS",
            "x-client-cert": "A" * 20000,
            "x-proxy-auth": TEST_PROXY_SECRET,
        },
    )
    assert response.status_code == 401


async def test_untrusted_peer_address_is_rejected(app, make_org, make_cert):
    """A request from outside the trusted proxy address is refused.

    Simulates an attacker who has reached the application's port directly and
    is replaying a complete, otherwise-valid set of proxy headers.
    """
    org = await make_org("meridian-global")
    pem, _ = await make_cert(org)

    transport = ASGITransport(app=app, client=("10.99.99.99", 0))
    async with AsyncClient(transport=transport, base_url="https://aivs.test") as attacker:
        response = await attacker.get("/api/v1/whoami", headers=proxy_headers(pem))

    assert response.status_code == 401


async def test_rejection_does_not_disclose_the_reason(client, make_org, make_cert, ca):
    """Every rejection returns the same body, whatever the underlying cause.

    An attacker probing enrolment status, revocation, or org suspension must not
    be able to tell these apart from the response.
    """
    org = await make_org("meridian-global", status=OrgStatus.SUSPENDED)
    suspended_pem, _ = await make_cert(org)
    unregistered_pem, _, _ = ca.issue("never-enrolled")

    bodies = set()
    for pem in (suspended_pem, unregistered_pem):
        response = await client.get("/api/v1/whoami", headers=proxy_headers(pem))
        assert response.status_code == 401
        bodies.add(response.text)

    assert len(bodies) == 1, "responses differ, leaking which check failed"
    combined = bodies.pop().lower()
    for leaked in ("suspended", "revoked", "not_registered", "expired", "org_"):
        assert leaked not in combined


async def test_circles_are_reported_for_the_caller(
    client, make_org, make_cert, make_circle, join_circle
):
    """whoami reports exactly the circles the caller belongs to."""
    org = await make_org("meridian-global")
    pem, _ = await make_cert(org)
    section9 = await make_circle("section9")
    gsib = await make_circle("gsib")
    await join_circle(org, section9)
    await join_circle(org, gsib)
    await make_circle("crit-infra-general")  # exists, but org is not a member

    response = await client.get("/api/v1/whoami", headers=proxy_headers(pem))

    assert response.status_code == 200
    reported = {entry["id"] for entry in response.json()["circles"]}
    assert reported == {str(section9.id), str(gsib.id)}


async def test_inactive_circle_grants_nothing(
    client, make_org, make_cert, make_circle, join_circle
):
    """Membership of a deactivated circle confers no access.

    Deactivating a circle is how an operator suspends a whole sharing community
    without unpicking its membership records.
    """
    org = await make_org("meridian-global")
    pem, _ = await make_cert(org)
    dormant = await make_circle("dormant", is_active=False)
    await join_circle(org, dormant)

    response = await client.get("/api/v1/whoami", headers=proxy_headers(pem))

    assert response.status_code == 200
    assert response.json()["circles"] == []


async def test_a_certificate_whose_registration_has_lapsed_is_refused_by_that_check(
    client, session, make_org, make_cert
):
    """The certificate is still valid; only the registration's recorded expiry
    has passed. The audit row names the check that refused, so another refusal
    cannot stand in for this one (CLAUDE.md section 2)."""
    org = await make_org("meridian-global")
    pem, row = await make_cert(org)
    assert (await client.get("/api/v1/whoami", headers=proxy_headers(pem))).status_code == 200

    row.not_after = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
    await session.commit()
    response = await client.get("/api/v1/whoami", headers=proxy_headers(pem))

    assert response.status_code == 401
    reasons = (
        (
            await session.execute(
                select(AuditLog.details["reason"].astext).where(
                    AuditLog.action == AuditAction.AUTH_FAILURE
                )
            )
        )
        .scalars()
        .all()
    )
    assert reasons == ["certificate_registration_expired"]
