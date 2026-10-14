"""Mutual TLS: who gets past nginx, and who gets past the application.

Two independent checks. nginx verifies the chain against the ISAC's trust
store (root and issuing CA). The application then requires the *issuing* CA's
signature on the certificate nginx forwards, so a certificate signed directly
by the root -- which nginx accepts, the chain being within its depth of 2 --
is refused one layer later. Each refusal is told apart by who answered: nginx's
JSON says a certificate is required; the application's is a TAXII error.
"""

from __future__ import annotations

import datetime as dt
import ssl
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests.e2e.stack import Stack, requires_stack

pytestmark = [pytest.mark.e2e, requires_stack]

NGINX_REFUSAL = "a valid AIVS member client certificate is required"


def _self_signed_client(directory: Path) -> tuple[Path, Path]:
    """A client certificate from a CA the ISAC never heard of, naming the member."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "e2e-member")])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "foreign.crt", directory / "foreign.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def whoami(stack: Stack, identity) -> httpx.Response:
    with stack.client(identity) as client:
        return client.get("/api/v1/whoami")


def test_the_member_certificate_is_accepted(stack):
    response = whoami(stack, stack.member)

    assert response.status_code == 200
    assert response.json()["organization"]["slug"] == stack.member_slug


def test_no_client_certificate_is_refused_by_nginx(stack):
    response = whoami(stack, None)

    assert response.status_code == 403
    assert NGINX_REFUSAL in response.text


def test_a_certificate_from_another_ca_is_refused_by_nginx(stack, tmp_path):
    cert_path, key_path = _self_signed_client(tmp_path)
    context = ssl.create_default_context(cafile=str(stack.ca_chain))
    context.load_cert_chain(str(cert_path), str(key_path))

    with httpx.Client(base_url=stack.base_url, verify=context, timeout=30.0) as client:
        response = client.get("/api/v1/whoami")

    assert response.status_code == 403
    assert NGINX_REFUSAL in response.text


def test_a_certificate_signed_by_the_root_passes_nginx_and_is_refused_by_the_app(stack):
    """Refused for the right reason. The certificate was never registered, so a
    401 alone would also follow from "unknown fingerprint" -- which is what an
    app pinning the root instead of the issuing CA answers. The audit row names
    the check that refused it."""
    response = whoami(stack, stack.root_signed)

    assert response.status_code == 401
    assert NGINX_REFUSAL not in response.text, "nginx refused it; the app's pin was never tested"
    reason = stack.sql(
        "SELECT details->>'reason' FROM audit_log WHERE request_id = :'request_id'",
        request_id=response.headers["x-request-id"],
    )
    assert reason == "issuer_mismatch"
