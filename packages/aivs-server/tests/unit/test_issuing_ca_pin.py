"""The issuing-CA pin verifies a signature, not a name (finding #2).

The old check compared the certificate's issuer DN with a configured string.
An issuer DN is chosen by whoever writes the certificate, so a self-signed
certificate carrying the right DN passed exactly as a genuine one did -- at
registration and, with nothing at all checked, at authentication. Each test
here is a pair: the forgery is refused and the genuine certificate, presented
the same way, is accepted, so a pass cannot come from the route simply being
broken.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from aivs_schemas.enums import CertStatus, OrgType
from aivs_server.auth.mtls import CertificateRejectedError, verify_issued_by
from aivs_server.config import Settings
from aivs_server.db.models import ClientCertificate
from tests.conftest import (
    TEST_CA_CERT_FILE,
    TEST_DATABASE_URL,
    TEST_PROXY_SECRET,
    TEST_SECRET_KEY,
    TEST_SESSION_SECRET,
    proxy_headers,
)
from tests.conftest import (
    TestCertificateAuthority as CertificateAuthority,
)

API = "/api/v1"


def _leaf(
    *,
    issuer: x509.Name,
    signing_key: ec.EllipticCurvePrivateKey,
    common_name: str,
    is_ca: bool = False,
    usages: list[x509.ObjectIdentifier] | None = None,
) -> x509.Certificate:
    """Build a certificate with full control over who signs it and what it claims."""
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer)
        .public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if usages is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=False)
    return builder.sign(signing_key, hashes.SHA256())


def _forged(ca: CertificateAuthority, common_name: str) -> x509.Certificate:
    """A certificate naming the real CA as issuer, signed by a key the CA never saw."""
    return _leaf(
        issuer=ca.certificate.subject,
        signing_key=ec.generate_private_key(ec.SECP256R1()),
        common_name=common_name,
        usages=[ExtendedKeyUsageOID.CLIENT_AUTH],
    )


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _fingerprint(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


# ---------------------------------------------------------------------------
# The check itself
# ---------------------------------------------------------------------------
def test_a_genuine_client_certificate_passes(ca):
    _pem_text, _fp, certificate = ca.issue("genuine-member")
    verify_issued_by(certificate, ca.certificate)


def test_a_forgery_carrying_the_ca_name_is_refused(ca):
    with pytest.raises(CertificateRejectedError, match="issuer_signature_invalid"):
        verify_issued_by(_forged(ca, "forged-member"), ca.certificate)


def test_a_certificate_from_another_ca_is_refused_by_name(ca):
    other = CertificateAuthority()
    _pem_text, _fp, certificate = other.issue("someone-elses-member")
    # Same subject DN as ours (the test CA always uses one), so this exercises
    # the signature rather than the pre-filter, which is the case that matters.
    with pytest.raises(CertificateRejectedError, match="issuer_signature_invalid"):
        verify_issued_by(certificate, ca.certificate)


def test_a_ca_signed_certificate_that_is_itself_a_ca_is_refused(ca):
    certificate = _leaf(
        issuer=ca.certificate.subject,
        signing_key=ca.key,
        common_name="sub-ca",
        is_ca=True,
        usages=[ExtendedKeyUsageOID.CLIENT_AUTH],
    )
    with pytest.raises(CertificateRejectedError, match="certificate_is_a_ca"):
        verify_issued_by(certificate, ca.certificate)


@pytest.mark.parametrize(
    "usages", [None, [ExtendedKeyUsageOID.SERVER_AUTH]], ids=["no-eku", "server-only"]
)
def test_a_ca_signed_certificate_without_client_auth_is_refused(ca, usages):
    certificate = _leaf(
        issuer=ca.certificate.subject, signing_key=ca.key, common_name="server", usages=usages
    )
    with pytest.raises(CertificateRejectedError, match="not_a_client_certificate"):
        verify_issued_by(certificate, ca.certificate)


# ---------------------------------------------------------------------------
# Authentication and registration
# ---------------------------------------------------------------------------
@pytest.mark.db
async def test_a_registered_forgery_cannot_authenticate(client, make_org, make_cert, ca, session):
    """Authentication checks issuance itself, not only what registration let in.

    The forgery's fingerprint is inserted directly, as a database writer or an
    older build without the check could have done. The genuine certificate for
    the same organisation is the control.
    """
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    genuine_pem, _row = await make_cert(org)
    forgery = _forged(ca, "meridian-global")
    session.add(
        ClientCertificate(
            org_id=org.id,
            fingerprint_sha256=_fingerprint(forgery),
            subject_dn=forgery.subject.rfc4514_string(),
            issuer_dn=forgery.issuer.rfc4514_string(),
            serial_hex=format(forgery.serial_number, "x"),
            not_before=forgery.not_valid_before_utc,
            not_after=forgery.not_valid_after_utc,
            status=CertStatus.ACTIVE,
        )
    )
    await session.commit()

    refused = await client.get(f"{API}/whoami", headers=proxy_headers(_pem(forgery)))
    accepted = await client.get(f"{API}/whoami", headers=proxy_headers(genuine_pem))

    assert refused.status_code == 401
    assert accepted.status_code == 200


@pytest.mark.db
async def test_registration_refuses_a_forgery_and_accepts_the_genuine(
    client, make_org, make_cert, ca
):
    isac = await make_org("hosting-isac", org_type=OrgType.ADMIN)
    isac_pem, _ = await make_cert(isac)
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    genuine_pem, _fp, _cert = ca.issue("meridian-global-second-key")

    refused = await client.post(
        f"{API}/orgs/{member.id}/certificates",
        json={"certificate_pem": _pem(_forged(ca, "meridian-global-forged"))},
        headers=proxy_headers(isac_pem),
    )
    accepted = await client.post(
        f"{API}/orgs/{member.id}/certificates",
        json={"certificate_pem": genuine_pem},
        headers=proxy_headers(isac_pem),
    )

    assert refused.status_code == 400
    assert accepted.status_code == 201


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": "staging",
        "public_base_url": "https://aivs.test",
        "database_url": TEST_DATABASE_URL,
        "proxy_shared_secret": TEST_PROXY_SECRET,
        "session_secret": TEST_SESSION_SECRET,
        "secret_encryption_key": TEST_SECRET_KEY,
        "issuing_ca_certificate_file": TEST_CA_CERT_FILE,
    }
    return Settings(**(base | overrides))  # type: ignore[arg-type]


def test_outside_dev_the_issuing_ca_is_required():
    assert _settings().issuing_ca_certificate is not None
    with pytest.raises(ValueError, match="issuing_ca_certificate_file"):
        _settings(issuing_ca_certificate_file=None)


def test_a_leaf_configured_as_the_issuing_ca_is_refused_at_startup(ca, tmp_path: Path):
    _pem_text, _fp, leaf = ca.issue("not-a-ca")
    leaf_file = tmp_path / "leaf.pem"
    leaf_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))

    with pytest.raises(ValueError, match="is not a CA"):
        _settings(issuing_ca_certificate_file=leaf_file)
