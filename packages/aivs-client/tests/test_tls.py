"""The client's TLS posture: our certificate goes out, and only the ISAC's CA comes in.

The assertions are made on the SSL context httpx will actually use, by running a
real TLS handshake against it in memory. Asserting on the arguments passed to
httpx is exactly what failed before: ``httpx.Client(cert=..., verify="<path>")``
looked right and silently dropped the client certificate (CLAUDE.md section 5,
"Third-party convenience arguments can cancel each other out silently").

Certificates are generated here, at test time, so nothing cryptographic is
committed (CLAUDE.md section 6).
"""

from __future__ import annotations

import datetime as dt
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from aivs_client.config import ClientConfig, ConfigError
from aivs_client.transport import build_http_client

HOST = "aivs.test"
MEMBER = "example-member"

#: A TLS 1.3 handshake with client authentication takes three flights; the
#: margin is for TLS 1.2 and for a refusal that surfaces a round late.
_MAX_ROUNDS = 10


@dataclass(frozen=True)
class Issued:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    def write(self, directory: Path, stem: str) -> tuple[Path, Path]:
        cert_path = directory / f"{stem}.pem"
        key_path = directory / f"{stem}.key"
        cert_path.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return cert_path, key_path


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _validity(builder: x509.CertificateBuilder) -> x509.CertificateBuilder:
    now = dt.datetime.now(dt.UTC)
    return builder.not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(
        now + dt.timedelta(days=1)
    )


def make_ca(common_name: str) -> Issued:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    return Issued(_validity(builder).sign(key, hashes.SHA256()), key)


def issue(ca: Issued, common_name: str, *, dns_name: str | None) -> Issued:
    """Issue a leaf: a server certificate when ``dns_name`` is given, else a client one."""
    key = ec.generate_private_key(ec.SECP256R1())
    usage = ExtendedKeyUsageOID.SERVER_AUTH if dns_name else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()),
            critical=False,
        )
    )
    if dns_name:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False
        )
    return Issued(_validity(builder).sign(ca.key, hashes.SHA256()), key)


@dataclass(frozen=True)
class Pki:
    config: ClientConfig
    ca_path: Path
    isac_ca: Issued


@pytest.fixture
def pki(tmp_path) -> Pki:
    isac_ca = make_ca("Example ISAC CA")
    ca_path, _ = isac_ca.write(tmp_path, "isac-ca")
    cert_path, key_path = issue(isac_ca, MEMBER, dns_name=None).write(tmp_path, "member")
    config = ClientConfig(
        base_url=f"https://{HOST}",
        certificate=cert_path,
        private_key=key_path,
        ca_bundle=ca_path,
        state_dir=tmp_path / "state",
    )
    return Pki(config=config, ca_path=ca_path, isac_ca=isac_ca)


def server_context(tmp_path: Path, server: Issued, client_ca_path: Path) -> ssl.SSLContext:
    """A server that requires a client certificate issued by ``client_ca_path``."""
    cert_path, key_path = server.write(tmp_path, "server")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    context.load_verify_locations(cafile=client_ca_path)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _advance(side: ssl.SSLObject) -> bool:
    try:
        side.do_handshake()
    except ssl.SSLWantReadError:
        return False
    return True


def handshake(client_context: ssl.SSLContext, server_ctx: ssl.SSLContext) -> dict[str, Any]:
    """Run a TLS handshake in memory; return the client certificate the server verified.

    Raises whatever :mod:`ssl` raises on the side that refuses.
    """
    to_server, from_client = ssl.MemoryBIO(), ssl.MemoryBIO()
    to_client, from_server = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(to_client, from_client, server_hostname=HOST)
    server = server_ctx.wrap_bio(to_server, from_server, server_side=True)

    client_done = server_done = False
    for _ in range(_MAX_ROUNDS):
        client_done = client_done or _advance(client)
        to_server.write(from_client.read())
        server_done = server_done or _advance(server)
        to_client.write(from_server.read())
        if client_done and server_done:
            return server.getpeercert() or {}
    msg = "handshake did not complete"
    raise AssertionError(msg)


def context_httpx_uses(http: httpx.Client) -> ssl.SSLContext:
    """The SSL context httpx will hand to its connection pool.

    Private attributes, deliberately: httpx exposes no public accessor, and the
    defect this guards against lived precisely in the gap between the arguments
    httpx was given and the context it built from them.
    """
    context = http._transport._pool._ssl_context  # type: ignore[attr-defined]
    assert isinstance(context, ssl.SSLContext)
    return context


def common_name_of(peer: dict[str, Any]) -> str:
    return dict(pair[0] for pair in peer["subject"])["commonName"]


# ---------------------------------------------------------------------------
# Our certificate goes out
# ---------------------------------------------------------------------------
def test_the_http_client_presents_our_certificate(pki, tmp_path):
    server = server_context(tmp_path, issue(pki.isac_ca, HOST, dns_name=HOST), pki.ca_path)

    with build_http_client(pki.config) as http:
        peer = handshake(context_httpx_uses(http), server)

    assert common_name_of(peer) == MEMBER


def test_a_server_requiring_a_certificate_refuses_a_client_without_one(pki, tmp_path):
    """The harness can tell the difference: the absent case fails the handshake.

    Without this, the test above could pass because the server never asked.
    """
    server = server_context(tmp_path, issue(pki.isac_ca, HOST, dns_name=HOST), pki.ca_path)
    anonymous = ssl.create_default_context(cafile=pki.ca_path)

    with pytest.raises(ssl.SSLError):
        handshake(anonymous, server)


# ---------------------------------------------------------------------------
# Only the ISAC's CA comes in
# ---------------------------------------------------------------------------
def test_the_client_refuses_a_server_certificate_from_another_ca(pki, tmp_path):
    other_ca = make_ca("Some Other CA")
    server = server_context(tmp_path, issue(other_ca, HOST, dns_name=HOST), pki.ca_path)

    with build_http_client(pki.config) as http, pytest.raises(ssl.SSLCertVerificationError):
        handshake(context_httpx_uses(http), server)


def test_the_client_refuses_a_server_certificate_for_another_host(pki, tmp_path):
    impostor = issue(pki.isac_ca, "elsewhere.test", dns_name="elsewhere.test")
    server = server_context(tmp_path, impostor, pki.ca_path)

    with build_http_client(pki.config) as http, pytest.raises(ssl.SSLCertVerificationError):
        handshake(context_httpx_uses(http), server)


def test_the_client_trusts_exactly_the_configured_ca(pki):
    """The pin is the ISAC's CA and nothing else that is loaded eagerly.

    Limit: a system trust store loaded through ``capath`` is read lazily and does
    not appear in ``get_ca_certs``, so this cannot prove the system store is
    absent -- only that nothing beyond the ISAC's CA was loaded explicitly.
    """
    with build_http_client(pki.config) as http:
        trusted = context_httpx_uses(http).get_ca_certs()

    assert [dict(pair[0] for pair in ca["subject"]) for ca in trusted] == [
        {"commonName": "Example ISAC CA"}
    ]


# ---------------------------------------------------------------------------
# Missing credentials fail before anything connects
# ---------------------------------------------------------------------------
def test_a_missing_credential_file_is_refused_by_name(pki):
    absent = pki.config.certificate.with_name("absent.pem")
    config = ClientConfig(
        base_url=pki.config.base_url,
        certificate=absent,
        private_key=pki.config.private_key,
        ca_bundle=pki.config.ca_bundle,
    )

    with pytest.raises(ConfigError, match=r"absent\.pem"):
        build_http_client(config)
