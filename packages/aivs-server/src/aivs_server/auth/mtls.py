"""Client-certificate identity extracted from the reverse proxy's headers.

This module implements the most security-sensitive boundary in AIVS: turning
HTTP headers -- which any client can *attempt* to set -- into an authenticated
organisation identity. Three stacked controls make that safe, and all three are
enforced here or in the deployment topology:

1. **The application publishes no port outside the internal network.** Only the
   reverse proxy can reach it (``docker-compose.yml`` deliberately declares no
   host port mapping for the app service).
2. **The proxy unconditionally overwrites the identity headers** on every
   request, so a client-supplied ``X-Client-Cert`` never survives to the app
   (``deploy/nginx/nginx.conf``).
3. **The proxy proves it is the proxy** with a shared secret in ``X-Proxy-Auth``,
   compared here in constant time, and its peer address is checked against an
   allowlist. Even an attacker who lands inside the container network cannot
   forge an identity without also stealing that secret.

The certificate itself is re-parsed here rather than trusting the proxy's
summary of it. nginx's ``$ssl_client_fingerprint`` is **SHA-1**, which we will
not key identity on; instead the proxy forwards the full escaped PEM and the
application computes the SHA-256 itself and independently re-checks the validity
window. That costs a few hundred microseconds per request and removes the proxy
from the set of components that must be correct for identity to be sound.
"""

from __future__ import annotations

import datetime as dt
import hmac
import logging
from dataclasses import dataclass
from typing import Final
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from aivs_server.config import Settings

__all__ = [
    "CertificateRejectedError",
    "ClientCertificateIdentity",
    "MtlsError",
    "extract_client_certificate",
]

logger = logging.getLogger(__name__)

#: nginx's ``$ssl_client_verify`` value meaning the chain validated.
_VERIFY_SUCCESS: Final[str] = "SUCCESS"

#: Upper bound on the forwarded certificate header before we attempt to parse
#: it. A real client certificate chain is a few kilobytes; anything larger is
#: either misconfiguration or an attempt to make us burn CPU on ASN.1 parsing.
MAX_CERT_HEADER_BYTES: Final[int] = 16 * 1024

#: Tolerance for clock skew between the certificate authority and this host when
#: re-checking the validity window. Small enough to be meaningless to an
#: attacker, large enough to absorb ordinary NTP drift.
CLOCK_SKEW_TOLERANCE: Final[dt.timedelta] = dt.timedelta(minutes=5)


class MtlsError(Exception):
    """Base class for client-certificate authentication failures."""


@dataclass(frozen=True, slots=True)
class CertificateRejectedError(MtlsError):
    """A request did not present a usable client certificate.

    ``reason`` is a short stable token for audit logs and metrics. It is
    deliberately never returned to the caller: telling an unauthenticated client
    precisely which of several checks it failed helps only the attacker.
    """

    reason: str

    def __str__(self) -> str:
        return f"client certificate rejected: {self.reason}"


@dataclass(frozen=True, slots=True)
class ClientCertificateIdentity:
    """The verified facts about a presented client certificate.

    This is *authentication* only. It says which certificate was presented, not
    what its holder may do -- that is resolved against the database and then
    decided in ``auth.policy``.
    """

    fingerprint_sha256: str
    subject_dn: str
    issuer_dn: str
    serial_hex: str
    not_before: dt.datetime
    not_after: dt.datetime
    common_name: str | None


def _format_name(name: x509.Name) -> str:
    """Render an X.509 name in RFC 4514 form."""
    return name.rfc4514_string()


def _common_name(name: x509.Name) -> str | None:
    attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return None
    value = attributes[0].value
    return value if isinstance(value, str) else value.decode("utf-8", errors="replace")


def _require_trusted_proxy(
    settings: Settings, peer_ip: str | None, proxy_auth_header: str | None
) -> None:
    """Verify the request actually came from the mTLS-terminating proxy.

    Both checks are performed even when the first fails, so that this function's
    running time does not distinguish "wrong source address" from "wrong
    secret".
    """
    peer_ok = settings.peer_is_trusted_proxy(peer_ip)

    expected = settings.proxy_shared_secret.get_secret_value()
    presented = proxy_auth_header or ""
    # compare_digest on the UTF-8 bytes; a plain == would leak the shared
    # secret's prefix length through timing.
    secret_ok = hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))

    if settings.dev_trust_unauthenticated_proxy:
        # Gated to non-production by Settings.validate_production_posture.
        return

    if not peer_ok:
        raise CertificateRejectedError("untrusted_proxy_peer")
    if not secret_ok:
        raise CertificateRejectedError("proxy_auth_mismatch")


def _parse_certificate(raw_header: str) -> x509.Certificate:
    """Decode and parse the proxy-forwarded PEM certificate."""
    if len(raw_header) > MAX_CERT_HEADER_BYTES:
        raise CertificateRejectedError("certificate_header_too_large")

    pem = unquote(raw_header)
    if "BEGIN CERTIFICATE" not in pem:
        raise CertificateRejectedError("certificate_malformed")

    try:
        return x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        # Deliberately broad on the parse: any failure to decode attacker-
        # influenced ASN.1 is a rejection, never a traceback to the client.
        logger.warning("client certificate failed to parse", extra={"error": str(exc)})
        raise CertificateRejectedError("certificate_unparseable") from exc


def _check_validity_window(certificate: x509.Certificate, now: dt.datetime) -> None:
    """Re-check the certificate's validity window.

    The proxy already enforced this. We repeat it because a proxy
    misconfiguration (``ssl_verify_client optional`` left in place, a stale
    trust store) would otherwise silently promote an expired certificate into a
    valid session, and this check costs nothing.
    """
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc

    if now + CLOCK_SKEW_TOLERANCE < not_before:
        raise CertificateRejectedError("certificate_not_yet_valid")
    if now - CLOCK_SKEW_TOLERANCE > not_after:
        raise CertificateRejectedError("certificate_expired")


def extract_client_certificate(
    settings: Settings,
    headers: dict[str, str],
    peer_ip: str | None,
    now: dt.datetime | None = None,
) -> ClientCertificateIdentity:
    """Return the verified client certificate identity for a request.

    ``headers`` must be lowercase-keyed, as Starlette provides. Raises
    :class:`CertificateRejectedError` for every failure mode; callers translate that
    into a 401 without echoing the reason.
    """
    now = now or dt.datetime.now(dt.UTC)

    _require_trusted_proxy(settings, peer_ip, headers.get(settings.header_proxy_auth))

    verify = headers.get(settings.header_client_verify, "").strip().upper()
    if verify != _VERIFY_SUCCESS:
        # nginx reports NONE when no certificate was presented and
        # "FAILED:<reason>" when the chain did not validate. Neither is a state
        # we can proceed from, and the distinction is not the client's business.
        raise CertificateRejectedError("client_verify_not_success")

    raw_certificate = headers.get(settings.header_client_cert)
    if not raw_certificate:
        raise CertificateRejectedError("certificate_header_missing")

    certificate = _parse_certificate(raw_certificate)
    _check_validity_window(certificate, now)

    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()

    return ClientCertificateIdentity(
        fingerprint_sha256=fingerprint,
        subject_dn=_format_name(certificate.subject),
        issuer_dn=_format_name(certificate.issuer),
        serial_hex=format(certificate.serial_number, "x"),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        common_name=_common_name(certificate.subject),
    )
