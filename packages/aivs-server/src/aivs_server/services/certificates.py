"""Binding an issued client certificate to an organisation.

Used by the API and by the bootstrap command, so there is one description of
what a registrable certificate is.
"""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import CertStatus, OrgStatus
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.mtls import CertificateRejectedError, verify_issued_by
from aivs_server.auth.policy import can_register_certificate, require
from aivs_server.db.models import ClientCertificate, Organization

__all__ = ["CertificateRegistrationError", "register_certificate"]


class CertificateRegistrationError(ValueError):
    """The certificate cannot be registered; the message is safe to show."""


def _parse(certificate_pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        msg = "Certificate could not be parsed"
        raise CertificateRegistrationError(msg) from exc


def _require_registrable(
    certificate: x509.Certificate, issuing_ca: x509.Certificate | None, now: dt.datetime
) -> None:
    """Refuse an expired certificate, or one this instance's CA did not issue.

    Registration binds a fingerprint to an organisation, so a certificate the
    issuing CA did not sign must never get that far, whatever the proxy would
    later say. ``issuing_ca`` is ``None`` only in dev.
    """
    if certificate.not_valid_after_utc <= now:
        msg = "Certificate has already expired"
        raise CertificateRegistrationError(msg)
    if issuing_ca is None:
        return
    try:
        verify_issued_by(certificate, issuing_ca)
    except CertificateRejectedError as exc:
        msg = (
            "Certificate was not issued by this instance's certificate authority "
            "as a client certificate"
        )
        raise CertificateRegistrationError(msg) from exc


def _require_may_register(ctx: AuthContext | None, organisation: Organization) -> None:
    """Refuse unless the caller may register to ``organisation`` as it is now.

    ``organisation`` must have been loaded under its row lock, so its status is
    the one a concurrent quarantine left. ``ctx`` is ``None`` only for the
    host's bootstrap command, which may register to an active organisation and
    nothing else.
    """
    if ctx is None:
        allowed = organisation.status is OrgStatus.ACTIVE
    else:
        allowed = can_register_certificate(ctx, organisation)
    require(allowed, "certificate_register")


async def register_certificate(
    session: AsyncSession,
    ctx: AuthContext | None,
    *,
    organisation: Organization,
    certificate_pem: str,
    label: str | None,
    issuing_ca: x509.Certificate | None,
    now: dt.datetime,
) -> ClientCertificate:
    """Register ``certificate_pem`` against ``organisation``. Does not commit.

    The fingerprint is computed here from the certificate, never accepted as a
    parameter: a caller-supplied fingerprint that did not match would bind an
    identity to material nobody holds.

    ``organisation`` is loaded with ``load_org_for_update`` and ``now`` read
    after it: the row is stamped with ``now`` rather than the database's
    transaction start, so it is on the same clock as ``quarantined_at`` --
    the database's, read after the lock, from every caller (``db.clock``). A
    registration whose transaction opened before a quarantine and waited on its
    lock was otherwise stamped earlier than the quarantine it followed.
    """
    _require_may_register(ctx, organisation)
    certificate = _parse(certificate_pem)
    _require_registrable(certificate, issuing_ca, now)

    row = ClientCertificate(
        org_id=organisation.id,
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        subject_dn=certificate.subject.rfc4514_string(),
        issuer_dn=certificate.issuer.rfc4514_string(),
        serial_hex=format(certificate.serial_number, "x"),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        status=CertStatus.ACTIVE,
        label=label,
        created_at=now,
    )
    session.add(row)
    await record(
        session,
        action=AuditAction.CERT_REGISTERED,
        ctx=ctx,
        org_id=organisation.id,
        resource_type="organization",
        resource_id=str(organisation.id),
        details={"fingerprint": row.fingerprint_sha256, "subject": row.subject_dn},
    )
    return row
