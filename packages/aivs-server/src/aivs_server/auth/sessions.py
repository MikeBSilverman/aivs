"""Portal sessions, and the certificate binding that makes them two factors.

An analyst authenticates with a password and a TOTP code. That alone would be
one factor's worth of assurance about *which organisation* is calling, because
a stolen credential works from anywhere. So a session is additionally **bound to
the client certificate** that established the network path, and the binding is
re-checked on every request rather than only at login.

The two factors are then genuinely independent: the certificate proves the
organisation and lives on the firm's own infrastructure behind their network
gating; the password and TOTP prove the person. Stealing a session cookie is
useless without also being inside that organisation's certificate-bearing path,
and holding the organisation's certificate is useless without a human
credential.

Per-request re-checking also closes the gap a review flagged: revoking a
certificate must lock out the humans using it, not only the machines. A session
whose bound certificate has been revoked is refused on its next request, with no
separate revocation step to remember.

Only the SHA-256 of a session token is stored, so a database disclosure does not
hand an attacker live sessions.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
import uuid
from dataclasses import dataclass
from typing import Final

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import CertStatus, OrgStatus
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.memberships import load_circle_grants
from aivs_server.auth.passwords import (
    constant_time_equals,
    generate_session_token,
    hash_password,
    matching_totp_step,
    needs_rehash,
    verify_password,
)
from aivs_server.auth.secretbox import SecretBox, SecretPurpose
from aivs_server.config import Settings
from aivs_server.db.models import (
    ClientCertificate,
    Operator,
    Organization,
    PortalSession,
)

logger = logging.getLogger(__name__)

__all__ = [
    "LOCKOUT_THRESHOLD",
    "SessionRejectedError",
    "authenticate_operator",
    "establish_session",
    "resolve_session",
    "revoke_session",
    "revoke_sessions_for_certificate",
]

#: Consecutive failures before an operator is locked out. Low enough to stop
#: online guessing, high enough that a person mistyping twice is not locked out
#: of an incident response.
LOCKOUT_THRESHOLD: Final[int] = 5
LOCKOUT_DURATION: Final[dt.timedelta] = dt.timedelta(minutes=15)


class SessionRejectedError(Exception):
    """A session could not be established or resumed.

    ``reason`` is a stable token for the audit log. As everywhere else in this
    package, it is not shown to the caller: an attacker must not learn whether a
    login failed on the address, the password, the second factor, or a lockout.
    """

    __slots__ = ("reason",)

    def __init__(self, reason: str) -> None:
        super().__init__(f"session rejected: {reason}")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class EstablishedSession:
    """A newly created session and the token to hand to the browser."""

    token: str
    csrf_token: str
    expires_at: dt.datetime
    operator_id: uuid.UUID


def _digest(token: str) -> str:
    """Return the stored form of a token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def authenticate_operator(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    totp_code: str,
    org_id: uuid.UUID,
    secret_box: SecretBox,
    now: dt.datetime | None = None,
) -> Operator:
    """Verify an operator's credentials, or raise :class:`SessionRejectedError`.

    ``org_id`` comes from the client certificate on the request, and the
    operator must belong to it. That is what stops a stolen credential being
    replayed from inside a *different* member firm's network path.

    Every failure raises the same exception type with a different reason token,
    and the caller renders one message for all of them.
    """
    now = now or dt.datetime.now(dt.UTC)
    normalised = email.strip().lower()

    # FOR UPDATE, because the lockout counter below is a read-modify-write and
    # the lockout is the only bound on password guessing.
    #
    # Without it, `failed_login_count += 1` is an absolute UPDATE of a value read
    # before the attempt: N concurrent failures all read the same count and all
    # write the same count, so N attempts record one increment and the threshold
    # is never reached. An attacker inside a member firm's certificate-bearing
    # path could then guess without limit, while `locked_until` stayed null and
    # the audit log showed an ordinary run of failures.
    #
    # The lock is held across the Argon2 verification below, which serialises
    # concurrent attempts against one operator. That is the intent rather than a
    # cost: attempts on one account queue instead of racing, and it is a single
    # row, so there is nothing to deadlock against.
    operator = (
        await session.execute(
            select(Operator).where(Operator.email == normalised).with_for_update()
        )
    ).scalar_one_or_none()

    # Verified even when no operator matched, so the response time does not
    # distinguish a real address from an invented one.
    password_ok = verify_password(operator.password_hash if operator else None, password)

    if operator is None:
        raise SessionRejectedError("unknown_operator")
    if not operator.is_active:
        raise SessionRejectedError("operator_inactive")
    if operator.locked_until is not None and operator.locked_until > now:
        raise SessionRejectedError("operator_locked")
    if operator.org_id != org_id:
        # The credential is real but is being presented from another
        # organisation's certificate path.
        raise SessionRejectedError("operator_org_mismatch")

    seed = secret_box.unseal(
        operator.totp_secret_encrypted, purpose=SecretPurpose.TOTP, subject=operator.id
    )
    if seed is None and password_ok:
        # The server cannot open its own copy of the seed: a key-encryption key
        # missing, rotated away, or misconfigured. That is our fault, not the
        # operator's, so it must not count towards their lockout -- charging it
        # did, and progressively locked out every operator who tried to sign in,
        # with lockouts that outlived the fix and an audit trail that read
        # exactly like a password-guessing attack. The webhook dispatcher made
        # the same call for the same cause and wrote down why.
        #
        # Only when the password was right: a wrong password is still a failed
        # guess and still counts, so this cannot be used to guess for free.
        logger.error(
            "operator TOTP seed could not be opened; check AIVS_SECRET_ENCRYPTION_KEY",
            extra={"operator_id": str(operator.id)},
        )
        raise SessionRejectedError("totp_seed_unavailable")
    code_step = matching_totp_step(seed, totp_code, now=now)
    code_is_fresh = code_step is not None and (
        operator.last_totp_step is None or code_step > operator.last_totp_step
    )

    if not (password_ok and code_is_fresh):
        operator.failed_login_count += 1
        if operator.failed_login_count >= LOCKOUT_THRESHOLD:
            operator.locked_until = now + LOCKOUT_DURATION
            operator.failed_login_count = 0
        await session.commit()
        # A valid code already spent is a replay, worth telling apart in the
        # audit trail; the person signing in sees one message for every failure.
        replayed = password_ok and code_step is not None
        raise SessionRejectedError("totp_reused" if replayed else "bad_credentials")

    operator.failed_login_count = 0
    operator.locked_until = None
    operator.last_login_at = now
    # Under the row lock taken above and in this commit: a second login with the
    # same code waits for this one and then reads this step.
    operator.last_totp_step = code_step
    if needs_rehash(operator.password_hash):
        # Transparent upgrade: the stored cost keeps up with the library's
        # current parameters without a migration or a forced password reset.
        operator.password_hash = hash_password(password)

    # Committed here rather than left to the caller, symmetrically with the
    # failure path above. Deferring it meant a successful login did not clear
    # the lockout counter unless session creation also succeeded -- so a
    # transient failure between the two would leave an operator several
    # successful logins away from being locked out of their own account.
    await session.commit()

    return operator


async def establish_session(
    session: AsyncSession,
    settings: Settings,
    *,
    operator: Operator,
    cert_fingerprint: str,
    source_ip: str | None = None,
    user_agent: str | None = None,
    now: dt.datetime | None = None,
) -> EstablishedSession:
    """Create a session bound to the certificate that carried the login.

    A fresh token is minted here rather than reusing anything the browser
    supplied, so a session fixed before login cannot survive it.

    ``cert_fingerprint`` is required rather than optional: the binding to the
    organisation's certificate is what makes the password and the transport two
    independent factors, and a session created without one would be a cookie
    that authenticates on its own.
    """
    now = now or dt.datetime.now(dt.UTC)
    token = generate_session_token()
    csrf_token = generate_session_token()
    expires_at = now + dt.timedelta(minutes=settings.session_ttl_minutes)

    session.add(
        PortalSession(
            token_hash=_digest(token),
            csrf_token_hash=_digest(csrf_token),
            operator_id=operator.id,
            org_id=operator.org_id,
            cert_fingerprint=cert_fingerprint,
            source_ip=source_ip,
            user_agent=(user_agent or "")[:400] or None,
            expires_at=expires_at,
            last_seen_at=now,
        )
    )
    await session.commit()

    return EstablishedSession(
        token=token,
        csrf_token=csrf_token,
        expires_at=expires_at,
        operator_id=operator.id,
    )


async def resolve_session(
    session: AsyncSession,
    settings: Settings,
    *,
    token: str,
    cert_fingerprint: str | None,
    request_id: str = "",
    source_ip: str | None = None,
    now: dt.datetime | None = None,
) -> tuple[AuthContext, str]:
    """Resume a session, returning its context and CSRF token hash.

    Every check that could have changed since login is re-run here, because a
    session that outlives the authority it was granted under is the whole
    problem sessions create. In order: the token exists and is not revoked, the
    absolute and idle deadlines have not passed, the certificate presented on
    *this* request is the one the session was bound to, that certificate is
    still active, the operator is still active, and their organisation still is.
    """
    now = now or dt.datetime.now(dt.UTC)

    row = await _load_live_session(session, settings, token=token, now=now)
    _check_certificate_binding(row, cert_fingerprint)
    await _check_bound_certificate(session, row, now=now)
    operator = await _load_active_operator(session, row)
    organization = await _load_active_organization(session, row)

    circles = await load_circle_grants(session, organization.id)

    row.last_seen_at = now
    await session.commit()

    context = AuthContext(
        org_id=organization.id,
        org_slug=organization.slug,
        org_type=organization.org_type,
        org_status=organization.status,
        auth_method=AuthMethod.PORTAL_SESSION,
        circles=circles,
        cert_fingerprint=row.cert_fingerprint,
        operator_id=operator.id,
        operator_roles=frozenset(operator.roles),
        request_id=request_id,
        source_ip=source_ip,
    )
    return context, row.csrf_token_hash


async def _load_live_session(
    session: AsyncSession, settings: Settings, *, token: str, now: dt.datetime
) -> PortalSession:
    """The session row for ``token``, refused if revoked or past either deadline."""
    row = (
        await session.execute(
            select(PortalSession).where(PortalSession.token_hash == _digest(token))
        )
    ).scalar_one_or_none()

    if row is None:
        raise SessionRejectedError("unknown_session")
    if row.revoked_at is not None:
        raise SessionRejectedError("session_revoked")
    if row.expires_at <= now:
        raise SessionRejectedError("session_expired")

    idle_deadline = row.last_seen_at + dt.timedelta(minutes=settings.session_idle_timeout_minutes)
    if idle_deadline <= now:
        raise SessionRejectedError("session_idle_timeout")
    return row


def _check_certificate_binding(row: PortalSession, cert_fingerprint: str | None) -> None:
    """Refuse unless this request presents the certificate the session is bound to.

    A cookie replayed from outside this organisation's certificate-bearing path
    fails here, which is what makes the password and the certificate two
    independent factors rather than one.

    Unconditional. These checks used to sit inside `if row.cert_fingerprint is
    not None`, so a session row with a null fingerprint resolved to a full
    context with no certificate requirement at all -- the cookie alone would
    have been sufficient, from any network path that could reach the app. No
    caller could produce such a row, but "permit only this" is the shape that
    stays correct when the next caller arrives.
    """
    if row.cert_fingerprint is None:
        raise SessionRejectedError("session_unbound")
    if cert_fingerprint is None or not constant_time_equals(row.cert_fingerprint, cert_fingerprint):
        raise SessionRejectedError("session_certificate_mismatch")


async def _check_bound_certificate(
    session: AsyncSession, row: PortalSession, *, now: dt.datetime
) -> None:
    """Refuse unless the session's certificate is still registered, active and unexpired."""
    certificate = (
        await session.execute(
            select(ClientCertificate).where(
                ClientCertificate.fingerprint_sha256 == row.cert_fingerprint
            )
        )
    ).scalar_one_or_none()
    if certificate is None or certificate.status is not CertStatus.ACTIVE:
        # Revoking a certificate locks out the humans using it, not only the
        # machines, and takes effect on the next request.
        raise SessionRejectedError("session_certificate_revoked")
    if certificate.not_after <= now:
        # The same check get_auth_context makes on the machine path: where the
        # recorded registration and the certificate itself disagree, the database
        # is the authority. Without it a registration whose expiry was shortened
        # kept working for portal sessions while machine calls were refused.
        raise SessionRejectedError("session_certificate_expired")


async def _load_active_operator(session: AsyncSession, row: PortalSession) -> Operator:
    operator = await session.get(Operator, row.operator_id)
    if operator is None or not operator.is_active:
        raise SessionRejectedError("operator_inactive")
    return operator


async def _load_active_organization(session: AsyncSession, row: PortalSession) -> Organization:
    organization = await session.get(Organization, row.org_id)
    if organization is None or organization.status is not OrgStatus.ACTIVE:
        raise SessionRejectedError("org_inactive")
    return organization


async def revoke_session(session: AsyncSession, *, token: str) -> None:
    """Revoke one session. Idempotent."""
    await session.execute(
        update(PortalSession)
        .where(PortalSession.token_hash == _digest(token), PortalSession.revoked_at.is_(None))
        .values(revoked_at=dt.datetime.now(dt.UTC))
    )
    await session.commit()


async def revoke_sessions_for_certificate(
    session: AsyncSession, *, fingerprint: str, now: dt.datetime | None = None
) -> int:
    """Revoke every session bound to a certificate. Returns the count.

    Called when a certificate is revoked. ``resolve_session`` would refuse these
    anyway on their next request, but ending them immediately means the audit
    record shows the sessions closing at revocation time rather than whenever
    each browser happened to poll next.
    """
    now = now or dt.datetime.now(dt.UTC)
    result = await session.execute(
        update(PortalSession)
        .where(
            PortalSession.cert_fingerprint == fingerprint,
            PortalSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
        .returning(PortalSession.id)
    )
    return len(result.scalars().all())
