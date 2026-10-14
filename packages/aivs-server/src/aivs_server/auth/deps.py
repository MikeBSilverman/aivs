"""FastAPI dependencies that resolve the caller's identity.

The chain is deliberately short and has no branches that end in "allow":

    proxy headers -> verified certificate -> registered org -> circles -> AuthContext

Every failure raises 401 with a generic body. The specific reason goes to the
audit log and never to the caller: telling an unauthenticated client whether it
failed because the certificate was unknown, revoked, or belonged to a suspended
organisation is free reconnaissance.
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Final

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import CertStatus, CircleRole, OrgStatus
from aivs_server.audit.log import AuditAction, record_independently
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.memberships import load_circle_grants
from aivs_server.auth.mtls import (
    CertificateRejectedError,
    ClientCertificateIdentity,
    client_address,
    extract_client_certificate,
)
from aivs_server.auth.sessions import SessionRejectedError, resolve_session
from aivs_server.config import Settings, get_settings
from aivs_server.db.engine import get_session
from aivs_server.db.models import ClientCertificate, Organization

__all__ = [
    "AuthenticatedContext",
    "SessionDep",
    "SettingsDep",
    "get_auth_context",
    "request_certificate",
    "request_certificate_fingerprint",
    "request_source_ip",
    "resolve_request_session",
]

#: Returned for every authentication failure, regardless of cause.
_GENERIC_UNAUTHORIZED: Final[str] = "Client certificate authentication required"


def _settings_dependency(request: Request) -> Settings:
    """Return the settings this application instance was built with.

    Read from application state rather than the process-wide cache so that the
    running app is governed by exactly the configuration it was constructed
    with. Falling back to the environment here would let a test -- or a second
    app in the same process -- silently authenticate against different settings
    than the ones it was handed.
    """
    settings: Settings | None = getattr(request.app.state, "settings", None)
    return settings if settings is not None else get_settings()


SettingsDep = Annotated[Settings, Depends(_settings_dependency)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]


def _client_ip(request: Request) -> str | None:
    """Return the peer address of the TCP connection.

    This is the *proxy's* address, not the member's -- which is exactly what the
    trusted-proxy allowlist needs to check, and nothing else should use it.
    """
    return request.client.host if request.client else None


def _request_headers(request: Request) -> dict[str, str]:
    return {key.lower(): value for key, value in request.headers.items()}


def request_source_ip(request: Request, settings: Settings) -> str | None:
    """The address to record on audit rows and sessions for this request.

    The member's, when the proxy vouches for it (``auth.mtls.client_address``);
    the peer otherwise. Informational: no authorization decision reads it.
    """
    return client_address(settings, _request_headers(request), _client_ip(request))


# The API's dependency and the portal's cookie sessions both identify a caller
# through the three functions below, so the proxy check, the certificate
# checks and the session's binding to the certificate are one door, not two
# copies a later edit could let drift apart.


def request_certificate(request: Request, settings: Settings) -> ClientCertificateIdentity:
    """The client certificate the trusted proxy vouches for on this request.

    Raises ``CertificateRejectedError`` unless the request came from the proxy
    with its shared secret and a certificate that passes every check in
    ``auth.mtls``.
    """
    return extract_client_certificate(settings, _request_headers(request), _client_ip(request))


def request_certificate_fingerprint(request: Request, settings: Settings) -> str | None:
    """The fingerprint of :func:`request_certificate`, or ``None`` when it is refused.

    For the portal, where a missing certificate is not answered with a 401:
    login refuses it by name, and a session bound to a certificate is refused
    when there is none to compare.
    """
    try:
        return request_certificate(request, settings).fingerprint_sha256
    except CertificateRejectedError:
        return None


async def resolve_request_session(
    request: Request,
    settings: Settings,
    session: AsyncSession,
    *,
    token: str,
    cert_fingerprint: str | None,
) -> tuple[AuthContext, str]:
    """Resume the signed-in human's session on this request; see ``resolve_session``.

    Raises ``SessionRejectedError``. The caller decides what a refusal looks
    like on its surface: a 401 for the API, a redirect to sign in for the portal.
    """
    return await resolve_session(
        session,
        settings,
        token=token,
        cert_fingerprint=cert_fingerprint,
        request_id=request.scope.get("aivs_request_id", ""),
        source_ip=request_source_ip(request, settings),
    )


async def _reject(
    reason: str,
    request: Request,
    source_ip: str | None,
) -> HTTPException:
    """Audit an authentication failure and build the response to raise."""
    await record_independently(
        action=AuditAction.AUTH_FAILURE,
        actor_type="anonymous",
        outcome="failure",
        request_id=request.scope.get("aivs_request_id"),
        source_ip=source_ip,
        details={"reason": reason, "path": request.url.path, "method": request.method},
    )
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=_GENERIC_UNAUTHORIZED,
    )


async def _human_session_context(
    request: Request,
    settings: Settings,
    session: AsyncSession,
    *,
    authorization: str,
    cert_fingerprint: str,
    source_ip: str | None,
) -> AuthContext:
    """Resolve a signed-in human presenting their session as a bearer token.

    How ISAC staff reach the editorial and membership endpoints from a script:
    every ISAC power requires a human session, and the API authenticates
    machines. The token is the portal session's own, so it is bound to the
    certificate on this request, carries the same deadlines and revocation,
    and was issued only after password and TOTP. A bearer header is never sent
    by a browser on its own, which is why this path needs no CSRF token where
    the portal's cookie does.

    A header that is present but not a valid session is refused outright. It is
    never quietly downgraded to the certificate's machine identity: a caller who
    asked to act as a person and is not one must not proceed as something else.
    """
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise await _reject("authorization_malformed", request, source_ip)
    try:
        ctx, _csrf_hash = await resolve_request_session(
            request, settings, session, token=token.strip(), cert_fingerprint=cert_fingerprint
        )
    except SessionRejectedError as rejection:
        raise await _reject(f"bearer_{rejection.reason}", request, source_ip) from rejection
    return ctx


async def get_auth_context(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
) -> AuthContext:
    """Resolve the caller, and leave the result where error handlers can find it.

    The 403 and 404 handlers audit *who* was refused. They read the context
    from ``request.state``, which nothing used to set, so every ``authz.denied``
    row was written with no actor and "repeated denials from one org" could
    not be reviewed.
    """
    ctx = await _resolve_auth_context(request, settings, session)
    request.state.auth_context = ctx
    return ctx


async def _resolve_auth_context(
    request: Request,
    settings: Settings,
    session: AsyncSession,
) -> AuthContext:
    """Resolve the calling organisation from its client certificate.

    Raises 401 unless every one of the following holds: the request arrived via
    the trusted proxy with the correct shared secret, the proxy reports a
    successful chain verification, the presented certificate parses and is
    within its validity window, that certificate is registered and not revoked,
    and its organisation is active.
    """
    source_ip = request_source_ip(request, settings)

    try:
        certificate = request_certificate(request, settings)
    except CertificateRejectedError as rejection:
        raise await _reject(rejection.reason, request, source_ip) from rejection

    authorization = _request_headers(request).get("authorization")
    if authorization is not None:
        return await _human_session_context(
            request,
            settings,
            session,
            authorization=authorization,
            cert_fingerprint=certificate.fingerprint_sha256,
            source_ip=source_ip,
        )

    row = (
        await session.execute(
            select(ClientCertificate, Organization)
            .join(Organization, ClientCertificate.org_id == Organization.id)
            .where(ClientCertificate.fingerprint_sha256 == certificate.fingerprint_sha256)
        )
    ).first()

    if row is None:
        raise await _reject("certificate_not_registered", request, source_ip)

    registration, organization = row

    if registration.status is not CertStatus.ACTIVE:
        # Revocation is authoritative here rather than in a CRL: one indexed
        # lookup, effective on the member's very next request.
        raise await _reject("certificate_revoked", request, source_ip)

    now = dt.datetime.now(dt.UTC)
    if registration.not_after <= now:
        # The registration's own recorded expiry, distinct from the validity
        # window already checked on the presented certificate. They should
        # agree; if they do not, the database is the authority.
        raise await _reject("certificate_registration_expired", request, source_ip)

    if organization.status is not OrgStatus.ACTIVE:
        raise await _reject(f"org_{organization.status.value}", request, source_ip)

    circles = await load_circle_grants(session, organization.id)

    return AuthContext(
        org_id=organization.id,
        org_slug=organization.slug,
        org_type=organization.org_type,
        org_status=organization.status,
        auth_method=AuthMethod.MTLS,
        circles=circles,
        cert_fingerprint=certificate.fingerprint_sha256,
        request_id=request.scope.get("aivs_request_id", ""),
        source_ip=source_ip,
    )


#: The dependency every authenticated route declares. There is no route-level
#: opt-out; endpoints that are genuinely public (``/healthz``) simply do not
#: declare it, and the authorization matrix test asserts that the set of such
#: endpoints is exactly the intended one.
AuthenticatedContext = Annotated[AuthContext, Depends(get_auth_context)]


def _role_rank(role: CircleRole) -> int:
    """Order circle roles by privilege, for comparisons in routers."""
    return {CircleRole.MEMBER: 0, CircleRole.CONTRIBUTOR: 1, CircleRole.CIRCLE_ADMIN: 2}[role]
