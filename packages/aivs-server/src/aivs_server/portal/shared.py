"""Helpers shared by the portal's member and administrative screens.

Extracted when the administrative screens were added, rather than duplicated
into them. Session resolution, CSRF checking and the notice mechanism are all
security-relevant, and a second copy of any of them is one edit away from being
a second, weaker copy -- which is exactly how a portal becomes a softer door to
the same operations than the API it sits beside.

The public names here have no leading underscore because they are now a small
internal interface with two consumers, not private helpers of one module.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

from aivs_schemas.enums import TLP
from aivs_schemas.tlp import TLP_NAMES
from aivs_server.audit.log import AuditAction, record_independently
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.deps import (
    SessionDep,
    request_certificate_fingerprint,
    request_source_ip,
    resolve_request_session,
    resolve_request_sso_session,
)
from aivs_server.auth.passwords import constant_time_equals
from aivs_server.auth.policy import can_view_instance_status, is_isac_staff
from aivs_server.auth.sessions import SessionRejectedError
from aivs_server.config import Settings
from aivs_server.db.models import Operator

__all__ = [
    "LOGIN_FAILED",
    "TEMPLATES",
    "base_context",
    "current_session",
    "operator_name",
    "redirect_to_identity_provider",
    "redirect_to_login",
    "redirect_within_portal",
    "render",
    "require_csrf",
    "set_notice",
    "signed_out_response",
    "stamp",
    "tlp_label",
]

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

#: One message for every login failure. Which of the three inputs was wrong is
#: half the credential.
LOGIN_FAILED = "Those credentials were not accepted."


async def current_session(
    request: Request, settings: Settings, session: SessionDep
) -> tuple[AuthContext, str]:
    """Resolve the signed-in person, or send them to sign in.

    The request decides which kind of session it may resume. One that carries
    a client certificate resumes only a certificate-bound session; one with no
    certificate -- the public listener -- resumes only an SSO session, and only
    when member SSO is configured. Each resolver refuses the other kind, so a
    cookie taken from one path is worth nothing on the other.
    """
    fingerprint = request_certificate_fingerprint(request, settings)
    is_sso = fingerprint is None and settings.is_member_sso_enabled
    sign_in = redirect_to_sso_login() if is_sso else redirect_to_login()
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise sign_in
    try:
        # Identity is resolved in auth.deps, as the API's is; this function
        # decides only which kind of session the request may resume, and what
        # a refusal looks like here.
        if is_sso:
            resolved = await resolve_request_sso_session(request, settings, session, token=token)
        else:
            resolved = await resolve_request_session(
                request, settings, session, token=token, cert_fingerprint=fingerprint
            )
    except SessionRejectedError as exc:
        await record_independently(
            action=AuditAction.SESSION_REJECTED,
            outcome="denied",
            request_id=request.scope.get("aivs_request_id"),
            source_ip=request_source_ip(request, settings),
            details={"reason": exc.reason, "path": request.url.path},
        )
        raise sign_in from exc
    # For the 403 and 404 handlers, which audit who was refused.
    request.state.auth_context = resolved[0]
    return resolved


def redirect_to_sso_login() -> HTTPException:
    """Where a person on the public listener signs in: the ISAC's identity provider."""
    return HTTPException(
        status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/portal/sso/login"}
    )


#: Where an SSO session lands after signing out. Not a redirect to the IdP:
#: the IdP would sign the person straight back in, so signing out would not
#: appear to have happened. Not ``/portal/login`` either: the public listener
#: does not serve the password form, so the person would land on nginx's 404.
_SSO_SIGNED_OUT_PAGE: Final[str] = (
    '<!doctype html><meta charset="utf-8"><title>Signed out</title>'
    '<p>You have signed out.</p><p><a href="/portal/sso/login">Sign in again</a></p>'
)


def signed_out_response(ctx: AuthContext) -> Response:
    """Where a person goes after signing out: the sign-in for the kind of session they had."""
    if ctx.auth_method is AuthMethod.SSO_SESSION:
        return HTMLResponse(_SSO_SIGNED_OUT_PAGE)
    return redirect_within_portal("/portal/login")


def redirect_to_login() -> HTTPException:
    """A redirect expressed as an exception, so callers can raise it inline."""
    return HTTPException(
        status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/portal/login"}
    )


def require_csrf(submitted: str, expected_hash: str) -> None:
    """Reject a form post whose CSRF token does not match the session.

    Compared as digests in constant time. A missing or wrong token is a 403 with
    no detail: a cross-site attempt should learn nothing about why it failed.
    """
    digest = hashlib.sha256(submitted.encode("utf-8")).hexdigest()
    if not constant_time_equals(digest, expected_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Invalid form token")


def base_context(
    request: Request, settings: Settings, ctx: AuthContext, operator_name: str, active: str
) -> dict[str, Any]:
    return {
        "request": request,
        "instance_name": settings.instance_name,
        "org_slug": ctx.org_slug,
        "operator_name": operator_name,
        "is_admin": is_isac_staff(ctx),
        "can_view_status": can_view_instance_status(ctx),
        "active": active,
        "notices": take_notices(request),
        # Every authenticated page carries the sign-out form, so the token
        # belongs in the shared context rather than being threaded through each
        # route. Pages that mint their own still override it.
        "csrf_token": request.cookies.get("aivs_csrf", ""),
    }


#: Cookie carrying a one-shot notice across the redirect that follows a POST.
#: Signed so the message rendered back to the operator is one this server wrote,
#: and cleared as soon as it is read.
NOTICE_COOKIE: Final[str] = "aivs_notice"
NOTICE_SALT: Final[str] = "aivs.portal.notice.v1"
NOTICE_MAX_AGE: Final[int] = 60


def set_notice(response: Response, settings: Settings, level: str, message: str) -> None:
    """Attach a one-shot notice to a redirect response."""
    serializer = URLSafeTimedSerializer(
        settings.session_secret.get_secret_value(), salt=NOTICE_SALT
    )
    response.set_cookie(
        NOTICE_COOKIE,
        serializer.dumps({"level": level, "message": message}),
        max_age=NOTICE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/portal",
    )


def take_notices(request: Request) -> list[dict[str, str]]:
    """Read and consume any pending notice.

    Without this, a workflow verb that failed redirected to the same page as one
    that succeeded, with nothing to distinguish them -- so an operator who tried
    to distribute to a circle whose TLP floor refused the submission was shown
    the detail page and no message, and would reasonably conclude the members had
    been warned.
    """
    raw = request.cookies.get(NOTICE_COOKIE)
    if not raw:
        return []

    settings: Settings = request.app.state.settings
    serializer = URLSafeTimedSerializer(
        settings.session_secret.get_secret_value(), salt=NOTICE_SALT
    )
    try:
        payload = serializer.loads(raw, max_age=NOTICE_MAX_AGE)
    except BadSignature:
        return []

    if not isinstance(payload, dict):
        return []
    level = str(payload.get("level", "error"))
    message = str(payload.get("message", ""))
    if not message:
        return []

    # Consumed, so render clears it. A notice that survived the page it was
    # written for would reappear on the next reload and describe a failure that
    # had already been reported.
    request.state.aivs_notice_consumed = True
    return [{"level": level, "message": message}]


def render(request: Request, template: str, context: dict[str, Any]) -> Response:
    """Render a portal template, clearing any notice this page just displayed."""
    response = TEMPLATES.TemplateResponse(request, template, context)
    if getattr(request.state, "aivs_notice_consumed", False):
        response.delete_cookie(NOTICE_COOKIE, path="/portal")
    return response


async def operator_name(session: SessionDep, ctx: AuthContext) -> str:
    if ctx.operator_id is None:
        return ctx.org_slug
    operator = await session.get(Operator, ctx.operator_id)
    return operator.display_name if operator else ctx.org_slug


def tlp_label(value: Any) -> str:
    try:
        return TLP_NAMES[TLP(str(value))]
    except (ValueError, KeyError):
        return str(value)


def stamp(value: dt.datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M") if value else ""


def redirect_to_identity_provider(authorize_url: str, issuer: str) -> RedirectResponse:
    """A 303 to the member IdP's authorization endpoint, on the issuer's own origin.

    The one redirect that leaves the portal on purpose. The endpoint comes from
    the issuer's discovery document; requiring the issuer's scheme and host
    keeps a wrong or tampered document from turning sign-in into a redirect to
    somewhere else.
    """
    target, trusted = urlsplit(authorize_url), urlsplit(issuer)
    is_issuer_origin = target.scheme == "https" and (target.scheme, target.netloc) == (
        trusted.scheme,
        trusted.netloc,
    )
    if not is_issuer_origin:
        msg = f"refusing to redirect off the identity provider's origin: {authorize_url!r}"
        raise ValueError(msg)
    return RedirectResponse(authorize_url, status_code=status.HTTP_303_SEE_OTHER)


def redirect_within_portal(path: str) -> RedirectResponse:
    """A 303 to a page of this portal, and nowhere else.

    Every portal redirect is built from constants and typed path parameters
    today, so none can be steered off-site. This makes that a checked property
    rather than an observation: a later caller handing in a string from a form
    or a query cannot turn the portal into an open redirect, which a phishing
    page would use to borrow the instance's address.
    """
    is_local = path.startswith("/portal/") and "//" not in path and "\\" not in path
    if not is_local:
        msg = f"refusing to redirect outside the portal: {path!r}"
        raise ValueError(msg)
    return RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER)
