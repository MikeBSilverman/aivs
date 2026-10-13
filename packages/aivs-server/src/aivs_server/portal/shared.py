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

from fastapi import HTTPException, Request, Response, status
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

from aivs_schemas.enums import TLP
from aivs_schemas.tlp import TLP_NAMES
from aivs_server.audit.log import AuditAction, record_independently
from aivs_server.auth.context import AuthContext
from aivs_server.auth.deps import SessionDep, request_source_ip
from aivs_server.auth.mtls import CertificateRejectedError, extract_client_certificate
from aivs_server.auth.passwords import constant_time_equals
from aivs_server.auth.policy import can_view_instance_status, is_isac_staff
from aivs_server.auth.sessions import SessionRejectedError, resolve_session
from aivs_server.config import Settings
from aivs_server.db.models import Operator

__all__ = [
    "LOGIN_FAILED",
    "TEMPLATES",
    "base_context",
    "client_fingerprint",
    "current_session",
    "operator_name",
    "redirect_to_login",
    "render",
    "require_csrf",
    "set_notice",
    "stamp",
    "tlp_label",
]

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

#: One message for every login failure. Which of the three inputs was wrong is
#: half the credential.
LOGIN_FAILED = "Those credentials were not accepted."


def client_fingerprint(request: Request, settings: Settings) -> str | None:
    """Fingerprint of the certificate on this request, or ``None``.

    The portal is reached through the same mTLS proxy as everything else, so
    this is the organisation's identity. Absent means the deployment is not
    behind the proxy, which the session binding then refuses.
    """
    headers = {key.lower(): value for key, value in request.headers.items()}
    peer = request.client.host if request.client else None
    try:
        return extract_client_certificate(settings, headers, peer).fingerprint_sha256
    except CertificateRejectedError:
        return None


async def current_session(
    request: Request, settings: Settings, session: SessionDep
) -> tuple[AuthContext, str]:
    """Resolve the signed-in analyst, or redirect to the login page."""
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise redirect_to_login()
    try:
        resolved = await resolve_session(
            session,
            settings,
            token=token,
            cert_fingerprint=client_fingerprint(request, settings),
            request_id=request.scope.get("aivs_request_id", ""),
            source_ip=request_source_ip(request, settings),
        )
    except SessionRejectedError as exc:
        await record_independently(
            action=AuditAction.SESSION_REJECTED,
            outcome="denied",
            request_id=request.scope.get("aivs_request_id"),
            source_ip=request_source_ip(request, settings),
            details={"reason": exc.reason, "path": request.url.path},
        )
        raise redirect_to_login() from exc
    # For the 403 and 404 handlers, which audit who was refused.
    request.state.auth_context = resolved[0]
    return resolved


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
