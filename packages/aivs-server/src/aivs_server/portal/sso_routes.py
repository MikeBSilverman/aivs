"""Member sign-in through the ISAC's identity provider, on the public listener.

Two routes: one sends the browser to the IdP with a pending-login cookie, the
other takes it back, verifies everything (``auth.oidc``), decides who the
person is (``services.sso``) and starts an SSO session bound to them and to
this browser's device cookie. Every refusal is audited with its reason; the
browser is told only that sign-in was refused.
"""

from __future__ import annotations

import datetime as dt
import secrets
from typing import Annotated, Final

import httpx
from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, Response

from aivs_server.audit.log import AuditAction, record_independently
from aivs_server.auth.deps import SettingsDep, request_source_ip
from aivs_server.auth.oidc import PENDING_COOKIE, SsoRejectedError, begin_login, complete_login
from aivs_server.auth.sessions import SessionRejectedError
from aivs_server.auth.staff_auth import sign_in_federated
from aivs_server.config import Settings
from aivs_server.portal.shared import redirect_to_identity_provider

__all__ = ["router"]

router = APIRouter(prefix="/portal/sso", include_in_schema=False)

#: A device cookie outlives sessions: it is what an SSO session is bound to
#: besides its own cookie, so it must persist across sign-ins on one browser.
_DEVICE_COOKIE_DAYS: Final[int] = 400

#: The callback is the end of a cross-site navigation from the IdP, and a
#: SameSite=Strict cookie set there is withheld on a redirect that continues
#: it. A page that refreshes to the portal starts a same-site navigation, on
#: which the new session cookie is sent.
_SIGNED_IN_PAGE: Final[str] = (
    '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/portal/">'
    '<title>Signed in</title><p><a href="/portal/">Continue</a></p>'
)
_REFUSED_PAGE: Final[str] = (
    '<!doctype html><meta charset="utf-8"><title>Sign-in refused</title>'
    "<p>Sign-in was refused. If you expected access, contact your ISAC.</p>"
)


def _oidc_http(request: Request) -> httpx.AsyncClient:
    """The client the relying party talks to the IdP with; tests replace it."""
    client: httpx.AsyncClient | None = getattr(request.app.state, "oidc_http", None)
    if client is None:
        client = httpx.AsyncClient(follow_redirects=False)
        request.app.state.oidc_http = client
    return client


def _require_enabled(settings: Settings) -> None:
    if not settings.is_member_sso_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")


@router.get("/login")
async def sso_login(request: Request, settings: SettingsDep) -> Response:
    """Send the browser to the ISAC's identity provider."""
    _require_enabled(settings)
    try:
        pending = await begin_login(_oidc_http(request), settings)
    except SsoRejectedError as exc:
        return await _refused(request, settings, exc.reason)
    try:
        response = redirect_to_identity_provider(
            pending.authorize_url, settings.oidc_member_issuer or ""
        )
    except ValueError:
        return await _refused(request, settings, "authorization_endpoint_off_origin")
    response.set_cookie(
        PENDING_COOKIE,
        pending.cookie,
        max_age=600,
        httponly=True,
        secure=True,
        # Lax, not Strict: it must come back on the IdP's top-level redirect.
        samesite="lax",
        path="/portal/sso",
    )
    return response


@router.get("/callback")
async def sso_callback(
    request: Request,
    settings: SettingsDep,
    state: Annotated[str, Query(max_length=200)] = "",
    code: Annotated[str, Query(max_length=2000)] = "",
) -> Response:
    """Verify the IdP's answer and start an SSO session, or refuse."""
    _require_enabled(settings)
    try:
        identity = await complete_login(
            _oidc_http(request),
            settings,
            returned_state=state,
            code=code,
            pending_cookie=request.cookies.get(PENDING_COOKIE),
        )
    except SsoRejectedError as exc:
        return await _refused(request, settings, exc.reason)

    device = request.cookies.get(settings.sso_device_cookie_name) or secrets.token_urlsafe(32)
    # On the staff login (``auth.staff_auth``): the member login cannot insert
    # an operator (R27). An organisation that left between sign-in and the
    # session keeps nothing the sign-in wrote (a provisioned operator).
    try:
        sign_in, established = await sign_in_federated(
            settings,
            identity,
            device_cookie=device,
            source_ip=request_source_ip(request, settings),
            user_agent=request.headers.get("user-agent"),
            now=dt.datetime.now(dt.UTC),
        )
    except (SsoRejectedError, SessionRejectedError) as exc:
        return await _refused(request, settings, exc.reason)
    await record_independently(
        action=AuditAction.SSO_LOGIN_SUCCESS,
        actor_type="operator",
        actor_id=str(sign_in.operator.id),
        org_id=sign_in.organization.id,
        outcome="success",
        request_id=request.scope.get("aivs_request_id"),
        source_ip=request_source_ip(request, settings),
        details={"amr": list(identity.amr), "provisioned": sign_in.provisioned},
    )
    return _signed_in(settings, established.token, established.csrf_token, device)


def _signed_in(settings: Settings, token: str, csrf_token: str, device: str) -> Response:
    response = HTMLResponse(_SIGNED_IN_PAGE)
    lifetime = min(settings.session_ttl_minutes, settings.sso_session_max_age_minutes) * 60
    for name, value in ((settings.session_cookie_name, token), ("aivs_csrf", csrf_token)):
        response.set_cookie(
            name,
            value,
            max_age=lifetime,
            httponly=True,
            secure=True,
            samesite="strict",
            path="/portal",
        )
    response.set_cookie(
        settings.sso_device_cookie_name,
        device,
        max_age=_DEVICE_COOKIE_DAYS * 86400,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/portal",
    )
    response.delete_cookie(PENDING_COOKIE, path="/portal/sso")
    return response


async def _refused(request: Request, settings: Settings, reason: str) -> Response:
    await record_independently(
        action=AuditAction.SSO_LOGIN_REFUSED,
        outcome="denied",
        request_id=request.scope.get("aivs_request_id"),
        source_ip=request_source_ip(request, settings),
        details={"reason": reason},
    )
    response = HTMLResponse(_REFUSED_PAGE, status_code=status.HTTP_403_FORBIDDEN)
    response.delete_cookie(PENDING_COOKIE, path="/portal/sso")
    return response
