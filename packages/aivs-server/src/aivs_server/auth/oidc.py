"""OpenID Connect relying party for the member tenant: code flow with PKCE only.

identity-federation.md §3 is the profile; this module implements it for the
member issuer:

- ``response_type=code`` with PKCE ``S256``; no implicit or hybrid flow, and
  SP-initiated only -- a callback that does not correlate to a login this
  browser started is refused.
- ``state`` correlates the callback to the login. It is held in a signed,
  short-lived cookie on the browser that started the login (the certificate
  binding the design describes has nothing to bind to on ordinary TLS), so a
  callback replayed into another browser carries no matching cookie.
- The PKCE verifier and the ``nonce`` are derived from ``state`` with an HMAC
  under the session secret, so nothing about a pending login is stored and
  nothing is left behind by one that was abandoned.
- The ID token's signature is checked against the issuer's published JWKS
  with PyJWT, from an allow-list of algorithms, and ``iss``, ``aud``, ``exp``,
  ``iat`` and ``nonce`` are all required and checked.

Network access goes through an ``httpx.AsyncClient`` the caller supplies, so
tests run against a local fake issuer and production can set timeouts and
proxies in one place.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlencode

import httpx
import jwt
from itsdangerous import BadSignature, URLSafeTimedSerializer

from aivs_server.config import Settings

__all__ = [
    "PENDING_COOKIE",
    "PendingLogin",
    "SsoRejectedError",
    "VerifiedIdentity",
    "begin_login",
    "complete_login",
]

#: The browser-held half of a pending login.
PENDING_COOKIE: Final[str] = "aivs_sso_pending"

#: How long a login may take between leaving for the IdP and coming back.
_PENDING_MAX_AGE_SECONDS: Final[int] = 600

#: Signature algorithms an ID token may use. Never ``none``, never HMAC: an
#: HS256 token would be verified with the client secret as the key, which the
#: relying party shares with the issuer and so could have forged itself.
_ALGORITHMS: Final[tuple[str, ...]] = ("RS256", "PS256", "ES256", "ES384")

_HTTP_TIMEOUT: Final[float] = 10.0

#: Distinct authentication methods in ``amr`` that count as a second factor
#: when the IdP does not say ``mfa`` outright.
_FACTORS_REQUIRED: Final[int] = 2


class SsoRejectedError(Exception):
    """A sign-in attempt was refused. ``reason`` is for the audit row, never the browser."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class PendingLogin:
    authorize_url: str
    #: Value for :data:`PENDING_COOKIE`.
    cookie: str


@dataclass(frozen=True)
class VerifiedIdentity:
    """What a verified ID token says about the person. Nothing here is a grant."""

    issuer: str
    subject: str
    email: str | None
    name: str | None
    groups: tuple[str, ...]
    amr: tuple[str, ...]


@dataclass(frozen=True)
class _Provider:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


# ---------------------------------------------------------------------------
# Starting a login
# ---------------------------------------------------------------------------
async def begin_login(http: httpx.AsyncClient, settings: Settings) -> PendingLogin:
    """The IdP URL to send the browser to, and the cookie that must come back with it."""
    provider = await _discover(http, _issuer(settings))
    state = secrets.token_urlsafe(32)
    query = {
        "response_type": "code",
        "client_id": settings.oidc_member_client_id,
        "redirect_uri": settings.oidc_member_redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "nonce": _derive(settings, "nonce", state),
        "code_challenge": _challenge(_derive(settings, "pkce", state)),
        "code_challenge_method": "S256",
    }
    return PendingLogin(
        authorize_url=f"{provider.authorization_endpoint}?{urlencode(query)}",
        cookie=_pending_serializer(settings).dumps(state),
    )


# ---------------------------------------------------------------------------
# Finishing it
# ---------------------------------------------------------------------------
async def complete_login(
    http: httpx.AsyncClient,
    settings: Settings,
    *,
    returned_state: str,
    code: str,
    pending_cookie: str | None,
) -> VerifiedIdentity:
    """Correlate the callback, redeem the code, and verify the ID token.

    Raises :class:`SsoRejectedError` at the first check that fails.
    """
    state = _correlated_state(settings, returned_state, pending_cookie)
    provider = await _discover(http, _issuer(settings))
    id_token = await _redeem(http, settings, provider, code=code, state=state)
    claims = await _verify(http, settings, provider, id_token, state=state)
    identity = _identity(settings, claims)
    _require_second_factor(identity.amr)
    return identity


def _require_second_factor(amr: tuple[str, ...]) -> None:
    """The IdP says the person used more than one factor, or nobody signs in.

    The second factor is the IdP's to perform and ours to insist on: a
    sign-on policy edited to password-only would otherwise put single-factor
    sessions on AMBER content from any browser, and nothing here would notice.
    Permit-only (CLAUDE.md section 5): ``mfa`` (RFC 8176), or at least two
    distinct methods such as ``pwd`` and ``otp``. A token with no ``amr`` is
    refused, never assumed.
    """
    if "mfa" in amr or len(set(amr)) >= _FACTORS_REQUIRED:
        return
    reason = "second_factor_not_asserted"
    raise SsoRejectedError(reason)


def _correlated_state(settings: Settings, returned_state: str, pending_cookie: str | None) -> str:
    """The callback's ``state`` equals the one this browser was sent off with."""
    if not pending_cookie:
        reason = "no_pending_login"
        raise SsoRejectedError(reason)
    try:
        state = _pending_serializer(settings).loads(
            pending_cookie, max_age=_PENDING_MAX_AGE_SECONDS
        )
    except BadSignature as exc:
        reason = "pending_login_invalid_or_expired"
        raise SsoRejectedError(reason) from exc
    if not isinstance(state, str) or not hmac.compare_digest(state, returned_state):
        reason = "state_mismatch"
        raise SsoRejectedError(reason)
    return state


async def _redeem(
    http: httpx.AsyncClient, settings: Settings, provider: _Provider, *, code: str, state: str
) -> str:
    secret = settings.oidc_member_client_secret
    response = await _call(
        http,
        "POST",
        provider.token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.oidc_member_redirect_uri,
            "client_id": settings.oidc_member_client_id,
            "client_secret": secret.get_secret_value() if secret else "",
            "code_verifier": _derive(settings, "pkce", state),
        },
    )
    if response.status_code != httpx.codes.OK:
        reason = "token_exchange_refused"
        raise SsoRejectedError(reason)
    id_token = response.json().get("id_token")
    if not isinstance(id_token, str):
        reason = "no_id_token"
        raise SsoRejectedError(reason)
    return id_token


async def _verify(
    http: httpx.AsyncClient, settings: Settings, provider: _Provider, id_token: str, *, state: str
) -> Mapping[str, Any]:
    key = await _signing_key(http, provider, id_token)
    try:
        claims: Mapping[str, Any] = jwt.decode(
            id_token,
            key=key,
            algorithms=list(_ALGORITHMS),
            audience=settings.oidc_member_client_id,
            issuer=provider.issuer,
            options={"require": ["iss", "aud", "exp", "iat", "sub", "nonce"]},
        )
    except jwt.PyJWTError as exc:
        reason = "id_token_invalid"
        raise SsoRejectedError(reason) from exc
    if not hmac.compare_digest(str(claims["nonce"]), _derive(settings, "nonce", state)):
        reason = "nonce_mismatch"
        raise SsoRejectedError(reason)
    return claims


async def _signing_key(http: httpx.AsyncClient, provider: _Provider, id_token: str) -> Any:
    """The issuer's published key the token names, and no other."""
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        reason = "id_token_malformed"
        raise SsoRejectedError(reason) from exc
    response = await _call(http, "GET", provider.jwks_uri)
    if response.status_code != httpx.codes.OK:
        reason = "jwks_unavailable"
        raise SsoRejectedError(reason)
    try:
        keys = jwt.PyJWKSet.from_dict(response.json())
    except jwt.PyJWTError as exc:
        reason = "jwks_invalid"
        raise SsoRejectedError(reason) from exc
    for candidate in keys.keys:
        if candidate.key_id == header.get("kid"):
            return candidate.key
    reason = "signing_key_unknown"
    raise SsoRejectedError(reason)


def _identity(settings: Settings, claims: Mapping[str, Any]) -> VerifiedIdentity:
    groups = claims.get(settings.oidc_member_group_claim) or []
    amr = claims.get("amr") or []
    return VerifiedIdentity(
        issuer=str(claims["iss"]),
        subject=str(claims["sub"]),
        email=_optional_string(claims.get("email")),
        name=_optional_string(claims.get("name")),
        groups=_strings(groups),
        amr=_strings(amr),
    )


# ---------------------------------------------------------------------------
# Mechanics
# ---------------------------------------------------------------------------
async def _discover(http: httpx.AsyncClient, issuer: str) -> _Provider:
    """The issuer's endpoints, from its discovery document, which must name itself."""
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    response = await _call(http, "GET", url)
    if response.status_code != httpx.codes.OK:
        reason = "discovery_unavailable"
        raise SsoRejectedError(reason)
    document = response.json()
    if document.get("issuer") != issuer:
        # A discovery document for another issuer is a misconfiguration or a
        # substitution; either way its keys must not verify our tokens.
        reason = "discovery_issuer_mismatch"
        raise SsoRejectedError(reason)
    try:
        return _Provider(
            issuer=issuer,
            authorization_endpoint=str(document["authorization_endpoint"]),
            token_endpoint=str(document["token_endpoint"]),
            jwks_uri=str(document["jwks_uri"]),
        )
    except KeyError as exc:
        reason = "discovery_incomplete"
        raise SsoRejectedError(reason) from exc


async def _call(http: httpx.AsyncClient, method: str, url: str, **kwargs: Any) -> httpx.Response:
    """One request to the IdP. An unreachable IdP is a refused sign-in, not a server fault."""
    try:
        return await http.request(method, url, timeout=_HTTP_TIMEOUT, **kwargs)
    except httpx.HTTPError as exc:
        reason = "idp_unreachable"
        raise SsoRejectedError(reason) from exc


def _issuer(settings: Settings) -> str:
    if settings.oidc_member_issuer is None:
        reason = "sso_not_configured"
        raise SsoRejectedError(reason)
    return settings.oidc_member_issuer


def _derive(settings: Settings, purpose: str, state: str) -> str:
    """A per-login secret recomputable from ``state``: PKCE verifier or nonce."""
    digest = hmac.new(
        settings.session_secret.get_secret_value().encode("utf-8"),
        f"aivs-sso:{purpose}:{state}".encode(),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _pending_serializer(settings: Settings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        settings.session_secret.get_secret_value(), salt="aivs-sso-pending"
    )


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(item for item in value if isinstance(item, str))
    return ()
