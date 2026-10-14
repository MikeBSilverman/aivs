"""A local OIDC identity provider for tests, and an app wired to it. Never a network IdP.

The fake keeps what a real one would: an RSA signing key published as a JWKS,
a discovery document naming itself, an authorization step that remembers the
PKCE challenge for the code it issues, and a token endpoint that refuses a
code redeemed with the wrong verifier, or twice.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from aivs_server.config import Settings

ISSUER = "https://idp.member-tenant.test"
CLIENT_ID = "aivs-member-portal"
CLIENT_SECRET = "test-oidc-client-secret-not-a-real-secret"
REDIRECT_URI = "https://members.aivs.test/portal/sso/callback"


def sso_settings(settings: Settings) -> Settings:
    """The suite's settings with member SSO pointed at the fake IdP."""
    return settings.model_copy(
        update={
            "oidc_member_issuer": ISSUER,
            "oidc_member_client_id": CLIENT_ID,
            "oidc_member_client_secret": SecretStr(CLIENT_SECRET),
            "oidc_member_redirect_uri": REDIRECT_URI,
        }
    )


@dataclass
class FakeIdp:
    key: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    kid: str = "test-key-1"
    #: code -> (PKCE challenge, claims to put in the ID token)
    codes: dict[str, tuple[str, dict[str, Any]]] = field(default_factory=dict)
    #: Claims overridden for the next token, e.g. a wrong nonce.
    tamper: dict[str, Any] = field(default_factory=dict)
    #: Discovery-document fields overridden, e.g. an endpoint on another host.
    discovery_tamper: dict[str, Any] = field(default_factory=dict)
    #: Whole responses replaced by path, to play an IdP that is down or wrong.
    overrides: dict[str, Callable[[httpx.Request], httpx.Response]] = field(default_factory=dict)

    def authorize(self, authorize_url: str, **claims: Any) -> tuple[str, str]:
        """Play the user signing in at the IdP: returns (code, state) for the callback."""
        query = {k: v[0] for k, v in parse_qs(urlparse(authorize_url).query).items()}
        assert query["response_type"] == "code"
        assert query["code_challenge_method"] == "S256"
        assert query["client_id"] == CLIENT_ID
        assert query["redirect_uri"] == REDIRECT_URI
        code = secrets.token_urlsafe(16)
        self.codes[code] = (query["code_challenge"], {"nonce": query["nonce"], **claims})
        return code, query["state"]

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path in self.overrides:
            return self.overrides[request.url.path](request)
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=self._discovery())
        if request.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [self.jwk()]})
        if request.url.path == "/token" and request.method == "POST":
            return self._token(request)
        return httpx.Response(404)

    def _discovery(self) -> dict[str, Any]:
        return {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
            **self.discovery_tamper,
        }

    def jwk(self) -> dict[str, Any]:
        jwk: dict[str, Any] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return {**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        entry = self.codes.pop(form.get("code", ""), None)
        if entry is None or form.get("client_secret") != CLIENT_SECRET:
            return httpx.Response(400, json={"error": "invalid_grant"})
        challenge, claims = entry
        verifier = form.get("code_verifier", "")
        derived = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
        if derived.decode() != challenge:
            return httpx.Response(400, json={"error": "invalid_grant", "detail": "pkce"})
        return httpx.Response(200, json={"id_token": self.id_token(claims), "token_type": "Bearer"})

    def id_token(self, claims: dict[str, Any]) -> str:
        now = dt.datetime.now(dt.UTC)
        payload = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": f"subject-{uuid.uuid4()}",
            "iat": now,
            "exp": now + dt.timedelta(minutes=5),
            # A tenant whose sign-on policy requires a second factor says so.
            "amr": ["pwd", "mfa"],
            **claims,
            **self.tamper,
        }
        return jwt.encode(payload, self.key, algorithm="RS256", headers={"kid": self.kid})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def browser(app: Any, **cookies: str) -> AsyncClient:
    """A browser on the public listener: no client certificate, no proxy identity headers."""
    return AsyncClient(
        transport=ASGITransport(app=app, client=("127.0.0.1", 0)),
        base_url="https://members.aivs.test",
        follow_redirects=False,
        cookies=cookies,
    )
