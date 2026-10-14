"""ASGI middleware: request correlation, body limits, and security headers.

These are written as raw ASGI middleware rather than Starlette's
``BaseHTTPMiddleware``. That base class buffers the request through an anyio
task pair, which both defeats the point of a streaming body-size limit and has a
history of subtle interactions with background tasks and exception propagation.
At this layer the raw interface is the simpler thing to reason about, and this
layer is one a reviewer will read closely.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, Final

from aivs_server.auth.mtls import client_address, is_vouched_for_by_proxy
from aivs_server.config import Settings
from aivs_server.logging_config import set_request_id

__all__ = [
    "PORTAL_PATH_PREFIX",
    "BodySizeLimitMiddleware",
    "RequestContextMiddleware",
    "SecurityHeadersMiddleware",
    "security_headers_for",
]

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

#: Applied to every response. Rationale per header:
#:
#: - ``nosniff``      : the API returns JSON; never let a browser re-interpret it.
#: - ``DENY``         : nothing in AIVS is meant to be framed.
#: - ``no-referrer``  : submission URLs contain identifiers; do not leak them.
#: - HSTS            : the service is https-only on every deployment.
#: - ``Permissions-Policy``: the portal needs no device capability at all.
#:
#: **``preload`` is deliberately absent.** Submitting a domain to the browser
#: preload list is effectively irreversible, and it is the hosting ISAC's
#: decision about their own domain, not ours to make on their behalf by shipping
#: a default. ``deploy/nginx`` declines it for the same reason; this must not
#: reintroduce it, because when both layers emit HSTS a user agent honours the
#: first header it sees (RFC 6797 section 8.1) -- which is this one.
_BASE_SECURITY_HEADERS: Final[tuple[tuple[bytes, bytes], ...]] = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
    (b"permissions-policy", b"accelerometer=(), camera=(), geolocation=(), microphone=(), usb=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
)

#: API and TAXII responses are machine-consumed and carry embargoed content.
#: ``default-src 'none'`` means a browser tricked into rendering one can load
#: nothing; ``no-store`` keeps intermediaries and disk caches out of it.
_API_CSP: Final[bytes] = b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

#: The portal serves its own CSS and a single vendored htmx bundle, both
#: same-origin. No inline script, no CDN, no eval -- the portal is deliberately
#: boring so this policy can stay this tight.
_PORTAL_CSP: Final[bytes] = (
    b"default-src 'none'; "
    b"script-src 'self'; "
    b"style-src 'self'; "
    b"img-src 'self' data:; "
    b"font-src 'self'; "
    b"connect-src 'self'; "
    b"form-action 'self'; "
    b"frame-ancestors 'none'; "
    b"base-uri 'none'"
)


#: One structured line per request. Uvicorn's own access log is turned off in
#: favour of this one, which carries the correlation id and nothing else uvicorn
#: would add -- in particular not the query string, whose TAXII filters name
#: what a member was looking for.
_access_logger = logging.getLogger("aivs_server.access")


def _headers_and_peer(scope: Scope) -> tuple[dict[str, str], str | None]:
    peer = scope.get("client")
    headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in scope.get("headers", [])
    }
    return headers, peer[0] if peer else None


def _client(scope: Scope, settings: Settings) -> str | None:
    """The member's address when the proxy vouches for it, as on audit rows."""
    headers, peer = _headers_and_peer(scope)
    return client_address(settings, headers, peer)


def _vouched_request_id(scope: Scope, settings: Settings, header_name: bytes) -> str | None:
    """The proxy's request id, or ``None`` when the proxy did not send this request.

    nginx overwrites the header so a caller cannot choose the id an audit row
    carries; a request that reaches the app without the proxy's credential
    could otherwise choose it here.
    """
    headers, peer = _headers_and_peer(scope)
    if not is_vouched_for_by_proxy(settings, headers, peer):
        return None
    return _header_value(scope, header_name)


def _log_access(scope: Scope, settings: Settings, status_code: int, started: float) -> None:
    _access_logger.info(
        "request",
        extra={
            "method": scope.get("method"),
            "path": scope.get("path"),
            "status": status_code,
            "duration_ms": round((time.monotonic() - started) * 1000, 1),
            "client": _client(scope, settings),
        },
    )


class RequestContextMiddleware:
    """Assign every request a correlation id and expose the client address.

    The id is taken from the proxy's ``X-Request-Id`` when present so that a
    trace spans the proxy and the application, and generated otherwise. It is
    echoed on the response, which is what lets a member firm quote an id when
    reporting a problem.
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings
        self._header_name = settings.header_request_id.encode("ascii")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = _vouched_request_id(scope, self.settings, self._header_name)
        # An inbound id is echoed for correlation but never trusted as
        # structure: it lands in logs, so bound its length and character set.
        request_id = _sanitise_request_id(incoming) or uuid.uuid4().hex

        scope["aivs_request_id"] = request_id
        set_request_id(request_id)

        # 500 unless a response says otherwise: an exception that escapes the
        # application is logged as the failure it is, not skipped.
        status_code = 500
        started = time.monotonic()

        async def send_with_request_id(message: MutableMapping[str, Any]) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                headers.append((self._header_name, request_id.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            _log_access(scope, self.settings, status_code, started)


class _BodyTooLargeError(Exception):
    """Raised internally when a request body exceeds the configured limit."""


class BodySizeLimitMiddleware:
    """Reject request bodies larger than the configured maximum.

    Two checks, because either alone is insufficient:

    * ``Content-Length`` is inspected up front, so an oversized declared body is
      refused before a single byte is read.
    * the stream is then counted as it is consumed, because a chunked request
      carries no ``Content-Length`` at all and would otherwise bypass the first
      check entirely.

    The proxy enforces its own ``client_max_body_size``. This is not redundant:
    the application must be safe when deployed behind someone else's proxy, or
    when a future misconfiguration relaxes that setting.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = _header_value(scope, b"content-length")
        refusal = _declared_length_refusal(declared, self.max_bytes)
        if refusal is not None:
            await _send_json_error(send, *refusal)
            return

        counting_receive = _CountingReceive(receive, self.max_bytes)
        tracking_send = _StartTrackingSend(send)
        try:
            await self.app(scope, counting_receive, tracking_send)
        except _BodyTooLargeError:
            # Only safe to write a response if the application had not already
            # begun one; otherwise the connection is simply dropped, which is
            # the correct outcome for a client that lied about its body size.
            if not tracking_send.response_started:
                await _send_json_error(send, 413, "Request body too large")


def _declared_length_refusal(declared: str | None, max_bytes: int) -> tuple[int, str] | None:
    """The status and message refusing a declared ``Content-Length``, or ``None``.

    ``None`` means "not refused here", which includes a request that declares no
    length at all: the streamed count still applies to it.

    A declared length is ASCII digits and nothing else (RFC 9110 section 8.6).
    This used to be "whatever ``int()`` accepts", which let ``-1``, ``+10`` and
    ``1_0`` through -- harmless only because the stream count still bounded
    them, and the shape of a check that is right by accident.
    """
    if declared is None:
        return None
    if not (declared.isascii() and declared.isdigit()):
        return 400, "Malformed Content-Length header"
    declared_bytes = int(declared)
    if declared_bytes > max_bytes:
        return 413, "Request body too large"
    return None


class _CountingReceive:
    """Wraps ``receive``, raising once the body consumed exceeds the limit."""

    def __init__(self, receive: Receive, max_bytes: int) -> None:
        self._receive = receive
        self._max_bytes = max_bytes
        self._received = 0

    async def __call__(self) -> MutableMapping[str, Any]:
        message = await self._receive()
        if message["type"] == "http.request":
            self._received += len(message.get("body", b""))
            if self._received > self._max_bytes:
                raise _BodyTooLargeError
        return message


class _StartTrackingSend:
    """Wraps ``send``, recording whether a response has begun."""

    def __init__(self, send: Send) -> None:
        self._send = send
        self.response_started = False

    async def __call__(self, message: MutableMapping[str, Any]) -> None:
        if message["type"] == "http.response.start":
            self.response_started = True
        await self._send(message)


#: Where the portal is mounted. Shared so that anything reproducing this
#: middleware's header set outside the ASGI stack picks the same policy.
PORTAL_PATH_PREFIX: Final[str] = "/portal"


def security_headers_for(path: str) -> list[tuple[bytes, bytes]]:
    """The complete security header set a response on ``path`` must carry.

    Exists because one response class never reaches
    :class:`SecurityHeadersMiddleware`: Starlette installs the ``Exception``
    handler in ``ServerErrorMiddleware``, which sits *outside* the user
    middleware stack and writes to the server's own ``send``. So an unhandled
    exception -- a pool timeout, a driver error -- produced the one response a
    member is most likely to report, carrying none of these headers.

    Handlers that do traverse the middleware may apply these too: the middleware
    only fills in names that are absent, so doing both is idempotent.
    """
    csp = _PORTAL_CSP if path.startswith(PORTAL_PATH_PREFIX) else _API_CSP
    return [
        *_BASE_SECURITY_HEADERS,
        (b"content-security-policy", csp),
        (b"cache-control", b"no-store, max-age=0"),
    ]


class SecurityHeadersMiddleware:
    """Attach security headers to every response.

    The Content-Security-Policy differs by path: the portal renders HTML and
    needs same-origin styles and scripts, while the API and TAXII surfaces get
    ``default-src 'none'``. Applying the portal's looser policy everywhere would
    weaken the machine-facing endpoints for no benefit.
    """

    def __init__(self, app: ASGIApp, portal_path_prefix: str = PORTAL_PATH_PREFIX) -> None:
        self.app = app
        self.portal_path_prefix = portal_path_prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        is_portal = scope.get("path", "").startswith(self.portal_path_prefix)
        csp = _PORTAL_CSP if is_portal else _API_CSP

        async def send_with_headers(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                for name, value in _BASE_SECURITY_HEADERS:
                    if name not in present:
                        headers.append((name, value))
                if b"content-security-policy" not in present:
                    headers.append((b"content-security-policy", csp))
                if b"cache-control" not in present:
                    # Responses carry embargoed intelligence. Nothing in AIVS is
                    # cacheable by default; endpoints that genuinely are say so
                    # for themselves.
                    headers.append((b"cache-control", b"no-store, max-age=0"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _header_value(scope: Scope, name: bytes) -> str | None:
    """Return a request header's value, or ``None``."""
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return bytes(value).decode("latin-1")
    return None


def _sanitise_request_id(value: str | None) -> str | None:
    """Return a request id safe to log and echo, or ``None``.

    A proxy-supplied correlation id is attacker-influenced in the general case.
    Restricting it to a short alphanumeric token means it cannot forge log
    structure, inject terminal escapes, or bloat a log line.
    """
    if not value:
        return None
    candidate = value.strip()[:64]
    if not candidate:
        return None
    if not all(char.isalnum() or char in "-_" for char in candidate):
        return None
    return candidate


async def _send_json_error(send: Send, status: int, message: str) -> None:
    """Emit a minimal JSON error response from middleware.

    Uses the TAXII error media type, which is a superset-compatible JSON body
    for the native API too, so a client never has to branch on which surface
    rejected it.
    """
    body = json.dumps({"title": message, "http_status": str(status)}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/taxii+json;version=2.1"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store, max-age=0"),
                (b"x-content-type-options", b"nosniff"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
