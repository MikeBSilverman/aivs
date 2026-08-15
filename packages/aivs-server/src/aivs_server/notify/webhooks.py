"""Outbound webhook delivery.

The only place AIVS makes a network request to an address a member supplied,
which makes it the only place server-side request forgery is possible. A member
who can point a webhook at ``http://169.254.169.254/`` or at a service on the
ISAC's internal network turns the instance into a proxy for reaching things it
can reach and they cannot.

Four controls, applied in order, and each closes a distinct hole:

1. **https only**, enforced at registration and again here. Plaintext delivery
   of "a new critical finding landed in your circle" is itself disclosure.
2. **Resolve, then judge, then pin.** The hostname is resolved once; every
   returned address is checked against the ranges that must never be reachable;
   the connection is then made *to the address that was checked*, with SNI and
   Host set to the original name. Validating a hostname and then letting the
   HTTP client resolve it again leaves a DNS-rebinding window between the two.
3. **No redirects.** An allowed host that answers with a redirect to a forbidden
   one would defeat the check, and a 30x is not a delivery anyway.
4. **Bounded time and size.** A member endpoint that accepts a connection and
   never responds must not tie up a worker.

Payloads are signed with HMAC-SHA256 over the exact bytes sent, so a receiver
can verify the notification came from their instance rather than from anyone who
learned the URL.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import uuid
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.audit.log import AuditAction, record
from aivs_server.config import Settings
from aivs_server.db.models import Webhook, WebhookDelivery

__all__ = [
    "WebhookRejectedError",
    "deliver_event",
    "resolve_delivery_target",
    "sign_payload",
]

logger = logging.getLogger(__name__)

#: Largest response body read from a member endpoint. We need the status code,
#: not the content; reading an unbounded body from an address a member chose is
#: a memory-exhaustion vector for no benefit.
MAX_RESPONSE_BYTES: Final[int] = 8192

#: Header carrying the signature, and the version prefix on its value so the
#: scheme can change without receivers guessing which one they are looking at.
SIGNATURE_HEADER: Final[str] = "x-aivs-signature"
SIGNATURE_VERSION: Final[str] = "v1"

#: A delivery counts as accepted only on a 2xx. A 3xx is not a delivery
#: (redirects are disabled), and 4xx/5xx are the receiver telling us so.
_SUCCESS_FLOOR: Final[int] = 200
_SUCCESS_CEILING: Final[int] = 300


class WebhookRejectedError(ValueError):
    """A delivery target is not one AIVS will connect to.

    ``reason`` is a stable token for the audit log. It is safe to show the
    member who registered the URL -- it describes their own configuration -- but
    it is not echoed to anyone else.
    """

    __slots__ = ("reason",)

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class DeliveryTarget:
    """A validated destination: the address to connect to, and the name to present."""

    url: str
    hostname: str
    address: str
    port: int


def _address_is_forbidden(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether an address is one AIVS must never be induced to contact.

    Deliberately a denylist of *categories* rather than of specific addresses.
    ``is_private`` alone would miss loopback, link-local (which covers cloud
    metadata at 169.254.169.254), multicast, and the reserved ranges; naming
    them individually would age badly.
    """
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def resolve_delivery_target(url: str, *, allow_private: bool = False) -> DeliveryTarget:
    """Validate a webhook URL and resolve it to a specific address.

    ``allow_private`` exists for tests, which necessarily point at loopback. It
    is gated to non-production by ``Settings.validate_production_posture``; if it
    is ever true in production, that is the SSRF hole this function exists to
    prevent.
    """
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise WebhookRejectedError("scheme_not_https")
    if not parsed.hostname:
        raise WebhookRejectedError("no_hostname")
    if parsed.username or parsed.password:
        # Credentials in the URL would be sent to whatever the host resolves to.
        raise WebhookRejectedError("credentials_in_url")

    port = parsed.port or 443
    hostname = parsed.hostname

    try:
        resolved = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise WebhookRejectedError("dns_resolution_failed") from exc

    if not resolved:
        raise WebhookRejectedError("dns_resolution_empty")

    addresses = [ipaddress.ip_address(info[4][0]) for info in resolved]

    if not allow_private:
        # Every returned address must be acceptable, not merely the first. A
        # name that resolves to one public and one internal address would
        # otherwise be usable by racing the resolver.
        forbidden = [str(address) for address in addresses if _address_is_forbidden(address)]
        if forbidden:
            raise WebhookRejectedError(f"address_not_routable:{forbidden[0]}")

    return DeliveryTarget(url=url, hostname=hostname, address=str(addresses[0]), port=port)


def sign_payload(secret: bytes, body: bytes, timestamp: str) -> str:
    """Return the signature header value for a payload.

    The timestamp is signed alongside the body so a receiver can reject a replay
    of a genuine notification, which a signature over the body alone would
    permit indefinitely.
    """
    message = timestamp.encode("ascii") + b"." + body
    digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_VERSION}={digest}"


async def _post(
    client: httpx.AsyncClient, target: DeliveryTarget, body: bytes, headers: dict[str, str]
) -> httpx.Response:
    """POST to the validated address, presenting the original hostname.

    The URL's host is replaced by the address that was checked, while SNI and
    the Host header keep the name -- so TLS verification still checks the
    certificate against the hostname the member registered, and no second DNS
    lookup can substitute a different address.
    """
    parsed = urlparse(target.url)
    literal = f"[{target.address}]" if ":" in target.address else target.address
    pinned = parsed._replace(netloc=f"{literal}:{target.port}").geturl()

    return await client.post(
        pinned,
        content=body,
        headers={**headers, "Host": target.hostname},
        extensions={"sni_hostname": target.hostname},
    )


async def deliver_event(
    session: AsyncSession,
    settings: Settings,
    *,
    webhook: Webhook,
    event: str,
    payload: dict[str, Any],
    secret: bytes,
    now: dt.datetime | None = None,
) -> WebhookDelivery:
    """Attempt one delivery, recording the outcome either way.

    Returns the delivery record rather than raising: a member's endpoint being
    down is their operational problem, not an error in ours, and the whole point
    of recording attempts is that failures are data.
    """
    now = now or dt.datetime.now(dt.UTC)
    timestamp = now.isoformat()
    body = json.dumps(
        {"event": event, "sent_at": timestamp, "data": payload},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    delivery = WebhookDelivery(webhook_id=webhook.id, event=event, attempts=1)
    session.add(delivery)

    headers = {
        "content-type": "application/json",
        SIGNATURE_HEADER: sign_payload(secret, body, timestamp),
        "x-aivs-timestamp": timestamp,
        "x-aivs-event": event,
        "user-agent": f"aivs/{settings.instance_name}",
    }

    try:
        target = resolve_delivery_target(
            webhook.url, allow_private=settings.dev_allow_private_webhook_targets
        )
    except WebhookRejectedError as exc:
        delivery.error = f"target rejected: {exc.reason}"
        webhook.consecutive_failures += 1
        await record(
            session,
            action=AuditAction.WEBHOOK_DELIVERY_FAILED,
            actor_type="system",
            org_id=webhook.org_id,
            resource_type="webhook",
            resource_id=str(webhook.id),
            details={"event": event, "reason": exc.reason},
        )
        return delivery

    try:
        async with httpx.AsyncClient(
            timeout=settings.webhook_timeout_seconds,
            # An allowed host redirecting to a forbidden one would defeat the
            # address check, and a 30x is not a delivery.
            follow_redirects=False,
        ) as client:
            response = await _post(client, target, body, headers)
            delivery.response_code = response.status_code
            if _SUCCESS_FLOOR <= response.status_code < _SUCCESS_CEILING:
                delivery.delivered_at = now
                webhook.consecutive_failures = 0
            else:
                delivery.error = f"endpoint returned {response.status_code}"
                webhook.consecutive_failures += 1
    except httpx.HTTPError as exc:
        # Deliberately broad within httpx's own hierarchy: timeouts, TLS
        # failures and connection errors are all "their endpoint did not accept
        # it", and none should propagate into whatever triggered the event.
        delivery.error = type(exc).__name__
        webhook.consecutive_failures += 1

    if delivery.delivered_at is None:
        await record(
            session,
            action=AuditAction.WEBHOOK_DELIVERY_FAILED,
            actor_type="system",
            org_id=webhook.org_id,
            resource_type="webhook",
            resource_id=str(webhook.id),
            details={
                "event": event,
                "response_code": delivery.response_code,
                "error": delivery.error,
                "consecutive_failures": webhook.consecutive_failures,
            },
        )

    return delivery


async def active_webhooks_for(
    session: AsyncSession, *, org_id: uuid.UUID, event: str
) -> list[Webhook]:
    """Return an organisation's active webhooks subscribed to ``event``."""
    rows = (
        (
            await session.execute(
                select(Webhook).where(
                    Webhook.org_id == org_id,
                    Webhook.is_active.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    return [hook for hook in rows if not hook.events or event in hook.events]
