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

This module owns *what is safe to connect to* and *how a payload is signed*, and
nothing else. The delivery loop -- queueing, retries, backoff, recording
outcomes -- lives in :mod:`aivs_server.notify.dispatcher`, and what a
notification is allowed to say lives in :mod:`aivs_server.notify.events`. The
split matters because these checks are the security-critical part and should be
readable without the scheduling around them.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlparse

__all__ = [
    "WebhookRejectedError",
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
