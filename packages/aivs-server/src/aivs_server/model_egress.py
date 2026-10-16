"""Where a model may be reached, and what it may be sent (Phase O, Mike's Q33).

Two kinds of model, each with a fixed ceiling on the content it may receive:

- ``private_endpoint``: a model in the ISAC's own cloud account (Bedrock behind
  an OpenAI-compatible gateway, for example). Content up to AMBER+STRICT, over
  https with the certificate verified.
- ``local``: a model on the ISAC's own hardware, which may receive RED. Plain
  http only to a loopback address; any other address must be private (RFC 1918
  or ULA) and reached over https with the certificate verified -- RED in
  cleartext across a LAN is what the ceiling exists to stop. A public address
  is refused outright, however the URL is spelled.

The rules are checked twice. At startup, on the URL as written, so a wrong
configuration fails the healthcheck. And at connect time, on every address the
name resolves to, because a name can be made to resolve somewhere else after
startup (the webhook dispatcher's rule, R11).

The ceiling is the kind's. A setting may lower it, never raise it: an operator
who wants a private endpoint to receive RED has to run the model locally.
"""

from __future__ import annotations

import enum
import ipaddress
from collections.abc import Iterable
from typing import Final
from urllib.parse import urlparse

from aivs_schemas.enums import TLP, tlp_at_least_as_restrictive

__all__ = [
    "KIND_CEILING",
    "AiProvider",
    "address_problem",
    "ceiling_for",
    "url_problem",
]

Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class AiProvider(enum.StrEnum):
    NONE = "none"
    LOCAL = "local"
    PRIVATE_ENDPOINT = "private_endpoint"


#: The most a kind of model may ever be sent (Q33).
KIND_CEILING: Final[dict[AiProvider, TLP]] = {
    AiProvider.LOCAL: TLP.RED,
    AiProvider.PRIVATE_ENDPOINT: TLP.AMBER_STRICT,
}

_LOOPBACK_NAMES: Final[frozenset[str]] = frozenset({"localhost"})


def ceiling_for(kind: AiProvider, lowered_to: TLP | None) -> TLP:
    """The kind's ceiling, or a lower one the operator chose; never higher."""
    ceiling = KIND_CEILING[kind]
    if lowered_to is None:
        return ceiling
    if not tlp_at_least_as_restrictive(ceiling, lowered_to):
        msg = f"ai_tlp_ceiling {lowered_to.value} is above what a {kind.value} model may receive"
        raise ValueError(msg)
    return lowered_to


def url_problem(kind: AiProvider, url: str) -> str | None:
    """Why ``url`` may not carry content to a ``kind`` model, judged as written; or ``None``."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return "the model endpoint must be http or https"
    if not parsed.hostname:
        return "the model endpoint names no host"
    if parsed.username or parsed.password:
        return "the model endpoint carries credentials in its URL; use ai_api_key_file"
    if parsed.scheme == "https":
        return None
    if kind is AiProvider.PRIVATE_ENDPOINT:
        return "a private endpoint is reached over https only"
    if not _names_loopback(parsed.hostname):
        return "a local model is reached over plain http only at a loopback address"
    return None


def address_problem(kind: AiProvider, scheme: str, addresses: Iterable[Address]) -> str | None:
    """Why the resolved ``addresses`` may not be connected to; or ``None``.

    Every address must pass, not the first: a name resolving to one good and
    one bad address could be raced.
    """
    resolved = list(addresses)
    if not resolved:
        return "the model endpoint resolved to no address"
    for address in resolved:
        problem = _one_address_problem(kind, scheme, address)
        if problem is not None:
            return problem
    return None


def _one_address_problem(kind: AiProvider, scheme: str, address: Address) -> str | None:
    if _never_reachable(address):
        return f"the model endpoint resolved to {address}, which is never connected to"
    if kind is AiProvider.PRIVATE_ENDPOINT:
        return None
    if address.is_loopback:
        return None
    if not address.is_private:
        return f"a local model resolved to the public address {address}"
    if scheme != "https":
        return f"a local model at {address} is not loopback, so it is reached over https only"
    return None


def _never_reachable(address: Address) -> bool:
    """Link-local covers cloud metadata (169.254.169.254); the rest is never a model."""
    return (
        address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or (address.is_reserved and not address.is_private)
    )


def _names_loopback(hostname: str) -> bool:
    if hostname.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False
