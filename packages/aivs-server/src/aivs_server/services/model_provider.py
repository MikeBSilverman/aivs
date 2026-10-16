"""The model behind the model-assisted checks, as one interface (Phase O, slice 4).

``ModelProvider`` is what ``services.model_triage`` calls: a ceiling, the names
it records, and one call that takes the prompt and returns the model's text.
Tests use a stub that implements it, as the email intake's tests use a fake
mailbox; no test reaches a real model.

The one implementation speaks OpenAI-compatible chat completions over httpx,
which local servers (vLLM, llama.cpp, Ollama) and a gateway in front of a cloud
account's model both offer. It makes no other request and follows no redirect.
Each call resolves the endpoint's name, checks every address it resolves to
against ``model_egress`` (a name re-pointed after startup is caught here), and
connects to the address it checked, with the original name for TLS and Host.

What the model returns is untrusted text. This module returns it as text; it is
``services.model_triage`` that decides whether it means anything.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol
from urllib.parse import urlparse

import httpx

from aivs_schemas.enums import TLP
from aivs_server.config import Settings
from aivs_server.model_egress import AiProvider, address_problem, ceiling_for

__all__ = [
    "ModelCallError",
    "ModelProvider",
    "ModelReply",
    "OpenAICompatibleEndpoint",
    "provider_from_settings",
]

#: Largest reply read. The answer is a short JSON document; anything larger is
#: not one, and reading it unbounded is a memory-exhaustion vector.
MAX_REPLY_BYTES: Final[int] = 65_536

#: Why a call produced no reply, as the record names it. Never content.
DNS_FAILED: Final[str] = "dns_resolution_failed"
REPLY_TOO_LARGE: Final[str] = "reply_too_large"
NOT_A_CHAT_COMPLETION: Final[str] = "reply_not_chat_completion"


class ModelCallError(RuntimeError):
    """The call did not produce a reply: refused, unreachable, timed out, or malformed.

    ``reason`` is a stable token for the record; it never carries content.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ModelReply:
    #: The model's message, untrusted.
    text: str
    #: The model the endpoint says answered, when it says.
    model_reported: str | None


class ModelProvider(Protocol):
    kind: AiProvider
    model_id: str
    #: The most restrictive TLP this provider may be sent.
    ceiling: TLP

    async def complete(self, system: str, user: str) -> ModelReply: ...


@dataclass(frozen=True, slots=True)
class _Target:
    pinned_url: str
    hostname: str


class OpenAICompatibleEndpoint:
    """A chat-completions endpoint, reached only at an address ``model_egress`` allows."""

    def __init__(
        self,
        *,
        kind: AiProvider,
        url: str,
        model_id: str,
        ceiling: TLP,
        api_key: str | None,
        ca_file: Path | None,
        timeout_seconds: float,
    ) -> None:
        self.kind = kind
        self.model_id = model_id
        self.ceiling = ceiling
        self._url = url.rstrip("/") + "/chat/completions"
        self._api_key = api_key
        self._ca_file = ca_file
        self._timeout = timeout_seconds

    async def complete(self, system: str, user: str) -> ModelReply:
        target = await asyncio.to_thread(self._resolve)
        body = {
            "model": self.model_id,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        raw = await self._post(target, body)
        return _reply_of(raw)

    def _resolve(self) -> _Target:
        """Resolve, judge every address, and pin the one connected to (R11)."""
        parsed = urlparse(self._url)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            resolved = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise ModelCallError(DNS_FAILED) from exc
        addresses = [ipaddress.ip_address(info[4][0]) for info in resolved]
        problem = address_problem(self.kind, parsed.scheme, addresses)
        if problem is not None:
            reason = f"address_refused: {problem}"
            raise ModelCallError(reason)
        first = addresses[0]
        literal = f"[{first}]" if isinstance(first, ipaddress.IPv6Address) else str(first)
        pinned = self._url.replace(f"//{parsed.netloc}", f"//{literal}:{port}", 1)
        return _Target(pinned_url=pinned, hostname=hostname)

    async def _post(self, target: _Target, body: dict[str, Any]) -> bytes:
        headers = {"content-type": "application/json", "Host": target.hostname}
        if self._api_key is not None:
            headers["authorization"] = f"Bearer {self._api_key}"
        try:
            async with (
                httpx.AsyncClient(
                    verify=self._tls(), timeout=self._timeout, follow_redirects=False
                ) as client,
                client.stream(
                    "POST",
                    target.pinned_url,
                    content=json.dumps(body),
                    headers=headers,
                    extensions={"sni_hostname": target.hostname},
                ) as response,
            ):
                if response.status_code != httpx.codes.OK:
                    reason = f"endpoint_returned_{response.status_code}"
                    raise ModelCallError(reason)
                return await _bounded(response)
        except httpx.HTTPError as exc:
            raise ModelCallError(type(exc).__name__) from exc

    def _tls(self) -> ssl.SSLContext:
        """Built explicitly, so a CA file and verification cannot cancel out (CLAUDE.md §5)."""
        context = ssl.create_default_context(
            cafile=str(self._ca_file) if self._ca_file is not None else None
        )
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context


async def _bounded(response: httpx.Response) -> bytes:
    received = bytearray()
    async for chunk in response.aiter_bytes():
        received.extend(chunk)
        if len(received) > MAX_REPLY_BYTES:
            raise ModelCallError(REPLY_TOO_LARGE)
    return bytes(received)


def _reply_of(raw: bytes) -> ModelReply:
    """The message text from a chat-completions reply, or ``ModelCallError``."""
    try:
        parsed = json.loads(raw)
        text = parsed["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise ModelCallError(NOT_A_CHAT_COMPLETION) from exc
    if not isinstance(text, str):
        raise ModelCallError(NOT_A_CHAT_COMPLETION)
    reported = parsed.get("model")
    return ModelReply(text=text, model_reported=reported if isinstance(reported, str) else None)


def provider_from_settings(settings: Settings) -> ModelProvider | None:
    """The configured model, or ``None`` when none is: then nothing is built or sent."""
    if settings.ai_provider is AiProvider.NONE:
        return None
    if settings.ai_endpoint_url is None or settings.ai_model_id is None:
        return None
    return OpenAICompatibleEndpoint(
        kind=settings.ai_provider,
        url=settings.ai_endpoint_url,
        model_id=settings.ai_model_id,
        ceiling=ceiling_for(settings.ai_provider, settings.ai_tlp_ceiling),
        api_key=settings.ai_api_key.get_secret_value() if settings.ai_api_key else None,
        ca_file=settings.ai_ca_file,
        timeout_seconds=settings.ai_timeout_seconds,
    )
