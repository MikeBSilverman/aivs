"""Where a model may be reached, checked at startup and again at every connect (SF-97).

Mike's Q33 and main's refinement: a private endpoint over https only; a local
model over plain http only at loopback, over https with the certificate
verified anywhere else on the ISAC's own network, and never at a public
address. Each rule is tested as written in the settings and as resolved at
connect time, because a name can be re-pointed after startup.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from aivs_schemas.enums import TLP
from aivs_server.model_egress import AiProvider, address_problem, ceiling_for, url_problem
from aivs_server.services import model_provider
from aivs_server.services.model_provider import (
    ModelCallError,
    OpenAICompatibleEndpoint,
    provider_from_settings,
)
from tests.unit.test_smtp_settings import _settings

pytestmark = pytest.mark.requirement("SF-97")

LOCAL, PRIVATE = AiProvider.LOCAL, AiProvider.PRIVATE_ENDPOINT


def ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(text)


# ---------------------------------------------------------------------------
# The URL as written
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("kind", "url", "allowed"),
    [
        (PRIVATE, "https://models.isac.example/v1", True),
        (PRIVATE, "http://models.isac.example/v1", False),
        (PRIVATE, "http://127.0.0.1:8080/v1", False),
        (LOCAL, "http://127.0.0.1:8080/v1", True),
        (LOCAL, "http://localhost:8080/v1", True),
        (LOCAL, "http://[::1]:8080/v1", True),
        (LOCAL, "http://10.0.0.5:8080/v1", False),
        (LOCAL, "http://gpu.isac.internal/v1", False),
        (LOCAL, "https://10.0.0.5/v1", True),
        (LOCAL, "https://gpu.isac.internal/v1", True),
        (LOCAL, "https://user:pass@gpu.isac.internal/v1", False),
        (PRIVATE, "ftp://models.isac.example/", False),
    ],
)
def test_a_url_carries_content_only_as_its_kind_allows(kind, url, allowed):
    assert (url_problem(kind, url) is None) is allowed


# ---------------------------------------------------------------------------
# The addresses it resolves to
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("kind", "scheme", "addresses", "allowed"),
    [
        (LOCAL, "http", ["127.0.0.1"], True),
        (LOCAL, "http", ["::1"], True),
        (LOCAL, "http", ["10.0.0.5"], False),
        (LOCAL, "https", ["10.0.0.5"], True),
        (LOCAL, "https", ["192.168.1.20"], True),
        (LOCAL, "https", ["fd00::5"], True),
        (LOCAL, "https", ["8.8.8.8"], False),
        (LOCAL, "https", ["2001:4860:4860::8888"], False),
        (LOCAL, "https", ["10.0.0.5", "8.8.8.8"], False),
        (LOCAL, "https", ["169.254.169.254"], False),
        (PRIVATE, "https", ["8.8.8.8"], True),
        (PRIVATE, "https", ["10.0.0.5"], True),
        (PRIVATE, "https", ["169.254.169.254"], False),
        (PRIVATE, "https", [], False),
    ],
    ids=str,
)
def test_every_resolved_address_is_judged(kind, scheme, addresses, allowed):
    """Every address, not the first: a name resolving to one good and one bad
    address could otherwise be raced."""
    assert (address_problem(kind, scheme, [ip(a) for a in addresses]) is None) is allowed


# ---------------------------------------------------------------------------
# The ceiling
# ---------------------------------------------------------------------------
def test_each_kind_has_its_ceiling_and_a_setting_may_only_lower_it():
    assert ceiling_for(PRIVATE, None) is TLP.AMBER_STRICT
    assert ceiling_for(LOCAL, None) is TLP.RED
    assert ceiling_for(LOCAL, TLP.AMBER) is TLP.AMBER
    with pytest.raises(ValueError, match="above what a private_endpoint"):
        ceiling_for(PRIVATE, TLP.RED)


# ---------------------------------------------------------------------------
# The settings
# ---------------------------------------------------------------------------
def test_with_no_provider_nothing_is_built():
    assert provider_from_settings(_settings()) is None
    assert provider_from_settings(_settings(ai_endpoint_url="", ai_model_id="")) is None


def test_a_provider_needs_its_endpoint_and_model():
    with pytest.raises(ValidationError, match="needs ai_endpoint_url and ai_model_id"):
        _settings(ai_provider="local")


@pytest.mark.parametrize(
    ("provider", "url", "reason"),
    [
        (
            "private_endpoint",
            "http://models.isac.example/v1",
            "a private endpoint is reached over https only",
        ),
        (
            "local",
            "http://10.0.0.5/v1",
            "a local model is reached over plain http only at a loopback",
        ),
    ],
    ids=["private-endpoint", "local"],
)
def test_a_url_its_kind_may_not_use_refuses_to_start(provider, url, reason):
    """Each refused by its own rule: the reason is asserted, not only the refusal."""
    with pytest.raises(ValidationError, match=reason):
        _settings(ai_provider=provider, ai_endpoint_url=url, ai_model_id="m")
    https = url.replace("http://", "https://")
    assert _settings(ai_provider=provider, ai_endpoint_url=https, ai_model_id="m")


def test_a_ceiling_above_the_kinds_refuses_to_start():
    with pytest.raises(ValidationError, match="above what a private_endpoint"):
        _settings(
            ai_provider="private_endpoint",
            ai_endpoint_url="https://models.isac.example/v1",
            ai_model_id="m",
            ai_tlp_ceiling="red",
        )


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    path = tmp_path / "ai-key"
    path.write_text("model-key-for-tests-only", encoding="utf-8")
    path.chmod(0o600)
    return path


def test_outside_dev_the_key_comes_from_a_file(key_file: Path):
    named = {
        "ai_provider": "private_endpoint",
        "ai_endpoint_url": "https://models.isac.example/v1",
        "ai_model_id": "m",
    }
    with pytest.raises(ValidationError, match="ai_api_key_file"):
        _settings(**named, ai_api_key="model-key-for-tests-only")
    provider = provider_from_settings(_settings(**named, ai_api_key_file=key_file))
    assert provider is not None
    assert provider.ceiling is TLP.AMBER_STRICT


# ---------------------------------------------------------------------------
# At connect time
# ---------------------------------------------------------------------------
def endpoint(kind: AiProvider, url: str) -> OpenAICompatibleEndpoint:
    return OpenAICompatibleEndpoint(
        kind=kind,
        url=url,
        model_id="m",
        ceiling=ceiling_for(kind, None),
        api_key=None,
        ca_file=None,
        timeout_seconds=5,
    )


def resolves_to(monkeypatch, address: str) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET

    def _resolve(_host: str, port: int, **_kwargs: Any) -> list[Any]:
        return [(family, socket.SOCK_STREAM, 6, "", (address, port))]

    monkeypatch.setattr(model_provider.socket, "getaddrinfo", _resolve)


def no_connection(monkeypatch) -> None:
    def _refuse(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("a connection was opened to an address the rules refuse")

    monkeypatch.setattr(model_provider.httpx, "AsyncClient", _refuse)


@pytest.mark.parametrize(
    ("kind", "url", "address"),
    [
        (LOCAL, "https://gpu.isac.internal/v1", "8.8.8.8"),
        (LOCAL, "http://localhost:8080/v1", "10.0.0.5"),
        (PRIVATE, "https://models.isac.example/v1", "169.254.169.254"),
    ],
    ids=["local-name-rebound-public", "loopback-name-rebound-to-lan-over-http", "metadata"],
)
async def test_a_name_resolving_somewhere_refused_is_never_connected_to(
    monkeypatch, kind, url, address
):
    """The URL passed at startup; the name now resolves elsewhere."""
    assert url_problem(kind, url) is None
    resolves_to(monkeypatch, address)
    no_connection(monkeypatch)

    with pytest.raises(ModelCallError, match="address_refused"):
        await endpoint(kind, url).complete("system", "user")


def answering(monkeypatch, handler) -> list[httpx.Request]:
    sent: list[httpx.Request] = []
    real = httpx.AsyncClient

    def _client(**kwargs: Any) -> httpx.AsyncClient:
        def _record(request: httpx.Request) -> httpx.Response:
            sent.append(request)
            return handler(request)

        kwargs.pop("verify", None)
        return real(transport=httpx.MockTransport(_record), **kwargs)

    monkeypatch.setattr(model_provider.httpx, "AsyncClient", _client)
    return sent


async def test_the_connection_goes_to_the_checked_address_with_the_name_kept(monkeypatch):
    resolves_to(monkeypatch, "10.0.0.5")
    sent = answering(
        monkeypatch,
        lambda _r: httpx.Response(
            200, json={"model": "m-1", "choices": [{"message": {"content": "{}"}}]}
        ),
    )

    reply = await endpoint(LOCAL, "https://gpu.isac.internal/v1").complete("system", "user")

    [request] = sent
    assert request.url.host == "10.0.0.5"
    assert request.headers["host"] == "gpu.isac.internal"
    assert request.extensions["sni_hostname"] == "gpu.isac.internal"
    assert json.loads(request.content)["temperature"] == 0
    assert (reply.text, reply.model_reported) == ("{}", "m-1")


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, json={}),
        httpx.Response(302, headers={"location": "https://elsewhere.example/"}),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(200, json={"choices": [{"message": {"content": 7}}]}),
        httpx.Response(200, content=b"x" * (model_provider.MAX_REPLY_BYTES + 1)),
    ],
    ids=["error", "redirect", "not-json", "no-choice", "not-text", "too-large"],
)
async def test_anything_but_a_chat_completion_is_no_reply(monkeypatch, response):
    resolves_to(monkeypatch, "127.0.0.1")
    answering(monkeypatch, lambda _r: response)

    with pytest.raises(ModelCallError):
        await endpoint(LOCAL, "http://127.0.0.1:8080/v1").complete("system", "user")
