"""The request body limit holds whether or not the client declares a length.

``BodySizeLimitMiddleware`` makes two checks because either alone can be
walked around: a declared ``Content-Length`` is refused before the application
runs, and the stream is counted as it is read, because a chunked request
declares nothing and a lying one declares too little. Driven as raw ASGI, so
each test sees exactly which messages reached the client and whether the
application ran at all. Each test is a pair: the refused case beside the served
one.
"""

from __future__ import annotations

import json
from collections.abc import MutableMapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import pytest

from aivs_server.middleware import ASGIApp, BodySizeLimitMiddleware, Receive, Scope, Send

LIMIT = 10


@dataclass
class Exchange:
    """What one request through the middleware produced."""

    sent: list[MutableMapping[str, Any]] = field(default_factory=list)
    app_ran: bool = False

    @property
    def statuses(self) -> list[int]:
        return [m["status"] for m in self.sent if m["type"] == "http.response.start"]


async def drive(
    app: ASGIApp, *, headers: Sequence[tuple[bytes, bytes]], chunks: Sequence[bytes]
) -> Exchange:
    exchange = Exchange()
    pending = list(chunks)

    async def receive() -> MutableMapping[str, Any]:
        body = pending.pop(0) if pending else b""
        return {"type": "http.request", "body": body, "more_body": bool(pending)}

    async def send(message: MutableMapping[str, Any]) -> None:
        exchange.sent.append(message)

    async def recording_app(scope: Scope, receive: Receive, send: Send) -> None:
        exchange.app_ran = True
        await app(scope, receive, send)

    scope = {"type": "http", "headers": list(headers)}
    await BodySizeLimitMiddleware(recording_app, LIMIT)(scope, receive, send)
    return exchange


async def _read_body(receive: Receive) -> None:
    while (await receive()).get("more_body"):
        pass


async def reads_then_responds(scope: Scope, receive: Receive, send: Send) -> None:
    await _read_body(receive)
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def responds_then_reads(scope: Scope, receive: Receive, send: Send) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await _read_body(receive)


def declared(length: bytes) -> list[tuple[bytes, bytes]]:
    return [(b"content-length", length)]


async def test_declared_length_over_limit_is_refused_before_the_application_runs() -> None:
    exchange = await drive(reads_then_responds, headers=declared(b"11"), chunks=[b"x" * 11])

    assert exchange.statuses == [413]
    assert not exchange.app_ran
    assert json.loads(exchange.sent[1]["body"]) == {
        "title": "Request body too large",
        "http_status": "413",
    }


async def test_body_of_exactly_the_limit_is_served() -> None:
    exchange = await drive(reads_then_responds, headers=declared(b"10"), chunks=[b"x" * 10])

    assert exchange.statuses == [200]


async def test_malformed_declared_length_is_refused_before_the_application_runs() -> None:
    exchange = await drive(reads_then_responds, headers=declared(b"ten"), chunks=[b""])

    assert exchange.statuses == [400]
    assert not exchange.app_ran


@pytest.mark.parametrize("length", [b"-1", b"+10", b"1_0", b" 10", b"", b"\xb2"])
async def test_declared_length_that_is_not_plain_digits_is_refused(length: bytes) -> None:
    # int() accepts the first four. The empty string was always refused. The
    # last decodes to a superscript digit that isdigit() accepts and int() does
    # not, which would escape as a 500. A declared length is 1*DIGIT or it is
    # malformed.
    exchange = await drive(reads_then_responds, headers=declared(length), chunks=[b"x"])

    assert exchange.statuses == [400]
    assert not exchange.app_ran


async def test_declared_length_of_zero_is_served() -> None:
    exchange = await drive(reads_then_responds, headers=declared(b"0"), chunks=[b""])

    assert exchange.statuses == [200]


async def test_undeclared_body_is_counted_and_refused_past_the_limit() -> None:
    exchange = await drive(reads_then_responds, headers=[], chunks=[b"x" * 6, b"x" * 5])

    assert exchange.statuses == [413]


async def test_undeclared_body_within_the_limit_is_served() -> None:
    exchange = await drive(reads_then_responds, headers=[], chunks=[b"x" * 5, b"x" * 5])

    assert exchange.statuses == [200]


async def test_body_longer_than_its_declared_length_is_refused_past_the_limit() -> None:
    exchange = await drive(reads_then_responds, headers=declared(b"3"), chunks=[b"x" * 11])

    assert exchange.statuses == [413]


async def test_no_second_response_once_the_application_has_started_one() -> None:
    # The client lied about its size after the application already answered;
    # a second http.response.start would be a protocol error, so the
    # connection is dropped instead.
    exchange = await drive(responds_then_reads, headers=[], chunks=[b"x" * 6, b"x" * 5])

    assert exchange.statuses == [200]
    assert len(exchange.sent) == 1
