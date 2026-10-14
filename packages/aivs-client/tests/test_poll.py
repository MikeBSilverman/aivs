"""Polling cursors: a member's collector must neither re-ingest nor skip.

``_poll_collection`` is driven against a stand-in TAXII server
(``httpx.MockTransport``) and a real :class:`CursorStore` on disk. Each property
has its pair: the cursor that should move, and the one that should not.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from aivs_client.cli import _poll_collection
from aivs_client.state import CursorStore
from aivs_client.transport import AivsError, TaxiiClient

BASE = "https://aivs.test"
COLLECTION = "c-advisories"
STORED = "2026-10-01T00:00:00.000Z"
SINCE = "2026-09-01T00:00:00.000Z"
LATEST = "2026-10-02T00:00:00.000Z"

OBJECTS = (
    {"type": "vulnerability", "id": "vulnerability--00000000-0000-4000-8000-000000000001"},
    {"type": "vulnerability", "id": "vulnerability--00000000-0000-4000-8000-000000000002"},
)


def page(
    *objects: dict[str, str], last: str | None = None, next_cursor: str | None = None
) -> httpx.Response:
    body: dict[str, object] = {"objects": list(objects), "more": next_cursor is not None}
    if next_cursor:
        body["next"] = next_cursor
    headers = {"X-TAXII-Date-Added-Last": last} if last else {}
    return httpx.Response(200, json=body, headers=headers)


class StandInServer:
    """Serves the given responses in order and records each request."""

    def __init__(self, *responses: httpx.Response) -> None:
        self._responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._responses.pop(0)

    def client(self) -> TaxiiClient:
        return TaxiiClient(httpx.Client(transport=httpx.MockTransport(self), base_url=BASE))

    def added_after(self, index: int = 0) -> str | None:
        return self.requests[index].url.params.get("added_after")


@pytest.fixture
def cursors(tmp_path) -> CursorStore:
    return CursorStore(tmp_path, BASE)


def poll(server: StandInServer, cursors: CursorStore, *, since=None, full=False) -> int:
    return _poll_collection(server.client(), cursors, COLLECTION, since=since, full=full)


# ---------------------------------------------------------------------------
# The cursor advances, and only after the objects are out
# ---------------------------------------------------------------------------
def test_the_cursor_advances_to_the_last_date_added_after_emitting(cursors, capsys):
    server = StandInServer(page(*OBJECTS, last=LATEST))

    count = poll(server, cursors)

    emitted = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert count == 2
    assert [obj["id"] for obj in emitted] == [obj["id"] for obj in OBJECTS]
    assert cursors.get(COLLECTION) == LATEST


def test_a_failure_while_emitting_leaves_the_cursor_where_it_was(cursors, monkeypatch):
    """A broken pipe part-way through means the next run re-collects, not skips."""
    cursors.set(COLLECTION, STORED)
    monkeypatch.setattr("typer.echo", _fails_on_call(2))
    server = StandInServer(page(*OBJECTS, last=LATEST))

    with pytest.raises(BrokenPipeError):
        poll(server, cursors)

    assert cursors.get(COLLECTION) == STORED


def test_a_failure_fetching_a_later_page_leaves_the_cursor_where_it_was(cursors):
    cursors.set(COLLECTION, STORED)
    server = StandInServer(
        page(OBJECTS[0], next_cursor="page-2"),
        httpx.Response(503, json={"title": "unavailable"}),
    )

    with pytest.raises(AivsError):
        poll(server, cursors)

    assert cursors.get(COLLECTION) == STORED


def _fails_on_call(failing_call: int) -> Callable[..., None]:
    calls = 0

    def echo(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == failing_call:
            raise BrokenPipeError

    return echo


# ---------------------------------------------------------------------------
# Where a run starts
# ---------------------------------------------------------------------------
def test_without_flags_the_stored_cursor_is_the_starting_point(cursors):
    cursors.set(COLLECTION, STORED)
    server = StandInServer(page(last=None))

    poll(server, cursors)

    assert server.added_after() == STORED


def test_full_ignores_the_stored_cursor(cursors):
    cursors.set(COLLECTION, STORED)
    server = StandInServer(page(*OBJECTS, last=LATEST))

    poll(server, cursors, full=True)

    assert server.added_after() is None


def test_full_does_not_advance_the_cursor(cursors):
    cursors.set(COLLECTION, STORED)
    server = StandInServer(page(*OBJECTS, last=LATEST))

    poll(server, cursors, full=True)

    assert cursors.get(COLLECTION) == STORED


def test_since_overrides_the_stored_cursor(cursors):
    cursors.set(COLLECTION, STORED)
    server = StandInServer(page(last=None))

    poll(server, cursors, since=SINCE)

    assert server.added_after() == SINCE


def test_since_is_never_written_as_the_cursor(cursors):
    """Nothing new arrived, so the stored cursor stands; ``--since`` was for this run only."""
    cursors.set(COLLECTION, STORED)
    server = StandInServer(page(last=None))

    poll(server, cursors, since=SINCE)

    assert cursors.get(COLLECTION) == STORED


# ---------------------------------------------------------------------------
# Collections do not share cursors
# ---------------------------------------------------------------------------
def test_an_empty_collection_does_not_inherit_the_previous_collections_cursor(cursors):
    server = StandInServer(page(*OBJECTS, last=LATEST), page(last=None))
    taxii = server.client()

    _poll_collection(taxii, cursors, "c-first", since=None, full=False)
    _poll_collection(taxii, cursors, "c-empty", since=None, full=False)

    assert cursors.get("c-first") == LATEST
    assert cursors.get("c-empty") is None


def test_a_collection_whose_paging_stops_early_does_not_inherit_the_previous_cursor(cursors):
    """``more`` without ``next`` ends paging before the final-page header is read.

    That is the one path on which ``last_date_added`` is not reassigned, so only
    the clear on entry stops the previous collection's cursor being persisted
    here -- skipping everything in this collection between the two timestamps.
    """
    stalled = httpx.Response(200, json={"objects": [OBJECTS[1]], "more": True})
    server = StandInServer(page(*OBJECTS, last=LATEST), stalled)
    taxii = server.client()

    _poll_collection(taxii, cursors, "c-first", since=None, full=False)
    _poll_collection(taxii, cursors, "c-stalled", since=None, full=False)

    assert cursors.get("c-stalled") is None


# ---------------------------------------------------------------------------
# Filters survive pagination
# ---------------------------------------------------------------------------
def test_a_type_filter_is_sent_on_every_page():
    server = StandInServer(page(OBJECTS[0], next_cursor="page-2"), page(OBJECTS[1], last=LATEST))

    list(server.client().objects(COLLECTION, match_type="vulnerability"))

    assert [r.url.params.get("match[type]") for r in server.requests] == [
        "vulnerability",
        "vulnerability",
    ]
    assert server.requests[1].url.params.get("next") == "page-2"
