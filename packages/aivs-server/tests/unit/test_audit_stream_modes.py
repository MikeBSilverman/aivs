"""What the audit stream serves of its own reading: ``full`` or ``condensed`` (Mike, Q30).

The stream serves only below a cluster-wide horizon (CLAUDE.md section 3), so a
test that waited for "an empty page" would pass whenever another database held
the horizon back -- which is how the T10 hang passed for a day. These tests
therefore compare what each page *contained*, as the poller saw it, with what
the server *recorded* for that page, and page with bounded loops that fail
rather than spin.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import uuid

import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import OperatorRole, OrgType
from aivs_server.audit.log import AuditAction, record
from aivs_server.db.models import AuditLog, AuditStreamModeChange
from aivs_server.services.audit_read_summary import summarise_audit_reads
from aivs_server.services.detections import RULES, run_detections

pytestmark = pytest.mark.db

EVENTS = "/api/v1/audit/events"
MODE = "/api/v1/instance/audit-stream"
#: Far more pages than any drain here needs; reaching it is the hang, reported.
MAX_PAGES = 300
READS = (AuditAction.AUDIT_READ, AuditAction.AUDIT_READ_QUIET)


def _later(days: int = 30) -> dt.datetime:
    return dt.datetime.now(dt.UTC) + dt.timedelta(days=days)


@pytest.fixture
async def world(make_org, make_cert, make_operator, human_headers, isac_org):
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    isac_pem, _ = await make_cert(isac_org)
    auditors = []
    for _ in range(2):
        operator, _ = await make_operator(
            isac_org, roles=(OperatorRole.AUDITOR,), role_expires_at=_later()
        )
        auditors.append((operator, await human_headers(operator, isac_pem)))
    admin, _ = await make_operator(isac_org, roles=(OperatorRole.SYSTEM_ADMIN,))
    return {
        "member": member,
        "a": auditors[0],
        "b": auditors[1],
        "admin": await human_headers(admin, isac_pem),
    }


@dataclasses.dataclass
class Poller:
    """One auditor's view: its cursor, every event it was served, and per page
    whether the page held anything but reads (which decides how it is recorded)."""

    headers: dict[str, str]
    cursor: str | None = None
    events: list[dict] = dataclasses.field(default_factory=list)
    loud_pages: int = 0
    quiet_pages: int = 0

    async def page(self, client) -> list[dict]:
        params = {"limit": 3, **({"cursor": self.cursor} if self.cursor else {})}
        response = await client.get(EVENTS, params=params, headers=self.headers)
        assert response.status_code == 200, response.text
        body = response.json()
        served = body["events"]
        self.cursor = body["cursor"]
        self.events += served
        if any(event["action"] != AuditAction.AUDIT_READ for event in served):
            self.loud_pages += 1
        else:
            self.quiet_pages += 1
        return served

    async def drain(self, client) -> None:
        for _ in range(MAX_PAGES):
            if not await self.page(client):
                return
        pytest.fail(f"the stream never ran out after {MAX_PAGES} pages")

    async def until_a_page_of_reads(self, client) -> None:
        """Page until a page holding reads and nothing else is served.

        That page is the case the recording rule is about. Paged straight to
        empty, a drain can finish before the horizon lets the reads through,
        and a test asserting how such a page is recorded then passes having
        seen none: M362 survived one run in two that way.
        """
        deadline = asyncio.get_running_loop().time() + 60
        while True:
            served = await self.page(client)
            if served and all(event["action"] == AuditAction.AUDIT_READ for event in served):
                return
            assert asyncio.get_running_loop().time() < deadline, "no page of reads alone"
            await asyncio.sleep(0.2)

    async def wait_for_more(self, client) -> None:
        """Page until something new is served."""
        before = len(self.events)
        deadline = asyncio.get_running_loop().time() + 60
        while len(self.events) == before:
            assert asyncio.get_running_loop().time() < deadline, "nothing more was served"
            await self.page(client)
            await asyncio.sleep(0.2)

    async def until_served(self, client, marker: str) -> None:
        """Page until ``marker`` is served: everything committed before it is
        then below the horizon too."""
        deadline = asyncio.get_running_loop().time() + 60
        for _ in range(MAX_PAGES):
            await self.page(client)
            if any(event["resource_id"] == marker for event in self.events):
                return
            assert asyncio.get_running_loop().time() < deadline, f"{marker} never served"
            await asyncio.sleep(0.2)
        pytest.fail(f"{marker} not served within {MAX_PAGES} pages")


async def _marker(session) -> str:
    label = f"marker-{uuid.uuid4()}"
    await record(
        session,
        action="test.marker",
        actor_type="system",
        resource_type="test",
        resource_id=label,
    )
    await session.commit()
    return label


async def _recorded(session, operator_id: uuid.UUID) -> dict[str, int]:
    rows = await session.execute(
        select(AuditLog.action, func.count())
        .where(AuditLog.actor_id == str(operator_id), AuditLog.action.in_(READS))
        .group_by(AuditLog.action)
    )
    return dict(rows.tuples().all())


async def _set_mode(client, world, mode: str):
    return await client.put(
        MODE, json={"mode": mode, "reason": f"test: the stream goes {mode}"}, headers=world["admin"]
    )


def _hashes(events: list[dict]) -> list[str]:
    return [event["hash"] for event in events]


# ---------------------------------------------------------------------------
# condensed: the default
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-78")
async def test_condensed_is_the_default_and_serves_no_reads(client, session, world):
    poller = Poller(world["a"][1])
    await poller.until_served(client, await _marker(session))
    await poller.until_served(client, await _marker(session))
    assert not [e for e in poller.events if e["action"] in READS]


# ---------------------------------------------------------------------------
# full
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-78")
async def test_full_serves_reads_and_records_an_all_reads_page_as_quiet(client, session, world):
    """The rule that lets a poller drain: only a page holding something other
    than reads is recorded as a read the stream will serve."""
    operator, headers = world["a"]
    assert (await _set_mode(client, world, "full")).json() == {"mode": "full", "changed": True}
    poller = Poller(headers)
    await poller.until_served(client, await _marker(session))
    await poller.until_served(client, await _marker(session))
    await poller.until_a_page_of_reads(client)
    await poller.drain(client)
    # Every quiet row the drain wrote committed before this marker, so paging
    # until the marker is served pages past them too. Without it the drain can
    # end before a lagging horizon lets them be served, and "no quiet row is
    # served" holds of rows the poller was never offered (CLAUDE.md section 3).
    await poller.until_served(client, await _marker(session))

    recorded = await _recorded(session, operator.id)
    assert any(e["action"] == AuditAction.AUDIT_READ for e in poller.events), "reads are served"
    assert recorded.get(AuditAction.AUDIT_READ, 0) == poller.loud_pages
    assert recorded.get(AuditAction.AUDIT_READ_QUIET, 0) == poller.quiet_pages
    assert not [e for e in poller.events if e["action"] == AuditAction.AUDIT_READ_QUIET]


@pytest.mark.requirement("SF-78")
async def test_two_pollers_reading_each_others_reads_both_run_out(client, session, world):
    """A's reads are B's content and B's are A's. Each records a read only for a
    page with something else in it, and those are finite, so both reach an
    empty page -- and the server recorded each page as the poller saw it."""
    await _set_mode(client, world, "full")
    a, b = Poller(world["a"][1]), Poller(world["b"][1])
    for _ in range(3):
        marker = await _marker(session)
        await a.until_served(client, marker)
        await b.until_served(client, marker)
    for _ in range(MAX_PAGES):
        served = [await a.page(client), await b.page(client)]
        if not any(served):
            break
    else:
        pytest.fail("two pollers fed each other for good")
    # A page of nothing but the other's reads, for certain: B starts where A's
    # last loud page left off, so what follows is A's record of that page and
    # nothing else. Waiting for it, rather than for "an empty page", is what
    # keeps a lagging horizon from ending the test before such a page exists.
    await a.until_served(client, await _marker(session))
    b.cursor = a.cursor
    await b.wait_for_more(client)

    for (operator, _), poller in ((world["a"], a), (world["b"], b)):
        recorded = await _recorded(session, operator.id)
        assert recorded.get(AuditAction.AUDIT_READ, 0) == poller.loud_pages
        assert recorded.get(AuditAction.AUDIT_READ_QUIET, 0) == poller.quiet_pages
    assert any(e["actor_id"] == str(world["b"][0].id) for e in a.events), "A was served B's reads"


# ---------------------------------------------------------------------------
# A change of mode
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-78")
async def test_a_change_of_mode_keeps_every_cursor_and_every_hash(client, session, world):
    """Reads are judged by the mode in force when each was written. A mode read
    at serve time would re-sort history: an export from genesis after the
    change would differ from the one an auditor already holds, and the chain
    they kept would no longer match."""
    before = Poller(world["a"][1])
    await before.until_served(client, await _marker(session))
    await before.drain(client)
    kept, kept_cursor = list(before.events), before.cursor

    await _set_mode(client, world, "full")
    continued = Poller(world["a"][1], cursor=kept_cursor)
    in_full_marker = await _marker(session)
    await continued.until_served(client, in_full_marker)
    in_full = Poller(world["b"][1])
    await in_full.until_served(client, in_full_marker)

    await _set_mode(client, world, "condensed")
    after = Poller(world["b"][1])
    await after.until_served(client, await _marker(session))

    assert _hashes(in_full.events[: len(kept)]) == _hashes(kept)
    assert _hashes(in_full.events[len(kept) :][: len(continued.events)]) == _hashes(
        continued.events
    )
    assert _hashes(after.events[: len(in_full.events)]) == _hashes(in_full.events)
    assert [e for e in after.events if e["action"] == AuditAction.AUDIT_STREAM_MODE_CHANGED]


async def test_choosing_the_mode_in_force_writes_nothing(client, session, world):
    first = await _set_mode(client, world, "full")
    again = await _set_mode(client, world, "full")
    changes = await session.scalar(select(func.count()).select_from(AuditStreamModeChange))
    assert (first.json()["changed"], again.json()["changed"], changes) == (True, False, 1)


async def test_an_auditor_cannot_choose_the_mode(client, world):
    refused = await client.put(
        MODE, json={"mode": "full", "reason": "an auditor tries"}, headers=world["a"][1]
    )
    assert refused.status_code == 403


# ---------------------------------------------------------------------------
# Summaries, in both modes
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-78")
@pytest.mark.parametrize("mode", ["condensed", "full"])
async def test_each_reader_is_summarised_once_and_the_summary_is_served(
    client, session, world, mode
):
    operator, headers = world["a"]
    await _set_mode(client, world, mode)
    poller = Poller(headers)
    await poller.until_served(client, await _marker(session))
    await poller.drain(client)
    reading = await _marker(session)
    await Poller(world["b"][1]).until_served(client, reading)

    written = await summarise_audit_reads(session)
    await summarise_audit_reads(session)
    summaries = (
        await session.scalars(
            select(AuditLog).where(
                AuditLog.action == AuditAction.AUDIT_READ_SUMMARY,
                AuditLog.resource_id == str(operator.id),
            )
        )
    ).all()

    assert written >= 1
    assert len(summaries) == 1, "a second run summarises none of A's reads again"
    details = summaries[0].details
    assert details["pages"] + details["quiet_pages"] == poller.loud_pages + poller.quiet_pages
    assert details["streams"] == ["audit"]
    await poller.until_served(client, str(operator.id))


@pytest.mark.requirement("SF-78")
async def test_reading_summaries_adds_at_most_one_summary_per_reader_per_run(
    client, session, world
):
    """Reading a summary is a read, summarised on the next run: a feedback loop,
    but one row per reader per run, so a poller draining between runs ends."""
    operator, headers = world["a"]
    poller = Poller(headers)
    runs = 3
    for _ in range(runs):
        await poller.until_served(client, await _marker(session))
        await poller.drain(client)
        await summarise_audit_reads(session)
    summaries = await session.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.action == AuditAction.AUDIT_READ_SUMMARY,
            AuditLog.resource_id == str(operator.id),
        )
    )
    assert 1 <= summaries <= runs


@pytest.mark.requirement("SF-78")
async def test_the_summary_job_writes_nothing_while_distribution_is_paused(client, session, world):
    await Poller(world["a"][1]).until_served(client, await _marker(session))
    paused = await client.post(
        "/api/v1/instance/distribution/pause",
        json={"reason": "test: incident drill"},
        headers=world["admin"],
    )
    assert paused.status_code == 200, paused.text
    assert await summarise_audit_reads(session) == 0


# ---------------------------------------------------------------------------
# auditor_bulk_read sees every read, in either mode
# ---------------------------------------------------------------------------
def _bulk(threshold: int):
    rule = next(rule for rule in RULES if rule.name == "auditor_bulk_read")
    return dataclasses.replace(rule, threshold=threshold)


@pytest.mark.requirement("SF-78")
@pytest.mark.parametrize("mode", ["condensed", "full"])
async def test_bulk_reading_is_noticed_in_either_mode(client, session, world, mode):
    operator, headers = world["a"]
    await _set_mode(client, world, mode)
    for _ in range(4):
        await record(session, action="test.filler", actor_type="system", resource_type="test")
    await session.commit()
    poller = Poller(headers)
    await poller.until_served(client, await _marker(session))
    raised = await run_detections(
        session, quarantine_policy="propose", now=dt.datetime.now(dt.UTC), rules=[_bulk(5)]
    )
    assert [(f.rule, f.subject) for f in raised] == [("auditor_bulk_read", str(operator.id))]


@pytest.mark.requirement("SF-78")
async def test_reads_of_nothing_but_reads_still_count_towards_bulk_reading(client, session, world):
    """B reads the trail first, then pages over what A read after it: nothing but
    reads, so every one of those pages is quiet. The events are still ones B was
    served, and the rule must count them or a reader evades it by reading reads."""
    await _set_mode(client, world, "full")
    last = ""
    for _ in range(4):
        last = await _marker(session)
    b = Poller(world["b"][1])
    await b.until_served(client, last)
    await b.drain(client)
    before = len(b.events)
    await Poller(world["a"][1]).until_served(client, last)
    deadline = asyncio.get_running_loop().time() + 60
    while len(b.events) == before:
        assert asyncio.get_running_loop().time() < deadline, "A's reads never reached B"
        await b.page(client)
        await asyncio.sleep(0.2)
    await b.drain(client)

    reads_only = b.events[before:]
    assert all(e["action"] == AuditAction.AUDIT_READ for e in reads_only)
    raised = await run_detections(
        session,
        quarantine_policy="propose",
        now=dt.datetime.now(dt.UTC),
        rules=[_bulk(len(b.events))],
    )
    assert str(world["b"][0].id) in [f.subject for f in raised]
