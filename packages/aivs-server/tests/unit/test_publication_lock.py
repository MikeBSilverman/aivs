"""Publication order equals commit order (finding #1, SF-10).

Two distributions that stamp ``date_added`` in one order and commit in the
other hand a polling member a cursor past the batch that commits last, and
that batch is never delivered. These tests hold one publication open in its own
transaction and show that a second writer, and a cursor-issuing reader, wait
for it -- and, as the other half of each pair, that they do not wait when
nothing is in flight, so a pass cannot come from the operation simply being
slow.

Interleaving uses two sessions and asyncio rather than threads, so it is
deterministic. Every session is rolled back in ``finally``: a leaked open
transaction holds locks the per-test TRUNCATE needs, and surfaces as a
misleading "another test run" error rather than as this test's failure.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.auth.context import AuthContext
from aivs_server.db import models
from aivs_server.services.distribution import distribute_submission
from aivs_server.services.embargo import release_embargo_now
from aivs_server.services.publication import wait_for_publications
from tests.conftest import is_blocked

pytestmark = pytest.mark.db


async def _distribute(
    session: AsyncSession, ctx: AuthContext, submission_id: uuid.UUID, circle_id: uuid.UUID
) -> None:
    submission = await session.get(models.Submission, submission_id)
    assert submission is not None
    await distribute_submission(session, ctx, submission, circle_ids=[circle_id])


async def test_a_second_distribution_waits_for_the_first_to_commit(
    open_session, isac_ctx, make_validated, make_circle
):
    circle = await make_circle("sector")
    first_id = await make_validated("first")
    second_id = await make_validated("second")
    first, second = open_session(), open_session()

    # The first publication stamps its rows and stays uncommitted.
    await _distribute(first, isac_ctx, first_id, circle.id)

    async def second_publication() -> None:
        await _distribute(second, isac_ctx, second_id, circle.id)
        await second.commit()

    blocked, task = await is_blocked(second_publication())
    assert blocked, "a second distribution stamped while the first was uncommitted"

    await first.commit()
    await asyncio.wait_for(task, timeout=10)

    rows = (
        await second.execute(
            select(models.Distribution.submission_id, models.Distribution.date_added).order_by(
                models.Distribution.seq
            )
        )
    ).all()
    assert [row.submission_id for row in rows] == [first_id, second_id]
    assert rows[0].date_added <= rows[1].date_added


async def test_a_distribution_proceeds_when_none_is_in_flight(
    open_session, isac_ctx, make_validated, make_circle
):
    circle = await make_circle("sector")
    only_id = await make_validated("only")
    writer = open_session()

    blocked, task = await is_blocked(_distribute(writer, isac_ctx, only_id, circle.id))
    assert not blocked
    await task


async def test_a_paging_read_waits_for_an_open_publication(
    open_session, isac_ctx, make_validated, make_circle
):
    circle = await make_circle("sector")
    submission_id = await make_validated("in flight")
    writer, reader = open_session(), open_session()

    await _distribute(writer, isac_ctx, submission_id, circle.id)

    blocked, task = await is_blocked(wait_for_publications(reader))
    assert blocked, "a cursor could be issued while a publication was uncommitted"

    await writer.commit()
    await asyncio.wait_for(task, timeout=10)


async def test_a_paging_read_proceeds_when_nothing_is_in_flight(open_session):
    reader, other_reader = open_session(), open_session()

    # Shared with another reader too: readers must never queue behind readers.
    await wait_for_publications(other_reader)
    blocked, task = await is_blocked(wait_for_publications(reader))
    assert not blocked
    await task


async def test_an_early_embargo_release_waits_for_an_open_publication(
    open_session, isac_ctx, make_validated, make_circle, session
):
    # release_embargo_now moves date_added; it is a writer like any other.
    circle = await make_circle("sector")
    embargoed_id = await make_validated("embargoed")
    in_flight_id = await make_validated("in flight")
    embargoed = await session.get(models.Submission, embargoed_id)
    assert embargoed is not None
    await distribute_submission(
        session,
        isac_ctx,
        embargoed,
        circle_ids=[circle.id],
        release_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=7),
    )
    await session.commit()

    writer, releaser = open_session(), open_session()
    await _distribute(writer, isac_ctx, in_flight_id, circle.id)

    blocked, task = await is_blocked(
        release_embargo_now(releaser, isac_ctx, submission_id=embargoed_id)
    )
    assert blocked, "an early release stamped while a distribution was uncommitted"

    await writer.commit()
    await asyncio.wait_for(task, timeout=10)
