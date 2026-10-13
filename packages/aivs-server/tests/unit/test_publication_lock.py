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
from collections.abc import AsyncIterator, Awaitable
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aivs_schemas.enums import TLP, DiscoveryScope, OrgStatus, OrgType, SubmissionState
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.db import models
from aivs_server.services.distribution import distribute_submission
from aivs_server.services.embargo import release_embargo_now
from aivs_server.services.publication import wait_for_publications

pytestmark = pytest.mark.db

#: Long enough that a writer which is *not* blocked has certainly finished, short
#: enough to keep the suite fast. A blocked writer stays blocked indefinitely, so
#: the margin only has to cover the unblocked case.
_SETTLE_SECONDS = 0.5


@pytest.fixture
async def open_session(engine: Any) -> AsyncIterator[Any]:
    """Factory for extra sessions, each rolled back and closed at teardown."""
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    opened: list[AsyncSession] = []

    def _open() -> AsyncSession:
        session = factory()
        opened.append(session)
        return session

    yield _open
    for session in opened:
        await session.rollback()
        await session.close()


@pytest.fixture
async def isac_ctx(make_org) -> AuthContext:
    org = await make_org("the-isac", org_type=OrgType.ADMIN)
    return AuthContext(
        org_id=org.id,
        org_slug=org.slug,
        org_type=OrgType.ADMIN,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.MTLS,
    )


@pytest.fixture
async def make_validated(session: AsyncSession, make_org):
    """Factory for a validated submission carrying one STIX object."""
    member = await make_org("member-bank")

    async def _make(name: str) -> uuid.UUID:
        submission = models.Submission(
            submitter_org_id=member.id,
            state=SubmissionState.VALIDATED,
            tlp=TLP.AMBER,
            discovery_scope=DiscoveryScope.AI_SYSTEM,
            title=name,
        )
        session.add(submission)
        await session.flush()
        stix_id = f"vulnerability--{uuid.uuid4()}"
        session.add(
            models.StixObject(
                stix_id=stix_id,
                modified=submission.created_at,
                created=submission.created_at,
                type="vulnerability",
                spec_version="2.1",
                submission_id=submission.id,
                name=name,
                raw={"type": "vulnerability", "spec_version": "2.1", "id": stix_id, "name": name},
            )
        )
        await session.commit()
        return submission.id

    return _make


async def _distribute(
    session: AsyncSession, ctx: AuthContext, submission_id: uuid.UUID, circle_id: uuid.UUID
) -> None:
    submission = await session.get(models.Submission, submission_id)
    assert submission is not None
    await distribute_submission(session, ctx, submission, circle_ids=[circle_id])


async def _is_blocked(operation: Awaitable[Any]) -> tuple[bool, asyncio.Task[Any]]:
    task = asyncio.ensure_future(operation)
    done, _ = await asyncio.wait({task}, timeout=_SETTLE_SECONDS)
    return task not in done, task


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

    blocked, task = await _is_blocked(second_publication())
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

    blocked, task = await _is_blocked(_distribute(writer, isac_ctx, only_id, circle.id))
    assert not blocked
    await task


async def test_a_paging_read_waits_for_an_open_publication(
    open_session, isac_ctx, make_validated, make_circle
):
    circle = await make_circle("sector")
    submission_id = await make_validated("in flight")
    writer, reader = open_session(), open_session()

    await _distribute(writer, isac_ctx, submission_id, circle.id)

    blocked, task = await _is_blocked(wait_for_publications(reader))
    assert blocked, "a cursor could be issued while a publication was uncommitted"

    await writer.commit()
    await asyncio.wait_for(task, timeout=10)


async def test_a_paging_read_proceeds_when_nothing_is_in_flight(open_session):
    reader, other_reader = open_session(), open_session()

    # Shared with another reader too: readers must never queue behind readers.
    await wait_for_publications(other_reader)
    blocked, task = await _is_blocked(wait_for_publications(reader))
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

    blocked, task = await _is_blocked(
        release_embargo_now(releaser, isac_ctx, submission_id=embargoed_id)
    )
    assert blocked, "an early release stamped while a distribution was uncommitted"

    await writer.commit()
    await asyncio.wait_for(task, timeout=10)
