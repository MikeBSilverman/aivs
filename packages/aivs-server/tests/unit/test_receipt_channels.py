"""A receipt per channel per day: a person reading is a different fact from a poll (SF-51).

Driven through ``record_retrievals``, the only writer of retrieval receipts.
The portal pages that call it with ``AckVia.PORTAL`` arrive with the
vulnerability page; the key they depend on is pinned here.
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import AckVia, SubmissionState
from aivs_server.db.models import Acknowledgment, Submission
from aivs_server.services.receipts import record_retrievals
from tests.conftest import seed_filing

pytestmark = pytest.mark.db

NOON = dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.UTC)


@pytest.fixture
async def received(session, make_org):
    org = await make_org("receipt-member")
    submission = Submission(
        state=SubmissionState.DISTRIBUTED,
        tlp="amber",
        discovery_scope="own_product",
        title="Received",
        distributed_at=NOON,
    )
    await seed_filing(session, submission, org)
    await session.commit()
    return org, submission


async def _retrieve(session, org, submission, via, now=NOON) -> int:
    """How many receipts the retrieval wrote: counted, since the writer cannot say."""
    before = await _count(session)
    await record_retrievals(
        session, org_id=org.id, submission_ids=[submission.id], via=via, actor_ref=None, now=now
    )
    await session.commit()
    return await _count(session) - before


async def _count(session) -> int:
    return await session.scalar(select(func.count()).select_from(Acknowledgment))


@pytest.mark.requirement("SF-51")
async def test_a_portal_read_after_a_same_day_poll_is_its_own_receipt(session, received):
    org, submission = received
    assert await _retrieve(session, org, submission, AckVia.TAXII) == 1
    assert await _retrieve(session, org, submission, AckVia.PORTAL) == 1
    assert await _count(session) == 2


@pytest.mark.requirement("SF-51")
async def test_two_portal_reads_on_one_day_are_one_receipt(session, received):
    org, submission = received
    assert await _retrieve(session, org, submission, AckVia.PORTAL) == 1
    assert (
        await _retrieve(session, org, submission, AckVia.PORTAL, NOON + dt.timedelta(hours=3)) == 0
    )
    assert await _count(session) == 1
