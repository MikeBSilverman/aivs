"""Visibility is compared on one clock, the database's (R-P1, L-P3).

``date_added``, a reader's "now", the cursors readers hand out, and the edges
of a membership interval are all compared with one another. They were read
from each app replica's own clock, so two replicas that disagreed -- or one NTP
step -- could stamp a row below a cursor already issued (never delivered), show
an embargo early, or close a membership an hour late. Each test here skews the
Python clock of one module by an hour and shows that what it stamps or reads
follows the database regardless. The pair in each case is the same operation
on an honest clock, which the rest of the suite already exercises.
"""

from __future__ import annotations

import datetime as dt
import types
from typing import Any

import pytest
from sqlalchemy import select, update

from aivs_schemas.enums import OrgType
from aivs_server.db import models
from aivs_server.db.clock import database_now
from aivs_server.services import distribution as distribution_service
from aivs_server.services import embargo as embargo_service
from aivs_server.services.distribution import distribute_submission
from aivs_server.services.embargo import EmbargoError, extend_embargo, release_embargo_now
from aivs_server.taxii import router as taxii_router
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

HOUR = dt.timedelta(hours=1)
#: How far a stamp may sit from the database clock and still count as read from
#: it: generous for a slow CI host, far inside the hour of skew.
CLOSE = dt.timedelta(minutes=1)


def skew_clock(monkeypatch: pytest.MonkeyPatch, module: types.ModuleType, offset: dt.timedelta):
    """Make ``module``'s ``dt.datetime.now`` run ``offset`` away from the host clock."""
    real = dt.datetime

    class Skewed(real):
        @classmethod
        def now(cls, tz: Any = None) -> Any:
            return real.now(tz) + offset

    fake = types.SimpleNamespace(**{name: getattr(dt, name) for name in dir(dt) if name[0] != "_"})
    fake.datetime = Skewed
    monkeypatch.setattr(module, "dt", fake)


def close_to(stamp: dt.datetime, reference: dt.datetime) -> bool:
    return abs(stamp - reference) < CLOSE


# ---------------------------------------------------------------------------
# Writers of date_added
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-10")
async def test_distribution_stamps_date_added_on_the_database_clock(
    session, monkeypatch, isac_ctx, make_validated, make_circle
):
    circle = await make_circle("sector")
    submission = await session.get(models.Submission, await make_validated("finding"))
    skew_clock(monkeypatch, distribution_service, -HOUR)

    before = await database_now(session)
    result = await distribute_submission(session, isac_ctx, submission, circle_ids=[circle.id])

    assert result.date_added > before, "stamped below an instant the database had passed"
    assert close_to(result.date_added, before)


@pytest.fixture
async def embargoed(session, isac_ctx, make_validated, make_circle):
    """A distribution held three days out: ``(submission_id, circle)``."""
    circle = await make_circle("sector")
    submission = await session.get(models.Submission, await make_validated("held"))
    release_at = dt.datetime.now(dt.UTC) + dt.timedelta(days=3)
    await distribute_submission(
        session, isac_ctx, submission, circle_ids=[circle.id], release_at=release_at
    )
    await session.commit()
    return submission.id, circle


@pytest.mark.requirement("SF-10")
async def test_early_release_stamps_on_the_database_clock(
    session, monkeypatch, isac_ctx, embargoed
):
    """An app clock an hour behind released the rows an hour into the past,
    below every cursor members had been handed in that hour."""
    submission_id, _circle = embargoed
    skew_clock(monkeypatch, embargo_service, -HOUR)

    before = await database_now(session)
    embargo = await release_embargo_now(session, isac_ctx, submission_id=submission_id)
    stamps = (
        await session.execute(
            select(models.Distribution.date_added).where(
                models.Distribution.submission_id == submission_id
            )
        )
    ).scalars()

    assert embargo.released_at is not None
    assert embargo.released_at > before
    assert all(stamp == embargo.released_at for stamp in stamps)


async def test_an_extension_on_a_lagging_app_clock_cannot_retract_released_content(
    session, monkeypatch, isac_ctx, embargoed
):
    """Released a minute ago by the database's clock; an hour in the future by
    a replica's. Deciding on the replica's moved content members already held
    back into the future."""
    submission_id, _circle = embargoed
    elapsed = await database_now(session) - dt.timedelta(minutes=1)
    await session.execute(
        update(models.Distribution)
        .where(models.Distribution.submission_id == submission_id)
        .values(date_added=elapsed)
    )
    await session.execute(
        update(models.Embargo)
        .where(models.Embargo.submission_id == submission_id)
        .values(release_at=elapsed)
    )
    await session.commit()
    skew_clock(monkeypatch, embargo_service, -HOUR)

    with pytest.raises(EmbargoError, match="already passed"):
        await extend_embargo(
            session,
            isac_ctx,
            submission_id=submission_id,
            release_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=10),
        )
    await session.rollback()

    stamps = set(
        (
            await session.execute(
                select(models.Distribution.date_added).where(
                    models.Distribution.submission_id == submission_id
                )
            )
        ).scalars()
    )
    assert stamps == {elapsed}


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-10")
async def test_a_reader_ahead_of_the_writers_neither_shows_an_embargo_nor_skips_a_row(
    client,
    session,
    monkeypatch,
    make_org,
    make_cert,
    make_circle,
    join_circle,
    make_collection,
    publish,
):
    """A replica an hour fast served an embargo due in half an hour, and handed
    out its stamp as the cursor; the next distribution, stamped on an honest
    clock below that cursor, was never delivered to that member."""
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    circle = await make_circle("sector")
    await join_circle(member, circle)
    collection = await make_collection(circle)
    publisher = await make_org("atlantic-clearing", org_type=OrgType.GSIB)
    url = f"/taxii2/aivs/collections/{collection.id}/objects/"
    await publish(
        publisher,
        circle,
        name="embargoed",
        date_added=await database_now(session) + dt.timedelta(minutes=30),
    )
    skew_clock(monkeypatch, taxii_router, HOUR)

    first = await client.get(url, headers=proxy_headers(pem))
    await publish(
        publisher,
        circle,
        name="distributed next",
        date_added=await database_now(session) + dt.timedelta(milliseconds=1),
    )
    cursor = first.headers.get("X-TAXII-Date-Added-Last")
    second = await client.get(
        url, params={"added_after": cursor} if cursor else {}, headers=proxy_headers(pem)
    )

    assert first.status_code == 200
    assert "embargoed" not in {item["name"] for item in first.json().get("objects", [])}
    assert {item["name"] for item in second.json().get("objects", [])} == {"distributed next"}
