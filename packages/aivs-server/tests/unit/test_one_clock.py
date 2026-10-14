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
from aivs_server.api import admin as admin_api
from aivs_server.db import models
from aivs_server.db.clock import database_now
from aivs_server.services import circles as circles_service
from aivs_server.services import distribution as distribution_service
from aivs_server.services import embargo as embargo_service
from aivs_server.services.circles import reconcile_circle
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


# ---------------------------------------------------------------------------
# Membership intervals (L-P3)
# ---------------------------------------------------------------------------
async def test_a_removal_on_a_fast_app_clock_withholds_the_gap_and_allows_a_rejoin(
    client,
    session,
    monkeypatch,
    isac,
    make_org,
    make_cert,
    make_circle,
    join_circle,
    make_collection,
    publish,
):
    """The interval closed an hour in the future: the member could not be re-added
    for that hour (the new interval overlapped it), and once it was, the hour it
    was out would have been readable."""
    _isac_org, isac_headers = isac
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    circle = await make_circle("sector")
    await join_circle(member, circle)
    collection = await make_collection(circle)
    publisher = await make_org("atlantic-clearing", org_type=OrgType.GSIB)
    await publish(publisher, circle, name="before", date_added=await database_now(session) - HOUR)
    skew_clock(monkeypatch, admin_api, HOUR)

    removed = await client.delete(
        f"/api/v1/circles/{circle.id}/members/{member.id}", headers=isac_headers
    )
    await publish(
        publisher,
        circle,
        name="while out",
        date_added=await database_now(session) + dt.timedelta(milliseconds=1),
    )
    rejoined = await client.post(
        f"/api/v1/circles/{circle.id}/members",
        json={"org_ids": [str(member.id)]},
        headers=isac_headers,
    )
    await publish(
        publisher,
        circle,
        name="after rejoining",
        date_added=await database_now(session) + dt.timedelta(milliseconds=1),
    )
    feed = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )

    assert (removed.status_code, rejoined.status_code) == (204, 204), rejoined.text
    names = {item["name"] for item in feed.json().get("objects", [])}
    assert names == {"before", "after rejoining"}


async def test_a_rule_opens_and_closes_membership_on_the_database_clock(
    session, monkeypatch, make_org, make_circle
):
    circle = await make_circle("section9")
    circle.auto_member_org_types = ["section9"]
    org = await make_org("regional-bank", org_type=OrgType.SECTION9)
    await session.commit()
    skew_clock(monkeypatch, circles_service, HOUR)

    await reconcile_circle(session, None, circle=circle)
    await session.commit()
    org.org_type = OrgType.GSIB
    await session.flush()
    await reconcile_circle(session, None, circle=circle)
    await session.commit()

    reference = await database_now(session)
    row = (
        await session.execute(
            select(models.CircleMembership).where(models.CircleMembership.org_id == org.id)
        )
    ).scalar_one()
    assert close_to(row.joined_at, reference)
    assert row.left_at is not None
    assert close_to(row.left_at, reference), "the interval closed on the app's clock"


async def test_quarantine_and_reconnection_stamp_the_database_clock(
    client, session, monkeypatch, isac, make_org, make_cert, make_circle, join_circle, ca
):
    """The quarantine's start is the edge of the gap a new interval withholds."""
    _isac_org, isac_headers = isac
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    await make_cert(member)
    circle = await make_circle("sector")
    await join_circle(member, circle)
    skew_clock(monkeypatch, admin_api, HOUR)

    quarantined = await client.post(
        f"/api/v1/orgs/{member.id}/quarantine",
        json={"reason": "collector host compromised"},
        headers=isac_headers,
    )
    fresh_pem, _fp, _cert = ca.issue("meridian-global-after-incident")
    registered = await client.post(
        f"/api/v1/orgs/{member.id}/certificates",
        json={"certificate_pem": fresh_pem},
        headers=isac_headers,
    )
    reconnected = await client.post(
        f"/api/v1/orgs/{member.id}/reconnect",
        json={"reason": "collector rebuilt", "backlog": "new_interval"},
        headers=isac_headers,
    )

    assert (quarantined.status_code, registered.status_code, reconnected.status_code) == (
        200,
        201,
        200,
    ), reconnected.text
    reference = await database_now(session)
    intervals = (
        (
            await session.execute(
                select(models.CircleMembership)
                .where(models.CircleMembership.org_id == member.id)
                .order_by(models.CircleMembership.joined_at)
            )
        )
        .scalars()
        .all()
    )
    closed, reopened = intervals
    assert closed.left_at is not None
    assert close_to(closed.left_at, reference), "the gap began on the app's clock"
    assert close_to(reopened.joined_at, reference), "the new interval began on the app's clock"
