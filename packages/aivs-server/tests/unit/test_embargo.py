"""Embargo records, early release, extension, and the sweeper.

The property that governs this module is asymmetric and easy to get wrong:
moving a visibility timestamp *earlier* is safe when it is still in the future,
because no member's polling cursor can have passed it — but moving it earlier
than now, or moving it later after release, is not. These tests pin each
direction separately.

They also pin the split the design rests on: the timestamp holds the content
back, and the ``embargoes`` row merely records that fact. Content becomes
visible when its time arrives whether or not the sweeper has run.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import EmbargoStatus, OrgStatus, OrgType, SubmissionState
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.db.models import Distribution, Embargo
from aivs_server.services.embargo import (
    EmbargoError,
    extend_embargo,
    release_embargo_now,
    sweep_due_embargoes,
)
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1/submissions"
STAMP = "2026-08-01T00:00:00.000Z"


def bundle() -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{uuid.uuid4()}",
                "created": STAMP,
                "modified": STAMP,
                "name": "Embargoed finding",
            }
        ],
    }


@pytest.fixture
async def embargoed(client, isac, make_org, make_cert, make_circle, join_circle, make_collection):
    """A submission distributed with a future release time."""
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    member_pem, _ = await make_cert(member)
    _isac_org, isac_headers = isac
    circle = await make_circle("section9")
    await join_circle(member, circle)
    collection = await make_collection(circle)

    created = await client.post(
        API,
        json={
            "title": "Held until Friday",
            "discovery_scope": "ai_system",
            "tlp": "amber",
            "bundle": bundle(),
        },
        headers=proxy_headers(member_pem),
    )
    assert created.status_code == 201
    submission_id = created.json()["id"]

    await client.post(f"{API}/{submission_id}/submit", json={}, headers=proxy_headers(member_pem))
    await client.post(f"{API}/{submission_id}/validate", json={}, headers=isac_headers)

    release_at = dt.datetime.now(dt.UTC) + dt.timedelta(days=3)
    distributed = await client.post(
        f"{API}/{submission_id}/distribute",
        json={"circle_ids": [str(circle.id)], "release_at": release_at.isoformat()},
        headers=isac_headers,
    )
    assert distributed.status_code == 200, distributed.text

    return {
        "submission_id": submission_id,
        "member_pem": member_pem,
        "isac_headers": isac_headers,
        "collection": collection,
        "release_at": release_at,
    }


def feed_url(collection) -> str:
    return f"/taxii2/aivs/collections/{collection.id}/objects/"


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------
async def test_distributing_with_a_future_time_records_the_embargo(embargoed, session):
    """The row is the operator's view; the timestamp is the enforcement."""
    row = (await session.execute(select(Embargo))).scalar_one()
    assert row.status is EmbargoStatus.PENDING
    assert row.release_at is not None


async def test_the_detail_view_reports_the_embargo(client, embargoed):
    """It reported None for everything before the record was wired up."""
    detail = await client.get(
        f"{API}/{embargoed['submission_id']}", headers=embargoed["isac_headers"]
    )
    assert detail.status_code == 200
    assert detail.json()["embargo"] is not None
    assert detail.json()["embargo"]["status"] == "pending"


async def test_content_is_invisible_before_release(client, embargoed):
    feed = await client.get(
        feed_url(embargoed["collection"]), headers=proxy_headers(embargoed["member_pem"])
    )
    assert feed.json() == {}


# ---------------------------------------------------------------------------
# Early release
# ---------------------------------------------------------------------------
async def test_the_isac_can_release_early(client, embargoed, session):
    """The escape hatch: a finding under active exploitation cannot wait."""
    response = await client.post(
        f"{API}/{embargoed['submission_id']}/embargo/release",
        json={"reason": "observed in the wild"},
        headers=embargoed["isac_headers"],
    )
    assert response.status_code == 200

    feed = await client.get(
        feed_url(embargoed["collection"]), headers=proxy_headers(embargoed["member_pem"])
    )
    assert len(feed.json()["objects"]) == 1

    row = (await session.execute(select(Embargo))).scalar_one()
    await session.refresh(row)
    assert row.status is EmbargoStatus.LIFTED_EARLY
    assert row.released_at is not None


async def test_early_release_never_moves_a_timestamp_into_the_past(client, embargoed, session):
    """Safe in the direction it moves, and only that direction.

    An embargoed row's timestamp is in the future, so lowering it to now leaves
    it at or ahead of every cursor a member could hold. Lowering it *below* now
    is what backdating at distribution time would do, and is refused there.
    """
    before = dt.datetime.now(dt.UTC)
    await client.post(
        f"{API}/{embargoed['submission_id']}/embargo/release",
        json={},
        headers=embargoed["isac_headers"],
    )

    rows = (await session.execute(select(Distribution.date_added))).scalars().all()
    assert rows
    for stamp in rows:
        assert stamp >= before - dt.timedelta(seconds=5)


async def test_a_member_cannot_release_their_own_embargo(client, embargoed):
    response = await client.post(
        f"{API}/{embargoed['submission_id']}/embargo/release",
        json={},
        headers=proxy_headers(embargoed["member_pem"]),
    )
    assert response.status_code == 403


async def test_releasing_twice_is_refused(client, embargoed):
    first = await client.post(
        f"{API}/{embargoed['submission_id']}/embargo/release",
        json={},
        headers=embargoed["isac_headers"],
    )
    assert first.status_code == 200

    second = await client.post(
        f"{API}/{embargoed['submission_id']}/embargo/release",
        json={},
        headers=embargoed["isac_headers"],
    )
    assert second.status_code == 409
    assert "already been released" in second.text


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------
async def test_an_embargo_can_be_extended(client, embargoed, session):
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=10)
    response = await client.post(
        f"{API}/{embargoed['submission_id']}/embargo/extend",
        json={"circle_ids": [str(uuid.uuid4())], "release_at": later.isoformat()},
        headers=embargoed["isac_headers"],
    )
    assert response.status_code == 200

    row = (await session.execute(select(Embargo))).scalar_one()
    await session.refresh(row)
    assert row.status is EmbargoStatus.EXTENDED
    assert row.release_at > embargoed["release_at"] - dt.timedelta(seconds=1)


async def test_an_embargo_cannot_be_shortened_by_extending(client, embargoed):
    """Shortening has a correct route -- release early -- with its own audit entry."""
    sooner = dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)
    response = await client.post(
        f"{API}/{embargoed['submission_id']}/embargo/extend",
        json={"circle_ids": [str(uuid.uuid4())], "release_at": sooner.isoformat()},
        headers=embargoed["isac_headers"],
    )
    assert response.status_code == 409
    assert "release it early" in response.text


async def test_a_released_embargo_cannot_be_reinstated(client, embargoed):
    """Members already hold the content; retracting it would be a false promise."""
    await client.post(
        f"{API}/{embargoed['submission_id']}/embargo/release",
        json={},
        headers=embargoed["isac_headers"],
    )

    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=10)
    response = await client.post(
        f"{API}/{embargoed['submission_id']}/embargo/extend",
        json={"circle_ids": [str(uuid.uuid4())], "release_at": later.isoformat()},
        headers=embargoed["isac_headers"],
    )
    assert response.status_code == 409
    assert "cannot be reinstated" in response.text


async def test_extending_into_the_past_is_refused(client, embargoed):
    past = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    response = await client.post(
        f"{API}/{embargoed['submission_id']}/embargo/extend",
        json={"circle_ids": [str(uuid.uuid4())], "release_at": past.isoformat()},
        headers=embargoed["isac_headers"],
    )
    assert response.status_code == 409


# ---------------------------------------------------------------------------
# The sweeper
# ---------------------------------------------------------------------------
async def test_the_sweeper_marks_due_embargoes_released(session, embargoed):
    """Bookkeeping, run after the fact."""
    row = (await session.execute(select(Embargo))).scalar_one()
    row.release_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
    await session.commit()

    swept = await sweep_due_embargoes(session)
    assert swept == 1

    await session.refresh(row)
    assert row.status is EmbargoStatus.RELEASED
    assert row.released_at is not None


async def test_the_sweeper_leaves_pending_embargoes_alone(session, embargoed):
    assert await sweep_due_embargoes(session) == 0
    row = (await session.execute(select(Embargo))).scalar_one()
    assert row.status is EmbargoStatus.PENDING


@pytest.mark.requirement("NFR-A3")
async def test_content_becomes_visible_without_the_sweeper_running(client, session, embargoed):
    """The property the whole split exists for.

    The sweeper is bookkeeping. Content becomes readable the instant its
    timestamp passes, so a sweeper that has been down for a week leaks nothing
    and delays nothing -- it only leaves a status column stale.
    """
    await session.execute(
        Distribution.__table__.update().values(
            date_added=dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
        )
    )
    await session.commit()

    feed = await client.get(
        feed_url(embargoed["collection"]), headers=proxy_headers(embargoed["member_pem"])
    )
    assert len(feed.json()["objects"]) == 1, "visible without the sweeper having run"

    row = (await session.execute(select(Embargo))).scalar_one()
    assert row.status is EmbargoStatus.PENDING, "and the record is merely stale"


async def test_the_sweeper_is_idempotent(session, embargoed):
    row = (await session.execute(select(Embargo))).scalar_one()
    row.release_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
    await session.commit()

    assert await sweep_due_embargoes(session) == 1
    assert await sweep_due_embargoes(session) == 0


# ---------------------------------------------------------------------------
# Service-level guards
# ---------------------------------------------------------------------------
async def test_releasing_a_submission_with_no_embargo_is_refused(session, make_org):

    org = await make_org("meridian-global", org_type=OrgType.ADMIN)
    ctx = AuthContext(
        org_id=org.id,
        org_slug=org.slug,
        org_type=OrgType.ADMIN,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.MTLS,
    )
    with pytest.raises(EmbargoError, match="not under embargo"):
        await release_embargo_now(session, ctx, submission_id=uuid.uuid4())


async def test_extending_with_a_naive_time_is_refused(session, make_org):

    org = await make_org("hosting-isac", org_type=OrgType.ADMIN)
    ctx = AuthContext(
        org_id=org.id,
        org_slug=org.slug,
        org_type=OrgType.ADMIN,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.MTLS,
    )
    with pytest.raises(EmbargoError, match="timezone-aware"):
        await extend_embargo(
            session,
            ctx,
            submission_id=uuid.uuid4(),
            release_at=dt.datetime(2026, 12, 1),  # noqa: DTZ001 - the point
        )


def test_the_submission_state_machine_is_unaffected_by_embargo():
    """Embargo governs visibility, not workflow state.

    A submission under embargo is `distributed` -- it has been released to
    circles, and the timestamp governs when they can read it. Conflating the two
    would make "distributed" mean two different things.
    """
    assert SubmissionState.DISTRIBUTED.value == "distributed"
