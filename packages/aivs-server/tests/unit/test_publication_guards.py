"""What the review of Phase A found on the publication surface.

Each test is a pair. The defects: a distribution stamped in a millisecond a
reader had already reported; a sweeper that overwrote a concurrent extension
and announced releases during a pause; an early release that misdated an
elapsed one; and notifications to organisations that could not read what they
were told about.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import EmbargoPolicy, EmbargoStatus, OrgStatus, OrgType
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db import models
from aivs_server.notify.dispatcher import dispatch_pending
from aivs_server.notify.events import queue_visibility_notifications
from aivs_server.services.distribution import distribute_submission
from aivs_server.services.embargo import release_embargo_now, sweep_due_embargoes
from aivs_server.services.publication import hold_publication_lock
from aivs_server.taxii.resources import truncate_to_taxii_precision
from tests.conftest import StubEndpoint, is_blocked, proxy_headers

pytestmark = pytest.mark.db

NOW = dt.datetime(2026, 10, 13, 12, 0, 0, 400_000, tzinfo=dt.UTC)


async def _pause(session, paused: bool = True) -> None:
    control = await session.get(models.InstanceControl, 1)
    if control is None:
        control = models.InstanceControl(id=1)
        session.add(control)
    control.distribution_paused = paused
    await session.commit()


async def _embargoed(session, submission_id, release_at) -> models.Embargo:
    embargo = models.Embargo(
        submission_id=submission_id,
        policy=EmbargoPolicy.TIMER,
        status=EmbargoStatus.PENDING,
        release_at=release_at,
    )
    session.add(embargo)
    await session.commit()
    return embargo


# ---------------------------------------------------------------------------
# Stamping
# ---------------------------------------------------------------------------
async def test_a_distribution_is_stamped_after_the_current_millisecond(
    session, isac_ctx, make_validated, make_circle
):
    """A reader in this millisecond may already have reported it as
    X-TAXII-Date-Added-Last; a row stamped with it would never reach that
    poller. A future release time is kept as it is."""
    circle = await make_circle("sector")
    now_id, later_id = await make_validated("now"), await make_validated("later")
    later = NOW + dt.timedelta(hours=1)

    immediate = await distribute_submission(
        session,
        isac_ctx,
        await session.get(models.Submission, now_id),
        circle_ids=[circle.id],
        now=NOW,
    )
    embargoed = await distribute_submission(
        session,
        isac_ctx,
        await session.get(models.Submission, later_id),
        circle_ids=[circle.id],
        release_at=later,
        now=NOW,
    )

    assert immediate.date_added == truncate_to_taxii_precision(NOW) + dt.timedelta(milliseconds=1)
    assert embargoed.date_added == truncate_to_taxii_precision(later)


# ---------------------------------------------------------------------------
# The sweeper
# ---------------------------------------------------------------------------
async def test_the_sweeper_waits_for_an_open_publication(open_session, session, make_validated):
    submission_id = await make_validated("due")
    await _embargoed(session, submission_id, dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1))
    holder, sweeper = open_session(), open_session()

    await hold_publication_lock(holder)
    blocked, task = await is_blocked(sweep_due_embargoes(sweeper))
    await holder.rollback()
    released = await asyncio.wait_for(task, timeout=5)

    assert blocked, "the sweeper must serialise with extensions and releases"
    assert released == 1


async def test_a_paused_instance_releases_and_announces_nothing(
    session, make_validated, make_circle
):
    submission_id = await make_validated("due")
    embargo = await _embargoed(
        session, submission_id, dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
    )
    embargo_id = embargo.id

    await _pause(session)
    while_paused = await sweep_due_embargoes(session)
    await _pause(session, paused=False)
    after_resume = await sweep_due_embargoes(session)

    assert while_paused == 0
    assert after_resume == 1
    session.expire_all()
    assert (await session.get(models.Embargo, embargo_id)).status is EmbargoStatus.RELEASED


async def test_releasing_an_elapsed_embargo_records_when_it_really_became_visible(
    session, isac_ctx, make_validated
):
    elapsed_id, pending_id = await make_validated("elapsed"), await make_validated("pending")
    await _embargoed(session, elapsed_id, NOW - dt.timedelta(minutes=1))
    await _embargoed(session, pending_id, NOW + dt.timedelta(days=1))

    elapsed = await release_embargo_now(session, isac_ctx, submission_id=elapsed_id, now=NOW)
    early = await release_embargo_now(session, isac_ctx, submission_id=pending_id, now=NOW)

    assert (elapsed.status, elapsed.released_at) == (
        EmbargoStatus.RELEASED,
        NOW - dt.timedelta(minutes=1),
    )
    assert early.status is EmbargoStatus.LIFTED_EARLY


# ---------------------------------------------------------------------------
# Who is notified
# ---------------------------------------------------------------------------
async def _member_with_hook(session, make_org, join_circle, secret_box, circle, slug, status):
    org = await make_org(slug, org_type=OrgType.GSIB)
    await join_circle(org, circle)
    org.status = status
    hook_id = uuid.uuid4()
    session.add(
        models.Webhook(
            id=hook_id,
            org_id=org.id,
            url=f"https://{slug}.example/hook",
            hmac_secret_encrypted=secret_box.seal(
                "s" * 32, purpose=SecretPurpose.WEBHOOK_HMAC, subject=hook_id
            ),
            events=[],
        )
    )
    await session.commit()
    return hook_id


async def test_only_organisations_that_can_read_it_are_notified(
    session, make_org, make_circle, make_collection, join_circle, publish, secret_box
):
    circle = await make_circle("sector")
    await make_collection(circle)
    submitter = await make_org("submitter", org_type=OrgType.GSIB)
    submission, _obj, _dist = await publish(submitter, circle)
    hooks = {
        status: await _member_with_hook(
            session, make_org, join_circle, secret_box, circle, f"m-{status.value}", status
        )
        for status in (OrgStatus.ACTIVE, OrgStatus.QUARANTINED, OrgStatus.SUSPENDED)
    }

    await queue_visibility_notifications(
        session,
        submission_id=submission.id,
        circle_ids=[circle.id],
        visible_at=dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1),
    )
    await session.commit()

    queued = set((await session.execute(select(models.WebhookDelivery.webhook_id))).scalars())
    assert queued == {hooks[OrgStatus.ACTIVE]}


async def test_a_deactivated_circle_notifies_nobody(
    session, make_org, make_circle, make_collection, join_circle, publish, secret_box
):
    circle = await make_circle("retired")
    await make_collection(circle)
    submitter = await make_org("submitter", org_type=OrgType.GSIB)
    submission, _obj, _dist = await publish(submitter, circle)
    await _member_with_hook(
        session, make_org, join_circle, secret_box, circle, "member", OrgStatus.ACTIVE
    )
    circle.is_active = False
    await session.commit()

    queued = await queue_visibility_notifications(
        session,
        submission_id=submission.id,
        circle_ids=[circle.id],
        visible_at=dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1),
    )

    assert queued == 0


async def test_a_pause_holds_members_deliveries_but_not_the_isacs(
    session,
    settings,
    make_org,
    secret_box,
    member_endpoint,
):
    """The ISAC must still hear its own alerts -- among them, that someone
    pressed the stop button."""
    endpoint = member_endpoint(StubEndpoint(status_code=204))
    queued: dict[str, uuid.UUID] = {}
    for slug, org_type in (("the-isac", OrgType.ADMIN), ("a-member", OrgType.GSIB)):
        org = await make_org(slug, org_type=org_type)
        hook_id = uuid.uuid4()
        session.add(
            models.Webhook(
                id=hook_id,
                org_id=org.id,
                url="https://example.com/hook",
                hmac_secret_encrypted=secret_box.seal(
                    "s" * 32, purpose=SecretPurpose.WEBHOOK_HMAC, subject=hook_id
                ),
                events=[],
            )
        )
        await session.flush()
        delivery = models.WebhookDelivery(webhook_id=hook_id, event="e", payload={"event": "e"})
        session.add(delivery)
        await session.flush()
        queued[slug] = delivery.id
    await session.commit()
    await _pause(session)

    sent_while_paused = await dispatch_pending(session, settings)
    await _pause(session, paused=False)
    sent_after = await dispatch_pending(session, settings)

    assert sent_while_paused == 1
    assert sent_after == 1
    assert len(endpoint.requests) == 2


# ---------------------------------------------------------------------------
# The lock at the call sites (Phase A review: tested only by calling the helper)
# ---------------------------------------------------------------------------
async def test_a_taxii_page_waits_for_an_open_publication_and_not_otherwise(
    client, open_session, make_org, make_cert, make_circle, make_collection, join_circle
):
    member = await make_org("poller", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    circle = await make_circle("sector")
    collection = await make_collection(circle)
    await join_circle(member, circle)
    objects = f"/taxii2/aivs/collections/{collection.id}/objects/"
    headers = proxy_headers(pem)

    idle, _task = await is_blocked(client.get(objects, headers=headers))
    holder = open_session()
    await hold_publication_lock(holder)
    blocked, task = await is_blocked(client.get(objects, headers=headers))
    await holder.rollback()
    page = await asyncio.wait_for(task, timeout=5)

    assert idle is False
    assert blocked is True, "a cursor-issuing read must wait for the publication"
    assert page.status_code == 200


async def test_extending_an_embargo_waits_for_an_open_publication(
    open_session, session, isac_ctx, make_validated
):
    from aivs_server.services.embargo import extend_embargo  # noqa: PLC0415 - one test

    submission_id = await make_validated("held")
    await _embargoed(session, submission_id, dt.datetime.now(dt.UTC) + dt.timedelta(days=1))
    holder, extender = open_session(), open_session()

    await hold_publication_lock(holder)
    blocked, task = await is_blocked(
        extend_embargo(
            extender,
            isac_ctx,
            submission_id=submission_id,
            release_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=2),
        )
    )
    await holder.rollback()
    await asyncio.wait_for(task, timeout=5)

    assert blocked is True
