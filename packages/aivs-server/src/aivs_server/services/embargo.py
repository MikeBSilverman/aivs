"""Embargo records, early release, and the release sweeper.

Two things carry an embargo, and keeping them straight is the whole design:

**Visibility is the timestamp.** ``distributions.date_added`` in the future is
what actually makes content unreadable, and it is checked on every read. Nothing
here is required for the embargo to hold.

**The ``embargoes`` row is the record.** Policy, status, coordination notes, and
when it was released — the operator's view, and the audit trail's. If the
sweeper never runs, the embargo still holds; the row just says ``pending``
longer than it should.

That split is why the sweeper is safe to be down, and it is the reason to resist
"simplifying" this into a single flag that the reader consults.

On moving ``date_added`` around, which looks symmetric and is not:

* **Releasing early is safe, provided it moves strictly ahead.** An embargoed
  row's timestamp is in the future, so no member's polling cursor can have
  passed it. The ``seq`` tiebreaker does *not* rescue the same-instant case, as
  this docstring once claimed: a released row keeps the ``seq`` it was given at
  distribution time, which is lower than anything distributed since, so at an
  equal ``date_added`` it sorts *below* a current cursor. ``release_embargo_now``
  therefore stamps the millisecond after ``now`` rather than ``now`` itself.
* **Backdating at distribution time is not**, which is why
  ``distribute_submission`` refuses it: there the timestamp can land below
  cursors members are already past, and ``added_after`` never looks backwards.
* **Extending after release is not**, because members already hold the content.
  Retracting visibility would be a false promise, exactly as withdrawal is after
  distribution.

**Release re-checks the content rules** (``services.content_rules``) that
distribution checked, because an embargo runs for days and what they are
decided by moves: a target withdrawn from disclosure, a referent re-marked
stricter. Release used to rely on the check made at distribution (W-P1).

* Early release is an operator's act, so it re-checks and refuses, saying why.
* A timer releases by the clock, with no transaction to refuse in -- the
  property that lets the sweeper be down (NFR-A3). So the sweeper re-checks
  every embargo still on its timer on every pass, and one that no longer passes
  is *held* before its time arrives: its rows move to
  ``HELD_UNTIL_RELEASED``, out of the clock's reach, the embargo becomes
  ``manual`` with no release time, and the ISAC is told (an ``embargo.held``
  audit row and a warning). An operator then releases it early, which
  re-checks again, or extends it, which puts it back on a timer. Holding moves
  content later, so it runs during a pause, as an extension may.
* What this cannot catch: a rule that stops holding within one sweep interval
  of the release time, or while the sweeper is down. That content becomes
  readable on time, as NFR-A3 promises; the release is still recorded, and
  ``content_problem`` in its audit row says what no longer holds, so the ISAC
  learns of it. Closing that window means making release a write the sweeper
  performs, which trades NFR-A3 away; that is a decision, not a fix.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Final

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import EmbargoPolicy, EmbargoStatus
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.attribution_key import AttributionKey
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import Distribution, Embargo, StixObject, Submission
from aivs_server.notify.events import (
    circle_ids_for_submission,
    queue_visibility_notifications,
)
from aivs_server.services.attribution import submitter_of
from aivs_server.services.content_rules import content_problem
from aivs_server.services.publication import (
    earliest_publication_instant,
    hold_publication_lock,
    publication_paused,
    release_out_of_range,
)
from aivs_server.taxii.resources import truncate_to_taxii_precision

__all__ = [
    "HELD_UNTIL_RELEASED",
    "EmbargoError",
    "extend_embargo",
    "record_embargo",
    "release_embargo_now",
    "release_problem",
    "sweep_due_embargoes",
]

logger = logging.getLogger(__name__)

#: Where a held embargo's rows wait. Beyond any timer, so the clock never
#: releases them; and still a future ``date_added``, so everything that reads
#: "embargoed" as ``date_added > now`` (the ownership and disclosure rules, the
#: AI gate's previous version) goes on reading it that way. Moving rows here is
#: safe for the reason extension is: they are not yet visible.
HELD_UNTIL_RELEASED: Final[dt.datetime] = dt.datetime(9999, 12, 31, tzinfo=dt.UTC)


class EmbargoError(ValueError):
    """An embargo operation was refused for a reason the operator can act on."""


async def record_embargo(
    session: AsyncSession,
    *,
    submission_id: uuid.UUID,
    release_at: dt.datetime,
    policy: EmbargoPolicy = EmbargoPolicy.TIMER,
    coordination_notes: str | None = None,
) -> Embargo:
    """Create or replace the embargo record for a submission.

    Called by the distribution service when a future release time is given.
    Writes into the caller's transaction so the record lands with the
    distribution rows it describes.
    """
    existing = (
        await session.execute(select(Embargo).where(Embargo.submission_id == submission_id))
    ).scalar_one_or_none()

    if existing is not None:
        existing.policy = policy
        existing.release_at = release_at
        existing.status = EmbargoStatus.PENDING
        existing.coordination_notes = coordination_notes
        return existing

    embargo = Embargo(
        submission_id=submission_id,
        policy=policy,
        status=EmbargoStatus.PENDING,
        release_at=release_at,
        coordination_notes=coordination_notes,
    )
    session.add(embargo)
    return embargo


async def release_embargo_now(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    key: AttributionKey,
    submission_id: uuid.UUID,
    reason: str | None = None,
    now: dt.datetime | None = None,
) -> Embargo:
    """Release an embargoed submission immediately.

    The operational escape hatch: when a finding starts being exploited in the
    wild, an ISAC must be able to push it without waiting for a timer it set
    days ago.

    Safe in the direction it moves. See the module docstring.
    """
    # The lock first, and the clock is the database's, read under it: see
    # services.publication. ``now`` is injectable for tests only.
    locked_at = await hold_publication_lock(session, refuse_while_paused=True)
    now = now or locked_at
    # The next millisecond, not this one. A released row keeps the `seq` it was
    # given when it was *distributed*, which is necessarily lower than that of
    # anything distributed since -- so the monotonic tiebreaker does not help
    # here, contrary to what this module used to claim. Stamping the current
    # millisecond meant that releasing early in the same millisecond as an
    # unrelated distribution ("this is being exploited, push everything now" is
    # exactly that shape) put the released rows at (T, low_seq) below a member's
    # cursor at (T, high_seq), and they were never delivered. One millisecond
    # ahead is strictly greater than every cursor that can already exist: a
    # cursor is only issued for a row that is visible, and the publication lock
    # (taken above, and shared by every cursor-issuing read) means no cursor is
    # being computed while this transaction is open. Without the lock that claim
    # was false -- a distribution committing after this one could still land
    # its rows below a cursor issued in between.
    released_at = earliest_publication_instant(now)

    embargo = (
        await session.execute(select(Embargo).where(Embargo.submission_id == submission_id))
    ).scalar_one_or_none()
    if embargo is None:
        msg = "this submission is not under embargo"
        raise EmbargoError(msg)
    if embargo.status in (EmbargoStatus.RELEASED, EmbargoStatus.LIFTED_EARLY):
        msg = "this embargo has already been released"
        raise EmbargoError(msg)
    if embargo.release_at is not None and embargo.release_at <= now:
        # Due but not yet swept: members have been able to read it since
        # release_at. Recording an *early* release now would misstate when they
        # could, in the record that exists to say exactly that.
        return await _record_elapsed_release(session, ctx, embargo, reason=reason)
    problem = await release_problem(session, key, submission_id, now=now)
    if problem is not None:
        logger.warning(
            "early release refused: the content no longer passes the rules distribution checked",
            extra={"submission_id": str(submission_id), "reason": problem},
        )
        msg = f"not released: {problem}"
        raise EmbargoError(msg)

    # Only rows still in the future move; anything already visible keeps the
    # timestamp members have been polling against.
    await session.execute(
        update(Distribution)
        .where(
            Distribution.submission_id == submission_id,
            Distribution.date_added > released_at,
        )
        .values(date_added=released_at)
    )

    embargo.status = EmbargoStatus.LIFTED_EARLY
    embargo.released_at = released_at

    await record(
        session,
        action=AuditAction.EMBARGO_RELEASED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission_id),
        details={
            "released_at": released_at.isoformat(),
            "originally_due": embargo.release_at.isoformat() if embargo.release_at else None,
            "early": True,
            "reason": reason,
        },
    )
    return embargo


async def _record_elapsed_release(
    session: AsyncSession, ctx: AuthContext, embargo: Embargo, *, reason: str | None
) -> Embargo:
    """Record, on the operator's request, a release that already happened.

    Nothing about visibility changes. The sweeper would have written this row;
    once the status says released it never will, so it is written here.
    """
    embargo.status = EmbargoStatus.RELEASED
    embargo.released_at = embargo.release_at
    await record(
        session,
        action=AuditAction.EMBARGO_RELEASED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(embargo.submission_id),
        details={
            "released_at": embargo.release_at.isoformat() if embargo.release_at else None,
            "early": False,
            "reason": reason,
        },
    )
    return embargo


async def extend_embargo(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    submission_id: uuid.UUID,
    release_at: dt.datetime,
    reason: str | None = None,
    now: dt.datetime | None = None,
) -> Embargo:
    """Push an embargo's release time further out.

    Refused once released, and refused if it would move the time backwards --
    members poll forwards only, so a retraction is not something the system can
    honestly offer.
    """
    # The lock first, and the clock is the database's, read under it: the
    # "already visible" tests below compare against it, and a replica whose
    # own clock lagged would find content members already hold still in the
    # future, and move it back there. See services.publication.
    locked_at = await hold_publication_lock(session, refuse_while_paused=False)
    now = now or locked_at
    if release_at.tzinfo is None:
        msg = "release_at must be timezone-aware"
        raise EmbargoError(msg)
    too_late = release_out_of_range(release_at)
    if too_late is not None:
        raise EmbargoError(too_late)

    target = truncate_to_taxii_precision(release_at)
    if target <= now:
        msg = "an extension must be in the future"
        raise EmbargoError(msg)

    embargo = (
        await session.execute(select(Embargo).where(Embargo.submission_id == submission_id))
    ).scalar_one_or_none()
    if embargo is None:
        msg = "this submission is not under embargo"
        raise EmbargoError(msg)
    if embargo.status in (EmbargoStatus.RELEASED, EmbargoStatus.LIFTED_EARLY):
        # Members already hold it. Pretending otherwise would be a false
        # promise, exactly as withdrawal is after distribution.
        msg = "this embargo has already been released and cannot be reinstated"
        raise EmbargoError(msg)
    if embargo.release_at is not None and target < embargo.release_at:
        msg = "an embargo can be extended but not shortened; release it early instead"
        raise EmbargoError(msg)
    if embargo.release_at is not None and embargo.release_at <= now:
        # Status is bookkeeping the sweeper writes; visibility is
        # `date_added <= now`, evaluated per read. Between the release moment
        # passing and the sweeper's next pass -- up to
        # embargo_sweep_interval_seconds, or indefinitely if the sweeper is
        # erroring -- an elapsed embargo is still PENDING while its content is
        # already being served. Testing only the status let an extension in that
        # window move content members had already retrieved back into the
        # future, which is the retraction this module says it will not offer.
        msg = (
            "this embargo's release time has already passed; members can "
            "already read the content and it cannot be reinstated"
        )
        raise EmbargoError(msg)

    await session.execute(
        update(Distribution)
        .where(
            Distribution.submission_id == submission_id,
            # Never move a row that is already visible, whatever the status says.
            Distribution.date_added > now,
        )
        .values(date_added=target)
    )

    previous = embargo.release_at
    embargo.release_at = target
    embargo.status = EmbargoStatus.EXTENDED
    # A held embargo goes back on a timer, and the sweeper checks it again.
    embargo.policy = EmbargoPolicy.TIMER

    await record(
        session,
        action=AuditAction.EMBARGO_EXTENDED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission_id),
        details={
            "from": previous.isoformat() if previous else None,
            "to": target.isoformat(),
            "reason": reason,
        },
    )
    return embargo


async def release_problem(
    session: AsyncSession, key: AttributionKey, submission_id: uuid.UUID, *, now: dt.datetime
) -> str | None:
    """Why this submission's held content may not become readable now, or ``None``."""
    submission = await session.get(Submission, submission_id)
    if submission is None:
        return "the embargoed submission no longer exists"
    raws = list(
        (
            await session.execute(
                select(StixObject.raw).where(StixObject.submission_id == submission_id)
            )
        ).scalars()
    )
    # The sweeper runs on the staff login, which reads who filed what.
    filer = await submitter_of(session, submission)
    return await content_problem(session, submission, raws, filer=filer, now=now, key=key)


async def sweep_due_embargoes(
    session: AsyncSession, key: AttributionKey, *, now: dt.datetime | None = None
) -> int:
    """Hold what no longer passes, then mark what has come due released. Returns the count released.

    Releasing is bookkeeping. The content became visible the instant its
    ``date_added`` passed, whether or not this ever runs -- so a sweeper that
    has been down for a week leaks nothing, and catches up in one pass when it
    returns. It exists so the operator console and the audit trail say
    ``released`` rather than ``pending`` for content members can already read,
    and so the release is announced.

    Holding is not bookkeeping: it is the only check a timer gets before the
    clock releases it. See the module docstring.

    It takes the publication lock and the rows' locks, like every other writer
    of an embargo. Without them an extension committing between this read and
    its write was overwritten: the embargo said released, members were told to
    poll for content still held, and both operator controls then refused it as
    already released. While distribution is paused it releases nothing, so no
    member is told that anything exists, and catches up on resume; it still
    holds, because resuming makes every timer that elapsed during the pause
    readable at once, before a later pass could.
    """
    # Not refused while paused: holding moves content later. Releasing is
    # skipped below instead.
    locked_at = await hold_publication_lock(session, refuse_while_paused=False)
    now = now or locked_at

    held = await _hold_timers_that_no_longer_pass(session, key, now=now)
    released = 0 if await publication_paused(session) else await _release_due(session, key, now=now)

    # Always: the commit is also what releases the publication lock.
    await session.commit()
    if held or released:
        logger.info("embargo sweep held %d and released %d submission(s)", held, released)
    return released


async def _hold_timers_that_no_longer_pass(
    session: AsyncSession, key: AttributionKey, *, now: dt.datetime
) -> int:
    """Hold every embargo still on its timer whose content no longer passes. Returns the count.

    One embargo's refusal is a hold, never an exception, so it cannot stop the
    pass reaching the others.
    """
    pending = (
        (
            await session.execute(
                select(Embargo)
                .where(
                    Embargo.policy == EmbargoPolicy.TIMER,
                    Embargo.status.in_((EmbargoStatus.PENDING, EmbargoStatus.EXTENDED)),
                    Embargo.release_at > now,
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    held = 0
    for embargo in pending:
        problem = await release_problem(session, key, embargo.submission_id, now=now)
        if problem is not None:
            await _hold(session, embargo, problem=problem, now=now)
            held += 1
    return held


async def _hold(session: AsyncSession, embargo: Embargo, *, problem: str, now: dt.datetime) -> None:
    """Take an embargo off its timer until an operator decides, and say why."""
    await session.execute(
        update(Distribution)
        .where(Distribution.submission_id == embargo.submission_id, Distribution.date_added > now)
        .values(date_added=HELD_UNTIL_RELEASED)
    )
    originally_due = embargo.release_at
    embargo.policy = EmbargoPolicy.MANUAL
    embargo.release_at = None
    await record(
        session,
        action=AuditAction.EMBARGO_HELD,
        actor_type="system",
        resource_type="submission",
        resource_id=str(embargo.submission_id),
        details={
            "reason": problem,
            "originally_due": originally_due.isoformat() if originally_due else None,
        },
    )
    logger.warning(
        "embargo held: its content no longer passes the rules distribution checked",
        extra={"submission_id": str(embargo.submission_id), "reason": problem},
    )


async def _release_due(session: AsyncSession, key: AttributionKey, *, now: dt.datetime) -> int:
    """Record and announce every embargo whose time has arrived. Returns the count."""
    due = (
        (
            await session.execute(
                select(Embargo)
                .where(
                    Embargo.status.in_((EmbargoStatus.PENDING, EmbargoStatus.EXTENDED)),
                    Embargo.release_at.is_not(None),
                    Embargo.release_at <= now,
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for embargo in due:
        await _record_timed_release(session, key, embargo, now=now)
    return len(due)


async def _record_timed_release(
    session: AsyncSession, key: AttributionKey, embargo: Embargo, *, now: dt.datetime
) -> None:
    """Mark one elapsed embargo released, announce it, and report a rule it now fails."""
    embargo.status = EmbargoStatus.RELEASED
    embargo.released_at = embargo.release_at
    # The third moment content becomes visible, and the one nobody is
    # watching: a timed release happens without an operator present, so if
    # the sweeper does not queue the notification, nothing does.
    await queue_visibility_notifications(
        session,
        key=key,
        submission_id=embargo.submission_id,
        circle_ids=await circle_ids_for_submission(session, embargo.submission_id),
        visible_at=embargo.release_at or now,
        now=now,
    )
    details: dict[str, object] = {
        "released_at": embargo.release_at.isoformat() if embargo.release_at else None,
        "early": False,
    }
    # Already readable by the clock, so not retracted; but a rule that stopped
    # holding inside the last sweep interval (or while this was down) is the
    # ISAC's to know about.
    problem = await release_problem(session, key, embargo.submission_id, now=now)
    if problem is not None:
        details["content_problem"] = problem
        logger.warning(
            "embargo released by its timer although its content no longer passes the rules",
            extra={"submission_id": str(embargo.submission_id), "reason": problem},
        )
    await record(
        session,
        action=AuditAction.EMBARGO_RELEASED,
        actor_type="system",
        resource_type="submission",
        resource_id=str(embargo.submission_id),
        details=details,
    )
