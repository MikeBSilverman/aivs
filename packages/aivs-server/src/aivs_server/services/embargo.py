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
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import Distribution, Embargo
from aivs_server.notify.events import (
    circle_ids_for_submission,
    queue_visibility_notifications,
)
from aivs_server.services.publication import hold_publication_lock
from aivs_server.taxii.resources import truncate_to_taxii_precision

__all__ = [
    "EmbargoError",
    "extend_embargo",
    "record_embargo",
    "release_embargo_now",
    "sweep_due_embargoes",
]

logger = logging.getLogger(__name__)

#: One tick of the precision TAXII timestamps carry. Used to place an
#: early-released row strictly ahead of every cursor that can already exist.
_ONE_MILLISECOND: Final[dt.timedelta] = dt.timedelta(milliseconds=1)


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
    # Before the clock is read: see services.publication.
    await hold_publication_lock(session)
    now = now or dt.datetime.now(dt.UTC)
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
    released_at = truncate_to_taxii_precision(now) + _ONE_MILLISECOND

    embargo = (
        await session.execute(select(Embargo).where(Embargo.submission_id == submission_id))
    ).scalar_one_or_none()
    if embargo is None:
        msg = "this submission is not under embargo"
        raise EmbargoError(msg)
    if embargo.status in (EmbargoStatus.RELEASED, EmbargoStatus.LIFTED_EARLY):
        msg = "this embargo has already been released"
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
    # Before the clock is read: the "already visible" test below compares
    # against it. See services.publication.
    await hold_publication_lock(session)
    now = now or dt.datetime.now(dt.UTC)
    if release_at.tzinfo is None:
        msg = "release_at must be timezone-aware"
        raise EmbargoError(msg)

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


async def sweep_due_embargoes(session: AsyncSession, *, now: dt.datetime | None = None) -> int:
    """Mark embargoes whose time has arrived as released. Returns the count.

    Bookkeeping only. The content became visible the instant its ``date_added``
    passed, whether or not this ever runs — so a sweeper that has been down for
    a week leaks nothing, and catches up in one pass when it returns.

    It exists so the operator console and the audit trail say ``released``
    rather than ``pending`` for content members can already read.
    """
    now = now or dt.datetime.now(dt.UTC)

    due = (
        (
            await session.execute(
                select(Embargo).where(
                    Embargo.status.in_((EmbargoStatus.PENDING, EmbargoStatus.EXTENDED)),
                    Embargo.release_at.is_not(None),
                    Embargo.release_at <= now,
                )
            )
        )
        .scalars()
        .all()
    )

    for embargo in due:
        embargo.status = EmbargoStatus.RELEASED
        embargo.released_at = embargo.release_at
        # The third moment content becomes visible, and the one nobody is
        # watching: a timed release happens without an operator present, so if
        # the sweeper does not queue the notification, nothing does.
        await queue_visibility_notifications(
            session,
            submission_id=embargo.submission_id,
            circle_ids=await circle_ids_for_submission(session, embargo.submission_id),
            visible_at=embargo.release_at or now,
            now=now,
        )
        await record(
            session,
            action=AuditAction.EMBARGO_RELEASED,
            actor_type="system",
            resource_type="submission",
            resource_id=str(embargo.submission_id),
            details={
                "released_at": embargo.release_at.isoformat() if embargo.release_at else None,
                "early": False,
            },
        )

    if due:
        await session.commit()
        logger.info("embargo sweep released %d submission(s)", len(due))

    return len(due)
