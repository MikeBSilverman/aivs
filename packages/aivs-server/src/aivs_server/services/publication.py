"""The lock that keeps ``date_added`` order and commit order the same.

TAXII polling is a keyset walk over ``(date_added, seq)`` that only ever moves
forward: a member echoes the last ``date_added`` it received as ``added_after``
and never looks back. That is only correct if no row can *become visible* with
a key below a cursor the server has already issued. Two things break it, and
this module is the answer to both.

**Two writers, one clock.** ``date_added`` is stamped (and ``seq`` assigned)
when a row is written, but the row becomes visible when its transaction
commits. If distribution A stamps first and commits second, a member polling
in between is handed a cursor past A's batch, and A's rows are never delivered
-- to exactly the members who poll correctly, while the receipts say they
simply never fetched it. Every writer of ``date_added`` therefore takes this
lock *exclusively* before reading the clock and holds it until commit, so
stamps are taken in commit order. The earlier argument that the ``seq``
identity made this impossible was wrong: identity values are assigned at
INSERT, not at COMMIT, so they order inserts, not visibility.

**A clock that moves under a writer.** Serialising writers is not enough on
its own. A timer embargo is a row whose ``date_added`` was stamped days ago in
the future; it becomes visible by the clock, with no transaction at all. If it
crosses ``now`` while A's transaction is open, a reader sees it, is issued a
cursor at the embargo's timestamp, and A -- stamped a moment earlier --
commits below that cursor. So readers that issue cursors take the same lock
*shared*: no cursor is computed while any publication is in flight, and any
publication that starts waits for the reading transaction to finish.

**One clock for all of it.** The lock orders transactions, not clocks. If
each process read its own clock, a replica running behind would stamp below a
cursor a replica running ahead had already issued, and the lock would have
ordered the two perfectly to no effect. So the clock is the database's, read
*after* the lock is taken, and both helpers return it: a writer stamps with the
instant ``hold_publication_lock`` returns, and a reader computes visibility and
cursors with the one ``wait_for_publications`` returns. See ``db.clock`` for
the one case this does not cover.

The cost is that a TAXII read and a distribution never overlap. Distributions
run hundreds of times a year and complete in milliseconds; a read waits at most
the length of one. The wait is bounded by the engine's ``lock_timeout``, so a
stuck writer surfaces as an error, not as a hang.

Writers: ``distribute_submission``, ``release_embargo_now``, ``extend_embargo``,
and ``sweep_due_embargoes`` (which holds an embargo by moving its rows later).
Readers: the four TAXII listings that compute ``X-TAXII-Date-Added-Last``.
A new writer or reader of ``distributions.date_added`` belongs on that list.
"""

from __future__ import annotations

import datetime as dt
from typing import Final

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.db.clock import database_now
from aivs_server.db.models import InstanceControl
from aivs_server.taxii.resources import truncate_to_taxii_precision

__all__ = [
    "PublicationPausedError",
    "earliest_publication_instant",
    "hold_publication_lock",
    "publication_paused",
    "wait_for_publications",
]

_ONE_MILLISECOND: Final[dt.timedelta] = dt.timedelta(milliseconds=1)


class PublicationPausedError(RuntimeError):
    """Distribution is paused instance-wide; nothing may be published."""


#: One fixed key for the whole instance. Publications are rare enough that a
#: single global lock costs nothing, and anything finer-grained (per circle)
#: would reopen the race for a submission distributed into two circles that a
#: member reads through one. The value is arbitrary but must never change while
#: an old and a new process can run side by side, as during a rolling deploy.
_PUBLICATION_LOCK_KEY: Final[int] = 0x41495653_00000001  # "AIVS", lock 1


async def hold_publication_lock(session: AsyncSession, *, refuse_while_paused: bool) -> dt.datetime:
    """Take the publication lock exclusively until this transaction ends; return the time.

    The returned instant is the database's clock, read under the lock: the
    "now" to stamp ``date_added`` from. A ``now`` read before the lock is
    acquired, or from the process's own clock, reopens the race this lock
    exists to close.

    ``refuse_while_paused`` is the caller's to state. Everything that makes
    content visible sooner refuses during a pause. Extending an embargo moves
    content later, so it is allowed: an editor who paused because embargoed
    content is at risk must be able to push it out before resuming, or every
    timer that passed during the pause opens at once on resume (Mike, end of
    Phase A).
    """
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:key)"), {"key": _PUBLICATION_LOCK_KEY}
    )
    # Checked under the lock, so a pause that commits while a writer waits is
    # seen by that writer rather than raced past.
    if refuse_while_paused and await publication_paused(session):
        msg = "distribution is paused instance-wide"
        raise PublicationPausedError(msg)
    return await database_now(session)


async def publication_paused(session: AsyncSession) -> bool:
    """Whether the instance's stop button is pressed."""
    paused = await session.scalar(
        select(InstanceControl.distribution_paused).where(InstanceControl.id == 1)
    )
    return bool(paused)


async def wait_for_publications(session: AsyncSession) -> dt.datetime:
    """Take the publication lock shared until this transaction ends; return the time.

    Call in any read that issues a paging cursor, and use the instant it
    returns -- the database's clock, read under the lock -- as the read's
    "now". Returns once no publication is in flight, and holds off new ones
    until the read's transaction ends.
    """
    await session.execute(
        text("SELECT pg_advisory_xact_lock_shared(:key)"), {"key": _PUBLICATION_LOCK_KEY}
    )
    return await database_now(session)


def earliest_publication_instant(now: dt.datetime) -> dt.datetime:
    """The earliest ``date_added`` a publication may be stamped with now.

    The next TAXII millisecond, never the current one. ``added_after`` is a
    strict comparison at millisecond precision: a reader in this millisecond
    can already have handed out ``X-TAXII-Date-Added-Last`` equal to it (for a
    row distributed earlier in it, or an embargo whose time has just arrived),
    and a row stamped with the same millisecond is then never delivered to that
    poller. The lock orders commits; it cannot separate two stamps that
    truncate to the same value. Early release learned this first; distribution
    did not, until review found the same tie there.
    """
    return truncate_to_taxii_precision(now) + _ONE_MILLISECOND
