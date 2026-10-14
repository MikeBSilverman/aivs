"""The one clock that ``date_added`` and membership intervals are compared on.

Visibility is a comparison of stored instants: ``date_added`` against a
reader's "now", against a cursor another reader issued, and against
``joined_at`` and ``left_at``. Each of those used to come from whichever
process wrote or read it -- each app replica's Python clock, or the database's
``now()`` where a column default filled it in. Two replicas whose clocks
disagree, or one NTP step backwards, then let a writer stamp a row below a
cursor a reader had already handed out, and ``added_after`` polling never looks
back: the row is never delivered. The publication lock orders transactions; it
cannot order clocks.

So every instant that takes part in those comparisons is read here, from the
database host, which every replica shares. ``clock_timestamp()`` rather than
``now()``: ``now()`` is the *transaction's* start, and a writer that waited on
a lock would stamp the moment it began waiting, before whatever it waited for.
Read it after the lock the comparison depends on.

What this does not cover: a step backwards of the database host's own clock.
Every replica then agrees on the wrong time, and a row stamped after the step
can land below a cursor issued before it. Keep that host on NTP that slews
rather than steps.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

__all__ = ["database_now"]


async def database_now(session: AsyncSession) -> dt.datetime:
    """The database host's wall clock, read now, as an aware UTC datetime."""
    instant: dt.datetime = (await session.execute(text("SELECT clock_timestamp()"))).scalar_one()
    return instant.astimezone(dt.UTC)
