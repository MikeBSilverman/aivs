"""Published counts: k-anonymous numbers that one firm's change cannot move.

A k-anonymous count read live can still be subtracted (review R2-C1, Q6). An
ISAC reviewer reads "7 patched", sees a firm's audited posture write, reads "8
patched", and knows that firm is patched. An editor suspends a firm and every
count that drops by one names something it did. Suppression below K does not
help: each count stays above K throughout.

So counts are read from a published snapshot, and a snapshot is replaced only
once at least K organisations' contributions differ from it (Mike, 2026-10-14:
"a day-old count is ok"). Whatever moves between two published snapshots is
the sum of at least K firms' changes. The snapshot also fixes the population:
a firm suspended after it was taken is still counted in it, so a status change
alone moves nothing.

The comparison is per organisation, not per total. Two firms swapping
statuses leave every total unchanged, but they are two changes, and they still
count toward the K that lets the next snapshot be published.

What this does not stop: an observer who sees at least K firms change (a
known coordinated patch day, say) learns the sum of their changes, which is
what a k-anonymous count is meant to show.

Callers build the live basis, ``{org_id: contribution}``, and decide what it
counts; this module only keeps, compares and replaces it.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.db.models import CountSnapshot, CountSubject

__all__ = [
    "K_ANONYMITY",
    "Published",
    "changed_organisations",
    "forget_organisation",
    "publish_if_changed",
    "published",
    "should_publish",
]

#: The smallest group a count may describe, everywhere (plan, Appendix F rule
#: 11). Defined here, beside the rule that publishes counts, and re-exported by
#: ``services.telemetry``.
K_ANONYMITY: Final[int] = 5


@dataclass(frozen=True, slots=True)
class Published:
    """The basis last published for one subject, and when."""

    basis: Mapping[str, str]
    taken_at: dt.datetime


def changed_organisations(old: Mapping[str, str], new: Mapping[str, str]) -> int:
    """How many organisations contribute differently, joining or leaving included."""
    return sum(1 for org in old.keys() | new.keys() if old.get(org) != new.get(org))


def should_publish(old: Mapping[str, str] | None, new: Mapping[str, str]) -> bool:
    """Replace the published basis only once K organisations differ from it.

    A subject never published counts as an empty basis, so its first snapshot
    waits for K contributions like every later one. Until then every count
    about it would be withheld below K anyway.
    """
    return changed_organisations(old or {}, new) >= K_ANONYMITY


async def published(session: AsyncSession, kind: CountSubject, subject_id: str) -> Published | None:
    row = await session.get(CountSnapshot, (kind.value, subject_id))
    if row is None:
        return None
    return Published(basis=row.basis, taken_at=row.taken_at)


async def publish_if_changed(
    session: AsyncSession,
    kind: CountSubject,
    subject_id: str,
    basis: Mapping[str, str],
    *,
    now: dt.datetime,
) -> bool:
    """Publish ``basis`` if enough has changed; return whether it was. Does not commit."""
    row = await session.get(CountSnapshot, (kind.value, subject_id), with_for_update=True)
    if not should_publish(None if row is None else row.basis, basis):
        return False
    if row is None:
        session.add(
            CountSnapshot(
                subject_kind=kind.value, subject_id=subject_id, taken_at=now, basis=dict(basis)
            )
        )
    else:
        row.basis = dict(basis)
        row.taken_at = now
    return True


async def forget_organisation(session: AsyncSession, org_id: str) -> None:
    """Remove one organisation from every basis, for offboarding. Does not commit.

    The next comparison then counts it as one organisation that left, which is
    what it did.
    """
    await session.execute(
        update(CountSnapshot)
        .where(CountSnapshot.basis.has_key(org_id))
        .values(basis=CountSnapshot.basis.op("-")(org_id))
    )
