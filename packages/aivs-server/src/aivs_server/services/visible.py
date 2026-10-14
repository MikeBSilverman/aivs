"""The stored objects a caller may read, for views computed from them.

Readiness and the vulnerability page are both conclusions drawn from content,
and each must draw them only from what the caller could have read for itself:
a conclusion drawn from more tells the caller that the rest exists. They share
this one scope so that the page can never show an object that readiness was
not allowed to count, or the other way round.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import Select, and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import VISIBLE_SUBMISSION_STATES
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import can_review_submissions, distribution_visibility_clause
from aivs_server.db.models import Distribution, StixObject, Submission

__all__ = ["related_stix_ids", "visible_objects"]


def visible_objects(ctx: AuthContext, now: dt.datetime) -> Select[Any]:
    """Every stored object ``ctx`` may read, as a select over ``StixObject``.

    A member reads what was distributed to it, through the visibility clause,
    which also carries an SSO session's TLP ceiling. The ISAC's reviewers read
    every distributed object, whatever circle it went to: the sector's view is
    what they triage against.

    One row per distribution, so ``Distribution.date_added`` is there to read:
    an object reaches a member once per circle, and "when was this shared with
    us" is the earliest of those the member can see.
    """
    query = (
        select(StixObject)
        .join(Submission, Submission.id == StixObject.submission_id)
        .join(Distribution, Distribution.stix_object_id == StixObject.id)
    )
    if can_review_submissions(ctx):
        return query.where(Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)))
    return query.where(distribution_visibility_clause(ctx, now))


async def related_stix_ids(session: AsyncSession, visible: Select[Any], stix_id: str) -> list[str]:
    """The ids at the other end of every ``relationship`` in ``visible`` that touches ``stix_id``.

    Only the relationship is held to ``visible`` here. The objects it names are
    not: a caller who reads a relationship has not thereby been given the
    object at its other end, so every caller looks those up through ``visible``
    again.
    """
    source = StixObject.raw["source_ref"].astext
    target = StixObject.raw["target_ref"].astext
    rows = (
        await session.execute(
            visible.with_only_columns(source, target).where(
                StixObject.type == "relationship",
                or_(source == stix_id, target == stix_id),
                and_(source.is_not(None), target.is_not(None)),
            )
        )
    ).all()
    return sorted(
        {target_ref if source_ref == stix_id else source_ref for source_ref, target_ref in rows}
    )
