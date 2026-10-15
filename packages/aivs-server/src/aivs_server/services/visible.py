"""The stored objects a caller may read, for views computed from them.

Readiness, the vulnerability page, the evidence pack, the IoC pack and the
guided view are all conclusions drawn from content, and each must draw them
only from what the caller could have read for itself: a conclusion drawn from
more tells the caller that the rest exists. They share this one scope so that
no view can show an object another was not allowed to count.

Two of them were written separately once (review H2-3), and had drifted:
readiness and the page followed a relationship through any version the caller
could see, so a link its owner had revoked or re-pointed still connected the
old object, while the IoC pack followed only the latest. Which objects are
related is now decided here too, in two named ways: as things stand
(``related_stix_ids``) and as they ever were (``ever_related_stix_ids``, for
the evidence pack, which is the record of what arrived).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from typing import Any

from sqlalchemy import Select, and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import VISIBLE_SUBMISSION_STATES
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import can_review_submissions, distribution_visibility_clause
from aivs_server.db.models import Distribution, StixObject, Submission

__all__ = [
    "VulnerabilityNotVisibleError",
    "ever_related_stix_ids",
    "related_stix_ids",
    "require_visible_vulnerability",
    "visible_objects",
]


class VulnerabilityNotVisibleError(LookupError):
    """The caller cannot see a vulnerability with that id -- or none exists.

    One error for both, deliberately: a distinct answer for "exists but not
    visible" would confirm a pre-CVE finding to an outsider (SF-47).
    """


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


async def require_visible_vulnerability(
    session: AsyncSession, visible: Select[Any], stix_id: str
) -> None:
    """Raise :class:`VulnerabilityNotVisibleError` unless ``visible`` holds that vulnerability."""
    found = await session.scalar(
        visible.with_only_columns(StixObject.id)
        .where(StixObject.stix_id == stix_id, StixObject.type == "vulnerability")
        .limit(1)
    )
    if found is None:
        raise VulnerabilityNotVisibleError(stix_id)


async def related_stix_ids(session: AsyncSession, visible: Select[Any], stix_id: str) -> list[str]:
    """The ids ``stix_id`` is related to now, through relationships in ``visible``.

    Each relationship counts as its latest version in ``visible`` says: one its
    owner revoked connects nothing, and one re-pointed connects what it points
    at now. The objects it names are not held to ``visible`` here; a caller
    who reads a relationship has not thereby been given the object at its
    other end, so every caller looks those up through ``visible`` again.
    """
    touching = _touching(visible, stix_id).with_only_columns(StixObject.stix_id).distinct()
    rows = (
        await session.execute(
            visible.with_only_columns(
                StixObject.stix_id, StixObject.modified, StixObject.raw
            ).where(StixObject.stix_id.in_(touching.scalar_subquery()))
        )
    ).all()
    latest: dict[str, tuple[dt.datetime, Mapping[str, Any]]] = {}
    for relationship_id, modified, raw in rows:
        if relationship_id not in latest or modified > latest[relationship_id][0]:
            latest[relationship_id] = (modified, raw)
    return sorted(
        {
            other_end
            for _, raw in latest.values()
            if not raw.get("revoked") and (other_end := _other_end(raw, stix_id)) is not None
        }
    )


async def ever_related_stix_ids(
    session: AsyncSession, visible: Select[Any], stix_id: str
) -> list[str]:
    """The ids any version of a relationship in ``visible`` ever related to ``stix_id``.

    For the evidence pack, which records what reached the organisation,
    including links later revoked. Views of the vulnerability as it stands use
    :func:`related_stix_ids`.
    """
    source = StixObject.raw["source_ref"].astext
    target = StixObject.raw["target_ref"].astext
    rows = (
        await session.execute(
            _touching(visible, stix_id)
            .with_only_columns(source, target)
            .where(and_(source.is_not(None), target.is_not(None)))
        )
    ).all()
    return sorted(
        {target_ref if source_ref == stix_id else source_ref for source_ref, target_ref in rows}
    )


def _touching(visible: Select[Any], stix_id: str) -> Select[Any]:
    """Every version in ``visible`` of a relationship with ``stix_id`` at either end."""
    source = StixObject.raw["source_ref"].astext
    target = StixObject.raw["target_ref"].astext
    return visible.where(
        StixObject.type == "relationship", or_(source == stix_id, target == stix_id)
    )


def _other_end(relationship: Mapping[str, Any], stix_id: str) -> str | None:
    """The end that is not ``stix_id``; ``None`` if this version no longer touches it."""
    source = relationship.get("source_ref")
    target = relationship.get("target_ref")
    if source == stix_id and isinstance(target, str):
        return target
    if target == stix_id and isinstance(source, str):
        return source
    return None
