"""Query construction for TAXII object and manifest listings.

Separated from the router so the visibility and version logic can be tested
directly, and so that a reviewer auditing "can a member see what they should
not" has one file to read rather than a set of endpoint handlers.

One subtlety is load-bearing and worth stating plainly. ``match[version]=last``
resolves the latest version **among the versions visible to this caller**, not
the latest version stored. Resolving it globally and then applying the
visibility filter would return zero rows for an object whose newest version has
not been distributed to the caller's circle -- from which the caller could infer
that a newer version exists and that it is being withheld. Scoping the version
resolution to visible rows is both the correct semantic and the non-leaky one.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import Select, and_, func, select

from aivs_schemas.enums import VISIBLE_SUBMISSION_STATES
from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.taxii.filters import TaxiiFilters, VersionSelector
from aivs_server.taxii.paging import Cursor

__all__ = ["build_object_listing_query", "build_version_listing_query"]


def _visible_rows(circle_id: uuid.UUID, now: dt.datetime) -> Select[Any]:
    """Return a subquery selecting every distribution row visible right now.

    Three conditions, all required, and this is the authoritative embargo gate:
    the row belongs to the requested circle, its ``date_added`` has arrived, and
    the owning submission is in a state whose content is visible. An embargoed
    object simply has a future ``date_added``, so nothing leaks early even if
    the release scheduler is not running.
    """
    return (
        select(
            Distribution.id.label("distribution_id"),
            Distribution.date_added.label("date_added"),
            StixObject.id.label("stix_object_id"),
            StixObject.stix_id.label("stix_id"),
            StixObject.modified.label("modified"),
            StixObject.type.label("type"),
            StixObject.spec_version.label("spec_version"),
            StixObject.raw.label("raw"),
            Distribution.submission_id.label("submission_id"),
        )
        .select_from(Distribution)
        .join(StixObject, StixObject.id == Distribution.stix_object_id)
        .join(Submission, Submission.id == Distribution.submission_id)
        .where(
            Distribution.circle_id == circle_id,
            Distribution.date_added <= now,
            Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)),
        )
    )


def _apply_match_filters(query: Select[Any], filters: TaxiiFilters, visible: Any) -> Select[Any]:
    """Apply the ``match[...]`` predicates, which AND together."""
    if filters.ids:
        query = query.where(visible.c.stix_id.in_(filters.ids))
    if filters.types:
        query = query.where(visible.c.type.in_(filters.types))
    if filters.spec_versions:
        query = query.where(visible.c.spec_version.in_(filters.spec_versions))
    return query


def _apply_version_filter(
    query: Select[Any], filters: TaxiiFilters, visible: Any, peers: Any
) -> Select[Any]:
    """Restrict to the requested versions of each object.

    ``all`` applies no restriction. ``first`` and ``last`` resolve against the
    visible rows only -- see the module docstring. Explicit timestamps match the
    STIX ``modified`` property exactly.

    ``peers`` is a second alias over the same visible-rows subquery. It has to
    be a distinct alias: correlating ``visible`` against itself would make
    ``stix_id`` ambiguous and silently compare each row's modified timestamp to
    its own maximum, which is every row.
    """
    if filters.wants_all_versions:
        return query

    conditions = []

    if VersionSelector.LAST in filters.version_selectors:
        latest = (
            select(func.max(peers.c.modified))
            .where(peers.c.stix_id == visible.c.stix_id)
            .scalar_subquery()
        )
        conditions.append(visible.c.modified == latest)

    if VersionSelector.FIRST in filters.version_selectors:
        earliest = (
            select(func.min(peers.c.modified))
            .where(peers.c.stix_id == visible.c.stix_id)
            .scalar_subquery()
        )
        conditions.append(visible.c.modified == earliest)

    if filters.version_timestamps:
        conditions.append(visible.c.modified.in_(filters.version_timestamps))

    if not conditions:
        return query

    # The selectors OR together: match[version]=first,last means either.
    combined = conditions[0]
    for condition in conditions[1:]:
        combined = combined | condition
    return query.where(combined)


def build_object_listing_query(
    *,
    circle_id: uuid.UUID,
    filters: TaxiiFilters,
    now: dt.datetime,
    cursor: Cursor | None,
    limit: int,
    stix_id: str | None = None,
) -> Select[Any]:
    """Build the ordered, paginated query behind an objects listing.

    Ordering is ascending by ``(date_added, id)``, matching both the
    specification's requirement that objects sort by date added and the column
    order of ``ix_distributions_circle_paging``. Changing one without the other
    turns every member poll into a sequential scan.

    ``limit + 1`` rows are fetched so the caller can set the envelope's ``more``
    flag without a second counting query.
    """
    visible = _visible_rows(circle_id, now).subquery("visible")
    peers = _visible_rows(circle_id, now).subquery("visible_peers")

    query = select(
        visible.c.distribution_id,
        visible.c.date_added,
        visible.c.stix_id,
        visible.c.modified,
        visible.c.type,
        visible.c.spec_version,
        visible.c.raw,
        visible.c.submission_id,
    ).select_from(visible)

    if stix_id is not None:
        query = query.where(visible.c.stix_id == stix_id)

    query = _apply_match_filters(query, filters, visible)
    query = _apply_version_filter(query, filters, visible, peers)

    if filters.added_after is not None:
        # Strictly greater than: `added_after` is exclusive, so a client that
        # re-sends the timestamp of its last object does not receive it twice.
        query = query.where(visible.c.date_added > filters.added_after)

    if cursor is not None:
        # Keyset predicate over the composite sort key. The tuple comparison
        # form lets PostgreSQL use the index directly rather than evaluating a
        # disjunction row by row.
        query = query.where(
            and_(
                visible.c.date_added >= cursor.date_added,
                ~and_(
                    visible.c.date_added == cursor.date_added,
                    visible.c.distribution_id <= cursor.distribution_id,
                ),
            )
        )

    return query.order_by(visible.c.date_added.asc(), visible.c.distribution_id.asc()).limit(
        limit + 1
    )


def build_version_listing_query(
    *, circle_id: uuid.UUID, stix_id: str, now: dt.datetime, limit: int
) -> Select[Any]:
    """Build the query behind the object-versions endpoint.

    Returns the ``modified`` timestamps of every visible version of one object,
    ascending. Only versions the caller may see are listed, for the same reason
    the version filter is scoped that way.
    """
    visible = _visible_rows(circle_id, now).subquery("visible")
    return (
        select(visible.c.modified, visible.c.date_added)
        .select_from(visible)
        .where(visible.c.stix_id == stix_id)
        .order_by(visible.c.modified.asc())
        .limit(limit + 1)
    )
