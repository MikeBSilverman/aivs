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

from sqlalchemy import ColumnElement, Select, exists, func, literal, select, tuple_

from aivs_server.auth.policy import Intervals, visible_content_clause
from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.services.attribution import submitter_column
from aivs_server.services.ownership import owner_key
from aivs_server.taxii.filters import TaxiiFilters, VersionSelector
from aivs_server.taxii.paging import Cursor

__all__ = ["build_object_listing_query", "build_version_listing_query"]


def _visible_rows(
    circle_id: uuid.UUID, intervals: Intervals, now: dt.datetime, ceiling: ColumnElement[bool]
) -> Select[Any]:
    """Return a subquery selecting every distribution row visible right now.

    Four conditions, all required, and this is the authoritative embargo gate:
    the row belongs to the requested circle, its ``date_added`` falls within one
    of the caller's membership ``intervals`` so the caller receives neither the
    circle's back catalogue nor what was shared while it was out,
    its ``date_added`` has arrived, and the owning submission is in a state
    whose content is visible. An embargoed object simply has a future
    ``date_added``, so nothing leaks early even if the release scheduler is not
    running.

    ``ceiling`` is the caller's TLP ceiling (``policy.tlp_ceiling_clause``),
    required rather than defaulted: no session kind that has one can reach
    TAXII today, and a reader that relied on that would read RED the day one
    could.
    """
    return (
        select(
            Distribution.id.label("distribution_id"),
            Distribution.seq.label("seq"),
            Distribution.date_added.label("date_added"),
            StixObject.id.label("stix_object_id"),
            StixObject.stix_id.label("stix_id"),
            StixObject.modified.label("modified"),
            StixObject.type.label("type"),
            StixObject.spec_version.label("spec_version"),
            StixObject.raw.label("raw"),
            Distribution.submission_id.label("submission_id"),
            owner_key(submitter_column(Submission)).label("owner"),
        )
        .select_from(Distribution)
        .join(StixObject, StixObject.id == Distribution.stix_object_id)
        .join(Submission, Submission.id == Distribution.submission_id)
        # The visibility conditions come from auth.policy so there is one
        # definition of them; see visible_content_clause.
        .where(visible_content_clause({circle_id: intervals}, now), ceiling)
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

    # Both correlations are scoped to the same *owner* as well as the same
    # stix_id. A version is superseded only by a later version from the
    # organisation that owns it (SF-48): the owner's newer version in a later
    # submission replaces its older one in the default feed, which is what
    # supersession means. Resolving across every owner would let one firm's
    # later `modified` take another's id over -- `last` is the default when
    # match[version] is absent -- and the write path refuses that at validate
    # and distribution; this keeps the read side from honouring it if a row
    # ever got through. Scoping to the submission, as before, served every
    # superseded version of the owner's object as "last".
    if VersionSelector.LAST in filters.version_selectors:
        latest = (
            select(func.max(peers.c.modified))
            .where(
                peers.c.stix_id == visible.c.stix_id,
                peers.c.owner == visible.c.owner,
            )
            .scalar_subquery()
        )
        conditions.append(visible.c.modified == latest)

    if VersionSelector.FIRST in filters.version_selectors:
        earliest = (
            select(func.min(peers.c.modified))
            .where(
                peers.c.stix_id == visible.c.stix_id,
                peers.c.owner == visible.c.owner,
            )
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


def _first_arrival_only(query: Select[Any], visible: Any, peers: Any) -> Select[Any]:
    """One row per version: each owner's ``(stix_id, modified)`` at its first visible arrival.

    One owner may carry the same version in two submissions (a TIP resending a
    whole bundle does), and each submission stores its own copy, so a circle can
    hold two rows of one version. The objects listing, the manifest and the
    object endpoint served both: ``match[version]=last`` matched each, since
    both are the latest (review R2-P3). The versions endpoint already collapsed
    them to the first arrival, for the paging reason it gives; this is the same
    rule for the other three. A row is dropped when an earlier visible row of
    the same owner, id and version exists. The peers are not filtered by
    ``added_after`` or the cursor, so a second arrival is never served just
    because the first fell before the client's position.
    """
    earlier = select(peers.c.seq).where(
        peers.c.stix_id == visible.c.stix_id,
        peers.c.owner == visible.c.owner,
        peers.c.modified == visible.c.modified,
        tuple_(peers.c.date_added, peers.c.seq) < tuple_(visible.c.date_added, visible.c.seq),
    )
    return query.where(~exists(earlier))


def build_object_listing_query(
    *,
    circle_id: uuid.UUID,
    intervals: Intervals,
    ceiling: ColumnElement[bool],
    filters: TaxiiFilters,
    now: dt.datetime,
    cursor: Cursor | None,
    limit: int,
    stix_id: str | None = None,
) -> Select[Any]:
    """Build the ordered, paginated query behind an objects listing.

    Ordering is ascending by ``(date_added, seq)``, matching both the
    specification's requirement that objects sort by date added and the column
    order of ``ix_distributions_circle_paging``. Changing one without the other
    turns every member poll into a sequential scan. ``seq`` -- the distribution
    row's monotonic identity, not its random UUID -- is what makes the tiebreaker
    within one ``date_added`` value stable enough that pagination cannot skip a
    row (see ``Distribution.seq``).

    ``limit + 1`` rows are fetched so the caller can set the envelope's ``more``
    flag without a second counting query.
    """
    visible = _visible_rows(circle_id, intervals, now, ceiling).subquery("visible")
    peers = _visible_rows(circle_id, intervals, now, ceiling).subquery("visible_peers")

    query = select(
        visible.c.distribution_id,
        visible.c.seq,
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
    query = _first_arrival_only(query, visible, peers)

    if filters.added_after is not None:
        # Strictly greater than: `added_after` is exclusive, so a client that
        # re-sends the timestamp of its last object does not receive it twice.
        query = query.where(visible.c.date_added > filters.added_after)

    if cursor is not None:
        # Keyset predicate over the composite sort key, written as a row-value
        # comparison so PostgreSQL walks ix_distributions_circle_paging directly
        # rather than evaluating a disjunction row by row. Strictly greater than
        # the cursor position, so the row the cursor points at is not repeated.
        query = query.where(
            tuple_(visible.c.date_added, visible.c.seq)
            > tuple_(literal(cursor.date_added), literal(cursor.seq))
        )

    return query.order_by(visible.c.date_added.asc(), visible.c.seq.asc()).limit(limit + 1)


def build_version_listing_query(
    *,
    circle_id: uuid.UUID,
    intervals: Intervals,
    ceiling: ColumnElement[bool],
    stix_id: str,
    now: dt.datetime,
    cursor: Cursor | None,
    limit: int,
    added_after: dt.datetime | None = None,
) -> Select[Any]:
    """Build the query behind the object-versions endpoint.

    One row per visible version of one object, carrying the ``(date_added,
    seq)`` of the first distribution row through which the caller can see it,
    and paged on that key exactly as the objects listing is. Only versions the
    caller may see are listed, for the same reason the version filter is scoped
    that way.

    **Ordered by when the version arrived, not by ``modified``.** A client
    continues a listing with ``added_after`` set to the previous page's
    ``X-TAXII-Date-Added-Last``. That is only safe if everything on later pages
    was added after everything on earlier ones, which ``date_added`` order
    guarantees and ``modified`` order does not: a correction distributed before
    a backfilled earlier version put the later-added version on page one, its
    stamp in the header, and the earlier-added one on page two below the
    client's new ``added_after``, where it was never listed.

    **One row per version, at its first visible arrival.** Two submissions may
    carry the same ``(stix_id, modified)``, distributed at different times.
    Keyed on the first, a later redistribution of a version the client already
    holds is not news; keyed on each row, ``added_after`` between the two stamps
    listed it again. The first visible arrival cannot move earlier once a
    cursor has passed it, for the reason any ``date_added`` cannot (see
    ``services.publication``), so the key is as stable as the objects listing's.
    """
    visible = _visible_rows(circle_id, intervals, now, ceiling).subquery("visible")
    first_arrival = (
        select(visible.c.modified, visible.c.date_added, visible.c.seq)
        .where(visible.c.stix_id == stix_id)
        .distinct(visible.c.modified)
        .order_by(visible.c.modified, visible.c.date_added, visible.c.seq)
        .subquery("first_arrival")
    )
    query = select(
        first_arrival.c.modified, first_arrival.c.date_added, first_arrival.c.seq
    ).select_from(first_arrival)
    # Filtered after the versions are collapsed, never before: before, the
    # second arrival of a version survives an `added_after` the first fails.
    if added_after is not None:
        query = query.where(first_arrival.c.date_added > added_after)
    if cursor is not None:
        query = query.where(
            tuple_(first_arrival.c.date_added, first_arrival.c.seq)
            > tuple_(literal(cursor.date_added), literal(cursor.seq))
        )
    return query.order_by(first_arrival.c.date_added.asc(), first_arrival.c.seq.asc()).limit(
        limit + 1
    )
