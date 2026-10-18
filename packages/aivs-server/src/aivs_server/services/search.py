"""Full-text search over the distributed objects a caller may read (SF-11).

A search is a view drawn from content, like readiness and the vulnerability
page, so it must be drawn only from what the caller could have read for
itself: a hit, a missing hit, or a "more" that came from content the caller
cannot see tells it that content exists. Three choices keep it that way.

- **One statement, visibility first.** The caller's visible rows
  (``visible.visible_objects``, which carries the membership intervals, the
  embargo, the pause, and an SSO session's TLP ceiling) are a materialised
  CTE; each object's latest version is chosen among those rows alone; only
  then is the text matched. A match decided first and filtered afterwards
  would let invisible hits take the page's places, and a latest version
  chosen over every stored row would find a newer version's text the caller
  cannot read yet. The fence also keeps the work proportional to what the
  caller can see, not to what matches elsewhere, which is why there is no
  text index: a GIN index would start from every match in the table.
- **The latest version, and never a revoked one.** Revocation is a new
  version carrying the same text, so matching any visible version would find
  an object its owner took back. An object whose latest visible version is
  revoked matches nothing.
- **No totals, no ranking, no snippets.** A hit names the object, its type,
  its TLP and when it was shared with the caller, newest first, and the page
  says only whether there is more. A count or a relevance score is one more
  number to reason about; a description snippet would be the warning itself,
  read without the receipt its page writes (SF-51).

The text indexed is the object's own words, not its provenance: name,
aliases, description, a note's abstract and content, an opinion's
explanation, and the ids in its external references. AI tooling fields and
custom ``x_`` properties are left out, because a search over them gathers a
firm's other objects by its tooling, which is what owner tokens exist not to
allow (R38).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Select, String, and_, cast, false, func, literal, select
from sqlalchemy.dialects.postgresql import JSONPATH, REGCONFIG
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import TLP
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.services.visible import visible_objects

__all__ = ["SearchHit", "SearchPage", "SearchTermsError", "parse_search_terms", "search_visible"]

#: Bounds on what a person types. Short enough that the query is never the
#: expensive part, long enough for a product name and a version.
MIN_TERMS_LENGTH: Final[int] = 2
MAX_TERMS_LENGTH: Final[int] = 200

#: The text matched for one version is cut here. A tsvector is limited to
#: 1 MB, and one object's prose past this length adds nothing a person types.
_MAX_INDEXED_CHARACTERS: Final[int] = 100_000

#: No stemming and no stop words: product names, versions and identifiers
#: are most of what is searched for, and a stemmer bends those.
_CONFIG: Final[str] = "simple"


#: Where an object's external reference ids are: "CVE-2026-1234" finds the
#: vulnerability that cites it.
_REFERENCE_IDS: Final = cast(literal("$.external_references[*].external_id"), JSONPATH)


class SearchTermsError(ValueError):
    """The terms cannot be searched for; the message says why."""


@dataclass(frozen=True, slots=True)
class SearchTerms:
    """What a person typed, normalised once at the boundary."""

    text: str


@dataclass(frozen=True, slots=True)
class SearchHit:
    stix_id: str
    type: str
    name: str | None
    tlp: TLP
    #: When this version was first shared with the caller.
    shared_at: dt.datetime
    modified: dt.datetime


@dataclass(frozen=True, slots=True)
class SearchPage:
    hits: tuple[SearchHit, ...]
    #: More objects match than were returned; narrow the terms to see them.
    more: bool


def parse_search_terms(raw: str) -> SearchTerms:
    """Collapse whitespace and bound the length, or raise :class:`SearchTermsError`."""
    text = " ".join(raw.split())
    if not MIN_TERMS_LENGTH <= len(text) <= MAX_TERMS_LENGTH:
        reason = f"search terms are {MIN_TERMS_LENGTH} to {MAX_TERMS_LENGTH} characters"
        raise SearchTermsError(reason)
    return SearchTerms(text)


async def search_visible(
    session: AsyncSession,
    ctx: AuthContext,
    terms: SearchTerms,
    *,
    now: dt.datetime,
    limit: int,
) -> SearchPage:
    """The newest objects ``ctx`` can read whose latest visible version matches ``terms``."""
    rows = (
        await session.execute(build_search_statement(visible_objects(ctx, now), terms, limit))
    ).all()
    hits = tuple(
        SearchHit(
            stix_id=row.stix_id,
            type=row.type,
            name=row.name,
            tlp=row.tlp,
            shared_at=row.shared_at,
            modified=row.modified,
        )
        for row in rows[:limit]
    )
    return SearchPage(hits=hits, more=len(rows) > limit)


def build_search_statement(visible: Select[Any], terms: SearchTerms, limit: int) -> Select[Any]:
    """Visibility, then each object's latest visible version, then the match.

    ``visible`` has one row per distribution the caller can read. The CTE is
    ``MATERIALIZED`` so the planner cannot push the match into it.
    """
    readable = (
        visible.with_only_columns(
            StixObject.id.label("object_id"),
            StixObject.stix_id.label("stix_id"),
            StixObject.owner_token.label("owner_token"),
            StixObject.modified.label("modified"),
            Submission.tlp.label("tlp"),
            Distribution.date_added.label("date_added"),
            Distribution.seq.label("seq"),
        )
        .cte("readable")
        .prefix_with("MATERIALIZED")
    )
    # One row per object: its latest version among the readable rows, and that
    # version's first arrival to the caller (the TAXII rule, per owner, SF-27).
    latest = (
        select(readable)
        .distinct(readable.c.stix_id, readable.c.owner_token)
        .order_by(
            readable.c.stix_id,
            readable.c.owner_token,
            readable.c.modified.desc(),
            readable.c.date_added,
            readable.c.seq,
        )
        .subquery("latest")
    )
    return (
        select(
            StixObject.stix_id,
            StixObject.type,
            StixObject.name,
            latest.c.tlp,
            latest.c.date_added.label("shared_at"),
            latest.c.modified,
        )
        .join(latest, latest.c.object_id == StixObject.id)
        .where(
            and_(
                func.coalesce(StixObject.raw["revoked"].as_boolean(), false()).is_(False),
                _searchable_text(StixObject.raw).op("@@")(
                    func.websearch_to_tsquery(_regconfig(), terms.text)
                ),
            )
        )
        .order_by(latest.c.date_added.desc(), latest.c.seq.desc())
        .limit(limit + 1)
    )


def _searchable_text(raw: Any) -> Any:
    """One version's own words, as a text-search vector."""
    words = func.concat_ws(
        " ",
        raw["name"].astext,
        cast(raw["aliases"], String),
        raw["description"].astext,
        raw["abstract"].astext,
        raw["content"].astext,
        raw["explanation"].astext,
        cast(func.jsonb_path_query_array(raw, _REFERENCE_IDS), String),
    )
    return func.to_tsvector(_regconfig(), func.left(words, _MAX_INDEXED_CHARACTERS))


def _regconfig() -> Any:
    return cast(literal(_CONFIG), REGCONFIG)
