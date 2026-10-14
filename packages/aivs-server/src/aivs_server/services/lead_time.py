"""Lead time: how far ahead of the public record a member heard about a vulnerability.

Content in a sandbox circle counts in neither figure: it is an exercise.

This is the number a member firm's CISO asks about at renewal -- "what did we
get for our dues?" -- so it is computed from records nobody can edit after the
fact: when a version of the vulnerability first became visible to the firm
(``distributions.date_added``, the same timestamp TAXII paging serves) against
the dates the public record carries on the object itself (``nvd_published``,
``kev_date_added``, which the KEV connector files).

Two readers, two answers, and neither sees the other's:

* **A member's quarterly statement** is that firm's own figures, including
  what it actioned (its own postures). It is the firm's record like its
  posture (SF-70): readable by that organisation only, and 404 to everyone
  else, the ISAC included. The ISAC learning which firms act slowly is exactly
  the ranking a member did not agree to.
* **The sector median** is the ISAC's: how far ahead of NVD and KEV the
  instance's distributions were, over everything distributed in the quarter.
  It is computed from distribution dates alone -- no member's behaviour enters
  it -- and is withheld below ``K_ANONYMITY`` items, so a quiet quarter does not
  turn a median into one identifiable vulnerability's timing.
"""

from __future__ import annotations

import datetime as dt
import statistics
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import VISIBLE_SUBMISSION_STATES, PostureStatus
from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import distribution_visibility_clause
from aivs_server.db.models import Circle, Distribution, OrgPosture, StixObject, Submission
from aivs_server.services.telemetry import K_ANONYMITY

__all__ = [
    "ItemLead",
    "OrgStatement",
    "Quarter",
    "SectorMedian",
    "item_lead",
    "org_statement",
    "sector_median",
    "summarise",
]

_SECONDS_PER_DAY: Final[float] = 86_400.0

#: Postures that record a decision reached: the firm fixed it or established it
#: was not affected. ``under_investigation`` and ``affected`` are still open.
_ACTIONED: Final[frozenset[PostureStatus]] = frozenset(
    {PostureStatus.FIXED, PostureStatus.NOT_AFFECTED}
)


@dataclass(frozen=True)
class Quarter:
    """A calendar quarter in UTC, ``[start, end)``."""

    year: int
    number: int

    @classmethod
    def parse(cls, text: str) -> Quarter:
        """``2026Q3`` -> Quarter(2026, 3). Anything else raises ``ValueError``."""
        year, separator, number = text.upper().partition("Q")
        if not separator or not year.isdigit() or number not in {"1", "2", "3", "4"}:
            msg = f"not a quarter: {text!r}"
            raise ValueError(msg)
        return cls(int(year), int(number))

    @property
    def start(self) -> dt.datetime:
        return dt.datetime(self.year, 3 * self.number - 2, 1, tzinfo=dt.UTC)

    @property
    def end(self) -> dt.datetime:
        if self.number == 4:  # noqa: PLR2004 - the year's last quarter rolls the year
            return dt.datetime(self.year + 1, 1, 1, tzinfo=dt.UTC)
        return dt.datetime(self.year, 3 * self.number + 1, 1, tzinfo=dt.UTC)

    def __str__(self) -> str:
        return f"{self.year}Q{self.number}"


@dataclass(frozen=True)
class ItemLead:
    """One vulnerability: when the reader first saw it and how far ahead that was.

    A lead is in days; positive means the reader had it before the public
    source. ``None`` means the public source has no date for it yet.
    """

    vulnerability_stix_id: str
    name: str
    first_visible: dt.datetime
    nvd_lead_days: float | None
    kev_lead_days: float | None


@dataclass(frozen=True)
class OrgStatement:
    quarter: str
    items: tuple[ItemLead, ...]
    relevant: int
    before_nvd: int
    before_kev: int
    median_days_ahead_of_nvd: float | None
    actioned: int


@dataclass(frozen=True)
class SectorMedian:
    quarter: str
    #: ``None`` when fewer than K items had a date to compare with.
    median_days_ahead_of_nvd: float | None
    median_days_ahead_of_kev: float | None
    #: Withheld with the medians: below K, the count is itself the disclosure.
    compared_with_nvd: int | None
    compared_with_kev: int | None


# ---------------------------------------------------------------------------
# Pure arithmetic
# ---------------------------------------------------------------------------
def item_lead(
    stix_id: str, name: str, first_visible: dt.datetime, versions: Iterable[Mapping[str, Any]]
) -> ItemLead:
    """The lead for one vulnerability, from the versions of it the reader can see.

    The public dates are taken as the earliest any visible version states: the
    KEV connector files a later version carrying ``kev_date_added``, and the
    ISAC's earlier version will not have it.
    """
    dates = [_public_dates(raw) for raw in versions]
    nvd = min((nvd for nvd, _ in dates if nvd is not None), default=None)
    kev = min((kev for _, kev in dates if kev is not None), default=None)
    return ItemLead(
        vulnerability_stix_id=stix_id,
        name=name,
        first_visible=first_visible,
        nvd_lead_days=_lead_days(first_visible, nvd),
        kev_lead_days=_lead_days(first_visible, kev),
    )


def summarise(quarter: Quarter, items: Sequence[ItemLead], actioned: int) -> OrgStatement:
    ahead_of_nvd = [item.nvd_lead_days for item in items if item.nvd_lead_days is not None]
    return OrgStatement(
        quarter=str(quarter),
        items=tuple(items),
        relevant=len(items),
        before_nvd=sum(1 for item in items if (item.nvd_lead_days or 0) > 0),
        before_kev=sum(1 for item in items if (item.kev_lead_days or 0) > 0),
        median_days_ahead_of_nvd=_median(ahead_of_nvd) if ahead_of_nvd else None,
        actioned=actioned,
    )


def _public_dates(raw: Mapping[str, Any]) -> tuple[dt.date | None, dt.date | None]:
    intel = (raw.get("extensions") or {}).get(AIVS_INTEL_EXTENSION_ID) or {}
    return _date(intel.get("nvd_published")), _date(intel.get("kev_date_added"))


def _date(value: Any) -> dt.date | None:
    if not isinstance(value, str):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def _lead_days(first_visible: dt.datetime, public: dt.date | None) -> float | None:
    """Days from first visible to the start of the public date, in UTC."""
    if public is None:
        return None
    public_start = dt.datetime(public.year, public.month, public.day, tzinfo=dt.UTC)
    return round((public_start - first_visible).total_seconds() / _SECONDS_PER_DAY, 1)


def _median(values: Sequence[float]) -> float:
    return round(statistics.median(values), 1)


def _withheld_median(values: Sequence[float]) -> float | None:
    return _median(values) if len(values) >= K_ANONYMITY else None


# ---------------------------------------------------------------------------
# A member's own statement
# ---------------------------------------------------------------------------
async def org_statement(
    session: AsyncSession, ctx: AuthContext, quarter: Quarter, *, now: dt.datetime
) -> OrgStatement:
    """``ctx``'s organisation's statement for ``quarter``: its figures and nobody else's.

    Every number is read through the caller's own visibility and the caller's
    own postures; the route decides who may ask (the organisation itself).
    """
    first_seen = await _first_visible(session, ctx, now, quarter)
    versions = await _visible_versions(session, ctx, now, list(first_seen))
    items = [
        item_lead(stix_id, name, first, versions.get(stix_id, ()))
        for stix_id, (first, name) in sorted(first_seen.items(), key=lambda kv: kv[1][0])
    ]
    actioned = await _actioned(session, ctx.org_id, list(first_seen))
    return summarise(quarter, items, actioned)


async def _first_visible(
    session: AsyncSession, ctx: AuthContext, now: dt.datetime, quarter: Quarter
) -> dict[str, tuple[dt.datetime, str]]:
    """Vulnerabilities first visible to ``ctx`` within the quarter, with when and their name."""
    first = func.min(Distribution.date_added)
    rows = (
        await session.execute(
            select(StixObject.stix_id, first, func.max(StixObject.name))
            .join(Distribution, Distribution.stix_object_id == StixObject.id)
            .join(Submission, Submission.id == Distribution.submission_id)
            .join(Circle, Circle.id == Distribution.circle_id)
            .where(
                StixObject.type == "vulnerability",
                distribution_visibility_clause(ctx, now),
                Circle.is_sandbox.is_(False),
            )
            .group_by(StixObject.stix_id)
            .having(first >= quarter.start, first < quarter.end)
        )
    ).all()
    return {stix_id: (when, name or stix_id) for stix_id, when, name in rows}


async def _visible_versions(
    session: AsyncSession, ctx: AuthContext, now: dt.datetime, stix_ids: Sequence[str]
) -> dict[str, list[Mapping[str, Any]]]:
    if not stix_ids:
        return {}
    rows = (
        await session.execute(
            select(StixObject.stix_id, StixObject.raw)
            .join(Distribution, Distribution.stix_object_id == StixObject.id)
            .join(Submission, Submission.id == Distribution.submission_id)
            .join(Circle, Circle.id == Distribution.circle_id)
            .where(
                StixObject.stix_id.in_(stix_ids),
                distribution_visibility_clause(ctx, now),
                Circle.is_sandbox.is_(False),
            )
            .distinct()
        )
    ).all()
    versions: dict[str, list[Mapping[str, Any]]] = {}
    for stix_id, raw in rows:
        versions.setdefault(stix_id, []).append(raw)
    return versions


async def _actioned(session: AsyncSession, org_id: uuid.UUID, stix_ids: Sequence[str]) -> int:
    if not stix_ids:
        return 0
    count = await session.scalar(
        select(func.count())
        .select_from(OrgPosture)
        .where(
            OrgPosture.org_id == org_id,
            OrgPosture.vulnerability_stix_id.in_(stix_ids),
            OrgPosture.status.in_(tuple(_ACTIONED)),
        )
    )
    return int(count or 0)


# ---------------------------------------------------------------------------
# The ISAC's sector median
# ---------------------------------------------------------------------------
async def sector_median(
    session: AsyncSession, quarter: Quarter, *, now: dt.datetime
) -> SectorMedian:
    """How far ahead of NVD and KEV the instance distributed, over the quarter.

    "First visible" here is the vulnerability's first distribution to anyone:
    a figure about the ISAC's timing, not any member's reading. Content still
    under embargo is not counted until it is released: a lead nobody has had
    yet is a forecast. Withheld, with its count, below ``K_ANONYMITY`` items.
    """
    first_distributed = await _first_distributed(session, quarter, now)
    versions = await _distributed_versions(session, list(first_distributed), now)
    items = [
        item_lead(stix_id, stix_id, first, versions.get(stix_id, ()))
        for stix_id, first in first_distributed.items()
    ]
    nvd = [item.nvd_lead_days for item in items if item.nvd_lead_days is not None]
    kev = [item.kev_lead_days for item in items if item.kev_lead_days is not None]
    return SectorMedian(
        quarter=str(quarter),
        median_days_ahead_of_nvd=_withheld_median(nvd),
        median_days_ahead_of_kev=_withheld_median(kev),
        compared_with_nvd=len(nvd) if len(nvd) >= K_ANONYMITY else None,
        compared_with_kev=len(kev) if len(kev) >= K_ANONYMITY else None,
    )


def _distributed(now: dt.datetime) -> Select[Any]:
    return (
        select(StixObject.stix_id)
        .join(Distribution, Distribution.stix_object_id == StixObject.id)
        .join(Submission, Submission.id == Distribution.submission_id)
        .join(Circle, Circle.id == Distribution.circle_id)
        .where(
            StixObject.type == "vulnerability",
            Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)),
            # A sandbox's content is an exercise, not the ISAC's timing.
            Circle.is_sandbox.is_(False),
            Distribution.date_added <= now,
        )
    )


async def _first_distributed(
    session: AsyncSession, quarter: Quarter, now: dt.datetime
) -> dict[str, dt.datetime]:
    first = func.min(Distribution.date_added)
    rows = (
        await session.execute(
            _distributed(now)
            .add_columns(first)
            .group_by(StixObject.stix_id)
            .having(first >= quarter.start, first < quarter.end)
        )
    ).all()
    return {str(stix_id): when for stix_id, when in rows}


async def _distributed_versions(
    session: AsyncSession, stix_ids: Sequence[str], now: dt.datetime
) -> dict[str, list[Mapping[str, Any]]]:
    if not stix_ids:
        return {}
    rows = (
        await session.execute(
            _distributed(now).add_columns(StixObject.raw).where(StixObject.stix_id.in_(stix_ids))
        )
    ).all()
    versions: dict[str, list[Mapping[str, Any]]] = {}
    for stix_id, raw in rows:
        versions.setdefault(stix_id, []).append(raw)
    return versions
