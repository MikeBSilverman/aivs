"""What's available for a vulnerability: remediation, mitigation, detection, validation.

Readiness is the RFI's maturity framework in four words, and it is computed,
never stored (SF-8). It is derived from the objects the *caller* can see: a
stored, global value would tell a member that content exists in a circle it is
not in -- "a fix is available" for a vulnerability whose only fix was shared at
RED is the existence of RED content, stated to everyone. For the same reason it
is shown in the API and portal and never sent over TAXII, which serves content
and nothing derived from content someone else may hold.

Two parts: :func:`assess` is a pure function over what the caller can see, and
:func:`readiness_for` gathers that under the visibility clause.
"""

from __future__ import annotations

import datetime as dt
import enum
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.auth.context import AuthContext
from aivs_server.db.models import StixObject
from aivs_server.services.guidance import review_lapsed, stated_review_by
from aivs_server.services.visible import (
    VulnerabilityNotVisibleError,
    related_stix_ids,
    require_visible_vulnerability,
    visible_objects,
)

__all__ = [
    "Availability",
    "Readiness",
    "ReadinessInput",
    "VulnerabilityNotVisibleError",
    "assess",
    "readiness_for",
]


class Availability(enum.StrEnum):
    #: Something the caller can see provides it.
    AVAILABLE = "available"
    #: Someone the caller can see says there is none (CSAF ``none_available`` or
    #: ``no_fix_planned``): a statement, not an absence.
    NONE_AVAILABLE = "none_available"
    #: Something the caller can see made a claim -- a fix exists, or none
    #: does -- and its ``review_by`` has passed. The claim is stale, not
    #: reversed: "unavailable" here would turn a lapsed "fix available" into a
    #: fresh statement that there is no fix, which is as wrong as the original.
    #: ``Readiness.not_confirmed_since`` says since when.
    LAPSED = "lapsed"
    #: Nothing the caller can see says either way.
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ReadinessInput:
    """The few facts about one visible version of an object that readiness reads."""

    stix_id: str
    modified: dt.datetime
    stix_type: str
    remediation_category: str | None = None
    pattern_type: str | None = None
    valid_until: dt.datetime | None = None
    revoked: bool = False
    #: A course of action's ``review_by``, as written (``guidance.stated_review_by``).
    review_by: str | None = None


@dataclass(frozen=True)
class Readiness:
    remediation: Availability
    mitigation: Availability
    detection: Availability
    validation: Availability
    #: For each LAPSED group, the latest ``review_by`` among its stale claims:
    #: the last day anyone vouched for one. None when the only date given was
    #: not a date.
    not_confirmed_since: Mapping[str, dt.date | None] = field(default_factory=dict)


#: CSAF remediation categories (and ours) and the group each makes available.
#: ``rollback`` makes nothing available: knowing how to undo a fix is not a fix.
_CATEGORY_GROUP: Final[Mapping[str, str]] = {
    "vendor_fix": "remediation",
    "mitigation": "mitigation",
    "workaround": "mitigation",
    "validation": "validation",
}

#: Categories that state there is no fix, which is different from not knowing.
_NO_FIX: Final[frozenset[str]] = frozenset({"none_available", "no_fix_planned"})

_GROUPS: Final[tuple[str, ...]] = ("remediation", "mitigation", "detection", "validation")


def assess(objects: Iterable[ReadinessInput], now: dt.datetime) -> Readiness:
    """Readiness from the objects a caller can see. ``now`` decides what has expired.

    An indicator counts only while it is valid. One with no ``valid_until`` --
    stored before the rule that requires it -- does not count: AIVS cannot say
    it is still current, and a stale detection reported as available is worse
    than an honest gap.

    A course of action past its ``review_by`` no longer makes its claim, either
    way; its group is LAPSED unless a current claim answers it.
    """
    available: set[str] = set()
    stated_none: set[str] = set()
    lapsed: dict[str, list[dt.date | None]] = {}
    for obj in _latest_versions(objects):
        if obj.revoked:
            continue
        if obj.stix_type == "indicator" and _is_current(obj, now):
            available.add("detection")
        claim = _claim(obj)
        if claim is None:
            continue
        group, claims = claim
        if review_lapsed(obj.review_by, now):
            lapsed.setdefault(group, []).append(_review_date(obj.review_by))
        else:
            (available if claims == "available" else stated_none).add(group)
    groups = {group: _availability(group, available, stated_none, lapsed) for group in _GROUPS}
    return Readiness(
        **groups,
        not_confirmed_since={
            group: _latest(lapsed[group])
            for group, value in groups.items()
            if value is Availability.LAPSED
        },
    )


def _claim(obj: ReadinessInput) -> tuple[str, str] | None:
    """The group a course of action speaks to, and whether it says available or none."""
    if obj.stix_type != "course-of-action" or obj.remediation_category is None:
        return None
    group = _CATEGORY_GROUP.get(obj.remediation_category)
    if group is not None:
        return group, "available"
    if obj.remediation_category in _NO_FIX:
        return "remediation", "none"
    return None


def _latest_versions(objects: Iterable[ReadinessInput]) -> list[ReadinessInput]:
    """Each object's latest version among those given (the caller's visible ones).

    An older version must not count once its owner has changed it: a workaround
    later revised to a rollback, or revoked, no longer makes anything available.
    Latest *visible* version, as ``match[version]=last`` resolves it (SF-27).
    """
    latest: dict[str, ReadinessInput] = {}
    for obj in objects:
        current = latest.get(obj.stix_id)
        if current is None or obj.modified > current.modified:
            latest[obj.stix_id] = obj
    return list(latest.values())


def _is_current(obj: ReadinessInput, now: dt.datetime) -> bool:
    return obj.pattern_type is not None and obj.valid_until is not None and obj.valid_until > now


def _availability(
    group: str,
    available: set[str],
    stated_none: set[str],
    lapsed: Mapping[str, list[dt.date | None]],
) -> Availability:
    """A current claim wins over a stale one; a stale one over silence."""
    if group in available:
        return Availability.AVAILABLE
    if group in stated_none:
        return Availability.NONE_AVAILABLE
    if group in lapsed:
        return Availability.LAPSED
    return Availability.UNAVAILABLE


def _review_date(review_by: str | None) -> dt.date | None:
    try:
        return dt.date.fromisoformat(review_by) if review_by is not None else None
    except ValueError:
        return None


def _latest(dates: list[dt.date | None]) -> dt.date | None:
    known = [date for date in dates if date is not None]
    return max(known) if known else None


# ---------------------------------------------------------------------------
# What the caller can see
# ---------------------------------------------------------------------------
async def readiness_for(
    session: AsyncSession, ctx: AuthContext, vulnerability_stix_id: str, *, now: dt.datetime
) -> Readiness:
    """Readiness of one vulnerability, as ``ctx`` can see it.

    Raises :class:`VulnerabilityNotVisibleError` unless the caller can see the
    vulnerability itself. Related objects are found through ``relationship``
    objects the caller can see, in either direction, and are themselves held to
    the same scope: a relationship the caller can see does not grant the
    object at its other end.
    """
    visible = visible_objects(ctx, now)
    await require_visible_vulnerability(session, visible, vulnerability_stix_id)

    related_ids = await related_stix_ids(session, visible, vulnerability_stix_id)
    rows = (
        await session.execute(
            visible.with_only_columns(
                StixObject.stix_id,
                StixObject.modified,
                StixObject.type,
                StixObject.remediation_category,
                StixObject.pattern_type,
                StixObject.valid_until,
                StixObject.raw["revoked"].as_boolean(),
                StixObject.raw["extensions"],
            ).where(
                StixObject.stix_id.in_(related_ids),
                StixObject.type.in_(("course-of-action", "indicator")),
            )
        )
    ).all()
    return assess(
        (
            ReadinessInput(
                stix_id=stix_id,
                modified=modified,
                stix_type=stix_type,
                remediation_category=category,
                pattern_type=pattern_type,
                valid_until=valid_until,
                revoked=bool(revoked),
                review_by=stated_review_by({"extensions": extensions or {}}),
            )
            for (
                stix_id,
                modified,
                stix_type,
                category,
                pattern_type,
                valid_until,
                revoked,
                extensions,
            ) in rows
        ),
        now,
    )
