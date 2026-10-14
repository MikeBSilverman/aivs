"""A submission's triage priority: CISA's SSVC decision, with the factors shown.

The default is CISA's own table (``ssvc_data/cisa_coordinator_2_0_3.csv``, read
verbatim) applied to the decision points the content carries: Exploitation,
Automatable and Technical Impact from a vulnerability's 2.0 extension, and
Mission and Well-Being Impact from the instance, since that one describes the
ISAC's sector rather than the vulnerability. An editor may set a priority
instead; that is the only value stored, so the default follows the content.

Factors are always returned, including what was missing: a priority an
analyst cannot trace to its inputs is one nobody can argue with, which is the
wrong property for a triage queue.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

from aivs_schemas.enums import SsvcPriority
from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID

__all__ = ["PriorityAssessment", "assess_priority", "cisa_table", "decision_points"]

_TABLE: Final[Path] = Path(__file__).parent / "ssvc_data" / "cisa_coordinator_2_0_3.csv"

#: The order of the CISA ranking, lowest first, for choosing the most urgent of
#: several vulnerabilities in one submission.
_RANK: Final[tuple[SsvcPriority, ...]] = (
    SsvcPriority.TRACK,
    SsvcPriority.TRACK_STAR,
    SsvcPriority.ATTEND,
    SsvcPriority.ACT,
)

#: CISA's vulnrichment spells the Exploitation value ``poc``; CERT/CC's table
#: spells it ``public poc``. Same decision point, same meaning.
_EXPLOITATION_SPELLING: Final[Mapping[str, str]] = {"poc": "public poc"}

_POINTS: Final[tuple[str, ...]] = (
    "ssvc_exploitation",
    "ssvc_automatable",
    "ssvc_technical_impact",
)


@dataclass(frozen=True)
class PriorityAssessment:
    """A default priority (``None`` if the inputs are incomplete) and what it rests on."""

    decision: SsvcPriority | None
    #: Each decision point and its value, in the table's order.
    factors: Mapping[str, str]
    #: The decision points no content supplied.
    missing: tuple[str, ...]


@lru_cache(maxsize=1)
def cisa_table() -> Mapping[tuple[str, str, str, str], SsvcPriority]:
    """The CISA table as ``(exploitation, automatable, impact, mission) -> decision``."""
    with _TABLE.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    return {
        (exploitation, automatable, impact, mission): SsvcPriority(decision)
        for _row, exploitation, automatable, impact, mission, decision in rows[1:]
    }


def decision_points(raw_objects: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    """The SSVC points each vulnerability in a submission states, from its 2.0 body."""
    found: list[dict[str, str]] = []
    for raw in raw_objects:
        if raw.get("type") != "vulnerability":
            continue
        body = (raw.get("extensions") or {}).get(AIVS_INTEL_EXTENSION_ID)
        if isinstance(body, Mapping):
            found.append(
                {point: body[point] for point in _POINTS if isinstance(body.get(point), str)}
            )
    return found


def assess_priority(
    points_per_vulnerability: Iterable[Mapping[str, str]], *, mission_impact: str
) -> PriorityAssessment:
    """The most urgent CISA decision across a submission's vulnerabilities.

    A vulnerability missing any point yields no decision of its own; if none
    has a complete set, the default is ``None`` and ``missing`` says why.
    """
    best: tuple[SsvcPriority, Mapping[str, str]] | None = None
    gaps: set[str] = set()
    for points in points_per_vulnerability:
        absent = tuple(point for point in _POINTS if point not in points)
        if absent:
            gaps.update(absent)
            continue
        decision, factors = _one(points, mission_impact)
        if best is None or _RANK.index(decision) > _RANK.index(best[0]):
            best = (decision, factors)
    if best is not None:
        return PriorityAssessment(decision=best[0], factors=best[1], missing=())
    return PriorityAssessment(
        decision=None,
        factors={"mission_impact": mission_impact},
        missing=tuple(point for point in _POINTS if point in gaps) or _POINTS,
    )


def _one(points: Mapping[str, str], mission_impact: str) -> tuple[SsvcPriority, Mapping[str, str]]:
    exploitation = _EXPLOITATION_SPELLING.get(
        points["ssvc_exploitation"], points["ssvc_exploitation"]
    )
    factors = {
        "exploitation": exploitation,
        "automatable": points["ssvc_automatable"],
        "technical_impact": points["ssvc_technical_impact"],
        "mission_impact": mission_impact,
    }
    key = (exploitation, factors["automatable"], factors["technical_impact"], mission_impact)
    return cisa_table()[key], factors
