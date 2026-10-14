"""The disclosure split: when a contribution about another's vulnerability is legal (SF-7, SF-47).

A submitter may always share findings in its own products and estate, or about
AI systems. Two scopes are about somebody else's vulnerability, and their
legality is a property of that *target* -- never of the submitter's bundle,
which would be checking the rule against the request that asserts it:

- ``disclosed_third_party`` is legal once the target is public. "Public" here
  is the ISAC's own canonical record saying so: ``cve_status`` ``published``.
- ``coordinated_disclosure`` is legal while the vendor is a party to the case:
  a vendor organisation an editor placed in a circle the target was distributed
  to, which has itself filed an agreeing ``opinion`` on it that the ISAC
  validated and distributed; or a CERT coordination case (VINCE, GOLD EAGLE)
  recorded on the target as an external reference. Never a party list the
  submitter wrote.

**The canonical target and its current state.** The canonical vulnerability is
the ISAC's: the latest version (by ``modified``) of the referenced id among the
ISAC organisation's submissions that are validated, distributed or superseded,
excluding the submission under check. A member's own pre-CVE finding under the
same id is not canonical and decides nothing.

**Where it is checked, and what a refusal may say.** At ingest only against
targets the submitter can see, and a reference to a target it cannot see gets
exactly the refusal a nonexistent one does, byte for byte: otherwise the
difference confirms that a pre-CVE finding exists (SF-47). At validate and at
distribution against the current state globally, by the ISAC -- so a target
whose disclosure is withdrawn between validation and distribution stops the
contribution there.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import (
    THIRD_PARTY_DISCOVERY_SCOPES,
    DiscoveryScope,
    OrgType,
    SubmissionState,
)
from aivs_schemas.extension.builders import AIVS_EXTENSION_ID, AIVS_INTEL_EXTENSION_ID
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import distribution_visibility_clause
from aivs_server.db.models import (
    CircleMembership,
    Distribution,
    Organization,
    StixObject,
    Submission,
)
from aivs_server.services.ownership import ISAC_OWNER_TYPES
from aivs_server.services.references import external_references_by_type

__all__ = ["DisclosureScope", "cve_status", "disclosure_problem"]

#: One refusal for a target that is absent, invisible to the caller, or not the
#: ISAC's. Identical in every case, because any difference is an existence
#: oracle over pre-CVE findings (SF-47).
UNKNOWN_TARGET: Final[str] = (
    "this contribution refers to a vulnerability you cannot contribute to here: "
    "reference the ISAC's published record of it"
)

#: Submission states whose content the ISAC has accepted.
_CANONICAL_STATES: Final[frozenset[SubmissionState]] = frozenset(
    {SubmissionState.VALIDATED, SubmissionState.DISTRIBUTED, SubmissionState.SUPERSEDED}
)

#: External-reference sources naming a CERT coordination case. Ours: neither
#: VINCE nor GOLD EAGLE registers a STIX source_name, so these are the names
#: AIVS writes and reads.
COORDINATION_CASE_SOURCES: Final[frozenset[str]] = frozenset({"vince", "gold-eagle"})

#: STIX ``opinion`` values that acknowledge rather than dispute.
_AGREEING_OPINIONS: Final[frozenset[str]] = frozenset({"agree", "strongly-agree"})


@dataclass(frozen=True, slots=True)
class DisclosureScope:
    """Whose view a check takes: a submitter's at ingest, the ISAC's otherwise.

    ``visible_to=None`` is the ISAC's view of everything. The submission under
    check is always excluded from the canonical state it is checked against.
    """

    visible_to: AuthContext | None
    exclude_submission_id: uuid.UUID
    now: dt.datetime


def cve_status(raw: Mapping[str, Any]) -> str | None:
    extensions = raw.get("extensions") or {}
    for extension_id in (AIVS_INTEL_EXTENSION_ID, AIVS_EXTENSION_ID):
        body = extensions.get(extension_id)
        if isinstance(body, Mapping) and isinstance(body.get("cve_status"), str):
            return str(body["cve_status"])
    return None


def _has_coordination_case(raw: Mapping[str, Any]) -> bool:
    return any(
        isinstance(reference, Mapping)
        and str(reference.get("source_name", "")).lower() in COORDINATION_CASE_SOURCES
        and reference.get("external_id")
        for reference in raw.get("external_references") or []
    )


async def _canonical_current(
    session: AsyncSession, stix_id: str, scope: DisclosureScope
) -> Mapping[str, Any] | None:
    """The canonical target's current version as ``scope`` may see it, or ``None``."""
    query = (
        select(StixObject.raw)
        .join(Submission, Submission.id == StixObject.submission_id)
        .join(Organization, Organization.id == Submission.submitter_org_id)
        .where(
            StixObject.stix_id == stix_id,
            Organization.org_type.in_(tuple(ISAC_OWNER_TYPES)),
            Submission.state.in_(tuple(_CANONICAL_STATES)),
            Submission.id != scope.exclude_submission_id,
        )
        .order_by(StixObject.modified.desc())
        .limit(1)
    )
    if scope.visible_to is not None:
        query = query.join(Distribution, Distribution.stix_object_id == StixObject.id).where(
            distribution_visibility_clause(scope.visible_to, scope.now)
        )
    raw: Mapping[str, Any] | None = (await session.execute(query)).scalars().first()
    return raw


async def _vendor_party_acknowledges(session: AsyncSession, stix_id: str) -> bool:
    """A vendor an editor put in a circle the target reached agreed, in a distributed opinion."""
    vendors_in_case = (
        select(CircleMembership.org_id)
        .join(Organization, Organization.id == CircleMembership.org_id)
        .join(Distribution, Distribution.circle_id == CircleMembership.circle_id)
        .join(StixObject, StixObject.id == Distribution.stix_object_id)
        .where(
            Organization.org_type == OrgType.VENDOR,
            CircleMembership.left_at.is_(None),
            StixObject.stix_id == stix_id,
        )
    )
    agreeing = await session.scalar(
        select(StixObject.id)
        .join(Submission, Submission.id == StixObject.submission_id)
        .where(
            StixObject.type == "opinion",
            StixObject.raw.contains({"object_refs": [stix_id]}),
            StixObject.raw["opinion"].astext.in_(tuple(_AGREEING_OPINIONS)),
            and_(
                Submission.state == SubmissionState.DISTRIBUTED,
                Submission.submitter_org_id.in_(vendors_in_case),
            ),
        )
        .limit(1)
    )
    return agreeing is not None


async def _target_problem(
    session: AsyncSession, scope_value: DiscoveryScope, stix_id: str, scope: DisclosureScope
) -> str | None:
    current = await _canonical_current(session, stix_id, scope)
    if current is None:
        return UNKNOWN_TARGET
    if scope_value is DiscoveryScope.DISCLOSED_THIRD_PARTY:
        if cve_status(current) == "published":
            return None
        return (
            f"{stix_id} is not public yet; a contribution before disclosure is "
            "coordinated_disclosure, which needs the vendor as a party to the case"
        )
    if _has_coordination_case(current) or await _vendor_party_acknowledges(session, stix_id):
        return None
    return (
        f"{stix_id} has no coordination case: the ISAC records the vendor as a party, or a "
        "VINCE or GOLD EAGLE case, before a coordinated contribution is accepted"
    )


async def disclosure_problem(
    session: AsyncSession,
    *,
    discovery_scope: DiscoveryScope,
    objects: Iterable[Mapping[str, Any]],
    scope: DisclosureScope,
) -> str | None:
    """Why a submission's scope is not legal for what it refers to, or ``None``."""
    if discovery_scope not in THIRD_PARTY_DISCOVERY_SCOPES:
        return None
    listed = list(objects)
    if any(obj.get("type") == "vulnerability" for obj in listed):
        return (
            f"a {discovery_scope.value} contribution carries no vulnerability of its own; "
            "it references the ISAC's record of one. File a finding of your own through "
            "the native API, with the discovery scope that describes it"
        )
    targets = sorted(external_references_by_type(listed, "vulnerability"))
    if not targets:
        return UNKNOWN_TARGET
    for stix_id in targets:
        problem = await _target_problem(session, discovery_scope, stix_id, scope)
        if problem is not None:
            return problem
    return None
