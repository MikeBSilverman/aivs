"""Who reviewed an object, and the gate on what a machine may change (SF-6).

**The reviewer is written by validate, from the authenticated context.** The
provenance extension's ``human_reviewed_by_ref`` and ``reviewed_at`` say an ISAC
editor looked at this object and when. A submitter that sets them is claiming a
review that did not happen, so ingest refuses them, and here validate writes
them for every object from the operator who performed the transition.

The reviewer is named by a STIX identity derived from the operator's id
(``reviewer_identity_id``): stable, so a member can see two objects had the
same reviewer, and opaque, so it names nobody outside the ISAC.

**The AI gate.** A submission from an automation organisation (source
``system``) that changes something a member acts on without reading closely --
lowers a CVSS score or an SSVC value against the version members already have,
asserts a novel attack vector, or says a fix needs a system or parent restart
-- is refused at validate unless the editor names each such change as
acknowledged. Validate is already human-only (SF-42); what this adds is that a
consequential machine change cannot pass inside a routine click.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterable, Mapping
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from aivs_schemas.enums import SubmissionSource
from aivs_schemas.extension.builders import (
    AIVS_EXTENSION_ID,
    AIVS_INTEL_EXTENSION_ID,
    AIVS_PROVENANCE_EXTENSION_ID,
)
from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.taxii.resources import to_taxii_timestamp

__all__ = [
    "consequential_changes",
    "reviewer_identity_id",
    "stamp_review",
    "unacknowledged_changes_problem",
]

#: Namespace for reviewer identities. Fixed: changing it would give every
#: reviewer a new identity and break the link between objects they reviewed.
_REVIEWER_NAMESPACE: Final[uuid.UUID] = uuid.UUID("5d3c2a8e-7f4b-4c61-9e0a-2b6f8d1c4e73")

#: CSAF ``restart_required`` categories that take down more than the product.
_DISRUPTIVE_RESTARTS: Final[frozenset[str]] = frozenset({"system", "parent"})

#: SSVC v2 values in increasing urgency, CISA's spellings.
_SSVC_ORDER: Final[Mapping[str, tuple[str, ...]]] = {
    "ssvc_decision": ("Track", "Track*", "Attend", "Act"),
    "ssvc_exploitation": ("none", "poc", "active"),
}


def reviewer_identity_id(operator_id: uuid.UUID) -> str:
    """The STIX identity that names an ISAC operator as a reviewer."""
    return f"identity--{uuid.uuid5(_REVIEWER_NAMESPACE, str(operator_id))}"


def stamp_review(raw: Mapping[str, Any], *, reviewer: str, now: dt.datetime) -> dict[str, Any]:
    """``raw`` with the server-written reviewer fields, keeping the submitter's claims."""
    extensions = dict(raw.get("extensions") or {})
    body = dict(extensions.get(AIVS_PROVENANCE_EXTENSION_ID) or {})
    body.update(
        {
            "extension_type": "property-extension",
            "human_reviewed_by_ref": reviewer,
            "reviewed_at": to_taxii_timestamp(now),
        }
    )
    extensions[AIVS_PROVENANCE_EXTENSION_ID] = body
    return {**raw, "extensions": extensions}


def _body(raw: Mapping[str, Any]) -> dict[str, Any]:
    """The 1.0 and 2.0 extension properties of an object, merged (2.0 wins)."""
    extensions = raw.get("extensions") or {}
    merged: dict[str, Any] = {}
    for extension_id in (AIVS_EXTENSION_ID, AIVS_INTEL_EXTENSION_ID):
        body = extensions.get(extension_id)
        if isinstance(body, Mapping):
            merged.update(body)
    return merged


def _lowered(name: str, before: Any, after: Any) -> bool:
    if before is None or after is None:
        return False
    order = _SSVC_ORDER.get(name)
    if order is not None:
        return before in order and after in order and order.index(after) < order.index(before)
    return isinstance(before, (int, float)) and isinstance(after, (int, float)) and after < before


def _assertions(raw: Mapping[str, Any]) -> list[str]:
    """Consequential things an object asserts on its own, whatever came before."""
    body = _body(raw)
    found = []
    if body.get("novel_attack_vector") is True:
        found.append("novel_attack_vector")
    if body.get("restart_required") in _DISRUPTIVE_RESTARTS:
        found.append("restart_required")
    return found


def _lowerings(raw: Mapping[str, Any], previous: Mapping[str, Any] | None) -> list[str]:
    """Scores and SSVC values this version lowers against the one members hold."""
    if previous is None:
        return []
    before, after = _body(previous), _body(raw)
    names = ("cvss_v4_base_score", *_SSVC_ORDER)
    return [name for name in names if _lowered(name, before.get(name), after.get(name))]


async def _distributed_versions(
    session: AsyncSession, submission: Submission, stix_ids: set[str]
) -> dict[str, Mapping[str, Any]]:
    """The latest distributed version of each id from this submission's owner, before it.

    The owner as ownership defines it: an automation filing on the ISAC's record
    is compared with the ISAC's version. Comparing within the filing
    organisation found no previous version there, so a machine lowering the
    ISAC's score needed no acknowledgement.
    """
    own = aliased(StixObject)
    rows = (
        await session.execute(
            select(StixObject.stix_id, StixObject.raw)
            .join(Distribution, Distribution.stix_object_id == StixObject.id)
            .join(
                own,
                (own.stix_id == StixObject.stix_id) & (own.owner_token == StixObject.owner_token),
            )
            .where(
                StixObject.stix_id.in_(stix_ids),
                own.submission_id == submission.id,
                StixObject.submission_id != submission.id,
            )
            .order_by(StixObject.stix_id, StixObject.modified.desc())
            .distinct(StixObject.stix_id)
        )
    ).all()
    return {str(stix_id): raw for stix_id, raw in rows}


async def consequential_changes(
    session: AsyncSession, submission: Submission, objects: Iterable[Mapping[str, Any]]
) -> list[str]:
    """``<stix id>:<property>`` for each consequential change a system submission makes.

    Empty for a member's submission: the gate is on machine-made changes.
    """
    if submission.source is not SubmissionSource.SYSTEM:
        return []
    listed = [obj for obj in objects if isinstance(obj.get("id"), str)]
    previous = await _distributed_versions(session, submission, {obj["id"] for obj in listed})
    return sorted(
        f"{obj['id']}:{name}"
        for obj in listed
        for name in (*_assertions(obj), *_lowerings(obj, previous.get(obj["id"])))
    )


def unacknowledged_changes_problem(
    changes: Iterable[str], acknowledged: Iterable[str]
) -> str | None:
    """Why validate is refused, or ``None`` when every change is acknowledged."""
    missing = sorted(set(changes) - set(acknowledged))
    if not missing:
        return None
    return (
        "this machine-filed submission makes consequential changes an editor must "
        f"acknowledge by name before validating: {', '.join(missing)}"
    )
