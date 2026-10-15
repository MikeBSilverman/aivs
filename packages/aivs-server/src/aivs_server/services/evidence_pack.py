"""The member evidence pack: what reached this firm about one vulnerability, and what it did.

The member's answer to its regulator (DORA, NYDFS 500): for one vulnerability,
every version of the advisory -- the vulnerability and every object related
to it -- as it reached this organisation, with the interval each was the one
in force; this organisation's own receipts; its own posture; and the ISAC's
review stamp on each version. Content-hashed, so the pack a member files with
its regulator can later be shown to be the one the platform produced (the
hash is recorded in the audit trail).

**The member's alone.** Built for the caller's own organisation from what that
organisation could read (``services.visible``), and refused to everyone else
with the 404 an unknown vulnerability gets -- the ISAC included, because the
pack is the member's record of the member's conduct, and the ISAC already
holds the receipts it is built from.

**What it cannot show.** Posture is kept as its current row, not a history, so
the pack states the posture now and when it was last changed. Earlier
statuses are not recorded anywhere and the pack does not pretend otherwise.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.extension.builders import AIVS_PROVENANCE_EXTENSION_ID
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import (
    Acknowledgment,
    Distribution,
    Organization,
    OrgPosture,
    StixObject,
)
from aivs_server.services.visible import ever_related_stix_ids, visible_objects

__all__ = ["EvidencePack", "evidence_pack"]

#: Named in the pack, so a reader years later knows how it was built.
PACK_FORMAT = "aivs-evidence-pack/1"


@dataclass(frozen=True)
class EvidencePack:
    body: Mapping[str, Any]
    #: SHA-256 of the canonical JSON of ``body``: sorted keys, no whitespace.
    sha256: str


async def evidence_pack(
    session: AsyncSession, ctx: AuthContext, vulnerability_stix_id: str, *, now: dt.datetime
) -> EvidencePack | None:
    """The pack for the caller's organisation, or ``None`` if it cannot see the vulnerability.

    The caller decides whether this organisation may hold a pack at all
    (``policy.can_hold_evidence_pack``); this builds it from what it could read.
    """
    visible = visible_objects(ctx, now)
    advisory = await _versions(session, visible, [vulnerability_stix_id])
    if not advisory:
        return None
    related = await _versions(
        session, visible, await ever_related_stix_ids(session, visible, vulnerability_stix_id)
    )
    versions = [*advisory, *(v for v in related if v["type"] != "relationship")]
    submission_ids = {uuid.UUID(v["submission_id"]) for v in versions}
    body = {
        "format": PACK_FORMAT,
        "generated_at": _stamp(now),
        "organization": await _organisation(session, ctx.org_id),
        "vulnerability": vulnerability_stix_id,
        "versions": versions,
        "receipts": await _receipts(session, ctx.org_id, submission_ids),
        "posture": await _posture(session, ctx.org_id, vulnerability_stix_id),
    }
    return EvidencePack(body=body, sha256=content_hash(body))


def content_hash(body: Mapping[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


# ---------------------------------------------------------------------------
# The parts
# ---------------------------------------------------------------------------
async def _versions(
    session: AsyncSession, visible: Select[Any], stix_ids: Sequence[str]
) -> list[dict[str, Any]]:
    """Every visible version of each object, with the interval it was in force here."""
    if not stix_ids:
        return []
    rows = (
        await session.execute(
            visible.with_only_columns(
                StixObject.stix_id,
                StixObject.type,
                StixObject.modified,
                StixObject.submission_id,
                StixObject.raw,
                func.min(Distribution.date_added),
            )
            .where(StixObject.stix_id.in_(sorted(set(stix_ids))))
            .group_by(StixObject.id)
        )
    ).all()
    return _in_force(
        {
            "stix_id": stix_id,
            "type": stix_type,
            "modified": _stamp(modified),
            "submission_id": str(submission_id),
            "sha256": content_hash(raw),
            "isac_reviewed_at": _reviewed_at(raw),
            "reached_us_at": _stamp(reached),
        }
        for stix_id, stix_type, modified, submission_id, raw, reached in rows
    )


def _in_force(versions: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each version is in force from when it reached us until the next one of its object did."""
    ordered = sorted(versions, key=lambda v: (v["stix_id"], v["reached_us_at"], v["modified"]))
    for index, current in enumerate(ordered):
        following = ordered[index + 1] if index + 1 < len(ordered) else None
        if following is not None and following["stix_id"] == current["stix_id"]:
            current["in_force_until"] = following["reached_us_at"]
        else:
            current["in_force_until"] = None
    return ordered


def _reviewed_at(raw: Mapping[str, Any]) -> str | None:
    extensions = raw.get("extensions") or {}
    provenance = extensions.get(AIVS_PROVENANCE_EXTENSION_ID) or {}
    reviewed = provenance.get("reviewed_at")
    return reviewed if isinstance(reviewed, str) else None


async def _organisation(session: AsyncSession, org_id: uuid.UUID) -> dict[str, str]:
    organisation = await session.get(Organization, org_id)
    name = organisation.name if organisation is not None else ""
    return {"id": str(org_id), "name": name}


async def _receipts(
    session: AsyncSession, org_id: uuid.UUID, submission_ids: set[uuid.UUID]
) -> list[dict[str, Any]]:
    """This organisation's own receipts and assertions; never another firm's."""
    if not submission_ids:
        return []
    rows = (
        await session.execute(
            select(
                Acknowledgment.submission_id,
                Acknowledgment.ack_type,
                Acknowledgment.via,
                Acknowledgment.created_at,
            )
            .where(
                Acknowledgment.org_id == org_id,
                Acknowledgment.submission_id.in_(submission_ids),
            )
            .order_by(Acknowledgment.created_at, Acknowledgment.id)
        )
    ).all()
    return [
        {
            "submission_id": str(submission_id),
            "type": str(ack_type),
            "via": str(via),
            "at": _stamp(at),
        }
        for submission_id, ack_type, via, at in rows
    ]


async def _posture(session: AsyncSession, org_id: uuid.UUID, stix_id: str) -> dict[str, Any] | None:
    row = await session.scalar(
        select(OrgPosture).where(
            OrgPosture.org_id == org_id, OrgPosture.vulnerability_stix_id == stix_id
        )
    )
    if row is None:
        return None
    # The VEX statement as the member made it, and when the member last
    # confirmed it held: the "validation" a regulator asks about.
    return {
        "status": str(row.status),
        "justification": None if row.justification is None else str(row.justification),
        "impact_statement": row.impact_statement,
        "action_statement": row.action_statement,
        "products": list(row.products or []),
        "detection_deployed": row.detection_deployed,
        "validated_at": None if row.validated_at is None else _stamp(row.validated_at),
        "evidence_note": row.evidence_note,
        "updated_at": _stamp(row.updated_at),
    }


def _stamp(value: dt.datetime) -> str:
    return value.astimezone(dt.UTC).isoformat()
