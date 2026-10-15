"""Only the owner versions an object (SF-48).

A STIX consumer merges by ``id`` and ``modified``: a newer ``modified`` for an
id replaces what the consumer held. So a contributor that files its own object
under another firm's ``stix_id`` with a later ``modified`` rewrites that firm's
content in every member's TIP -- a vendor turning a member's workaround into
"not needed", a member quietly editing the ISAC's advisory. Everyone else
*references* an object (a ``relationship``, an ``opinion``); only the
organisation that first distributed an id may publish a newer version of it.

The owner is the submitting organisation of a distributed row, which the ISAC
always knows, including for anonymous submissions. Checked at validate and at
distribution, where the actor is the ISAC and sees everything; never at ingest,
where a refusal would tell a member that an id it cannot see is somebody's.
A ``relationship`` is owned like anything else. It used to be exempt, on the
reading that two parties relating the same pair make two statements -- but two
statements have two ids. The exemption let any organisation publish a newer
version under *another firm's* relationship id (``revoked: true`` on a member's
``mitigates``), which a TIP then applied. Relating two objects someone else
owns is referencing them, and needs no exemption.

**The ISAC is one owner.** The automation organisation is by definition the
ISAC's own machine identity -- the database allows one, as it allows one admin
organisation -- so its versions count as the ISAC's and the ISAC's as its: the
KEV enrichment script versions the ISAC's canonical record. An editor still
validates each such submission, and the AI gate compares it with the ISAC's
previous version (SF-6). It versions nobody else's object.

Everything that asks "whose version is this" -- this check, the feed's
``match[version]``, the AI gate's previous version, the canonical record --
asks it through ``owner_key``, so the equivalence has one definition.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from typing import Any, Final

from sqlalchemy import String, case, cast, literal, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased
from sqlalchemy.sql.elements import ColumnElement

from aivs_schemas.enums import OrgType
from aivs_server.db.models import Distribution, Organization, StixObject, Submission

__all__ = [
    "ISAC_OWNER",
    "ISAC_OWNER_TYPES",
    "STALE_VERSION",
    "foreign_owned_versions_problem",
    "is_isac_owner",
    "owner_key",
    "stale_version_problem",
]

#: The organisations that are the ISAC, for ownership: its own, and its machine.
ISAC_OWNER_TYPES: Final[frozenset[OrgType]] = frozenset({OrgType.ADMIN, OrgType.AUTOMATION})

#: ``owner_key``'s value for a version the ISAC or its automation filed.
ISAC_OWNER: Final[str] = "isac"


def is_isac_owner(org_type: OrgType | None) -> bool:
    """Whether an organisation of ``org_type`` counts as the ISAC, for ownership and attribution.

    The one Python statement of the equivalence. Ownership asks it to decide
    whose versions an organisation may publish; distribution asks it to decide
    whose name a version carries. Asked separately, the two drifted: the KEV
    script versioned the ISAC's record as the ISAC, and distribution stamped
    the version with the automation's own identity, so members saw the ISAC's
    canonical record re-attributed to a machine. ``owner_key`` is the same
    rule in SQL, over the same ``ISAC_OWNER_TYPES``.
    """
    return org_type in ISAC_OWNER_TYPES


def owner_key(submitter_org_id: Any) -> ColumnElement[str]:
    """The owner a version counts as, in SQL: ``ISAC_OWNER``, or the submitting org's id."""
    isac_orgs = select(Organization.id).where(Organization.org_type.in_(tuple(ISAC_OWNER_TYPES)))
    return case(
        (submitter_org_id.in_(isac_orgs), literal(ISAC_OWNER)),
        else_=cast(submitter_org_id, String),
    )


async def _owners_like(session: AsyncSession, org_id: uuid.UUID) -> set[uuid.UUID]:
    """``org_id`` and every organisation whose versions count as its own."""
    org_type = await session.scalar(select(Organization.org_type).where(Organization.id == org_id))
    if not is_isac_owner(org_type):
        return {org_id}
    isac = await session.execute(
        select(Organization.id).where(Organization.org_type.in_(tuple(ISAC_OWNER_TYPES)))
    )
    return set(isac.scalars().all())


async def foreign_owned_versions_problem(
    session: AsyncSession, objects: Iterable[Mapping[str, Any]], *, owner_org_id: uuid.UUID
) -> str | None:
    """Why these objects may not be published by ``owner_org_id``, or ``None``."""
    ids = {obj["id"] for obj in objects if isinstance(obj.get("id"), str)}
    if not ids:
        return None
    owners = await _owners_like(session, owner_org_id)
    taken = (
        await session.execute(
            select(StixObject.stix_id)
            .distinct()
            .join(Distribution, Distribution.stix_object_id == StixObject.id)
            .join(Submission, Submission.id == StixObject.submission_id)
            .where(StixObject.stix_id.in_(ids), Submission.submitter_org_id.not_in(owners))
        )
    ).scalars()
    foreign = sorted(taken)
    if not foreign:
        return None
    return (
        "only the organisation that first distributed an object may publish a new "
        f"version of it; reference it instead (a relationship or an opinion): {', '.join(foreign)}"
    )


#: The editor's refusal. One sentence and the ids: the editor sees the ISAC's
#: view of everything, so naming them confirms nothing it could not see.
STALE_VERSION: Final[str] = (
    "a version must be later than every version of the same object already "
    "distributed by its owner; file it with a later modified"
)


async def stale_version_problem(session: AsyncSession, submission: Submission) -> str | None:
    """Why some of ``submission``'s versions would not be the newest, or ``None``.

    Members' TIPs keep the version with the latest ``modified``. A version
    published with a ``modified`` no later than one its owner already
    distributed is therefore published and never shown: a late correction
    loses silently to the version it corrects -- the "warning a member would
    swear they never received" (CLAUDE.md section 5) -- and an equal one is
    taken for the same version and dropped.

    Compared with every version of the same object, by the same owner (the
    ISAC and its automation are one owner, so a KEV version filed over an ISAC
    draft correction counts), that has any distribution: embargoed and not yet
    readable, withdrawn or superseded since. Members hold what was delivered,
    and an embargo will be. The submission's own rows are left out, so its
    embargo release is not refused against itself. Stored versions on both
    sides, so the comparison is the one the database's uniqueness uses.
    """
    own = aliased(StixObject)
    other = aliased(StixObject)
    other_submission = aliased(Submission)
    owners = await _owners_like(session, submission.submitter_org_id)
    stale = (
        (
            await session.execute(
                select(own.stix_id)
                .distinct()
                .join(
                    other,
                    (other.stix_id == own.stix_id)
                    & (other.submission_id != own.submission_id)
                    & (other.modified >= own.modified),
                )
                .join(Distribution, Distribution.stix_object_id == other.id)
                .join(other_submission, other_submission.id == other.submission_id)
                .where(
                    own.submission_id == submission.id,
                    other_submission.submitter_org_id.in_(owners),
                )
                .order_by(own.stix_id)
            )
        )
        .scalars()
        .all()
    )
    if not stale:
        return None
    return f"{STALE_VERSION}: {', '.join(stale)}"
