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

Everything that asks "the same owner's versions of this object" -- this
check, newest-only, the anonymity pin, the feed's ``match[version]``, the AI
gate's previous version, the canonical record -- asks it of
``stix_objects.owner_token``: equal tokens on one id are one owner, and the
ISAC's and its automation's token is the constant ``ISAC_OWNER``
(``services.attribution.owner_tokens_for``, which ingest calls). So the
equivalence has one definition, and none of these asks who the owner is:
the token names nobody (Phase P, S2-1).
"""

from __future__ import annotations

from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from aivs_schemas.enums import OrgType
from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.services.attribution import ISAC_OWNER

__all__ = [
    "ISAC_OWNER",
    "ISAC_OWNER_TYPES",
    "STALE_VERSION",
    "foreign_owned_versions_problem",
    "is_isac_owner",
    "stale_version_problem",
]

#: The organisations that are the ISAC, for ownership: its own, and its machine.
ISAC_OWNER_TYPES: Final[frozenset[OrgType]] = frozenset({OrgType.ADMIN, OrgType.AUTOMATION})


def is_isac_owner(org_type: OrgType | None) -> bool:
    """Whether an organisation of ``org_type`` counts as the ISAC, for ownership and attribution.

    The one Python statement of the equivalence. Ownership asks it to decide
    whose versions an organisation may publish; distribution asks it to decide
    whose name a version carries. Asked separately, the two drifted: the KEV
    script versioned the ISAC's record as the ISAC, and distribution stamped
    the version with the automation's own identity, so members saw the ISAC's
    canonical record re-attributed to a machine. Ingest gives the ISAC's
    versions the one token ``ISAC_OWNER`` by ``policy.ISAC_FILER_TYPES``, which
    a test holds equal to ``ISAC_OWNER_TYPES``.
    """
    return org_type in ISAC_OWNER_TYPES


async def foreign_owned_versions_problem(
    session: AsyncSession, submission: Submission
) -> str | None:
    """Why ``submission`` may not publish these versions, or ``None``.

    Some other owner already distributed a version of one of its ids: a
    distributed row of the same id whose owner token is not this
    submission's own for that id.
    """
    own = aliased(StixObject)
    other = aliased(StixObject)
    taken = (
        await session.execute(
            select(own.stix_id)
            .distinct()
            .join(
                other,
                (other.stix_id == own.stix_id) & (other.owner_token != own.owner_token),
            )
            .join(Distribution, Distribution.stix_object_id == other.id)
            .where(own.submission_id == submission.id)
            .order_by(own.stix_id)
        )
    ).scalars()
    foreign = list(taken)
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
    stale = (
        (
            await session.execute(
                select(own.stix_id)
                .distinct()
                .join(
                    other,
                    (other.stix_id == own.stix_id)
                    & (other.owner_token == own.owner_token)
                    & (other.submission_id != own.submission_id)
                    & (other.modified >= own.modified),
                )
                .join(Distribution, Distribution.stix_object_id == other.id)
                .where(own.submission_id == submission.id)
                .order_by(own.stix_id)
            )
        )
        .scalars()
        .all()
    )
    if not stale:
        return None
    return f"{STALE_VERSION}: {', '.join(stale)}"
