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
``relationship`` objects are exempt: two parties relating the same pair is two
statements, not one rewritten.

**The ISAC is one owner.** The automation organisation is by definition the
ISAC's own machine identity, so its versions count as the ISAC's and the ISAC's
as its: the KEV enrichment script versions the ISAC's canonical record. An
editor still validates each such submission, and the AI gate applies because
its source is ``system`` (SF-6). It versions nobody else's object.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgType
from aivs_server.db.models import Distribution, Organization, StixObject, Submission

__all__ = ["foreign_owned_versions_problem"]

#: Object types anyone may file under an id another party already uses.
_UNOWNED_TYPES: Final[frozenset[str]] = frozenset({"relationship"})

#: The organisations that are the ISAC, for ownership: its own, and its machine.
_ISAC_OWNER_TYPES: Final[frozenset[OrgType]] = frozenset({OrgType.ADMIN, OrgType.AUTOMATION})


async def _owners_like(session: AsyncSession, org_id: uuid.UUID) -> set[uuid.UUID]:
    """``org_id`` and every organisation whose versions count as its own."""
    org_type = await session.scalar(select(Organization.org_type).where(Organization.id == org_id))
    if org_type not in _ISAC_OWNER_TYPES:
        return {org_id}
    isac = await session.execute(
        select(Organization.id).where(Organization.org_type.in_(tuple(_ISAC_OWNER_TYPES)))
    )
    return set(isac.scalars().all())


async def foreign_owned_versions_problem(
    session: AsyncSession, objects: Iterable[Mapping[str, Any]], *, owner_org_id: uuid.UUID
) -> str | None:
    """Why these objects may not be published by ``owner_org_id``, or ``None``."""
    ids = {
        obj["id"]
        for obj in objects
        if isinstance(obj.get("id"), str) and obj.get("type") not in _UNOWNED_TYPES
    }
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
