"""What a finished document's report may cite (Phase I, slice I3; SF-101).

A report names the objects it is about in ``object_refs``. Distributed, it
tells every reader that those ids exist and that one report concerns them all,
so it may cite only what its owner could already read: an object distributed
to the owner, or one the owner filed. Checked twice, from two views:

- at the finish, from the finisher's own (:func:`unseen_by_caller`), so a
  person cannot cite past their session's TLP ceiling;
- at validate, from the owner organisation's as it stands then
  (:func:`report_citation_problem`), since the owner may have left a circle
  while the report waited for review.

Neither says why an id is unseen: absent, invisible and embargoed are one
answer, as everywhere a member names an id (SF-47).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Mapping
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgStatus
from aivs_server.auth.context import AuthContext
from aivs_server.auth.memberships import load_circle_grants
from aivs_server.auth.policy import visible_content_clause
from aivs_server.db.models import Distribution, Document, Organization, StixObject, Submission
from aivs_server.services.attribution import submissions_filed_by
from aivs_server.services.instance import distribution_is_paused
from aivs_server.services.visible import visible_objects

__all__ = ["cited_ids", "report_citation_problem", "unseen_by_caller"]

#: The refusal at validate while distribution is paused. A pause empties every
#: organisation's view, so the owner's cannot be read until it resumes.
PAUSED: str = (
    "distribution is paused, and a finished document's report is checked against "
    "what its owner can read, which a pause hides; validate it once distribution resumes"
)


def cited_ids(objects: Iterable[Mapping[str, Any]]) -> set[str]:
    """The ids the bundle's reports cite, less those the bundle itself carries."""
    carried = {obj.get("id") for obj in objects}
    cited: set[str] = set()
    for obj in objects:
        refs = obj.get("object_refs") if obj.get("type") == "report" else None
        if isinstance(refs, list):
            cited.update(ref for ref in refs if isinstance(ref, str))
    return cited - carried


async def unseen_by_caller(
    session: AsyncSession, ctx: AuthContext, cited: set[str], *, now: dt.datetime
) -> list[str]:
    """The cited ids ``ctx`` cannot read now, nor filed itself."""
    seen = (
        visible_objects(ctx, now)
        .with_only_columns(StixObject.stix_id)
        .where(StixObject.stix_id.in_(cited))
    )
    return await _unseen(session, cited, seen, ctx.org_id)


async def report_citation_problem(
    session: AsyncSession, submission: Submission, objects: list[Any], *, now: dt.datetime
) -> str | None:
    """Why this document's report may not be validated, or ``None``.

    ``None`` for any other submission: keyed on the document's link to it,
    which only a finish writes.
    """
    owner = await session.scalar(
        select(Organization)
        .join(Document, Document.owner_org_id == Organization.id)
        .where(Document.report_submission_id == submission.id)
    )
    if owner is None:
        return None
    cited = cited_ids(objects)
    if not cited:
        return None
    if await distribution_is_paused(session):
        return PAUSED
    grants = await load_circle_grants(session, owner.id) if owner.status is OrgStatus.ACTIVE else {}
    seen = (
        select(StixObject.stix_id)
        .join(Submission, Submission.id == StixObject.submission_id)
        .join(Distribution, Distribution.stix_object_id == StixObject.id)
        .where(
            StixObject.stix_id.in_(cited),
            visible_content_clause(
                {circle: grant.intervals for circle, grant in grants.items()}, now
            ),
        )
    )
    unseen = await _unseen(session, cited, seen, owner.id)
    if not unseen:
        return None
    return (
        "this report cites objects its owner cannot read now: "
        f"{', '.join(unseen)}. Return it to the owner to cite what it can read."
    )


async def _unseen(
    session: AsyncSession, cited: set[str], seen: Select[Any], org_id: Any
) -> list[str]:
    filed = select(StixObject.stix_id).where(
        StixObject.submission_id.in_(await submissions_filed_by(org_id)),
        StixObject.stix_id.in_(cited),
    )
    found = set((await session.scalars(seen.union(filed))).all())
    return sorted(cited - found)
