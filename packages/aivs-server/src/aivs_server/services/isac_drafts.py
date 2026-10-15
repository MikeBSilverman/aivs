"""The ISAC's and its automation's own drafts, waiting for an editor (Mike, Q36).

Since Q15 and Q35 an analyst may draft for the ISAC and the automation may file
a KEV version, but only an ISAC editor may send either for review. Nothing
listed them, so a draft sat unnoticed -- and an automation draft holds its
record back from the next KEV run (``services.isac_records``), so a forgotten
one stalls that record's KEV updates. This is the list an editor works from,
and the count the status page shows when one has waited too long.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgType, SubmissionState
from aivs_server.auth.policy import ISAC_FILER_TYPES
from aivs_server.db.models import Operator, Organization, Submission
from aivs_server.services.attribution import creator_column, submitter_column

__all__ = ["STALE_AFTER", "StaleDrafts", "WaitingDraft", "stale_isac_drafts", "waiting_isac_drafts"]

#: How long a draft may wait before the status page calls it stale.
STALE_AFTER: Final[dt.timedelta] = dt.timedelta(days=7)


@dataclass(frozen=True)
class WaitingDraft:
    submission: Submission
    #: The person who drafted it, or ``None`` for the automation's filing.
    created_by: str | None
    by_automation: bool


@dataclass(frozen=True)
class StaleDrafts:
    #: Drafts by ISAC staff older than ``STALE_AFTER``.
    isac: int
    #: The automation's KEV drafts older than ``STALE_AFTER``: each stalls its record.
    kev: int


async def waiting_isac_drafts(session: AsyncSession) -> list[WaitingDraft]:
    """Every draft whose owner is the ISAC or its automation, oldest first.

    By the owner's organisation type, the grouping the submitter's verbs use
    (``policy.ISAC_FILER_TYPES``): a member's draft is its own and never listed.
    """
    rows = await session.execute(
        select(Submission, Operator.display_name, Organization.org_type)
        .join(Organization, Organization.id == submitter_column(Submission))
        .outerjoin(Operator, Operator.id == creator_column(Submission))
        .where(
            Submission.state == SubmissionState.DRAFT,
            Organization.org_type.in_(tuple(ISAC_FILER_TYPES)),
        )
        .order_by(Submission.created_at, Submission.id)
    )
    return [
        WaitingDraft(
            submission=submission,
            created_by=name,
            by_automation=org_type is OrgType.AUTOMATION,
        )
        for submission, name, org_type in rows.all()
    ]


async def stale_isac_drafts(session: AsyncSession, *, now: dt.datetime) -> StaleDrafts:
    """How many of the ISAC's and the automation's drafts have waited past ``STALE_AFTER``."""
    rows = await session.execute(
        select(Organization.org_type, func.count())
        .select_from(Submission)
        .join(Organization, Organization.id == submitter_column(Submission))
        .where(
            Submission.state == SubmissionState.DRAFT,
            Organization.org_type.in_(tuple(ISAC_FILER_TYPES)),
            Submission.created_at < now - STALE_AFTER,
        )
        .group_by(Organization.org_type)
    )
    counts: dict[OrgType, int] = {org_type: int(count) for org_type, count in rows.all()}
    return StaleDrafts(isac=counts.get(OrgType.ADMIN, 0), kev=counts.get(OrgType.AUTOMATION, 0))
