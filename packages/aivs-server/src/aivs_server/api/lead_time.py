"""Lead time over the API: a member's own quarterly statement, and the ISAC's sector median.

Who may ask is decided here, before anything is computed: the statement by
the organisation it describes and nobody else, the median by the ISAC's
reviewers. Both refuse with the same 404 as an absent route, so a caller
learns nothing about another organisation's statement by asking for it.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status

from aivs_server.auth.deps import AuthenticatedContext, SessionDep
from aivs_server.auth.policy import can_read_own_lead_time, can_review_submissions
from aivs_server.db.clock import database_now
from aivs_server.services.lead_time import Quarter, org_statement, sector_median

__all__ = ["router"]

router = APIRouter(prefix="/api/v1", tags=["lead time"])

_NOT_FOUND = HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

QuarterParam = Annotated[str, Query(pattern=r"^[0-9]{4}[Qq][1-4]$", examples=["2026Q3"])]


@router.get("/organizations/{org_id}/lead-time")
async def own_statement(
    org_id: uuid.UUID, quarter: QuarterParam, ctx: AuthenticatedContext, session: SessionDep
) -> dict[str, Any]:
    """The organisation's lead time over NVD and KEV for one quarter, and what it actioned.

    Readable by that organisation only; everyone else, the ISAC included, 404.
    """
    if not can_read_own_lead_time(ctx, org_id):
        raise _NOT_FOUND
    statement = await org_statement(
        session, ctx, Quarter.parse(quarter), now=await database_now(session)
    )
    return asdict(statement)


@router.get("/lead-time/sector")
async def sector(
    quarter: QuarterParam, ctx: AuthenticatedContext, session: SessionDep
) -> dict[str, Any]:
    """The ISAC's median lead over NVD and KEV for one quarter, withheld below k."""
    if not can_review_submissions(ctx):
        raise _NOT_FOUND
    median = await sector_median(session, Quarter.parse(quarter), now=await database_now(session))
    return asdict(median)
