"""The ISAC's own records, for its automation to version (``services.isac_records``).

Anyone else gets the 404 a route that does not exist would give: the route is
for one machine identity, and a member learns nothing from its existence that
the published API does not already say.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from aivs_server.auth.deps import AuthenticatedContext, SessionDep
from aivs_server.auth.policy import can_read_isac_records
from aivs_server.db.clock import database_now
from aivs_server.services.isac_records import latest_isac_vulnerabilities

__all__ = ["router"]

router = APIRouter(prefix="/api/v1/isac-records", tags=["automation"])


class IsacRecordsOut(BaseModel):
    objects: list[dict[str, Any]]
    #: Records left out because the automation's own draft of them still waits
    #: for an editor: their KEV updates stall until it is sent.
    waiting_drafts: int


@router.get("/vulnerabilities", response_model=IsacRecordsOut)
async def isac_vulnerabilities(ctx: AuthenticatedContext, session: SessionDep) -> IsacRecordsOut:
    """The newest version of each of the ISAC's vulnerability records. Its automation only."""
    if not can_read_isac_records(ctx):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    records = await latest_isac_vulnerabilities(session, now=await database_now(session))
    return IsacRecordsOut(objects=records.objects, waiting_drafts=records.waiting_drafts)
