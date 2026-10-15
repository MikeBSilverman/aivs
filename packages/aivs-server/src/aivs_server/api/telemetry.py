"""Telemetry for the submitter: what happened to what it shared.

The submitter's organisation only. Anyone else, the ISAC included, gets 404:
the ISAC already has the receipts, and a count addressed to the wrong reader
is a disclosure of who engaged with whom.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from aivs_server.auth.deps import AttributionKeyDep, AuthenticatedContext, SessionDep
from aivs_server.db.models import Submission
from aivs_server.services.attribution import is_submitted_by
from aivs_server.services.telemetry import Count, submission_telemetry

__all__ = ["router"]

router = APIRouter(prefix="/api/v1/submissions", tags=["submissions"])


class CountOut(BaseModel):
    value: int | None
    withheld: str | None


class TelemetryOut(BaseModel):
    submission_id: uuid.UUID
    distributed: bool
    reach: CountOut
    retrieved: CountOut
    acknowledged: CountOut
    actioned: CountOut
    #: When these counts were published; null before the first snapshot. Counts
    #: are replaced only once K organisations' receipts or reach have changed.
    as_of: dt.datetime | None
    later: list[str]


def _out(count: Count) -> CountOut:
    return CountOut(value=count.value, withheld=count.withheld)


@router.get("/{submission_id}/telemetry", response_model=TelemetryOut)
async def get_telemetry(
    submission_id: uuid.UUID,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> TelemetryOut:
    """Reach and engagement for one of the caller's own submissions, k-suppressed."""
    submission = await session.get(Submission, submission_id)
    if submission is None or not is_submitted_by(key, submission, ctx.org_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Submission not found")
    telemetry = await submission_telemetry(session, submission)
    return TelemetryOut(
        submission_id=telemetry.submission_id,
        distributed=telemetry.distributed,
        reach=_out(telemetry.reach),
        retrieved=_out(telemetry.retrieved),
        acknowledged=_out(telemetry.acknowledged),
        actioned=_out(telemetry.actioned),
        as_of=telemetry.as_of,
        later=list(telemetry.later),
    )
