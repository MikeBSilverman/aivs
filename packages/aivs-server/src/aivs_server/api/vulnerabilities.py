"""Read-side views of one vulnerability, computed for the caller.

Readiness lives here and not in TAXII: it is derived from what the caller can
see, so two members asking about one vulnerability may rightly get different
answers, and TAXII serves content rather than conclusions about content
someone else may hold (SF-8).
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Annotated, Any, Final

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from aivs_server.auth.deps import AuthenticatedContext, SessionDep
from aivs_server.db.clock import database_now
from aivs_server.services.exploitability import ExploitabilityStatus, exploitability_for
from aivs_server.services.readiness import Availability, readiness_for
from aivs_server.services.visible import VulnerabilityNotVisibleError

__all__ = ["router"]

router = APIRouter(prefix="/api/v1", tags=["vulnerabilities"])

_VULNERABILITY_ID: Final[re.Pattern[str]] = re.compile(
    r"^vulnerability--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class ReadinessOut(BaseModel):
    """What's available for a vulnerability, as the caller can see it."""

    vulnerability: str
    remediation: Availability
    mitigation: Availability
    detection: Availability
    validation: Availability
    #: For each group that is ``lapsed``: the last day its claim was vouched
    #: for (its ``review_by``), or null when that date was not a date. A
    #: lapsed group is neither available nor stated none -- ask the ISAC.
    not_confirmed_since: dict[str, dt.date | None]


@router.get("/vulnerabilities/readiness", response_model=ReadinessOut)
async def readiness(
    ctx: AuthenticatedContext,
    session: SessionDep,
    stix_id: Annotated[str, Query(alias="id", max_length=100)],
) -> ReadinessOut:
    """Remediation, mitigation, detection and validation: available, none, lapsed, or unknown.

    ``lapsed`` means a claim the caller can see -- a fix exists, or none does --
    has passed its ``review_by`` and nobody has re-checked it since; it is not a
    statement either way.

    A malformed id, an unknown id, and one the caller cannot see all answer the
    same 404, so the endpoint confirms nothing about what exists (SF-47). The
    id is a query parameter, not a path segment: request paths are logged with
    the caller's identity and forwarded off the platform, and the query string
    is not.
    """
    not_found = HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    if _VULNERABILITY_ID.match(stix_id) is None:
        raise not_found
    try:
        found = await readiness_for(session, ctx, stix_id, now=await database_now(session))
    except VulnerabilityNotVisibleError:
        raise not_found from None
    return ReadinessOut(
        vulnerability=stix_id,
        remediation=found.remediation,
        mitigation=found.mitigation,
        detection=found.detection,
        validation=found.validation,
        not_confirmed_since=dict(found.not_confirmed_since),
    )


class ConditionSourceOut(BaseModel):
    """One visible note's conditions, named by the note, never by who filed it."""

    note: str
    modified: dt.datetime
    summary: str
    conditions: list[dict[str, Any]]
    unknowns: list[str]
    reproduced: bool | None


class ExploitabilityOut(BaseModel):
    """What makes a vulnerability exploitable, as the caller can see it (Phase N).

    ``not_established``: assume affected. ``agreed``: exploitable only when
    every one of ``conditions`` holds, each by any one of its alternatives.
    ``contested``: the sources differ and no merged set is given; a member is
    not affected only if every source's conditions fail for it.
    """

    vulnerability: str
    status: ExploitabilityStatus
    conditions: list[dict[str, Any]]
    sources: list[ConditionSourceOut]


@router.get("/vulnerabilities/exploitability", response_model=ExploitabilityOut)
async def exploitability(
    ctx: AuthenticatedContext,
    session: SessionDep,
    stix_id: Annotated[str, Query(alias="id", max_length=100)],
) -> ExploitabilityOut:
    """The conditions under which a vulnerability is exploitable, from the notes the caller can see.

    The same 404 for a malformed, an unknown and an invisible id, and the id in
    the query rather than the path, for the reasons readiness gives (SF-47).
    """
    if _VULNERABILITY_ID.match(stix_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    try:
        view = await exploitability_for(session, ctx, stix_id, now=await database_now(session))
    except VulnerabilityNotVisibleError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found") from None
    return ExploitabilityOut(
        vulnerability=stix_id,
        status=view.status,
        conditions=[dict(condition) for condition in view.conditions],
        sources=[
            ConditionSourceOut(
                note=source.note_id,
                modified=source.modified,
                summary=source.summary,
                conditions=[dict(condition) for condition in source.conditions],
                unknowns=list(source.unknowns),
                reproduced=source.reproduced,
            )
            for source in view.sources
        ],
    )
