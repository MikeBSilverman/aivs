"""Sector events over the API: pin, unpin, list what you may see, and file call notes.

Opening, closing and filing call notes are an editor's; the role check comes
before any lookup, so an event id is no oracle. The listing answers every
active caller with the events on vulnerabilities it can see, and nothing else.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from aivs_schemas.enums import TLP, DiscoveryScope
from aivs_server.auth.deps import AttributionKeyDep, AuthenticatedContext, SessionDep
from aivs_server.auth.policy import is_isac_editor, require
from aivs_server.db.clock import database_now
from aivs_server.db.models import SectorEvent
from aivs_server.services.sector_events import (
    MAX_ACTION_ITEMS,
    SectorEventError,
    call_notes_bundle,
    close_sector_event,
    open_sector_event,
    pinned_events,
)
from aivs_server.services.submissions import STORAGE_ERRORS, SubmissionError, create_submission

__all__ = ["router"]

router = APIRouter(prefix="/api/v1", tags=["sector events"])

_NOT_FOUND = HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")


class SectorEventOpen(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerability_stix_id: Annotated[str, Field(max_length=100)]


class CallNotes(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: Annotated[str, Field(min_length=1, max_length=10_000)]
    action_items: Annotated[
        list[Annotated[str, Field(max_length=2_000)]], Field(max_length=MAX_ACTION_ITEMS)
    ] = []
    tlp: TLP = TLP.AMBER
    #: Named by the editor, and judged by the same disclosure rules as any
    #: filing: a call on a public CVE differs from one on a coordinated case.
    discovery_scope: DiscoveryScope


@router.get("/sector-events")
async def list_events(ctx: AuthenticatedContext, session: SessionDep) -> list[dict[str, Any]]:
    """Open sector events on vulnerabilities the caller can see."""
    events = await pinned_events(session, ctx, now=await database_now(session))
    return [asdict(event) for event in events]


@router.post("/sector-events", status_code=status.HTTP_201_CREATED)
async def open_event(
    payload: SectorEventOpen, ctx: AuthenticatedContext, session: SessionDep
) -> dict[str, str]:
    """Pin the ISAC's distributed record for a vulnerability. An editor only."""
    try:
        event = await open_sector_event(
            session, ctx, payload.vulnerability_stix_id, now=await database_now(session)
        )
        await session.commit()
    except SectorEventError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"id": str(event.id), "vulnerability_stix_id": event.vulnerability_stix_id}


@router.post("/sector-events/{event_id}/close")
async def close_event(
    event_id: uuid.UUID, ctx: AuthenticatedContext, session: SessionDep
) -> dict[str, str]:
    """Unpin an event. An editor only."""
    try:
        event = await close_sector_event(session, ctx, event_id, now=await database_now(session))
        if event is None:
            raise _NOT_FOUND
        await session.commit()
    except SectorEventError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"id": str(event.id), "closed_at": str(event.closed_at)}


@router.post("/sector-events/{event_id}/call-notes", status_code=status.HTTP_201_CREATED)
async def file_call_notes(
    event_id: uuid.UUID,
    payload: CallNotes,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
) -> dict[str, str]:
    """File a call's notes on the pinned advisory as an ISAC draft, for review. An editor only."""
    require(is_isac_editor(ctx), "sector_event_requires_isac_editor")
    event = await session.scalar(select(SectorEvent).where(SectorEvent.id == event_id))
    if event is None or event.closed_at is not None:
        raise _NOT_FOUND
    try:
        bundle = call_notes_bundle(
            event.vulnerability_stix_id,
            summary=payload.summary,
            action_items=payload.action_items,
            now=await database_now(session),
        )
        submission = await create_submission(
            session,
            ctx,
            title="Sector event call notes",
            summary=None,
            tlp=payload.tlp,
            discovery_scope=payload.discovery_scope,
            distribute_anonymously=False,
            bundle=bundle,
            filed_for=None,
            key=key,
        )
        await session.commit()
    except (SectorEventError, SubmissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except STORAGE_ERRORS as exc:
        await session.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="Notes rejected by storage"
        ) from exc
    return {"submission_id": str(submission.id)}
