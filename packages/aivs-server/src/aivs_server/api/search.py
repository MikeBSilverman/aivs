"""Search the distributed content the caller can read (SF-11).

The terms are a query parameter, not a path segment: request paths are logged
with the caller's identity and forwarded off the platform, and the query
string is not. Nothing here logs or audits them either. What a firm searches
for says what it is worried about.
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from aivs_schemas.enums import TLP
from aivs_server.auth.deps import AuthenticatedContext, SessionDep
from aivs_server.db.clock import database_now
from aivs_server.services.search import (
    MAX_TERMS_LENGTH,
    SearchTermsError,
    parse_search_terms,
    search_visible,
)

__all__ = ["router"]

router = APIRouter(prefix="/api/v1", tags=["search"])


class SearchHitOut(BaseModel):
    """One object the caller can read. Never who filed it."""

    stix_id: str
    type: str
    name: str | None
    tlp: TLP
    #: When this version was first shared with the caller.
    shared_at: dt.datetime
    modified: dt.datetime


class SearchPageOut(BaseModel):
    """The newest matches first. No total: ``more`` says only that there are others."""

    hits: list[SearchHitOut]
    more: bool


@router.get("/search", response_model=SearchPageOut)
async def search(
    ctx: AuthenticatedContext,
    session: SessionDep,
    q: Annotated[str, Query(max_length=MAX_TERMS_LENGTH * 2)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SearchPageOut:
    """Objects whose latest version the caller can read matches ``q``.

    Words are matched whole, case-insensitively; quote a phrase, and put ``-``
    before a word to exclude it. Name, aliases, description, a note's text, an
    opinion's explanation and external reference ids are searched.
    """
    try:
        terms = parse_search_terms(q)
    except SearchTermsError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    page = await search_visible(session, ctx, terms, now=await database_now(session), limit=limit)
    return SearchPageOut(
        hits=[
            SearchHitOut(
                stix_id=hit.stix_id,
                type=hit.type,
                name=hit.name,
                tlp=hit.tlp,
                shared_at=hit.shared_at,
                modified=hit.modified,
            )
            for hit in page.hits
        ],
        more=page.more,
    )
