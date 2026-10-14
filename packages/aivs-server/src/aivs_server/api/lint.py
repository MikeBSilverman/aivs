"""The sanitisation assist over the API, for the portal's submit page and any client.

It returns spans, never a verdict: the submitter decides what to redact. It
writes nothing and logs nothing of the text, which is unfiled content.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from aivs_server.auth.deps import AuthenticatedContext, SessionDep
from aivs_server.db.models import Organization
from aivs_server.services.sanitisation import free_text_of, lint

__all__ = ["router"]

router = APIRouter(prefix="/api/v1/submissions", tags=["submissions"])


class LintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Annotated[str, Field(max_length=300)] = ""
    summary: Annotated[str, Field(max_length=20_000)] = ""
    bundle: dict[str, Any] | None = None


class LintHit(BaseModel):
    field: str
    kind: str
    start: int
    end: int
    text: str


@router.post("/lint", response_model=list[LintHit])
async def lint_submission(
    payload: LintRequest, ctx: AuthenticatedContext, session: SessionDep
) -> list[LintHit]:
    """Free text that may identify the submitter or a victim, with its spans."""
    organisation = await session.get(Organization, ctx.org_id)
    own_names = [ctx.org_slug, organisation.name] if organisation else [ctx.org_slug]
    fields = {"title": payload.title, "summary": payload.summary}
    if payload.bundle is not None:
        fields |= free_text_of(payload.bundle)
    return [
        LintHit(field=hit.field, kind=hit.kind, start=hit.start, end=hit.end, text=hit.text)
        for hit in lint(fields, own_names=own_names)
    ]
