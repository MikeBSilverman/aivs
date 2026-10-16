"""The member evidence pack over the API: ``GET /api/v1/evidence-pack?vulnerability=``.

The vulnerability is a query parameter, never a path segment: paths are logged
beside the caller's identity and leave the platform, and "firm X drew its
evidence on V" is a statement about what the firm is answering a regulator for.

404 for every caller that may not hold a pack and for every vulnerability it
cannot see, with one body: the ISAC asking for a member's pack learns nothing
a member's own refusal would not say. The pack's hash is recorded in the audit
trail, so a pack filed with a regulator can be shown to be one this platform
produced.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Final

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.deps import AuthenticatedContext, SessionDep
from aivs_server.auth.policy import can_hold_evidence_pack
from aivs_server.db.clock import database_now
from aivs_server.services.member_staff_reads import own_evidence_pack

__all__ = ["router"]

router = APIRouter(prefix="/api/v1", tags=["evidence"])

_NOT_FOUND: Final = HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
_VULNERABILITY_ID: Final[re.Pattern[str]] = re.compile(
    r"^vulnerability--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class EvidencePackOut(BaseModel):
    pack: dict[str, Any]
    #: SHA-256 of the canonical JSON of ``pack`` (sorted keys, no whitespace).
    sha256: str


@router.get("/evidence-pack", response_model=EvidencePackOut)
async def draw_evidence_pack(
    ctx: AuthenticatedContext,
    session: SessionDep,
    vulnerability: Annotated[str, Query(max_length=100)],
) -> EvidencePackOut:
    """This organisation's evidence for one vulnerability, content-hashed."""
    if not can_hold_evidence_pack(ctx) or _VULNERABILITY_ID.match(vulnerability) is None:
        raise _NOT_FOUND
    pack = await own_evidence_pack(session, ctx, vulnerability, now=await database_now(session))
    if pack is None:
        raise _NOT_FOUND
    await record(
        session,
        action=AuditAction.EVIDENCE_PACK_DRAWN,
        ctx=ctx,
        resource_type="evidence_pack",
        resource_id=pack.sha256,
        details={"sha256": pack.sha256},
    )
    await session.commit()
    return EvidencePackOut(pack=dict(pack.body), sha256=pack.sha256)
