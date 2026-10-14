"""Exports of one vulnerability over the API: the IoC pack.

The portal serves the same pack to a person (``portal/reading_routes.py``);
both call one service function, so the two doors make the same visibility
decision and write the same receipt, differing only in the channel.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response, status

from aivs_schemas.enums import AckVia
from aivs_server.auth.deps import AuthenticatedContext, SessionDep
from aivs_server.db.clock import database_now
from aivs_server.services.ioc_pack import export_ioc_pack
from aivs_server.services.vulnerability_objects import VulnerabilityHiddenError

__all__ = ["CSV_MEDIA_TYPE", "csv_attachment", "router"]

router = APIRouter(prefix="/api/v1", tags=["exports"])

CSV_MEDIA_TYPE = "text/csv; charset=utf-8"


def csv_attachment(text: str, filename: str) -> Response:
    """A CSV download. ``filename`` is built from a validated STIX id, never from input."""
    return Response(
        content=text,
        media_type=CSV_MEDIA_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/vulnerabilities/ioc-pack.csv")
async def ioc_pack(
    ctx: AuthenticatedContext,
    session: SessionDep,
    stix_id: Annotated[str, Query(alias="id", max_length=100)],
) -> Response:
    """The vulnerability's current indicators as CSV, recorded as retrieved.

    A malformed id, an unknown id and one the caller cannot see all answer the
    same 404 (SF-47). The id is a query parameter, as for readiness: request
    paths are logged with the caller's identity and leave the platform, and
    "firm X pulled the pack for vulnerability V" is the posture leak SF-70
    closes.
    """
    try:
        pack = await export_ioc_pack(
            session, ctx, stix_id, via=AckVia.API, now=await database_now(session)
        )
    except VulnerabilityHiddenError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found") from None
    await session.commit()
    return csv_attachment(pack.text, f"{stix_id}-ioc-pack.csv")
