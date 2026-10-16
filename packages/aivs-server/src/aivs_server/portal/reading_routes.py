"""Portal routes for reading: the depth preference and the IoC pack download.

Neither decides what a person may see. The preference picks a rendering; the
pack is built by the same service the API calls, from the objects the
visibility gatherer hands it, and is recorded as a portal retrieval (SF-51).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse

from aivs_schemas.enums import AckVia, ReadingDepth
from aivs_server.api.exports import csv_attachment
from aivs_server.auth.deps import SessionDep, SettingsDep
from aivs_server.db.clock import database_now
from aivs_server.portal.shared import (
    base_context,
    current_session,
    operator_name,
    redirect_within_portal,
    render,
    require_csrf,
    set_notice,
    stamp,
)
from aivs_server.services.connection_health import member_health, readable_collections
from aivs_server.services.ioc_pack import export_ioc_pack
from aivs_server.services.member_staff_writes import set_own_default_depth
from aivs_server.services.tip_config import CollectionRef, Tip, tip_config
from aivs_server.services.vulnerability_objects import VulnerabilityHiddenError

__all__ = ["router"]

router = APIRouter(prefix="/portal", include_in_schema=False)

#: The form's value for "no preference": pages open at ``standard``.
_NO_PREFERENCE = ""


@router.post("/preferences/depth")
async def set_default_depth(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
    # "No preference" is an empty field, which form parsing reads as absent.
    depth: Annotated[str, Form()] = _NO_PREFERENCE,
) -> Response:
    """Store the depth the signed-in person's vulnerability pages open at.

    Only the person's own row, found from the session and never from the form.
    An unknown value is refused with a notice and changes nothing.
    """
    ctx, csrf_hash = await current_session(request, settings)
    require_csrf(csrf_token, csrf_hash)
    response = redirect_within_portal("/portal/")
    known = {value.value: value for value in ReadingDepth}
    if depth != _NO_PREFERENCE and depth not in known:
        set_notice(response, settings, "error", "That reading depth is not one the portal offers.")
        return response
    if not await set_own_default_depth(session, ctx, known.get(depth)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    await session.commit()
    set_notice(response, settings, "info", "Your reading depth is saved.")
    return response


@router.get("/vulnerabilities/ioc-pack.csv")
async def ioc_pack(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    stix_id: Annotated[str, Query(alias="id", max_length=100)],
) -> Response:
    """The vulnerability's current indicators as CSV, recorded as a portal retrieval."""
    ctx, _ = await current_session(request, settings)
    try:
        pack = await export_ioc_pack(
            session, ctx, stix_id, via=AckVia.PORTAL, now=await database_now(session)
        )
    except VulnerabilityHiddenError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found") from None
    await session.commit()
    return csv_attachment(pack.text, f"{stix_id}-ioc-pack.csv")


@router.get("/connection", response_class=HTMLResponse)
async def connection_page(request: Request, settings: SettingsDep, session: SessionDep) -> Response:
    """The signed-in person's organisation's connection, and its TIP's starting configuration."""
    ctx, _ = await current_session(request, settings)
    health = await member_health(session, ctx, await database_now(session))
    collections = [
        CollectionRef(collection_id, title)
        for collection_id, title, _circle, _sandbox in await readable_collections(session, ctx)
    ]
    context = base_context(request, settings, ctx, await operator_name(session, ctx), "connection")
    context.update(
        {
            "health": health,
            "snippets": [
                (tip.value, tip_config(tip, settings.public_base_url, collections)) for tip in Tip
            ],
            "stamp": stamp,
        }
    )
    return render(request, "connection.html", context)
