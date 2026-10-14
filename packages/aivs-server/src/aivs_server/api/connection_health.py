"""A member's view of its own connection, and starting configuration for its TIP.

Both describe the caller's own organisation and the collections it may read,
and nothing else: no other organisation's state, and no collection the caller
cannot read is named, even by id.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, HTTPException, Response, status

from aivs_server.auth.deps import AuthenticatedContext, SessionDep, SettingsDep
from aivs_server.db.clock import database_now
from aivs_server.services.connection_health import member_health, readable_collections
from aivs_server.services.tip_config import CollectionRef, Tip, tip_config

__all__ = ["router"]

router = APIRouter(prefix="/api/v1", tags=["connection"])


@router.get("/connection-health")
async def connection_health(ctx: AuthenticatedContext, session: SessionDep) -> dict[str, Any]:
    """Per readable collection, last collected and whether content waits; webhooks; certificates."""
    health = await member_health(session, ctx, await database_now(session))
    return {
        "collections": [
            {**asdict(collection), "waiting": collection.waiting}
            for collection in health.collections
        ],
        "webhooks": [asdict(webhook) for webhook in health.webhooks],
        "certificates": [asdict(certificate) for certificate in health.certificates],
    }


@router.get("/tip-config/{tool}")
async def tip_configuration(
    tool: str, ctx: AuthenticatedContext, session: SessionDep, settings: SettingsDep
) -> Response:
    """A starting configuration for ``tool`` (opencti, misp, splunk), as plain text."""
    known = {tip.value: tip for tip in Tip}
    if tool not in known:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    collections = [
        CollectionRef(collection_id, title)
        for collection_id, title, _circle, _sandbox in await readable_collections(session, ctx)
    ]
    return Response(
        content=tip_config(known[tool], settings.public_base_url, collections),
        media_type="text/plain; charset=utf-8",
    )
