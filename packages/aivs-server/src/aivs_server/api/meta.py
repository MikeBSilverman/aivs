"""Health, readiness, and caller-identity endpoints."""

from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from aivs_server.auth.deps import AuthenticatedContext, SessionDep, SettingsDep

__all__ = ["public_router", "router"]

#: Endpoints reachable without a client certificate. The reverse proxy confines
#: these to the internal network so that only the container healthcheck and the
#: orchestrator can call them; nothing here reveals anything about members or
#: content. The authorization matrix test asserts that this router's routes are
#: exactly the intended set of unauthenticated endpoints.
public_router = APIRouter(tags=["meta"])

router = APIRouter(prefix="/api/v1", tags=["meta"])


@public_router.get("/healthz", status_code=status.HTTP_200_OK)
async def healthz() -> dict[str, str]:
    """Liveness probe.

    Deliberately touches nothing. A liveness check that queries the database
    causes an orchestrator to kill and restart healthy application containers
    during a database blip, turning a brief outage into a restart storm.
    """
    return {"status": "ok"}


@public_router.get("/readyz")
async def readyz(session: SessionDep, response: Response) -> dict[str, Any]:
    """Readiness probe: can this instance actually serve traffic?

    Unlike liveness, this does check the database, because an instance that
    cannot reach its database should be taken out of rotation rather than
    restarted. Returns 503 so a load balancer stops sending it requests.
    """
    try:
        await session.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - any failure means "not ready", and the
        # reason belongs in the logs rather than in an unauthenticated response.
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unavailable", "database": "unreachable"}
    return {"status": "ready", "database": "ok"}


@router.get("/whoami")
async def whoami(ctx: AuthenticatedContext, settings: SettingsDep) -> dict[str, Any]:
    """Return the caller's own identity as the server resolved it.

    The first call a member makes after enrolment, and the fastest way to
    diagnose a certificate or circle-membership problem: it answers "who does
    the server think I am, and what can I see" in one round trip.
    """
    return {
        "instance": settings.instance_name,
        "organization": {
            "id": str(ctx.org_id),
            "slug": ctx.org_slug,
            "type": ctx.org_type.value,
            "status": ctx.org_status.value,
        },
        "authentication": {
            "method": ctx.auth_method.value,
            "certificate_fingerprint": ctx.cert_fingerprint,
        },
        "circles": [
            {"id": str(circle_id), "role": role.value}
            for circle_id, role in sorted(ctx.circles.items(), key=lambda item: str(item[0]))
        ],
        "server_time": dt.datetime.now(dt.UTC).isoformat(),
    }
