"""Health, readiness, and caller-identity endpoints."""

from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from aivs_server.auth.deps import AuthenticatedContext, SessionDep, SettingsDep

__all__ = ["public_router", "router"]

#: Endpoints reachable without a client certificate.
#:
#: These answer the orchestrator's health probes, which cannot present a member
#: certificate. Two things are true and were previously misstated here:
#:
#: 1. The orchestrator and container healthcheck reach these on the proxy's
#:    *internal* listener, which is not exposed off-host.
#: 2. They are ALSO reachable on the public listener, gated only by mTLS -- the
#:    proxy does not carve them out -- so any holder of a valid member
#:    certificate can call them. That is acceptable only because nothing here
#:    reveals anything about members or content: liveness is a constant, and the
#:    readiness probe discloses at most whether the database is reachable, which
#:    an authenticated member already learns the instant any real request fails.
#:
#: The consequence for maintainers: never add anything to this router that
#: reveals more than that, because "unauthenticated" here also means "readable
#: by every member". The authorization matrix test asserts that this router's
#: routes are exactly the intended set.
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
            {
                "id": str(circle_id),
                "role": grant.role.value,
                # Surfaced so a member can see for themselves from when their
                # access to each circle runs, rather than inferring it from what
                # their feed does and does not contain.
                "member_since": grant.joined_at.isoformat(),
            }
            for circle_id, grant in sorted(ctx.circles.items(), key=lambda item: str(item[0]))
        ],
        "server_time": dt.datetime.now(dt.UTC).isoformat(),
    }
