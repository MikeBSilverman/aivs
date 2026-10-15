"""Health, readiness, and caller-identity endpoints."""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from fastapi import APIRouter, Response, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import text

from aivs_server.auth.deps import AuthenticatedContext, SessionDep, SettingsDep
from aivs_server.db.engine import get_sessionmaker
from aivs_server.db.grants import connection_role_problem
from aivs_server.observability import HEARTBEATS, render_metrics
from aivs_server.services.instance_status import pending_deliveries, pending_embargoes

__all__ = ["public_router", "router"]

#: Endpoints reachable without a client certificate.
#:
#: These answer the orchestrator's health probes, which cannot present a member
#: certificate. Two things are true and were previously misstated here:
#:
#: 1. The container healthcheck asks /readyz on loopback, and a scraper reads
#:    /metrics over the compose backend network; neither goes through the
#:    proxy, whose internal listener answers /healthz alone.
#: 2. They are NOT reachable on the member-facing mTLS listener: nginx answers
#:    them there with exact-match 404s (``deploy/nginx/nginx.conf``). The
#:    application still keeps them harmless in case a deployment's proxy does
#:    not carve them out: nothing here reveals anything about members or
#:    content -- liveness is a constant, the readiness probe discloses whether
#:    the database is reachable and which background components are healthy,
#:    and ``/metrics`` adds two queue depths (undelivered notifications,
#:    unreleased embargoes). Those depths are the most this router reveals: an
#:    operational count with no identifier, wanted by the ISAC's monitoring
#:    and not worth a credential every Prometheus scraper would have to hold.
#:
#: The consequence for maintainers: never add anything to this router that
#: reveals more than that, because "unauthenticated" here also means "readable
#: by every member". The authorization matrix test asserts that this router's
#: routes are exactly the intended set.
public_router = APIRouter(tags=["meta"])

logger = logging.getLogger(__name__)

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
async def readyz(session: SessionDep, settings: SettingsDep, response: Response) -> dict[str, Any]:
    """Readiness probe: can this instance actually serve traffic, and is every
    background component running?

    503 when the database is unreachable -- that is when a load balancer should
    take the instance out -- and, outside dev, when the application is connected
    as a role that could undo the append-only triggers: a superuser, the
    tables' owner, or a member of it. The audit trail's guarantee rests on that
    deployment fact, and the stack does not start its proxy until the app is
    ready. A degraded background component (the embargo sweeper, the
    dispatcher, the detection rules) keeps the instance serving but is reported
    by name with its reason, so "up" and "every part working" are never the
    same answer.
    """
    try:
        await session.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - any failure means "not ready", and the
        # reason belongs in the logs rather than in an unauthenticated response.
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unavailable", "database": "unreachable"}
    if settings.environment != "dev":
        # Both logins: this request's session is the member login's (it is not
        # authenticated), and the staff login serves the ISAC and every
        # background job. Either one able to undo the triggers is not ready.
        problem = await connection_role_problem(session)
        if problem is None:
            async with get_sessionmaker()() as staff_session:
                problem = await connection_role_problem(staff_session)
        if problem is not None:
            # Which role, and why, to the log; the unauthenticated body says
            # only that the connection was refused.
            logger.error("not ready: the database connection's %s", problem)
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "unavailable", "database": "refused"}
    components = HEARTBEATS.report(now=dt.datetime.now(dt.UTC))
    degraded = any(component.state == "degraded" for component in components)
    return {
        "status": "degraded" if degraded else "ready",
        "database": "ok",
        "components": {
            component.name: {"state": component.state, "reason": component.reason}
            for component in components
        },
    }


@public_router.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> str:
    """Prometheus text exposition: component health and the work waiting.

    Counts and timestamps only. A scraper reaches it on the app's own port over
    the compose ``backend`` network, as the app's healthcheck does -- the
    proxy's internal listener answers ``/healthz`` from nginx itself and nothing
    else. The member-facing listener answers it with 404, as for the probes.

    Counted on the staff login: the request is not authenticated, so its own
    session is the member login's, which may not read the delivery queue (each
    delivery names the submission it announces). Two counts leave; no row does.
    """
    now = dt.datetime.now(dt.UTC)
    async with get_sessionmaker()() as staff_session:
        deliveries = await pending_deliveries(staff_session)
        embargoes = await pending_embargoes(staff_session)
    return render_metrics(
        HEARTBEATS.report(now=now), pending_deliveries=deliveries, pending_embargoes=embargoes
    )


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
                "member_since": grant.member_since.isoformat(),
            }
            for circle_id, grant in sorted(ctx.circles.items(), key=lambda item: str(item[0]))
        ],
        "server_time": dt.datetime.now(dt.UTC).isoformat(),
    }
