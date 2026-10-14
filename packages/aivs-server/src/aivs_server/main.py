"""Application factory and process entry point.

Everything that decides how AIVS behaves at the edge is assembled here: the
middleware stack, the exception handlers, and the routers. Two choices are worth
justifying because a reader will wonder:

**Interactive API documentation is disabled in production.** FastAPI's ``/docs``
and ``/openapi.json`` are unauthenticated by construction, and the schema
enumerates every endpoint including the administrative ones. The specification
is published to members as a file instead, so they lose nothing.

**No exception detail ever reaches a client in production.** The handlers below
log the full traceback server-side and return a fixed body. An error message
that quotes a database constraint or a file path is a free schema disclosure.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from aivs_server.api import acknowledgments, admin, lint, meta, submissions, telemetry
from aivs_server.audit.log import AuditAction, record_denial
from aivs_server.auth.deps import request_source_ip
from aivs_server.auth.policy import PolicyDeniedError
from aivs_server.config import Settings, get_settings
from aivs_server.db.engine import dispose_engine, get_engine, session_scope
from aivs_server.logging_config import configure_logging
from aivs_server.middleware import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    security_headers_for,
)
from aivs_server.notify.dispatcher import dispatch_pending
from aivs_server.observability import run_periodically
from aivs_server.portal import admin_routes as portal_admin_routes
from aivs_server.portal import routes as portal_routes
from aivs_server.services.detections import run_detections
from aivs_server.services.embargo import sweep_due_embargoes
from aivs_server.services.publication import PublicationPausedError
from aivs_server.services.telemetry import queue_milestones
from aivs_server.taxii import router as taxii_router

__all__ = ["create_app"]

logger = logging.getLogger(__name__)

#: TAXII 2.1 requires this exact media type on responses, including errors.
#: The native API uses it too so a client never has to branch on which surface
#: produced a failure.
TAXII_MEDIA_TYPE: Final[str] = "application/taxii+json;version=2.1"


def _error_response(status_code: int, title: str, **extra: Any) -> JSONResponse:
    """Build a TAXII-shaped error response.

    The TAXII 2.1 ``error`` resource requires only ``title``; ``http_status`` is
    optional but must match the response status when present.
    """
    body: dict[str, Any] = {"title": title, "http_status": str(status_code)}
    body.update(extra)
    return JSONResponse(status_code=status_code, content=body, media_type=TAXII_MEDIA_TYPE)


def _unwrapped_error_response(
    request: Request, status_code: int, title: str, **extra: Any
) -> JSONResponse:
    """An error response for a handler that does not traverse the middleware.

    Starlette routes the ``Exception`` handler to ``ServerErrorMiddleware``,
    which sits outside the user middleware stack, so neither
    ``SecurityHeadersMiddleware`` nor ``RequestContextMiddleware`` sees what it
    returns. Both are reapplied here rather than left to a layer that will not
    run.
    """
    response = _error_response(status_code, title, **extra)
    for name, value in security_headers_for(request.url.path):
        response.headers[name.decode("ascii")] = value.decode("ascii")

    request_id = request.scope.get("aivs_request_id")
    if isinstance(request_id, str):
        response.headers[request.app.state.settings.header_request_id] = request_id

    return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start and stop process-wide resources."""
    settings: Settings = app.state.settings
    configure_logging(settings.log_level)
    logger.info(
        "starting AIVS",
        extra={"environment": settings.environment, "instance": settings.instance_name},
    )
    # Construct the engine eagerly so a bad database URL fails at startup rather
    # than on a member's first request.
    get_engine()

    background = [
        asyncio.create_task(run_periodically(component.name, component.interval, component.work))
        for component in background_components(settings)
    ]
    try:
        yield
    finally:
        for task in background:
            task.cancel()
        for task in background:
            with suppress(asyncio.CancelledError):
                await task
        await dispose_engine()
        logger.info("stopped AIVS")


@dataclass(frozen=True, slots=True)
class BackgroundComponent:
    name: str
    interval: dt.timedelta
    work: Callable[[], Awaitable[object]]


def background_components(settings: Settings) -> list[BackgroundComponent]:
    """Every job the process runs unattended.

    Each goes through run_periodically, so each reports into the health
    registry /readyz, /metrics and the status page read. Separate tasks
    because they fail independently: a dead dispatcher must not stop embargoes
    being marked released, nor a dead sweeper stop alerts. Named here, not
    inline in the lifespan, so a test can see the list.
    """
    return [
        BackgroundComponent(
            "embargo_sweeper",
            dt.timedelta(seconds=settings.embargo_sweep_interval_seconds),
            _sweep_embargoes,
        ),
        BackgroundComponent(
            "webhook_dispatcher",
            dt.timedelta(seconds=settings.webhook_dispatch_interval_seconds),
            lambda: _dispatch_webhooks(settings),
        ),
        BackgroundComponent(
            "telemetry",
            dt.timedelta(seconds=settings.telemetry_interval_seconds),
            _queue_telemetry_milestones,
        ),
        BackgroundComponent(
            "detections",
            dt.timedelta(seconds=settings.detection_interval_seconds),
            lambda: _run_detections(settings),
        ),
    ]


async def _queue_telemetry_milestones() -> None:
    """Tell submitters, contentlessly, when what they shared crossed a milestone."""
    async with session_scope() as session:
        await queue_milestones(session, now=dt.datetime.now(dt.UTC), lookback=dt.timedelta(days=1))


async def _sweep_embargoes() -> None:
    """Mark embargoes released once due. Bookkeeping only: content becomes
    visible the instant its ``date_added`` passes, whether or not this runs."""
    async with session_scope() as session:
        await sweep_due_embargoes(session)


async def _dispatch_webhooks(settings: Settings) -> None:
    async with session_scope() as session:
        await dispatch_pending(session, settings)


async def _run_detections(settings: Settings) -> None:
    async with session_scope() as session:
        await run_detections(
            session,
            now=dt.datetime.now(dt.UTC),
            quarantine_policy=settings.detection_quarantine_policy,
        )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI application.

    Accepts an explicit ``settings`` so tests can construct an app without
    mutating process environment variables.
    """
    settings = settings or get_settings()
    # Permit only dev, never "deny only production" -- the same allow-list shape
    # validate_production_posture uses, and for the same reason. A staging
    # instance for a financial-sector ISAC mirrors production and holds real
    # embargoed intelligence; serving it an unauthenticated /openapi.json
    # publishes the entire admin surface and every response model.
    show_docs = settings.environment == "dev"

    app = FastAPI(
        title="AIVS",
        summary="ISAC vulnerability intelligence, from pre-CVE early warning onward",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if show_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if show_docs else None,
    )
    app.state.settings = settings

    # Middleware is applied outermost-last, so this order nests request
    # correlation outside security headers, which in turn sit outside the
    # body-size limit.
    # Request correlation is outermost so that even a body-size rejection is
    # logged with an id, and security headers wrap that rejection so no response
    # can escape without them.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware, settings=settings)

    _register_exception_handlers(app, settings)

    app.include_router(meta.public_router)
    app.include_router(meta.router)
    # Before submissions.router: its /submissions/{submission_id} would
    # otherwise match "lint" first.
    app.include_router(lint.router)
    app.include_router(telemetry.router)
    app.include_router(submissions.router)
    app.include_router(acknowledgments.router)
    app.include_router(admin.router)
    app.include_router(portal_routes.router)
    app.include_router(portal_admin_routes.router)
    app.include_router(taxii_router.router)

    # Served from the package so a deployment needs no separate asset step.
    app.mount(
        "/portal/static",
        StaticFiles(directory=str(Path(portal_routes.__file__).parent / "static")),
        name="portal-static",
    )

    return app


def _register_exception_handlers(app: FastAPI, settings: Settings) -> None:
    """Install handlers that keep internal detail server-side."""

    @app.exception_handler(PolicyDeniedError)
    async def _policy_denied(request: Request, exc: PolicyDeniedError) -> JSONResponse:
        """Turn an authorization refusal into a 403 that says nothing useful.

        The specific rule that refused is recorded in the audit log. The caller
        learns only that it was refused -- enumerating which check failed would
        let an attacker map the policy by probing.
        """
        await record_denial(
            reason=exc.reason,
            action=AuditAction.ACCESS_DENIED,
            ctx=getattr(request.state, "auth_context", None),
            request_id=request.scope.get("aivs_request_id"),
            source_ip=request_source_ip(request, request.app.state.settings),
            route=request.url.path,
        )
        return _error_response(status.HTTP_403_FORBIDDEN, "Forbidden")

    @app.exception_handler(PublicationPausedError)
    async def _publication_paused(
        request: Request,  # noqa: ARG001 - required by the handler signature
        exc: PublicationPausedError,  # noqa: ARG001 - the type is the message
    ) -> JSONResponse:
        """A paused instance is a state the operator chose, not a server fault.

        Reported as 409 with the cause named, so the editor who tried to
        distribute knows why it did not happen rather than reading a 500.
        """
        return _error_response(status.HTTP_409_CONFLICT, "Distribution is paused instance-wide")

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        request: Request,  # noqa: ARG001 - required by the handler signature
        exc: RequestValidationError,
    ) -> JSONResponse:
        """Report malformed input without echoing it back.

        Pydantic's default error payload includes the offending input value.
        Reflecting attacker-supplied content into a response is how a JSON API
        becomes an injection vector for whatever consumes its errors, so only
        the location and the message survive.
        """
        problems = [
            {
                "location": ".".join(str(part) for part in error.get("loc", ())),
                "message": str(error.get("msg", "invalid value")),
            }
            for error in exc.errors()[:20]
        ]
        return _error_response(
            status.HTTP_400_BAD_REQUEST, "Request validation failed", details={"errors": problems}
        )

    @app.exception_handler(HTTPException)
    async def _http_exception(request: Request, exc: HTTPException) -> JSONResponse:
        """Render HTTPException in the TAXII error shape, auditing a refused lookup.

        A 404 to a caller who authenticated is the refusal that must look like
        absence; recording it is how the ``not_found_burst`` detection sees
        someone enumerating identifiers. An unauthenticated 404 has no actor to
        attribute and is left to the access log. Today none reaches here: every
        route that raises 404 authenticates first, and an unknown path raises
        Starlette's own HTTPException, which this handler does not receive. The
        guard keeps a future public route from writing actorless rows.
        """
        ctx = getattr(request.state, "auth_context", None)
        if exc.status_code == status.HTTP_404_NOT_FOUND and ctx is not None:
            await record_denial(
                reason="not_found",
                action=AuditAction.ACCESS_NOT_FOUND,
                ctx=ctx,
                request_id=request.scope.get("aivs_request_id"),
                source_ip=request_source_ip(request, request.app.state.settings),
                route=request.url.path,
            )
        headers = getattr(exc, "headers", None) or {}
        response = _error_response(exc.status_code, str(exc.detail))
        for key, value in headers.items():
            response.headers[key] = value
        return response

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        """Last resort: log everything, disclose nothing."""
        logger.exception(  # noqa: LOG004 - a FastAPI exception handler is an
            # exception context; ruff cannot see the framework's try/except.
            "unhandled exception",
            extra={"path": request.url.path, "method": request.method},
        )
        if settings.dev_expose_error_detail:
            # Gated to non-production by Settings.validate_production_posture.
            return _unwrapped_error_response(
                request,
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "Internal server error",
                details={"exception": type(exc).__name__, "message": str(exc)},
            )
        return _unwrapped_error_response(
            request, status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error"
        )


def main() -> None:  # pragma: no cover - process entry point
    """Run the server with uvicorn.

    The bind address comes from settings. Its default binds all interfaces
    because the container's network namespace is the boundary: compose
    publishes no host port for this service, so the only route in is the
    reverse proxy. Outside a container, set AIVS_BIND_HOST explicitly.
    """
    import uvicorn  # noqa: PLC0415 - deferred so importing this module as a
    # library (tests, the app factory) does not pull in a web server.

    settings = get_settings()
    configure_logging(settings.log_level)
    uvicorn.run(
        "aivs_server.main:create_app",
        factory=True,
        host=settings.bind_host,
        port=settings.bind_port,
        log_config=None,
        access_log=False,  # RequestContextMiddleware logs every request (aivs_server.access)
        server_header=False,
        date_header=True,
        # Uvicorn defaults this to True, with FORWARDED_ALLOW_IPS defaulting to
        # 127.0.0.1, which lets ProxyHeadersMiddleware rewrite scope["client"]
        # from X-Forwarded-For. That address is the sole input to
        # peer_is_trusted_proxy and the source_ip on every audit row, and this
        # application derives the member's address from headers deliberately and
        # separately. Nothing here ever wants the server rewriting the TCP peer
        # underneath it: with nginx on loopback it would swap in the member's
        # address and 401 every request; with FORWARDED_ALLOW_IPS=* it would let
        # a client-supplied header satisfy the peer allowlist.
        proxy_headers=False,
    )
