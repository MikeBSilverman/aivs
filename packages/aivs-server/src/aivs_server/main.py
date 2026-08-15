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
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any, Final

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from aivs_server.api import acknowledgments, admin, meta, submissions
from aivs_server.audit.log import AuditAction, record_denial
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
from aivs_server.portal import routes as portal_routes
from aivs_server.services.embargo import sweep_due_embargoes
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

    sweeper = asyncio.create_task(_embargo_sweeper(settings))
    try:
        yield
    finally:
        sweeper.cancel()
        with suppress(asyncio.CancelledError):
            await sweeper
        await dispose_engine()
        logger.info("stopped AIVS")


async def _embargo_sweeper(settings: Settings) -> None:
    """Mark embargoes as released once their time has passed.

    Bookkeeping only, and deliberately so: content becomes visible the instant
    its ``date_added`` passes, whether or not this loop is running. A sweeper
    that has been down for a week leaks nothing and catches up in one pass.

    Failures are logged and the loop continues. An instance that stopped serving
    members because a background bookkeeping task hit a transient database error
    would be a far worse outcome than a stale status column.
    """
    while True:
        await asyncio.sleep(settings.embargo_sweep_interval_seconds)
        try:
            async with session_scope() as session:
                await sweep_due_embargoes(session)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("embargo sweep failed; will retry on the next interval")


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
        summary="Pre-CVE AI vulnerability sharing",
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
    app.include_router(submissions.router)
    app.include_router(acknowledgments.router)
    app.include_router(admin.router)
    app.include_router(portal_routes.router)
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
            source_ip=request.client.host if request.client else None,
            route=request.url.path,
        )
        return _error_response(status.HTTP_403_FORBIDDEN, "Forbidden")

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
    async def _http_exception(
        request: Request,  # noqa: ARG001 - required by the handler signature
        exc: HTTPException,
    ) -> JSONResponse:
        """Render HTTPException in the TAXII error shape."""
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
        access_log=False,  # RequestContextMiddleware emits structured access logs
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
