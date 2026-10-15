"""Database engine and session lifecycle.

The engine is created once at application startup and disposed at shutdown.
Sessions are per-request and always closed, including on error, by the
``get_session`` dependency.

Two logins, two engines (Phase P). The **staff** engine connects as
``database_url``: ISAC staff, the ISAC's own organisations and every background
job. The **member** engine connects as ``member_database_url``: every request
from a member organisation, and anything not yet authenticated. Two logins
rather than one that switches role, because a role switch is SQL, and SQL
injected on the member path could switch back. A request's session is bound to
one of them on its first statement, by its caller (``routed_session``), and
stays bound: one request, one login, one transaction.

Every connection gets a server-side ``statement_timeout``. Without one, a single
pathological TAXII filter can hold a pooled connection open indefinitely and,
with a small pool, take the whole instance down -- a denial of service that
needs no authentication beyond a valid client certificate.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Final

from sqlalchemy import Engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session

from aivs_server.config import Settings, get_settings

__all__ = [
    "dispose_engine",
    "get_engine",
    "get_member_engine",
    "get_member_sessionmaker",
    "get_session",
    "get_sessionmaker",
    "routed_session",
    "session_scope",
]

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None
_member_engine: AsyncEngine | None = None
_member_sessionmaker: async_sessionmaker[AsyncSession] | None = None

#: Applied to every connection as it is checked out of the pool.
_CONNECT_OPTIONS_TEMPLATE: Final[str] = (
    "-c statement_timeout={statement_timeout_ms} "
    "-c idle_in_transaction_session_timeout={idle_timeout_ms} "
    "-c lock_timeout={lock_timeout_ms}"
)


def _build_engine(settings: Settings, url: str) -> AsyncEngine:
    idle_timeout_ms = settings.db_statement_timeout_ms * 2
    options = _CONNECT_OPTIONS_TEMPLATE.format(
        statement_timeout_ms=settings.db_statement_timeout_ms,
        idle_timeout_ms=idle_timeout_ms,
        lock_timeout_ms=settings.db_statement_timeout_ms,
    )
    return create_async_engine(
        url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout_seconds,
        # Recycle below typical proxy/firewall idle cutoffs so a member's
        # overnight-idle instance does not serve its first morning poll from a
        # dead connection.
        pool_recycle=1800,
        pool_pre_ping=True,
        # Never echo SQL: statements carry submission titles and member
        # identifiers, which do not belong in stdout.
        echo=False,
        # Bound parameters out of exception messages. A DBAPIError's text
        # otherwise carries the values -- STIX raw, titles -- into the traceback
        # the catch-all logs, and logs are forwarded to the ISAC's collector.
        hide_parameters=True,
        connect_args={"options": options},
    )


def get_engine() -> AsyncEngine:
    """Return the process-wide engine, creating it on first use."""
    global _engine  # noqa: PLW0603 - single process-wide engine by design
    if _engine is None:
        settings = get_settings()
        _engine = _build_engine(settings, settings.database_url.get_secret_value())
    return _engine


def get_member_engine() -> AsyncEngine:
    """Return the member path's engine, creating it on first use.

    Without ``member_database_url`` the member path shares the staff engine.
    The settings permit that in ``dev`` only (``validate_production_posture``).
    """
    global _member_engine  # noqa: PLW0603 - the second process-wide engine
    if _member_engine is None:
        settings = get_settings()
        if settings.member_database_url is None:
            return get_engine()
        _member_engine = _build_engine(settings, settings.member_database_url.get_secret_value())
    return _member_engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the process-wide session factory."""
    global _sessionmaker  # noqa: PLW0603 - paired with the engine above
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            autoflush=False,
        )
    return _sessionmaker


def get_member_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the member path's session factory: authentication's, before a caller is known."""
    global _member_sessionmaker  # noqa: PLW0603 - paired with the member engine
    if _member_sessionmaker is None:
        _member_sessionmaker = async_sessionmaker(
            bind=get_member_engine(),
            expire_on_commit=False,
            autoflush=False,
        )
    return _member_sessionmaker


async def dispose_engine() -> None:
    """Dispose both engines and reset the module state. Called at shutdown."""
    global _engine, _sessionmaker, _member_engine, _member_sessionmaker  # noqa: PLW0603 - shutdown teardown
    if _member_engine is not None and _member_engine is not _engine:
        await _member_engine.dispose()
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
    _member_engine = None
    _member_sessionmaker = None


#: Where a routed session keeps its chooser and, once chosen, its engine.
_CHOOSE = "aivs_choose_engine"
_BOUND = "aivs_bound_engine"


class _RoutedSession(Session):
    """A session that binds, on its first statement, to the engine its chooser names.

    And stays bound: asked again later in the request, it returns the engine
    it chose first, so one request never spans two logins.
    """

    def get_bind(self, *_args: Any, **_kwargs: Any) -> Engine:
        bound: AsyncEngine | None = self.info.get(_BOUND)
        if bound is None:
            bound = self.info[_CHOOSE]()
            self.info[_BOUND] = bound
        return bound.sync_engine


def routed_session(choose: Callable[[], AsyncEngine]) -> AsyncSession:
    """A session bound on first use to ``choose()``'s engine (see the module docstring)."""
    return AsyncSession(
        sync_session_class=_RoutedSession,
        info={_CHOOSE: choose},
        expire_on_commit=False,
        autoflush=False,
    )


async def get_session() -> AsyncIterator[AsyncSession]:
    """A staff session, rolled back and closed unconditionally.

    Not what a request's handler gets: that is ``auth.deps.SessionDep``, bound
    by its caller. This is for the code that has no caller but the ISAC.
    """
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Session context manager for background tasks, which have no request.

    Decorated, unlike ``get_session``: that one is a FastAPI dependency, which
    consumes a bare async generator, whereas this is used with ``async with``.
    The distinction is easy to miss because the bodies look identical.

    Commits on clean exit, rolls back on exception. The embargo sweeper and the
    webhook worker use this rather than ``get_session`` because they are not
    driven by FastAPI's dependency system.
    """
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
