"""Database engine and session lifecycle.

The engine is created once at application startup and disposed at shutdown.
Sessions are per-request and always closed, including on error, by the
``get_session`` dependency.

Every connection gets a server-side ``statement_timeout``. Without one, a single
pathological TAXII filter can hold a pooled connection open indefinitely and,
with a small pool, take the whole instance down -- a denial of service that
needs no authentication beyond a valid client certificate.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Final

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from aivs_server.config import Settings, get_settings

__all__ = [
    "dispose_engine",
    "get_engine",
    "get_session",
    "get_sessionmaker",
    "session_scope",
]

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None

#: Applied to every connection as it is checked out of the pool.
_CONNECT_OPTIONS_TEMPLATE: Final[str] = (
    "-c statement_timeout={statement_timeout_ms} "
    "-c idle_in_transaction_session_timeout={idle_timeout_ms} "
    "-c lock_timeout={lock_timeout_ms}"
)


def _build_engine(settings: Settings) -> AsyncEngine:
    idle_timeout_ms = settings.db_statement_timeout_ms * 2
    options = _CONNECT_OPTIONS_TEMPLATE.format(
        statement_timeout_ms=settings.db_statement_timeout_ms,
        idle_timeout_ms=idle_timeout_ms,
        lock_timeout_ms=settings.db_statement_timeout_ms,
    )
    return create_async_engine(
        settings.database_url.get_secret_value(),
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
        connect_args={"options": options},
    )


def get_engine() -> AsyncEngine:
    """Return the process-wide engine, creating it on first use."""
    global _engine  # noqa: PLW0603 - single process-wide engine by design
    if _engine is None:
        _engine = _build_engine(get_settings())
    return _engine


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


async def dispose_engine() -> None:
    """Dispose the engine and reset the module state. Called at shutdown."""
    global _engine, _sessionmaker  # noqa: PLW0603 - shutdown teardown
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a request-scoped session.

    The session is rolled back and closed unconditionally. Handlers commit
    explicitly; anything that reaches the exception path leaves no partial
    write behind.
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
