"""Alembic migration environment.

Reads the database URL from application settings rather than alembic.ini, so
there is exactly one place a connection string can come from and no opportunity
for a checked-in file to point a migration at the wrong database.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Importing the models package registers every table on Base.metadata, which is
# what autogenerate diffs against. Without this import autogenerate would
# cheerfully propose dropping the entire schema.
from aivs_server.db import models  # noqa: F401
from aivs_server.db.base import Base
from aivs_server.db.grants import APP_ROLE_ENV_VAR, grant_app_role

config = context.config

if config.config_file_name is not None:
    # disable_existing_loggers defaults to True, which silently switches off
    # every logger already created -- the application's included -- for the
    # rest of the process. Run in-process (the migration test, any tool that
    # migrates before serving), that left security warnings unlogged with no
    # sign anything had changed.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _database_url() -> str:
    """Return the migration target URL.

    Prefers AIVS_MIGRATION_DATABASE_URL over AIVS_DATABASE_URL, so that migrations can be run by an
    operator with elevated (DDL-capable) credentials that differ from the
    application's own restricted role.
    """
    url = os.environ.get("AIVS_MIGRATION_DATABASE_URL") or os.environ.get("AIVS_DATABASE_URL")
    if not url:
        msg = "set AIVS_DATABASE_URL (or AIVS_MIGRATION_DATABASE_URL) before running migrations"
        raise RuntimeError(msg)
    return url


def _include_name(name: str | None, type_: str, _parent_names: object) -> bool:
    """Compare our two schemas and nothing else on the server (Phase P).

    Without ``include_schemas`` autogenerate and ``alembic check`` look at the
    default schema only, so a table in ``attribution`` would drift unseen.
    """
    if type_ == "schema":
        return name in (None, "public", "attribution")
    return True


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it.

    Used to hand a reviewable script to a DBA in environments where the
    application's credentials cannot perform DDL.
    """
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        include_schemas=True,
        include_name=_include_name,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=True,
        include_name=_include_name,
        compare_type=True,
        compare_server_default=True,
        # Migrations run in one transaction so a failure part-way leaves the
        # schema exactly as it was.
        transaction_per_migration=False,
    )
    with context.begin_transaction():
        context.run_migrations()
        # In the same transaction, and on every run rather than in one
        # revision: the grants then cover whatever this run created, and a
        # role named late is put right by the next upgrade. See db/grants.py.
        app_role = os.environ.get(APP_ROLE_ENV_VAR, "").strip()
        if app_role:
            grant_app_role(connection, app_role)


async def run_async_migrations() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _database_url()
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
