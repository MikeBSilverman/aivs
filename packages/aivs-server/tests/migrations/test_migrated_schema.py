"""The protections that exist only in migrations, checked in a migrated database.

The suite builds its schema with ``create_all`` plus hand-written triggers, so a
test of the append-only triggers or the membership exclusion constraint proves
the *fixture's* DDL, not the migration's. ``alembic check`` cannot help: it
compares tables and columns and sees neither triggers nor exclusion constraints.
A migration that dropped one would pass every other gate. This test runs the
real migrations into a scratch database of its own and asks Postgres what
exists.

Its own database, never the suite's: a second process holding locks on
``aivs_test`` makes the suite hang (CLAUDE.md section 3). The name derives from
the test database URL, so a concurrent run against ``aivs_ci`` migrates into
``aivs_ci_migrations`` and the two never meet.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from tests.conftest import TEST_DATABASE_URL

pytestmark = pytest.mark.db

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


@pytest.fixture(scope="module")
def migrated_url() -> Iterator[str]:
    """Create an empty scratch database, migrate it to head, yield its URL."""
    test_url = make_url(TEST_DATABASE_URL)
    scratch = f"{test_url.database}_migrations"
    admin = create_engine(test_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        connection.execute(text(f'CREATE DATABASE "{scratch}"'))

    url = test_url.set(database=scratch).render_as_string(hide_password=False)
    saved = {
        name: os.environ.get(name) for name in ("AIVS_DATABASE_URL", "AIVS_SECRET_ENCRYPTION_KEY")
    }
    os.environ["AIVS_DATABASE_URL"] = url
    # The secrets migration refuses to run without a key; this database is empty
    # and dropped below, so a random one is enough.
    os.environ["AIVS_SECRET_ENCRYPTION_KEY"] = base64.b64encode(os.urandom(32)).decode()
    try:
        command.upgrade(Config(str(ALEMBIC_INI)), "head")
        yield url
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()


def _scalars(url: str, sql: str, **params: str) -> set[str]:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return {row[0] for row in connection.execute(text(sql), params)}
    finally:
        engine.dispose()


def test_membership_intervals_cannot_overlap(migrated_url: str):
    constraints = _scalars(
        migrated_url,
        "SELECT conname FROM pg_constraint "
        "WHERE conrelid = 'circle_memberships'::regclass AND contype = 'x'",
    )
    assert "ex_circle_memberships_no_overlap" in constraints


@pytest.mark.parametrize("table", ["audit_log", "submission_transitions"])
def test_append_only_tables_refuse_update_delete_truncate(migrated_url: str, table: str):
    triggers = _scalars(
        migrated_url,
        "SELECT t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
        "WHERE c.relname = :table AND NOT t.tgisinternal",
        table=table,
    )
    for operation in ("update", "delete", "truncate"):
        assert any(operation in name for name in triggers), (table, operation, triggers)
