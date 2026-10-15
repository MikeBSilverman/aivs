"""The proxy-filing marker is filled from the old column, and its downgrade refuses to lose a wait.

Rows are stored as ``c6f2a9d41e7b`` left them, where a deadline was the only
sign of a proxy filing; the migration runs and the marker is read back. Then
a filing waiting for a person, with no deadline, stops the downgrade: without
the marker it would read as the member's own, and could be distributed
unconfirmed. The same shape as ``test_attribution_move``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from tests.conftest import TEST_DATABASE_URL, TEST_SECRET_KEY_FILE

pytestmark = [pytest.mark.db, pytest.mark.slow, pytest.mark.requirement("SF-68")]

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"
BEFORE = "c6f2a9d41e7b"
MARKED = "f4abf9218295"

PROXY = "00000000-0000-4000-8000-0000000000e1"
OWN = "00000000-0000-4000-8000-0000000000e2"
WAITING = "00000000-0000-4000-8000-0000000000e3"
_TAG = "1.00000000.AAAAAAAAAAAAAAAAAAAAAA"


@pytest.fixture
def config() -> Iterator[Config]:
    test_url = make_url(TEST_DATABASE_URL)
    scratch = f"{test_url.database}_proxy_marker"
    admin = create_engine(test_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        connection.execute(text(f'CREATE DATABASE "{scratch}"'))
    url = test_url.set(database=scratch).render_as_string(hide_password=False)
    names = (
        "AIVS_DATABASE_URL",
        "AIVS_MIGRATION_DATABASE_URL",
        "AIVS_SECRET_ENCRYPTION_KEY",
        "AIVS_SECRET_ENCRYPTION_KEY_FILE",
    )
    saved = {name: os.environ.get(name) for name in names}
    os.environ["AIVS_DATABASE_URL"] = url
    os.environ["AIVS_MIGRATION_DATABASE_URL"] = url
    os.environ.pop("AIVS_SECRET_ENCRYPTION_KEY", None)
    os.environ["AIVS_SECRET_ENCRYPTION_KEY_FILE"] = str(TEST_SECRET_KEY_FILE)
    try:
        yield Config(str(ALEMBIC_INI))
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()


def _execute(url: str, statement: str, **params: str) -> list[tuple]:
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            result = connection.execute(text(statement), params)
            return [tuple(row) for row in result] if result.returns_rows else []
    finally:
        engine.dispose()


def _submission(url: str, submission_id: str, confirm_by: str | None) -> None:
    _execute(
        url,
        "INSERT INTO submissions (id, state, tlp, discovery_scope, distribute_anonymously, "
        "title, owner_tag, proxy_confirm_by) VALUES "
        "(:id, 'draft', 'amber', 'own_product', false, 'a filing', :tag, "
        "CAST(:confirm_by AS timestamptz))",
        id=submission_id,
        tag=_TAG,
        confirm_by=confirm_by,
    )


def test_existing_proxy_filings_are_marked_and_keep_their_deadline(config):
    url = os.environ["AIVS_MIGRATION_DATABASE_URL"]
    command.upgrade(config, BEFORE)
    _submission(url, PROXY, "2026-10-16T12:00:00+00:00")
    _submission(url, OWN, None)

    command.upgrade(config, MARKED)

    rows = dict(
        _execute(
            url,
            "SELECT id::text, filed_on_behalf FROM submissions WHERE proxy_confirm_by IS NOT NULL "
            "OR id = CAST(:own AS uuid)",
            own=OWN,
        )
    )
    assert rows == {PROXY: True, OWN: False}


def test_the_downgrade_refuses_while_a_filing_waits_with_no_deadline(config):
    url = os.environ["AIVS_MIGRATION_DATABASE_URL"]
    command.upgrade(config, MARKED)
    _submission(url, WAITING, None)
    _execute(
        url,
        "UPDATE submissions SET filed_on_behalf = true WHERE id = CAST(:id AS uuid)",
        id=WAITING,
    )

    with pytest.raises(RuntimeError, match="wait for a person with no deadline"):
        command.downgrade(config, BEFORE)

    _execute(url, "DELETE FROM submissions WHERE id = CAST(:id AS uuid)", id=WAITING)
    command.downgrade(config, BEFORE)
    columns = _execute(
        url,
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'submissions' AND column_name = 'filed_on_behalf'",
    )
    assert columns == []
