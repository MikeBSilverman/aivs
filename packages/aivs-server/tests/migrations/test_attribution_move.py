"""The attribution migration moves who filed what, and puts it back (Phase P, slice 2).

Rows are stored the way the previous release stored them -- the submitter on
``submissions`` -- then the migration runs and the rows are read back from
where they now live. Then the downgrade runs, which must restore every
column from ``attribution`` before it drops the schema, or rolling back
would lose who filed everything. The same shape as ``test_index_backfill``.
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

pytestmark = [pytest.mark.db, pytest.mark.slow]

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"
BEFORE = "14039d693865"
MOVE = "740334d0e829"

MEMBER = "00000000-0000-4000-8000-0000000000a1"
ISAC = "00000000-0000-4000-8000-0000000000a2"
FIRST = "00000000-0000-4000-8000-0000000000b1"
SECOND = "00000000-0000-4000-8000-0000000000b2"
ISAC_FILING = "00000000-0000-4000-8000-0000000000b3"
FILED_BY = {FIRST: MEMBER, SECOND: MEMBER, ISAC_FILING: ISAC}


@pytest.fixture(scope="module")
def config() -> Iterator[Config]:
    test_url = make_url(TEST_DATABASE_URL)
    scratch = f"{test_url.database}_attribution_move"
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


_SEED = (
    "INSERT INTO organizations (id, name, slug, org_type, status, stix_identity_id) VALUES "
    "(:member, 'Member', 'member', 'gsib', 'active', "
    "'identity--00000000-0000-4000-8000-0000000000a1'), "
    "(:isac, 'ISAC', 'isac', 'admin', 'active', "
    "'identity--00000000-0000-4000-8000-0000000000a2')",
    "INSERT INTO submissions (id, submitter_org_id, state, tlp, discovery_scope, "
    "distribute_anonymously, title) VALUES "
    "(:first, :member, 'draft', 'amber', 'own_product', false, 'first'), "
    "(:second, :member, 'draft', 'amber', 'own_product', false, 'second'), "
    "(:isac_filing, :isac, 'draft', 'amber', 'own_product', false, 'isac')",
    "INSERT INTO stix_objects (stix_id, modified, created, type, spec_version, submission_id, "
    "raw) VALUES "
    "('vulnerability--x', '2026-08-01', '2026-08-01', 'vulnerability', '2.1', :first, '{}'), "
    "('vulnerability--x', '2026-09-01', '2026-08-01', 'vulnerability', '2.1', :second, '{}'), "
    "('vulnerability--y', '2026-09-01', '2026-09-01', 'vulnerability', '2.1', :second, '{}'), "
    "('vulnerability--z', '2026-09-01', '2026-09-01', 'vulnerability', '2.1', :isac_filing, "
    "'{}')",
)
_PARAMS = {
    "member": MEMBER,
    "isac": ISAC,
    "first": FIRST,
    "second": SECOND,
    "isac_filing": ISAC_FILING,
}


def _execute(url: str, statements: tuple[str, ...]) -> None:
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement), _PARAMS)
    finally:
        engine.dispose()


def _rows(url: str, query: str) -> list[tuple]:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return [tuple(row) for row in connection.execute(text(query))]
    finally:
        engine.dispose()


def _filers(url: str) -> dict[str, str]:
    rows = _rows(url, "SELECT submission_id::text, org_id::text FROM attribution.submitters")
    return dict(rows)


def _tokens(url: str) -> dict[tuple[str, str], str]:
    rows = _rows(
        url, "SELECT submission_id::text, stix_id, owner_token FROM stix_objects ORDER BY stix_id"
    )
    return {(submission, stix_id): token for submission, stix_id, token in rows}


def _submissions_columns(url: str) -> set[str]:
    rows = _rows(
        url,
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'submissions'",
    )
    return {name for (name,) in rows}


@pytest.mark.requirement("SF-88")
def test_the_move_keeps_every_filer_and_the_downgrade_puts_them_back(config: Config):
    command.upgrade(config, BEFORE)
    url = os.environ["AIVS_MIGRATION_DATABASE_URL"]
    _execute(url, _SEED)

    command.upgrade(config, MOVE)

    assert _filers(url) == FILED_BY
    assert "submitter_org_id" not in _submissions_columns(url)
    tokens = _tokens(url)
    assert tokens[(FIRST, "vulnerability--x")] == tokens[(SECOND, "vulnerability--x")], (
        "one owner's versions of one id share a token"
    )
    assert tokens[(SECOND, "vulnerability--y")] != tokens[(SECOND, "vulnerability--x")], (
        "one owner's tokens on two ids say nothing about each other"
    )
    assert tokens[(ISAC_FILING, "vulnerability--z")] == "isac"
    owners = _rows(url, "SELECT stix_id, org_id::text FROM attribution.object_owners")
    assert sorted(owners) == [("vulnerability--x", MEMBER), ("vulnerability--y", MEMBER)]

    command.downgrade(config, BEFORE)

    restored = _rows(url, "SELECT id::text, submitter_org_id::text FROM submissions")
    assert dict(restored) == FILED_BY
    schemas = _rows(url, "SELECT 1 FROM pg_namespace WHERE nspname = 'attribution'")
    assert schemas == []

    command.upgrade(config, MOVE)
    assert _filers(url) == FILED_BY
