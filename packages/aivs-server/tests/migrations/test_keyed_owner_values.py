"""The keyed-owner migration computes every tag and token, and the downgrade restores the table.

Rows are stored as ``740334d0e829`` left them -- random tokens held in
``attribution.object_owners``, no tags -- then the migration runs with the
suite's attribution key, and every value is compared with what the
application computes for the filer it was made for. The same shape as
``test_attribution_move``.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from tests.conftest import (
    TEST_ATTRIBUTION_KEY,
    TEST_ATTRIBUTION_KEY_FILE,
    TEST_DATABASE_URL,
    TEST_SECRET_KEY_FILE,
)

pytestmark = [pytest.mark.db, pytest.mark.slow]

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"
BEFORE = "740334d0e829"
TAGGED = "c6f2a9d41e7b"

MEMBER = uuid.UUID("00000000-0000-4000-8000-0000000000c1")
ISAC = uuid.UUID("00000000-0000-4000-8000-0000000000c2")
FIRST = uuid.UUID("00000000-0000-4000-8000-0000000000d1")
SECOND = uuid.UUID("00000000-0000-4000-8000-0000000000d2")
ISAC_FILING = uuid.UUID("00000000-0000-4000-8000-0000000000d3")
FILED_BY = {FIRST: MEMBER, SECOND: MEMBER, ISAC_FILING: ISAC}
_KEY_VARIABLES = ("AIVS_ATTRIBUTION_KEY", "AIVS_ATTRIBUTION_KEY_FILE")


@pytest.fixture
def config() -> Iterator[Config]:
    test_url = make_url(TEST_DATABASE_URL)
    scratch = f"{test_url.database}_keyed_owners"
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
        *_KEY_VARIABLES,
    )
    saved = {name: os.environ.get(name) for name in names}
    os.environ["AIVS_DATABASE_URL"] = url
    os.environ["AIVS_MIGRATION_DATABASE_URL"] = url
    os.environ.pop("AIVS_SECRET_ENCRYPTION_KEY", None)
    os.environ["AIVS_SECRET_ENCRYPTION_KEY_FILE"] = str(TEST_SECRET_KEY_FILE)
    for name in _KEY_VARIABLES:
        os.environ.pop(name, None)
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
    "'identity--00000000-0000-4000-8000-0000000000c1'), "
    "(:isac, 'ISAC', 'isac', 'admin', 'active', "
    "'identity--00000000-0000-4000-8000-0000000000c2')",
    "INSERT INTO submissions (id, state, tlp, discovery_scope, distribute_anonymously, title) "
    "VALUES (:first, 'draft', 'amber', 'own_product', false, 'first'), "
    "(:second, 'draft', 'amber', 'own_product', false, 'second'), "
    "(:isac_filing, 'draft', 'amber', 'own_product', false, 'isac')",
    "INSERT INTO attribution.submitters (submission_id, org_id) VALUES "
    "(:first, :member), (:second, :member), (:isac_filing, :isac)",
    "INSERT INTO attribution.object_owners (owner_token, stix_id, org_id) VALUES "
    "('random-token-x', 'vulnerability--x', :member), "
    "('random-token-y', 'vulnerability--y', :member)",
    "INSERT INTO stix_objects (stix_id, modified, created, type, spec_version, submission_id, "
    "raw, owner_token) VALUES "
    "('vulnerability--x', '2026-08-01', '2026-08-01', 'vulnerability', '2.1', :first, '{}', "
    "'random-token-x'), "
    "('vulnerability--x', '2026-09-01', '2026-08-01', 'vulnerability', '2.1', :second, '{}', "
    "'random-token-x'), "
    "('vulnerability--y', '2026-09-01', '2026-09-01', 'vulnerability', '2.1', :second, '{}', "
    "'random-token-y'), "
    "('vulnerability--z', '2026-09-01', '2026-09-01', 'vulnerability', '2.1', :isac_filing, "
    "'{}', 'isac')",
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


def _tokens(url: str) -> dict[tuple[uuid.UUID, str], str]:
    rows = _rows(url, "SELECT submission_id, stix_id, owner_token FROM stix_objects")
    return {(submission, stix_id): token for submission, stix_id, token in rows}


def _tables_named(url: str, name: str) -> list[tuple]:
    return _rows(
        url,
        f"SELECT 1 FROM information_schema.tables WHERE table_schema = 'attribution' "  # noqa: S608 - a literal of this test
        f"AND table_name = '{name}'",
    )


@pytest.fixture
def seeded_url(config: Config) -> str:
    """A scratch database at ``BEFORE``, holding rows as that release wrote them."""
    command.upgrade(config, BEFORE)
    url = os.environ["AIVS_MIGRATION_DATABASE_URL"]
    _execute(url, _SEED)
    return url


@pytest.mark.requirement("SF-90")
def test_the_migration_refuses_to_run_without_the_key_when_there_are_rows(
    config: Config, seeded_url: str
):
    url = seeded_url
    with pytest.raises(RuntimeError, match="AIVS_ATTRIBUTION_KEY_FILE must be set"):
        command.upgrade(config, TAGGED)

    assert _tables_named(url, "object_owners") == [(1,)], "nothing was half done"


@pytest.mark.requirement("SF-90")
def test_every_tag_and_token_is_the_one_the_application_computes(config: Config, seeded_url: str):
    url = seeded_url
    os.environ["AIVS_ATTRIBUTION_KEY_FILE"] = str(TEST_ATTRIBUTION_KEY_FILE)
    try:
        command.upgrade(config, TAGGED)
    finally:
        os.environ.pop("AIVS_ATTRIBUTION_KEY_FILE", None)

    tags = dict(_rows(url, "SELECT id, owner_tag FROM submissions"))
    assert tags == {
        submission: TEST_ATTRIBUTION_KEY.owner_tag(org, submission)
        for submission, org in FILED_BY.items()
    }
    tokens = _tokens(url)
    assert tokens[(FIRST, "vulnerability--x")] == TEST_ATTRIBUTION_KEY.owner_token(
        MEMBER, "vulnerability--x"
    )
    assert tokens[(SECOND, "vulnerability--x")] == tokens[(FIRST, "vulnerability--x")]
    assert tokens[(SECOND, "vulnerability--y")] == TEST_ATTRIBUTION_KEY.owner_token(
        MEMBER, "vulnerability--y"
    )
    assert tokens[(ISAC_FILING, "vulnerability--z")] == "isac"
    assert _tables_named(url, "object_owners") == []

    command.downgrade(config, BEFORE)

    owners = _rows(url, "SELECT stix_id, org_id, owner_token FROM attribution.object_owners")
    assert sorted((stix_id, org) for stix_id, org, _token in owners) == [
        ("vulnerability--x", MEMBER),
        ("vulnerability--y", MEMBER),
    ]
    by_id = {stix_id: token for stix_id, _org, token in owners}
    restored = _tokens(url)
    assert restored[(FIRST, "vulnerability--x")] == by_id["vulnerability--x"]
    assert restored[(SECOND, "vulnerability--x")] == by_id["vulnerability--x"]
    assert restored[(SECOND, "vulnerability--y")] == by_id["vulnerability--y"]
    assert restored[(ISAC_FILING, "vulnerability--z")] == "isac"
    with pytest.raises(DBAPIError, match="append-only"):
        _execute(url, ("UPDATE attribution.object_owners SET org_id = org_id",))
