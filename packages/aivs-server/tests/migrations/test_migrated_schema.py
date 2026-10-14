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

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Enum as SAEnum
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from aivs_server.db.models import Base
from tests.conftest import TEST_DATABASE_URL, TEST_SECRET_KEY_FILE

pytestmark = [pytest.mark.db, pytest.mark.slow]

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
    names = (
        "AIVS_DATABASE_URL",
        "AIVS_MIGRATION_DATABASE_URL",
        "AIVS_SECRET_ENCRYPTION_KEY",
        "AIVS_SECRET_ENCRYPTION_KEY_FILE",
    )
    saved = {name: os.environ.get(name) for name in names}
    # Both names: alembic's env.py prefers AIVS_MIGRATION_DATABASE_URL. CI set
    # it job-wide, so this fixture migrated the CI database a second time and
    # left the scratch one empty -- green locally, where nobody sets it.
    os.environ["AIVS_DATABASE_URL"] = url
    os.environ["AIVS_MIGRATION_DATABASE_URL"] = url
    # The secrets migration refuses to run without a key. The file form, because
    # that is what a deployment outside dev uses, so what the migration must read.
    os.environ.pop("AIVS_SECRET_ENCRYPTION_KEY", None)
    os.environ["AIVS_SECRET_ENCRYPTION_KEY_FILE"] = str(TEST_SECRET_KEY_FILE)
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


@pytest.mark.requirement("SF-43")
def test_membership_intervals_cannot_overlap(migrated_url: str):
    constraints = _scalars(
        migrated_url,
        "SELECT conname FROM pg_constraint "
        "WHERE conrelid = 'circle_memberships'::regclass AND contype = 'x'",
    )
    assert "ex_circle_memberships_no_overlap" in constraints


_SEED_ORG = "00000000-0000-4000-8000-000000000001"
_SEED_SUBMISSION = "00000000-0000-4000-8000-000000000002"
_SEED_STATEMENTS = (
    "INSERT INTO organizations (id, name, slug, org_type, status, stix_identity_id) "
    "VALUES (:org, 'Seed', 'seed-org', 'gsib', 'active', :identity)",
    "INSERT INTO submissions (id, submitter_org_id, state, tlp, discovery_scope, "
    "distribute_anonymously, title) "
    "VALUES (:submission, :org, 'draft', 'amber', 'ai_system', false, 's')",
    "INSERT INTO submission_transitions (submission_id, to_state) VALUES (:submission, 'draft')",
    "INSERT INTO audit_log (actor_type, action, outcome, details) "
    "VALUES ('system', 'seed', 'success', '{}')",
)


def _seed_append_only_rows(url: str) -> None:
    """One row in each append-only table: a row-level trigger never fires on an
    empty table, so a refusal test against one proves nothing."""
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            for statement in _SEED_STATEMENTS:
                connection.execute(
                    text(statement),
                    {
                        "org": _SEED_ORG,
                        "submission": _SEED_SUBMISSION,
                        "identity": f"identity--{_SEED_ORG}",
                    },
                )
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def seeded_url(migrated_url: str) -> str:
    _seed_append_only_rows(migrated_url)
    return migrated_url


@pytest.mark.parametrize("table", ["audit_log", "submission_transitions"])
@pytest.mark.parametrize(
    "statement",
    ["UPDATE {table} SET id = id", "DELETE FROM {table}", "TRUNCATE {table} CASCADE"],
)
@pytest.mark.requirement("NFR-S6")
def test_append_only_tables_refuse_to_change_and_still_accept_inserts(
    seeded_url: str, table: str, statement: str
):
    """Attempted, not looked up by name: a trigger of the right name that fires
    BEFORE INSERT, or calls a no-op, passed the name check."""
    engine = create_engine(seeded_url)
    try:
        with engine.connect() as connection:
            with pytest.raises(DBAPIError, match="append-only"):
                connection.execute(text(statement.format(table=table)))
            connection.rollback()
            count = connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()  # noqa: S608 - table from the parametrize list
    finally:
        engine.dispose()
    assert count >= 1


def test_one_hosting_isac_and_rule_eligibility_exist_in_the_migrated_schema(migrated_url: str):
    """Neither is compared by alembic check, so a migration that lost one would
    pass every other gate."""
    indexes = _scalars(
        migrated_url, "SELECT indexname FROM pg_indexes WHERE tablename = 'organizations'"
    )
    checks = _scalars(
        migrated_url,
        "SELECT conname FROM pg_constraint WHERE conrelid = 'circles'::regclass AND contype = 'c'",
    )
    assert "uq_organizations_one_admin" in indexes
    assert "uq_organizations_one_automation" in indexes
    assert any("rule_admits_eligible_types" in name for name in checks), checks


@pytest.mark.parametrize("org_type", ["admin", "automation"])
def test_the_migrated_schema_refuses_a_second_isac_organisation(migrated_url: str, org_type: str):
    """Attempted, not looked up by name: a non-unique index, or one with the wrong
    predicate, of the right name passed the check above."""
    insert = text(
        "INSERT INTO organizations (id, name, slug, org_type, status, stix_identity_id) "
        "VALUES (:id, :slug, :slug, :org_type, 'active', :identity)"
    )

    def row(index: int) -> dict[str, str]:
        org_id = f"00000000-0000-4000-8000-0000000001{index:02d}"
        return {
            "id": org_id,
            "slug": f"second-{org_type}-{index}",
            "org_type": org_type,
            "identity": f"identity--{org_id}",
        }

    engine = create_engine(migrated_url)
    try:
        with engine.connect() as connection:
            connection.execute(insert, row(1))
            with pytest.raises(DBAPIError, match="uq_organizations_one_"):
                connection.execute(insert, row(2))
            connection.rollback()
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("columns", "values", "check"),
    [
        ("status", "'affected'", "affected_says_what_is_done"),
        ("status", "'not_affected'", "not_affected_says_why"),
        (
            "status, justification",
            "'fixed', 'component_not_present'",
            "justification_only_when_not_affected",
        ),
    ],
    ids=["affected", "not-affected", "justification-on-fixed"],
)
def test_the_migrated_schema_refuses_a_posture_vex_would_reject(
    migrated_url: str, columns: str, values: str, check: str
):
    """VEX's rules are in the migration, not only the model: attempted, not looked up."""
    org_id = "00000000-0000-4000-8000-000000000301"
    engine = create_engine(migrated_url)
    try:
        with engine.connect() as connection:
            connection.execute(
                text(
                    "INSERT INTO organizations "
                    "(id, name, slug, org_type, status, stix_identity_id) "
                    "VALUES (:id, 'Vex', 'vex-firm', 'gsib', 'active', :identity)"
                ),
                {"id": org_id, "identity": f"identity--{org_id}"},
            )
            with pytest.raises(DBAPIError, match=check):
                connection.execute(
                    text(
                        f"INSERT INTO org_postures (org_id, vulnerability_stix_id, {columns}) "  # noqa: S608 - columns and values from the parametrize list
                        f"VALUES (:org, 'vulnerability--x', {values})"
                    ),
                    {"org": org_id},
                )
            connection.rollback()
    finally:
        engine.dispose()


_LEAVER_ORG = "00000000-0000-4000-8000-000000000401"
_LEAVER_CIRCLE = "00000000-0000-4000-8000-000000000402"
_LEAVER_ROWS = (
    "INSERT INTO organizations (id, name, slug, org_type, status, stix_identity_id) "
    "VALUES (:org, 'Leaver', 'leaver-firm', 'gsib', 'offboarded', :identity)",
    "INSERT INTO circles (id, slug, name, minimum_tlp, is_active) "
    "VALUES (:circle, 'leaver-circle', 'Leaver circle', 'amber', true)",
)


def _close_interval_as(connection: Any, ended_by: str) -> None:
    params = {"org": _LEAVER_ORG, "circle": _LEAVER_CIRCLE, "identity": f"identity--{_LEAVER_ORG}"}
    for statement in _LEAVER_ROWS:
        connection.execute(text(statement), params)
    connection.execute(
        text(
            "INSERT INTO circle_memberships "
            "(circle_id, org_id, role, joined_at, left_at, ended_by) "
            "VALUES (:circle, :org, 'member', now() - interval '1 day', now(), :ended_by)"
        ),
        {**params, "ended_by": ended_by},
    )


def test_the_migrated_schema_knows_an_interval_closed_by_offboarding(migrated_url: str):
    """A changed check constraint is invisible to ``alembic check``: attempted, not compared."""
    engine = create_engine(migrated_url)
    try:
        with engine.connect() as connection:
            _close_interval_as(connection, "offboarding")
            connection.rollback()
            with pytest.raises(DBAPIError, match="ended_by_known"):
                _close_interval_as(connection, "unknown")
            connection.rollback()
    finally:
        engine.dispose()


def _declared_enum_labels() -> dict[str, set[str]]:
    """Every native enum type the models declare, with the labels it stores."""
    return {
        column.type.name: set(column.type.enums)
        for table in Base.metadata.tables.values()
        for column in table.columns
        if isinstance(column.type, SAEnum) and column.type.name
    }


def _migrated_enum_labels(url: str) -> dict[str, set[str]]:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT t.typname, e.enumlabel FROM pg_type t "
                    "JOIN pg_enum e ON e.enumtypid = t.oid"
                )
            ).all()
    finally:
        engine.dispose()
    labels: dict[str, set[str]] = {}
    for type_name, label in rows:
        labels.setdefault(type_name, set()).add(label)
    return labels


@pytest.mark.requirement("NFR-M2")
def test_every_enum_type_holds_exactly_the_labels_its_python_enum_declares(migrated_url: str):
    """``alembic check`` compares neither enum types nor their labels.

    The suite builds its types from the Python enums with ``create_all``, so a
    value added to a ``StrEnum`` without its ``ALTER TYPE ... ADD VALUE``
    migration passes every test and fails in production on the first write --
    and a migration adding a value the code no longer declares is invisible too.
    """
    migrated = _migrated_enum_labels(migrated_url)
    declared = _declared_enum_labels()

    mismatched = {
        name: {"declared": sorted(labels), "migrated": sorted(migrated.get(name, set()))}
        for name, labels in declared.items()
        if migrated.get(name) != labels
    }
    assert not mismatched, mismatched
