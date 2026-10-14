"""The application's database role, as the migration step leaves it.

The append-only triggers hold only against a role that can neither drop them
nor disable them: not a superuser, not the tables' owner, not a member of the
owner. The shipped stack connected as the Postgres image's superuser, so the
evidentiary guarantee the docs rest on did not hold in the one deployment we
ship. These tests migrate a scratch database as the owner, naming an
application role, then connect *as that role* and attempt what it must and must
not be able to do.

Roles are cluster-wide, so every name here derives from the scratch database's,
which derives from the test database URL: two concurrent runs never share one.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import DBAPIError

from aivs_server.db.grants import UnsafeAppRoleError
from tests.conftest import TEST_DATABASE_URL, TEST_SECRET_KEY_FILE

pytestmark = [pytest.mark.db, pytest.mark.slow]

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"
_ENV_NAMES = (
    "AIVS_DATABASE_URL",
    "AIVS_MIGRATION_DATABASE_URL",
    "AIVS_SECRET_ENCRYPTION_KEY",
    "AIVS_SECRET_ENCRYPTION_KEY_FILE",
    "AIVS_APP_DB_ROLE",
)
_ORG = "00000000-0000-4000-8000-0000000000a1"


def _admin(test_url: URL):
    return create_engine(test_url.set(database="postgres"), isolation_level="AUTOCOMMIT")


def _migrate(owner_url: str, app_role: str) -> None:
    """``alembic upgrade head`` as the owner, naming ``app_role``, as the stack does."""
    saved = {name: os.environ.get(name) for name in _ENV_NAMES}
    os.environ["AIVS_DATABASE_URL"] = owner_url
    os.environ["AIVS_MIGRATION_DATABASE_URL"] = owner_url
    os.environ.pop("AIVS_SECRET_ENCRYPTION_KEY", None)
    os.environ["AIVS_SECRET_ENCRYPTION_KEY_FILE"] = str(TEST_SECRET_KEY_FILE)
    os.environ["AIVS_APP_DB_ROLE"] = app_role
    try:
        command.upgrade(Config(str(ALEMBIC_INI)), "head")
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


class Scratch:
    def __init__(self, owner_url: URL, app_role: str, app_password: str) -> None:
        self.owner_url = owner_url.render_as_string(hide_password=False)
        self.app_url = owner_url.set(username=app_role, password=app_password)
        self.app_role = app_role


@pytest.fixture(scope="module")
def scratch() -> Iterator[Scratch]:
    test_url = make_url(TEST_DATABASE_URL)
    database = f"{test_url.database}_approle"
    app_role = f"{database}_app"
    app_password = secrets.token_hex(16)
    admin = _admin(test_url)
    with admin.connect() as connection:
        connection.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
        connection.execute(text(f'DROP ROLE IF EXISTS "{app_role}"'))
        connection.execute(text(f'CREATE DATABASE "{database}"'))
        # A password, because CI's Postgres checks one: the embedded server
        # here trusts every local login, so a role without one passed locally
        # and failed every connection in CI. Hex only, so the literal is safe.
        connection.execute(
            text(f"CREATE ROLE \"{app_role}\" LOGIN NOSUPERUSER PASSWORD '{app_password}'")
        )
    made = Scratch(test_url.set(database=database), app_role, app_password)
    try:
        _migrate(made.owner_url, app_role)
        yield made
    finally:
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
            connection.execute(text(f'DROP ROLE IF EXISTS "{app_role}"'))
        admin.dispose()


def _as_app(scratch: Scratch, *statements: str) -> None:
    engine = create_engine(scratch.app_url)
    try:
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement), {"org": _ORG, "identity": f"identity--{_ORG}"})
    finally:
        engine.dispose()


def test_the_app_role_may_read_and_change_ordinary_tables(scratch: Scratch):
    """The pair: confinement that also stopped the application working would be
    discovered at the first request, not at review."""
    _as_app(
        scratch,
        "INSERT INTO organizations (id, name, slug, org_type, status, stix_identity_id) "
        "VALUES (:org, 'Grant', 'grant-org', 'gsib', 'active', :identity)",
        "UPDATE organizations SET name = 'Granted' WHERE id = :org",
        "DELETE FROM organizations WHERE id = :org",
    )


@pytest.mark.requirement("NFR-S6")
def test_the_app_role_may_append_to_the_audit_log(scratch: Scratch):
    _as_app(
        scratch,
        "INSERT INTO audit_log (actor_type, action, outcome, details) "
        "VALUES ('system', 'grant-test', 'success', '{}')",
        "SELECT count(*) FROM audit_log",
    )


@pytest.mark.parametrize("table", ["audit_log", "submission_transitions"])
@pytest.mark.parametrize(
    "statement",
    ["UPDATE {table} SET id = id", "DELETE FROM {table}", "TRUNCATE {table}"],
    ids=["update", "delete", "truncate"],
)
@pytest.mark.requirement("NFR-S6")
def test_the_app_role_holds_no_privilege_to_change_history(
    scratch: Scratch, table: str, statement: str
):
    """Refused by the grant, before the trigger is reached.

    The trigger refuses too, with "append-only". Matching "permission denied"
    shows which check refused: the one a superuser or the owner would not meet.
    """
    with pytest.raises(DBAPIError, match=f"permission denied for table {table}"):
        _as_app(scratch, statement.format(table=table))


def test_the_app_role_owns_nothing_and_is_not_a_superuser(scratch: Scratch):
    engine = create_engine(scratch.app_url)
    try:
        with engine.connect() as connection:
            is_superuser = connection.execute(
                text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            ).scalar_one()
            owned = connection.execute(
                text("SELECT count(*) FROM pg_tables WHERE tableowner = current_user")
            ).scalar_one()
    finally:
        engine.dispose()
    assert (is_superuser, owned) == (False, 0)


@pytest.fixture
def extra_role(scratch: Scratch) -> Iterator[str]:
    test_url = make_url(TEST_DATABASE_URL)
    role = f"{scratch.app_role}_x"
    admin = _admin(test_url)
    with admin.connect() as connection:
        connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
    yield role
    with admin.connect() as connection:
        connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
    admin.dispose()


def _create_role(role: str, options: str) -> None:
    admin = _admin(make_url(TEST_DATABASE_URL))
    try:
        with admin.connect() as connection:
            connection.execute(text(f'CREATE ROLE "{role}" {options}'))
    finally:
        admin.dispose()


@pytest.mark.requirement("NFR-S6")
def test_migrating_refuses_a_superuser_as_the_app_role(scratch: Scratch, extra_role: str):
    _create_role(extra_role, "LOGIN SUPERUSER")
    with pytest.raises(UnsafeAppRoleError, match="is a superuser"):
        _migrate(scratch.owner_url, extra_role)


@pytest.mark.requirement("NFR-S6")
def test_migrating_refuses_a_member_of_the_owning_role(scratch: Scratch, extra_role: str):
    """A member can SET ROLE to the owner and disable a trigger, as the owner can."""
    owner = make_url(TEST_DATABASE_URL).username
    _create_role(extra_role, f'LOGIN NOSUPERUSER IN ROLE "{owner}"')
    with pytest.raises(UnsafeAppRoleError, match="member of a role that owns"):
        _migrate(scratch.owner_url, extra_role)


def test_migrating_refuses_an_app_role_that_does_not_exist(scratch: Scratch, extra_role: str):
    with pytest.raises(UnsafeAppRoleError, match="does not exist"):
        _migrate(scratch.owner_url, extra_role)
