"""The circle-role migration moves open sector memberships to contributor, and nothing else.

``default_circle_role`` decides the role of a membership opened from now on;
this migration applies it to the ones open already. It must leave an
operator's choices, closed intervals, and vendor or government readers as they
were, and it must say in the audit log what it changed, because the log is
where "why can this firm post here?" gets asked. Run on a scratch database at
the previous revision, seeded the way the previous release stored rows.
"""

from __future__ import annotations

import datetime as dt
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from aivs_server.audit.log import AuditAction
from tests.conftest import TEST_DATABASE_URL, TEST_SECRET_KEY_FILE

pytestmark = [pytest.mark.db, pytest.mark.slow]

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"
ROLES_REVISION = "3efc1e04d297"
ACTION = AuditAction.CIRCLE_MEMBER_ROLES_DEFAULTED


@pytest.fixture(scope="module")
def config() -> Iterator[Config]:
    test_url = make_url(TEST_DATABASE_URL)
    scratch = f"{test_url.database}_circle_roles"
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


#: name -> (org_type, role, closed). Each row is one membership in one circle.
MEMBERSHIPS = {
    "bank-reader": ("gsib", "member", False),
    "section9-reader": ("section9", "member", False),
    "bank-already-contributor": ("gsib", "contributor", False),
    "bank-historical": ("crit_infra", "member", True),
    "vendor-reader": ("vendor", "member", False),
    "regulator-reader": ("government", "member", False),
}


def _seed(url: str) -> None:
    engine = create_engine(url)
    joined = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    with engine.begin() as connection:
        circle = connection.execute(
            text(
                "INSERT INTO circles (slug, name, minimum_tlp, is_active) "
                "VALUES ('sector', 'Sector', 'amber', true) RETURNING id"
            )
        ).scalar_one()
        for index, (name, (org_type, role, closed)) in enumerate(MEMBERSHIPS.items()):
            org = connection.execute(
                text(
                    "INSERT INTO organizations (name, slug, org_type, status, stix_identity_id) "
                    "VALUES (:name, :name, :type, 'active', :identity) RETURNING id"
                ),
                {
                    "name": name,
                    "type": org_type,
                    "identity": f"identity--0f9c0000-0000-4000-8000-{index:012d}",
                },
            ).scalar_one()
            connection.execute(
                text(
                    "INSERT INTO circle_memberships (circle_id, org_id, role, joined_at, "
                    "left_at, ended_by) VALUES (:circle, :org, :role, :joined, :left, :ended)"
                ),
                {
                    "circle": circle,
                    "org": org,
                    "role": role,
                    "joined": joined,
                    "left": joined + dt.timedelta(days=30) if closed else None,
                    "ended": "operator" if closed else None,
                },
            )
    engine.dispose()


def _roles(url: str) -> dict[str, str]:
    engine = create_engine(url)
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT o.slug, m.role::text FROM circle_memberships m "
                "JOIN organizations o ON o.id = m.org_id"
            )
        ).all()
    engine.dispose()
    return dict(rows)


def _audit_rows(url: str) -> list[dict]:
    engine = create_engine(url)
    with engine.connect() as connection:
        rows = connection.execute(
            text("SELECT actor_type, details FROM audit_log WHERE action = :action"),
            {"action": ACTION},
        ).mappings()
        found = [dict(row) for row in rows]
    engine.dispose()
    return found


def test_open_sector_readers_become_contributors_and_nothing_else_moves(config: Config):
    revision = ScriptDirectory.from_config(config).get_revision(ROLES_REVISION).module
    assert revision.ACTION == ACTION, "the migration writes the action the code names"
    previous = ScriptDirectory.from_config(config).get_revision(ROLES_REVISION).down_revision
    command.upgrade(config, str(previous))
    url = os.environ["AIVS_DATABASE_URL"]
    _seed(url)

    command.upgrade(config, ROLES_REVISION)

    assert _roles(url) == {
        "bank-reader": "contributor",
        "section9-reader": "contributor",
        "bank-already-contributor": "contributor",
        "bank-historical": "member",
        "vendor-reader": "member",
        "regulator-reader": "member",
    }
    [audit] = _audit_rows(url)
    assert audit["actor_type"] == "system"
    assert len(audit["details"]["membership_ids"]) == 2

    command.downgrade(config, str(previous))

    assert _roles(url) == {name: role for name, (_type, role, _closed) in MEMBERSHIPS.items()}
