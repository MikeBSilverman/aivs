"""The running application connects as a role that cannot rewrite the audit log.

The append-only triggers stop everyone but a superuser and the tables' owner,
and the shipped stack connected the application as the Postgres image's
superuser, which is both. These tests ask the running app's own connection
string who it is and what it may do, in the app container, so they test the
deployment and not a description of it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tests.e2e.stack import Stack, requires_stack

pytestmark = [pytest.mark.e2e, requires_stack]

ROOT = Path(__file__).resolve().parents[4]

#: Run in the app container with its own AIVS_DATABASE_URL. UPDATE and DELETE
#: match no row and are refused before any would be touched; a defect here
#: still meets the triggers, so the probe cannot damage the audit log.
_PROBE = """
import json, os, psycopg
url = os.environ["AIVS_DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://", 1)
statements = {
    "select": "SELECT count(*) FROM audit_log",
    "update": "UPDATE audit_log SET id = id WHERE false",
    "delete": "DELETE FROM audit_log WHERE false",
}
out = {}
with psycopg.connect(url, autocommit=True) as connection:
    out["user"], out["superuser"] = connection.execute(
        "SELECT current_user, rolsuper FROM pg_roles WHERE rolname = current_user"
    ).fetchone()
    out["owned_tables"] = connection.execute(
        "SELECT count(*) FROM pg_tables WHERE tableowner = current_user"
    ).fetchone()[0]
    for name, statement in statements.items():
        try:
            connection.execute(statement)
            out[name] = "allowed"
        except psycopg.Error as error:
            out[name] = error.diag.message_primary
print(json.dumps(out))
"""


@pytest.fixture(scope="module")
def app_role(stack: Stack) -> dict[str, object]:
    result = stack.compose("exec", "-T", "app", "python", "-", stdin=_PROBE)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.requirement("NFR-S6")
def test_the_app_connects_as_a_role_that_is_not_a_superuser_and_owns_nothing(app_role):
    assert app_role["superuser"] is False
    assert app_role["owned_tables"] == 0
    assert app_role["user"] == "aivs_app"


@pytest.mark.requirement("NFR-S6")
@pytest.mark.parametrize("operation", ["update", "delete"])
def test_the_app_role_is_refused_changes_to_the_audit_log_by_privilege(app_role, operation):
    """ "permission denied", not the trigger's "append-only": the grant refused,
    which is the check a superuser or the owner would not meet."""
    assert app_role[operation] == "permission denied for table audit_log"


def test_the_app_role_reads_the_audit_log(app_role):
    assert app_role["select"] == "allowed"


def test_the_owner_still_meets_the_trigger(stack: Stack):
    """The second layer, which the owner meets: the trigger is installed."""
    result = stack.compose(
        "exec",
        "-T",
        "db",
        "sh",
        "-c",
        'PGPASSWORD="$POSTGRES_PASSWORD" '
        'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At',
        stdin="DELETE FROM audit_log WHERE false;",
    )
    assert result.returncode != 0
    assert "table audit_log is append-only; DELETE is not permitted" in result.stderr


def _db_healthcheck() -> str:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    kind, command = compose["services"]["db"]["healthcheck"]["test"]
    assert kind == "CMD-SHELL"
    return command.replace("$$", "$")


def test_the_db_healthcheck_passes_with_the_app_roles_password(stack: Stack):
    result = stack.compose("exec", "-T", "db", "sh", "-c", _db_healthcheck())
    assert result.returncode == 0, result.stderr


def test_the_db_healthcheck_fails_with_a_wrong_password(stack: Stack):
    """It authenticates: pg_isready, which it replaced, passed this."""
    result = stack.compose(
        "exec", "-T", "-e", "AIVS_DB_APP_PASSWORD=wrong", "db", "sh", "-c", _db_healthcheck()
    )
    assert result.returncode != 0
    assert "password authentication failed" in result.stderr
