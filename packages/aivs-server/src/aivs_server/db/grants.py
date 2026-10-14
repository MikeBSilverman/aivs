"""What the application's database role may do, granted after every migration.

The append-only audit trail rests on one deployment fact: the application does
not connect as a superuser or as the owner of the tables. Either can drop the
deny triggers and rewrite history, and nothing in the database would say so.
The shipped stack ran exactly that way: the app connected as the role the
Postgres image creates, which is a superuser, and the grants that were meant to
confine it applied only to a role nothing created.

So the migration step, which runs as the owner, also grants the application
role what it needs and nothing more, and refuses a role that could undo the
triggers. Running it after every ``alembic upgrade`` rather than in one
migration makes it convergent: a table a later migration adds is granted on the
next run, and a deployment migrated without the role named is put right by
naming it once.

A table is append-only exactly when it carries a trigger that calls
``aivs_deny_mutation`` (migration ``c185fd428721``). That is read from the
database, not from a list kept here, so a table made append-only later is
confined here without anyone remembering this module.
"""

from __future__ import annotations

from typing import Final

from sqlalchemy import Connection, text
from sqlalchemy.ext.asyncio import AsyncSession

__all__ = ["APP_ROLE_ENV_VAR", "UnsafeAppRoleError", "connection_role_problem", "grant_app_role"]

#: Names the role the application connects as. The same variable migration
#: ``c185fd428721`` reads.
APP_ROLE_ENV_VAR: Final[str] = "AIVS_APP_DB_ROLE"

_DENY_FUNCTION: Final[str] = "aivs_deny_mutation"
_SCHEMA: Final[str] = "public"


class UnsafeAppRoleError(RuntimeError):
    """The named application role could bypass the append-only triggers, or is absent."""


def grant_app_role(connection: Connection, role: str) -> None:
    """Refuse an unsafe ``role``; otherwise grant it the application's privileges."""
    _refuse_unsafe_role(connection, role)
    for statement in _grant_statements(role, _append_only_tables(connection)):
        connection.execute(text(statement))


#: The two questions that decide whether a role could undo the triggers. Asked
#: by the migration step of the role it is about to grant, and by readiness of
#: the role the application is connected as: one text, so the two cannot drift.
_IS_SUPERUSER: Final = text("SELECT rolsuper FROM pg_roles WHERE rolname = :role")
_HOLDS_AN_OWNER: Final = text(
    """
    SELECT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = :schema AND pg_has_role(:role, c.relowner, 'MEMBER')
    )
    """
)


def _role_problem(role: str, *, is_superuser: bool | None, holds_an_owner: bool) -> str | None:
    """Why ``role`` could undo the append-only triggers, or ``None`` if it could not."""
    if is_superuser is None:
        return f"role {role!r} does not exist"
    if is_superuser:
        return f"role {role!r} is a superuser, which can drop the append-only triggers"
    if holds_an_owner:
        # Membership is enough: a member of the owning role can SET ROLE to it
        # and then disable a trigger, exactly as the owner can.
        return (
            f"role {role!r} owns, or is a member of a role that owns, "
            "the schema's tables, and could drop the append-only triggers"
        )
    return None


def _refuse_unsafe_role(connection: Connection, role: str) -> None:
    params = {"role": role, "schema": _SCHEMA}
    is_superuser = connection.execute(_IS_SUPERUSER, params).scalar_one_or_none()
    # pg_has_role raises for a role that does not exist, so only ask of one that does.
    holds_an_owner = is_superuser is not None and bool(
        connection.execute(_HOLDS_AN_OWNER, params).scalar_one()
    )
    problem = _role_problem(role, is_superuser=is_superuser, holds_an_owner=holds_an_owner)
    if problem is None:
        return
    if is_superuser is None:
        problem += "; create it before migrating (deploy/db/init/10-app-role.sh)"
    msg = f"application {problem}"
    raise UnsafeAppRoleError(msg)


async def connection_role_problem(session: AsyncSession) -> str | None:
    """Why the role ``session`` is connected as could undo the triggers, or ``None``.

    ``current_user``, not the login: a connection that has done ``SET ROLE`` acts
    with the role it set.
    """
    role = (await session.execute(text("SELECT current_user"))).scalar_one()
    params = {"role": role, "schema": _SCHEMA}
    is_superuser = (await session.execute(_IS_SUPERUSER, params)).scalar_one_or_none()
    holds_an_owner = bool((await session.execute(_HOLDS_AN_OWNER, params)).scalar_one())
    return _role_problem(role, is_superuser=is_superuser, holds_an_owner=holds_an_owner)


def _append_only_tables(connection: Connection) -> list[str]:
    rows = connection.execute(
        text(
            """
            SELECT DISTINCT c.relname
            FROM pg_trigger t
            JOIN pg_proc p ON p.oid = t.tgfoid
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE p.proname = :function AND n.nspname = :schema
            ORDER BY c.relname
            """
        ),
        {"function": _DENY_FUNCTION, "schema": _SCHEMA},
    )
    return [str(name) for (name,) in rows]


def _grant_statements(role: str, append_only_tables: list[str]) -> list[str]:
    """Data manipulation everywhere; append and read only where history lives.

    TRUNCATE is never granted. ``alembic_version`` is readable and nothing more:
    the application has no reason to move the schema's recorded revision.
    """
    quoted_role = _quote(role)
    statements = [
        f"GRANT USAGE ON SCHEMA {_SCHEMA} TO {quoted_role}",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {_SCHEMA} TO {quoted_role}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {_SCHEMA} TO {quoted_role}",
        f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON {_SCHEMA}.alembic_version FROM {quoted_role}",
    ]
    statements.extend(
        f"REVOKE UPDATE, DELETE, TRUNCATE ON {_SCHEMA}.{_quote(table)} FROM {quoted_role}"
        for table in append_only_tables
    )
    return statements


def _quote(identifier: str) -> str:
    """Quote an identifier for DDL, which takes no bound parameters.

    The role comes from the deployment's environment, so it is held to the
    shape a role name of ours has rather than escaped and trusted.
    """
    if not identifier or not identifier.replace("_", "").isalnum():
        msg = f"refusing to interpolate unsafe identifier: {identifier!r}"
        raise UnsafeAppRoleError(msg)
    return f'"{identifier}"'
