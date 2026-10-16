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

The member login (Phase P) is the other way round: it is granted from a list,
``MEMBER_GRANTS``, table by table and privilege by privilege, and a table the
list does not name gets nothing. Every member organisation shares that login,
so whatever it may read, injected SQL on the member path may read for every
member. The list therefore withholds SELECT on who filed what
(``attribution``) and on every table that would say it by another route, and
withholds UPDATE on the two keyed owner columns, which carry no deny trigger.
``tests/migrations/test_member_login_grants.py`` asks Postgres, as the member
login, what each table and column allows, and compares it with a
classification of its own.

The list is what the member path does, recorded from every statement the
member login made across the suite (slice 3c), and the suite's own member
engine connects as a login granted from it. So a member path the suite never
runs meets a refused privilege the first time it runs in production. That is
fail-closed, and it is reported as such: the engine raises
``PrivilegeRefusedError``, a 500 logged as "database refused a privilege" with
the table and the operation (runbook section 10). The fix is a test that runs
the path and a line here, not a grant made by hand, which the next migration
run takes back.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from sqlalchemy import Connection, text
from sqlalchemy.ext.asyncio import AsyncSession

__all__ = [
    "APP_ROLE_ENV_VAR",
    "MEMBER_GRANTS",
    "MEMBER_ROLE_ENV_VAR",
    "TableGrant",
    "UnsafeAppRoleError",
    "connection_role_problem",
    "grant_app_role",
    "grant_member_role",
]

#: Names the role the application connects as. The same variable migration
#: ``c185fd428721`` reads.
APP_ROLE_ENV_VAR: Final[str] = "AIVS_APP_DB_ROLE"
#: Names the member path's login (Phase P): every member organisation's
#: request, and any handler whose caller is not yet known, connects as it.
#: Finding out who the caller is runs on the staff login (``auth.staff_auth``).
MEMBER_ROLE_ENV_VAR: Final[str] = "AIVS_MEMBER_DB_ROLE"

_DENY_FUNCTION: Final[str] = "aivs_deny_mutation"
#: Every schema the application's tables live in. ``attribution`` holds who
#: filed what (Phase P).
_SCHEMAS: Final[tuple[str, ...]] = ("public", "attribution")


@dataclass(frozen=True, slots=True)
class TableGrant:
    """What the member login may do to one table.

    ``update_columns`` grants UPDATE on those columns alone, for a table whose
    other columns the member path must not change; it is empty where
    ``privileges`` grants UPDATE on the whole table, or none.
    """

    privileges: tuple[str, ...]
    update_columns: tuple[str, ...] = ()


_READ: Final = TableGrant(("SELECT",))
#: Written on the member path, read only by staff: each row says, or lets SQL
#: work out, which organisation filed which submission.
_WRITE_ONLY: Final = TableGrant(("INSERT",))

#: The member login's privileges, table by table, and UPDATE column by column:
#: what the member path does, and nothing it does not. A table not named here
#: is granted nothing, so a new table stays closed to the member path until
#: someone decides what the member path may do with it. Every member shares
#: the login, so column grants matter beyond attribution: with UPDATE on the
#: whole of ``organizations``, SQL on the member path could set its own
#: ``org_type`` to the ISAC's and be routed to the staff login.
MEMBER_GRANTS: Final[Mapping[str, TableGrant]] = MappingProxyType(
    {
        # Who filed what: the member path records its own filings and reads
        # none, not even its own (services.attribution answers that, staff
        # side, from the authenticated organisation).
        "attribution.submitters": _WRITE_ONLY,
        # Each row of these names an organisation beside a submission: the
        # actor, the poster, the webhook a telemetry event went to.
        "public.audit_log": _WRITE_ONLY,
        "public.submission_transitions": _WRITE_ONLY,
        "public.taxii_status": _WRITE_ONLY,
        "public.webhook_deliveries": _WRITE_ONLY,
        # Filed on the member path, and changed only staff side, keyed on the
        # caller's own filing (member_staff_writes, slice 3g). With UPDATE on
        # any column, SQL on the member path could withdraw a peer's filing,
        # lower its TLP before review (R34), or copy one row's owner tag onto
        # another (SF-90: the keyed columns carry no deny trigger).
        "public.submissions": TableGrant(("SELECT", "INSERT")),
        # A new filing's objects are inserted; replacing a draft's bundle
        # deletes them, staff side (slice 3g: with DELETE, SQL on the member
        # path could delete any firm's undistributed objects). No UPDATE of ``raw``:
        # only distribution and validation rewrite it, both staff side since
        # slice 3f, and with it SQL on the member path could rewrite any
        # distributed object's content.
        "public.stix_objects": TableGrant(("SELECT", "INSERT")),
        # Retrievals are recorded on the member path; a member's own receipts
        # are read, and its assertions made, staff side (slice 3e: R26).
        "public.acknowledgments": _WRITE_ONLY,
        # Read for visibility; written only staff side (slice 3f: R33), or SQL
        # on the member path could publish any object into any circle.
        "public.distributions": _READ,
        "public.circle_memberships": _READ,
        "public.circles": _READ,
        "public.embargoes": _READ,
        "public.instance_controls": _READ,
        "public.sector_events": _READ,
        "public.taxii_collections": _READ,
        # Read on the authentication path; an organisation administrator's own
        # revocation is written staff side (member_staff_writes). With UPDATE
        # here, SQL on the member path could revoke every firm's certificate or
        # bring a revoked one back (R35).
        "public.client_certificates": _READ,
        # Its own status and settings a member changes on the staff login
        # (``member_staff_writes``): with them here, SQL on the member path could
        # lift a peer's quarantine or redirect its digest. ``updated_at`` only,
        # because the member path row-locks its own organisation.
        "public.organizations": TableGrant(("SELECT",), update_columns=("updated_at",)),
    }
)


class UnsafeAppRoleError(RuntimeError):
    """The named application role could bypass the append-only triggers, or is absent."""


def grant_app_role(connection: Connection, role: str) -> None:
    """Refuse an unsafe ``role``; otherwise grant it the application's privileges."""
    _refuse_unsafe_role(connection, role)
    for statement in _grant_statements(role, _append_only_tables(connection)):
        connection.execute(text(statement))


#: Whether one role can act as another: ``SET ROLE`` to it, or inherit its grants.
_CAN_ACT_AS: Final = text("SELECT pg_has_role(:role, :other, 'MEMBER')")


def grant_member_role(connection: Connection, role: str, *, staff_role: str) -> None:
    """Refuse an unsafe member login; otherwise grant it the member path's privileges.

    Everything ``grant_app_role`` refuses, and also the staff login itself or
    any role that can act as it: the split rests on the member login being
    unable to reach what the staff login can, and membership of the staff role
    reaches all of it with one ``SET ROLE``.
    """
    _refuse_unsafe_role(connection, role)
    if (
        role == staff_role
        or connection.execute(_CAN_ACT_AS, {"role": role, "other": staff_role}).scalar_one()
    ):
        msg = (
            f"member role {role!r} is, or can act as, the staff role {staff_role!r}; "
            "the member path must have a login of its own"
        )
        raise UnsafeAppRoleError(msg)
    statements = _member_revoke_statements(role, _member_column_grants(connection, role))
    statements += _member_grant_statements(
        role, _existing_tables(connection), _owned_sequences(connection)
    )
    for statement in statements:
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
        WHERE n.nspname = ANY(:schemas) AND pg_has_role(:role, c.relowner, 'MEMBER')
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
    params = {"role": role, "schemas": list(_SCHEMAS)}
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
    params = {"role": role, "schemas": list(_SCHEMAS)}
    is_superuser = (await session.execute(_IS_SUPERUSER, params)).scalar_one_or_none()
    holds_an_owner = bool((await session.execute(_HOLDS_AN_OWNER, params)).scalar_one())
    return _role_problem(role, is_superuser=is_superuser, holds_an_owner=holds_an_owner)


def _append_only_tables(connection: Connection) -> list[tuple[str, str]]:
    """Each table carrying the deny trigger, as ``(schema, table)``."""
    rows = connection.execute(
        text(
            """
            SELECT DISTINCT n.nspname, c.relname
            FROM pg_trigger t
            JOIN pg_proc p ON p.oid = t.tgfoid
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE p.proname = :function AND n.nspname = ANY(:schemas)
            ORDER BY n.nspname, c.relname
            """
        ),
        {"function": _DENY_FUNCTION, "schemas": list(_SCHEMAS)},
    )
    return [(str(schema), str(name)) for schema, name in rows]


def _grant_statements(role: str, append_only_tables: list[tuple[str, str]]) -> list[str]:
    """Data manipulation everywhere; append and read only where history lives.

    TRUNCATE is never granted. ``alembic_version`` is readable and nothing more:
    the application has no reason to move the schema's recorded revision.
    """
    quoted_role = _quote(role)
    statements = []
    for schema in _SCHEMAS:
        statements += [
            f"GRANT USAGE ON SCHEMA {schema} TO {quoted_role}",
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} "
            f"TO {quoted_role}",
            f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {quoted_role}",
        ]
    statements.append(
        f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.alembic_version FROM {quoted_role}"
    )
    statements.extend(
        f"REVOKE UPDATE, DELETE, TRUNCATE ON {schema}.{_quote(table)} FROM {quoted_role}"
        for schema, table in append_only_tables
    )
    return statements


def _existing_tables(connection: Connection) -> set[str]:
    """Every table in the application's schemas, as ``schema.table``."""
    rows = connection.execute(
        text("SELECT schemaname, tablename FROM pg_tables WHERE schemaname = ANY(:schemas)"),
        {"schemas": list(_SCHEMAS)},
    )
    return {f"{schema}.{name}" for schema, name in rows}


def _owned_sequences(connection: Connection) -> dict[str, list[str]]:
    """Each table's own sequences (a ``serial`` key's), as ``schema.sequence``."""
    rows = connection.execute(
        text(
            """
            SELECT tn.nspname, t.relname, sn.nspname, s.relname
            FROM pg_depend d
            JOIN pg_class s ON s.oid = d.objid AND s.relkind = 'S'
            JOIN pg_namespace sn ON sn.oid = s.relnamespace
            JOIN pg_class t ON t.oid = d.refobjid
            JOIN pg_namespace tn ON tn.oid = t.relnamespace
            WHERE d.deptype IN ('a', 'i') AND tn.nspname = ANY(:schemas)
            """
        ),
        {"schemas": list(_SCHEMAS)},
    )
    sequences: dict[str, list[str]] = {}
    for table_schema, table, sequence_schema, sequence in rows:
        sequences.setdefault(f"{table_schema}.{table}", []).append(f"{sequence_schema}.{sequence}")
    return sequences


def _member_column_grants(connection: Connection, role: str) -> list[tuple[str, str]]:
    """Each column ``role`` holds a column-level privilege on, as ``(schema.table, column)``.

    ``REVOKE ALL ON ALL TABLES`` leaves column grants in place, so a column
    taken off ``update_columns`` would otherwise keep its grant for good.
    """
    rows = connection.execute(
        text(
            """
            SELECT n.nspname, c.relname, a.attname
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY(:schemas) AND a.attacl IS NOT NULL
              AND EXISTS (
                  SELECT 1 FROM aclexplode(a.attacl) x
                  WHERE x.grantee = (SELECT oid FROM pg_roles WHERE rolname = :role)
              )
            """
        ),
        {"schemas": list(_SCHEMAS), "role": role},
    )
    return [(f"{schema}.{table}", str(column)) for schema, table, column in rows]


def _member_revoke_statements(role: str, column_grants: list[tuple[str, str]]) -> list[str]:
    """Take away whatever the member login holds, so the grants that follow are all it has.

    Convergent: a login granted more by an earlier release (slice 3a granted it
    everything the staff login has) is narrowed by the next migration run.
    """
    quoted_role = _quote(role)
    statements = []
    for schema in _SCHEMAS:
        statements += [
            f"REVOKE ALL ON ALL TABLES IN SCHEMA {schema} FROM {quoted_role}",
            f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA {schema} FROM {quoted_role}",
        ]
    statements.extend(
        f"REVOKE ALL ({_quote(column)}) ON {_qualified(table)} FROM {quoted_role}"
        for table, column in column_grants
    )
    return statements


def _member_grant_statements(
    role: str, existing_tables: set[str], owned_sequences: dict[str, list[str]]
) -> list[str]:
    """``MEMBER_GRANTS``, for the tables this revision has.

    A migration step that downgrades runs this too, against a schema without
    the newest tables; ``test_member_login_grants`` catches a name that is
    wrong rather than merely not yet created.
    """
    quoted_role = _quote(role)
    statements = [f"GRANT USAGE ON SCHEMA {schema} TO {quoted_role}" for schema in _SCHEMAS]
    for table, grant in MEMBER_GRANTS.items():
        if table not in existing_tables:
            continue
        qualified = _qualified(table)
        statements.append(f"GRANT {', '.join(grant.privileges)} ON {qualified} TO {quoted_role}")
        if grant.update_columns:
            columns = ", ".join(_quote(column) for column in grant.update_columns)
            statements.append(f"GRANT UPDATE ({columns}) ON {qualified} TO {quoted_role}")
        if "INSERT" in grant.privileges:
            statements.extend(
                f"GRANT USAGE ON SEQUENCE {_qualified(sequence)} TO {quoted_role}"
                for sequence in owned_sequences.get(table, [])
            )
    return statements


def _qualified(name: str) -> str:
    """``schema.table`` with each part quoted."""
    schema, _, table = name.partition(".")
    return f"{_quote(schema)}.{_quote(table)}"


def _quote(identifier: str) -> str:
    """Quote an identifier for DDL, which takes no bound parameters.

    The role comes from the deployment's environment, so it is held to the
    shape a role name of ours has rather than escaped and trusted.
    """
    if not identifier or not identifier.replace("_", "").isalnum():
        msg = f"refusing to interpolate unsafe identifier: {identifier!r}"
        raise UnsafeAppRoleError(msg)
    return f'"{identifier}"'
