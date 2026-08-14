"""Append-only enforcement for the audit trail.

Revision ID: c185fd428721
Revises: 9ee85e6a4811
Created: 2026-08-14

The audit log and the submission transition history are evidence. An AIVS
instance's value to a regulator rests on them being complete and unaltered, so
"the application only ever inserts" is not a strong enough guarantee -- it holds
only while every future code path behaves, and not at all against anyone with a
database session.

This migration enforces immutability in PostgreSQL itself, at two levels:

1. **A trigger that raises on UPDATE, DELETE, and TRUNCATE.** Declared
   ``FOR EACH STATEMENT`` rather than ``FOR EACH ROW`` so that it fires even
   when the statement matches no rows -- a probing ``DELETE FROM audit_log WHERE
   id = 1`` fails identically whether or not that row exists, and the attempt is
   an error rather than a silent no-op.

2. **Revoked privileges.** UPDATE, DELETE, and TRUNCATE are revoked from PUBLIC
   and, when ``AIVS_APP_DB_ROLE`` names the application's role, that role is
   granted only INSERT and SELECT. Belt and braces: the trigger stops the
   statement, the grant stops it being attempted.

A superuser can of course drop the trigger. That is unavoidable and is the
reason the deployment guidance has the application connect as a non-superuser
role that does not own these tables.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from alembic import op

revision: str = "c185fd428721"
down_revision: str | None = "9ee85e6a4811"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Tables that may only ever be appended to.
APPEND_ONLY_TABLES: tuple[str, ...] = ("audit_log", "submission_transitions")

#: Optional: the role the application connects as. When set, that role is
#: granted exactly the privileges it needs on these tables and nothing more.
APP_ROLE_ENV_VAR = "AIVS_APP_DB_ROLE"

_DENY_FUNCTION = """
CREATE OR REPLACE FUNCTION aivs_deny_mutation()
RETURNS trigger
LANGUAGE plpgsql
-- Pinning search_path stops a caller-controlled schema from shadowing anything
-- this function resolves.
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION
        'table % is append-only; % is not permitted', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
"""


def _quote(identifier: str) -> str:
    """Return a safely quoted SQL identifier.

    The values here are module constants rather than user input, but these
    strings are interpolated into DDL and the habit of quoting is cheaper to
    keep than to re-establish later.
    """
    if not identifier.replace("_", "").isalnum():
        msg = f"refusing to interpolate unsafe identifier: {identifier!r}"
        raise ValueError(msg)
    return f'"{identifier}"'


def upgrade() -> None:
    op.execute(_DENY_FUNCTION)

    for table in APPEND_ONLY_TABLES:
        quoted = _quote(table)
        op.execute(
            f"""
            CREATE TRIGGER {_quote(f"{table}_deny_update")}
            BEFORE UPDATE ON {quoted}
            FOR EACH STATEMENT EXECUTE FUNCTION aivs_deny_mutation();
            """
        )
        op.execute(
            f"""
            CREATE TRIGGER {_quote(f"{table}_deny_delete")}
            BEFORE DELETE ON {quoted}
            FOR EACH STATEMENT EXECUTE FUNCTION aivs_deny_mutation();
            """
        )
        op.execute(
            f"""
            CREATE TRIGGER {_quote(f"{table}_deny_truncate")}
            BEFORE TRUNCATE ON {quoted}
            FOR EACH STATEMENT EXECUTE FUNCTION aivs_deny_mutation();
            """
        )
        op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {quoted} FROM PUBLIC;")

    app_role = os.environ.get(APP_ROLE_ENV_VAR, "").strip()
    if app_role:
        role = _quote(app_role)
        for table in APPEND_ONLY_TABLES:
            quoted = _quote(table)
            op.execute(f"REVOKE ALL ON {quoted} FROM {role};")
            op.execute(f"GRANT INSERT, SELECT ON {quoted} TO {role};")
        # The sequences behind the bigserial primary keys still need to be
        # usable, or INSERT fails with a permission error at the first write.
        for table in APPEND_ONLY_TABLES:
            op.execute(f'GRANT USAGE ON SEQUENCE "{table}_id_seq" TO {role};')


def downgrade() -> None:
    for table in APPEND_ONLY_TABLES:
        quoted = _quote(table)
        for suffix in ("deny_update", "deny_delete", "deny_truncate"):
            op.execute(f'DROP TRIGGER IF EXISTS "{table}_{suffix}" ON {quoted};')
    op.execute("DROP FUNCTION IF EXISTS aivs_deny_mutation();")
