"""The audit stream's mode, as an append-only history (Mike, Q30).

``audit_stream_modes`` records each choice between ``full`` and ``condensed``
with the writing transaction's id. The stream judges each ``audit.read`` row by
the mode in force at *its* transaction (``services.audit_stream_mode``), so a
change re-sorts nothing already served: a SIEM's cursor continues, and an
export from genesis after a change reproduces every hash exported before it.
That only holds while the history cannot be edited, so the table carries the
same ``aivs_deny_mutation`` triggers as ``audit_log``; ``db.grants`` finds them
and strips update, delete and truncate from the application's role.

No row is ``condensed``, the behaviour T10 shipped, so existing instances
change nothing on upgrade.

Revision ID: c8341c8e14a1
Revises: 5d2e8a7c41f0
Created: 2026-10-15 09:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c8341c8e14a1"
down_revision: str | None = "5d2e8a7c41f0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "audit_stream_modes"
_CURRENT_XACT_ID = "(pg_current_xact_id())::text::bigint"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("mode", sa.String(length=20), nullable=False),
        sa.Column(
            "xact_id", sa.BigInteger(), server_default=sa.text(_CURRENT_XACT_ID), nullable=False
        ),
        sa.Column(
            "changed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("changed_by_operator_id", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.CheckConstraint("mode IN ('full', 'condensed')", name=op.f("ck_audit_stream_modes_mode_known")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_stream_modes")),
    )
    op.create_index("ix_audit_stream_modes_xact", _TABLE, ["xact_id", "id"], unique=False)
    for operation in ("update", "delete", "truncate"):
        op.execute(
            f'CREATE TRIGGER "{_TABLE}_deny_{operation}" '
            f"BEFORE {operation.upper()} ON {_TABLE} "
            "FOR EACH STATEMENT EXECUTE FUNCTION aivs_deny_mutation();"
        )
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {_TABLE} FROM PUBLIC;")


def downgrade() -> None:
    op.drop_index("ix_audit_stream_modes_xact", table_name=_TABLE)
    op.drop_table(_TABLE)
