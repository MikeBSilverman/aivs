"""The auditor role, and a commit-order-safe key for the audit and receipts streams.

Two changes, each read in the same release:

- ``operator_role`` gains ``auditor`` and ``operators`` gains
  ``role_expires_at``. An auditor holds that role alone and always has an end
  date (``ck_operators_auditor_alone_and_expiring``): an auditor who could also
  edit is reviewing itself, and one with no end date is the access nobody
  remembers to remove. Session resolution and ``policy.can_read_audit`` read
  the column.
- ``audit_log`` and ``acknowledgments`` gain ``xact_id``, the writing
  transaction's id. The auditor's stream (``services.audit_stream``), which a
  SIEM polls with a cursor, pages on ``(xact_id, id)`` and serves only rows
  below the oldest transaction still running. ``id`` alone comes from a
  sequence: a transaction holding a lower id can commit after a reader has
  passed it, and that event would never reach the SIEM -- the keyset rule
  CLAUDE.md section 5 records for ``date_added``.

The enum value is added in an autocommit block, because the check constraint
below names it and PostgreSQL refuses a new value inside the transaction that
added it (``219524b682c5`` explains the failure on a fresh install).

Existing rows get ``xact_id = 0`` from a constant default, which PostgreSQL
applies without rewriting a row: an ``UPDATE`` would meet both tables'
append-only triggers. Every existing row was committed before this revision,
so 0 sorts them correctly ahead of every later one. Only then does the default
become the current transaction's id.

Downgrade refuses while an auditor exists, because removing the column would
leave a reader of the whole audit trail with no end date. The enum value
stays: PostgreSQL cannot drop one.

Revision ID: 5d2e8a7c41f0
Revises: 7f3c2e5a9b81
Created: 2026-10-14 21:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "5d2e8a7c41f0"
down_revision: str | None = "7f3c2e5a9b81"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CURRENT_XACT_ID = "(pg_current_xact_id())::text::bigint"
_STREAMS = (("audit_log", "ix_audit_log_stream"), ("acknowledgments", "ix_acknowledgments_stream"))


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE operator_role ADD VALUE IF NOT EXISTS 'auditor'")

    op.add_column(
        "operators", sa.Column("role_expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_check_constraint(
        op.f("ck_operators_auditor_alone_and_expiring"),
        "operators",
        "NOT ('auditor' = ANY (roles)) OR (cardinality(roles) = 1 AND role_expires_at IS NOT NULL)",
    )
    for table, index in _STREAMS:
        op.add_column(
            table,
            sa.Column("xact_id", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        )
        op.alter_column(table, "xact_id", server_default=sa.text(_CURRENT_XACT_ID))
        op.create_index(index, table, ["xact_id", "id"])


def downgrade() -> None:
    auditors = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM operators WHERE 'auditor' = ANY (roles)")
    )
    if auditors:
        msg = (
            f"refusing to downgrade: {auditors} auditor operator(s) exist, and without "
            "role_expires_at their access would have no end. Deactivate them first."
        )
        raise RuntimeError(msg)
    for table, index in _STREAMS:
        op.drop_index(index, table_name=table)
        op.drop_column(table, "xact_id")
    op.drop_constraint(op.f("ck_operators_auditor_alone_and_expiring"), "operators", type_="check")
    op.drop_column("operators", "role_expires_at")
