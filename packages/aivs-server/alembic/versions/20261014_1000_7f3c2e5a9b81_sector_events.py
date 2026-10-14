"""Sector events.

Revision ID: 7f3c2e5a9b81
Revises: 6e4b1d93a2c5
Created: 2026-10-14 10:00:00+00:00

An editor pins one of the ISAC's canonical vulnerabilities while the sector
works it: it heads every entitled member's dashboard and marks every notice
about it. At most one open event per vulnerability, enforced by a partial
unique index (``alembic check`` sees it; ``tests/migrations`` need not).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7f3c2e5a9b81"
down_revision: str | None = "6e4b1d93a2c5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sector_events",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("vulnerability_stix_id", sa.String(length=100), nullable=False),
        sa.Column("opened_by_operator_id", sa.Uuid(), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_by_operator_id", sa.Uuid(), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["closed_by_operator_id"],
            ["operators.id"],
            name=op.f("fk_sector_events_closed_by_operator_id_operators"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["opened_by_operator_id"],
            ["operators.id"],
            name=op.f("fk_sector_events_opened_by_operator_id_operators"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sector_events")),
    )
    op.create_index(
        "uq_sector_events_one_open",
        "sector_events",
        ["vulnerability_stix_id"],
        unique=True,
        postgresql_where=sa.text("closed_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_sector_events_one_open",
        table_name="sector_events",
        postgresql_where=sa.text("closed_at IS NULL"),
    )
    op.drop_table("sector_events")
