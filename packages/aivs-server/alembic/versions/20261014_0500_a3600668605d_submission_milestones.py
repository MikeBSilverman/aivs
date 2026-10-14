"""Record which telemetry milestones a submitter has been told about.

Revision ID: a3600668605d
Revises: 5e1d7a3c9b20
Created: 2026-10-14 05:00:00+00:00

Telemetry back to the submitter announces milestones (first retrieval, 10
and 50 retrievals, first actioned) by a contentless webhook. This table is
what makes each one fire once. Operational data: no content, deleted with the
submission.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "a3600668605d"
down_revision: str | None = "5e1d7a3c9b20"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "submission_milestones",
        sa.Column("submission_id", sa.Uuid(), nullable=False),
        sa.Column("milestone", sa.String(length=40), nullable=False),
        sa.Column("reached_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name=op.f("fk_submission_milestones_submission_id_submissions"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "submission_id", "milestone", name=op.f("pk_submission_milestones")
        ),
    )


def downgrade() -> None:
    op.drop_table("submission_milestones")
