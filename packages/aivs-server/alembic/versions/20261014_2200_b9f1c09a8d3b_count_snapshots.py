"""Published k-anonymous counts: one snapshot per subject, replaced by K changes.

Posture summaries (for ISAC reviewers) and telemetry (for a submitter) were
computed live. Suppression below K kept any one count from naming a firm, but
not two reads of it: before and after one firm's audited posture write, or
around an editor suspending one firm, the count moved by exactly that firm
(reviews R-C3 and R2-C1; Mike accepted counts up to a day old, Q6).

``count_snapshots`` holds, per subject, the basis last published: each counted
organisation's contribution. Readers derive their counts from it, and
``services.count_snapshots`` replaces it only once at least K organisations'
contributions differ. It is a table rather than a cache because what was
published must survive a restart: recomputing on start-up would publish the
live state, which is the defect.

No backfill. Every count reads as not yet published until the first run of
the publishing job after upgrade, which is at most one interval.

Revision ID: b9f1c09a8d3b
Revises: c8341c8e14a1
Created: 2026-10-14 22:08:15.564852+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b9f1c09a8d3b"
down_revision: str | None = "c8341c8e14a1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "count_snapshots",
        sa.Column("subject_kind", sa.String(length=20), nullable=False),
        sa.Column("subject_id", sa.String(length=100), nullable=False),
        sa.Column("taken_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("basis", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "subject_kind IN ('posture', 'telemetry')",
            name=op.f("ck_count_snapshots_count_subject_known"),
        ),
        sa.PrimaryKeyConstraint("subject_kind", "subject_id", name=op.f("pk_count_snapshots")),
    )


def downgrade() -> None:
    op.drop_table("count_snapshots")
