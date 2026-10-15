"""The first pass's record, and the ``returned`` state it can send a submission to.

Revision ID: 14039d693865
Revises: 102b931e1599
Created: 2026-10-15 13:00:00+00:00

Phase O, slice 2. ``submission_triage`` holds what the first pass found each
time a submission was handed to the ISAC, keyed by that ``submitted``
transition: unique on it, so two app processes running the job cannot read
one submit twice, and a resubmission is a new transition and is read again.

``submission_state`` gains ``returned``. ``ALTER TYPE ... ADD VALUE`` is not
seen by autogenerate (CLAUDE.md section 7) and cannot be undone in
PostgreSQL, so the downgrade leaves the label: harmless with no row using it,
and the downgrade refuses while one does.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "14039d693865"
down_revision: str | None = "102b931e1599"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE submission_state ADD VALUE IF NOT EXISTS 'returned'")
    op.create_table(
        "submission_triage",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=False),
        sa.Column("transition_id", sa.BigInteger(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "disposition",
            sa.Enum("ready_for_review", "needs_changes", name="triage_disposition"),
            nullable=False,
        ),
        sa.Column("findings", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("rules_version", sa.String(length=40), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name=op.f("fk_submission_triage_submission_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["transition_id"],
            ["submission_transitions.id"],
            name=op.f("fk_submission_triage_transition_id"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_submission_triage")),
        sa.UniqueConstraint("transition_id", name=op.f("uq_submission_triage_transition_id")),
    )
    op.create_index(
        op.f("ix_submission_triage_submission_id"),
        "submission_triage",
        ["submission_id"],
        unique=False,
    )


def downgrade() -> None:
    returned = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM submissions WHERE state = 'returned'")
    )
    if returned:
        msg = f"{returned} submissions are 'returned'; resubmit or withdraw them first"
        raise RuntimeError(msg)
    op.drop_index(op.f("ix_submission_triage_submission_id"), table_name="submission_triage")
    op.drop_table("submission_triage")
    op.execute("DROP TYPE triage_disposition")
