"""What a model said about each submission, in shadow (Phase O slice 4, SF-96).

``model_reads`` holds one row per first-pass read the model-assisted checks
took up: the provider and model that answered, the prompt template, the
content's most restrictive marking, and the outcome -- typed findings, none,
a reply that failed its schema, an error, or content skipped as above the
provider's ceiling or over the organisation's hourly allowance. ISAC
reviewers read it; nothing that decides does.

It is evidence, and it carries the ``aivs_deny_mutation`` triggers: it is how
a bad model release is found and its findings set aside, and how the shadow
period is evaluated against the editors' own dispositions, and a record that
can be edited afterwards proves neither. ``db.grants`` finds the triggers and
strips update, delete and truncate from the application's role; the member
login is granted nothing on it.

It holds no organisation: a row links a submission to a model's reading,
never to who filed it (Phase P). Its foreign keys are RESTRICT, which an
append-only table can afford only because nothing deletes a submission: no
path in the application deletes one, drafts included (a withdrawn or
returned one is a state), and a submission is read only once it has been
handed to the ISAC, so it already carries a ``submission_triage`` row with
the same RESTRICT key.

Revision ID: 4867d88d83b5
Revises: 3b8e5d1c7a90
Created: 2026-10-16 04:08:45.389017+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "4867d88d83b5"
down_revision: str | None = "3b8e5d1c7a90"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "model_reads",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("triage_id", sa.Uuid(), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=30), nullable=False),
        sa.Column("model_id", sa.String(length=200), nullable=False),
        sa.Column("model_reported", sa.String(length=200), nullable=True),
        sa.Column("prompt_template", sa.String(length=40), nullable=False),
        sa.Column("content_tlp", sa.String(length=20), nullable=False),
        sa.Column("outcome", sa.String(length=30), nullable=False),
        sa.Column("findings", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "outcome IN ('findings', 'no_findings', 'invalid_response', 'error', 'skipped_above_ceiling', 'skipped_rate_limited')",
            name=op.f("ck_model_reads_outcome_known"),
        ),
        sa.CheckConstraint(
            "provider IN ('local', 'private_endpoint')", name=op.f("ck_model_reads_provider_known")
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name=op.f("fk_model_reads_submission_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["triage_id"],
            ["submission_triage.id"],
            name=op.f("fk_model_reads_triage_id"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_model_reads")),
        sa.UniqueConstraint("triage_id", name=op.f("uq_model_reads_triage_id")),
    )
    op.create_index(
        op.f("ix_model_reads_submission_id"), "model_reads", ["submission_id"], unique=False
    )
    for operation in ("update", "delete", "truncate"):
        op.execute(
            f'CREATE TRIGGER "model_reads_deny_{operation}" '
            f"BEFORE {operation.upper()} ON model_reads "
            "FOR EACH STATEMENT EXECUTE FUNCTION aivs_deny_mutation();"
        )
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON model_reads FROM PUBLIC;")


def downgrade() -> None:
    op.drop_index(op.f("ix_model_reads_submission_id"), table_name="model_reads")
    op.drop_table("model_reads")
