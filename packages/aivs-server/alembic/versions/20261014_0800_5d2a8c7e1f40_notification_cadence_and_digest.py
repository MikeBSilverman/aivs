"""Notification cadence and the contentless digest.

Revision ID: 5d2a8c7e1f40
Revises: 9b1f6c2e4a87
Created: 2026-10-14 08:00:00+00:00

A sector event is revised many times in an afternoon, and a member told once
per revision stops reading the notices. An organisation can now choose
``hourly`` or ``daily``. Its notices are held in ``pending_notices`` (one row
per subject, so versions of one advisory coalesce) and sent as one digest per
window, by webhook and, if it names a mailbox, by email
(``email_deliveries``).

Every existing organisation keeps ``immediate``, which is what it has today:
the column's server default fills it, and nothing about current delivery
changes until a member asks for a digest.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "5d2a8c7e1f40"
down_revision: str | None = "9b1f6c2e4a87"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CADENCE = postgresql.ENUM(
    "immediate", "hourly", "daily", name="notification_cadence", create_type=False
)


def upgrade() -> None:
    _CADENCE.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "organizations",
        sa.Column("notification_cadence", _CADENCE, server_default="immediate", nullable=False),
    )
    op.add_column("organizations", sa.Column("digest_email", sa.String(length=320), nullable=True))
    op.create_table(
        "pending_notices",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("subject", sa.String(length=120), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=False),
        sa.Column("collection_id", sa.Uuid(), nullable=False),
        sa.Column("visible_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("versions", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["collection_id"],
            ["taxii_collections.id"],
            name=op.f("fk_pending_notices_collection_id_taxii_collections"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_pending_notices_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name=op.f("fk_pending_notices_submission_id_submissions"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pending_notices")),
        sa.UniqueConstraint("org_id", "subject", name="uq_pending_notices_org_subject"),
    )
    op.create_table(
        "email_deliveries",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("recipient", sa.String(length=320), nullable=False),
        sa.Column("subject", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_email_deliveries_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_email_deliveries")),
    )
    op.create_index(
        op.f("ix_email_deliveries_org_id"), "email_deliveries", ["org_id"], unique=False
    )
    op.create_index(
        "ix_email_deliveries_pending",
        "email_deliveries",
        ["next_attempt_at", "id"],
        unique=False,
        postgresql_where=sa.text("delivered_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_email_deliveries_pending",
        table_name="email_deliveries",
        postgresql_where=sa.text("delivered_at IS NULL"),
    )
    op.drop_index(op.f("ix_email_deliveries_org_id"), table_name="email_deliveries")
    op.drop_table("email_deliveries")
    op.drop_table("pending_notices")
    op.drop_column("organizations", "digest_email")
    op.drop_column("organizations", "notification_cadence")
    _CADENCE.drop(op.get_bind(), checkfirst=True)
