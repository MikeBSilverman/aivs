"""Each message read from the email-to-draft mailbox is recorded (O, slice 3; SF-93).

Revision ID: 3b8e5d1c7a90
Revises: f4abf9218295
Created: 2026-10-15 17:00:00+00:00

Mike's answer to Q39: members email the ISAC, so AIVS reads a mailbox the
ISAC already runs and turns a message from a member's registered person into
a draft. This table is what makes that safe to run unattended:

- ``message_sha256`` is unique, so a message read twice (a run that recorded
  it and stopped before moving it, or two processes polling one mailbox) is
  filed once: the second insert waits on the index and fails;
- ``org_id`` and ``received_at`` carry the per-organisation hourly allowance;
- the checks make a row say what it means: an accepted message names its
  sender, a refused one names its reason.

It holds no content (the mailbox keeps the message, moved to a folder) and
no submission id: a second plain link between an organisation and what it
filed is what Phase P keeps out of the database. The member login is
granted nothing on it (``db.grants``: unlisted).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "3b8e5d1c7a90"
down_revision: str | None = "f4abf9218295"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "inbound_emails",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("message_sha256", sa.String(length=64), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.String(length=40), nullable=True),
        sa.Column("org_id", sa.Uuid(), nullable=True),
        sa.Column("operator_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "(outcome = 'accepted') = (reason IS NULL)",
            name=op.f("ck_inbound_emails_refusal_has_reason"),
        ),
        sa.CheckConstraint(
            "outcome <> 'accepted' OR (org_id IS NOT NULL AND operator_id IS NOT NULL)",
            name=op.f("ck_inbound_emails_accepted_has_sender"),
        ),
        sa.CheckConstraint(
            "outcome IN ('accepted', 'refused')", name=op.f("ck_inbound_emails_outcome_valid")
        ),
        sa.ForeignKeyConstraint(
            ["operator_id"],
            ["operators.id"],
            name=op.f("fk_inbound_emails_operator_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_inbound_emails_org_id"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inbound_emails")),
        sa.UniqueConstraint("message_sha256", name=op.f("uq_inbound_emails_message_sha256")),
    )
    op.create_index(
        "ix_inbound_emails_org_received", "inbound_emails", ["org_id", "received_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_inbound_emails_org_received", table_name="inbound_emails")
    op.drop_table("inbound_emails")
