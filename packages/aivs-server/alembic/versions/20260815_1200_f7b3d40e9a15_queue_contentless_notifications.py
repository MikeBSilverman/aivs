"""Make webhook deliveries a durable queue.

The delivery pipeline previously had no caller: a member registered an endpoint,
was handed a signing secret, and never heard anything. Wiring it up needs the
delivery row to become a *promise* rather than a record of something already
attempted, so that a process which dies before sending has still recorded the
debt and the dispatcher picks it up on restart. A crash mid-distribution is
exactly when a member most needs telling.

``payload`` carries the contentless notification body -- identifiers only, no
title, no TLP, no object content. ``next_attempt_at`` carries the backoff, and
the partial index is the dispatcher's drain query: undelivered, due, oldest
first.

Revision ID: f7b3d40e9a15
Revises: e5a92c11f7d4
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f7b3d40e9a15"
down_revision: str | None = "e5a92c11f7d4"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "webhook_deliveries",
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.add_column(
        "webhook_deliveries",
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_webhook_deliveries_pending",
        "webhook_deliveries",
        ["next_attempt_at", "id"],
        unique=False,
        postgresql_where=sa.text("delivered_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_webhook_deliveries_pending", table_name="webhook_deliveries")
    op.drop_column("webhook_deliveries", "next_attempt_at")
    op.drop_column("webhook_deliveries", "payload")
