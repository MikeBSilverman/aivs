"""Sandbox circles.

Revision ID: 6e4b1d93a2c5
Revises: 5d2a8c7e1f40
Created: 2026-10-14 09:00:00+00:00

A member verifies its TIP on day one, and the ISAC runs exercises, against
real TAXII paths with test content. That content must not count as reach in a
submitter's telemetry or as lead time in a quarterly statement, or an exercise
reads as engagement. ``is_sandbox`` marks such a circle; it is set at creation
and never changed after, and every existing circle is not one.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "6e4b1d93a2c5"
down_revision: str | None = "5d2a8c7e1f40"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "circles",
        sa.Column("is_sandbox", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("circles", "is_sandbox")
