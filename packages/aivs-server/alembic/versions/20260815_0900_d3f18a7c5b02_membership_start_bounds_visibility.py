"""Bound content visibility by when each membership began.

``visible_content_clause`` had no membership-start term, so adding an
organisation to a circle granted it **every object ever distributed into that
circle** -- years of other firms' embargoed intelligence, at that circle's TLP
floor, retroactively and in a single call. "Add them to the group" reads as a
grant of participation; it must never silently be a grant of the archive.

``joined_at`` is a column of its own rather than a reading of ``created_at``.
Two reasons, and the second is why it is worth a migration:

* ``created_at`` records when a row was written and must go on meaning only
  that. This one is load-bearing for authorization, and a value two things
  depend on for different reasons is the shape that drifts.
* It has to be settable. An organisation re-added after an administrative
  mistake, or moved during a certificate rotation, must be able to keep the
  history it legitimately had; a column that always means "now" cannot express
  that, and operators would work around it by editing the database.

Existing rows are backfilled from ``created_at``, which is the best available
evidence of when each membership actually started and preserves every current
member's present visibility exactly. Only *future* additions are bounded.

Revision ID: d3f18a7c5b02
Revises: b7c41e9a2f38
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "d3f18a7c5b02"
down_revision: str | None = "b7c41e9a2f38"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "circle_memberships",
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Backfill before the NOT NULL, so no existing member loses access at the
    # moment this migration runs.
    op.execute("UPDATE circle_memberships SET joined_at = created_at WHERE joined_at IS NULL")
    op.alter_column(
        "circle_memberships",
        "joined_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.text("now()"),
    )


def downgrade() -> None:
    op.drop_column("circle_memberships", "joined_at")
