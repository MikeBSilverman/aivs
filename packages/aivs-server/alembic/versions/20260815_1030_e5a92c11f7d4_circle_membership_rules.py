"""Rule-maintained circle membership.

An ISAC maintains its communities as groups -- "the Section 9 firms", "the
GSIBs" -- and re-states them here one organisation at a time. ``Circle`` gains
``auto_member_org_types``: the organisation types whose active members belong to
the circle automatically, so enrolling a firm covers it from day one rather than
from whenever someone remembers the second step.

``CircleMembership.managed_by_rule`` marks the rows a rule created.
Reconciliation only ever adds or removes rows it owns, so an organisation an
operator named by hand is never withdrawn because a rule stopped matching it,
and one an operator deliberately removed is not quietly reinstated. That
distinction is the difference between a feature operators trust and one they
work around.

Both columns default to "no rule, nothing managed", so every existing circle
keeps behaving exactly as it does today until an operator opts one in.

Depends on ``d3f18a7c5b02``, and not incidentally: without the membership-start
bound, a rule that added an organisation would hand it the circle's entire back
catalogue.

Revision ID: e5a92c11f7d4
Revises: d3f18a7c5b02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e5a92c11f7d4"
down_revision: str | None = "d3f18a7c5b02"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "circles",
        sa.Column(
            "auto_member_org_types",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
    )
    op.add_column(
        "circle_memberships",
        sa.Column(
            "managed_by_rule",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("circle_memberships", "managed_by_rule")
    op.drop_column("circles", "auto_member_org_types")
