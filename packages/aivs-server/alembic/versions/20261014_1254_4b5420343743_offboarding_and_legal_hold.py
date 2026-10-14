"""Offboarding: a terminal organisation status, an interval closed by it, and legal hold.

Phase H. `offboarded` is a new `org_status` label; it is terminal, and the code
refuses every write of another status over it. A membership interval it closes
says so (`ended_by = 'offboarding'`) rather than reading as an operator's
removal. A legal hold (`legal_hold_since`, `legal_hold_reason`, set together or
not at all) keeps what offboarding would delete until the hold is lifted.

`ALTER TYPE ... ADD VALUE` cannot be undone in PostgreSQL; the downgrade leaves
the label, as earlier enum migrations here do, and refuses while any
organisation carries it, since the old code has no meaning for one.

Revision ID: 4b5420343743
Revises: d48d5088d63b
Created: 2026-10-14 12:54:21.690475+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "4b5420343743"
down_revision: str | None = "d48d5088d63b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE org_status ADD VALUE IF NOT EXISTS 'offboarded'")
    op.add_column(
        "organizations", sa.Column("legal_hold_since", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("organizations", sa.Column("legal_hold_reason", sa.Text(), nullable=True))
    op.create_check_constraint(
        op.f("ck_organizations_legal_hold_has_reason"),
        "organizations",
        "(legal_hold_since IS NULL) = (legal_hold_reason IS NULL)",
    )
    op.drop_constraint(
        op.f("ck_circle_memberships_ended_by_known"), "circle_memberships", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_circle_memberships_ended_by_known"),
        "circle_memberships",
        "ended_by IS NULL OR ended_by IN ('operator', 'rule', 'offboarding')",
    )


def downgrade() -> None:
    bind = op.get_bind()
    offboarded = bind.execute(
        sa.text("SELECT count(*) FROM organizations WHERE status::text = 'offboarded'")
    ).scalar_one()
    if offboarded:
        msg = "organisations are offboarded; the previous revision has no such status"
        raise RuntimeError(msg)
    op.drop_constraint(
        op.f("ck_circle_memberships_ended_by_known"), "circle_memberships", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_circle_memberships_ended_by_known"),
        "circle_memberships",
        "ended_by IS NULL OR ended_by IN ('operator', 'rule')",
    )
    op.drop_constraint(
        op.f("ck_organizations_legal_hold_has_reason"), "organizations", type_="check"
    )
    op.drop_column("organizations", "legal_hold_reason")
    op.drop_column("organizations", "legal_hold_since")
