"""A circle's membership rule may admit only sector member types.

Revision ID: e778436963ef
Revises: b7e4c19d2a60

The plan says government bodies, researchers, service providers and automation
identities are never admitted to a circle by rule, and the rule could already
name the ISAC's own ``admin`` type; nothing enforced either. The request model
now refuses them and reconciliation ignores them; this check refuses them for
writes that bypass both. Any existing rule naming an ineligible type is
narrowed first, so the constraint can be added without failing on old rows --
narrowing can only remove automatic admission, never grant it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "e778436963ef"
down_revision: str | None = "b7e4c19d2a60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_ELIGIBLE = "ARRAY['crit_infra', 'gsib', 'section9']::text[]"


def upgrade() -> None:
    op.execute(
        "UPDATE circles SET auto_member_org_types = ARRAY("
        f"SELECT unnest(auto_member_org_types) INTERSECT SELECT unnest({_ELIGIBLE}))"
        f" WHERE NOT auto_member_org_types <@ {_ELIGIBLE}"
    )
    op.create_check_constraint(
        op.f("ck_circles_rule_admits_eligible_types"),
        "circles",
        f"auto_member_org_types <@ {_ELIGIBLE}",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_circles_rule_admits_eligible_types"), "circles", type_="check")
