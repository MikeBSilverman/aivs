"""Operators hold a set of roles, and the ISAC's powers split four ways.

Revision ID: b7e4c19d2a60
Revises: 40881ecc9707
Created: 2026-10-13 19:00:00+00:00

Two changes that belong together.

**The split.** ``system_admin`` used to be the only ISAC role, and any machine
certificate of the admin organisation counted as one. That bundled editorial
control (validate, distribute, embargo), access grants (enrolment, rosters,
certificates) and instance operation into one power, held by whoever could
mint an admin-org certificate -- in the managed mode, the host. The editorial
and membership powers move to ``isac_editor`` and ``isac_membership``, the
review queue to ``isac_analyst``, and every one of them now requires a human
session (``auth.policy``).

**The set.** A small ISAC's three staff each wear several of those hats; a large
one keeps them apart. Which is a choice the ISAC makes by assigning roles, so an
operator holds a set. Existing rows keep exactly the role they had.

``ALTER TYPE ... ADD VALUE`` is not detected by autogenerate and cannot be
undone in PostgreSQL, so the downgrade leaves the enum values in place and only
collapses the set back to its first role.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b7e4c19d2a60"
down_revision: str | None = "40881ecc9707"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NEW_ROLES = ("isac_analyst", "isac_editor", "isac_membership")


def upgrade() -> None:
    for role in _NEW_ROLES:
        op.execute(f"ALTER TYPE operator_role ADD VALUE IF NOT EXISTS '{role}'")

    operator_role = postgresql.ENUM(name="operator_role", create_type=False)
    op.add_column("operators", sa.Column("roles", postgresql.ARRAY(operator_role), nullable=True))
    op.execute("UPDATE operators SET roles = ARRAY[role]")
    op.alter_column("operators", "roles", nullable=False)
    op.drop_column("operators", "role")


def downgrade() -> None:
    operator_role = postgresql.ENUM(name="operator_role", create_type=False)
    op.add_column(
        "operators",
        sa.Column("role", operator_role, nullable=True),
    )
    op.execute("UPDATE operators SET role = roles[1]")
    op.alter_column("operators", "role", nullable=False)
    op.drop_column("operators", "roles")
