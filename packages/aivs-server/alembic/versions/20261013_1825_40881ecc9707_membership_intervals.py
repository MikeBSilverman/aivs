"""Circle membership becomes a set of intervals.

Revision ID: 40881ecc9707
Revises: a1c7e2b93d45
Created: 2026-10-13 18:25:06.071069+00:00

A membership row used to exist or not, with one ``joined_at``. Three defects
followed from that:

* Suspension deleted rule-managed rows, and reactivation re-created them with
  ``joined_at = now()``. Visibility is bounded by ``joined_at``, so a lapsed
  renewal silently cost a member years of a circle's back catalogue.
* Removing a member deleted the row, so the rule re-added any firm an operator
  had removed by hand on the next reconcile -- the opposite of what the rule's
  own documentation promised.
* A member that left and rejoined either lost its earlier history (new row) or,
  if ``joined_at`` was repaired, received what was shared while it was out.

Now a membership is an interval ``[joined_at, left_at)``. Leaving closes it and
records who closed it (``ended_by``); rejoining opens another. Suspension does
not touch memberships at all -- status is refused on every request already.

The exclusion constraint is the part that matters most and the part Alembic
cannot see: autogenerate does not detect ``ExcludeConstraint``, so it is written
here by hand and ``alembic check`` will not notice if it goes missing. A test
against the migrated database asserts it exists.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "40881ecc9707"
down_revision: str | None = "a1c7e2b93d45"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Needed to compare UUIDs for equality inside a GiST index.
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gist")

    op.add_column(
        "circle_memberships", sa.Column("left_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("circle_memberships", sa.Column("ended_by", sa.Text(), nullable=True))
    op.drop_constraint(
        op.f("uq_circle_memberships_circle_id_org_id"), "circle_memberships", type_="unique"
    )
    op.create_index(
        "uq_circle_memberships_open_interval",
        "circle_memberships",
        ["circle_id", "org_id"],
        unique=True,
        postgresql_where=sa.text("left_at IS NULL"),
    )
    op.execute(
        "ALTER TABLE circle_memberships ADD CONSTRAINT ex_circle_memberships_no_overlap "
        "EXCLUDE USING gist (circle_id WITH =, org_id WITH =, "
        "tstzrange(joined_at, left_at, '[)') WITH &&)"
    )
    op.create_check_constraint(
        op.f("ck_circle_memberships_ended_by_known"),
        "circle_memberships",
        "ended_by IS NULL OR ended_by IN ('operator', 'rule')",
    )
    op.create_check_constraint(
        op.f("ck_circle_memberships_ended_by_with_left_at"),
        "circle_memberships",
        "(left_at IS NULL) = (ended_by IS NULL)",
    )
    op.create_check_constraint(
        op.f("ck_circle_memberships_interval_ordered"),
        "circle_memberships",
        "left_at IS NULL OR left_at > joined_at",
    )


def downgrade() -> None:
    # Closed intervals have no representation in the old shape; deleting them
    # is what the old code did on removal, so that is what a downgrade does.
    op.execute("DELETE FROM circle_memberships WHERE left_at IS NOT NULL")
    op.drop_constraint(
        op.f("ck_circle_memberships_interval_ordered"), "circle_memberships", type_="check"
    )
    op.drop_constraint(
        op.f("ck_circle_memberships_ended_by_with_left_at"), "circle_memberships", type_="check"
    )
    op.drop_constraint(
        op.f("ck_circle_memberships_ended_by_known"), "circle_memberships", type_="check"
    )
    op.execute("ALTER TABLE circle_memberships DROP CONSTRAINT ex_circle_memberships_no_overlap")
    op.drop_index(
        "uq_circle_memberships_open_interval",
        table_name="circle_memberships",
        postgresql_where=sa.text("left_at IS NULL"),
    )
    op.create_unique_constraint(
        op.f("uq_circle_memberships_circle_id_org_id"),
        "circle_memberships",
        ["circle_id", "org_id"],
    )
    op.drop_column("circle_memberships", "ended_by")
    op.drop_column("circle_memberships", "left_at")
