"""An operator's default reading depth.

Revision ID: 9b1f6c2e4a87
Revises: 3efc1e04d297
Created: 2026-10-14 07:00:00+00:00

The one stored reading preference the plan allows (phase F). A reviewer at a
member bank reads every vulnerability at ``guided`` depth and should not have
to add ``?depth=guided`` to every link. It is nullable: no preference means
the page opens at ``standard``, which is what every existing operator sees
today, so no row needs a value.

The column decides a rendering and never a grant. Nothing reads it but the
depth resolver; the authorization matrix runs a principal with it set.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "9b1f6c2e4a87"
down_revision: str | None = "3efc1e04d297"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DEPTH = postgresql.ENUM("guided", "standard", "technical", name="reading_depth", create_type=False)


def upgrade() -> None:
    _DEPTH.create(op.get_bind(), checkfirst=True)
    op.add_column("operators", sa.Column("default_depth", _DEPTH, nullable=True))


def downgrade() -> None:
    op.drop_column("operators", "default_depth")
    _DEPTH.drop(op.get_bind(), checkfirst=True)
