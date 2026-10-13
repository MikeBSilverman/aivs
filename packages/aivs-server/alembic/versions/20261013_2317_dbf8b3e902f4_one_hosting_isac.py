"""One hosting ISAC per instance.

Authorization keys every ISAC power on ``org_type = 'admin'`` rather than on a
particular organisation's id, and enrolment accepted that type. A second
admin-type organisation was therefore a second ISAC: any of its operators given
an ISAC role held it, and detection alerts went to its webhooks. Enrolment now
refuses the type; this index makes "one" a property of the database, not of
every code path that creates an organisation. An instance that already holds
two fails this migration, which is the correct outcome: one of them must be
resolved by hand before the instance runs under the new rule.

Revision ID: dbf8b3e902f4
Revises: 5bd2d8339bd9
Created: 2026-10-13 23:17:26.178678+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "dbf8b3e902f4"
down_revision: str | None = "5bd2d8339bd9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "uq_organizations_one_admin",
        "organizations",
        ["org_type"],
        unique=True,
        postgresql_where=sa.text("org_type = 'admin'"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_organizations_one_admin",
        table_name="organizations",
        postgresql_where=sa.text("org_type = 'admin'"),
    )
