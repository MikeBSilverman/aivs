"""One automation organisation per instance.

Ownership (services/ownership.py) counts the automation organisation's versions
as the ISAC's, by type, so that the KEV enrichment script can version the
ISAC's canonical records. Keyed on the type, a second automation-type
organisation would be a second identity with that power -- enrolled from the
portal like any other. The admin organisation is held to one by the same kind
of index (uq_organizations_one_admin), for the same reason.

An instance that already enrolled two automation organisations fails this
upgrade, deliberately: one of them is versioning the ISAC's records without
being the ISAC's, and an operator must decide which.

The index runs in an autocommit block. Its predicate names the enum value
``automation``, which an earlier revision adds with ``ALTER TYPE ... ADD
VALUE``; migrations share one transaction here, and PostgreSQL refuses a new
enum value before the transaction that added it commits. So an instance
upgrading from before that revision -- every fresh install -- failed at this
step, while an instance that already had the value passed.

Revision ID: 219524b682c5
Revises: 3479c9a76d03
Created: 2026-10-14 07:25:15.120206+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "219524b682c5"
down_revision: str | None = "3479c9a76d03"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.create_index(
            "uq_organizations_one_automation",
            "organizations",
            ["org_type"],
            unique=True,
            postgresql_where=sa.text("org_type = 'automation'"),
        )


def downgrade() -> None:
    op.drop_index(
        "uq_organizations_one_automation",
        table_name="organizations",
        postgresql_where=sa.text("org_type = 'automation'"),
    )
