"""Sector members contribute to the circles they read.

Revision ID: 3efc1e04d297
Revises: 050718e2e6b4
Created: 2026-10-14 06:00:00+00:00

Until now every membership began as ``member``, read-only, unless an operator
named ``contributor``. Almost nobody did, so firms that could read a circle
could not post to it, and the one-click fast lane, which publishes only into
circles the member contributes to, published nowhere. The new rule is
``default_circle_role``: a sector member (G-SIB, Section 9, critical
infrastructure) contributes where it reads, and a vendor, a government body
or the ISAC's own organisation reads unless named a contributor.

This migration applies the rule to memberships that are open now, because the
rule describes the present, and only to rows still at ``member``: an
operator's explicit ``contributor`` or ``circle_admin`` is left as it is.
Closed intervals are history and keep the role they had. Vendor and government
memberships are untouched.

One audit row per circle changed records which memberships moved, as a
``system`` actor, so "why can this firm post here?" has an answer in the log
rather than only in this file. The downgrade cannot tell the rows this changed
from ones an operator later set to ``contributor`` on purpose, so it reverts
exactly the memberships the audit rows name.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "3efc1e04d297"
down_revision: str | None = "050718e2e6b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTION = "circle.member_roles_defaulted"

#: ``CONTRIBUTING_BY_DEFAULT_ORG_TYPES`` as of this revision. Spelt out rather
#: than imported, so the migration means the same thing whatever the set
#: becomes later.
SECTOR_TYPES = ["gsib", "section9", "crit_infra"]


def upgrade() -> None:
    statement = sa.text(
        """
        WITH moved AS (
            UPDATE circle_memberships AS m
               SET role = 'contributor'
              FROM organizations AS o
             WHERE o.id = m.org_id
               AND o.org_type::text = ANY(:sector_types)
               AND m.role = 'member'
               AND m.left_at IS NULL
         RETURNING m.circle_id, m.id
        )
        INSERT INTO audit_log (actor_type, action, resource_type, resource_id, outcome, details)
        SELECT 'system', :action, 'circle', circle_id::text, 'success',
               jsonb_build_object(
                   'membership_ids', jsonb_agg(id::text ORDER BY id),
                   'from', 'member',
                   'to', 'contributor',
                   'reason', 'sector members contribute to the circles they read'
               )
          FROM moved
         GROUP BY circle_id
        """
    ).bindparams(sa.bindparam("sector_types", type_=sa.ARRAY(sa.Text)), action=ACTION)
    op.execute(statement.bindparams(sector_types=SECTOR_TYPES))


def downgrade() -> None:
    statement = sa.text(
        """
        UPDATE circle_memberships
           SET role = 'member'
         WHERE role = 'contributor'
           AND id::text IN (
               SELECT jsonb_array_elements_text(details -> 'membership_ids')
                 FROM audit_log
                WHERE action = :action
           )
        """
    ).bindparams(action=ACTION)
    op.execute(statement)
