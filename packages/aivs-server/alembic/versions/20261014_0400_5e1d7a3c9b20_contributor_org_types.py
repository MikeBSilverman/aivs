"""Add the contributor organisation types.

Revision ID: 5e1d7a3c9b20
Revises: 9ba58d0d6c69
Created: 2026-10-14 04:00:00+00:00

Phase E opens contribution beyond members: vendors (about their own
products), researchers (under terms of contribution), the ISAC's own
automation (the KEV enrichment script), and government partners (explicit
circles only). Which of them may ever read a circle is CIRCLE_ELIGIBLE_ORG_TYPES,
enforced where membership is written.

``ALTER TYPE ... ADD VALUE`` is invisible to autogenerate and to
``alembic check``; ``tests/migrations`` compares every enum type's labels with
its Python enum, which is what notices this migration missing. PostgreSQL
cannot drop an enum value without rebuilding the type, so the downgrade leaves
them; an organisation of one of these types must be removed first by hand.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op


revision: str = "5e1d7a3c9b20"
down_revision: str | None = "9ba58d0d6c69"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NEW_TYPES = ("vendor", "researcher", "automation", "government")


def upgrade() -> None:
    for value in _NEW_TYPES:
        op.execute(f"ALTER TYPE org_type ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    """Values stay: see the module docstring."""
