"""Reserve the two disclosure scopes in the discovery_scope type.

Revision ID: 9ba58d0d6c69
Revises: dbf8b3e902f4
Created: 2026-10-14 01:56:07+00:00

``disclosed_third_party`` and ``coordinated_disclosure`` are added to the
Postgres enum now, and admitted by nothing: every ingest surface refuses them
exactly as it refuses an unknown value (``ACCEPTED_DISCOVERY_SCOPES``). Whether
either is legal depends on the state of the *target* vulnerability, which does
not exist as a record until Phase E; that phase adds the rule, and this type
change is already in place beneath it, so the release that starts accepting
them does not also have to alter a type that live rows use.

``ALTER TYPE ... ADD VALUE`` is not detected by autogenerate, is not compared
by ``alembic check``, and cannot be undone in PostgreSQL short of rebuilding
the type. ``tests/migrations`` asserts every enum type's labels against the
Python enum it stores, since nothing else would notice this migration missing.
The downgrade leaves the values in place: no row can hold them, because
nothing writes them.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op


revision: str = "9ba58d0d6c69"
down_revision: str | None = "dbf8b3e902f4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE discovery_scope ADD VALUE IF NOT EXISTS 'disclosed_third_party'")
    op.execute("ALTER TYPE discovery_scope ADD VALUE IF NOT EXISTS 'coordinated_disclosure'")


def downgrade() -> None:
    """Nothing to undo that Postgres can undo; see the module docstring."""
