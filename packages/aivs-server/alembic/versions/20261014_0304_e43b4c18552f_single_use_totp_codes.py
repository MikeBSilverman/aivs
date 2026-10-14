"""Each TOTP code signs in once.

Revision ID: e43b4c18552f
Revises: a3600668605d
Created: 2026-10-14 03:04:26.017868+00:00

``operators.last_totp_step`` holds the time step of the last code accepted at
login; a code for that step or an earlier one is refused (RFC 6238 section
5.2). Before it, the same code signed in any number of times inside its
90-second window, so a code read over a shoulder or captured by a phishing
page could be replayed while it lasted. Null means no code has been accepted
since this column arrived, which accepts the next valid one: existing
operators are not locked out by the upgrade.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "e43b4c18552f"
down_revision: str | None = "a3600668605d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("operators", sa.Column("last_totp_step", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("operators", "last_totp_step")
