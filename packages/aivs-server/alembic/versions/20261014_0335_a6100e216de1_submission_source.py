"""Record who filed a submission, derived from the principal.

Revision ID: a6100e216de1
Revises: 1e2fc8ecb375
Created: 2026-10-14 03:35:46.634208+00:00

``submissions.source`` is ``system`` for an automation organisation's filing and
``member`` otherwise, set from the authenticated principal when the submission is
created and never from anything the submission says about itself (SF-6). The AI
gate reads it at validate: a consequential change in a system submission needs
an editor's acknowledgement by name. Existing rows are ``member``: no automation
organisation could file before the contributor types existed.

The enum type is created and dropped explicitly: ``add_column`` does not emit
``CREATE TYPE``, and the test suite's ``create_all`` would hide that.
``tests/migrations`` checks the migrated labels against the Python enum.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a6100e216de1"
down_revision: str | None = "1e2fc8ecb375"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SOURCE = postgresql.ENUM("member", "system", name="submission_source", create_type=False)


def upgrade() -> None:
    _SOURCE.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "submissions",
        sa.Column("source", _SOURCE, server_default="member", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("submissions", "source")
    _SOURCE.drop(op.get_bind(), checkfirst=True)
