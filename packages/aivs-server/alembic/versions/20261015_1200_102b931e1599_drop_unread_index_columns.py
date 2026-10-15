"""Drop ``ssvc_exploitation`` and ``kev_listed``: two index columns nothing reads.

Revision ID: 102b931e1599
Revises: 65468f627fd5
Created: 2026-10-15 12:00:00+00:00

They were added with the other four (``1e2fc8ecb375``) for "the readers that
filter on them": the default priority and the KEV script. Neither filters. The
priority needs all four SSVC decision points of a vulnerability and reads them
from ``raw`` with the object it is assessing; the KEV script and lead time
read the whole record. So both columns were written on every ingest, held
equal to ``raw`` by a test, and consulted by nothing: a column with no caller,
which CLAUDE.md section 5 says to wire up or delete. A reader that does filter
on either brings its column back with it, with the backfill below.

The downgrade restores both, filled from extension 2.0 by the application's
rules (a string of at most 10 characters; a JSON boolean), so a rollback leaves
them equal to ``raw`` as the earlier test required.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "102b931e1599"
down_revision: str | None = "65468f627fd5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INTEL = "extension-definition--a61c713d-42f5-4e19-bffc-6870dc66d209"

_BACKFILL = f"""
UPDATE stix_objects
SET ssvc_exploitation = CASE
        WHEN jsonb_typeof(raw->'extensions'->'{_INTEL}'->'ssvc_exploitation') = 'string'
         AND length(raw->'extensions'->'{_INTEL}'->>'ssvc_exploitation') <= 10
        THEN raw->'extensions'->'{_INTEL}'->>'ssvc_exploitation'
    END,
    kev_listed = CASE
        WHEN jsonb_typeof(raw->'extensions'->'{_INTEL}'->'kev_listed') = 'boolean'
        THEN (raw->'extensions'->'{_INTEL}'->>'kev_listed')::boolean
    END
WHERE type = 'vulnerability'
"""


def upgrade() -> None:
    op.drop_column("stix_objects", "kev_listed")
    op.drop_column("stix_objects", "ssvc_exploitation")


def downgrade() -> None:
    op.add_column(
        "stix_objects", sa.Column("ssvc_exploitation", sa.String(length=10), nullable=True)
    )
    op.add_column("stix_objects", sa.Column("kev_listed", sa.Boolean(), nullable=True))
    op.execute(_BACKFILL)
