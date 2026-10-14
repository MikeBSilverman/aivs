"""Index the intelligence extension: six columns extracted from ``raw``.

Revision ID: 1e2fc8ecb375
Revises: e43b4c18552f
Created: 2026-10-14 03:25:14.492772+00:00

``raw`` stays canonical; these columns exist so the readers that filter on them
(readiness, the default priority, intake de-duplication, the KEV script; see
``services/indexing.py``) need not open every object's JSON. Each must equal the
place in ``raw`` it is read from, for existing rows as well as new ones, or a
reader filtering on the column silently misses content stored before today. So
the three that an existing row can already carry -- an indicator's
``pattern_type`` and ``valid_until``, a vulnerability's CWE references -- are
backfilled here with the same rules the application applies at ingest. The other
three come only from extension 2.0, which no stored object can carry: its
identifier was refused until this release.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "1e2fc8ecb375"
down_revision: str | None = "e43b4c18552f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "stix_objects", sa.Column("remediation_category", sa.String(length=40), nullable=True)
    )
    op.add_column("stix_objects", sa.Column("pattern_type", sa.String(length=40), nullable=True))
    op.add_column(
        "stix_objects", sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "stix_objects", sa.Column("ssvc_exploitation", sa.String(length=10), nullable=True)
    )
    op.add_column("stix_objects", sa.Column("kev_listed", sa.Boolean(), nullable=True))
    op.add_column(
        "stix_objects", sa.Column("cwe_ids", postgresql.ARRAY(sa.String(length=20)), nullable=True)
    )
    _backfill()


#: The application's rules, in SQL: the same widths, a STIX timestamp truncated to
#: TAXII's milliseconds, CWE ids in first-seen order without repeats. A value the
#: application would leave null (too long, not a timestamp) stays null here too.
_BACKFILL_INDICATORS = """
UPDATE stix_objects
SET pattern_type = CASE
        WHEN length(raw->>'pattern_type') <= 40 THEN raw->>'pattern_type'
    END,
    valid_until = CASE
        WHEN raw->>'valid_until' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$'
        THEN date_trunc('milliseconds', (raw->>'valid_until')::timestamptz)
    END
WHERE type = 'indicator'
"""

_BACKFILL_CWE_IDS = """
WITH refs AS (
    SELECT s.id, r.value->>'external_id' AS cwe, min(r.position) AS first_seen
    FROM stix_objects AS s,
         jsonb_array_elements(s.raw->'external_references') WITH ORDINALITY AS r(value, position)
    WHERE s.type = 'vulnerability'
      AND jsonb_typeof(s.raw->'external_references') = 'array'
      AND jsonb_typeof(r.value) = 'object'
      AND r.value->>'source_name' = 'cwe'
      AND jsonb_typeof(r.value->'external_id') = 'string'
      AND length(r.value->>'external_id') <= 20
    GROUP BY s.id, r.value->>'external_id'
)
UPDATE stix_objects AS t
SET cwe_ids = agg.ids
FROM (
    SELECT id, (array_agg(cwe ORDER BY first_seen))[1:50] AS ids FROM refs GROUP BY id
) AS agg
WHERE t.id = agg.id
"""


def _backfill() -> None:
    op.execute(_BACKFILL_INDICATORS)
    op.execute(_BACKFILL_CWE_IDS)


def downgrade() -> None:
    op.drop_column("stix_objects", "cwe_ids")
    op.drop_column("stix_objects", "kev_listed")
    op.drop_column("stix_objects", "ssvc_exploitation")
    op.drop_column("stix_objects", "valid_until")
    op.drop_column("stix_objects", "pattern_type")
    op.drop_column("stix_objects", "remediation_category")
