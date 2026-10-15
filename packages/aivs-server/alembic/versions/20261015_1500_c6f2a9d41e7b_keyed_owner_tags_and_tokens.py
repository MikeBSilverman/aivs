"""Owner tags and owner tokens become HMACs under a key the database never holds (Phase P, SF-90).

Revision ID: c6f2a9d41e7b
Revises: 740334d0e829
Created: 2026-10-15 15:00:00+00:00

The member login is about to lose its read of ``attribution`` (slice 3c). The
member path still asks two questions of it, and both are now answered by a
value the application computes under the attribution key
(``auth.attribution_key``), which SQL can neither compute nor reverse:

- **"Is this submission mine?"** ``submissions.owner_tag``, an HMAC of the
  filer and the submission id. New here. Per submission, so tags cannot be
  matched to gather one firm's filings.
- **"Which owner does this version count as?"** ``stix_objects.owner_token``,
  until now a random token held in ``attribution.object_owners`` and read back
  by ingest. Now an HMAC of the owner and the STIX id, which ingest computes.
  The ISAC's stays ``'isac'``.

**Why ``attribution.object_owners`` goes.** Its only job was to remember a
random token so that ingest could find it again; a keyed token is found again
by computing it. Kept, it would be a stored copy of a computable value -- a
second description that drifts -- and because its token was its primary key
and the table is append-only by trigger, every rekey would have had to disable
the trigger that makes it evidence. "Whose token is this" is still answerable,
staff side: a version's owner is the filer of its submission.

**What protects the two columns now.** Not a deny trigger: the columns are
recomputed on a rekey. SQL cannot compute a value for a guessed owner, but it
could copy one row's value onto another. Slice 3c withholds UPDATE on both
columns from the member login; until then, the gap is recorded in
``docs/threat-model.md``.

**Needs the key when there is anything to compute.** ``AIVS_ATTRIBUTION_KEY``
or ``AIVS_ATTRIBUTION_KEY_FILE``, the same key the application is given. An
empty database needs none. Computed values name their key id, and the
application refuses to start on values under a key it does not hold.

The downgrade recreates ``object_owners`` with fresh random tokens, the shape
of ``740334d0e829``, and drops the tags.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Sequence
from pathlib import Path

import sqlalchemy as sa
from alembic import op

from aivs_server.auth.attribution_key import AttributionKey
from aivs_server.config import read_secret_file

revision: str = "c6f2a9d41e7b"
down_revision: str | None = "740334d0e829"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCHEMA = "attribution"
_KEY_VAR = "AIVS_ATTRIBUTION_KEY"
_ISAC_OWNER = "isac"


_SUBMITTERS = sa.table(
    "submitters", sa.column("submission_id"), sa.column("org_id"), schema=_SCHEMA
)
_SUBMISSIONS = sa.table("submissions", sa.column("id"), sa.column("owner_tag"))
_VERSIONS = sa.table(
    "stix_objects",
    sa.column("id"),
    sa.column("stix_id"),
    sa.column("submission_id"),
    sa.column("owner_token"),
)


def upgrade() -> None:
    op.add_column("submissions", sa.Column("owner_tag", sa.String(length=36), nullable=True))
    bind = op.get_bind()
    filers = bind.execute(sa.select(_SUBMITTERS.c.submission_id, _SUBMITTERS.c.org_id)).all()
    versions = bind.execute(
        sa.select(_VERSIONS.c.id, _VERSIONS.c.stix_id, _SUBMITTERS.c.org_id)
        .join(_SUBMITTERS, _SUBMITTERS.c.submission_id == _VERSIONS.c.submission_id)
        .where(_VERSIONS.c.owner_token != _ISAC_OWNER)
    ).all()
    if filers or versions:
        key = _key()
        _set(
            bind,
            _SUBMISSIONS,
            "owner_tag",
            [(sid, key.owner_tag(org_id, sid)) for sid, org_id in filers],
        )
        _set(
            bind,
            _VERSIONS,
            "owner_token",
            [(vid, key.owner_token(org_id, stix_id)) for vid, stix_id, org_id in versions],
        )
    op.alter_column("submissions", "owner_tag", nullable=False)
    op.drop_table("object_owners", schema=_SCHEMA)


def _key() -> AttributionKey:
    # The same two forms the application accepts; outside dev it is the file.
    key_file = os.environ.get(f"{_KEY_VAR}_FILE")
    configured = read_secret_file(Path(key_file)) if key_file else os.environ.get(_KEY_VAR)
    if not configured:
        msg = (
            f"{_KEY_VAR}_FILE must be set to run this migration: it computes every "
            "submission's owner tag and every version's owner token. Use the key "
            "the application is given (`openssl rand -base64 32`, mode 0600); a "
            "different one leaves the application refusing to start."
        )
        raise RuntimeError(msg)
    return AttributionKey(base64.b64decode(configured, validate=True))


def _set(
    bind: sa.Connection, table: sa.TableClause, column: str, rows: list[tuple[object, str]]
) -> None:
    if rows:
        bind.execute(
            sa.update(table)
            .where(table.c.id == sa.bindparam("row_id"))
            .values({column: sa.bindparam("value")}),
            [{"row_id": row_id, "value": value} for row_id, value in rows],
        )


def downgrade() -> None:
    _recreate_object_owners()
    op.drop_column("submissions", "owner_tag")


def _recreate_object_owners() -> None:
    op.create_table(
        "object_owners",
        sa.Column("owner_token", sa.String(length=36), nullable=False),
        sa.Column("stix_id", sa.String(length=100), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_object_owners_org_id"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("owner_token", name=op.f("pk_object_owners")),
        sa.UniqueConstraint("stix_id", "org_id", name="uq_object_owners_stix_id_org_id"),
        schema=_SCHEMA,
    )
    op.execute(
        f"""
        INSERT INTO {_SCHEMA}.object_owners (owner_token, stix_id, org_id)
        SELECT gen_random_uuid()::text, pairs.stix_id, pairs.org_id
        FROM (
            SELECT DISTINCT o.stix_id, f.org_id
            FROM stix_objects o
            JOIN {_SCHEMA}.submitters f ON f.submission_id = o.submission_id
            WHERE o.owner_token <> '{_ISAC_OWNER}'
        ) AS pairs
        """
    )
    op.execute(
        f"""
        UPDATE stix_objects o
        SET owner_token = w.owner_token
        FROM {_SCHEMA}.submitters f, {_SCHEMA}.object_owners w
        WHERE f.submission_id = o.submission_id
          AND w.stix_id = o.stix_id AND w.org_id = f.org_id
          AND o.owner_token <> '{_ISAC_OWNER}'
        """
    )
    for operation in ("update", "delete", "truncate"):
        op.execute(
            f'CREATE TRIGGER "object_owners_deny_{operation}" '
            f"BEFORE {operation.upper()} ON {_SCHEMA}.object_owners "
            "FOR EACH STATEMENT EXECUTE FUNCTION aivs_deny_mutation();"
        )
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {_SCHEMA}.object_owners FROM PUBLIC;")
