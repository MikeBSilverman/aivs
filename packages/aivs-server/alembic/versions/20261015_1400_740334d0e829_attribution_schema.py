"""Who filed what moves to its own schema, ``attribution`` (Phase P; Mike, Q16 and Q37).

Revision ID: 740334d0e829
Revises: 14039d693865
Created: 2026-10-15 14:00:00+00:00

The submitter of a submission is ISAC-only and treated as TLP:RED. It sat in
``submissions.submitter_org_id``, in the table every member read path joins,
so a query that forgot a ``WHERE`` -- or a member path that was made to run
SQL it should not -- could read it. Moving it to a schema of its own is what
lets a database role be refused the whole of it (the member login, next
slice), which Postgres enforces whatever the query says.

``attribution.submitters`` takes the submitter and the three columns that
name or link who filed a proxy filing: the person who filed it, the analyst
who filed for the member, and the consent hash (one member's proxy filings
would share it). ``proxy_confirm_by`` stays on ``submissions``: it names
nobody, and it is what marks a proxy filing.

``stix_objects.owner_token`` keeps the read path's per-owner version
resolution -- SF-48's read-side layer -- without the owner: ``'isac'`` for the
ISAC and its automation, else a random token per *(owner, id)* held in
``attribution.object_owners``. Random, so it cannot be reversed by hashing the
few dozen organisation ids; per id, so tokens cannot be matched across ids to
gather one firm's objects.

Both new tables are append-only (the ``aivs_deny_mutation`` triggers of
``c185fd428721``): who filed something is evidence, and re-attributing a
filing after the fact is exactly what must not be possible.

The downgrade puts every column back, filled from ``attribution``, before it
drops the schema.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "740334d0e829"
down_revision: str | None = "14039d693865"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCHEMA = "attribution"
_APPEND_ONLY = ("submitters", "object_owners")
_ISAC_TYPES = "('admin', 'automation')"


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}")
    _create_submitters()
    _create_object_owners()
    _copy_filers()
    _give_every_version_an_owner_token()
    _drop_filers_from_submissions()
    _deny_mutation()


def _create_submitters() -> None:
    op.create_table(
        "submitters",
        sa.Column("submission_id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("created_by_operator_id", sa.Uuid(), nullable=True),
        sa.Column("filed_by_operator_id", sa.Uuid(), nullable=True),
        sa.Column("proxy_consent_sha256", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "(filed_by_operator_id IS NULL) = (proxy_consent_sha256 IS NULL)",
            name=op.f("ck_submitters_proxy_filing_has_consent"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by_operator_id"],
            ["operators.id"],
            name=op.f("fk_submitters_created_by_operator_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["filed_by_operator_id"],
            ["operators.id"],
            name=op.f("fk_submitters_filed_by_operator_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name=op.f("fk_submitters_org_id"), ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["submissions.id"],
            name=op.f("fk_submitters_submission_id"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("submission_id", name=op.f("pk_submitters")),
        schema=_SCHEMA,
    )
    op.create_index(
        op.f("ix_submitters_org_id"), "submitters", ["org_id"], unique=False, schema=_SCHEMA
    )


def _create_object_owners() -> None:
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


def _copy_filers() -> None:
    op.execute(
        f"""
        INSERT INTO {_SCHEMA}.submitters
            (submission_id, org_id, created_by_operator_id, filed_by_operator_id,
             proxy_consent_sha256)
        SELECT id, submitter_org_id, created_by_operator_id, filed_by_operator_id,
               proxy_consent_sha256
        FROM submissions
        """
    )


def _give_every_version_an_owner_token() -> None:
    """Every existing version gets the token ingest would have given it."""
    op.add_column("stix_objects", sa.Column("owner_token", sa.String(length=36), nullable=True))
    op.execute(
        f"""
        INSERT INTO {_SCHEMA}.object_owners (owner_token, stix_id, org_id)
        SELECT gen_random_uuid()::text, pairs.stix_id, pairs.org_id
        FROM (
            SELECT DISTINCT o.stix_id, s.submitter_org_id AS org_id
            FROM stix_objects o
            JOIN submissions s ON s.id = o.submission_id
            JOIN organizations g ON g.id = s.submitter_org_id
            WHERE g.org_type::text NOT IN {_ISAC_TYPES}
        ) AS pairs
        """
    )
    op.execute(
        f"""
        UPDATE stix_objects o
        SET owner_token = CASE
            WHEN g.org_type::text IN {_ISAC_TYPES} THEN 'isac'
            ELSE (
                SELECT w.owner_token FROM {_SCHEMA}.object_owners w
                WHERE w.stix_id = o.stix_id AND w.org_id = s.submitter_org_id
            )
        END
        FROM submissions s
        JOIN organizations g ON g.id = s.submitter_org_id
        WHERE s.id = o.submission_id
        """
    )
    op.alter_column("stix_objects", "owner_token", nullable=False)


def _drop_filers_from_submissions() -> None:
    op.drop_index(op.f("ix_submissions_org_state"), table_name="submissions")
    op.drop_index(op.f("ix_submissions_submitter_org_id"), table_name="submissions")
    op.drop_constraint(op.f("fk_submissions_submitter_org_id"), "submissions", type_="foreignkey")
    op.drop_constraint(
        op.f("fk_submissions_filed_by_operator_id"), "submissions", type_="foreignkey"
    )
    op.drop_constraint(
        op.f("fk_submissions_created_by_operator_id"), "submissions", type_="foreignkey"
    )
    op.drop_constraint(
        op.f("ck_submissions_proxy_filing_has_consent"), "submissions", type_="check"
    )
    op.drop_column("submissions", "created_by_operator_id")
    op.drop_column("submissions", "proxy_consent_sha256")
    op.drop_column("submissions", "filed_by_operator_id")
    op.drop_column("submissions", "submitter_org_id")


def _deny_mutation() -> None:
    for table in _APPEND_ONLY:
        for operation in ("update", "delete", "truncate"):
            op.execute(
                f'CREATE TRIGGER "{table}_deny_{operation}" '
                f"BEFORE {operation.upper()} ON {_SCHEMA}.{table} "
                "FOR EACH STATEMENT EXECUTE FUNCTION aivs_deny_mutation();"
            )
        op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {_SCHEMA}.{table} FROM PUBLIC;")


def downgrade() -> None:
    _restore_filers_to_submissions()
    op.drop_column("stix_objects", "owner_token")
    op.drop_table("object_owners", schema=_SCHEMA)
    op.drop_index(op.f("ix_submitters_org_id"), table_name="submitters", schema=_SCHEMA)
    op.drop_table("submitters", schema=_SCHEMA)
    op.execute(f"DROP SCHEMA {_SCHEMA}")


def _restore_filers_to_submissions() -> None:
    op.add_column("submissions", sa.Column("submitter_org_id", sa.Uuid(), nullable=True))
    op.add_column("submissions", sa.Column("filed_by_operator_id", sa.Uuid(), nullable=True))
    op.add_column(
        "submissions", sa.Column("proxy_consent_sha256", sa.String(length=64), nullable=True)
    )
    op.add_column("submissions", sa.Column("created_by_operator_id", sa.Uuid(), nullable=True))
    op.execute(
        f"""
        UPDATE submissions s
        SET submitter_org_id = f.org_id,
            created_by_operator_id = f.created_by_operator_id,
            filed_by_operator_id = f.filed_by_operator_id,
            proxy_consent_sha256 = f.proxy_consent_sha256
        FROM {_SCHEMA}.submitters f
        WHERE f.submission_id = s.id
        """
    )
    op.alter_column("submissions", "submitter_org_id", nullable=False)
    op.create_check_constraint(
        op.f("ck_submissions_proxy_filing_has_consent"),
        "submissions",
        "(filed_by_operator_id IS NULL) = (proxy_consent_sha256 IS NULL)",
    )
    op.create_foreign_key(
        op.f("fk_submissions_created_by_operator_id"),
        "submissions",
        "operators",
        ["created_by_operator_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        op.f("fk_submissions_filed_by_operator_id"),
        "submissions",
        "operators",
        ["filed_by_operator_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        op.f("fk_submissions_submitter_org_id"),
        "submissions",
        "organizations",
        ["submitter_org_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        op.f("ix_submissions_submitter_org_id"), "submissions", ["submitter_org_id"], unique=False
    )
    op.create_index(
        op.f("ix_submissions_org_state"), "submissions", ["submitter_org_id", "state"], unique=False
    )
