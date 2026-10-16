"""Text documents with document-only grants (Phase I, slice I1).

Five tables. ``documents`` holds each document's metadata and its own key,
sealed under the instance key; ``document_versions`` and ``document_comments``
hold bodies sealed under that key, each bound to its row; ``document_grants``
names who may read or edit a document, until revoked or expired;
``document_reads`` is the receipt every read writes.

The member login is granted nothing on any of them (``db.grants.MEMBER_GRANTS``
lists none): SQL on the member path cannot list another firm's documents,
owners or titles. Every read and write goes through ``services.documents`` on
the staff login, keyed on the caller's grant.

Versions, comments and receipts are evidence and carry the
``aivs_deny_mutation`` triggers: a saved version is what its readers read, a
comment stays after its author's grant ends, and a receipt that could be
deleted proves nothing. Documents and grants change state (a grant is closed,
never deleted) and do not. Nothing deletes any of the five; their foreign keys
are RESTRICT.

``tlp`` reuses the existing type; ``document_state``, ``document_permission``
and ``grant_principal`` are new.

Revision ID: 4b71211c333f
Revises: 4867d88d83b5
Created: 2026-10-16 05:28:51.217238+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "4b71211c333f"
down_revision: str | None = "4867d88d83b5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATE = postgresql.ENUM(
    "draft", "in_review", "finished", "archived", name="document_state", create_type=False
)
_PRINCIPAL = postgresql.ENUM("organization", "operator", name="grant_principal", create_type=False)
_PERMISSION = postgresql.ENUM("view", "edit", name="document_permission", create_type=False)
_TLP = postgresql.ENUM(
    "clear", "green", "amber", "amber_strict", "red", name="tlp", create_type=False
)
_NEW_TYPES = (_STATE, _PRINCIPAL, _PERMISSION)
_APPEND_ONLY = ("document_versions", "document_comments", "document_reads")


def upgrade() -> None:
    for kind in _NEW_TYPES:
        kind.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "documents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_org_id", sa.Uuid(), nullable=False),
        sa.Column("author_operator_id", sa.Uuid(), nullable=False),
        sa.Column(
            "state",
            _STATE,
            nullable=False,
        ),
        sa.Column(
            "tlp",
            _TLP,
            nullable=False,
        ),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("abstract", sa.Text(), nullable=True),
        sa.Column("dek_sealed", sa.LargeBinary(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["author_operator_id"],
            ["operators.id"],
            name=op.f("fk_documents_author_operator_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["owner_org_id"],
            ["organizations.id"],
            name=op.f("fk_documents_owner_org_id"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_documents")),
    )
    op.create_index(op.f("ix_documents_owner_org_id"), "documents", ["owner_org_id"], unique=False)
    op.create_table(
        "document_comments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("body_sealed", sa.LargeBinary(), nullable=False),
        sa.Column("author_operator_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["author_operator_id"],
            ["operators.id"],
            name=op.f("fk_document_comments_author_operator_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name=op.f("fk_document_comments_document_id"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_document_comments")),
    )
    op.create_index(
        op.f("ix_document_comments_document_id"), "document_comments", ["document_id"], unique=False
    )
    op.create_table(
        "document_grants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column(
            "principal_type",
            _PRINCIPAL,
            nullable=False,
        ),
        sa.Column("principal_org_id", sa.Uuid(), nullable=True),
        sa.Column("principal_operator_id", sa.Uuid(), nullable=True),
        sa.Column(
            "permission", _PERMISSION, nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("granted_by_operator_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=80), nullable=True),
        sa.CheckConstraint(
            "(principal_type = 'organization' AND principal_org_id IS NOT NULL AND principal_operator_id IS NULL) OR (principal_type = 'operator' AND principal_operator_id IS NOT NULL AND principal_org_id IS NULL)",
            name=op.f("ck_document_grants_one_principal"),
        ),
        sa.CheckConstraint(
            "(revoked_at IS NULL) = (revoked_by IS NULL)",
            name=op.f("ck_document_grants_revocation_says_why"),
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name=op.f("fk_document_grants_document_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["granted_by_operator_id"],
            ["operators.id"],
            name=op.f("fk_document_grants_granted_by_operator_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["principal_operator_id"],
            ["operators.id"],
            name=op.f("fk_document_grants_principal_operator_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["principal_org_id"],
            ["organizations.id"],
            name=op.f("fk_document_grants_principal_org_id"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_document_grants")),
    )
    op.create_index(
        op.f("ix_document_grants_document_id"), "document_grants", ["document_id"], unique=False
    )
    op.create_index(
        op.f("ix_document_grants_principal_operator_id"),
        "document_grants",
        ["principal_operator_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_document_grants_principal_org_id"),
        "document_grants",
        ["principal_org_id"],
        unique=False,
    )
    op.create_table(
        "document_reads",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("operator_id", sa.Uuid(), nullable=True),
        sa.Column(
            "read_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name=op.f("fk_document_reads_document_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["operator_id"],
            ["operators.id"],
            name=op.f("fk_document_reads_operator_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_document_reads_org_id"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_document_reads")),
    )
    op.create_index(
        op.f("ix_document_reads_document_id"), "document_reads", ["document_id"], unique=False
    )
    op.create_table(
        "document_versions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("body_sealed", sa.LargeBinary(), nullable=False),
        sa.Column("author_operator_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["author_operator_id"],
            ["operators.id"],
            name=op.f("fk_document_versions_author_operator_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name=op.f("fk_document_versions_document_id"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_document_versions")),
        sa.UniqueConstraint("document_id", "number", name="one_number_per_document"),
    )
    op.create_index(
        op.f("ix_document_versions_document_id"), "document_versions", ["document_id"], unique=False
    )
    for table in _APPEND_ONLY:
        for operation in ("update", "delete", "truncate"):
            op.execute(
                f'CREATE TRIGGER "{table}_deny_{operation}" '
                f"BEFORE {operation.upper()} ON {table} "
                "FOR EACH STATEMENT EXECUTE FUNCTION aivs_deny_mutation();"
            )
        op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM PUBLIC;")


def downgrade() -> None:
    op.drop_index(op.f("ix_document_versions_document_id"), table_name="document_versions")
    op.drop_table("document_versions")
    op.drop_index(op.f("ix_document_reads_document_id"), table_name="document_reads")
    op.drop_table("document_reads")
    op.drop_index(op.f("ix_document_grants_principal_org_id"), table_name="document_grants")
    op.drop_index(op.f("ix_document_grants_principal_operator_id"), table_name="document_grants")
    op.drop_index(op.f("ix_document_grants_document_id"), table_name="document_grants")
    op.drop_table("document_grants")
    op.drop_index(op.f("ix_document_comments_document_id"), table_name="document_comments")
    op.drop_table("document_comments")
    op.drop_index(op.f("ix_documents_owner_org_id"), table_name="documents")
    op.drop_table("documents")
    for kind in _NEW_TYPES:
        kind.drop(op.get_bind(), checkfirst=True)
