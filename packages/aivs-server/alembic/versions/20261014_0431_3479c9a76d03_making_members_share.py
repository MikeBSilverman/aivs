"""Making members share: lanes, proxy filing, post-moderated circles, posture.

Revision ID: 3479c9a76d03
Revises: a6100e216de1
Created: 2026-10-14 04:31:00+00:00

Four things Phase E's contribution paths need, each read by the code that lands
with it:

- ``submissions.lane`` (``review`` | ``fast`` | ``post_moderated``): how a
  submission reached members. The hourly limit on unreviewed contributions
  counts it (SF-66). Existing rows are ``review``: nothing reached members
  any other way before this.
- ``submissions.filed_by_operator_id``, ``proxy_consent_sha256``,
  ``proxy_confirm_by``, ``proxy_confirmed_at``: an analyst filing for a member
  (SF-68). A check constraint makes a proxy filing without a consent artefact
  unrepresentable.
- ``circles.post_moderated``: an editor's choice, off by default.
- ``org_postures``: a member's private VEX status per vulnerability (SF-70).
  Data class ``operational``: deleted when a member leaves.

The enum types are created and dropped explicitly: ``add_column`` does not emit
``CREATE TYPE``, and the suite's ``create_all`` would hide that.
``tests/migrations`` checks the migrated labels against the Python enums.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "3479c9a76d03"
down_revision: str | None = "a6100e216de1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_LANE = postgresql.ENUM(
    "review", "fast", "post_moderated", name="submission_lane", create_type=False
)
_POSTURE = postgresql.ENUM(
    "not_affected",
    "affected",
    "fixed",
    "under_investigation",
    name="posture_status",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    _LANE.create(bind, checkfirst=True)
    _POSTURE.create(bind, checkfirst=True)

    op.add_column("submissions", sa.Column("lane", _LANE, server_default="review", nullable=False))
    op.add_column("submissions", sa.Column("filed_by_operator_id", sa.Uuid(), nullable=True))
    op.add_column(
        "submissions", sa.Column("proxy_consent_sha256", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "submissions", sa.Column("proxy_confirm_by", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "submissions", sa.Column("proxy_confirmed_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_foreign_key(
        op.f("fk_submissions_filed_by_operator_id"),
        "submissions",
        "operators",
        ["filed_by_operator_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        op.f("ck_submissions_proxy_filing_has_consent"),
        "submissions",
        "(filed_by_operator_id IS NULL) = (proxy_consent_sha256 IS NULL)",
    )

    op.add_column(
        "circles",
        sa.Column("post_moderated", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )

    op.create_table(
        "org_postures",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_stix_id", sa.String(length=100), nullable=False),
        sa.Column("status", _POSTURE, nullable=False),
        sa.Column(
            "detection_deployed", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("updated_by_operator_id", sa.Uuid(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_org_postures_org_id"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_operator_id"],
            ["operators.id"],
            name=op.f("fk_org_postures_updated_by_operator_id"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_org_postures")),
        sa.UniqueConstraint("org_id", "vulnerability_stix_id", name="uq_org_postures_org_vuln"),
    )
    op.create_index("ix_org_postures_vuln", "org_postures", ["vulnerability_stix_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_org_postures_vuln", table_name="org_postures")
    op.drop_table("org_postures")
    op.drop_column("circles", "post_moderated")
    op.drop_constraint(
        op.f("ck_submissions_proxy_filing_has_consent"), "submissions", type_="check"
    )
    op.drop_constraint(
        op.f("fk_submissions_filed_by_operator_id"), "submissions", type_="foreignkey"
    )
    for column in ("proxy_confirmed_at", "proxy_confirm_by", "proxy_consent_sha256"):
        op.drop_column("submissions", column)
    op.drop_column("submissions", "filed_by_operator_id")
    op.drop_column("submissions", "lane")
    bind = op.get_bind()
    _POSTURE.drop(bind, checkfirst=True)
    _LANE.drop(bind, checkfirst=True)
