"""A posture is a VEX statement: justification, impact and action statements, products.

Phase H. A member's posture was a status and a "detection deployed" flag; a
member's regulator and its own tooling read VEX (OpenVEX / CSAF VEX), which
says *why* a product is not affected and *what is being done* where it is.
The columns are VEX's own; ``validated_at`` and ``evidence_note`` are ours,
named as such in intel-model.md.

The three checks are VEX's own rules, held by the database so the export is
always a valid VEX document whatever writes the row. A posture recorded before
the rules existed may break them: an ``affected`` row with no action
statement, or a ``not_affected`` row with neither a justification nor an
impact statement. Those rows get a statement that says exactly that, rather
than an invented reason, before the checks are added; otherwise the upgrade
would fail on the first instance with such a row.

Revision ID: d48d5088d63b
Revises: 219524b682c5
Created: 2026-10-14 12:36:37.232326+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d48d5088d63b"
down_revision: str | None = "219524b682c5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JUSTIFICATION = postgresql.ENUM(
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
    name="vex_justification",
    create_type=False,
)

#: Written into a statement the member never made, so it says so.
_NOT_STATED = "Not stated: recorded before AIVS asked for VEX statements."


def upgrade() -> None:
    bind = op.get_bind()
    _JUSTIFICATION.create(bind, checkfirst=True)
    op.add_column("org_postures", sa.Column("justification", _JUSTIFICATION, nullable=True))
    op.add_column("org_postures", sa.Column("impact_statement", sa.Text(), nullable=True))
    op.add_column("org_postures", sa.Column("action_statement", sa.Text(), nullable=True))
    op.add_column(
        "org_postures",
        sa.Column(
            "products",
            postgresql.ARRAY(sa.String(length=200)),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
    )
    op.add_column(
        "org_postures", sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("org_postures", sa.Column("evidence_note", sa.Text(), nullable=True))

    op.execute(
        sa.text(
            "UPDATE org_postures SET action_statement = :not_stated "
            "WHERE status = 'affected' AND action_statement IS NULL"
        ).bindparams(not_stated=_NOT_STATED)
    )
    op.execute(
        sa.text(
            "UPDATE org_postures SET impact_statement = :not_stated "
            "WHERE status = 'not_affected' AND justification IS NULL "
            "AND impact_statement IS NULL"
        ).bindparams(not_stated=_NOT_STATED)
    )

    op.create_check_constraint(
        op.f("ck_org_postures_affected_says_what_is_done"),
        "org_postures",
        "status <> 'affected' OR action_statement IS NOT NULL",
    )
    op.create_check_constraint(
        op.f("ck_org_postures_justification_only_when_not_affected"),
        "org_postures",
        "justification IS NULL OR status = 'not_affected'",
    )
    op.create_check_constraint(
        op.f("ck_org_postures_not_affected_says_why"),
        "org_postures",
        "status <> 'not_affected' OR justification IS NOT NULL OR impact_statement IS NOT NULL",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_org_postures_not_affected_says_why"), "org_postures", type_="check")
    op.drop_constraint(
        op.f("ck_org_postures_justification_only_when_not_affected"), "org_postures", type_="check"
    )
    op.drop_constraint(
        op.f("ck_org_postures_affected_says_what_is_done"), "org_postures", type_="check"
    )
    op.drop_column("org_postures", "evidence_note")
    op.drop_column("org_postures", "validated_at")
    op.drop_column("org_postures", "products")
    op.drop_column("org_postures", "action_statement")
    op.drop_column("org_postures", "impact_statement")
    op.drop_column("org_postures", "justification")
    _JUSTIFICATION.drop(op.get_bind(), checkfirst=True)
