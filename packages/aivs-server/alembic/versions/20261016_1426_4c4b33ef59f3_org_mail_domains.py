"""Each member's mail domains, recorded by the ISAC (Q41; threat model R30).

Revision ID: 4c4b33ef59f3
Revises: 4b71211c333f
Created: 2026-10-16 14:26:33.591989+00:00

An email address names a person to the email intake, and to the SSO link on a
first sign-in. Until now nothing said which addresses could be which
member's, so whoever could register one (an ISAC operator, or a member IdP
able to set its users' claims) decided where another firm's person's mail was
filed. Mike's answer to Q41: a domain-to-organisation mapping.

- ``domain`` is the primary key, so a domain is at most one organisation's;
  two members claiming one is for the ISAC to settle, never the server.
- The check restates the parser's output (lower case, A-labels, two or more
  labels), so a row written by hand cannot hold a form nothing compares equal.
- Nothing is seeded from existing operators' addresses: that would record as
  a member's exactly the addresses this exists to question. So on upgrade no
  organisation has a domain, the intake refuses every message and SSO links no
  new person until membership staff record them (runbook 9.7). People already
  linked by SSO sign in as before, by issuer and subject.

Operational (data inventory), deleted at offboarding so the domain can be
given to another member. The member login is granted nothing on it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "4c4b33ef59f3"
down_revision: str | None = "4b71211c333f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "org_mail_domains",
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("added_by_operator_id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'",
            name=op.f("ck_org_mail_domains_domain_format"),
        ),
        sa.ForeignKeyConstraint(
            ["added_by_operator_id"],
            ["operators.id"],
            name=op.f("fk_org_mail_domains_added_by_operator_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_org_mail_domains_org_id"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("domain", name=op.f("pk_org_mail_domains")),
    )
    op.create_index(
        op.f("ix_org_mail_domains_org_id"), "org_mail_domains", ["org_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_org_mail_domains_org_id"), table_name="org_mail_domains")
    op.drop_table("org_mail_domains")
