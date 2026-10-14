"""Member sign-in through the ISAC's identity provider (Phase M).

Revision ID: 7c4e2a91d5b3
Revises: 4b5420343743
Created: 2026-10-14 20:00:00+00:00

Three tables change, each read in the same release:

- ``organizations.directory_object_id``: the directory group whose members
  belong to the organisation. ``services.sso`` resolves a sign-in's group
  claim through it; a group mapped to nothing grants nothing.
- ``operators``: the federated identity, issuer and subject, unique together
  and both-or-neither; and ``password_hash`` becomes nullable, because a
  member provisioned on first sign-in has no local password, and
  ``passwords.verify_password`` already refuses a missing hash.
- ``portal_sessions``: an SSO session is bound to an issuer, a subject and a
  device cookie instead of a certificate, and records the IdP's ``amr``. The
  ``exactly_one_binding`` constraint makes a session with neither binding --
  a bare cookie -- or with both unrepresentable, so each resolver can rely on
  checking only its own kind.

Downgrade refuses while SSO sessions or federated-only operators exist, because
restoring NOT NULL on ``cert_fingerprint`` and ``password_hash`` would have to
delete them.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "7c4e2a91d5b3"
down_revision: str | None = "4b5420343743"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BINDING = (
    "(cert_fingerprint IS NOT NULL AND idp_issuer IS NULL AND idp_subject IS NULL "
    "AND device_cookie_hash IS NULL) OR (cert_fingerprint IS NULL "
    "AND idp_issuer IS NOT NULL AND idp_subject IS NOT NULL "
    "AND device_cookie_hash IS NOT NULL)"
)


def _refuse_while_federated_rows_exist() -> None:
    """Restoring NOT NULL would have to delete these rows; say so instead."""
    bind = op.get_bind()
    sessions = bind.execute(
        sa.text("SELECT count(*) FROM portal_sessions WHERE cert_fingerprint IS NULL")
    ).scalar_one()
    operators = bind.execute(
        sa.text("SELECT count(*) FROM operators WHERE password_hash IS NULL")
    ).scalar_one()
    if sessions or operators:
        msg = (
            f"refusing to downgrade: {sessions} SSO session(s) and {operators} operator(s) "
            "with no local password exist. Revoke and delete the sessions, and set a "
            "password for or deactivate and remove those operators, first."
        )
        raise RuntimeError(msg)


def upgrade() -> None:
    op.add_column("organizations", sa.Column("directory_object_id", sa.String(200), nullable=True))
    op.create_unique_constraint(
        op.f("uq_organizations_directory_object_id"), "organizations", ["directory_object_id"]
    )

    op.alter_column("operators", "password_hash", existing_type=sa.Text(), nullable=True)
    op.add_column("operators", sa.Column("federated_issuer", sa.String(500), nullable=True))
    op.add_column("operators", sa.Column("federated_subject", sa.String(255), nullable=True))
    op.create_unique_constraint(
        op.f("uq_operators_federated_identity"),
        "operators",
        ["federated_issuer", "federated_subject"],
    )
    op.create_check_constraint(
        op.f("ck_operators_federated_identity_complete"),
        "operators",
        "(federated_issuer IS NULL) = (federated_subject IS NULL)",
    )

    op.alter_column(
        "portal_sessions", "cert_fingerprint", existing_type=sa.String(64), nullable=True
    )
    op.add_column("portal_sessions", sa.Column("idp_issuer", sa.String(500), nullable=True))
    op.add_column("portal_sessions", sa.Column("idp_subject", sa.String(255), nullable=True))
    op.add_column("portal_sessions", sa.Column("device_cookie_hash", sa.String(64), nullable=True))
    op.add_column(
        "portal_sessions", sa.Column("amr", postgresql.ARRAY(sa.String(40)), nullable=True)
    )
    op.create_check_constraint(
        op.f("ck_portal_sessions_exactly_one_binding"), "portal_sessions", _BINDING
    )


def downgrade() -> None:
    _refuse_while_federated_rows_exist()
    op.drop_constraint(
        op.f("ck_portal_sessions_exactly_one_binding"), "portal_sessions", type_="check"
    )
    for column in ("amr", "device_cookie_hash", "idp_subject", "idp_issuer"):
        op.drop_column("portal_sessions", column)
    op.alter_column(
        "portal_sessions", "cert_fingerprint", existing_type=sa.String(64), nullable=False
    )

    op.drop_constraint(op.f("ck_operators_federated_identity_complete"), "operators", type_="check")
    op.drop_constraint(op.f("uq_operators_federated_identity"), "operators", type_="unique")
    op.drop_column("operators", "federated_subject")
    op.drop_column("operators", "federated_issuer")
    op.alter_column("operators", "password_hash", existing_type=sa.Text(), nullable=False)

    op.drop_constraint(
        op.f("uq_organizations_directory_object_id"), "organizations", type_="unique"
    )
    op.drop_column("organizations", "directory_object_id")
