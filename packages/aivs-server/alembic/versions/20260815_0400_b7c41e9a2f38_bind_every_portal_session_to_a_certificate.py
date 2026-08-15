"""Bind every portal session to a certificate.

``portal_sessions.cert_fingerprint`` was nullable, and the per-request binding
check in ``auth.sessions.resolve_session`` sat inside ``if row.cert_fingerprint
is not None``. A row with a null fingerprint would therefore have resolved to a
full authenticated context with no certificate requirement at all -- the session
cookie alone would have been sufficient, from any network path able to reach the
application. That is the opposite of what the column exists for: the binding is
what makes the operator's password and the organisation's transport certificate
two independent factors rather than one.

No caller could produce such a row (``login`` refuses when the fingerprint is
absent), so this is closing the shape rather than repairing damage. Any row that
somehow exists is deleted rather than backfilled: there is no correct value to
invent, and forcing those operators to sign in again is the safe outcome.

Revision ID: b7c41e9a2f38
Revises: 0524926135d9
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision: str = "b7c41e9a2f38"
down_revision: str | None = "0524926135d9"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Unbound sessions cannot be made valid, only ended.
    op.execute("DELETE FROM portal_sessions WHERE cert_fingerprint IS NULL")
    op.alter_column(
        "portal_sessions",
        "cert_fingerprint",
        existing_type=sa.String(length=64),
        nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "portal_sessions",
        "cert_fingerprint",
        existing_type=sa.String(length=64),
        nullable=True,
    )
