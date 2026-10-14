"""An offboarded organisation's status cannot change, enforced by the database.

``OFFBOARDED`` is terminal: offboarding deleted the member's operational data
and pseudonymised its people, and a reactivated organisation would come back
without either, looking whole. Until now only the code said so
(``services.org_status._refusal``, and ``change_org_status``'s allow-list),
so any other writer of ``organizations.status`` -- a future function, a
script, an operator's hand-typed UPDATE during an incident -- could revive one
(review L2-P6).

A row trigger refuses an UPDATE that moves ``status`` away from
``offboarded``. Other columns stay writable: lifting a legal hold on an
offboarded organisation clears ``legal_hold_since``, and that must keep
working. A returning firm is enrolled again, as a new organisation.

Revision ID: 65468f627fd5
Revises: b9f1c09a8d3b
Created: 2026-10-14 22:30:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "65468f627fd5"
down_revision: str | None = "b9f1c09a8d3b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FUNCTION = """
CREATE OR REPLACE FUNCTION aivs_offboarded_is_terminal()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF OLD.status = 'offboarded' AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION 'organisation % is offboarded; its status cannot change', OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
"""


def upgrade() -> None:
    op.execute(_FUNCTION)
    op.execute(
        "CREATE TRIGGER organizations_offboarded_is_terminal "
        "BEFORE UPDATE OF status ON organizations "
        "FOR EACH ROW EXECUTE FUNCTION aivs_offboarded_is_terminal();"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER organizations_offboarded_is_terminal ON organizations;")
    op.execute("DROP FUNCTION aivs_offboarded_is_terminal();")
