"""Triage columns on submissions, and the receipt channel in the daily dedupe key.

Revision ID: 050718e2e6b4
Revises: 7c4e2a91d5b3
Created: 2026-10-14 20:10:00+00:00

Three changes, each with its reader in the same release:

- ``submissions.assignee_operator_id``: who at the ISAC has the submission.
  Set through ``PUT /api/v1/submissions/{id}/assignee``; shown in the review
  queue. ``SET NULL`` when the operator row goes, so the submission returns to
  the queue rather than the delete failing.
- ``submissions.priority``: an editor's priority, one of CISA's SSVC decisions.
  ``NULL`` means the default derived from the content's decision points, which
  is computed when shown so it follows the content (``services/priority.py``).
- ``uq_acknowledgments_daily_dedupe`` gains ``via``. A person reading a warning
  in the portal on a day the member's TAXII client already polled it was
  absorbed by the old key, so the receipt an auditor asks for -- "a person
  looked" -- was never written (SF-51).

The enum type is created explicitly: ``add_column`` does not emit ``CREATE TYPE``,
and the suite's ``create_all`` would hide that. Downgrading restores the narrower
key, which fails if a member already holds two same-day receipts for one
submission through different channels; that is the information this release
exists to keep, and the downgrade refuses rather than deleting it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "050718e2e6b4"
down_revision: str | None = "7c4e2a91d5b3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PRIORITY = postgresql.ENUM(
    "track", "track*", "attend", "act", name="ssvc_priority", create_type=False
)
_DEDUPE = "uq_acknowledgments_daily_dedupe"


def upgrade() -> None:
    op.drop_constraint(_DEDUPE, "acknowledgments", type_="unique")
    op.create_unique_constraint(
        _DEDUPE, "acknowledgments", ["org_id", "submission_id", "ack_type", "via", "dedupe_day"]
    )
    _PRIORITY.create(op.get_bind(), checkfirst=True)
    op.add_column("submissions", sa.Column("assignee_operator_id", sa.Uuid(), nullable=True))
    op.add_column("submissions", sa.Column("priority", _PRIORITY, nullable=True))
    op.create_foreign_key(
        "fk_submissions_assignee_operator_id",
        "submissions",
        "operators",
        ["assignee_operator_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_submissions_assignee_operator_id", "submissions", type_="foreignkey")
    op.drop_column("submissions", "priority")
    op.drop_column("submissions", "assignee_operator_id")
    _PRIORITY.drop(op.get_bind(), checkfirst=True)
    op.drop_constraint(_DEDUPE, "acknowledgments", type_="unique")
    op.create_unique_constraint(
        _DEDUPE, "acknowledgments", ["org_id", "submission_id", "ack_type", "dedupe_day"]
    )
