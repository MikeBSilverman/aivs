"""A finished document's report, linked from the document (Phase I, slice I3; SF-101).

Revision ID: 37c8bd044fe0
Revises: 4c4b33ef59f3
Created: 2026-10-17 12:00:00+00:00

Finishing a document files a STIX report through the ordinary pipeline. The
report carries a link to the finished body on this instance, and the route
behind that link decides who may fetch the body by who may read the report:
whoever the report was distributed to. So the route needs the report a
document's finish filed, from the server's own record and never from the
bundle. A bundle is a member's claim, and a link a member could write would
let it point readers of its own report at another firm's document.

- ``report_submission_id`` is unique: a finish files one report, and a
  second finish racing the first fails on the constraint, not on a second
  filing.
- ``finished_version_number`` is the version the report's reference hashes,
  so what the route serves is what the report says it served.
- The checks hold the link's shape for any writer, a hand-written repair
  included: both halves or neither, every finished document has one, and only
  a finished document (or one archived after finishing) does.

Existing rows need nothing. No document could be finished before this (the
transition was refused), so every row satisfies the checks with both columns
null. The member login is granted nothing on ``documents``, and that holds.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "37c8bd044fe0"
down_revision: str | None = "4c4b33ef59f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("documents", sa.Column("report_submission_id", sa.Uuid(), nullable=True))
    op.add_column("documents", sa.Column("finished_version_number", sa.Integer(), nullable=True))
    op.create_unique_constraint(
        op.f("uq_documents_report_submission_id"), "documents", ["report_submission_id"]
    )
    op.create_foreign_key(
        op.f("fk_documents_report_submission_id"),
        "documents",
        "submissions",
        ["report_submission_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        op.f("ck_documents_report_link_complete"),
        "documents",
        "(report_submission_id IS NULL) = (finished_version_number IS NULL)",
    )
    op.create_check_constraint(
        op.f("ck_documents_finished_has_report"),
        "documents",
        "state <> 'finished' OR report_submission_id IS NOT NULL",
    )
    op.create_check_constraint(
        op.f("ck_documents_report_only_once_finished"),
        "documents",
        "report_submission_id IS NULL OR state IN ('finished', 'archived')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_documents_report_only_once_finished"), "documents", type_="check")
    op.drop_constraint(op.f("ck_documents_finished_has_report"), "documents", type_="check")
    op.drop_constraint(op.f("ck_documents_report_link_complete"), "documents", type_="check")
    op.drop_constraint(op.f("fk_documents_report_submission_id"), "documents", type_="foreignkey")
    op.drop_constraint(op.f("uq_documents_report_submission_id"), "documents", type_="unique")
    op.drop_column("documents", "finished_version_number")
    op.drop_column("documents", "report_submission_id")
