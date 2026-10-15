"""A proxy filing is marked as one, so its deadline can be absent (SF-68, Q1).

Revision ID: f4abf9218295
Revises: c6f2a9d41e7b
Created: 2026-10-15 16:00:00+00:00

Until now ``submissions.proxy_confirm_by`` did two jobs: it said a filing was
made on a member's behalf, and it said when silence confirms it. Mike's
answer to Q1 (2026-10-14) separates them: silence confirms only where the
member was sent the notice, to a webhook subscribed to it. Without one,
the filing waits for a person, and it needs a deadline of "never", which
the old column could not hold without stopping being a proxy filing.

So ``filed_on_behalf`` now marks the filing, and ``proxy_confirm_by`` is
only the deadline, NULL meaning silence never confirms. Existing proxy
filings are marked from the column they were read from, and **keep the
deadline they were given**: whether their member was notified was never
recorded, and changing a window already running would change what an
editor was told.

The downgrade refuses while any proxy filing has no deadline. Dropping the
marker would make such a filing indistinguishable from the member's own,
and it would be distributed without the confirmation it is waiting for.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f4abf9218295"
down_revision: str | None = "c6f2a9d41e7b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_submissions = sa.table(
    "submissions",
    sa.column("filed_on_behalf", sa.Boolean),
    sa.column("proxy_confirm_by", sa.DateTime(timezone=True)),
)


def upgrade() -> None:
    op.add_column(
        "submissions",
        sa.Column("filed_on_behalf", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.execute(
        sa.update(_submissions)
        .where(_submissions.c.proxy_confirm_by.is_not(None))
        .values(filed_on_behalf=True)
    )


def downgrade() -> None:
    waiting = op.get_bind().scalar(
        sa.select(sa.func.count())
        .select_from(_submissions)
        .where(_submissions.c.filed_on_behalf, _submissions.c.proxy_confirm_by.is_(None))
    )
    if waiting:
        reason = (
            f"{waiting} proxy filing(s) wait for a person with no deadline; without the "
            "marker they would read as the member's own filings and could be distributed "
            "unconfirmed. Have the members confirm or withdraw them first."
        )
        raise RuntimeError(reason)
    op.drop_column("submissions", "filed_on_behalf")
