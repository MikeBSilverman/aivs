"""Loading a caller's circle memberships, for both ways of authenticating.

One function, because the mTLS path and the portal-session path each built this
map themselves, and two copies of the query that decides what a caller may read
are one edit away from deciding it differently.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Mapping

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import CircleRole
from aivs_server.auth.context import CircleGrant, MembershipInterval
from aivs_server.db.models import Circle, CircleMembership

__all__ = ["load_circle_grants"]


async def load_circle_grants(
    session: AsyncSession, org_id: uuid.UUID
) -> Mapping[uuid.UUID, CircleGrant]:
    """Return a grant for every active circle where ``org_id`` has an open interval.

    Each grant carries all of the organisation's intervals in that circle, so
    content from an earlier membership stays readable after a rejoin and the
    gap between does not. A deactivated circle grants nothing: deactivating one
    is how an operator suspends a whole community without unpicking its records.
    """
    rows = (
        (
            await session.execute(
                select(CircleMembership)
                .join(Circle, Circle.id == CircleMembership.circle_id)
                .where(CircleMembership.org_id == org_id, Circle.is_active.is_(True))
                .order_by(CircleMembership.circle_id, CircleMembership.joined_at)
            )
        )
        .scalars()
        .all()
    )

    intervals: dict[uuid.UUID, list[MembershipInterval]] = defaultdict(list)
    current_role: dict[uuid.UUID, CircleRole] = {}
    for row in rows:
        intervals[row.circle_id].append(MembershipInterval(row.joined_at, row.left_at))
        if row.left_at is None:
            current_role[row.circle_id] = row.role

    return {
        circle_id: CircleGrant(role=role, intervals=tuple(intervals[circle_id]))
        for circle_id, role in current_role.items()
    }
