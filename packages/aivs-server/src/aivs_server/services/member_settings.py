"""An organisation's own settings, written only while it is still a member.

A request authenticates and then writes; offboarding can commit in between
(``db/org_lock``). Each writer here therefore reads the organisation's status
under a lock that offboarding's ``FOR UPDATE`` waits on or makes it wait for,
and writes nothing for an organisation that has gone.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import NotificationCadence, OrgStatus, ReadingDepth
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import Operator, Organization
from aivs_server.db.org_lock import org_still_active

__all__ = ["change_notification_settings", "store_default_depth"]


async def change_notification_settings(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    cadence: NotificationCadence,
    digest_email: str | None,
) -> Organization | None:
    """Set the cadence and mailbox on ``ctx``'s organisation; ``None`` if it has gone.

    This writes the organisation's own row, so it takes that row ``FOR UPDATE``
    rather than ``org_still_active``'s share lock: two writers that each held
    the share lock and then updated the row would deadlock each other. The
    status is read under the lock all the same, so an offboarding that
    committed first is seen.
    """
    org = await session.scalar(
        select(Organization).where(Organization.id == ctx.org_id).with_for_update()
    )
    if org is None or org.status is not OrgStatus.ACTIVE:
        return None
    org.notification_cadence = cadence
    org.digest_email = digest_email
    return org


async def store_default_depth(
    session: AsyncSession, ctx: AuthContext, depth: ReadingDepth | None
) -> bool:
    """Store the signed-in person's reading depth; ``False`` if their organisation has gone."""
    if ctx.operator_id is None or not await org_still_active(session, ctx.org_id):
        return False
    operator = await session.get(Operator, ctx.operator_id)
    if operator is None:
        return False
    operator.default_depth = depth
    return True
