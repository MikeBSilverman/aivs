"""Writing an organisation's own rows while it is still a member.

A request authenticates first and writes later. Between the two, offboarding
(or a quarantine, or a suspension) can commit: offboarding deletes the
organisation's operational rows, and a write that lands after it re-creates
one -- a webhook with its sealed secret, a posture, a portal session -- for an
organisation that has left, and nothing ever deletes it again. The foreign key
does not stop it: the row still exists.

So each writer of an organisation's own operational rows first share-locks the
organisation's row and reads its status under the lock. Offboarding holds that
row ``FOR UPDATE`` for its whole transaction, so a writer in flight waits for it
and then reads the status it committed; writers among themselves share the
lock and never wait on each other.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgStatus
from aivs_server.db.models import Organization

__all__ = ["org_still_active"]


async def org_still_active(session: AsyncSession, org_id: uuid.UUID) -> bool:
    """Share-lock ``org_id``'s row for the transaction; whether it is active under the lock."""
    status = await session.scalar(
        select(Organization.status).where(Organization.id == org_id).with_for_update(read=True)
    )
    return status is OrgStatus.ACTIVE
