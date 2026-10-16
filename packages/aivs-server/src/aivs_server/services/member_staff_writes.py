"""The one place a member's request writes on the staff login (Phase P, slice 3c).

The member login holds UPDATE on no column of ``organizations`` that matters
(``db.grants.MEMBER_GRANTS``). Every member organisation shares that login,
so a column it could update on its own row, SQL injected on the member path
could update on every member's: lift the quarantine or suspension the ISAC
put on a firm, quarantine a peer, or point a peer's digest at another mailbox.
Yet a member does change its own row: it quarantines itself ("we are
compromised, cut us off") and sets its notification settings. And since slice
3e, which holds the member login to nothing on ``operators``, a person sets
their own reading depth here too. Each function
here makes one such change on a staff session of its own.

Every function holds one invariant, and nothing else here makes it true:

* for a member caller it opens its own staff session, writes only the row of
  ``ctx.org_id``, records the audit row in the same transaction, commits, and
  never returns the session;
* for a caller already on the staff login (``policy.uses_staff_database``) it
  writes on that caller's own session, and the caller commits, as before.

Each goes through the service that knows the state it changes
(``services.quarantine``, ``services.member_settings``), never around it.
``tests/unit/test_staff_session_reach.py`` admits this module by name.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import NotificationCadence, ReadingDepth
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import uses_staff_database
from aivs_server.db.clock import database_now
from aivs_server.db.engine import get_sessionmaker
from aivs_server.db.models import Organization
from aivs_server.services.member_settings import (
    change_notification_settings,
    store_default_depth,
)
from aivs_server.services.org_status import load_org_for_update
from aivs_server.services.quarantine import quarantine_org

__all__ = ["quarantine_organisation", "set_notification_settings", "set_own_default_depth"]


@asynccontextmanager
async def _writer(session: AsyncSession, ctx: AuthContext) -> AsyncIterator[AsyncSession]:
    """The session to write on: the caller's own when it is staff, else a staff session.

    A staff session is committed on a clean exit and rolled back on an error;
    the caller's own is left to the caller, which commits it as it always has.
    """
    if uses_staff_database(ctx):
        yield session
        return
    async with get_sessionmaker()() as staff:
        try:
            yield staff
            await staff.commit()
        except BaseException:
            await staff.rollback()
            raise


async def quarantine_organisation(
    session: AsyncSession, ctx: AuthContext, *, org_id: uuid.UUID, reason: str
) -> Organization | None:
    """Quarantine ``org_id``; for a member, its own organisation and no other.

    ``None`` if the organisation is not found. ``QuarantineError`` as
    ``quarantine_org`` raises it. A member's ``org_id`` is ignored for its own:
    policy already admits a member only for itself (``can_quarantine_org``),
    and on the staff login that check is not the only thing keeping a peer's
    row out of reach.
    """
    async with _writer(session, ctx) as writer:
        target = org_id if uses_staff_database(ctx) else ctx.org_id
        organisation = await load_org_for_update(writer, target)
        if organisation is None:
            return None
        await quarantine_org(
            writer, ctx, organisation=organisation, reason=reason, now=await database_now(writer)
        )
        return organisation


async def set_notification_settings(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    cadence: NotificationCadence,
    digest_email: str | None,
) -> Organization | None:
    """Set the caller's own organisation's cadence and mailbox, and record it.

    ``None`` if the organisation has gone. The audit row is written with the
    change, on the same session, so the two commit together.
    """
    async with _writer(session, ctx) as writer:
        organisation = await change_notification_settings(
            writer, ctx, cadence=cadence, digest_email=digest_email
        )
        if organisation is None:
            return None
        await record(
            writer,
            action=AuditAction.NOTIFICATION_SETTINGS_SET,
            ctx=ctx,
            resource_type="organization",
            resource_id=str(organisation.id),
            details={"cadence": cadence.value, "digest_email": digest_email is not None},
        )
        return organisation


async def set_own_default_depth(
    session: AsyncSession, ctx: AuthContext, depth: ReadingDepth | None
) -> bool:
    """Store the signed-in person's reading depth; ``False`` if they or their org have gone."""
    async with _writer(session, ctx) as writer:
        return await store_default_depth(writer, ctx, depth)
