"""Activating and suspending an organisation.

One implementation for the API and the portal. There were two, and neither
knew about quarantine: activating a quarantined organisation returned it to
service with no fresh certificate, no backlog decision and no reconnection
record, which is everything ``reconnect_org`` exists to require.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgStatus, OrgType
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import Organization
from aivs_server.services.circles import reconcile_circles_for_org

__all__ = ["OrgStatusError", "change_org_status", "load_org_for_update"]


class OrgStatusError(ValueError):
    """The status change is refused; the message says why and what to do instead."""


async def load_org_for_update(session: AsyncSession, org_id: uuid.UUID) -> Organization | None:
    """Load an organisation with its row locked.

    Status changes are read-modify-write. Without the lock, a suspension that
    read ``active`` overwrote a quarantine committing in between.
    """
    return await session.get(Organization, org_id, with_for_update=True)


def _refusal(organisation: Organization) -> str | None:
    if organisation.org_type is OrgType.ADMIN:
        # Suspending the hosting ISAC refuses every staff credential, and only an
        # ISAC human can reverse it: the instance would be locked out of itself.
        return (
            "the hosting ISAC's own organisation cannot be suspended or reactivated; "
            "to stop distribution, pause it instead"
        )
    if organisation.status is OrgStatus.QUARANTINED:
        return (
            "this organisation is quarantined; reconnect it, which requires a fresh "
            "certificate and a decision on the backlog"
        )
    return None


async def change_org_status(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    organisation: Organization,
    target: OrgStatus,
    via: str,
) -> list[uuid.UUID]:
    """Set ``organisation`` to active or suspended. Returns circles reconciled.

    The caller loaded it with ``load_org_for_update`` and commits once.
    """
    refusal = _refusal(organisation)
    if refusal is not None:
        raise OrgStatusError(refusal)

    previous = organisation.status
    organisation.status = target
    # Flushed before reconciling: autoflush is off, so the rule would otherwise
    # be evaluated against the status this organisation had a moment ago.
    await session.flush()
    # Activation is the point a rule can start matching, and its membership
    # starts now. Suspension touches no membership (status is refused per
    # request); the reconcile still runs, for drift from an unreconciled rule.
    touched = await reconcile_circles_for_org(session, ctx, organisation=organisation)

    await record(
        session,
        action=AuditAction.ORG_STATUS_CHANGED,
        ctx=ctx,
        resource_type="organization",
        resource_id=str(organisation.id),
        details={
            "from": previous.value,
            "to": target.value,
            "via": via,
            "circles_reconciled": [str(circle_id) for circle_id in touched],
        },
    )
    return touched
