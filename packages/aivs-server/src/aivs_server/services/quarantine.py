"""Disconnecting a member during an incident, and reconnecting it.

Quarantine is for a member whose credentials may be in someone else's hands --
a compromised collector, a stolen laptop, an intrusion in progress. It is
status, refused on every request like suspension, plus the two things
suspension does not do: every certificate and every portal session the
organisation holds is revoked, so reconnection necessarily means fresh
credentials. Memberships are not touched: quarantine protects the member and
the community; it does not change what the member is entitled to.

Reconnection is the ISAC's, never the member's own -- a member cutting itself
off needs no approval, but turning itself back on would let whoever holds its
compromised credentials do the same.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import CertStatus, OrgStatus, QuarantineBacklog
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import (
    CircleMembership,
    ClientCertificate,
    Organization,
    PortalSession,
)

__all__ = ["QuarantineError", "quarantine_org", "reconnect_org"]


class QuarantineError(ValueError):
    """The quarantine or reconnection cannot be applied; the message says why."""


async def _revoke_credentials(
    session: AsyncSession, organisation: Organization, now: dt.datetime
) -> int:
    """Revoke every active certificate and portal session. Returns certificates revoked."""
    revoked = await session.execute(
        update(ClientCertificate)
        .where(
            ClientCertificate.org_id == organisation.id,
            ClientCertificate.status == CertStatus.ACTIVE,
        )
        .values(status=CertStatus.REVOKED, revoked_at=now, revoked_reason="quarantine")
    )
    await session.execute(
        update(PortalSession)
        .where(PortalSession.org_id == organisation.id, PortalSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    return int(revoked.rowcount or 0)  # type: ignore[attr-defined]


async def quarantine_org(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    organisation: Organization,
    reason: str,
    now: dt.datetime,
) -> None:
    """Cut an organisation off now. Does not commit."""
    if organisation.status is not OrgStatus.ACTIVE:
        msg = (
            "only an active organisation can be quarantined; "
            f"this one is {organisation.status.value}"
        )
        raise QuarantineError(msg)
    organisation.status = OrgStatus.QUARANTINED
    organisation.quarantined_at = now
    certificates = await _revoke_credentials(session, organisation, now)
    await record(
        session,
        action=AuditAction.ORG_QUARANTINED,
        ctx=ctx,
        resource_type="organization",
        resource_id=str(organisation.id),
        details={
            "reason": reason,
            "certificates_revoked": certificates,
            "self_quarantine": ctx.org_id == organisation.id,
        },
    )


async def _has_fresh_certificate(session: AsyncSession, organisation: Organization) -> bool:
    """Quarantine revoked every certificate, so any active one was registered since."""
    found = await session.scalar(
        select(ClientCertificate.id)
        .where(
            ClientCertificate.org_id == organisation.id,
            ClientCertificate.status == CertStatus.ACTIVE,
        )
        .limit(1)
    )
    return found is not None


async def _close_the_gap(
    session: AsyncSession, organisation: Organization, now: dt.datetime
) -> None:
    """End each open membership at the quarantine and open a new one from now."""
    started = organisation.quarantined_at
    open_rows = (
        (
            await session.execute(
                select(CircleMembership).where(
                    CircleMembership.org_id == organisation.id,
                    CircleMembership.left_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    for row in open_rows:
        row.left_at = started if started is not None and started > row.joined_at else now
        row.ended_by = "operator"
    await session.flush()
    for row in open_rows:
        session.add(
            CircleMembership(
                circle_id=row.circle_id,
                org_id=row.org_id,
                role=row.role,
                managed_by_rule=row.managed_by_rule,
                joined_at=now,
            )
        )


async def reconnect_org(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    organisation: Organization,
    backlog: QuarantineBacklog,
    reason: str,
    now: dt.datetime,
) -> None:
    """Return a quarantined organisation to service. Does not commit."""
    if organisation.status is not OrgStatus.QUARANTINED:
        msg = "this organisation is not quarantined"
        raise QuarantineError(msg)
    if not await _has_fresh_certificate(session, organisation):
        msg = (
            "register a new certificate first: quarantine revoked every one this "
            "organisation held, and reconnecting on none would leave it unable to "
            "connect -- or, if one were reinstated, on credentials that may be compromised"
        )
        raise QuarantineError(msg)
    if backlog is QuarantineBacklog.NEW_INTERVAL:
        await _close_the_gap(session, organisation, now)

    quarantined_at = organisation.quarantined_at
    organisation.status = OrgStatus.ACTIVE
    organisation.quarantined_at = None
    await record(
        session,
        action=AuditAction.ORG_RECONNECTED,
        ctx=ctx,
        resource_type="organization",
        resource_id=str(organisation.id),
        details={
            "reason": reason,
            "backlog": backlog.value,
            "quarantined_at": quarantined_at.isoformat() if quarantined_at else None,
        },
    )
