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

from aivs_schemas.enums import CertStatus, OrgStatus, OrgType, QuarantineBacklog
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import (
    CircleMembership,
    ClientCertificate,
    Organization,
    PortalSession,
)
from aivs_server.services.circles import reconcile_circles_for_org

__all__ = [
    "QuarantineError",
    "quarantine_org",
    "quarantine_org_automatically",
    "reconnect_org",
    "revoke_credentials",
]


class QuarantineError(ValueError):
    """The quarantine or reconnection cannot be applied; the message says why."""


async def revoke_credentials(
    session: AsyncSession, organisation: Organization, now: dt.datetime, *, reason: str
) -> int:
    """Revoke every active certificate and portal session. Returns certificates revoked.

    Quarantine and offboarding both end every credential an organisation
    holds; one function, so the two cannot disagree about what that means.
    """
    revoked = await session.execute(
        update(ClientCertificate)
        .where(
            ClientCertificate.org_id == organisation.id,
            ClientCertificate.status == CertStatus.ACTIVE,
        )
        .values(status=CertStatus.REVOKED, revoked_at=now, revoked_reason=reason)
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
    certificates = await _cut_off(session, organisation, now)
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


async def quarantine_org_automatically(
    session: AsyncSession, *, organisation: Organization, rule: str, now: dt.datetime
) -> None:
    """Quarantine on a detection, when the ISAC has configured ``enforce``.

    The same cut-off as a human's, refused in the same cases, and recorded as
    the system acting on a named rule, so the audit trail never makes an
    automatic quarantine look like a decision someone took. Does not commit.
    """
    certificates = await _cut_off(session, organisation, now)
    await record(
        session,
        action=AuditAction.ORG_QUARANTINED,
        actor_type="system",
        actor_id=f"detection:{rule}",
        resource_type="organization",
        resource_id=str(organisation.id),
        details={
            "reason": f"detection {rule}, quarantine policy enforce",
            "certificates_revoked": certificates,
            "self_quarantine": False,
            "automatic": True,
        },
    )


async def _cut_off(session: AsyncSession, organisation: Organization, now: dt.datetime) -> int:
    """Refuse what may not be quarantined, else revoke everything. Returns certificates revoked."""
    if organisation.org_type is OrgType.ADMIN:
        # It would revoke every ISAC credential, and reconnection needs an ISAC
        # human: only SQL could undo it. The instance-wide stop is the pause.
        msg = (
            "the hosting ISAC's own organisation cannot be quarantined; pause distribution instead"
        )
        raise QuarantineError(msg)
    if organisation.status is not OrgStatus.ACTIVE:
        msg = (
            "only an active organisation can be quarantined; "
            f"this one is {organisation.status.value}"
        )
        raise QuarantineError(msg)
    organisation.status = OrgStatus.QUARANTINED
    organisation.quarantined_at = now
    return await revoke_credentials(session, organisation, now, reason="quarantine")


async def _has_fresh_certificate(session: AsyncSession, organisation: Organization) -> bool:
    """An active certificate registered after the quarantine began.

    "Any active one" was not enough: a registration committing while the
    quarantine's revoking UPDATE ran stayed active, and would have counted as
    fresh although it was registered on the compromised side of the line.

    Both sides are one clock, read under the organisation's row lock
    (``register_certificate`` stamps ``created_at`` with its ``now``). Comparing
    the database's transaction start with the application's clock let a
    registration's stamp land on either side of the quarantine it raced. The
    callers pass the database's clock (``db.clock``), not the application's,
    because ``quarantined_at`` is also a membership edge compared with
    ``date_added``.
    """
    found = await session.scalar(
        select(ClientCertificate.id)
        .where(
            ClientCertificate.org_id == organisation.id,
            ClientCertificate.status == CertStatus.ACTIVE,
            ClientCertificate.created_at > organisation.quarantined_at,
        )
        .limit(1)
    )
    return found is not None


async def _revoke_older_than_the_quarantine(
    session: AsyncSession, organisation: Organization, now: dt.datetime
) -> int:
    """Revoke every active certificate not registered after the quarantine began.

    Quarantine revokes only what exists when it runs. Anything active and older
    was registered on the compromised side of the line, by whatever path, and
    reconnection must not return it to service with the organisation.
    """
    revoked = await session.execute(
        update(ClientCertificate)
        .where(
            ClientCertificate.org_id == organisation.id,
            ClientCertificate.status == CertStatus.ACTIVE,
            ClientCertificate.created_at <= organisation.quarantined_at,
        )
        .values(
            status=CertStatus.REVOKED,
            revoked_at=now,
            revoked_reason="registered before the quarantine",
        )
    )
    return int(revoked.rowcount or 0)  # type: ignore[attr-defined]


async def _close_the_gap(
    session: AsyncSession, organisation: Organization, now: dt.datetime
) -> None:
    """Withhold the quarantine: no interval of this organisation may cover it.

    Every interval reaching past the quarantine's start is ended there, whether
    it is still open or was closed during the quarantine (a removal then left
    ``[joined, removed)`` covering part of the gap). Each that was open gets a
    new one from now. Membership could not be added during the quarantine, so
    an interval starting inside it is a state this code refuses to guess about.
    """
    started = organisation.quarantined_at
    if started is None:
        msg = "this organisation has no recorded quarantine start"
        raise QuarantineError(msg)
    reaching = (
        (
            await session.execute(
                select(CircleMembership).where(
                    CircleMembership.org_id == organisation.id,
                    (CircleMembership.left_at.is_(None)) | (CircleMembership.left_at > started),
                )
            )
        )
        .scalars()
        .all()
    )
    if any(row.joined_at >= started for row in reaching):
        msg = "a membership began during the quarantine; resolve it before reconnecting"
        raise QuarantineError(msg)
    reopen = [row for row in reaching if row.left_at is None]
    for row in reaching:
        row.left_at = started
        row.ended_by = "operator"
    await session.flush()
    for row in reopen:
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
    """Return a quarantined organisation to service. Does not commit.

    The caller loaded ``organisation`` with ``load_org_for_update``.
    """
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
    stale = await _revoke_older_than_the_quarantine(session, organisation, now)
    if backlog is QuarantineBacklog.NEW_INTERVAL:
        await _close_the_gap(session, organisation, now)

    quarantined_at = organisation.quarantined_at
    organisation.status = OrgStatus.ACTIVE
    organisation.quarantined_at = None
    # Flushed first: autoflush is off, and the rules must see the status and
    # any interval reopened above. Reconnection writes ``active`` as surely as
    # activation does, so a rule written during the quarantine applies now.
    await session.flush()
    touched = await reconcile_circles_for_org(session, ctx, organisation=organisation)
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
            "stale_certificates_revoked": stale,
            "circles_reconciled": [str(circle_id) for circle_id in touched],
        },
    )
