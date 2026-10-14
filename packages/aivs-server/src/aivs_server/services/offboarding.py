"""An organisation leaves the ISAC: what ends, what is deleted, what is kept.

Offboarding is the one status nothing reverses (``OrgStatus.OFFBOARDED``).
Every phase that adds something an organisation holds extends this module, and
its test, which is how "an offboarded member holds nothing" stays true.

- **Ended**: every certificate and portal session (the same revocation as a
  quarantine), and every open circle membership, closed as ``offboarding`` so
  no rule reopens it and the interval says why it ended.
- **Pseudonymised**: its operators. The row and its id stay, because the audit
  log names actors by id (SF-45); the email, the display name, the password and
  the second factor go. The organisation's contact email goes too. Its name
  stays: receipts and audit rows are evidence, and evidence names who it is
  about.
- **Deleted**: every row of the data inventory's ``operational`` class that is
  the member's own -- its postures, its webhooks (with their queued
  deliveries), its portal sessions and its TAXII inbox statuses. Unless a legal
  hold is set: a hold keeps the postures until it is lifted, and lifting it on
  an offboarded organisation deletes them then. ``test_offboarding`` reads the
  inventory, so a new operational table that this misses fails it.
- **Kept**: contributions, receipts, transitions, telemetry milestones and the
  audit log. They are the ISAC's record of what was shared and who received it.

Membership staff only (``policy.can_offboard_org``), never the hosting ISAC's
own organisation. Does not commit; the route commits once.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Final

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgStatus, OrgType
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import can_offboard_org, can_set_legal_hold, require
from aivs_server.db.models import (
    CircleMembership,
    EmailDelivery,
    Operator,
    Organization,
    OrgPosture,
    PendingNotice,
    PortalSession,
    TaxiiStatus,
    Webhook,
)
from aivs_server.services.circles import remove_circle_member
from aivs_server.services.quarantine import revoke_credentials

__all__ = ["OffboardingError", "lift_legal_hold", "offboard_org", "set_legal_hold"]

#: Stored in place of an operator's password hash: no Argon2 hash parses as this,
#: so verification fails rather than matching anything.
_UNUSABLE_HASH: Final[str] = "!offboarded"


class OffboardingError(ValueError):
    """The organisation cannot be offboarded as asked; the message says why."""


def _refusal(organisation: Organization) -> str | None:
    if organisation.org_type is OrgType.ADMIN:
        return "the hosting ISAC's own organisation cannot be offboarded"
    if organisation.status is OrgStatus.OFFBOARDED:
        return "this organisation has already been offboarded"
    return None


async def _pseudonymise_operators(session: AsyncSession, org_id: uuid.UUID) -> int:
    """Strip each operator of what identifies or authenticates them; keep the id."""
    operators = (
        await session.execute(select(Operator).where(Operator.org_id == org_id).with_for_update())
    ).scalars()
    count = 0
    for operator in operators:
        operator.email = f"offboarded-{operator.id}@offboarded.invalid"
        operator.display_name = "Offboarded operator"
        operator.password_hash = _UNUSABLE_HASH
        operator.totp_secret_encrypted = None
        operator.totp_enrolled_at = None
        operator.is_active = False
        count += 1
    return count


async def _close_memberships(
    session: AsyncSession, ctx: AuthContext, org_id: uuid.UUID, now: dt.datetime
) -> int:
    circle_ids = (
        await session.execute(
            select(CircleMembership.circle_id).where(
                CircleMembership.org_id == org_id, CircleMembership.left_at.is_(None)
            )
        )
    ).scalars()
    closed = 0
    for circle_id in sorted(set(circle_ids), key=str):
        if await remove_circle_member(
            session,
            ctx,
            circle_id=circle_id,
            org_id=org_id,
            now=now,
            via="offboarding",
            ended_by="offboarding",
        ):
            closed += 1
    return closed


async def _delete_operational(session: AsyncSession, organisation: Organization) -> str:
    """Delete the member's own operational data. Returns what happened to its postures."""
    for table in (Webhook, PortalSession, TaxiiStatus, PendingNotice, EmailDelivery):
        await session.execute(delete(table).where(table.org_id == organisation.id))
    if organisation.legal_hold_since is not None:
        return "retained under legal hold"
    await session.execute(delete(OrgPosture).where(OrgPosture.org_id == organisation.id))
    return "deleted"


async def offboard_org(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    organisation: Organization,
    reason: str,
    now: dt.datetime,
) -> None:
    """Offboard ``organisation``, locked by the caller. Does not commit."""
    require(can_offboard_org(ctx), "offboard_requires_isac_membership")
    refusal = _refusal(organisation)
    if refusal is not None:
        raise OffboardingError(refusal)

    organisation.status = OrgStatus.OFFBOARDED
    organisation.contact_email = None
    organisation.digest_email = None
    await session.flush()
    certificates = await revoke_credentials(session, organisation, now, reason="offboarded")
    operators = await _pseudonymise_operators(session, organisation.id)
    memberships = await _close_memberships(session, ctx, organisation.id, now)
    postures = await _delete_operational(session, organisation)
    await record(
        session,
        action=AuditAction.ORG_OFFBOARDED,
        ctx=ctx,
        resource_type="organization",
        resource_id=str(organisation.id),
        # Counts of what ended, never of the postures: how many vulnerabilities
        # a firm held a posture on is a fact about its exposure.
        details={
            "reason": reason,
            "certificates_revoked": certificates,
            "operators_pseudonymised": operators,
            "memberships_closed": memberships,
            "postures": postures,
        },
    )


async def set_legal_hold(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    organisation: Organization,
    reason: str,
    now: dt.datetime,
) -> None:
    """Place a hold, locked by the caller. Does not commit."""
    require(can_set_legal_hold(ctx), "legal_hold_requires_isac_membership")
    if organisation.legal_hold_since is not None:
        msg = "this organisation is already under a legal hold"
        raise OffboardingError(msg)
    organisation.legal_hold_since = now
    organisation.legal_hold_reason = reason
    await record(
        session,
        action=AuditAction.LEGAL_HOLD_SET,
        ctx=ctx,
        resource_type="organization",
        resource_id=str(organisation.id),
        details={"reason": reason},
    )


async def lift_legal_hold(
    session: AsyncSession, ctx: AuthContext, *, organisation: Organization, reason: str
) -> None:
    """Lift a hold, locked by the caller. Does not commit.

    On an offboarded organisation, what the hold kept is deleted now, as
    offboarding would have deleted it.
    """
    require(can_set_legal_hold(ctx), "legal_hold_requires_isac_membership")
    if organisation.legal_hold_since is None:
        msg = "this organisation is not under a legal hold"
        raise OffboardingError(msg)
    organisation.legal_hold_since = None
    organisation.legal_hold_reason = None
    postures = "kept: the organisation is still a member"
    if organisation.status is OrgStatus.OFFBOARDED:
        await session.execute(delete(OrgPosture).where(OrgPosture.org_id == organisation.id))
        postures = "deleted"
    await record(
        session,
        action=AuditAction.LEGAL_HOLD_LIFTED,
        ctx=ctx,
        resource_type="organization",
        resource_id=str(organisation.id),
        details={"reason": reason, "postures": postures},
    )
