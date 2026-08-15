"""Circle membership: bulk addition, and rules that maintain themselves.

An ISAC does not think in individual firms. It thinks "the Section 9 community",
"the GSIBs" — groups it already maintains elsewhere and re-states here every time
a member joins. Two mechanisms reduce that to something an operator can live
with, and the difference between them matters:

**Bulk addition** is ergonomics. Naming thirty organisations in one call instead
of thirty is the same deliberate act, performed once. Nothing about the trust
model changes.

**Rules** are automation. ``Circle.auto_member_org_types`` says "every active
organisation of these types belongs here", and enrolling a firm of that type puts
it in the circle without anyone remembering to. That is the real win — a member
who is covered from day one rather than from whenever someone noticed — and it is
also the sharper edge, because it makes *enrolment* an access grant. Three
choices keep that edge safe:

1. **Rules are materialised, never evaluated at read time.** Reconciliation
   writes ordinary ``circle_memberships`` rows. The visibility predicate, the
   audit trail and the join-time bound all go on working exactly as they do for
   a hand-added member, and "who could see this on 3 March?" remains a query
   against stored rows rather than an attempt to reconstruct what every
   organisation's ``org_type`` used to be.

2. **Reconciliation only touches rows it owns.** ``managed_by_rule`` marks them.
   An organisation an operator added by hand is never removed because a rule
   stopped matching; one an operator deliberately removed is not quietly
   reinstated on the next pass.

3. **A new membership starts now, not at the beginning of time.**
   ``joined_at`` defaults to the moment the row is written, so a firm enrolled
   today receives what is shared from today. Without that bound, a rule would
   hand every newly enrolled organisation the circle's entire back catalogue —
   which is precisely why this module could not be written until
   ``visible_content_clause`` learned about membership start.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import CircleRole, OrgStatus
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import Circle, CircleMembership, Organization

__all__ = [
    "CircleMembershipError",
    "ReconcileResult",
    "add_circle_members",
    "reconcile_circle",
    "reconcile_circles_for_org",
    "resolve_organisations",
]


class CircleMembershipError(ValueError):
    """A membership change could not be applied as asked."""


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    """What one reconciliation pass changed."""

    added: tuple[uuid.UUID, ...] = ()
    removed: tuple[uuid.UUID, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


async def resolve_organisations(
    session: AsyncSession, *, org_ids: list[uuid.UUID], org_slugs: list[str]
) -> list[Organization]:
    """Resolve organisations named by identifier, by slug, or by both.

    Slugs are accepted because that is how the list exists in the world an
    operator is copying from — a regulator's roster, an existing
    community-of-interest sheet — and requiring them to look up thirty UUIDs
    first is how a bulk endpoint ends up unused.

    Every name must resolve. A partial application would leave the operator
    believing a group was complete when it was not, which for a distribution
    list is the failure that matters.
    """
    if not org_ids and not org_slugs:
        msg = "name at least one organisation, by org_ids or org_slugs"
        raise CircleMembershipError(msg)

    found: dict[uuid.UUID, Organization] = {}

    if org_ids:
        rows = (
            (await session.execute(select(Organization).where(Organization.id.in_(org_ids))))
            .scalars()
            .all()
        )
        found.update({org.id: org for org in rows})
        missing_ids = sorted(str(i) for i in set(org_ids) - set(found))
        if missing_ids:
            msg = f"unknown organisation id(s): {', '.join(missing_ids)}"
            raise CircleMembershipError(msg)

    if org_slugs:
        rows = (
            (await session.execute(select(Organization).where(Organization.slug.in_(org_slugs))))
            .scalars()
            .all()
        )
        by_slug = {org.slug: org for org in rows}
        missing_slugs = sorted(set(org_slugs) - set(by_slug))
        if missing_slugs:
            msg = f"unknown organisation slug(s): {', '.join(missing_slugs)}"
            raise CircleMembershipError(msg)
        found.update({org.id: org for org in by_slug.values()})

    return sorted(found.values(), key=lambda org: org.slug)


async def add_circle_members(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    circle: Circle,
    organisations: list[Organization],
    role: CircleRole,
    joined_at: dt.datetime | None = None,
) -> list[uuid.UUID]:
    """Add organisations to a circle, skipping any already in it.

    Returns the identifiers actually added. Already-a-member is not an error
    here: re-running a roster is a normal thing for an operator to do, and
    failing the whole batch on the one firm already present would train them to
    apply rosters one at a time.

    ``joined_at`` exists for restoration — an organisation re-added after an
    administrative mistake, or moved during a certificate rotation, keeps the
    history it legitimately had. It is a deliberate act with an audit record,
    because backdating it grants access to content shared before the row
    existed.
    """
    existing = set(
        (
            await session.execute(
                select(CircleMembership.org_id).where(CircleMembership.circle_id == circle.id)
            )
        )
        .scalars()
        .all()
    )

    added: list[uuid.UUID] = []
    for org in organisations:
        if org.id in existing:
            continue
        membership = CircleMembership(circle_id=circle.id, org_id=org.id, role=role)
        if joined_at is not None:
            membership.joined_at = joined_at
        session.add(membership)
        added.append(org.id)

    if added:
        await record(
            session,
            action=AuditAction.CIRCLE_MEMBER_ADDED,
            ctx=ctx,
            resource_type="circle",
            resource_id=str(circle.id),
            details={
                "org_ids": [str(org_id) for org_id in added],
                "role": role.value,
                "backdated_to": joined_at.isoformat() if joined_at else None,
            },
        )

    return added


async def reconcile_circle(
    session: AsyncSession, ctx: AuthContext | None, *, circle: Circle
) -> ReconcileResult:
    """Bring a circle's rule-managed membership in line with its rule.

    Adds every active organisation the rule matches and that is not already a
    member; removes rule-managed rows whose organisation no longer matches.
    Hand-added rows are left alone in both directions -- see the module
    docstring.

    Does not commit. The caller owns the transaction, so a reconciliation
    triggered by enrolment lands atomically with the enrolment itself.
    """
    if not circle.auto_member_org_types:
        return ReconcileResult()

    matching = set(
        (
            await session.execute(
                select(Organization.id).where(
                    Organization.org_type.in_(circle.auto_member_org_types),
                    # Only active organisations. A pending enrolment has not been
                    # accepted yet and a suspended one has been switched off;
                    # neither should be handed a circle by a rule.
                    Organization.status == OrgStatus.ACTIVE,
                )
            )
        )
        .scalars()
        .all()
    )

    current = {
        row.org_id: row.managed_by_rule
        for row in (
            await session.execute(
                select(CircleMembership.org_id, CircleMembership.managed_by_rule).where(
                    CircleMembership.circle_id == circle.id
                )
            )
        ).all()
    }

    added = sorted(matching - set(current), key=str)
    for org_id in added:
        session.add(
            CircleMembership(
                circle_id=circle.id,
                org_id=org_id,
                role=CircleRole.MEMBER,
                managed_by_rule=True,
            )
        )

    # Only rows this rule created, and only where the organisation no longer
    # qualifies. A hand-added member is not the rule's to withdraw.
    removed = sorted(
        (org_id for org_id, by_rule in current.items() if by_rule and org_id not in matching),
        key=str,
    )
    if removed:
        await session.execute(
            delete(CircleMembership).where(
                CircleMembership.circle_id == circle.id,
                CircleMembership.org_id.in_(removed),
                CircleMembership.managed_by_rule.is_(True),
            )
        )

    result = ReconcileResult(added=tuple(added), removed=tuple(removed))

    if result.changed:
        await record(
            session,
            action=AuditAction.CIRCLE_MEMBER_ADDED if added else AuditAction.CIRCLE_MEMBER_REMOVED,
            ctx=ctx,
            actor_type="system" if ctx is None else None,
            resource_type="circle",
            resource_id=str(circle.id),
            details={
                "reason": "auto_member_rule",
                "org_types": list(circle.auto_member_org_types),
                "added": [str(i) for i in added],
                "removed": [str(i) for i in removed],
            },
        )

    return result


async def reconcile_circles_for_org(
    session: AsyncSession, ctx: AuthContext | None, *, organisation: Organization
) -> list[uuid.UUID]:
    """Reconcile every rule-bearing circle after an organisation changes.

    Called when an organisation is enrolled, activated, or suspended -- the three
    events that change whether a rule matches it. Returns the circles whose
    membership moved, for the audit detail of whatever triggered it.
    """
    circles = (
        (
            await session.execute(
                select(Circle).where(
                    Circle.is_active.is_(True),
                    # cardinality(), not `!= []`: an empty ARRAY[] literal has no
                    # inferable element type, so SQLAlchemy emits an untyped
                    # `ARRAY[]` that Postgres cannot compare and the filter
                    # silently matches nothing.
                    func.cardinality(Circle.auto_member_org_types) > 0,
                )
            )
        )
        .scalars()
        .all()
    )

    touched: list[uuid.UUID] = []
    for circle in circles:
        # Reconciles the whole circle rather than just this organisation. It is
        # the same query either way, and it means any drift from a rule change
        # that was never reconciled is repaired the next time anything happens.
        result = await reconcile_circle(session, ctx, circle=circle)
        if result.changed:
            touched.append(circle.id)

    del organisation  # the trigger, not an input: the rule is evaluated over all
    return touched
