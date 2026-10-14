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

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import (
    CIRCLE_ELIGIBLE_ORG_TYPES,
    RULE_ELIGIBLE_ORG_TYPES,
    CircleRole,
    OrgStatus,
)
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import Circle, CircleMembership, Organization

__all__ = [
    "CircleMembershipError",
    "MembershipStartRefusedError",
    "ReconcileResult",
    "add_circle_members",
    "reconcile_circle",
    "reconcile_circles_for_org",
    "remove_circle_member",
    "resolve_organisations",
]


class CircleMembershipError(ValueError):
    """A membership change could not be applied as asked."""


class MembershipStartRefusedError(CircleMembershipError):
    """A ``joined_at`` would hand over a period the organisation was out of the circle."""


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


async def _open_memberships(
    session: AsyncSession, circle_id: uuid.UUID
) -> dict[uuid.UUID, CircleMembership]:
    """Return each organisation's open membership interval in a circle."""
    rows = (
        (
            await session.execute(
                select(CircleMembership).where(
                    CircleMembership.circle_id == circle_id,
                    CircleMembership.left_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    return {row.org_id: row for row in rows}


def _refuse_unsafe_additions(
    organisations: list[Organization], joined_at: dt.datetime | None, now: dt.datetime
) -> None:
    if joined_at is not None and joined_at > now:
        msg = "a membership cannot start in the future"
        raise CircleMembershipError(msg)
    ineligible = sorted(
        org.slug for org in organisations if org.org_type not in CIRCLE_ELIGIBLE_ORG_TYPES
    )
    if ineligible:
        msg = (
            "these organisations contribute but never read a circle, so cannot be "
            f"members: {', '.join(ineligible)}"
        )
        raise CircleMembershipError(msg)
    quarantined = sorted(org.slug for org in organisations if org.status is OrgStatus.QUARANTINED)
    if quarantined:
        msg = f"quarantined organisations cannot change membership: {', '.join(quarantined)}"
        raise CircleMembershipError(msg)


async def _orgs_that_have_left(
    session: AsyncSession, circle_id: uuid.UUID, org_ids: list[uuid.UUID]
) -> set[uuid.UUID]:
    """The organisations among ``org_ids`` with a closed interval in this circle."""
    return set(
        (
            await session.execute(
                select(CircleMembership.org_id).where(
                    CircleMembership.circle_id == circle_id,
                    CircleMembership.org_id.in_(org_ids),
                    CircleMembership.left_at.is_not(None),
                )
            )
        )
        .scalars()
        .all()
    )


def _reaches_into_a_gap(
    current: CircleMembership | None, joined_at: dt.datetime, now: dt.datetime
) -> bool:
    """Whether ``joined_at`` starts the open interval earlier than it would otherwise.

    Asked only of an organisation that has left the circle before, whose every
    earlier interval ended at or before the open one's start (or ``now``, for
    one about to be opened). Anything earlier than that start is the gap.
    """
    start_otherwise = now if current is None else current.joined_at
    return joined_at < start_otherwise


async def _refuse_starts_in_a_gap(
    session: AsyncSession,
    circle_id: uuid.UUID,
    existing: dict[uuid.UUID, CircleMembership],
    organisations: list[Organization],
    joined_at: dt.datetime,
    now: dt.datetime,
) -> None:
    """Refuse a start moved earlier for an organisation that has left this circle before.

    The exclusion constraint refuses only an overlap, so a start moved back to
    the instant an earlier interval ended passed it and handed over the gap --
    including what a "new interval" reconnection deliberately withheld from a
    quarantined member. Nothing records why an interval closed (a removal and a
    quarantine both write ``operator``), so every gap is refused: the earlier
    interval's content is kept whatever happens, and only the gap is lost.
    """
    left_before = await _orgs_that_have_left(session, circle_id, [org.id for org in organisations])
    refused = sorted(
        org.slug
        for org in organisations
        if org.id in left_before and _reaches_into_a_gap(existing.get(org.id), joined_at, now)
    )
    if refused:
        msg = (
            "a membership start cannot move earlier for an organisation that has left "
            f"this circle before; that would hand over the gap: {', '.join(refused)}"
        )
        raise MembershipStartRefusedError(msg)


async def _lock_circle(session: AsyncSession, circle_id: uuid.UUID) -> None:
    """Serialise every membership change to one circle.

    Add, remove and reconcile each read the open intervals and then write. Run
    side by side they interleaved: an add reported "already belonged" for a
    member just removed, a joined_at repair landed on an interval just closed,
    and two reconciles inserted the same rule row, the second failing as a 500.
    """
    await session.execute(select(Circle.id).where(Circle.id == circle_id).with_for_update())


async def add_circle_members(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    circle: Circle,
    organisations: list[Organization],
    role: CircleRole,
    joined_at: dt.datetime | None,
    now: dt.datetime,
) -> list[uuid.UUID]:
    """Open a membership interval for each organisation not already in the circle.

    Returns the identifiers actually added. Already-a-member is not an error:
    re-running a roster is a normal thing for an operator to do, and failing the
    whole batch on the one firm already present would train them to apply
    rosters one at a time.

    ``joined_at`` is the audited repair for an administrative mistake: it sets
    the start of the *open* interval, for new members and existing ones alike.
    It used to be ignored for an organisation already present -- the skip ran
    first -- so the one repair the docs described could not reach the case it
    existed for. Backdating grants access to content shared before the row was
    written, which is why it is recorded. For an organisation that has left the
    circle before, a start may not move earlier at all: the exclusion
    constraint refuses only an overlap with the earlier interval, and the gap
    between the two is what a removal or a quarantine withheld.

    Refused for a quarantined organisation: a membership opened during the
    quarantine lies wholly inside the gap a "new interval" reconnection must
    withhold. Refused for a future ``joined_at``, which grants nothing until
    then and cannot be closed before it starts.
    """
    _refuse_unsafe_additions(organisations, joined_at, now)
    await _lock_circle(session, circle.id)
    existing = await _open_memberships(session, circle.id)
    if joined_at is not None:
        await _refuse_starts_in_a_gap(session, circle.id, existing, organisations, joined_at, now)

    added: list[uuid.UUID] = []
    repaired: list[uuid.UUID] = []
    for org in organisations:
        current = existing.get(org.id)
        if current is None:
            membership = CircleMembership(circle_id=circle.id, org_id=org.id, role=role)
            if joined_at is not None:
                membership.joined_at = joined_at
            session.add(membership)
            added.append(org.id)
        elif joined_at is not None and current.joined_at != joined_at:
            current.joined_at = joined_at
            repaired.append(org.id)

    if added or repaired:
        await record(
            session,
            action=AuditAction.CIRCLE_MEMBER_ADDED,
            ctx=ctx,
            resource_type="circle",
            resource_id=str(circle.id),
            details={
                "org_ids": [str(org_id) for org_id in added],
                "joined_at_repaired": [str(org_id) for org_id in repaired],
                "role": role.value,
                "backdated_to": joined_at.isoformat() if joined_at else None,
            },
        )

    return added


async def remove_circle_member(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    circle_id: uuid.UUID,
    org_id: uuid.UUID,
    now: dt.datetime,
    via: str,
) -> bool:
    """Close an organisation's open membership interval. Returns whether one was open.

    Closed, never deleted. Content they collected is theirs and their receipts
    outlive the membership; if they rejoin, the new interval starts then, so the
    gap stays unreadable while the earlier interval's content does not vanish.
    Recorded as an operator's act, which the rule will not undo.
    """
    await _lock_circle(session, circle_id)
    membership = (
        await session.execute(
            select(CircleMembership)
            .where(
                CircleMembership.circle_id == circle_id,
                CircleMembership.org_id == org_id,
                CircleMembership.left_at.is_(None),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if membership is None:
        return False

    membership.left_at = now
    membership.ended_by = "operator"
    await record(
        session,
        action=AuditAction.CIRCLE_MEMBER_REMOVED,
        ctx=ctx,
        resource_type="circle",
        resource_id=str(circle_id),
        details={"org_id": str(org_id), "via": via},
    )
    return True


def _eligible_rule_types(circle: Circle) -> list[str]:
    """The rule's types, intersected with the ones a rule may ever admit.

    The request model and a database check already refuse anything else; this
    is the guard at the point of use, so a row that predates both cannot hand
    the ISAC's own organisation -- or anyone added by name only -- a circle.
    """
    eligible = {org_type.value for org_type in RULE_ELIGIBLE_ORG_TYPES}
    return sorted(set(circle.auto_member_org_types) & eligible)


async def _orgs_matching_rule(session: AsyncSession, circle: Circle) -> set[uuid.UUID]:
    """Active organisations of the rule's types: the ones a rule may add."""
    return set(
        (
            await session.execute(
                select(Organization.id).where(
                    Organization.org_type.in_(_eligible_rule_types(circle)),
                    # A pending enrolment has not been accepted, and a suspended
                    # or quarantined one is switched off; a rule hands none of
                    # them a circle. That is about *adding* only -- see below.
                    Organization.status == OrgStatus.ACTIVE,
                )
            )
        )
        .scalars()
        .all()
    )


async def _orgs_of_rule_type(session: AsyncSession, circle: Circle) -> set[uuid.UUID]:
    """Every organisation of the rule's types, whatever its status."""
    return set(
        (
            await session.execute(
                select(Organization.id).where(
                    Organization.org_type.in_(_eligible_rule_types(circle))
                )
            )
        )
        .scalars()
        .all()
    )


async def _orgs_removed_by_operator(session: AsyncSession, circle: Circle) -> set[uuid.UUID]:
    """Organisations whose most recent interval an operator closed."""
    latest = (
        select(
            CircleMembership.org_id,
            func.max(CircleMembership.joined_at).label("joined_at"),
        )
        .where(CircleMembership.circle_id == circle.id)
        .group_by(CircleMembership.org_id)
        .subquery()
    )
    return set(
        (
            await session.execute(
                select(CircleMembership.org_id)
                .join(
                    latest,
                    (latest.c.org_id == CircleMembership.org_id)
                    & (latest.c.joined_at == CircleMembership.joined_at),
                )
                .where(
                    CircleMembership.circle_id == circle.id,
                    CircleMembership.ended_by == "operator",
                )
            )
        )
        .scalars()
        .all()
    )


async def reconcile_circle(
    session: AsyncSession,
    ctx: AuthContext | None,
    *,
    circle: Circle,
    now: dt.datetime | None = None,
) -> ReconcileResult:
    """Bring a circle's rule-managed membership in line with its rule.

    Opens an interval for every active organisation the rule matches that has
    none open and that an operator has not removed; closes rule-managed
    intervals whose organisation's *type* no longer matches. Hand-added
    intervals are left alone in both directions -- see the module docstring.

    Status is deliberately not a reason to close. Closing on suspension (as
    this did) meant reactivation opened a fresh interval at reactivation time,
    and visibility then started there: years of the circle's history gone from
    a member's feed after a lapsed renewal, with no warning. A suspended or
    quarantined organisation is refused on every request already; its
    membership interval has nothing to add to that.

    Does not commit. The caller owns the transaction.
    """
    await _lock_circle(session, circle.id)
    if not circle.auto_member_org_types:
        return ReconcileResult()
    now = now or dt.datetime.now(dt.UTC)

    open_rows = await _open_memberships(session, circle.id)
    excluded = await _orgs_removed_by_operator(session, circle)
    eligible = await _orgs_matching_rule(session, circle)

    added = sorted(eligible - set(open_rows) - excluded, key=str)
    for org_id in added:
        session.add(
            CircleMembership(
                circle_id=circle.id,
                org_id=org_id,
                role=CircleRole.MEMBER,
                managed_by_rule=True,
            )
        )

    of_type = await _orgs_of_rule_type(session, circle)
    removed = sorted(
        (
            org_id
            for org_id, row in open_rows.items()
            if row.managed_by_rule and org_id not in of_type
        ),
        key=str,
    )
    for org_id in removed:
        open_rows[org_id].left_at = now
        open_rows[org_id].ended_by = "rule"

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
