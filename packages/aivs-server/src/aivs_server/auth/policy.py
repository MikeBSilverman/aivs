"""The authorization decision point. All of it.

Every "may this caller do that" question in AIVS is answered here and nowhere
else. Routers call these predicates; they never re-implement a rule inline. The
reason is testability rather than tidiness: ``tests/authz_matrix`` enumerates
every route against every caller shape and asserts the exact outcome, and that
proof is only worth something if there is one place where the rules live.

Three invariants hold throughout:

**Deny by default.** Every predicate returns ``False`` unless a rule explicitly
grants access. There is no branch that ends in a permissive fallthrough.

**Suspended and pending organisations get nothing.** The status check is the
first thing every entry point does, so revoking an org's participation is a
single field update that takes effect on their next request.

**Circle membership governs collection visibility, even for the hosting ISAC.**
A system administrator does not silently appear inside every member's TAXII
feed; their oversight runs through the native API and the portal, which are
separately authorized and separately audited. An ISAC that wants to read a
circle's contents joins that circle, visibly.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping
from typing import TYPE_CHECKING, Final

from sqlalchemy import ColumnElement, and_, exists, false, or_, true

from aivs_schemas.enums import (
    VISIBLE_SUBMISSION_STATES,
    CircleRole,
    OperatorRole,
    OrgStatus,
    OrgType,
    SubmissionState,
    is_transition_allowed,
)
from aivs_server.auth.context import AuthContext, AuthMethod, MembershipInterval
from aivs_server.db.models import Distribution, InstanceControl, Submission

if TYPE_CHECKING:  # pragma: no cover
    pass

#: A circle membership's history, oldest first. See ``auth.context.MembershipInterval``.
Intervals = tuple[MembershipInterval, ...]

__all__ = [
    "PolicyDeniedError",
    "can_administer_circle",
    "can_change_embargo",
    "can_manage_org",
    "can_manage_own_webhooks",
    "can_pause_distribution",
    "can_quarantine_org",
    "can_read_circle",
    "can_reconnect_org",
    "can_resume_distribution",
    "can_reveal_submitter",
    "can_review_submissions",
    "can_submit_to_circle",
    "can_transition_submission",
    "can_view_instance_status",
    "can_view_submission",
    "can_view_submission_receipts",
    "distribution_visibility_clause",
    "is_active",
    "is_isac_editor",
    "is_isac_membership",
    "is_isac_staff",
    "is_org_admin",
    "is_system_admin",
    "readable_circle_grants",
    "readable_circle_ids",
    "require",
    "visible_content_clause",
    "writable_circle_ids",
]


class PolicyDeniedError(Exception):
    """A caller was refused an action.

    ``reason`` is a short stable token recorded in the audit log. It is not
    returned to the caller: an unauthenticated or under-privileged client learns
    only that it was denied, never which specific rule it tripped.
    """

    __slots__ = ("reason",)

    def __init__(self, reason: str) -> None:
        super().__init__(f"denied: {reason}")
        self.reason = reason


#: Roles within a circle that permit contributing content, not merely reading.
_WRITING_CIRCLE_ROLES: Final[frozenset[CircleRole]] = frozenset(
    {CircleRole.CONTRIBUTOR, CircleRole.CIRCLE_ADMIN}
)


def require(allowed: bool, reason: str) -> None:
    """Raise :class:`PolicyDeniedError` unless ``allowed``.

    Lets a router read as ``require(can_read_circle(ctx, cid), "circle_read")``
    rather than growing its own if/raise ladder.
    """
    if not allowed:
        raise PolicyDeniedError(reason)


# ---------------------------------------------------------------------------
# Baseline predicates
# ---------------------------------------------------------------------------
def is_active(ctx: AuthContext) -> bool:
    """Return whether the caller's organisation is permitted to transact at all.

    Checked first by every other predicate in this module. A ``PENDING`` org has
    enrolled but not been activated; a ``SUSPENDED`` org has been switched off.
    Neither may read or write anything.
    """
    return ctx.org_status is OrgStatus.ACTIVE


def _isac_human(ctx: AuthContext, role: OperatorRole) -> bool:
    """A human at the hosting ISAC, signed in, holding ``role``.

    Every ISAC power requires a human session. A machine identity belonging to
    the admin organisation used to be "the instance itself" and held all of
    them -- and whoever controls the issuing CA can mint one, which in the
    managed-hosting mode is the host. That made editorial control, and every
    access grant, available to the one party the topology says must not have
    them. A certificate now authenticates the network path and nothing more.
    """
    return (
        is_active(ctx)
        and ctx.org_type is OrgType.ADMIN
        and ctx.auth_method is AuthMethod.PORTAL_SESSION
        and role in ctx.operator_roles
    )


def is_system_admin(ctx: AuthContext) -> bool:
    """Runs the instance: operators and settings. Holds no editorial verb."""
    return _isac_human(ctx, OperatorRole.SYSTEM_ADMIN)


def is_isac_editor(ctx: AuthContext) -> bool:
    """Validates, distributes, sets embargoes, reveals, and governs circles."""
    return _isac_human(ctx, OperatorRole.ISAC_EDITOR)


def is_isac_membership(ctx: AuthContext) -> bool:
    """Enrols, suspends and quarantines organisations; keeps rosters and certificates."""
    return _isac_human(ctx, OperatorRole.ISAC_MEMBERSHIP)


def can_review_submissions(ctx: AuthContext) -> bool:
    """Sees every submission's workflow record and the review queue.

    The ISAC's analysts and editors. Not membership staff: they enrol firms and
    never need to read what those firms filed.
    """
    return _isac_human(ctx, OperatorRole.ISAC_ANALYST) or is_isac_editor(ctx)


def is_isac_staff(ctx: AuthContext) -> bool:
    """Holds any ISAC role. Decides what the portal *shows*, never what anyone may do."""
    return any(
        _isac_human(ctx, role)
        for role in (
            OperatorRole.ISAC_ANALYST,
            OperatorRole.ISAC_EDITOR,
            OperatorRole.ISAC_MEMBERSHIP,
            OperatorRole.SYSTEM_ADMIN,
        )
    )


def is_org_admin(ctx: AuthContext) -> bool:
    """Return whether the caller may administer their own organisation."""
    return is_active(ctx) and OperatorRole.ORG_ADMIN in ctx.operator_roles


def can_manage_own_webhooks(ctx: AuthContext) -> bool:
    """Register or delete the caller's own organisation's webhooks.

    At the hosting ISAC, only a signed-in system admin: its webhooks carry the
    platform's own detection alerts, and the admin organisation's certificate
    alone -- which whoever holds the issuing CA can mint, in managed hosting the
    host -- could otherwise subscribe to learn when it has been noticed. At a
    member, its machine certificate (collectors register their own endpoint)
    or a signed-in org admin, not any analyst.
    """
    if not is_active(ctx):
        return False
    if ctx.org_type is OrgType.ADMIN:
        return is_system_admin(ctx)
    if ctx.auth_method is AuthMethod.MTLS and ctx.operator_id is None:
        return True
    return is_org_admin(ctx)


def can_reveal_submitter(ctx: AuthContext) -> bool:
    """Name the submitter of an anonymous submission: an editorial act, audited."""
    return is_isac_editor(ctx)


def can_change_embargo(ctx: AuthContext) -> bool:
    """Release early or extend an embargo: an editorial decision."""
    return is_isac_editor(ctx)


# ---------------------------------------------------------------------------
# Circle access
# ---------------------------------------------------------------------------
def can_read_circle(ctx: AuthContext, circle_id: uuid.UUID) -> bool:
    """Return whether the caller may read content shared into ``circle_id``.

    Membership alone decides this -- see the module docstring on why system
    administrators are not exempt.
    """
    return is_active(ctx) and circle_id in ctx.circles


def can_submit_to_circle(ctx: AuthContext, circle_id: uuid.UUID) -> bool:
    """Return whether the caller may contribute content into ``circle_id``."""
    if not is_active(ctx):
        return False
    grant = ctx.circles.get(circle_id)
    return grant is not None and grant.role in _WRITING_CIRCLE_ROLES


def can_administer_circle(ctx: AuthContext, circle_id: uuid.UUID) -> bool:
    """Return whether the caller may change ``circle_id``'s membership.

    **The hosting ISAC alone.** Admitting an organisation to a circle is a
    read-in: the circle carries other members' embargoed intelligence, and
    membership is normally backed by a sharing agreement, sector eligibility and
    an NDA that the ISAC — not a member firm — holds. A classified programme does
    not let a cleared participant read in the next one; the programme manager
    does, because the manager is who the obligation runs to. This works the same
    way, and for the same reason.

    Delegation to a member holding ``CircleRole.CIRCLE_ADMIN`` was permitted
    until the argument for it ran out. That argument was operational load, and
    rule-based membership (``services/circles.py``) plus the portal's
    administrative screens absorbed nearly all of it: the routine changes now
    happen without anyone filing anything. What was left was a member firm able
    to admit another firm to a room holding a third firm's content, which is a
    hole in the one claim an ISAC-in-a-box is really selling.

    ``circle_id`` is still taken, and is deliberately not ignored by the
    signature: if delegation is reintroduced it is reintroduced here, scoped to a
    circle, rather than by widening some caller's idea of what "admin" means.
    """
    del circle_id
    return is_isac_membership(ctx)


def readable_circle_ids(ctx: AuthContext) -> frozenset[uuid.UUID]:
    """Return every circle the caller may read.

    Returns the empty set for an inactive organisation, which makes the
    visibility clause below match nothing rather than everything -- the failure
    mode of an empty ``IN ()`` is the safe one here, and is asserted in tests.

    For *content* visibility use :func:`readable_circle_grants` instead: the set
    of circles alone omits when each membership began, which is half the
    predicate.
    """
    if not is_active(ctx):
        return frozenset()
    return ctx.circle_ids


def readable_circle_grants(ctx: AuthContext) -> Mapping[uuid.UUID, Intervals]:
    """Return each readable circle with the intervals the caller belonged to it.

    The input to :func:`visible_content_clause`. Empty for an inactive
    organisation, which that function maps to an explicit false.
    """
    if not is_active(ctx):
        return {}
    return {circle_id: grant.intervals for circle_id, grant in ctx.circles.items()}


def writable_circle_ids(ctx: AuthContext) -> frozenset[uuid.UUID]:
    """Return every circle the caller may contribute to."""
    if not is_active(ctx):
        return frozenset()
    return frozenset(
        circle_id for circle_id, grant in ctx.circles.items() if grant.role in _WRITING_CIRCLE_ROLES
    )


# ---------------------------------------------------------------------------
# Submission access
# ---------------------------------------------------------------------------
def can_view_submission(ctx: AuthContext, submission: Submission) -> bool:
    """Return whether the caller may view a submission's workflow record.

    Distinct from whether they can read its distributed *content*: the submitter
    and the hosting ISAC can see a submission while it is still a draft, whereas
    members see the objects only once they are distributed into a circle they
    belong to, which the TAXII visibility clause governs.
    """
    if not is_active(ctx):
        return False
    if can_review_submissions(ctx):
        return True
    return submission.submitter_org_id == ctx.org_id


def can_view_submission_receipts(ctx: AuthContext, submission: Submission) -> bool:
    """Return whether the caller may see who retrieved and acknowledged a submission.

    Restricted to the submitter and the hosting ISAC. Receipts reveal which
    member firms are paying attention to which threats, which is exactly the
    kind of inference other members must not be able to draw about each other.
    """
    if not is_active(ctx):
        return False
    if can_review_submissions(ctx):
        return True
    return submission.submitter_org_id == ctx.org_id


def can_transition_submission(
    ctx: AuthContext, submission: Submission, target: SubmissionState
) -> bool:
    """Return whether the caller may move ``submission`` into ``target``.

    Two independent gates, both of which must pass:

    * the move is legal in the state machine (``aivs_schemas.enums``), and
    * the caller holds the right to perform that particular move.

    Validation and distribution are reserved to an ISAC editor, in a human
    session -- never a certificate alone. That is the human checkpoint which
    keeps AIVS clear of the coordinated-disclosure consent problem: content
    reaches members only when the ISAC has decided it should, never merely
    because a member uploaded it.
    """
    if not is_active(ctx):
        return False
    if not is_transition_allowed(submission.state, target):
        return False

    is_submitter = submission.submitter_org_id == ctx.org_id
    admin = is_isac_editor(ctx)

    match target:
        case SubmissionState.SUBMITTED:
            return is_submitter
        case SubmissionState.VALIDATED | SubmissionState.DISTRIBUTED:
            return admin
        case SubmissionState.WITHDRAWN:
            return is_submitter or admin
        case SubmissionState.SUPERSEDED:
            return is_submitter or admin
        case _:  # pragma: no cover - exhaustive over SubmissionState
            return False


def can_manage_org(ctx: AuthContext, target_org_id: uuid.UUID) -> bool:
    """Return whether the caller may administer ``target_org_id``.

    Enrolling organisations, issuing and revoking their certificates, and
    changing their status belong to the ISAC's membership staff. An organisation
    administrator may manage their own organisation only.
    """
    if not is_active(ctx):
        return False
    if is_isac_membership(ctx):
        return True
    return is_org_admin(ctx) and target_org_id == ctx.org_id


# ---------------------------------------------------------------------------
# The visibility clause
# ---------------------------------------------------------------------------
def _distribution_not_paused() -> ColumnElement[bool]:
    """False while the instance's stop button is pressed.

    Part of visibility, not only of publishing: an embargo stamped days ago
    becomes visible by the clock with no writer involved, so blocking writers
    alone would not stop it. Members' paging cursors do not move on an empty
    page, so nothing is skipped when distribution resumes.
    """
    return ~exists().where(InstanceControl.id == 1, InstanceControl.distribution_paused.is_(True))


def can_quarantine_org(ctx: AuthContext, target_org_id: uuid.UUID) -> bool:
    """Cut an organisation off during an incident.

    ISAC membership staff, editors and system admins; and the organisation's
    own ``org_admin`` for itself -- "we are compromised, cut us off" needs no
    one's approval, because stopping is the safe direction.
    """
    if is_isac_membership(ctx) or is_isac_editor(ctx) or is_system_admin(ctx):
        return True
    return is_org_admin(ctx) and ctx.org_id == target_org_id


def can_reconnect_org(ctx: AuthContext) -> bool:
    """Return a quarantined organisation to service. The ISAC's alone: a member
    reconnecting itself would let whoever holds its compromised credentials do
    the same."""
    return is_isac_membership(ctx) or is_isac_editor(ctx)


def can_view_instance_status(ctx: AuthContext) -> bool:
    """Read the status page: health, queues, usage counts, expiring credentials.

    The people who run the instance and the people who run the membership. It
    carries counts and identifiers, never content, so a role with no content
    right may read it.
    """
    return is_system_admin(ctx) or is_isac_membership(ctx)


def can_pause_distribution(ctx: AuthContext) -> bool:
    """Press the stop button. Editors, and the people who run the instance.

    Wider than resuming on purpose: in an incident the person who notices is
    not always an editor, and stopping is the safe direction.
    """
    return is_isac_editor(ctx) or is_system_admin(ctx)


def can_resume_distribution(ctx: AuthContext) -> bool:
    """Start publishing again: an editorial decision."""
    return is_isac_editor(ctx)


def _within_any(intervals: Intervals) -> ColumnElement[bool]:
    """``date_added`` falls inside at least one membership interval."""
    return or_(
        *(
            and_(
                Distribution.date_added >= interval.joined_at,
                Distribution.date_added < interval.left_at
                if interval.left_at is not None
                else true(),
            )
            for interval in intervals
        ),
        false(),
    )


def visible_content_clause(
    grants: Mapping[uuid.UUID, Intervals], now: dt.datetime
) -> ColumnElement[bool]:
    """Return the SQL predicate selecting distributed content readable right now.

    **The read-side enforcement point, and the authoritative embargo gate.**
    ``grants`` maps each circle the caller belongs to to the intervals during
    which it belonged. Four conditions, all required:

    1. the object was distributed into one of the caller's circles,
    2. its ``date_added`` for that circle falls **within one of the caller's
       membership intervals** -- at or after a ``joined_at``, and before that
       interval's ``left_at`` if it has closed,
    3. its ``date_added`` has arrived -- which is what makes embargo enforcement
       safe even when the release scheduler is not running, since an unreleased
       object simply has a future ``date_added``, and
    4. the owning submission is in a state whose content is visible.

    Callers must join ``Submission`` for condition 4 to resolve.

    Condition 2 is the one that is easy to leave out, and it was. Without it,
    adding an organisation to a circle handed them **every object ever
    distributed there** -- years of other firms' embargoed intelligence, at that
    circle's TLP floor, retroactively and in one call. "Add them to the group"
    reads like a grant of participation; it must not silently be a grant of the
    archive. It is expressed per circle rather than as one global floor because
    a member typically joins different circles at different times, and the
    earliest of those must not widen the others. It is a union of intervals
    rather than one start time because a member that leaves and rejoins must
    keep what it had and must not receive what was shared while it was out.

    Both readers go through here -- ``taxii.queries`` for a single collection and
    :func:`distribution_visibility_clause` for everything a caller may read --
    so the conditions have one definition. They were briefly written twice, and
    a duplicated security condition is one refactor away from being two
    different security conditions.
    """
    if not grants:
        # An explicit false, rather than `IN ()`, which some dialects treat
        # inconsistently and which reads ambiguously in a query log. The failure
        # mode of an empty set must be "match nothing", never "match everything".
        return or_(False)

    # Sorted so the emitted SQL is deterministic for a given membership set,
    # which keeps query logs diffable and plan caches warm.
    per_circle = [
        and_(Distribution.circle_id == circle_id, _within_any(intervals))
        for circle_id, intervals in sorted(grants.items(), key=lambda item: str(item[0]))
    ]

    return and_(
        or_(*per_circle),
        Distribution.date_added <= now,
        Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)),
        _distribution_not_paused(),
    )


def distribution_visibility_clause(ctx: AuthContext, now: dt.datetime) -> ColumnElement[bool]:
    """Return the predicate selecting everything ``ctx`` may read, across circles.

    An inactive organisation yields an empty circle set and therefore a clause
    that matches no rows.
    """
    return visible_content_clause(readable_circle_grants(ctx), now)
