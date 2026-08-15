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

from sqlalchemy import ColumnElement, and_, or_

from aivs_schemas.enums import (
    VISIBLE_SUBMISSION_STATES,
    CircleRole,
    OperatorRole,
    OrgStatus,
    OrgType,
    SubmissionState,
    is_transition_allowed,
)
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.db.models import Distribution, Submission

if TYPE_CHECKING:  # pragma: no cover
    pass

__all__ = [
    "PolicyDeniedError",
    "can_administer_circle",
    "can_manage_org",
    "can_read_circle",
    "can_submit_to_circle",
    "can_transition_submission",
    "can_view_submission",
    "can_view_submission_receipts",
    "distribution_visibility_clause",
    "is_active",
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


def is_system_admin(ctx: AuthContext) -> bool:
    """Return whether the caller operates the instance (the hosting ISAC).

    A human at the hosting ISAC must additionally hold the ``SYSTEM_ADMIN``
    role: an analyst who happens to work at the ISAC is an analyst. A machine
    identity belonging to the admin organisation is the instance itself.
    """
    if not is_active(ctx) or ctx.org_type is not OrgType.ADMIN:
        return False
    if ctx.operator_id is not None:
        return ctx.operator_role is OperatorRole.SYSTEM_ADMIN
    return ctx.auth_method is AuthMethod.MTLS


def is_org_admin(ctx: AuthContext) -> bool:
    """Return whether the caller may administer their own organisation."""
    if not is_active(ctx):
        return False
    if is_system_admin(ctx):
        return True
    return ctx.operator_role in (OperatorRole.ORG_ADMIN, OperatorRole.SYSTEM_ADMIN)


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
    """Return whether the caller may change ``circle_id``'s membership."""
    if not is_active(ctx):
        return False
    if is_system_admin(ctx):
        return True
    grant = ctx.circles.get(circle_id)
    return grant is not None and grant.role is CircleRole.CIRCLE_ADMIN


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


def readable_circle_grants(ctx: AuthContext) -> Mapping[uuid.UUID, dt.datetime]:
    """Return each readable circle with the moment the caller's access began.

    The input to :func:`visible_content_clause`. Empty for an inactive
    organisation, which that function maps to an explicit false.
    """
    if not is_active(ctx):
        return {}
    return {circle_id: grant.joined_at for circle_id, grant in ctx.circles.items()}


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
    if is_system_admin(ctx):
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
    if is_system_admin(ctx):
        return True
    return submission.submitter_org_id == ctx.org_id


def can_transition_submission(
    ctx: AuthContext, submission: Submission, target: SubmissionState
) -> bool:
    """Return whether the caller may move ``submission`` into ``target``.

    Two independent gates, both of which must pass:

    * the move is legal in the state machine (``aivs_schemas.enums``), and
    * the caller holds the right to perform that particular move.

    Validation and distribution are reserved to the hosting ISAC. That is the
    human checkpoint which keeps AIVS clear of the coordinated-disclosure
    consent problem: content reaches members only when the ISAC has decided it
    should, never merely because a member uploaded it.
    """
    if not is_active(ctx):
        return False
    if not is_transition_allowed(submission.state, target):
        return False

    is_submitter = submission.submitter_org_id == ctx.org_id
    admin = is_system_admin(ctx)

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
    changing their status belong to the hosting ISAC. An organisation
    administrator may manage their own organisation only.
    """
    if not is_active(ctx):
        return False
    if is_system_admin(ctx):
        return True
    return is_org_admin(ctx) and target_org_id == ctx.org_id


# ---------------------------------------------------------------------------
# The visibility clause
# ---------------------------------------------------------------------------
def visible_content_clause(
    grants: Mapping[uuid.UUID, dt.datetime], now: dt.datetime
) -> ColumnElement[bool]:
    """Return the SQL predicate selecting distributed content readable right now.

    **The read-side enforcement point, and the authoritative embargo gate.**
    ``grants`` maps each circle the caller belongs to to the moment their access
    to it began. Four conditions, all required:

    1. the object was distributed into one of the caller's circles,
    2. its ``date_added`` for that circle is **at or after** the caller joined,
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
    earliest of those must not widen the others.

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
        and_(
            Distribution.circle_id == circle_id,
            Distribution.date_added >= joined_at,
        )
        for circle_id, joined_at in sorted(grants.items(), key=lambda item: str(item[0]))
    ]

    return and_(
        or_(*per_circle),
        Distribution.date_added <= now,
        Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)),
    )


def distribution_visibility_clause(ctx: AuthContext, now: dt.datetime) -> ColumnElement[bool]:
    """Return the predicate selecting everything ``ctx`` may read, across circles.

    An inactive organisation yields an empty circle set and therefore a clause
    that matches no rows.
    """
    return visible_content_clause(readable_circle_grants(ctx), now)
