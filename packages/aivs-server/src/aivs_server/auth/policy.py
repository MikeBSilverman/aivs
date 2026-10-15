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
    CIRCLE_ELIGIBLE_ORG_TYPES,
    TLP,
    VISIBLE_SUBMISSION_STATES,
    CircleRole,
    OperatorRole,
    OrgStatus,
    OrgType,
    SubmissionState,
    is_transition_allowed,
    tlp_at_least_as_restrictive,
)
from aivs_server.auth.context import AuthContext, AuthMethod, MembershipInterval
from aivs_server.db.models import Distribution, Embargo, InstanceControl, Organization, Submission

if TYPE_CHECKING:  # pragma: no cover
    pass

#: A circle membership's history, oldest first. See ``auth.context.MembershipInterval``.
Intervals = tuple[MembershipInterval, ...]

__all__ = [
    "PolicyDeniedError",
    "audit_scope",
    "can_acknowledge_own_submission",
    "can_administer_circle",
    "can_assign_submission",
    "can_change_embargo",
    "can_confirm_proxy_filing",
    "can_hold_evidence_pack",
    "can_manage_org",
    "can_manage_own_webhooks",
    "can_offboard_org",
    "can_pause_distribution",
    "can_quarantine_org",
    "can_read_audit",
    "can_read_circle",
    "can_read_isac_records",
    "can_read_own_lead_time",
    "can_reconnect_org",
    "can_register_certificate",
    "can_resume_distribution",
    "can_reveal_submitter",
    "can_review_submissions",
    "can_set_audit_stream_mode",
    "can_set_legal_hold",
    "can_set_priority",
    "can_submit_to_circle",
    "can_transition_submission",
    "can_validate_in_bulk",
    "can_view_instance_status",
    "can_view_submission",
    "can_view_submission_receipts",
    "distribution_visibility_clause",
    "files_through_an_editor",
    "holds_submitter_rights",
    "is_active",
    "is_auditor",
    "is_isac_editor",
    "is_isac_filing_needing_an_editor",
    "is_isac_membership",
    "is_isac_staff",
    "is_org_admin",
    "is_system_admin",
    "isac_record_read_clause",
    "readable_circle_grants",
    "readable_circle_ids",
    "require",
    "submission_within_ceiling",
    "tlp_ceiling",
    "tlp_ceiling_clause",
    "visible_content_clause",
    "within_tlp_ceiling",
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
    """Return whether the caller is permitted to transact at all.

    Checked first by every other predicate in this module. A ``PENDING`` org has
    enrolled but not been activated; a ``SUSPENDED`` org has been switched off.
    Neither may read or write anything.

    An auditor's session transacts nothing either. It reads the audit trail
    through :func:`can_read_audit`, which does not come through here, and
    every other predicate refuses it at this first check. A member firm's
    content is readable by its people because they are the firm's; an auditor
    is the firm's too, and refusing it here rather than in each predicate is
    what makes "never content" true of predicates written later.
    """
    return ctx.org_status is OrgStatus.ACTIVE and OperatorRole.AUDITOR not in ctx.operator_roles


def is_auditor(ctx: AuthContext) -> bool:
    """A signed-in auditor: a session that reads the audit trail and nothing else."""
    return OperatorRole.AUDITOR in ctx.operator_roles


def can_read_audit(ctx: AuthContext, now: dt.datetime) -> bool:
    """May the caller read the audit trail and receipts (within :func:`audit_scope`)?

    A signed-in auditor of an active organisation, before its access ends. The
    end is checked here against the caller's ``now`` as well as at session
    resolution, so a request cannot outlive it.
    """
    return (
        ctx.org_status is OrgStatus.ACTIVE
        and ctx.operator_id is not None
        and OperatorRole.AUDITOR in ctx.operator_roles
        and ctx.role_expires_at is not None
        and now < ctx.role_expires_at
    )


def can_hold_evidence_pack(ctx: AuthContext) -> bool:
    """May the caller's organisation draw its own evidence pack?

    The organisations that read by circle membership, other than the ISAC: the
    pack is a member's record of its own conduct, for its own regulator. The
    ISAC already holds the receipts it is built from, and an automation or a
    researcher reads nothing.
    """
    return is_active(ctx) and ctx.org_type in CIRCLE_ELIGIBLE_ORG_TYPES - {OrgType.ADMIN}


def audit_scope(ctx: AuthContext) -> uuid.UUID | None:
    """The organisation an auditor reads, or ``None`` for the whole instance.

    The ISAC's auditor reads the instance; a member's auditor reads its own
    organisation's records and nothing that names another.
    """
    if ctx.org_type is OrgType.ADMIN:
        return None
    return ctx.org_id


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


def can_set_audit_stream_mode(ctx: AuthContext) -> bool:
    """Choose what the audit stream serves of its own reading. Runs the
    instance, so the system administrator's; an auditor reads the choice and
    cannot make it."""
    return is_system_admin(ctx)


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
    """Return whether the caller may administer their own organisation.

    A member firm's role. At the hosting ISAC it grants nothing: the admin
    organisation's certificates and webhooks are ISAC powers, held through
    the ISAC roles, and an ``org_admin`` there could otherwise cut every
    staff certificate or register a new one with no ISAC role at all.
    """
    return (
        is_active(ctx)
        and ctx.org_type is not OrgType.ADMIN
        and OperatorRole.ORG_ADMIN in ctx.operator_roles
    )


def can_acknowledge_own_submission(ctx: AuthContext) -> bool:
    """Acknowledge or action a submission the caller's own organisation filed.

    Only ISAC staff (Mike's decision): an ISAC employee filing an advisory may
    record that the ISAC acted on it. A member acknowledging its own warning
    is evidence of nothing, and it would sit in the receipts and the
    submitter's telemetry beside the members who really did.
    """
    return is_isac_staff(ctx)


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


def can_assign_submission(ctx: AuthContext) -> bool:
    """Take or hand a submission to a reviewer: the people who work the queue."""
    return can_review_submissions(ctx)


def can_set_priority(ctx: AuthContext) -> bool:
    """Override the SSVC default priority: an editorial judgement."""
    return is_isac_editor(ctx)


def can_validate_in_bulk(ctx: AuthContext) -> bool:
    """Validate a review group in one action: an editor, as for a single validate."""
    return is_isac_editor(ctx)


def can_read_own_lead_time(ctx: AuthContext, org_id: uuid.UUID) -> bool:
    """A lead-time statement: the organisation it describes, and nobody else.

    Not the ISAC either. The statement carries what the firm actioned, from its
    own postures (SF-70), and the ISAC holding every firm's statement is the
    ranking of who acts slowly that no member agreed to. The ISAC has the
    sector median, which no member's behaviour enters.
    """
    return is_active(ctx) and ctx.org_id == org_id


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
def tlp_ceiling(ctx: AuthContext) -> TLP:
    """The most restrictive marking this caller may read.

    A member's person signed in through the IdP, over ordinary TLS from any
    browser, reads up to AMBER+STRICT -- organisation-only, and the person is in
    the organisation. RED is for named individuals on named devices and stays on
    the certificate-bound path (Mike's decision, "Human access"). Written as the
    one session kind that is limited, so a new kind is unlimited only if someone
    says so here.
    """
    if ctx.auth_method is AuthMethod.SSO_SESSION:
        return TLP.AMBER_STRICT
    return TLP.RED


def within_tlp_ceiling(ctx: AuthContext, marking: TLP) -> bool:
    """Whether ``marking`` is no more restrictive than the caller's ceiling."""
    return tlp_at_least_as_restrictive(tlp_ceiling(ctx), marking)


def tlp_ceiling_clause(ctx: AuthContext) -> ColumnElement[bool]:
    """The ceiling as SQL, for every read that serves content.

    Over ``Submission``: the query it joins must join the owning submission.

    An SSO session also never reads content distributed under an embargo: the
    pre-CVE lane under embargo stays on the certificate-bound path for its
    whole life, released or not, because a warning that was worth an embargo
    is the content RED-adjacent handling exists for.
    """
    allowed = tuple(marking for marking in TLP if within_tlp_ceiling(ctx, marking))
    marking_allowed = Submission.tlp.in_(allowed)
    if ctx.auth_method is not AuthMethod.SSO_SESSION:
        return marking_allowed
    embargoed = exists().where(Embargo.submission_id == Submission.id)
    return and_(marking_allowed, ~embargoed)


def submission_within_ceiling(ctx: AuthContext, submission: Submission) -> bool:
    """:func:`tlp_ceiling_clause` for one loaded submission: the same two terms.

    Reads ``submission.embargo``, so for an SSO session the submission must
    have been loaded with it (``load_submission`` does); the check is made
    first, so other sessions never touch the relationship.
    """
    if not within_tlp_ceiling(ctx, submission.tlp):
        return False
    return ctx.auth_method is not AuthMethod.SSO_SESSION or submission.embargo is None


def can_view_submission(ctx: AuthContext, submission: Submission) -> bool:
    """Return whether the caller may view a submission's workflow record.

    Distinct from whether they can read its distributed *content*: the submitter
    and the hosting ISAC can see a submission while it is still a draft, whereas
    members see the objects only once they are distributed into a circle they
    belong to, which the TAXII visibility clause governs.
    """
    if not is_active(ctx) or not submission_within_ceiling(ctx, submission):
        return False
    if can_review_submissions(ctx):
        return True
    return submission.submitter_org_id == ctx.org_id


def can_view_submission_receipts(ctx: AuthContext) -> bool:
    """Return whether the caller may see, firm by firm, who retrieved and acted on it.

    The ISAC's reviewers only. Receipts reveal which member firms attend to
    which threats; each row is the *receiving* member's record, and one
    member's receipts are never produced to another without process (sharing
    agreement section 9). The submitter is another member, so it gets the
    k-suppressed counts of ``services/telemetry.py`` instead. Letting it read
    the named rows as well made that suppression decorative: a "fewer than 5"
    beside a list of the four firms.
    """
    return is_active(ctx) and can_review_submissions(ctx)


def can_confirm_proxy_filing(ctx: AuthContext, submission: Submission) -> bool:
    """Confirm a filing an ISAC editor made in this organisation's name (SF-68).

    A person at that organisation, never its machine certificate. The window
    exists so someone at the member can say "we did not send this"; a
    collector that confirms whatever arrives would close it unread.
    """
    return (
        is_active(ctx) and submission.submitter_org_id == ctx.org_id and ctx.operator_id is not None
    )


def holds_submitter_rights(ctx: AuthContext, submission: Submission) -> bool:
    """Whether the caller may act as ``submission``'s submitter: amend its
    draft, submit, withdraw or supersede it.

    A member firm holds these for what it filed, by certificate or by session.
    A filing whose owner is the ISAC's own organisation is the instance's
    record, so each of its verbs needs a human ``isac_editor``, as validating
    already did (Mike, Q15). Until then the submitter's rights applied to it
    as to any member's: an ISAC analyst's session, or the admin
    organisation's certificate alone, could amend a draft or withdraw a
    validated advisory.
    """
    if submission.submitter_org_id != ctx.org_id:
        return False
    return not is_isac_filing_needing_an_editor(ctx, submission)


def is_isac_filing_needing_an_editor(ctx: AuthContext, submission: Submission) -> bool:
    """The caller is at the ISAC, the filing is the ISAC's, and the caller is
    not a signed-in editor: the refusal ``holds_submitter_rights`` makes, named
    so the refusal can say which rule refused."""
    return submission.submitter_org_id == ctx.org_id and files_through_an_editor(ctx)


def files_through_an_editor(ctx: AuthContext) -> bool:
    """ISAC staff without the editor role, or the ISAC's certificate alone.

    Whatever they file is the ISAC's own, and sending it on is an editor's
    verb (Mike, Q15), so a shortcut that would file and submit in one step
    refuses them before filing anything.
    """
    return ctx.org_type is OrgType.ADMIN and not is_isac_editor(ctx)


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

    is_submitter = holds_submitter_rights(ctx, submission)
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


def can_register_certificate(ctx: AuthContext, organisation: Organization) -> bool:
    """Bind a certificate to ``organisation``, decided on its row read under the lock.

    ``can_manage_org`` is decided on the caller's context, resolved before the
    row lock. A member's admin whose registration waited on a quarantine
    therefore inserted an ACTIVE certificate the quarantine never saw. So a
    member's own admin may register only while its organisation is active.
    ISAC membership staff may register whatever the status: enrolment
    registers before activation, and reconnection requires a certificate
    registered during the quarantine. Nobody registers one to an offboarded
    organisation: that status is terminal.
    """
    if organisation.status is OrgStatus.OFFBOARDED:
        return False
    if is_isac_membership(ctx):
        return True
    return can_manage_org(ctx, organisation.id) and organisation.status is OrgStatus.ACTIVE


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


def can_offboard_org(ctx: AuthContext) -> bool:
    """End an organisation's membership of the ISAC, for good. Membership staff only.

    Narrower than quarantine on purpose: quarantine is the safe direction and
    anyone who notices may press it, but offboarding deletes what the member
    keeps operationally and pseudonymises its people, and nothing reverses it.
    """
    return is_isac_membership(ctx)


def can_set_legal_hold(ctx: AuthContext) -> bool:
    """Place or lift a legal hold on an organisation's data. Membership staff only."""
    return is_isac_membership(ctx)


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


def can_read_isac_records(ctx: AuthContext) -> bool:
    """Read the ISAC's own canonical records, outside any circle, to version them.

    The automation organisation's certificate, and nothing else. It is the
    ISAC's machine identity -- the database allows one -- and it versions the
    ISAC's records (KEV status), so it must read them. It cannot reach them
    through a circle: it is not circle-eligible, and making it a member would
    hand it every member's content in that circle. So this is a read of its
    own organisation's records, as ownership counts them, and of nothing a
    member filed.

    No person: the automation organisation has no analysts, and a session
    reaching this would be an ISAC power held through a door the role checks
    do not guard. :func:`isac_record_read_clause` bounds what it returns.
    """
    return (
        is_active(ctx)
        and ctx.org_type is OrgType.AUTOMATION
        and ctx.auth_method is AuthMethod.MTLS
        and ctx.operator_id is None
    )


def isac_record_read_clause(now: dt.datetime) -> ColumnElement[bool]:
    """What the automation may read of the ISAC's records: released, visible, and not RED.

    Released and visible for the reason every reader's clause has them: an
    embargoed version is not yet anyone's to act on, and the stop button stops
    this reader too. Not RED because RED names its recipients one by one, and
    a machine key on an operator's host is not one of them; KEV status is
    about published CVEs, which no RED record needs. Callers join
    ``Submission`` and ``Distribution``.
    """
    return and_(
        Distribution.date_added <= now,
        Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)),
        Submission.tlp != TLP.RED,
        _distribution_not_paused(),
    )


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

    An inactive organisation matches no rows, as a plain ``FALSE`` rather than
    ``FALSE AND <ceiling>``, so the refusal can be read off the rendered SQL.
    """
    if not is_active(ctx):
        return false()
    return and_(visible_content_clause(readable_circle_grants(ctx), now), tlp_ceiling_clause(ctx))
