"""Direct tests of the authorization predicates.

``auth.policy`` is a pure module: every predicate takes an ``AuthContext`` and
returns a bool. It therefore needs no database, and there is no excuse for its
branches to be untested — yet an audit found seven ``if not is_active(ctx)``
deny-paths, the whole operator-authorization branch, and the withdraw/supersede
arms had never once executed.

Those deny-paths matter even though authentication already rejects an inactive
organisation in ``auth.deps``. They are defence in depth: the day someone
relaxes the authentication layer — "let a suspended firm log in to see a
billing banner" — these become load-bearing, and code that has never run is
code nobody should be betting on.

The end-to-end behaviour is proved in the authorization matrix. This file proves
the predicates themselves, including the branches the HTTP surface cannot
currently reach.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from aivs_schemas.enums import (
    TLP,
    CircleRole,
    OperatorRole,
    OrgStatus,
    OrgType,
    SubmissionState,
)
from aivs_server.auth.context import AuthContext, AuthMethod, CircleGrant, MembershipInterval
from aivs_server.auth.policy import (
    PolicyDeniedError,
    can_administer_circle,
    can_manage_org,
    can_read_circle,
    can_review_submissions,
    can_submit_to_circle,
    can_transition_submission,
    can_view_submission,
    can_view_submission_receipts,
    distribution_visibility_clause,
    is_active,
    is_isac_editor,
    is_isac_membership,
    is_org_admin,
    is_system_admin,
    readable_circle_ids,
    require,
    visible_content_clause,
    writable_circle_ids,
)
from aivs_server.db.models import Submission

CIRCLE = uuid.UUID("0f9c0000-0000-4000-8000-00000000000a")
OTHER_CIRCLE = uuid.UUID("0f9c0000-0000-4000-8000-00000000000b")
ORG = uuid.UUID("0f9c0000-0000-4000-8000-000000000001")
OTHER_ORG = uuid.UUID("0f9c0000-0000-4000-8000-000000000002")


def context(
    *,
    org_type: OrgType = OrgType.GSIB,
    status: OrgStatus = OrgStatus.ACTIVE,
    circles: dict[uuid.UUID, CircleRole] | None = None,
    operator_roles: frozenset[OperatorRole] | None = None,
    org_id: uuid.UUID = ORG,
) -> AuthContext:
    """Build a synthetic caller.

    ``operator_roles`` set implies a portal session with an operator id, which is
    how the human-authorization branches are reached at all.
    """
    return AuthContext(
        org_id=org_id,
        org_slug="test-org",
        org_type=org_type,
        org_status=status,
        auth_method=(AuthMethod.PORTAL_SESSION if operator_roles is not None else AuthMethod.MTLS),
        circles={
            circle_id: (
                value
                if isinstance(value, CircleGrant)
                else CircleGrant(value, (MembershipInterval(LONG_AGO),))
            )
            for circle_id, value in (circles or {}).items()
        },
        cert_fingerprint="a" * 64,
        operator_id=uuid.uuid4() if operator_roles is not None else None,
        operator_roles=operator_roles or frozenset(),
    )


#: Membership start for callers whose join time is not what the test is about.
#: Early enough that every fixture's content was distributed after it, so a
#: role-focused test keeps testing roles.
LONG_AGO = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)


def submission(*, submitter: uuid.UUID = ORG, state: SubmissionState) -> Submission:
    """A detached Submission carrying only what the predicates read.

    ``tlp`` explicitly: the column default is applied at INSERT, and a stored
    submission always has a marking for the ceiling to read.
    """
    return Submission(id=uuid.uuid4(), submitter_org_id=submitter, state=state, tlp=TLP.AMBER)


INACTIVE = [OrgStatus.PENDING, OrgStatus.SUSPENDED]


# ---------------------------------------------------------------------------
# Every predicate denies an inactive organisation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("status", INACTIVE)
def test_inactive_orgs_are_denied_everywhere(status):
    """The deny-path in every predicate, exercised.

    Authentication already rejects these callers today, so none of these
    branches is reachable over HTTP. That is exactly why they need a direct
    test: they are the second line, and an untested second line is a first line
    nobody has checked.
    """
    ctx = context(status=status, circles={CIRCLE: CircleRole.CIRCLE_ADMIN})
    draft = submission(state=SubmissionState.DRAFT)

    assert is_active(ctx) is False
    assert is_system_admin(ctx) is False
    assert is_org_admin(ctx) is False
    assert can_read_circle(ctx, CIRCLE) is False
    assert can_submit_to_circle(ctx, CIRCLE) is False
    assert can_administer_circle(ctx, CIRCLE) is False
    assert can_view_submission(ctx, draft) is False
    assert can_view_submission_receipts(ctx) is False
    assert can_transition_submission(ctx, draft, SubmissionState.SUBMITTED) is False
    assert can_manage_org(ctx, ORG) is False
    assert readable_circle_ids(ctx) == frozenset()
    assert writable_circle_ids(ctx) == frozenset()


@pytest.mark.parametrize("status", INACTIVE)
def test_an_inactive_org_sees_no_content(status):
    """The empty circle set must render as "match nothing", never "match all"."""
    ctx = context(status=status, circles={CIRCLE: CircleRole.MEMBER})
    clause = distribution_visibility_clause(ctx, dt.datetime.now(dt.UTC))
    rendered = str(clause.compile(dialect=postgresql.dialect()))
    assert rendered.strip().lower() == "false"


# ---------------------------------------------------------------------------
# The ISAC's powers: human, and split four ways (SF-42)
# ---------------------------------------------------------------------------
ISAC_PREDICATES = {
    "system_admin": is_system_admin,
    "editor": is_isac_editor,
    "membership": is_isac_membership,
    "reviewer": can_review_submissions,
}


def isac_human(*roles: OperatorRole, **overrides: Any) -> AuthContext:
    """A signed-in human at the hosting ISAC holding ``roles``."""
    return context(org_type=OrgType.ADMIN, operator_roles=frozenset(roles), **overrides)


@pytest.mark.parametrize("predicate", list(ISAC_PREDICATES), ids=list(ISAC_PREDICATES))
def test_a_machine_identity_at_the_admin_org_holds_no_isac_power(predicate):
    """Inverted from ``..._is_the_instance``, which asserted the defect.

    A certificate of the admin organisation used to *be* the instance and held
    every ISAC power. Whoever controls the issuing CA can mint one -- in the
    managed mode, the host -- so editorial control and every access grant were
    available to the party the topology says must not have them. The pair: the
    same organisation, as a human holding every role, holds every power.
    """
    machine = context(org_type=OrgType.ADMIN)
    everyone = isac_human(
        OperatorRole.SYSTEM_ADMIN,
        OperatorRole.ISAC_EDITOR,
        OperatorRole.ISAC_MEMBERSHIP,
        OperatorRole.ISAC_ANALYST,
    )
    assert ISAC_PREDICATES[predicate](machine) is False
    assert ISAC_PREDICATES[predicate](everyone) is True


@pytest.mark.parametrize(
    ("role", "grants"),
    [
        (OperatorRole.SYSTEM_ADMIN, {"system_admin"}),
        (OperatorRole.ISAC_EDITOR, {"editor", "reviewer"}),
        (OperatorRole.ISAC_MEMBERSHIP, {"membership"}),
        (OperatorRole.ISAC_ANALYST, {"reviewer"}),
        (OperatorRole.ORG_ADMIN, set()),
        (OperatorRole.ANALYST, set()),
    ],
)
def test_each_isac_role_grants_exactly_its_own_powers(role, grants):
    """Employment is not authority, and no role implies another.

    ``system_admin`` runs the instance and holds no editorial verb; membership
    staff enrol firms and never read what those firms filed.
    """
    ctx = isac_human(role)
    held = {name for name, predicate in ISAC_PREDICATES.items() if predicate(ctx)}
    assert held == grants


@pytest.mark.parametrize("org_type", [OrgType.GSIB, OrgType.SECTION9, OrgType.CRIT_INFRA])
def test_no_member_org_holds_an_isac_power_whatever_its_roles(org_type):
    """``org_type`` is a database field a member cannot set, and it gates first."""
    ctx = context(
        org_type=org_type,
        operator_roles=frozenset(
            {OperatorRole.SYSTEM_ADMIN, OperatorRole.ISAC_EDITOR, OperatorRole.ISAC_MEMBERSHIP}
        ),
    )
    assert not any(predicate(ctx) for predicate in ISAC_PREDICATES.values())


# ---------------------------------------------------------------------------
# Organisation administration
# ---------------------------------------------------------------------------
def test_an_org_admin_may_manage_only_their_own_org():
    ctx = context(operator_roles=frozenset({OperatorRole.ORG_ADMIN}))
    assert can_manage_org(ctx, ORG) is True
    assert can_manage_org(ctx, OTHER_ORG) is False


def test_an_org_admin_at_the_hosting_isac_manages_nothing():
    """The admin organisation's certificates are ISAC powers, held through ISAC roles.

    Otherwise an ``org_admin`` there could revoke every staff certificate, or
    register a new one, with no ISAC role at all.
    """
    ctx = context(org_type=OrgType.ADMIN, operator_roles=frozenset({OperatorRole.ORG_ADMIN}))
    assert can_manage_org(ctx, ORG) is False
    assert is_org_admin(ctx) is False


def test_an_analyst_may_manage_no_org():
    ctx = context(operator_roles=frozenset({OperatorRole.ANALYST}))
    assert can_manage_org(ctx, ORG) is False


def test_a_machine_identity_may_not_manage_its_own_org():
    """A compromised member certificate must not mint itself a successor.

    A machine has no roles, so the org-admin branch cannot be reached by one.
    Certificate rotation is deliberately a human or ISAC action.
    """
    assert can_manage_org(context(), ORG) is False


def test_isac_membership_staff_may_manage_any_org_and_a_machine_may_not():
    assert can_manage_org(isac_human(OperatorRole.ISAC_MEMBERSHIP), OTHER_ORG) is True
    assert can_manage_org(context(org_type=OrgType.ADMIN), OTHER_ORG) is False


# ---------------------------------------------------------------------------
# Circles
# ---------------------------------------------------------------------------
def test_circle_access_follows_membership():
    ctx = context(circles={CIRCLE: CircleRole.MEMBER})
    assert can_read_circle(ctx, CIRCLE) is True
    assert can_read_circle(ctx, OTHER_CIRCLE) is False
    assert can_submit_to_circle(ctx, CIRCLE) is False, "member reads, does not write"


@pytest.mark.parametrize(
    ("role", "may_write"),
    [
        (CircleRole.MEMBER, False),
        (CircleRole.CONTRIBUTOR, True),
        (CircleRole.CIRCLE_ADMIN, True),
    ],
)
def test_circle_roles_grant_what_they_say(role, may_write):
    """Reading and contributing follow the role. Administering does not."""
    ctx = context(circles={CIRCLE: role})
    assert can_read_circle(ctx, CIRCLE) is True
    assert can_submit_to_circle(ctx, CIRCLE) is may_write


@pytest.mark.parametrize("role", list(CircleRole))
def test_no_circle_role_permits_administering_it(role):
    """Admitting an organisation to a circle is the hosting ISAC's alone.

    A circle carries other members' embargoed intelligence, and membership is
    backed by an agreement the ISAC holds. A classified programme does not let a
    cleared participant read in the next one; the programme manager does. That
    includes CIRCLE_ADMIN, whose name is now historical -- it is retained only
    because removing a PostgreSQL enum value is disruptive, and it confers
    exactly what CONTRIBUTOR does.
    """
    ctx = context(circles={CIRCLE: role})
    assert can_administer_circle(ctx, CIRCLE) is False


def test_the_hosting_isac_administers_every_circle():
    """Including circles it has not joined -- administering is not reading.

    The ISAC runs membership without appearing in the feed; reading a circle
    still requires joining it, visibly. See
    test_the_isac_does_not_read_circles_it_has_not_joined.
    """
    ctx = isac_human(OperatorRole.ISAC_MEMBERSHIP)
    assert can_administer_circle(ctx, CIRCLE) is True
    assert can_administer_circle(ctx, OTHER_CIRCLE) is True


def test_a_suspended_isac_administers_nothing():
    """The status check comes first here as it does everywhere else."""
    for status in INACTIVE:
        ctx = isac_human(OperatorRole.ISAC_MEMBERSHIP, status=status)
        assert can_administer_circle(ctx, CIRCLE) is False


def test_the_isac_does_not_read_circles_it_has_not_joined():
    """No administrative bypass here, deliberately.

    An ISAC that wants to read a circle joins it, visibly, so that a member's
    view of who receives their content is complete.
    """
    ctx = isac_human(
        OperatorRole.SYSTEM_ADMIN, OperatorRole.ISAC_EDITOR, OperatorRole.ISAC_MEMBERSHIP
    )
    assert is_isac_editor(ctx) is True
    assert can_read_circle(ctx, CIRCLE) is False


def test_writable_circles_are_the_contributing_ones():
    ctx = context(
        circles={
            CIRCLE: CircleRole.CONTRIBUTOR,
            OTHER_CIRCLE: CircleRole.MEMBER,
        }
    )
    assert writable_circle_ids(ctx) == frozenset({CIRCLE})
    assert readable_circle_ids(ctx) == frozenset({CIRCLE, OTHER_CIRCLE})


# ---------------------------------------------------------------------------
# Submission transitions -- including the arms the HTTP surface never reaches
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("state", "target", "by_submitter", "by_isac"),
    [
        (SubmissionState.DRAFT, SubmissionState.SUBMITTED, True, False),
        (SubmissionState.SUBMITTED, SubmissionState.VALIDATED, False, True),
        (SubmissionState.VALIDATED, SubmissionState.DISTRIBUTED, False, True),
        (SubmissionState.DRAFT, SubmissionState.WITHDRAWN, True, True),
        (SubmissionState.SUBMITTED, SubmissionState.WITHDRAWN, True, True),
        (SubmissionState.VALIDATED, SubmissionState.WITHDRAWN, True, True),
        (SubmissionState.DISTRIBUTED, SubmissionState.SUPERSEDED, True, True),
    ],
)
def test_who_may_perform_each_transition(state, target, by_submitter, by_isac):
    """The full authority table, including withdraw and supersede.

    Validation and distribution are reserved to the hosting ISAC: that human
    checkpoint is what keeps AIVS clear of the coordinated-disclosure consent
    problem, so a submitter must never be able to reach them.
    """
    record = submission(state=state)
    submitter = context()
    isac = isac_human(OperatorRole.ISAC_EDITOR, org_id=OTHER_ORG)

    assert can_transition_submission(submitter, record, target) is by_submitter
    assert can_transition_submission(isac, record, target) is by_isac


def test_an_unrelated_member_may_transition_nothing():
    record = submission(submitter=OTHER_ORG, state=SubmissionState.DRAFT)
    assert can_transition_submission(context(), record, SubmissionState.SUBMITTED) is False


@pytest.mark.parametrize(
    ("state", "target"),
    [
        (SubmissionState.DRAFT, SubmissionState.VALIDATED),
        (SubmissionState.DRAFT, SubmissionState.DISTRIBUTED),
        (SubmissionState.DISTRIBUTED, SubmissionState.WITHDRAWN),
        (SubmissionState.WITHDRAWN, SubmissionState.SUBMITTED),
        (SubmissionState.SUPERSEDED, SubmissionState.DISTRIBUTED),
    ],
)
def test_illegal_transitions_are_refused_even_for_the_isac(state, target):
    """The state machine binds authority, not the other way round.

    Note the third case: distributed content cannot be withdrawn by anyone,
    because members already hold it and withdrawal would be a false promise.
    """
    record = submission(state=state)
    assert can_transition_submission(isac_human(OperatorRole.ISAC_EDITOR), record, target) is False


# ---------------------------------------------------------------------------
# Submission visibility
# ---------------------------------------------------------------------------
def test_submissions_are_visible_to_their_submitter_and_the_isac():
    record = submission(state=SubmissionState.DRAFT)
    assert can_view_submission(context(), record) is True
    assert (
        can_view_submission(isac_human(OperatorRole.ISAC_ANALYST, org_id=OTHER_ORG), record) is True
    )
    assert can_view_submission(context(org_id=OTHER_ORG), record) is False


@pytest.mark.requirement("SF-15")
def test_named_receipts_are_the_isacs_alone():
    """Not the submitter's, and not a fellow circle member's.

    Which firms attend to which threats is not an inference members may draw
    about one another, and the submitter is a member: it gets k-suppressed
    telemetry. The pair: the ISAC's analyst reads them.
    """
    peer = context(org_id=OTHER_ORG, circles={CIRCLE: CircleRole.MEMBER})
    assert can_view_submission_receipts(context()) is False
    assert can_view_submission_receipts(peer) is False
    assert can_view_submission_receipts(isac_human(OperatorRole.ISAC_ANALYST)) is True


# ---------------------------------------------------------------------------
# The visibility clause
# ---------------------------------------------------------------------------
def test_the_visibility_clause_carries_all_four_gates():
    """Circle, membership start, embargo, and submission state -- each load-bearing."""
    rendered = str(
        visible_content_clause(
            {CIRCLE: (MembershipInterval(LONG_AGO),)}, dt.datetime.now(dt.UTC)
        ).compile(dialect=postgresql.dialect())
    ).lower()
    assert "circle_id =" in rendered
    assert "date_added >=" in rendered, "membership start bounds the back catalogue"
    assert "date_added <=" in rendered
    assert "state in" in rendered


def test_a_closed_interval_bounds_its_end_and_an_open_one_does_not():
    """Leaving ends what is readable from that interval; the open one has no end."""
    left = dt.datetime(2024, 6, 1, tzinfo=dt.UTC)
    rejoined = dt.datetime(2025, 3, 1, tzinfo=dt.UTC)
    rendered = str(
        visible_content_clause(
            {CIRCLE: (MembershipInterval(LONG_AGO, left), MembershipInterval(rejoined))},
            dt.datetime.now(dt.UTC),
        ).compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    ).lower()
    assert "date_added < '2024-06-01" in rendered, "the gap must be excluded"
    assert "2025-03-01" in rendered
    assert rendered.count("date_added < '") == 1, "an open interval has no upper bound"


def test_each_circle_carries_its_own_membership_start():
    """A member joins different circles at different times.

    Collapsing them to one floor would let the earliest join widen every other
    circle, which is the same back-catalogue leak in a subtler form.
    """
    other = uuid.uuid4()
    rendered = str(
        visible_content_clause(
            {
                CIRCLE: (MembershipInterval(LONG_AGO),),
                other: (MembershipInterval(dt.datetime(2026, 1, 1, tzinfo=dt.UTC)),),
            },
            dt.datetime.now(dt.UTC),
        ).compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    ).lower()
    assert "2020-01-01" in rendered
    assert "2026-01-01" in rendered


def test_an_empty_circle_set_matches_nothing():
    rendered = str(
        visible_content_clause({}, dt.datetime.now(dt.UTC)).compile(dialect=postgresql.dialect())
    )
    assert rendered.strip().lower() == "false"


# ---------------------------------------------------------------------------
# The require helper
# ---------------------------------------------------------------------------
def test_require_raises_with_the_audit_token():
    with pytest.raises(PolicyDeniedError) as caught:
        require(False, "some_reason_token")
    assert caught.value.reason == "some_reason_token"


def test_require_passes_when_allowed():
    require(True, "unused")


@pytest.mark.parametrize(
    "predicate",
    [
        "is_system_admin",
        "is_isac_editor",
        "is_isac_membership",
        "can_review_submissions",
        "can_change_embargo",
        "can_reveal_submitter",
        "can_pause_distribution",
        "can_resume_distribution",
        "can_reconnect_org",
        "can_view_instance_status",
    ],
)
def test_isac_roles_on_a_non_session_context_confer_nothing(predicate):
    """Every ISAC power needs a *signed-in human*, not only the role.

    Today a certificate context carries no roles, so the role test alone
    refuses it and the session test was untested defence in depth (a mutation
    dropping it survived). The day any other path builds a context with roles
    (single sign-on, in Phase M), this is what keeps a role from working
    without a portal session. The pair: the same roles on a session are
    honoured.
    """
    from aivs_server.auth import policy  # noqa: PLC0415 - name-addressed predicates

    # Every role a staff member can hold together. An auditor holds its role
    # alone (ck_operators_auditor_alone_and_expiring), and holding it closes
    # every predicate here, so it cannot be among the roles that would grant.
    every_role = frozenset(OperatorRole) - {OperatorRole.AUDITOR}

    def context(method: AuthMethod) -> AuthContext:
        return AuthContext(
            org_id=uuid.uuid4(),
            org_slug="hosting-isac",
            org_type=OrgType.ADMIN,
            org_status=OrgStatus.ACTIVE,
            auth_method=method,
            operator_id=uuid.uuid4(),
            operator_roles=every_role,
        )

    check = getattr(policy, predicate)
    assert check(context(AuthMethod.PORTAL_SESSION)) is True
    assert check(context(AuthMethod.MTLS)) is False
