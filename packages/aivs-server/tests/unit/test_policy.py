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

import pytest
from sqlalchemy.dialects import postgresql

from aivs_schemas.enums import (
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
    can_submit_to_circle,
    can_transition_submission,
    can_view_submission,
    can_view_submission_receipts,
    distribution_visibility_clause,
    is_active,
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
    operator_role: OperatorRole | None = None,
    org_id: uuid.UUID = ORG,
) -> AuthContext:
    """Build a synthetic caller.

    ``operator_role`` set implies a portal session with an operator id, which is
    how the human-authorization branches are reached at all.
    """
    return AuthContext(
        org_id=org_id,
        org_slug="test-org",
        org_type=org_type,
        org_status=status,
        auth_method=(AuthMethod.PORTAL_SESSION if operator_role is not None else AuthMethod.MTLS),
        circles={
            circle_id: (
                value
                if isinstance(value, CircleGrant)
                else CircleGrant(value, (MembershipInterval(LONG_AGO),))
            )
            for circle_id, value in (circles or {}).items()
        },
        cert_fingerprint="a" * 64,
        operator_id=uuid.uuid4() if operator_role is not None else None,
        operator_role=operator_role,
    )


#: Membership start for callers whose join time is not what the test is about.
#: Early enough that every fixture's content was distributed after it, so a
#: role-focused test keeps testing roles.
LONG_AGO = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)


def submission(*, submitter: uuid.UUID = ORG, state: SubmissionState) -> Submission:
    """A detached Submission carrying only what the predicates read."""
    return Submission(id=uuid.uuid4(), submitter_org_id=submitter, state=state)


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
    assert can_view_submission_receipts(ctx, draft) is False
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
# System administration
# ---------------------------------------------------------------------------
def test_a_machine_identity_at_the_admin_org_is_the_instance():
    assert is_system_admin(context(org_type=OrgType.ADMIN)) is True


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (OperatorRole.SYSTEM_ADMIN, True),
        (OperatorRole.ORG_ADMIN, False),
        (OperatorRole.ANALYST, False),
    ],
)
def test_a_human_at_the_isac_needs_the_system_admin_role(role, expected):
    """Employment is not authority.

    This is the operator branch of `is_system_admin`, which the HTTP surface
    cannot reach today because no portal session exists yet — so without this
    test the rule "an analyst who happens to work at the ISAC is an analyst"
    would be an unverified comment.
    """
    ctx = context(org_type=OrgType.ADMIN, operator_role=role)
    assert is_system_admin(ctx) is expected


@pytest.mark.parametrize("org_type", [OrgType.GSIB, OrgType.SECTION9, OrgType.CRIT_INFRA])
def test_no_member_org_can_be_a_system_admin(org_type):
    """Not even one holding the system_admin operator role.

    `org_type` is a database field a member cannot set, and it gates first.
    """
    ctx = context(org_type=org_type, operator_role=OperatorRole.SYSTEM_ADMIN)
    assert is_system_admin(ctx) is False


# ---------------------------------------------------------------------------
# Organisation administration
# ---------------------------------------------------------------------------
def test_an_org_admin_may_manage_only_their_own_org():
    ctx = context(operator_role=OperatorRole.ORG_ADMIN)
    assert can_manage_org(ctx, ORG) is True
    assert can_manage_org(ctx, OTHER_ORG) is False


def test_an_analyst_may_manage_no_org():
    ctx = context(operator_role=OperatorRole.ANALYST)
    assert can_manage_org(ctx, ORG) is False


def test_a_machine_identity_may_not_manage_its_own_org():
    """A compromised member certificate must not mint itself a successor.

    `operator_role` is None for mTLS, so the org-admin branch cannot be reached
    by a machine. Certificate rotation is deliberately a human or ISAC action.
    """
    assert can_manage_org(context(), ORG) is False


def test_the_isac_may_manage_any_org():
    assert can_manage_org(context(org_type=OrgType.ADMIN), OTHER_ORG) is True


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
    ctx = context(org_type=OrgType.ADMIN)
    assert can_administer_circle(ctx, CIRCLE) is True
    assert can_administer_circle(ctx, OTHER_CIRCLE) is True


def test_a_suspended_isac_administers_nothing():
    """The status check comes first here as it does everywhere else."""
    for status in INACTIVE:
        ctx = context(org_type=OrgType.ADMIN, status=status)
        assert can_administer_circle(ctx, CIRCLE) is False


def test_the_isac_does_not_read_circles_it_has_not_joined():
    """No administrative bypass here, deliberately.

    An ISAC that wants to read a circle joins it, visibly, so that a member's
    view of who receives their content is complete.
    """
    ctx = context(org_type=OrgType.ADMIN)
    assert is_system_admin(ctx) is True
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
    isac = context(org_type=OrgType.ADMIN, org_id=OTHER_ORG)

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
    assert can_transition_submission(context(org_type=OrgType.ADMIN), record, target) is False


# ---------------------------------------------------------------------------
# Submission visibility
# ---------------------------------------------------------------------------
def test_submissions_are_visible_to_their_submitter_and_the_isac():
    record = submission(state=SubmissionState.DRAFT)
    assert can_view_submission(context(), record) is True
    assert can_view_submission(context(org_type=OrgType.ADMIN, org_id=OTHER_ORG), record) is True
    assert can_view_submission(context(org_id=OTHER_ORG), record) is False


def test_receipts_are_visible_to_their_submitter_and_the_isac_only():
    """Not to a fellow circle member.

    Which firms attend to which threats is not an inference members may draw
    about one another.
    """
    record = submission(state=SubmissionState.DISTRIBUTED)
    peer = context(org_id=OTHER_ORG, circles={CIRCLE: CircleRole.MEMBER})
    assert can_view_submission_receipts(context(), record) is True
    assert can_view_submission_receipts(peer, record) is False


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
