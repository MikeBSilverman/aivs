"""A locked load returns the row as it is now, not as the request first read it.

Sessions keep loaded objects (``expire_on_commit=False``), and a plain
``session.get(..., with_for_update=True)`` takes the lock but hands back the
object already in the identity map, attributes unrefreshed. ``resolve_session``
loads the caller's own organisation at the start of every request, so a member
quarantining itself read the status it had then: after the ISAC suspended it,
the quarantine wrote ``quarantined`` over ``suspended``, and a reconnection
returned it to ``active`` (identity-lifecycle review, L-C2).
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import update

from aivs_schemas.enums import OperatorRole, OrgStatus, OrgType, SubmissionState
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.db.models import Organization, Submission
from aivs_server.services.org_status import change_org_status, load_org_for_update
from aivs_server.services.quarantine import QuarantineError, quarantine_org
from aivs_server.services.submissions import load_submission

pytestmark = pytest.mark.db


def _person(org_id: uuid.UUID, org_type: OrgType, role: OperatorRole) -> AuthContext:
    return AuthContext(
        org_id=org_id,
        org_slug="caller",
        org_type=org_type,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.PORTAL_SESSION,
        operator_id=uuid.uuid4(),
        operator_roles=frozenset({role}),
    )


async def _suspend_elsewhere(open_session, org_id: uuid.UUID) -> None:
    desk = open_session()
    organisation = await load_org_for_update(desk, org_id)
    await change_org_status(
        desk,
        _person(uuid.uuid4(), OrgType.ADMIN, OperatorRole.ISAC_MEMBERSHIP),
        organisation=organisation,
        target=OrgStatus.SUSPENDED,
        via="api",
    )
    await desk.commit()


async def test_a_self_quarantine_after_a_suspension_reads_the_suspension(open_session, make_org):
    """The quarantine is refused: only an active organisation can be quarantined."""
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    request = open_session()
    first_read = await request.get(Organization, org.id)
    assert first_read.status is OrgStatus.ACTIVE
    await _suspend_elsewhere(open_session, org.id)

    locked = await load_org_for_update(request, org.id)

    assert locked.status is OrgStatus.SUSPENDED
    with pytest.raises(QuarantineError):
        await quarantine_org(
            request,
            _person(org.id, OrgType.GSIB, OperatorRole.ORG_ADMIN),
            organisation=locked,
            reason="we are compromised",
            now=dt.datetime.now(dt.UTC),
        )


async def test_a_self_quarantine_with_nothing_in_between_goes_ahead(open_session, make_org):
    """The pair: the same sequence with no suspension quarantines."""
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    request = open_session()
    await request.get(Organization, org.id)

    locked = await load_org_for_update(request, org.id)
    await quarantine_org(
        request,
        _person(org.id, OrgType.GSIB, OperatorRole.ORG_ADMIN),
        organisation=locked,
        reason="we are compromised",
        now=dt.datetime.now(dt.UTC),
    )

    assert locked.status is OrgStatus.QUARANTINED


async def test_a_locked_submission_load_reads_a_state_committed_since_the_first_read(
    open_session, make_validated
):
    """A route that changes a submission decides on its current state; the
    unlocked read, which changes nothing, may keep what it had."""
    submission_id = await make_validated("withdrawn meanwhile")
    request = open_session()
    unlocked = await load_submission(request, submission_id, for_update=False)
    assert unlocked.state is SubmissionState.VALIDATED

    submitter = open_session()
    await submitter.execute(
        update(Submission)
        .where(Submission.id == submission_id)
        .values(state=SubmissionState.WITHDRAWN)
    )
    await submitter.commit()
    locked = await load_submission(request, submission_id, for_update=True)

    assert locked.state is SubmissionState.WITHDRAWN
