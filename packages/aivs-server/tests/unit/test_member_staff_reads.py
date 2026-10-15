"""A member's own records, read on the staff login, are that member's alone (Phase P, slice 3c).

``services.member_staff_reads`` opens a staff session on a member's behalf, so
the organisation filter in each function is the one guard on that connection.
Where the route reads nothing else first, its pair test drives the route:
``test_taxii_inbox`` (the status resource, the allowance), ``test_connection_health``
(last collected, webhooks), ``test_auditor`` (the audit page). Here are the
three a route refuses before it reads -- history, first pass and telemetry
answer 404 for a peer's submission -- so through the route a dropped filter
could not be seen. These call each function as a route that forgot its own
check would: with a member's context and a peer's submission. Every row is
made by its own writer.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from aivs_schemas.enums import OrgStatus, OrgType
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.db.models import CountSubject
from aivs_server.services.count_snapshots import K_ANONYMITY, publish_if_changed
from aivs_server.services.member_staff_reads import (
    first_pass_of,
    submission_history,
    telemetry_snapshot,
)
from aivs_server.services.triage import triage_pending
from tests.conftest import TEST_ATTRIBUTION_KEY, proxy_headers
from tests.unit.test_submission_workflow import API, create_draft

pytestmark = [pytest.mark.db, pytest.mark.requirement("SF-91")]


def _member(org) -> AuthContext:
    return AuthContext(
        org_id=org.id,
        org_slug=org.slug,
        org_type=OrgType.GSIB,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.MTLS,
    )


@pytest.fixture
async def filed(client, make_org, make_cert):
    """A submission one member filed and submitted, and a peer: ``(id, filer, peer)``."""
    filer = await make_org("own-records-filer", org_type=OrgType.GSIB)
    peer = await make_org("own-records-peer", org_type=OrgType.GSIB)
    pem, _ = await make_cert(filer)
    created = await create_draft(client, pem)
    submitted = await client.post(
        f"{API}/{created['id']}/submit", json={}, headers=proxy_headers(pem)
    )
    assert submitted.status_code == 200, submitted.text
    return uuid.UUID(created["id"]), _member(filer), _member(peer)


async def test_a_submissions_history_is_its_filers_alone(app, session, filed):
    submission_id, filer, peer = filed
    assert await submission_history(session, filer, submission_id) != []
    assert await submission_history(session, peer, submission_id) == []


async def test_a_first_pass_is_its_filers_alone(app, session, filed):
    submission_id, filer, peer = filed
    await triage_pending(session, TEST_ATTRIBUTION_KEY, now=dt.datetime.now(dt.UTC))
    assert await first_pass_of(session, filer, submission_id) is not None
    assert await first_pass_of(session, peer, submission_id) is None


async def test_telemetry_counts_are_their_filers_alone(app, session, filed):
    submission_id, filer, peer = filed
    basis = {str(uuid.uuid4()): "retrieved" for _ in range(K_ANONYMITY)}
    assert await publish_if_changed(
        session, CountSubject.TELEMETRY, str(submission_id), basis, now=dt.datetime.now(dt.UTC)
    )
    await session.commit()
    assert await telemetry_snapshot(session, filer, submission_id) is not None
    assert await telemetry_snapshot(session, peer, submission_id) is None
