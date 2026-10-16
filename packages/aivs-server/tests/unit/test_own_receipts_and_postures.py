"""A member's own receipts and postures are read staff side, and only its own (Phase P slice 3e).

The member login may record a retrieval and read no receipt, and holds nothing
on ``org_postures`` (R26). What a member's page, pack and lead time still need
of its own rows is read on the staff login (``services.member_staff_reads``),
where the organisation key is the only thing between one firm and every
other's. Each test has a peer -- the vendor that filed the content -- retrieve
it in the portal and fix the vulnerability, through the real writers, and asks
the reader's question: none of it comes back as the reader's. The peer's own
answer is checked too, so a test cannot pass on a write that never happened.
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import AckVia, OrgStatus, OrgType, PostureStatus
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.memberships import load_circle_grants
from aivs_server.db.models import Acknowledgment
from aivs_server.services.member_staff_reads import (
    own_actioned_count,
    own_evidence_pack,
    own_last_portal_read,
    own_posture_on,
    own_retrievals,
)
from aivs_server.services.member_staff_writes import record_own_posture
from aivs_server.services.posture import VexStatement
from aivs_server.services.receipts import record_retrievals
from tests.unit.test_vulnerability_page import build_case

pytestmark = [pytest.mark.db, pytest.mark.requirement("SF-91")]

ACTIONED = frozenset({PostureStatus.FIXED, PostureStatus.NOT_AFFECTED})


@pytest.fixture
async def case(
    client,
    session,
    settings,
    isac_org,
    make_org,
    make_cert,
    make_operator,
    make_circle,
    join_circle,
):
    return await build_case(
        client,
        session,
        settings,
        isac_org,
        make_org=make_org,
        make_cert=make_cert,
        make_operator=make_operator,
        make_circle=make_circle,
        join_circle=join_circle,
    )


async def _member(session, org) -> AuthContext:
    return AuthContext(
        org_id=org.id,
        org_slug=org.slug,
        org_type=OrgType.GSIB,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.MTLS,
        circles=await load_circle_grants(session, org.id),
    )


@pytest.fixture
async def acted(app, session, case):
    """The peer read the shared submission in the portal and fixed the vulnerability."""
    now = dt.datetime.now(dt.UTC)
    peer = await _member(session, case["vendor"])
    await record_retrievals(
        session,
        org_id=peer.org_id,
        submission_ids=[case["shared"]],
        via=AckVia.PORTAL,
        actor_ref=None,
        now=now,
    )
    await session.commit()
    await record_own_posture(
        session,
        peer,
        vulnerability_id=case["stix_id"],
        statement=VexStatement(status=PostureStatus.FIXED),
        now=now,
    )
    await session.commit()
    return await _member(session, case["reader_org"]), peer


async def test_a_peers_posture_is_not_shown_as_the_members(session, case, acted):
    member, peer = acted
    assert await own_posture_on(session, peer, case["stix_id"]) == PostureStatus.FIXED.value
    assert await own_posture_on(session, member, case["stix_id"]) is None


async def test_a_peers_actioned_posture_is_not_counted_as_the_members(session, case, acted):
    member, peer = acted
    assert await own_actioned_count(session, peer, [case["stix_id"]], ACTIONED) == 1
    assert await own_actioned_count(session, member, [case["stix_id"]], ACTIONED) == 0


async def test_a_peers_retrieval_is_not_the_members(session, case, acted):
    member, peer = acted
    shared = frozenset({case["shared"]})
    assert await own_retrievals(session, peer, shared) == shared
    assert await own_retrievals(session, member, shared) == frozenset()


async def test_a_peers_portal_read_is_not_the_members_last_read(session, case, acted):
    member, peer = acted
    assert await own_last_portal_read(session, peer, [case["shared"]]) is not None
    assert await own_last_portal_read(session, member, [case["shared"]]) is None


async def test_the_pack_holds_the_members_own_receipts_and_posture(session, case, acted):
    member, _peer = acted
    own_receipts = await session.scalar(
        select(func.count())
        .select_from(Acknowledgment)
        .where(Acknowledgment.org_id == member.org_id)
    )

    drawn = await own_evidence_pack(session, member, case["stix_id"], now=dt.datetime.now(dt.UTC))

    assert drawn is not None
    assert len(drawn.body["receipts"]) == own_receipts
    assert drawn.body["posture"] is None
