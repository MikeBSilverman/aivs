"""A member's request reads its own person's record staff side, and only that person's (slice 3e).

The member login holds nothing on ``operators``: it could read every
operator's password hash (Phase P slice 3e). What a member's page still needs of
its own person -- the name in the header, the reading depth they chose -- is
read and written on the staff login by ``services.member_staff_reads`` and
``member_staff_writes``, keyed on the operator authentication resolved. Each
test sets a peer's record first, so a read that lost its key would find the
peer's.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from aivs_schemas.enums import OperatorRole, OrgStatus, OrgType, ReadingDepth
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.db.models import Operator
from aivs_server.services.member_staff_reads import own_default_depth
from aivs_server.services.member_staff_writes import set_own_default_depth
from tests.conftest import proxy_headers
from tests.unit.test_portal import make_operator, sign_in

pytestmark = [pytest.mark.db, pytest.mark.requirement("SF-89")]


@pytest.fixture
async def people(session, secret_box, make_org, make_cert):
    """A peer's person, made first, and a member's: ``(own, secret, pem, peer)``."""
    peer_org = await make_org("own-records-peer-firm", org_type=OrgType.GSIB)
    member_org = await make_org("own-records-member-firm", org_type=OrgType.GSIB)
    peer, _ = await make_operator(session, secret_box, peer_org)
    own, secret = await make_operator(session, secret_box, member_org)
    peer.display_name = "Peer Person"
    peer.default_depth = ReadingDepth.TECHNICAL
    own.display_name = "Own Person"
    await session.commit()
    for person in (own, peer):
        await session.refresh(person)
    pem, _ = await make_cert(member_org)
    return own, secret, pem, peer


def _signed_in(operator: Operator) -> AuthContext:
    return AuthContext(
        org_id=operator.org_id,
        org_slug="own-records-member-firm",
        org_type=OrgType.GSIB,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.PORTAL_SESSION,
        operator_id=operator.id,
        operator_roles=frozenset({OperatorRole.ANALYST}),
    )


async def test_the_portal_names_the_signed_in_person_and_no_one_else(client, people):
    own, secret, pem, _peer = people
    await sign_in(client, own, secret, pem)

    page = await client.get("/portal/", headers=proxy_headers(pem))

    assert page.status_code == 200, page.text
    assert "Own Person" in page.text
    assert "Peer Person" not in page.text


async def test_a_persons_reading_depth_is_their_own_to_read_and_set(app, session, people):
    own, _secret, _pem, peer = people
    ctx = _signed_in(own)

    assert await own_default_depth(session, ctx) is None
    assert await set_own_default_depth(session, ctx, ReadingDepth.GUIDED)
    assert await own_default_depth(session, ctx) is ReadingDepth.GUIDED

    peers_depth = await session.scalar(select(Operator.default_depth).where(Operator.id == peer.id))
    assert peers_depth is ReadingDepth.TECHNICAL
