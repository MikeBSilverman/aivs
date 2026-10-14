"""An organisation's own settings are written only while it is still a member.

The race these pin: a request authenticates while the organisation is active,
offboarding commits, then the request writes. The context in hand is the stale
one; the write must read the status under its lock and do nothing.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, update

from aivs_schemas.enums import NotificationCadence, OrgStatus, OrgType, ReadingDepth
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.db.models import Operator, Organization
from aivs_server.services.member_settings import change_notification_settings, store_default_depth

pytestmark = pytest.mark.db


async def _member(session, make_org, make_operator, slug: str) -> tuple[AuthContext, Operator]:
    org = await make_org(slug, org_type=OrgType.GSIB)
    operator, _seed = await make_operator(org)
    ctx = AuthContext(
        org_id=org.id,
        org_slug=org.slug,
        org_type=org.org_type,
        org_status=org.status,
        auth_method=AuthMethod.MTLS,
        operator_id=operator.id,
    )
    return ctx, operator


async def _offboard_behind_the_request(session, ctx: AuthContext) -> None:
    await session.execute(
        update(Organization)
        .where(Organization.id == ctx.org_id)
        .values(status=OrgStatus.OFFBOARDED)
    )
    await session.commit()


@pytest.mark.parametrize("offboarded", [False, True])
async def test_notification_settings_are_written_only_for_a_member(
    session, make_org, make_operator, offboarded
):
    ctx, _operator = await _member(
        session, make_org, make_operator, f"settings-race-{offboarded}".lower()
    )
    if offboarded:
        await _offboard_behind_the_request(session, ctx)

    written = await change_notification_settings(
        session, ctx, cadence=NotificationCadence.DAILY, digest_email="soc@race.example"
    )
    await session.commit()

    assert (written is not None) is not offboarded
    session.expire_all()
    stored = await session.scalar(
        select(Organization.digest_email).where(Organization.id == ctx.org_id)
    )
    assert (stored == "soc@race.example") is not offboarded


@pytest.mark.parametrize("offboarded", [False, True])
async def test_a_reading_depth_is_stored_only_for_a_member(
    session, make_org, make_operator, offboarded
):
    ctx, operator = await _member(
        session, make_org, make_operator, f"depth-race-{offboarded}".lower()
    )
    operator_id = operator.id
    if offboarded:
        await _offboard_behind_the_request(session, ctx)

    stored = await store_default_depth(session, ctx, ReadingDepth.GUIDED)
    await session.commit()

    assert stored is not offboarded
    session.expire_all()
    depth = await session.scalar(select(Operator.default_depth).where(Operator.id == operator_id))
    assert (depth is ReadingDepth.GUIDED) is not offboarded
