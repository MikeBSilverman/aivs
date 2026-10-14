"""Membership changes to one circle are serialised; other circles are not.

Add, remove and reconcile read the open intervals and then write. Side by side
they interleaved (Phase A review): "already belonged" reported for a member
just removed, a repair landing on an interval just closed, and two reconciles
inserting the same rule row, the second a 500.
"""

from __future__ import annotations

import asyncio
import datetime as dt

import pytest

from aivs_schemas.enums import CircleRole, OrgType
from aivs_server.services.circles import add_circle_members, remove_circle_member
from tests.conftest import is_blocked

pytestmark = pytest.mark.db


async def test_a_removal_waits_for_an_open_addition_to_the_same_circle_only(
    open_session, isac_ctx, make_org, make_circle, join_circle
):
    busy, quiet = await make_circle("busy"), await make_circle("quiet")
    newcomer = await make_org("newcomer", org_type=OrgType.GSIB)
    leaver = await make_org("leaver", org_type=OrgType.GSIB)
    for circle in (busy, quiet):
        await join_circle(leaver, circle)
    now = dt.datetime.now(dt.UTC)
    adder, remover, elsewhere = open_session(), open_session(), open_session()

    await add_circle_members(
        adder,
        isac_ctx,
        circle=busy,
        organisations=[newcomer],
        role=CircleRole.MEMBER,
        joined_at=None,
        now=now,
    )
    other_circle, _done = await is_blocked(
        remove_circle_member(
            elsewhere,
            isac_ctx,
            circle_id=quiet.id,
            org_id=leaver.id,
            now=now,
            via="api",
            ended_by="operator",
        )
    )
    same_circle, task = await is_blocked(
        remove_circle_member(
            remover,
            isac_ctx,
            circle_id=busy.id,
            org_id=leaver.id,
            now=now,
            via="api",
            ended_by="operator",
        )
    )
    await adder.rollback()
    await asyncio.wait_for(task, timeout=5)

    assert other_circle is False
    assert same_circle is True
