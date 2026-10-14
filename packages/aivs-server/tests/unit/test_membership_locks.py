"""Membership changes to one circle are serialised; other circles are not.

Add, remove and reconcile read the open intervals and then write. Side by side
they interleaved (Phase A review): "already belonged" reported for a member
just removed, a repair landing on an interval just closed, and two reconciles
inserting the same rule row, the second a 500.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

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


async def test_rule_reconciliation_takes_circles_in_the_order_offboarding_does(
    session, isac_ctx, make_org, monkeypatch
):
    """Both lock the organisation, then its circles by ascending id. Reconciliation
    took them in whatever order Postgres returned, so an activation and an
    offboarding touching the same two circles could each hold one and wait for
    the other. Created here in descending id order, so storage order is wrong."""
    from aivs_server.db.models import Circle  # noqa: PLC0415 - one test
    from aivs_server.services import circles as circles_service  # noqa: PLC0415 - one test

    ids = sorted((uuid.uuid4() for _ in range(4)), reverse=True)
    for index, circle_id in enumerate(ids):
        session.add(
            Circle(
                id=circle_id,
                slug=f"ruled-{index}",
                name=f"Ruled {index}",
                auto_member_org_types=[OrgType.GSIB.value],
            )
        )
    await session.commit()
    visited: list[uuid.UUID] = []
    original = circles_service.reconcile_circle

    async def recording(session, ctx, *, circle):
        visited.append(circle.id)
        return await original(session, ctx, circle=circle)

    monkeypatch.setattr(circles_service, "reconcile_circle", recording)

    await circles_service.reconcile_circles_for_org(
        session, isac_ctx, organisation=await make_org("rule-target")
    )

    assert visited == sorted(ids)
