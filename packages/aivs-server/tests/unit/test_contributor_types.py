"""Contributors who never read: which organisation types may join a circle (SF-62).

Phase E opens contribution to vendors, researchers, the ISAC's automation and
government partners. Membership is how content is read, so a declared set
decides who may ever be a member, and every path that writes membership
consults it. Pairs: each excluded type refused, each admitted type accepted.
"""

from __future__ import annotations

import datetime as dt

import pytest

from aivs_schemas.enums import (
    CIRCLE_ELIGIBLE_ORG_TYPES,
    RULE_ELIGIBLE_ORG_TYPES,
    CircleRole,
    OrgType,
)
from aivs_server.services.circles import CircleMembershipError, add_circle_members

pytestmark = pytest.mark.db


@pytest.mark.parametrize("org_type", [OrgType.RESEARCHER, OrgType.AUTOMATION])
async def test_a_contributor_that_never_reads_cannot_be_added(
    session, isac_ctx, make_org, make_circle, org_type
):
    contributor = await make_org(f"c-{org_type.value}", org_type=org_type)
    circle = await make_circle("section9")

    with pytest.raises(CircleMembershipError, match="never read a circle"):
        await add_circle_members(
            session,
            isac_ctx,
            circle=circle,
            organisations=[contributor],
            role=CircleRole.MEMBER,
            joined_at=None,
            now=dt.datetime.now(dt.UTC),
        )


@pytest.mark.parametrize("org_type", [OrgType.VENDOR, OrgType.GOVERNMENT, OrgType.GSIB])
async def test_a_reader_type_can_be_added_by_name(
    session, isac_ctx, make_org, make_circle, org_type
):
    reader = await make_org(f"r-{org_type.value}", org_type=org_type)
    circle = await make_circle("coordination")

    added = await add_circle_members(
        session,
        isac_ctx,
        circle=circle,
        organisations=[reader],
        role=CircleRole.MEMBER,
        joined_at=None,
        now=dt.datetime.now(dt.UTC),
    )

    assert added == [reader.id]


def test_vendors_and_government_are_named_in_never_matched_by_a_rule():
    assert {OrgType.VENDOR, OrgType.GOVERNMENT} <= CIRCLE_ELIGIBLE_ORG_TYPES
    assert not {OrgType.VENDOR, OrgType.GOVERNMENT} & RULE_ELIGIBLE_ORG_TYPES
    assert RULE_ELIGIBLE_ORG_TYPES <= CIRCLE_ELIGIBLE_ORG_TYPES, "a rule never admits more"
    assert not {OrgType.RESEARCHER, OrgType.AUTOMATION} & CIRCLE_ELIGIBLE_ORG_TYPES
