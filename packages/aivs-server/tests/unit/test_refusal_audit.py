"""Refusals name who was refused.

The 403 and 404 handlers read the caller from ``request.state``, which nothing
used to set: every ``authz.denied`` row had no actor, so the runbook's weekly
"repeated denials from one org" review could not be done, and a 404 left no
row at all. Each test is a pair across "authenticated" and "not".
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import OrgType
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db


async def _rows(session, action: str) -> list[AuditLog]:
    session.expire_all()
    return list(
        (await session.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()
    )


async def test_a_forbidden_request_is_recorded_against_the_caller(
    client, session, make_org, make_cert
):
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    member_id = member.id
    pem, _ = await make_cert(member)

    response = await client.post(
        "/api/v1/orgs",
        json={"slug": "not-allowed", "name": "Not Allowed", "org_type": "gsib"},
        headers=proxy_headers(pem),
    )

    assert response.status_code == 403
    [row] = await _rows(session, AuditAction.ACCESS_DENIED)
    assert row.org_id == member_id


async def test_a_lookup_of_an_invisible_id_is_recorded_and_an_unknown_path_is_not(
    client, session, make_org, make_cert
):
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    member_id = member.id
    pem, _ = await make_cert(member)

    authenticated = await client.get(
        f"/api/v1/submissions/{uuid.uuid4()}", headers=proxy_headers(pem)
    )
    anonymous = await client.get("/no-such-route")

    assert authenticated.status_code == anonymous.status_code == 404
    rows = await _rows(session, AuditAction.ACCESS_NOT_FOUND)
    assert [row.org_id for row in rows] == [member_id]
