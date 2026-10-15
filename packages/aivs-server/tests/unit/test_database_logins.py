"""Each request runs on the database login its caller is entitled to (Phase P, slice 3a).

The ISAC's organisations run on the staff login, every member organisation
and every request not yet authenticated on the member login; authentication
itself, before the caller is known, on the member login. Two engines over the
one test database stand in for the two logins, each labelling the statements
it runs, so a test can say which login served which request.

What the logins may read is slice 3c's to narrow. This proves the routing that
narrowing will rely on: a member request that reached the staff engine would
reach whatever the staff login can, whatever the grants say.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from aivs_schemas.enums import OperatorRole, OrgType
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.policy import uses_staff_database
from tests.conftest import proxy_headers
from tests.unit.test_portal import make_operator as portal_make_operator
from tests.unit.test_portal import sign_in

pytestmark = pytest.mark.db

API = "/api/v1/submissions"


def _labelled(url: str, label: str, seen: list[str]) -> AsyncEngine:
    engine = create_async_engine(url)

    @event.listens_for(engine.sync_engine, "before_cursor_execute")
    def _seen(*_args: Any, **_kwargs: Any) -> None:
        seen.append(label)

    return engine


@pytest.fixture
async def logins(app, settings) -> Iterator[list[str]]:
    """Separate staff and member engines on the test database, recording which ran."""
    from aivs_server.db import engine as engine_module  # noqa: PLC0415 - the fixture's own swap

    seen: list[str] = []
    url = settings.database_url.get_secret_value()
    staff = _labelled(url, "staff", seen)
    member = _labelled(url, "member", seen)
    engine_module._engine = staff
    engine_module._sessionmaker = async_sessionmaker(
        bind=staff, expire_on_commit=False, autoflush=False
    )
    engine_module._member_engine = member
    engine_module._member_sessionmaker = async_sessionmaker(
        bind=member, expire_on_commit=False, autoflush=False
    )
    yield seen
    await staff.dispose()
    await member.dispose()


# ---------------------------------------------------------------------------
# Who gets the staff login
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-89")
@pytest.mark.parametrize(
    ("org_type", "staff"),
    [(OrgType.ADMIN, True), (OrgType.AUTOMATION, True)]
    + [
        (org_type, False)
        for org_type in OrgType
        if org_type not in (OrgType.ADMIN, OrgType.AUTOMATION)
    ],
    ids=lambda value: getattr(value, "value", str(value)),
)
def test_only_the_isacs_organisations_use_the_staff_login(org_type, staff):
    import uuid  # noqa: PLC0415 - one use

    ctx = AuthContext(
        org_id=uuid.uuid4(),
        org_slug="any",
        org_type=org_type,
        org_status="active",
        auth_method=AuthMethod.MTLS,
    )
    assert uses_staff_database(ctx) is staff


# ---------------------------------------------------------------------------
# Which login served each request
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-89")
async def test_a_members_api_request_never_touches_the_staff_login(
    client, logins, make_org, make_cert
):
    member = await make_org("routed-member")
    pem, _ = await make_cert(member)
    logins.clear()

    listed = await client.get(API, headers=proxy_headers(pem))

    assert listed.status_code == 200, listed.text
    assert "member" in logins
    assert "staff" not in logins


@pytest.mark.requirement("SF-89")
async def test_an_isac_editors_api_request_is_served_by_the_staff_login(client, logins, isac):
    _org, editor = isac
    logins.clear()

    listed = await client.get(API, headers=editor)

    assert listed.status_code == 200, listed.text
    assert "staff" in logins, "the handler's work ran on the staff login"


@pytest.mark.requirement("SF-89")
async def test_a_members_portal_page_never_touches_the_staff_login(
    client, logins, session, secret_box, make_org, make_cert
):
    member = await make_org("routed-portal-member")
    pem, _ = await make_cert(member)
    operator, secret = await portal_make_operator(session, secret_box, member)
    await sign_in(client, operator, secret, pem)
    logins.clear()

    page = await client.get("/portal/submissions", headers=proxy_headers(pem))

    assert page.status_code == 200, page.text
    assert "staff" not in logins


@pytest.mark.requirement("SF-89")
async def test_an_isac_editors_portal_page_is_served_by_the_staff_login(
    client, logins, session, secret_box, isac_org, make_cert
):
    pem, _ = await make_cert(isac_org)
    operator, secret = await portal_make_operator(
        session, secret_box, isac_org, roles=(OperatorRole.ISAC_EDITOR,), email="ed@isac.test"
    )
    await sign_in(client, operator, secret, pem)
    logins.clear()

    page = await client.get("/portal/review", headers=proxy_headers(pem))

    assert page.status_code == 200, page.text
    assert "staff" in logins


@pytest.mark.requirement("SF-89")
async def test_an_unauthenticated_request_runs_on_the_member_login(client, logins):
    logins.clear()

    page = await client.get("/portal/login")

    assert page.status_code == 200, page.text
    assert "staff" not in logins
