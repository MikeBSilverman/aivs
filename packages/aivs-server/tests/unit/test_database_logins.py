"""Each request runs on the database login its caller is entitled to (Phase P, slice 3a).

The ISAC's organisations run on the staff login, every member organisation
and every handler whose caller is not yet known on the member login;
authentication itself on the staff login, in ``auth.staff_auth`` (slice 3e),
keyed on what the request presented. Two engines over the
one test database stand in for the two logins, each labelling the statements
it runs, so a test can say which login served which request. The member one
connects as the suite's real member login: a read the grants refuse it fails
the request, where a label alone would only move.

What the logins may read is slice 3c's to narrow. This proves the routing that
narrowing will rely on: a member request that reached the staff engine would
reach whatever the staff login can, whatever the grants say. The staff reads
a member's request makes are of its own records, on sessions of their own,
through ``services.attribution``, ``services.member_staff_reads`` and
``services.member_staff_writes``: here their sessionmakers are given a third
engine, labelled ``own``, and authentication's a fourth, labelled ``auth``, so
a staff statement on a member's request that none of them made shows up on the
routed ``staff`` engine and fails.
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
from tests.conftest import TEST_MEMBER_DATABASE_URL, proxy_headers
from tests.unit.test_portal import make_operator as portal_make_operator
from tests.unit.test_portal import sign_in
from tests.unit.test_submission_workflow import create_draft

pytestmark = pytest.mark.db

API = "/api/v1/submissions"


class Seen(list[str]):
    """Which engine ran each statement: ``staff``, ``member``, ``own`` (the staff
    reads and writes of a member's own records) or ``auth`` (authentication)."""


def _labelled(url: str, label: str, seen: Seen) -> AsyncEngine:
    engine = create_async_engine(url)

    @event.listens_for(engine.sync_engine, "before_cursor_execute")
    def _seen(_conn: Any, _cursor: Any, _statement: str, *_args: Any) -> None:
        seen.append(label)

    return engine


@pytest.fixture
async def logins(app, settings, monkeypatch) -> Iterator[Seen]:
    """Separate staff and member engines on the test database, recording which ran."""
    from aivs_server.db import engine as engine_module  # noqa: PLC0415 - the fixture's own swap

    seen = Seen()
    url = settings.database_url.get_secret_value()
    staff = _labelled(url, "staff", seen)
    member = _labelled(TEST_MEMBER_DATABASE_URL, "member", seen)
    own = _labelled(url, "own", seen)
    own_records = async_sessionmaker(bind=own, expire_on_commit=False, autoflush=False)
    for module in ("attribution", "member_staff_reads", "member_staff_writes"):
        monkeypatch.setattr(f"aivs_server.services.{module}.get_sessionmaker", lambda: own_records)
    auth = _labelled(url, "auth", seen)
    authentication = async_sessionmaker(bind=auth, expire_on_commit=False, autoflush=False)
    monkeypatch.setattr("aivs_server.auth.staff_auth.get_sessionmaker", lambda: authentication)
    engine_module._engine = staff
    engine_module._sessionmaker = async_sessionmaker(
        bind=staff, expire_on_commit=False, autoflush=False
    )
    engine_module._member_engine = member
    engine_module._member_sessionmaker = async_sessionmaker(
        bind=member, expire_on_commit=False, autoflush=False
    )
    yield seen
    for engine in (staff, member, own, auth):
        await engine.dispose()


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
async def test_a_members_api_request_reads_only_its_own_filings_on_the_staff_login(
    client, logins, make_org, make_cert
):
    member = await make_org("routed-member")
    pem, _ = await make_cert(member)
    logins.clear()

    listed = await client.get(API, headers=proxy_headers(pem))

    assert listed.status_code == 200, listed.text
    assert "member" in logins
    assert "own" in logins, "the list was read staff side"
    assert "staff" not in logins


@pytest.mark.requirement("SF-89")
async def test_a_members_own_submission_reads_staff_side_only_through_the_two_modules(
    client, logins, make_org, make_cert
):
    """Its history, first pass and telemetry are read staff side (Phase P, slice 3c)."""
    member = await make_org("routed-detail-member")
    pem, _ = await make_cert(member)
    created = await create_draft(client, pem)
    logins.clear()

    detail = await client.get(f"{API}/{created['id']}", headers=proxy_headers(pem))
    telemetry = await client.get(f"{API}/{created['id']}/telemetry", headers=proxy_headers(pem))

    assert (detail.status_code, telemetry.status_code) == (200, 200), detail.text
    assert "own" in logins, "its own records were read staff side"
    assert "staff" not in logins


@pytest.mark.requirement("SF-89")
async def test_a_members_sign_in_is_authenticated_on_authentications_own_login(
    client, logins, session, secret_box, make_org, make_cert
):
    """Slice 3e: the member login holds nothing on ``operators`` or
    ``portal_sessions``, so a sign-in that reached it would be refused."""
    member = await make_org("routed-sign-in")
    pem, _ = await make_cert(member)
    operator, secret = await portal_make_operator(session, secret_box, member)
    logins.clear()

    await sign_in(client, operator, secret, pem)
    page = await client.get("/portal/", headers=proxy_headers(pem))

    assert page.status_code == 200, page.text
    assert "auth" in logins, "the sign-in and the session were resolved staff side"
    assert "staff" not in logins


@pytest.mark.requirement("SF-89")
async def test_an_isac_editors_api_request_is_served_by_the_staff_login(client, logins, isac):
    _org, editor = isac
    logins.clear()

    listed = await client.get(API, headers=editor)

    assert listed.status_code == 200, listed.text
    assert "staff" in logins, "the handler's work ran on the staff login"


@pytest.mark.requirement("SF-89")
async def test_a_members_portal_page_reads_only_its_own_filings_on_the_staff_login(
    client, logins, session, secret_box, make_org, make_cert
):
    member = await make_org("routed-portal-member")
    pem, _ = await make_cert(member)
    operator, secret = await portal_make_operator(session, secret_box, member)
    await sign_in(client, operator, secret, pem)
    logins.clear()

    page = await client.get("/portal/submissions", headers=proxy_headers(pem))

    assert page.status_code == 200, page.text
    assert "own" in logins, "the list was read staff side"
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
