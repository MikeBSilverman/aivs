"""Readiness refuses a database connection that could rewrite the audit log.

The append-only triggers hold only against a role that is not a superuser, not
the tables' owner and not a member of the owner. The migration step refuses to
grant such a role, but nothing stopped the application from *connecting* as
one: a deployment that pointed ``AIVS_DATABASE_URL`` at the owner ran, healthy,
with the means to rewrite its own evidence. Outside ``dev`` the readiness probe
now asks the connection who it is.

The suite itself connects as the embedded cluster's superuser, which is the
case refused here; tests that need a ready instance take ``safe_database_role``.
Roles are cluster-wide, so their names derive from the test database's.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

from aivs_server.db.grants import connection_role_problem
from tests.conftest import TEST_DATABASE_URL

pytestmark = pytest.mark.db

_PREFIX = make_url(TEST_DATABASE_URL).database
PLAIN_ROLE = f"{_PREFIX}_ready_plain"
OWNER_MEMBER_ROLE = f"{_PREFIX}_ready_owner_member"


@pytest.fixture
async def probe_roles(engine, _schema) -> AsyncIterator[None]:
    """A plain role, and one that is a member of the role owning the tables."""
    async with engine.connect() as connection:
        owner = (await connection.execute(text("SELECT current_user"))).scalar_one()
        for role in (PLAIN_ROLE, OWNER_MEMBER_ROLE):
            await connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
            await connection.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
        await connection.execute(text(f'GRANT "{owner}" TO "{OWNER_MEMBER_ROLE}"'))
        await connection.commit()
    yield
    async with engine.connect() as connection:
        for role in (PLAIN_ROLE, OWNER_MEMBER_ROLE):
            await connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
        await connection.commit()


async def _problem_as(session, role: str | None) -> str | None:
    if role is not None:
        await session.execute(text(f'SET LOCAL ROLE "{role}"'))
    return await connection_role_problem(session)


@pytest.mark.requirement("NFR-S6")
async def test_a_superuser_connection_is_a_problem(session):
    assert "superuser" in (await _problem_as(session, None) or "")


@pytest.mark.requirement("NFR-S6")
async def test_a_member_of_the_tables_owner_is_a_problem(session, probe_roles):
    assert "owns" in (await _problem_as(session, OWNER_MEMBER_ROLE) or "")


@pytest.mark.requirement("NFR-S6")
async def test_a_role_that_is_neither_is_not(session, probe_roles):
    assert await _problem_as(session, PLAIN_ROLE) is None


@pytest.fixture
def hardened(app, monkeypatch):
    """The suite's app as a staging instance, connected as the suite is: a superuser."""
    monkeypatch.setattr(
        app.state, "settings", app.state.settings.model_copy(update={"environment": "staging"})
    )


@pytest.mark.requirement("NFR-S6")
async def test_readiness_refuses_an_unsafe_connection_outside_dev(client, hardened):
    response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "database": "refused"}


@pytest.fixture
def dev(app, monkeypatch):
    monkeypatch.setattr(
        app.state, "settings", app.state.settings.model_copy(update={"environment": "dev"})
    )


@pytest.mark.requirement("NFR-S6")
async def test_readiness_does_not_ask_in_dev(client, dev):
    response = await client.get("/readyz")

    assert response.status_code == 200
    assert response.json()["database"] == "ok"
