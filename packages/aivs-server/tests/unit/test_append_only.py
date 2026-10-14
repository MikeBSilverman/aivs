"""The append-only guarantee, tested against a live database.

The audit trail and the transition history are the product's evidentiary value:
an ISAC's answer to "did you warn us, and when did we collect it" is these two
tables. They are protected in PostgreSQL rather than by convention, because
"the application only ever inserts" holds only while every future code path
behaves, and not at all against anyone with a database session.

That control had no test at all until an audit pointed it out. It was verified
by hand once, early, and then trusted — which is how a protection quietly stops
working. These tests attempt each forbidden operation and assert it is refused.

Note the zero-row case. The triggers are ``FOR EACH STATEMENT`` specifically so
that a probing ``DELETE ... WHERE id = -1`` fails identically to one that would
match, rather than succeeding as a silent no-op. A ``FOR EACH ROW`` trigger
would pass every other test in this file and fail that one.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

APPEND_ONLY_TABLES = ("audit_log", "submission_transitions")

#: A column that genuinely exists on each protected table.
#:
#: The UPDATE probe used to be ``SET action = 'tampered'`` for both, and
#: ``submission_transitions`` has no ``action`` column -- so PostgreSQL raised
#: UndefinedColumn before the trigger was ever consulted, and
#: ``pytest.raises(DBAPIError)`` accepted it. The UPDATE half of the guarantee
#: passed for that table with the trigger dropped. Both the real column and the
#: ``match=`` below are needed: either alone leaves the test satisfied by the
#: wrong error.
MUTABLE_COLUMN = {"audit_log": "action", "submission_transitions": "to_state"}

#: Text the trigger raises. Asserted so that only the append-only refusal
#: passes, rather than any error the statement happens to provoke.
REFUSAL = "append-only"

pytestmark = pytest.mark.db


@pytest.fixture
async def seeded_audit_row(session):
    """One row in each protected table, so mutations have something to target."""
    await session.execute(
        text(
            "INSERT INTO audit_log (actor_type, action, outcome, details) "
            "VALUES ('system', 'test.seed', 'success', '{}')"
        )
    )
    await session.commit()


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.requirement("NFR-S6")
async def test_update_is_refused(session, table, seeded_audit_row):
    """Rewriting history is refused, not merely discouraged."""
    column = MUTABLE_COLUMN[table]
    with pytest.raises(DBAPIError, match=REFUSAL):
        await session.execute(text(f"UPDATE {table} SET {column} = {column}"))  # noqa: S608
    await session.rollback()


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.requirement("NFR-S6")
async def test_delete_is_refused(session, table, seeded_audit_row):
    with pytest.raises(DBAPIError, match=REFUSAL):
        await session.execute(text(f"DELETE FROM {table}"))  # noqa: S608
    await session.rollback()


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.requirement("NFR-S6")
async def test_truncate_is_refused(session, table, seeded_audit_row):
    with pytest.raises(DBAPIError, match=REFUSAL):
        await session.execute(text(f"TRUNCATE {table}"))
    await session.rollback()


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
async def test_a_delete_matching_no_rows_is_still_refused(session, table, seeded_audit_row):
    """The reason the triggers are FOR EACH STATEMENT.

    A row-level trigger fires only for rows it matches, so a probe that matches
    nothing would succeed silently and tell an attacker the table is mutable.
    Statement-level fires regardless, so probing and doing are equally refused.
    """
    with pytest.raises(DBAPIError, match=REFUSAL):
        await session.execute(text(f"DELETE FROM {table} WHERE id = -1"))  # noqa: S608
    await session.rollback()


async def test_insert_is_permitted(session):
    """Append-only, not read-only -- the tables must still accept new records."""
    await session.execute(
        text(
            "INSERT INTO audit_log (actor_type, action, outcome, details) "
            "VALUES ('system', 'test.insert', 'success', '{}')"
        )
    )
    await session.commit()
    count = (
        await session.execute(text("SELECT count(*) FROM audit_log WHERE action = 'test.insert'"))
    ).scalar_one()
    assert count == 1


async def test_the_protection_survives_a_refused_attempt(session, seeded_audit_row):
    """A rejected mutation must leave the row untouched, not partially applied."""
    before = (await session.execute(text("SELECT count(*) FROM audit_log"))).scalar_one()

    with pytest.raises(DBAPIError, match=REFUSAL):
        await session.execute(text("DELETE FROM audit_log"))
    await session.rollback()

    after = (await session.execute(text("SELECT count(*) FROM audit_log"))).scalar_one()
    assert after == before


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.requirement("NFR-S6")
async def test_every_protected_table_carries_all_three_triggers(session, table):
    """Guards the test schema against drifting from the migration.

    ``conftest`` builds the schema from the models plus hand-written trigger DDL
    rather than by running Alembic, so the two can diverge. This asserts the
    trigger set the migration creates is actually present, which is the half of
    that risk a test can close.
    """
    rows = (
        (
            await session.execute(
                text(
                    "SELECT tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
                    "WHERE c.relname = :table AND NOT t.tgisinternal"
                ),
                {"table": table},
            )
        )
        .scalars()
        .all()
    )

    present = set(rows)
    for operation in ("update", "delete", "truncate"):
        expected = f"{table}_deny_{operation}"
        assert expected in present, f"{expected} missing; the append-only control is incomplete"
