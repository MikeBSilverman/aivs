"""What the member login may do, as the migration step leaves it (Phase P, slice 3c).

Every member organisation's request runs on one login, so whatever that login
may read, SQL on the member path may read for every member. The migration step
grants it from an allow-list (``db.grants.MEMBER_GRANTS``); this file holds a
classification of its own, of every table and every updatable column, and asks
Postgres -- connected as the member login, after a real migration -- what it
actually allows. A table a later migration adds fails here until someone
classifies it, and a grant that drifts from the classification fails here
whichever of the two was edited.

Then it attempts what the grants exist to refuse, and the neighbouring
operation the member path needs, so a refusal is shown to be the grant's and
not the database's in general.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from typing import Final

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url

from aivs_server.db.engine import PrivilegeRefusedError
from tests.conftest import TEST_DATABASE_URL
from tests.migrations.test_app_role_grants import _admin, _migrate

pytestmark = [pytest.mark.db, pytest.mark.slow]

_READ: Final = frozenset({"SELECT"})
_WRITE_ONLY: Final = frozenset({"INSERT"})
_NOTHING: Final = frozenset[str]()

#: Every table, and the table-level privileges the member login holds on it.
CLASSIFICATION: Final[dict[str, frozenset[str]]] = {
    # Who filed what, and what says it by another route: written, never read.
    "attribution.submitters": _WRITE_ONLY,
    # Every firm's receipts (SF-15 reserves them to the ISAC's reviewers):
    # recorded on the member path, read staff side (slice 3e).
    "public.acknowledgments": _WRITE_ONLY,
    "public.audit_log": _WRITE_ONLY,
    "public.submission_transitions": _WRITE_ONLY,
    "public.taxii_status": _WRITE_ONLY,
    "public.webhook_deliveries": _WRITE_ONLY,
    # The member path neither reads nor writes these.
    "public.alembic_version": _NOTHING,
    "public.audit_stream_modes": _NOTHING,
    "public.count_snapshots": _NOTHING,
    "public.detection_state": _NOTHING,
    "public.email_deliveries": _NOTHING,
    "public.inbound_emails": _NOTHING,
    # Authentication runs on the staff login (auth.staff_auth, slice 3e): every
    # operator's password hash, a peer's lockout and its sessions.
    "public.operators": _NOTHING,
    "public.org_postures": _NOTHING,
    "public.pending_notices": _NOTHING,
    # A member's own webhooks are read and written staff side (slice 3g); the
    # member login read every firm's delivery URLs.
    "public.webhooks": _NOTHING,
    "public.portal_sessions": _NOTHING,
    "public.submission_milestones": _NOTHING,
    "public.submission_triage": _NOTHING,
    "public.model_reads": _NOTHING,
    # Every read and write of a document is staff side, decided by the
    # caller's own grant (services.documents): with SELECT, SQL on the member
    # path could list every firm's documents, owners and titles.
    "public.documents": _NOTHING,
    "public.document_versions": _NOTHING,
    "public.document_comments": _NOTHING,
    "public.document_grants": _NOTHING,
    "public.document_reads": _NOTHING,
    # Which code finds which firm: with SELECT, SQL on the member path could
    # read every firm's code hash, and name any firm it held a code for.
    "public.org_sharing_codes": _NOTHING,
    # Read, and written only where listed.
    "public.circle_memberships": _READ,
    "public.circles": _READ,
    "public.client_certificates": _READ,
    "public.distributions": _READ,
    "public.embargoes": _READ,
    "public.instance_controls": _READ,
    "public.organizations": _READ,
    "public.sector_events": _READ,
    "public.stix_objects": frozenset({"SELECT", "INSERT"}),
    "public.submissions": frozenset({"SELECT", "INSERT"}),
    "public.taxii_collections": _READ,
}

#: The columns the member login may UPDATE; every other column of every table
#: it may not. No table is updatable as a whole.
UPDATABLE: Final[dict[str, frozenset[str]]] = {
    # Status and settings are written staff side (member_staff_writes).
    "public.organizations": frozenset({"updated_at"}),
}

_TABLE_PRIVILEGES: Final = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES")


class Logins:
    def __init__(
        self, owner_url: URL, staff_role: str, member_role: str, member_password: str
    ) -> None:
        self.owner_url = owner_url.render_as_string(hide_password=False)
        self.member_url = owner_url.set(username=member_role, password=member_password)
        self.staff_role = staff_role
        self.member_role = member_role


@pytest.fixture(scope="module")
def logins() -> Iterator[Logins]:
    """A scratch database migrated as the owner, naming a staff and a member login."""
    test_url = make_url(TEST_DATABASE_URL)
    database = f"{test_url.database}_memberlogin"
    staff, member = f"{database}_staff", f"{database}_member"
    staff_password, member_password = secrets.token_hex(16), secrets.token_hex(16)
    admin = _admin(test_url)
    with admin.connect() as connection:
        connection.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
        for role in (staff, member):
            connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
        connection.execute(text(f'CREATE DATABASE "{database}"'))
        # Passwords, because CI's Postgres checks them; hex only, so safe here.
        connection.execute(text(f"CREATE ROLE \"{staff}\" LOGIN PASSWORD '{staff_password}'"))
        connection.execute(text(f"CREATE ROLE \"{member}\" LOGIN PASSWORD '{member_password}'"))
    made = Logins(test_url.set(database=database), staff, member, member_password)
    try:
        _migrate(made.owner_url, staff, member_role=member)
        yield made
    finally:
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
            for role in (staff, member):
                connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
        admin.dispose()


def _granted(logins: Logins) -> tuple[dict[str, frozenset[str]], dict[str, frozenset[str]]]:
    """What Postgres says the member login may do: per table, and UPDATE per column."""
    engine = create_engine(logins.member_url)
    try:
        with engine.connect() as connection:
            tables = [
                f"{schema}.{name}"
                for schema, name in connection.execute(
                    text(
                        "SELECT schemaname, tablename FROM pg_tables "
                        "WHERE schemaname IN ('public', 'attribution')"
                    )
                )
            ]
            table_privileges = {
                table: frozenset(
                    privilege
                    for privilege in _TABLE_PRIVILEGES
                    if connection.execute(
                        text("SELECT has_table_privilege(:table, :privilege)"),
                        {"table": table, "privilege": privilege},
                    ).scalar_one()
                )
                for table in tables
            }
            updatable = {
                table: frozenset(
                    column
                    for (column,) in connection.execute(
                        text(
                            "SELECT attname FROM pg_attribute "
                            "WHERE attrelid = CAST(:table AS regclass) AND attnum > 0 "
                            "AND NOT attisdropped "
                            "AND has_column_privilege(attrelid, attnum, 'UPDATE')"
                        ),
                        {"table": table},
                    )
                )
                for table in tables
            }
    finally:
        engine.dispose()
    return table_privileges, {table: columns for table, columns in updatable.items() if columns}


@pytest.mark.requirement("SF-91")
def test_every_table_is_classified_and_granted_as_classified(logins: Logins):
    table_privileges, _updatable = _granted(logins)
    assert set(table_privileges) == set(CLASSIFICATION), (
        "a table the classification does not name, or a name with no table: "
        "classify every table here and in db.grants.MEMBER_GRANTS"
    )
    assert table_privileges == CLASSIFICATION


@pytest.mark.requirement("SF-91")
def test_only_the_classified_columns_are_updatable(logins: Logins):
    _table_privileges, updatable = _granted(logins)
    assert updatable == UPDATABLE


def _as_member(logins: Logins, statement: str) -> None:
    engine = create_engine(logins.member_url)
    try:
        with engine.begin() as connection:
            connection.execute(text(statement))
    finally:
        engine.dispose()


@pytest.mark.requirement("SF-91")
@pytest.mark.parametrize(
    ("refused", "permitted"),
    [
        pytest.param(
            "SELECT org_id FROM attribution.submitters",
            "INSERT INTO attribution.submitters (submission_id, org_id) "
            "SELECT id, id FROM submissions WHERE false",
            id="who-filed-what",
        ),
        pytest.param(
            "SELECT org_id FROM audit_log",
            "INSERT INTO audit_log (actor_type, action, outcome, details) "
            "SELECT 'system', 'grant-test', 'success', '{}' WHERE false",
            id="the-audit-log",
        ),
        pytest.param(
            "UPDATE submissions SET owner_tag = owner_tag",
            "SELECT title FROM submissions",
            id="owner-tag",
        ),
        pytest.param(
            "UPDATE stix_objects SET owner_token = owner_token",
            "SELECT id FROM stix_objects",
            id="owner-token",
        ),
        pytest.param(
            "UPDATE stix_objects SET raw = raw",
            "SELECT raw FROM stix_objects",
            id="object-content",
        ),
        pytest.param(
            "INSERT INTO distributions (stix_object_id, circle_id, submission_id, date_added)"
            " SELECT id, id, id, now() FROM stix_objects WHERE false",
            "SELECT circle_id FROM distributions",
            id="publication",
        ),
        pytest.param(
            "UPDATE submissions SET proxy_confirm_by = NULL",
            "SELECT proxy_confirm_by FROM submissions",
            id="proxy-window",
        ),
        pytest.param(
            "UPDATE organizations SET status = status",
            "UPDATE organizations SET updated_at = updated_at",
            id="org-status",
        ),
        pytest.param(
            "UPDATE organizations SET digest_email = digest_email",
            "UPDATE organizations SET updated_at = updated_at",
            id="org-digest",
        ),
        pytest.param(
            "UPDATE organizations SET org_type = org_type",
            "UPDATE organizations SET updated_at = updated_at",
            id="org-type",
        ),
        pytest.param(
            "UPDATE organizations SET directory_object_id = directory_object_id",
            "UPDATE organizations SET updated_at = updated_at",
            id="org-sso-group",
        ),
        pytest.param(
            "UPDATE client_certificates SET status = 'revoked'",
            "SELECT status FROM client_certificates",
            id="certificate-revocation",
        ),
        pytest.param(
            "UPDATE client_certificates SET status = 'active' WHERE status = 'revoked'",
            "SELECT status FROM client_certificates",
            id="certificate-revival",
        ),
        pytest.param(
            "UPDATE submissions SET tlp = 'clear'",
            "SELECT tlp FROM submissions",
            id="filing-rewrite",
        ),
        pytest.param(
            "DELETE FROM stix_objects WHERE false",
            "SELECT id FROM stix_objects",
            id="object-deletion",
        ),
        pytest.param(
            "SELECT url FROM webhooks",
            "SELECT id FROM organizations",
            id="webhook-urls",
        ),
        pytest.param(
            "SELECT password_hash FROM operators",
            "SELECT id FROM organizations",
            id="operator-password-hashes",
        ),
        pytest.param(
            "INSERT INTO operators (org_id, email) SELECT id, 'x@example.org' FROM organizations"
            " WHERE false",
            "SELECT id FROM organizations",
            id="operator-insert",
        ),
        pytest.param(
            "UPDATE operators SET failed_login_count = 0",
            "SELECT id FROM organizations",
            id="operator-lockout",
        ),
        pytest.param(
            "SELECT token_hash FROM portal_sessions",
            "SELECT id FROM organizations",
            id="portal-sessions",
        ),
        pytest.param(
            "SELECT org_id, submission_id FROM acknowledgments",
            "INSERT INTO acknowledgments (id, org_id, submission_id, ack_type, via, dedupe_day)"
            " SELECT gen_random_uuid(), id, id, 'retrieved', 'taxii', current_date"
            " FROM organizations WHERE false",
            id="receipts",
        ),
        pytest.param(
            "SELECT org_id, status FROM org_postures",
            "SELECT id FROM organizations",
            id="postures",
        ),
    ],
)
def test_the_member_login_is_refused_what_its_grants_withhold(
    logins: Logins, refused: str, permitted: str
):
    """Postgres checks privileges when it plans a statement, so an empty table proves them."""
    _as_member(logins, permitted)
    with pytest.raises(PrivilegeRefusedError) as refusal:
        _as_member(logins, refused)
    # The grant's refusal, not the append-only trigger's: both are 42501.
    assert "permission denied" in str(refusal.value.__cause__)


@pytest.mark.requirement("SF-91")
def test_a_login_granted_more_by_an_earlier_release_is_narrowed(logins: Logins):
    """Slice 3a granted the member login everything the staff login holds, and a
    column grant survives ``REVOKE ALL ON ALL TABLES``: the next migration run
    takes all of it back, column grants included."""
    owner = create_engine(make_url(logins.owner_url))
    try:
        with owner.begin() as connection:
            for schema in ("public", "attribution"):
                connection.execute(
                    text(f'GRANT ALL ON ALL TABLES IN SCHEMA {schema} TO "{logins.member_role}"')
                )
            connection.execute(
                text(f'GRANT UPDATE (owner_tag) ON submissions TO "{logins.member_role}"')
            )
    finally:
        owner.dispose()

    _migrate(logins.owner_url, logins.staff_role, member_role=logins.member_role)

    table_privileges, updatable = _granted(logins)
    assert (table_privileges, updatable) == (CLASSIFICATION, UPDATABLE)
