"""Shared test fixtures.

Three things here are deliberate and worth reading before adding tests.

**Certificates are generated, never committed.** A repository that contains a
private key trains everyone who works in it that keys in git are normal. The
fixtures below mint a throwaway CA and client certificates in-process, which
also means the tests exercise real X.509 parsing rather than a stub.

**The proxy is simulated faithfully.** ``proxy_headers`` builds exactly what
``deploy/nginx/nginx.conf`` sends -- URL-escaped PEM in ``x-client-cert``, the
verify status, and the shared secret -- so a test that passes here is testing the
real trust boundary, not a convenient fiction.

**Cleanup explicitly disables the append-only triggers.** It has to: the audit
log and transition history refuse DELETE and TRUNCATE by design. Needing an
explicit override to reset the database is the intended friction, and it means
any test that accidentally relies on mutating audit history fails loudly.
"""

from __future__ import annotations

import asyncio
import atexit
import base64
import datetime as dt
import functools
import os
import secrets
import shutil
import tempfile
import uuid
from collections.abc import AsyncIterator, Awaitable
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote

import httpx
import pyotp
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aivs_schemas.enums import (
    TLP,
    CertStatus,
    CircleRole,
    DiscoveryScope,
    OperatorRole,
    OrgStatus,
    OrgType,
    SubmissionState,
)
from aivs_server.auth.attribution_key import AttributionKey
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.passwords import hash_password
from aivs_server.auth.policy import ISAC_FILER_TYPES
from aivs_server.auth.secretbox import SecretBox, SecretPurpose
from aivs_server.auth.sessions import establish_session
from aivs_server.config import Settings
from aivs_server.db import models
from aivs_server.db.base import Base
from aivs_server.db.grants import grant_member_role
from aivs_server.services.attribution import (
    FilingRecord,
    owner_tokens_for,
    record_filing,
    submitter_of,
)
from aivs_server.taxii.resources import truncate_to_taxii_precision


def pytest_runtest_setup(item: pytest.Item) -> None:
    """A ``horizon`` test on a parallel worker fails at once, saying how to run it.

    The audit stream serves rows below the oldest transaction open anywhere on
    the cluster, and parallel workers always have one open, so the stream
    stalls and the test would wait out its minute and fail on a timeout that
    names nothing. Refused, never skipped: a skip would read as covered.
    """
    if os.environ.get("PYTEST_XDIST_WORKER") and item.get_closest_marker("horizon"):
        pytest.fail(
            "horizon tests read the cluster-wide transaction horizon and cannot run beside "
            "parallel workers: run them serially (scripts/test-parallel.sh does both phases)",
            pytrace=False,
        )


# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------
#: Point at a scratch database, never a real one. Overridable so CI can supply
#: its own service container.
_BASE_TEST_DATABASE_URL = os.environ.get(
    "AIVS_TEST_DATABASE_URL",
    "postgresql+psycopg://aivs@127.0.0.1:55432/aivs_test",
)


def _database_for_this_process(base_url: str, worker: str | None) -> str:
    """The base database alone, or under ``pytest -n`` one of its own per worker.

    Cleanup is TRUNCATE, so two processes sharing a database block each other
    (section 3 of CLAUDE.md); each xdist worker gets ``<base>_<worker>``,
    created if it is missing. Every scratch database and role a test makes is
    named after this one, so workers never share those either.
    """
    if worker is None:
        return base_url
    url = make_url(base_url)
    name = f"{url.database}_{worker}"
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            exists = connection.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": name}
            ).first()
            if exists is None:
                connection.execute(text(f'CREATE DATABASE "{name}"'))
    finally:
        admin.dispose()
    return url.set(database=name).render_as_string(hide_password=False)


TEST_DATABASE_URL = _database_for_this_process(
    _BASE_TEST_DATABASE_URL, os.environ.get("PYTEST_XDIST_WORKER")
)

#: Fixed test secrets. Long enough to satisfy the production-strength validator,
#: and obviously fake so no one mistakes them for something to protect.
TEST_PROXY_SECRET = "test-proxy-shared-secret-not-a-real-secret-0123456789"
TEST_SESSION_SECRET = "test-session-signing-secret-not-a-real-secret-0123456789"

#: Key-encryption key for the suite. Fixed rather than random so a failure is
#: reproducible from the file alone, and base64 of exactly 32 bytes because
#: ``Settings`` refuses anything else.
TEST_SECRET_KEY = base64.b64encode(b"aivs-test-kek-not-a-real-key-32b").decode("ascii")

#: The same key as a file, because outside dev the application reads it from a
#: file only its owner can read and refuses the environment form. The suite runs
#: as "test", which is held to that posture.
_secrets_directory = Path(tempfile.mkdtemp(prefix="aivs-test-secrets-"))
TEST_SECRET_KEY_FILE = _secrets_directory / "secret-encryption-key"
TEST_SECRET_KEY_FILE.write_text(TEST_SECRET_KEY + "\n", encoding="utf-8")
TEST_SECRET_KEY_FILE.chmod(0o600)
atexit.register(shutil.rmtree, _secrets_directory, ignore_errors=True)

#: The attribution key for the suite (SF-90), fixed for the same reason, and a
#: file for the same posture. Every seeded tag and token is made with it, as the
#: application's would be.
TEST_ATTRIBUTION_KEY_BYTES = b"aivs-test-attribution-not-a-key!"
TEST_ATTRIBUTION_KEY_FILE = _secrets_directory / "attribution-key"
TEST_ATTRIBUTION_KEY_FILE.write_text(
    base64.b64encode(TEST_ATTRIBUTION_KEY_BYTES).decode("ascii") + "\n", encoding="utf-8"
)
TEST_ATTRIBUTION_KEY_FILE.chmod(0o600)
TEST_ATTRIBUTION_KEY = AttributionKey(TEST_ATTRIBUTION_KEY_BYTES)


#: The member login the suite's member engine connects as: a real role, granted
#: by ``grant_member_role`` exactly as the migration step grants a deployment's,
#: so a member request that needs a privilege the login lacks fails here rather
#: than in production. Roles are cluster-wide, so the name derives from the test
#: database's: two concurrent runs never share one. The password is minted per
#: run; CI's Postgres authenticates by password, the local one by trust.
TEST_MEMBER_ROLE = f"aivs_member_{make_url(TEST_DATABASE_URL).database}"
_TEST_MEMBER_PASSWORD = secrets.token_hex(16)
TEST_MEMBER_DATABASE_URL = (
    make_url(TEST_DATABASE_URL)
    .set(username=TEST_MEMBER_ROLE, password=_TEST_MEMBER_PASSWORD)
    .render_as_string(hide_password=False)
)


@pytest.fixture(scope="session")
def settings() -> Settings:
    """Settings for the test environment.

    ``environment="test"`` rather than ``"dev"`` so the production-posture
    validator still runs its structural checks while permitting the test-only
    conveniences.
    """
    return Settings(
        environment="test",
        instance_name="AIVS Test",
        public_base_url="https://aivs.test",
        database_url=TEST_DATABASE_URL,  # type: ignore[arg-type]
        # A login of its own, as the posture requires outside dev: the app
        # fixture's member engine connects as it.
        member_database_url=TEST_MEMBER_DATABASE_URL,  # type: ignore[arg-type]
        proxy_shared_secret=TEST_PROXY_SECRET,  # type: ignore[arg-type]
        session_secret=TEST_SESSION_SECRET,  # type: ignore[arg-type]
        secret_encryption_key_file=TEST_SECRET_KEY_FILE,
        attribution_key_file=TEST_ATTRIBUTION_KEY_FILE,
        trusted_proxy_cidrs=["127.0.0.1/32"],
        issuing_ca_certificate_file=TEST_CA_CERT_FILE,
        log_level="WARNING",
    )


@pytest.fixture(scope="session")
def attribution_key(settings: Settings) -> AttributionKey:
    """The key the app makes and checks owner tags and tokens with."""
    return AttributionKey.from_settings(settings)


@pytest.fixture(scope="session")
def secret_box(settings: Settings) -> SecretBox:
    """The suite's sealer, built from the same settings the app uses.

    Tests that seed an operator or a webhook must seal through this rather than
    writing bytes directly: the seal is bound to the row id, so a fixture that
    hand-rolled the format would pass while the application could not open it.
    """
    return SecretBox.from_settings(settings)


# ---------------------------------------------------------------------------
# Certificate authority
# ---------------------------------------------------------------------------
class TestCertificateAuthority:
    """A throwaway CA that issues client certificates for tests.

    P-256 rather than RSA purely for speed: a test suite that mints dozens of
    certificates should not spend its time on key generation.
    """

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AIVS Test CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "AIVS Test Root"),
            ]
        )
        now = dt.datetime.now(dt.UTC)
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .sign(self.key, hashes.SHA256())
        )

    def issue(
        self,
        common_name: str,
        *,
        not_before: dt.datetime | None = None,
        not_after: dt.datetime | None = None,
    ) -> tuple[str, str, x509.Certificate]:
        """Issue a client certificate.

        Returns ``(pem, sha256_fingerprint_hex, certificate)``. The validity
        window is overridable so tests can mint already-expired and
        not-yet-valid certificates without waiting.
        """
        now = dt.datetime.now(dt.UTC)
        not_before = not_before or (now - dt.timedelta(hours=1))
        not_after = not_after or (now + dt.timedelta(days=365))

        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AIVS Test Member"),
                        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    ]
                )
            )
            .issuer_name(self.certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
            )
            .sign(self.key, hashes.SHA256())
        )
        pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        return pem, fingerprint, certificate


#: One CA for the whole run, written to a file before any ``Settings`` exists, so
#: the suite runs with the issuance check *on* and exercises the path a real
#: deployment takes. Generated at test time, never committed (CLAUDE.md section 6).
TEST_CA = TestCertificateAuthority()
_ca_directory = Path(tempfile.mkdtemp(prefix="aivs-test-ca-"))
TEST_CA_CERT_FILE = _ca_directory / "issuing-ca.pem"
TEST_CA_CERT_FILE.write_bytes(TEST_CA.certificate.public_bytes(serialization.Encoding.PEM))
atexit.register(shutil.rmtree, _ca_directory, ignore_errors=True)


@pytest.fixture(scope="session")
def ca() -> TestCertificateAuthority:
    return TEST_CA


def proxy_headers(
    cert_pem: str,
    *,
    proxy_secret: str = TEST_PROXY_SECRET,
    verify: str = "SUCCESS",
) -> dict[str, str]:
    """Build the headers the reverse proxy sends for an authenticated request.

    Mirrors ``deploy/nginx/nginx.conf`` exactly: nginx forwards the certificate
    URL-escaped via ``$ssl_client_escaped_cert``, so the escaping is part of the
    contract under test rather than an implementation detail of this helper.
    """
    return {
        "x-client-verify": verify,
        "x-client-cert": quote(cert_pem, safe=""),
        "x-proxy-auth": proxy_secret,
    }


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="session")
async def engine(settings: Settings) -> AsyncIterator[Any]:
    """Session-scoped engine against the scratch database."""
    engine = create_async_engine(settings.database_url.get_secret_value(), poolclass=None)
    yield engine
    await engine.dispose()


@pytest.fixture(scope="session")
async def member_engine(settings: Settings, _schema: None) -> AsyncIterator[Any]:
    """Session-scoped engine on the test database, as the suite's member login."""
    assert settings.member_database_url is not None
    engine = create_async_engine(settings.member_database_url.get_secret_value(), poolclass=None)
    yield engine
    await engine.dispose()


@pytest.fixture(scope="session")
async def _schema(engine: Any) -> AsyncIterator[None]:
    """Create the schema once for the session, then drop it.

    Built from ``Base.metadata`` plus the hand-written protections, rather than
    by running Alembic, so that a broken migration fails its own dedicated test
    instead of preventing the whole suite from running. A separate test asserts
    that the migrations and the models agree.
    """
    async with engine.begin() as connection:
        await _refuse_to_wait_on_another_run(connection)
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
        await connection.execute(text(_DENY_MUTATION_FUNCTION))
        for table in _APPEND_ONLY_TABLES:
            for operation in ("UPDATE", "DELETE", "TRUNCATE"):
                await connection.execute(
                    text(
                        f'CREATE TRIGGER "{table.rpartition(".")[2]}_deny_{operation.lower()}" '
                        f"BEFORE {operation} ON {table} "
                        "FOR EACH STATEMENT EXECUTE FUNCTION aivs_deny_mutation();"
                    )
                )
        # Migration 65468f627fd5, as written there: offboarded is terminal.
        await connection.execute(text(_OFFBOARDED_IS_TERMINAL_FUNCTION))
        await connection.execute(
            text(
                "CREATE TRIGGER organizations_offboarded_is_terminal "
                "BEFORE UPDATE OF status ON organizations "
                "FOR EACH ROW EXECUTE FUNCTION aivs_offboarded_is_terminal();"
            )
        )
    await _create_member_role(engine)
    yield
    async with engine.begin() as connection:
        await _refuse_to_wait_on_another_run(connection)
        await connection.run_sync(Base.metadata.drop_all)
        await _drop_member_role(connection)
        await connection.execute(text("DROP TABLE IF EXISTS alembic_version"))


async def _create_member_role(engine: Any) -> None:
    """The suite's member login, granted what a deployment's is granted.

    A role left by a run that was killed is dropped first, with what it was
    granted: the tables it was granted on went with that run's ``drop_all``,
    but its grants on the schemas did not.
    """
    async with engine.begin() as connection:
        await _drop_member_role(connection)
        # Every migrated database has it, and the grants name it.
        await connection.execute(
            text("CREATE TABLE IF NOT EXISTS alembic_version (version_num varchar(32) PRIMARY KEY)")
        )
        await connection.execute(
            text(f"CREATE ROLE \"{TEST_MEMBER_ROLE}\" LOGIN PASSWORD '{_TEST_MEMBER_PASSWORD}'")
        )
        staff_role = (await connection.execute(text("SELECT current_user"))).scalar_one()
        await connection.run_sync(
            functools.partial(grant_member_role, role=TEST_MEMBER_ROLE, staff_role=staff_role)
        )


async def _drop_member_role(connection: Any) -> None:
    exists = await connection.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": TEST_MEMBER_ROLE}
    )
    if exists.scalar_one_or_none() is None:
        return
    await connection.execute(text(f'DROP OWNED BY "{TEST_MEMBER_ROLE}"'))
    await connection.execute(text(f'DROP ROLE "{TEST_MEMBER_ROLE}"'))


async def _refuse_to_wait_on_another_run(connection: Any) -> None:
    """Fail in seconds, naming the cause, rather than wait forever on another run.

    The per-test TRUNCATE already had this. Schema setup and teardown did not,
    so a second pytest process pointed at the same database (a helper session
    that did not set AIVS_TEST_DATABASE_URL) queued a DROP TABLE behind a running
    suite's open transaction, and both waited indefinitely; when the second
    process was killed, its DROP stayed queued server-side and stalled the
    first run anyway.
    """
    await connection.execute(text("SET LOCAL lock_timeout = '15s'"))


_DENY_MUTATION_FUNCTION = """
CREATE OR REPLACE FUNCTION aivs_deny_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'table % is append-only; % is not permitted', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
"""

_OFFBOARDED_IS_TERMINAL_FUNCTION = """
CREATE OR REPLACE FUNCTION aivs_offboarded_is_terminal()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF OLD.status = 'offboarded' AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION 'organisation % is offboarded; its status cannot change', OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
"""

#: Every table, ordered so the truncate statement is deterministic.
#: Tables carrying the ``aivs_deny_mutation`` triggers, as the migrations
#: give them; cleanup lifts them for its TRUNCATE and restores them.
_APPEND_ONLY_TABLES: Final[tuple[str, ...]] = (
    "audit_log",
    "submission_transitions",
    "audit_stream_modes",
    "attribution.submitters",
)

_ALL_TABLES = (
    "attribution.submitters",
    "audit_log",
    "webhook_deliveries",
    "pending_notices",
    "email_deliveries",
    "inbound_emails",
    "sector_events",
    "webhooks",
    "portal_sessions",
    "acknowledgments",
    "distributions",
    "taxii_status",
    "stix_objects",
    "submission_triage",
    "submission_transitions",
    "audit_stream_modes",
    "embargoes",
    "org_postures",
    "submissions",
    "taxii_collections",
    "circle_memberships",
    "circles",
    "client_certificates",
    "operators",
    "organizations",
    "instance_controls",
    "detection_state",
    "submission_milestones",
    "count_snapshots",
)


@pytest.fixture(autouse=True)
async def clean_database(engine: Any, _schema: None) -> AsyncIterator[None]:
    """Reset every table between tests.

    The append-only triggers are disabled for the duration of the truncate and
    restored immediately afterwards. Doing this explicitly -- rather than
    quietly granting the test role a way around the protection -- keeps the
    protection honest: nothing in the application can take this path.

    ``TRUNCATE`` needs an ACCESS EXCLUSIVE lock, so **two test runs cannot share
    one database**: the second blocks on the first indefinitely and the suite
    appears to hang with no explanation. The ``lock_timeout`` below turns that
    into an immediate, self-describing failure. Point concurrent runs at
    separate databases with ``AIVS_TEST_DATABASE_URL``.
    """
    yield
    async with engine.begin() as connection:
        # Fail fast rather than queue behind another run's cleanup.
        await connection.execute(text("SET LOCAL lock_timeout = '15s'"))
        try:
            for table in _APPEND_ONLY_TABLES:
                await connection.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER USER"))
            await connection.execute(
                text(f"TRUNCATE {', '.join(_ALL_TABLES)} RESTART IDENTITY CASCADE")
            )
            for table in _APPEND_ONLY_TABLES:
                await connection.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER USER"))
        except OperationalError as exc:  # pragma: no cover - diagnostic path
            message = (
                f"could not reset {TEST_DATABASE_URL.rsplit('/', 1)[-1]} within the lock "
                "timeout. Another test run is almost certainly using the same database; "
                "give each run its own via AIVS_TEST_DATABASE_URL."
            )
            raise RuntimeError(message) from exc


@pytest.fixture
async def session(engine: Any, _schema: None) -> AsyncIterator[AsyncSession]:
    """A database session for tests that manipulate rows directly."""
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with factory() as session:
        yield session
        await session.rollback()


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
@pytest.fixture
async def app(
    settings: Settings, engine: Any, member_engine: Any, _schema: None
) -> AsyncIterator[Any]:
    """The FastAPI application wired to the test database."""
    # Imported inside the fixture so that module import order cannot cause
    # aivs_server.db.engine to build a real engine from process environment
    # before the test settings are in place.
    from aivs_server.db import engine as engine_module  # noqa: PLC0415
    from aivs_server.main import create_app  # noqa: PLC0415

    # Point the module-level engine at the test database. Assigning the private
    # names directly is deliberate: the alternative is a production seam whose
    # only purpose is to let tests swap the engine, and a security-relevant
    # module is better off without a hook that exists solely to be overridden.
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    engine_module._engine = engine
    engine_module._sessionmaker = factory
    # The member engine connects as the suite's member login, so every member
    # request runs with that login's grants. Which login each caller is routed
    # to is asserted by test_database_logins.
    engine_module._member_engine = member_engine
    engine_module._member_sessionmaker = async_sessionmaker(
        bind=member_engine, expire_on_commit=False, autoflush=False
    )

    application = create_app(settings)
    yield application

    engine_module._sessionmaker = None
    engine_module._engine = None
    engine_module._member_sessionmaker = None
    engine_module._member_engine = None


@pytest.fixture
def safe_database_role(monkeypatch: pytest.MonkeyPatch) -> None:
    """Readiness sees the connection as a safe application role, for tests that need a 200.

    The suite connects as the cluster's superuser, which outside dev readiness
    refuses. This stands in for the deployment's application role rather than
    making the instance ``dev``, so nothing else about the request changes. The
    check itself is tested against real roles in ``test_readiness_role.py``.
    """

    async def _no_problem(_session: Any) -> None:
        return None

    monkeypatch.setattr("aivs_server.api.meta.connection_role_problem", _no_problem)


@pytest.fixture
async def client(app: Any) -> AsyncIterator[AsyncClient]:
    """HTTP client speaking to the app in-process.

    ``client=("127.0.0.1", 0)`` makes the request appear to arrive from the
    trusted proxy address, which is what the peer-address allowlist checks.
    Tests that need to defeat that allowlist override it explicitly.
    """
    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    async with AsyncClient(
        transport=transport, base_url="https://aivs.test", follow_redirects=False
    ) as http_client:
        yield http_client


# ---------------------------------------------------------------------------
# Domain fixtures
# ---------------------------------------------------------------------------
def _identity_id() -> str:
    return f"identity--{uuid.uuid4()}"


@pytest.fixture
async def make_org(session: AsyncSession):
    """Factory creating an organisation."""

    async def _make(
        slug: str,
        *,
        org_type: OrgType = OrgType.GSIB,
        status: OrgStatus = OrgStatus.ACTIVE,
        name: str | None = None,
    ) -> models.Organization:
        org = models.Organization(
            name=name or slug.replace("-", " ").title(),
            slug=slug,
            org_type=org_type,
            status=status,
            stix_identity_id=_identity_id(),
        )
        session.add(org)
        await session.commit()
        await session.refresh(org)
        return org

    return _make


@pytest.fixture
async def make_cert(session: AsyncSession, ca: TestCertificateAuthority):
    """Factory issuing a certificate and registering it against an organisation.

    Returns the PEM alongside the row, because a test almost always needs both:
    the PEM to present and the row to manipulate.
    """

    async def _make(
        org: models.Organization,
        *,
        status: CertStatus = CertStatus.ACTIVE,
        not_before: dt.datetime | None = None,
        not_after: dt.datetime | None = None,
    ) -> tuple[str, models.ClientCertificate]:
        pem, fingerprint, certificate = ca.issue(
            org.slug, not_before=not_before, not_after=not_after
        )
        row = models.ClientCertificate(
            org_id=org.id,
            fingerprint_sha256=fingerprint,
            subject_dn=certificate.subject.rfc4514_string(),
            issuer_dn=certificate.issuer.rfc4514_string(),
            serial_hex=format(certificate.serial_number, "x"),
            not_before=certificate.not_valid_before_utc,
            not_after=certificate.not_valid_after_utc,
            status=status,
            revoked_at=dt.datetime.now(dt.UTC) if status is CertStatus.REVOKED else None,
            revoked_reason="test revocation" if status is CertStatus.REVOKED else None,
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)
        return pem, row

    return _make


@pytest.fixture
async def make_circle(session: AsyncSession):
    """Factory creating a sharing circle."""

    async def _make(slug: str, *, is_active: bool = True) -> models.Circle:
        circle = models.Circle(
            slug=slug,
            name=slug.replace("-", " ").title(),
            is_active=is_active,
        )
        session.add(circle)
        await session.commit()
        await session.refresh(circle)
        return circle

    return _make


#: Default membership start for test fixtures: earlier than any content a test
#: publishes, so an organisation joined this way sees everything in its circles.
#:
#: Explicit rather than "now" because content visibility is bounded by when a
#: membership began -- a test whose subject is paging or embargo should not have
#: to think about join times, but it must not accidentally depend on the bound
#: being absent either. Tests that *are* about the bound pass joined_at.
FOUNDING_MEMBER_SINCE = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)


@pytest.fixture
async def join_circle(session: AsyncSession):
    """Factory adding an organisation to a circle.

    ``joined_at`` defaults to :data:`FOUNDING_MEMBER_SINCE`.
    """

    async def _join(
        org: models.Organization,
        circle: models.Circle,
        role: CircleRole = CircleRole.MEMBER,
        joined_at: dt.datetime | None = None,
    ) -> models.CircleMembership:
        membership = models.CircleMembership(
            circle_id=circle.id,
            org_id=org.id,
            role=role,
            joined_at=joined_at or FOUNDING_MEMBER_SINCE,
        )
        session.add(membership)
        await session.commit()
        await session.refresh(membership)
        return membership

    return _join


@pytest.fixture
async def make_collection(session: AsyncSession):
    """Factory creating a TAXII collection over a circle."""

    async def _make(
        circle: models.Circle,
        *,
        title: str | None = None,
        can_read: bool = True,
        can_write: bool = True,
        is_active: bool = True,
    ) -> models.TaxiiCollection:
        collection = models.TaxiiCollection(
            circle_id=circle.id,
            title=title or f"{circle.name} feed",
            description=f"Content shared into {circle.name}",
            can_read=can_read,
            can_write=can_write,
            is_active=is_active,
        )
        session.add(collection)
        await session.commit()
        await session.refresh(collection)
        return collection

    return _make


@pytest.fixture
async def publish(session: AsyncSession):
    """Factory that puts a STIX object into a circle, end to end.

    Creates a submission, a STIX object, and the distribution row that makes it
    visible -- the same three records the distribution service writes. Tests use
    this rather than driving the workflow API so that a TAXII test fails for
    TAXII reasons rather than for a change in the submission endpoints.

    ``date_added`` is settable so a test can place content in the future, which
    is exactly how an embargoed object is represented.
    """

    async def _publish(
        org: models.Organization,
        circle: models.Circle,
        *,
        stix_id: str | None = None,
        stix_type: str = "vulnerability",
        name: str = "Test finding",
        modified: dt.datetime | None = None,
        date_added: dt.datetime | None = None,
        state: SubmissionState = SubmissionState.DISTRIBUTED,
        submission: models.Submission | None = None,
    ) -> tuple[models.Submission, models.StixObject, models.Distribution]:
        now = dt.datetime.now(dt.UTC)
        modified = modified or now
        # Millisecond precision, matching what the distribution service must do.
        date_added = truncate_to_taxii_precision(date_added or now)
        stix_id = stix_id or f"{stix_type}--{uuid.uuid4()}"

        if submission is None:
            submission = models.Submission(
                state=state,
                tlp=TLP.AMBER,
                discovery_scope=DiscoveryScope.AI_SYSTEM,
                title=name,
                distributed_at=now if state is SubmissionState.DISTRIBUTED else None,
            )
            await seed_filing(session, submission, org)
            await session.commit()
            await session.refresh(submission)

        stix_object = models.StixObject(
            stix_id=stix_id,
            modified=modified,
            created=modified,
            type=stix_type,
            spec_version="2.1",
            submission_id=submission.id,
            name=name,
            owner_token=await seeded_owner_token(session, submission, stix_id),
            raw={
                "type": stix_type,
                "spec_version": "2.1",
                "id": stix_id,
                "created": modified.isoformat().replace("+00:00", "Z"),
                "modified": modified.isoformat().replace("+00:00", "Z"),
                "name": name,
            },
        )
        session.add(stix_object)
        await session.commit()
        await session.refresh(stix_object)

        distribution = models.Distribution(
            stix_object_id=stix_object.id,
            circle_id=circle.id,
            submission_id=submission.id,
            date_added=date_added,
        )
        session.add(distribution)
        await session.commit()
        await session.refresh(distribution)

        return submission, stix_object, distribution

    return _publish


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Absolute path to the repository root."""
    return Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# Humans
# ---------------------------------------------------------------------------
#: What a small ISAC's staff member typically holds: the review queue, the
#: editorial verbs, and membership administration. ``SYSTEM_ADMIN`` is left out
#: on purpose -- it runs the instance and grants no editorial power.
ISAC_STAFF_ROLES: tuple[OperatorRole, ...] = (
    OperatorRole.ISAC_ANALYST,
    OperatorRole.ISAC_EDITOR,
    OperatorRole.ISAC_MEMBERSHIP,
)

#: Password used for every test operator.
TEST_OPERATOR_PASSWORD = "correct-horse-battery-staple"


@functools.cache
def _test_operator_password_hash() -> str:
    """Hashed once per run. Argon2 is slow by design, and every ISAC fixture
    creates an operator, so hashing per test doubled the suite's runtime."""
    return hash_password(TEST_OPERATOR_PASSWORD)


@pytest.fixture
async def make_operator(session: AsyncSession, secret_box: SecretBox):
    """Factory creating an operator with a sealed TOTP seed. Returns it and the seed."""

    async def _make(
        org: models.Organization,
        *,
        roles: tuple[OperatorRole, ...] = (OperatorRole.ANALYST,),
        email: str | None = None,
        role_expires_at: dt.datetime | None = None,
    ) -> tuple[models.Operator, str]:
        seed = pyotp.random_base32()
        # Explicit id: the seal is bound to it, and the column default is not
        # applied until flush.
        operator_id = uuid.uuid4()
        operator = models.Operator(
            id=operator_id,
            org_id=org.id,
            email=email or f"{uuid.uuid4().hex[:8]}@{org.slug}.test",
            display_name="Test Operator",
            roles=list(roles),
            password_hash=_test_operator_password_hash(),
            totp_secret_encrypted=secret_box.seal(
                seed, purpose=SecretPurpose.TOTP, subject=operator_id
            ),
            is_active=True,
            role_expires_at=role_expires_at,
        )
        session.add(operator)
        await session.commit()
        await session.refresh(operator)
        return operator, seed

    return _make


@pytest.fixture
async def human_headers(session: AsyncSession, settings: Settings):
    """Factory: request headers for a signed-in human, session as a bearer token.

    The session is established directly rather than through the login form, and
    bound to ``pem``'s certificate exactly as a login over that path would be.
    """

    async def _headers(operator: models.Operator, pem: str) -> dict[str, str]:
        certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
        established = await establish_session(
            session,
            settings,
            operator=operator,
            cert_fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
        )
        await session.commit()
        return {**proxy_headers(pem), "authorization": f"Bearer {established.token}"}

    return _headers


@pytest.fixture
async def isac(isac_org, make_org, make_cert, make_operator, human_headers):
    """The hosting ISAC, as a signed-in member of its staff: ``(org, headers)``.

    A person, not a certificate: every ISAC power requires a human session, and
    the admin organisation's certificate on its own authenticates nothing more
    than the network path.
    """
    org = isac_org
    pem, _ = await make_cert(org)
    operator, _seed = await make_operator(org, roles=ISAC_STAFF_ROLES)
    return org, await human_headers(operator, pem)


@pytest.fixture
async def isac_org(make_org):
    """The instance's one hosting ISAC, shared by every fixture that needs it.

    The database allows exactly one admin-type organisation, so fixtures that
    each created their own could not be used together.
    """
    return await make_org("hosting-isac", org_type=OrgType.ADMIN)


@pytest.fixture
async def isac_machine(isac_org, make_cert):
    """The admin organisation's *certificate* alone: ``(org, headers)``.

    Kept for the tests that prove a certificate confers no ISAC power.
    """
    pem, _ = await make_cert(isac_org)
    return isac_org, proxy_headers(pem)


# ---------------------------------------------------------------------------
# Concurrency and outbound-delivery helpers, shared across modules
# ---------------------------------------------------------------------------
#: How long ``is_blocked`` watches an operation that is expected to wait. A
#: blocked writer stays blocked indefinitely, so this only has to be long enough
#: for an unblocked one to finish on a quiet machine.
_SETTLE_SECONDS = 0.5
#: How long ``runs_unblocked`` gives an operation that is expected *not* to wait.
#: It was ``_SETTLE_SECONDS`` too, which made "not blocked" a timing assertion:
#: with other suites loading the shared cluster, an unblocked TAXII read took
#: over half a second and failed as "blocked", in the full suite and alone. Any
#: lock holder in these tests releases only after the check, so an operation that
#: wrongly waits still fails, just later.
_UNBLOCKED_SECONDS = 10.0


@pytest.fixture
async def open_session(engine: Any) -> AsyncIterator[Any]:
    """Factory for extra sessions, each rolled back and closed at teardown."""
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    opened: list[AsyncSession] = []

    def _open() -> AsyncSession:
        session = factory()
        opened.append(session)
        return session

    yield _open
    for session in opened:
        await session.rollback()
        await session.close()


@pytest.fixture
async def isac_ctx(isac_org) -> AuthContext:
    org = isac_org
    return AuthContext(
        org_id=org.id,
        org_slug=org.slug,
        org_type=OrgType.ADMIN,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.MTLS,
    )


@pytest.fixture
async def make_validated(session: AsyncSession, make_org):
    """Factory for a validated submission carrying one STIX object."""
    member = await make_org("member-bank")

    async def _make(name: str) -> uuid.UUID:
        submission = models.Submission(
            state=SubmissionState.VALIDATED,
            tlp=TLP.AMBER,
            discovery_scope=DiscoveryScope.AI_SYSTEM,
            title=name,
        )
        await seed_filing(session, submission, member)
        stix_id = f"vulnerability--{uuid.uuid4()}"
        session.add(
            models.StixObject(
                stix_id=stix_id,
                modified=submission.created_at,
                created=submission.created_at,
                type="vulnerability",
                spec_version="2.1",
                submission_id=submission.id,
                name=name,
                owner_token=await seeded_owner_token(session, submission, stix_id),
                raw={"type": "vulnerability", "spec_version": "2.1", "id": stix_id, "name": name},
            )
        )
        await session.commit()
        return submission.id

    return _make


async def seed_filing(
    session: AsyncSession,
    submission: models.Submission,
    org: models.Organization,
    *,
    created_by: uuid.UUID | None = None,
) -> models.Submission:
    """Add a hand-built submission, recorded as ``org``'s filing by the writer ingest uses.

    Who filed it is held apart (``services.attribution``); a seeded row gets
    its filer through the same function as a filed one, so it is the row the
    readers will meet (CLAUDE.md section 2: build seeded rows with the
    writer's own functions).
    """
    await record_filing(
        session,
        TEST_ATTRIBUTION_KEY,
        submission,
        FilingRecord(org_id=org.id, created_by=created_by, proxy_editor=None, proxy_consent=None),
    )
    return submission


async def seeded_owner_token(
    session: AsyncSession, submission: models.Submission, stix_id: str
) -> str:
    """The owner token ingest would store a version of ``stix_id`` in ``submission`` with."""
    org_id = await submitter_of(session, submission)
    org_type = await session.scalar(
        select(models.Organization.org_type).where(models.Organization.id == org_id)
    )
    tokens = owner_tokens_for(
        TEST_ATTRIBUTION_KEY, org_id, [stix_id], owner_is_isac=org_type in ISAC_FILER_TYPES
    )
    return tokens[stix_id]


async def is_blocked(operation: Awaitable[Any]) -> tuple[bool, asyncio.Task[Any]]:
    task = asyncio.ensure_future(operation)
    done, _ = await asyncio.wait({task}, timeout=_SETTLE_SECONDS)
    return task not in done, task


async def runs_unblocked(operation: Awaitable[Any]) -> tuple[bool, asyncio.Task[Any]]:
    task = asyncio.ensure_future(operation)
    done, _ = await asyncio.wait({task}, timeout=_UNBLOCKED_SECONDS)
    return task in done, task


class StubEndpoint(httpx.AsyncBaseTransport):
    """Stands in for a member's endpoint."""

    def __init__(self, *, status_code: int = 204, raises: Exception | None = None) -> None:
        self.status_code = status_code
        self.raises = raises
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raises is not None:
            raise self.raises
        return httpx.Response(self.status_code, request=request)


@pytest.fixture
def member_endpoint(monkeypatch):
    """Point the dispatcher's client at a stand-in endpoint."""

    def _install(transport: StubEndpoint) -> StubEndpoint:
        real = httpx.AsyncClient

        def _factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return real(*args, **kwargs)

        monkeypatch.setattr("aivs_server.notify.dispatcher.httpx.AsyncClient", _factory)
        return transport

    return _install
