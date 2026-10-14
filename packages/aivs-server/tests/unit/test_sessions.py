"""Portal authentication and the certificate binding.

The property under test is the one that makes the portal's two factors
independent: a session is bound to the client certificate that carried the
login, and that binding is re-checked on every request. A stolen cookie is
useless outside the organisation's certificate-bearing path, and the
organisation's certificate is useless without a human credential.

The revocation tests matter for a reason a review surfaced: revoking a
certificate has to lock out the humans using it, not only the machines.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as dt
import os
import uuid

import pyotp
import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from aivs_schemas.enums import CertStatus, OperatorRole, OrgStatus, OrgType
from aivs_server.auth.context import AuthMethod
from aivs_server.auth.passwords import (
    generate_totp_secret,
    hash_password,
    matching_totp_step,
    verify_password,
)
from aivs_server.auth.secretbox import SecretBox, SecretPurpose
from aivs_server.auth.sessions import (
    LOCKOUT_THRESHOLD,
    SessionRejectedError,
    authenticate_operator,
    establish_session,
    resolve_session,
    revoke_session,
    revoke_sessions_for_certificate,
)
from aivs_server.db.models import Operator, PortalSession

pytestmark = pytest.mark.db

PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
async def operator_setup(session, settings, secret_box, make_org, make_cert):
    """An active operator at an active org, with a registered certificate."""
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, certificate = await make_cert(org)

    totp_secret = generate_totp_secret()
    # The id is set here rather than left to the column default, because the
    # seal is bound to it and the default is not applied until flush.
    operator_id = uuid.uuid4()
    operator = Operator(
        id=operator_id,
        org_id=org.id,
        email="analyst@meridian.test",
        display_name="Test Analyst",
        roles=[OperatorRole.ANALYST],
        password_hash=hash_password(PASSWORD),
        totp_secret_encrypted=secret_box.seal(
            totp_secret, purpose=SecretPurpose.TOTP, subject=operator_id
        ),
        is_active=True,
    )
    session.add(operator)
    await session.commit()
    await session.refresh(operator)
    return org, operator, totp_secret, certificate, pem


def current_code(secret: str) -> str:
    return pyotp.TOTP(secret).now()


# ---------------------------------------------------------------------------
# Credential verification
# ---------------------------------------------------------------------------
async def test_correct_credentials_authenticate(secret_box, session, operator_setup):
    org, operator, secret, _cert, _pem = operator_setup
    result = await authenticate_operator(
        session,
        secret_box=secret_box,
        email=operator.email,
        password=PASSWORD,
        totp_code=current_code(secret),
        org_id=org.id,
    )
    assert result.id == operator.id


@pytest.mark.parametrize(
    ("password", "use_valid_code"),
    [(PASSWORD, False), ("wrong-password-entirely", True), ("wrong", False)],
)
async def test_both_factors_are_required(
    secret_box, session, operator_setup, password, use_valid_code
):
    """Neither factor alone authenticates."""
    org, operator, secret, _cert, _pem = operator_setup
    with pytest.raises(SessionRejectedError):
        await authenticate_operator(
            session,
            secret_box=secret_box,
            email=operator.email,
            password=password,
            totp_code=current_code(secret) if use_valid_code else "000000",
            org_id=org.id,
        )


async def test_a_credential_from_another_orgs_path_is_refused(
    secret_box, session, operator_setup, make_org
):
    """A stolen credential replayed from a different firm's network path fails.

    The organisation comes from the client certificate, not from the form, so
    knowing the password and holding a TOTP device is not enough if you are
    coming from somewhere else.
    """
    _org, operator, secret, _cert, _pem = operator_setup
    other = await make_org("atlantic-clearing")

    with pytest.raises(SessionRejectedError) as caught:
        await authenticate_operator(
            session,
            secret_box=secret_box,
            email=operator.email,
            password=PASSWORD,
            totp_code=current_code(secret),
            org_id=other.id,
        )
    assert caught.value.reason == "operator_org_mismatch"


async def test_an_unknown_address_is_refused(secret_box, session, operator_setup):
    org, _operator, secret, _cert, _pem = operator_setup
    with pytest.raises(SessionRejectedError):
        await authenticate_operator(
            session,
            secret_box=secret_box,
            email="nobody@meridian.test",
            password=PASSWORD,
            totp_code=current_code(secret),
            org_id=org.id,
        )


async def test_an_inactive_operator_is_refused(secret_box, session, operator_setup):
    org, operator, secret, _cert, _pem = operator_setup
    operator.is_active = False
    await session.commit()

    with pytest.raises(SessionRejectedError) as caught:
        await authenticate_operator(
            session,
            secret_box=secret_box,
            email=operator.email,
            password=PASSWORD,
            totp_code=current_code(secret),
            org_id=org.id,
        )
    assert caught.value.reason == "operator_inactive"


async def test_repeated_failures_lock_the_operator_out(secret_box, session, operator_setup):
    """Online guessing is bounded, and the lockout survives a correct password."""
    org, operator, secret, _cert, _pem = operator_setup

    for _ in range(LOCKOUT_THRESHOLD):
        with pytest.raises(SessionRejectedError):
            await authenticate_operator(
                session,
                secret_box=secret_box,
                email=operator.email,
                password="wrong",
                totp_code="000000",
                org_id=org.id,
            )

    with pytest.raises(SessionRejectedError) as caught:
        await authenticate_operator(
            session,
            secret_box=secret_box,
            email=operator.email,
            password=PASSWORD,
            totp_code=current_code(secret),
            org_id=org.id,
        )
    assert caught.value.reason == "operator_locked"


async def test_a_successful_login_clears_the_failure_count(secret_box, session, operator_setup):
    org, operator, secret, _cert, _pem = operator_setup

    with pytest.raises(SessionRejectedError):
        await authenticate_operator(
            session,
            secret_box=secret_box,
            email=operator.email,
            password="wrong",
            totp_code="000000",
            org_id=org.id,
        )

    await authenticate_operator(
        session,
        secret_box=secret_box,
        email=operator.email,
        password=PASSWORD,
        totp_code=current_code(secret),
        org_id=org.id,
    )
    await session.refresh(operator)
    assert operator.failed_login_count == 0
    assert operator.last_login_at is not None


# ---------------------------------------------------------------------------
# The certificate binding
# ---------------------------------------------------------------------------
async def test_a_session_resumes_with_the_bound_certificate(session, settings, operator_setup):
    _org, operator, _secret, certificate, _pem = operator_setup
    established = await establish_session(
        session,
        settings,
        operator=operator,
        cert_fingerprint=certificate.fingerprint_sha256,
    )

    ctx, _csrf_hash = await resolve_session(
        session,
        settings,
        token=established.token,
        cert_fingerprint=certificate.fingerprint_sha256,
    )
    assert ctx.operator_id == operator.id
    assert ctx.auth_method is AuthMethod.PORTAL_SESSION
    assert ctx.operator_roles == {OperatorRole.ANALYST}


async def test_a_session_cookie_is_useless_from_another_certificate_path(
    session, settings, operator_setup, ca
):
    """The property the whole design rests on.

    Without this, the password and the certificate would be one factor: a
    stolen cookie would work from anywhere on the network.
    """
    _org, operator, _secret, certificate, _pem = operator_setup
    established = await establish_session(
        session,
        settings,
        operator=operator,
        cert_fingerprint=certificate.fingerprint_sha256,
    )

    _other_pem, other_fingerprint, _cert = ca.issue("somewhere-else")
    with pytest.raises(SessionRejectedError) as caught:
        await resolve_session(
            session,
            settings,
            token=established.token,
            cert_fingerprint=other_fingerprint,
        )
    assert caught.value.reason == "session_certificate_mismatch"


async def test_a_session_cookie_is_useless_with_no_certificate(session, settings, operator_setup):
    _org, operator, _secret, certificate, _pem = operator_setup
    established = await establish_session(
        session,
        settings,
        operator=operator,
        cert_fingerprint=certificate.fingerprint_sha256,
    )

    with pytest.raises(SessionRejectedError):
        await resolve_session(session, settings, token=established.token, cert_fingerprint=None)


@pytest.mark.requirement("NFR-S2")
async def test_revoking_the_certificate_ends_the_humans_sessions(session, settings, operator_setup):
    """Revocation locks out people, not only machines.

    A review found that certificate revocation touched nothing in
    portal_sessions, so a logged-in analyst would have kept working for the rest
    of the session TTL after their firm's certificate was pulled.
    """
    _org, operator, _secret, certificate, _pem = operator_setup
    established = await establish_session(
        session,
        settings,
        operator=operator,
        cert_fingerprint=certificate.fingerprint_sha256,
    )

    certificate.status = CertStatus.REVOKED
    certificate.revoked_at = dt.datetime.now(dt.UTC)
    await session.commit()

    with pytest.raises(SessionRejectedError) as caught:
        await resolve_session(
            session,
            settings,
            token=established.token,
            cert_fingerprint=certificate.fingerprint_sha256,
        )
    assert caught.value.reason == "session_certificate_revoked"


async def test_bulk_revocation_closes_every_bound_session(session, settings, operator_setup):
    _org, operator, _secret, certificate, _pem = operator_setup
    first = await establish_session(
        session, settings, operator=operator, cert_fingerprint=certificate.fingerprint_sha256
    )
    second = await establish_session(
        session, settings, operator=operator, cert_fingerprint=certificate.fingerprint_sha256
    )

    closed = await revoke_sessions_for_certificate(
        session, fingerprint=certificate.fingerprint_sha256
    )
    await session.commit()
    assert closed == 2

    for established in (first, second):
        with pytest.raises(SessionRejectedError):
            await resolve_session(
                session,
                settings,
                token=established.token,
                cert_fingerprint=certificate.fingerprint_sha256,
            )


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------
async def test_an_unknown_token_is_refused(session, settings, operator_setup):
    with pytest.raises(SessionRejectedError):
        await resolve_session(
            session, settings, token="not-a-real-token", cert_fingerprint="a" * 64
        )


async def test_an_expired_session_is_refused(session, settings, operator_setup):
    _org, operator, _secret, certificate, _pem = operator_setup
    established = await establish_session(
        session, settings, operator=operator, cert_fingerprint=certificate.fingerprint_sha256
    )

    row = (await session.execute(select(PortalSession))).scalar_one()
    row.expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
    await session.commit()

    with pytest.raises(SessionRejectedError) as caught:
        await resolve_session(
            session,
            settings,
            token=established.token,
            cert_fingerprint=certificate.fingerprint_sha256,
        )
    assert caught.value.reason == "session_expired"


async def test_an_idle_session_is_refused(session, settings, operator_setup):
    """Idle timeout is separate from the absolute deadline.

    An unattended browser on an analyst's desk should stop working long before
    the session's outer TTL expires.
    """
    _org, operator, _secret, certificate, _pem = operator_setup
    established = await establish_session(
        session, settings, operator=operator, cert_fingerprint=certificate.fingerprint_sha256
    )

    row = (await session.execute(select(PortalSession))).scalar_one()
    row.last_seen_at = dt.datetime.now(dt.UTC) - dt.timedelta(
        minutes=settings.session_idle_timeout_minutes + 1
    )
    await session.commit()

    with pytest.raises(SessionRejectedError) as caught:
        await resolve_session(
            session,
            settings,
            token=established.token,
            cert_fingerprint=certificate.fingerprint_sha256,
        )
    assert caught.value.reason == "session_idle_timeout"


@pytest.mark.requirement("NFR-S2")
async def test_logout_revokes_the_session(session, settings, operator_setup):
    _org, operator, _secret, certificate, _pem = operator_setup
    established = await establish_session(
        session, settings, operator=operator, cert_fingerprint=certificate.fingerprint_sha256
    )

    await revoke_session(session, token=established.token)

    with pytest.raises(SessionRejectedError) as caught:
        await resolve_session(
            session,
            settings,
            token=established.token,
            cert_fingerprint=certificate.fingerprint_sha256,
        )
    assert caught.value.reason == "session_revoked"


async def test_suspending_the_org_ends_its_sessions(session, settings, operator_setup):
    org, operator, _secret, certificate, _pem = operator_setup
    established = await establish_session(
        session, settings, operator=operator, cert_fingerprint=certificate.fingerprint_sha256
    )

    org.status = OrgStatus.SUSPENDED
    await session.commit()

    with pytest.raises(SessionRejectedError) as caught:
        await resolve_session(
            session,
            settings,
            token=established.token,
            cert_fingerprint=certificate.fingerprint_sha256,
        )
    assert caught.value.reason == "org_inactive"


async def test_each_login_mints_a_fresh_token(session, settings, operator_setup):
    """A session fixed before login must not survive it."""
    _org, operator, _secret, certificate, _pem = operator_setup
    first = await establish_session(
        session, settings, operator=operator, cert_fingerprint=certificate.fingerprint_sha256
    )
    second = await establish_session(
        session, settings, operator=operator, cert_fingerprint=certificate.fingerprint_sha256
    )
    assert first.token != second.token
    assert first.csrf_token != second.csrf_token


# ---------------------------------------------------------------------------
# Password and TOTP primitives
# ---------------------------------------------------------------------------
def test_a_short_password_is_refused():
    with pytest.raises(ValueError, match="at least"):
        hash_password("short")


def test_verification_of_a_missing_operator_always_fails():
    """Called with None so the timing does not reveal whether the address exists."""
    assert verify_password(None, "anything") is False


def test_a_correct_password_verifies():
    stored = hash_password(PASSWORD)
    assert verify_password(stored, PASSWORD) is True
    assert verify_password(stored, PASSWORD + "x") is False


@pytest.mark.parametrize("code", ["", "abcdef", "12345", None])
def test_a_malformed_totp_code_is_refused(code):
    secret = generate_totp_secret()
    assert matching_totp_step(secret, code or "", now=dt.datetime.now(dt.UTC)) is None


def test_a_missing_totp_secret_never_verifies():
    """An operator part-way through enrolment cannot pass the second factor."""
    assert matching_totp_step(None, "123456", now=dt.datetime.now(dt.UTC)) is None


def test_a_code_matches_the_step_it_was_generated_for_within_the_window():
    secret = generate_totp_secret()
    now = dt.datetime(2026, 10, 14, 12, 0, 15, tzinfo=dt.UTC)
    totp = pyotp.TOTP(secret)
    current = totp.timecode(now)

    assert matching_totp_step(secret, totp.at(now), now=now) == current
    assert matching_totp_step(secret, totp.at(now - STEP), now=now) == current - 1
    assert matching_totp_step(secret, totp.at(now - 2 * STEP), now=now) is None


# ---------------------------------------------------------------------------
# Each code signs in once (RFC 6238 section 5.2)
# ---------------------------------------------------------------------------
STEP = dt.timedelta(seconds=30)
LOGIN_AT = dt.datetime(2026, 10, 14, 12, 0, 15, tzinfo=dt.UTC)


async def sign_in(session, secret_box, org, operator, code, *, now):
    return await authenticate_operator(
        session,
        secret_box=secret_box,
        email=operator.email,
        password=PASSWORD,
        totp_code=code,
        org_id=org.id,
        now=now,
    )


@pytest.mark.requirement("SF-73")
async def test_a_code_that_has_signed_in_is_refused_the_second_time(
    secret_box, session, operator_setup
):
    org, operator, secret, _cert, _pem = operator_setup
    code = pyotp.TOTP(secret).at(LOGIN_AT)
    await sign_in(session, secret_box, org, operator, code, now=LOGIN_AT)

    with pytest.raises(SessionRejectedError) as caught:
        await sign_in(
            session, secret_box, org, operator, code, now=LOGIN_AT + dt.timedelta(seconds=5)
        )

    assert caught.value.reason == "totp_reused"


@pytest.mark.requirement("SF-73")
async def test_the_next_windows_code_signs_in_after_one_has(secret_box, session, operator_setup):
    org, operator, secret, _cert, _pem = operator_setup
    totp = pyotp.TOTP(secret)
    await sign_in(session, secret_box, org, operator, totp.at(LOGIN_AT), now=LOGIN_AT)

    later = LOGIN_AT + STEP
    result = await sign_in(session, secret_box, org, operator, totp.at(later), now=later)

    assert result.id == operator.id


@pytest.mark.requirement("SF-73")
async def test_an_earlier_windows_code_is_refused_once_a_later_one_has_signed_in(
    secret_box, session, operator_setup
):
    """Both codes are inside the drift window; only the newer may be used."""
    org, operator, secret, _cert, _pem = operator_setup
    totp = pyotp.TOTP(secret)
    await sign_in(session, secret_box, org, operator, totp.at(LOGIN_AT), now=LOGIN_AT)

    with pytest.raises(SessionRejectedError) as caught:
        await sign_in(session, secret_box, org, operator, totp.at(LOGIN_AT - STEP), now=LOGIN_AT)

    assert caught.value.reason == "totp_reused"


@pytest.mark.requirement("SF-73")
async def test_a_replayed_code_counts_towards_the_lockout(secret_box, session, operator_setup):
    org, operator, secret, _cert, _pem = operator_setup
    code = pyotp.TOTP(secret).at(LOGIN_AT)
    await sign_in(session, secret_box, org, operator, code, now=LOGIN_AT)

    with pytest.raises(SessionRejectedError):
        await sign_in(session, secret_box, org, operator, code, now=LOGIN_AT)

    await session.refresh(operator)
    assert operator.failed_login_count == 1


@pytest.mark.requirement("SF-73")
async def test_two_concurrent_logins_with_one_code_let_exactly_one_in(
    engine, secret_box, session, operator_setup
):
    """The step is checked and recorded under the login's row lock, so the second
    login waits for the first to commit and then reads the step it wrote. Each
    attempt has its own session and transaction, as two portal requests would."""
    org, operator, secret, _cert, _pem = operator_setup
    code = pyotp.TOTP(secret).at(LOGIN_AT)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

    async def attempt() -> str:
        async with factory() as own_session:
            try:
                await sign_in(own_session, secret_box, org, operator, code, now=LOGIN_AT)
            except SessionRejectedError as rejected:
                return rejected.reason
            return "signed_in"

    outcomes = await asyncio.gather(attempt(), attempt())

    assert sorted(outcomes) == ["signed_in", "totp_reused"]


async def test_concurrent_failures_all_count_against_the_lockout(
    engine, secret_box, session, operator_setup
):
    """The lockout is the only bound on password guessing, so it must not race.

    `failed_login_count += 1` is a read-modify-write. Without a row lock,
    SQLAlchemy emits an absolute `SET failed_login_count = <n>` from a value read
    before the attempt, so N concurrent failures against one operator all read
    the same count and all write the same count: N attempts record one
    increment, `locked_until` stays null, and LOCKOUT_THRESHOLD bounds nothing.

    Each attempt here gets its own session and its own transaction, which is what
    a portal request does -- driving them from one session would serialise them
    for free and prove nothing.
    """
    org, operator, _secret, _cert, _pem = operator_setup
    attempts = LOCKOUT_THRESHOLD

    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

    async def one_attempt() -> None:
        async with factory() as own_session:
            with contextlib.suppress(SessionRejectedError):
                await authenticate_operator(
                    own_session,
                    secret_box=secret_box,
                    email=operator.email,
                    password="wrong-password-entirely",
                    totp_code="000000",
                    org_id=org.id,
                )

    await asyncio.gather(*(one_attempt() for _ in range(attempts)))

    await session.refresh(operator)
    # At the threshold the counter resets to 0 and the lockout is set, so the
    # observable proof that every attempt was counted is the lockout itself.
    assert operator.locked_until is not None, (
        f"{attempts} concurrent failures did not reach the threshold: "
        "the increment is racing and the lockout bounds nothing"
    )


async def test_an_unopenable_seed_is_a_server_fault_not_a_failed_login(
    session, settings, operator_setup
):
    """Finding #5: a key misconfiguration progressively locked out every operator.

    ``unseal`` returning ``None`` made the second factor simply false, which
    counted towards lockout and was audited as ``bad_credentials`` -- lockouts
    that outlived the fix, in an audit trail indistinguishable from an attack.
    The pair: the same attempt with a box that *can* open the seed succeeds,
    and the failure count is untouched by the server's fault.
    """
    org, operator, secret, _cert, _pem = operator_setup
    wrong_key = SecretBox.from_settings(
        settings.model_copy(
            update={"secret_encryption_key": SecretStr(base64.b64encode(os.urandom(32)).decode())}
        )
    )

    for _ in range(LOCKOUT_THRESHOLD + 1):
        with pytest.raises(SessionRejectedError) as caught:
            await authenticate_operator(
                session,
                secret_box=wrong_key,
                email=operator.email,
                password=PASSWORD,
                totp_code=current_code(secret),
                org_id=org.id,
            )
        assert caught.value.reason == "totp_seed_unavailable"

    await session.refresh(operator)
    assert operator.failed_login_count == 0
    assert operator.locked_until is None

    recovered = await authenticate_operator(
        session,
        secret_box=SecretBox.from_settings(settings),
        email=operator.email,
        password=PASSWORD,
        totp_code=current_code(secret),
        org_id=org.id,
    )
    assert recovered.id == operator.id


async def test_a_wrong_password_still_counts_when_the_seed_cannot_be_opened(
    session, settings, operator_setup
):
    """The exemption is for the server's fault only; it must not be a free guess."""
    org, operator, _secret, _cert, _pem = operator_setup
    wrong_key = SecretBox.from_settings(
        settings.model_copy(
            update={"secret_encryption_key": SecretStr(base64.b64encode(os.urandom(32)).decode())}
        )
    )

    with pytest.raises(SessionRejectedError) as caught:
        await authenticate_operator(
            session,
            secret_box=wrong_key,
            email=operator.email,
            password="a wrong guess",
            totp_code="000000",
            org_id=org.id,
        )
    assert caught.value.reason == "bad_credentials"
    await session.refresh(operator)
    assert operator.failed_login_count == 1
