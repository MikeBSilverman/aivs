"""Authentication on the staff login (Phase P slice 3e).

The member login holds nothing on ``operators`` or ``portal_sessions``
(``db.grants.MEMBER_GRANTS``). It held SELECT on every column of
``operators``, ``password_hash`` included, so SQL on the member path could
carry every operator's Argon2id hash away -- the ISAC's staff among them -- and
guess at leisure. It could also insert an operator naming any organisation
(R27) and rewrite a peer's lockout counter or spent TOTP step (R28).

Yet a member's request authenticates through those tables before anyone knows
who is asking. So authentication runs here, and every function holds one
invariant, which nothing else here makes true:

* it opens a staff session of its own, keyed only on what the caller
  presented -- a session token, an email with the organisation of the
  certificate that carried it, an identity the member issuer signed, a
  certificate the caller may manage -- and on nothing the caller names;
* it commits or rolls back before it returns, and returns values, never the
  session or a row still attached to it.

What each check refuses is ``auth.sessions``' and ``services.sso``'s, unchanged.
``tests/unit/test_staff_session_reach.py`` admits this module by name.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.auth.oidc import VerifiedIdentity
from aivs_server.auth.secretbox import SecretBox
from aivs_server.auth.sessions import (
    EstablishedSession,
    authenticate_operator,
    establish_session,
    establish_sso_session,
    revoke_session,
    revoke_sessions_for_certificate,
)
from aivs_server.config import Settings
from aivs_server.db.engine import get_sessionmaker
from aivs_server.services.sso import SignIn, resolve_member_sign_in

__all__ = [
    "authentication_session",
    "close_sessions_for_certificate",
    "sign_in_federated",
    "sign_in_with_password",
    "sign_out",
]


@asynccontextmanager
async def authentication_session() -> AsyncIterator[AsyncSession]:
    """A staff session for resolving who is calling, rolled back unless committed.

    For ``auth.deps`` and the portal's session resolution, which read the
    certificate or token presented and commit their own bookkeeping.
    """
    async with get_sessionmaker()() as session:
        try:
            yield session
        finally:
            await session.rollback()


async def sign_in_with_password(
    settings: Settings,
    *,
    email: str,
    password: str,
    totp_code: str,
    org_id: uuid.UUID,
    cert_fingerprint: str,
    secret_box: SecretBox,
    source_ip: str | None,
    user_agent: str | None,
) -> EstablishedSession:
    """Check a person's credentials from ``org_id``'s certificate and start their session.

    ``SessionRejectedError`` as ``authenticate_operator`` and ``establish_session``
    raise it; each commits its own bookkeeping, a failed attempt's included.
    """
    async with authentication_session() as session:
        operator = await authenticate_operator(
            session,
            email=email,
            password=password,
            totp_code=totp_code,
            org_id=org_id,
            secret_box=secret_box,
        )
        return await establish_session(
            session,
            settings,
            operator=operator,
            cert_fingerprint=cert_fingerprint,
            source_ip=source_ip,
            user_agent=user_agent,
        )


async def sign_out(token: str) -> None:
    """End the session ``token`` names. Idempotent."""
    async with authentication_session() as session:
        await revoke_session(session, token=token)


async def sign_in_federated(
    settings: Settings,
    identity: VerifiedIdentity,
    *,
    device_cookie: str,
    source_ip: str | None,
    user_agent: str | None,
    now: dt.datetime,
) -> tuple[SignIn, EstablishedSession]:
    """Sign a verified member identity in, provisioning it if allowed, and start its session.

    ``SsoRejectedError`` and ``SessionRejectedError`` as the two steps raise
    them; on either, nothing the sign-in wrote (a provisioned operator) is kept.
    """
    async with authentication_session() as session:
        sign_in = await resolve_member_sign_in(
            session, identity, jit_provisioning=settings.oidc_member_jit_provisioning
        )
        established = await establish_sso_session(
            session,
            settings,
            operator=sign_in.operator,
            issuer=identity.issuer,
            subject=identity.subject,
            device_cookie=device_cookie,
            amr=identity.amr,
            source_ip=source_ip,
            user_agent=user_agent,
            now=now,
        )
        await session.commit()
        return sign_in, established


async def close_sessions_for_certificate(fingerprint: str) -> int:
    """End every session bound to a certificate its caller has just revoked. The count.

    Committed on its own, before the caller's revocation commits: a session
    closed for a revocation that then rolls back costs a person a sign-in,
    and ``resolve_session`` refuses a revoked certificate's sessions anyway.
    """
    async with authentication_session() as session:
        closed = await revoke_sessions_for_certificate(session, fingerprint=fingerprint)
        await session.commit()
        return closed
