"""Operator password hashing and second-factor verification.

Argon2id, with the reference implementation's defaults rather than tuned
constants: the parameters that matter are memory and time cost, and a number
chosen once and never revisited is worse than the library's, which tracks
current guidance.

Two properties are enforced here rather than left to callers:

**Verification is constant-time in the failure case that matters.** A login
attempt for an address that does not exist must take about as long as one for an
address that does, or the response time enumerates operators. :func:`verify` is
therefore always called, against a dummy hash when no operator was found.

**Rehashing is automatic.** When the library's parameters change, a correct
password is transparently re-hashed at next login, so the stored cost keeps up
without a migration.
"""

from __future__ import annotations

import hmac
import secrets
from typing import Final

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

__all__ = [
    "MIN_PASSWORD_LENGTH",
    "generate_totp_secret",
    "hash_password",
    "needs_rehash",
    "totp_provisioning_uri",
    "verify_password",
    "verify_totp",
]

_hasher: Final[PasswordHasher] = PasswordHasher()

#: A dummy hash, verified against when no operator matched, so that a login for
#: an unknown address costs the same as one for a known address.
_DUMMY_HASH: Final[str] = _hasher.hash("not-a-real-password")

#: NIST SP 800-63B puts the floor at 8 and explicitly discourages composition
#: rules; length is what matters. Operators here are named individuals at member
#: firms, not the public, so this is a floor rather than the whole policy.
MIN_PASSWORD_LENGTH: Final[int] = 12

#: TOTP tolerance, in 30-second steps either side of now. One step absorbs
#: ordinary clock drift; more would widen the window a stolen code stays usable.
_TOTP_VALID_WINDOW: Final[int] = 1


def hash_password(password: str) -> str:
    """Return an Argon2id hash. Raises if the password is too short."""
    if len(password) < MIN_PASSWORD_LENGTH:
        msg = f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        raise ValueError(msg)
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Verify a password, in time independent of whether the operator exists.

    ``stored_hash`` of ``None`` means no operator matched; the dummy hash is
    verified instead so the caller can branch on the boolean without the timing
    of that branch revealing which case it was.
    """
    candidate = stored_hash or _DUMMY_HASH
    try:
        _hasher.verify(candidate, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    # An operator that does not exist never authenticates, whatever the dummy
    # hash happens to verify against.
    return stored_hash is not None


def needs_rehash(stored_hash: str) -> bool:
    """Whether a stored hash should be upgraded to current parameters."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        # An unparseable hash cannot be verified either, so the operator will
        # fail login regardless; reporting True keeps the caller's logic simple.
        return True


def generate_totp_secret() -> str:
    """Return a fresh base32 TOTP secret."""
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, *, operator_email: str, instance_name: str) -> str:
    """Return the otpauth:// URI an authenticator app scans.

    The instance name is the issuer, so an analyst who belongs to more than one
    ISAC's instance can tell the entries apart in their authenticator.
    """
    return pyotp.TOTP(secret).provisioning_uri(name=operator_email, issuer_name=instance_name)


def verify_totp(secret: str | None, code: str) -> bool:
    """Verify a TOTP code against a secret.

    Returns ``False`` for a missing secret rather than raising: an operator who
    has not completed enrolment simply cannot pass the second factor, which is
    the correct outcome and not an error condition.
    """
    if not secret:
        return False
    candidate = code.strip().replace(" ", "")
    if not candidate.isdigit():
        return False
    return bool(pyotp.TOTP(secret).verify(candidate, valid_window=_TOTP_VALID_WINDOW))


def generate_session_token() -> str:
    """Return a fresh session token.

    256 bits from the system CSPRNG. The token is handed to the browser; only
    its SHA-256 is stored, so a database disclosure does not hand an attacker
    live sessions.
    """
    return secrets.token_urlsafe(32)


def constant_time_equals(left: str, right: str) -> bool:
    """Compare two tokens without leaking their common prefix length."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
