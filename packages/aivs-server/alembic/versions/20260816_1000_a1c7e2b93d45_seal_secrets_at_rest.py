"""Re-seal the two reversible secrets with real encryption.

``operators.totp_secret_encrypted`` and ``webhooks.hmac_secret_encrypted`` were
base64 for as long as they existed. The columns said ``encrypted``, the model
comments said otherwise, and anyone with a database read -- a backup, a replica,
a support engineer with SELECT -- held every operator's working second factor
and every member's webhook signing key.

This is a data migration, not a schema one: the columns are already ``bytea``
and keep their names, which are accurate for the first time. Each value is
decoded from base64 and re-sealed by ``auth.secretbox`` -- an AEAD bound by
additional authenticated data to the id of the row it belongs to, under the key
in ``AIVS_SECRET_ENCRYPTION_KEY`` and the algorithm in
``AIVS_SECRET_ENCRYPTION_ALGORITHM`` (AES-256-GCM unless set). Each value
records which of those it was written with, so a later change to either is a
re-wrap rather than another migration.

**It requires that key in the environment and refuses to run without it.** The
alternative -- carrying a "read the legacy format" branch in the application
indefinitely -- means the base64 path survives in the code long after anyone
remembers why, and the migration that was meant to remove it never gets written.
One format in the codebase is worth one operational precondition, and the
precondition is stated in docs/operator-runbook.md.

Downgrade re-encodes to base64, because a downgrade that left ciphertext behind
under a column the old code reads with ``b64decode`` would silently break every
login rather than restoring the previous state.

Revision ID: a1c7e2b93d45
Revises: f7b3d40e9a15
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
import uuid

import sqlalchemy as sa
from alembic import op

from aivs_server.config import read_secret_file
from aivs_server.auth.secretbox import (
    DEFAULT_ALGORITHM_NAME,
    SecretBox,
    SecretPurpose,
    algorithm_by_name,
)

revision: str = "a1c7e2b93d45"
down_revision: str | None = "f7b3d40e9a15"
branch_labels: str | None = None
depends_on: str | None = None

_KEY_VAR = "AIVS_SECRET_ENCRYPTION_KEY"
_ALGORITHM_VAR = "AIVS_SECRET_ENCRYPTION_ALGORITHM"

_OPERATORS = sa.table(
    "operators",
    sa.column("id", sa.Uuid()),
    sa.column("totp_secret_encrypted", sa.LargeBinary()),
)
_WEBHOOKS = sa.table(
    "webhooks",
    sa.column("id", sa.Uuid()),
    sa.column("hmac_secret_encrypted", sa.LargeBinary()),
)


def _box() -> SecretBox:
    # The same two forms the application accepts; the file form is required
    # outside dev, so a migration that read only the variable could not run
    # against a correctly configured deployment.
    key_file = os.environ.get(f"{_KEY_VAR}_FILE")
    configured = read_secret_file(Path(key_file)) if key_file else os.environ.get(_KEY_VAR)
    if not configured:
        msg = (
            f"{_KEY_VAR} must be set to run this migration: it re-encrypts the "
            "stored TOTP seeds and webhook signing keys. Generate one with "
            "`openssl rand -base64 32` and set it on the application too -- the "
            "same value, or every one of those secrets becomes unreadable."
        )
        raise RuntimeError(msg)
    # The algorithm is read from the environment as well, so a deployment that
    # has chosen something other than the default does not have every row
    # written under the default and immediately need re-wrapping.
    return SecretBox(
        active=base64.b64decode(configured),
        algorithm=algorithm_by_name(os.environ.get(_ALGORITHM_VAR) or DEFAULT_ALGORITHM_NAME),
    )


def upgrade() -> None:
    bind = op.get_bind()
    box = _box()

    for row in bind.execute(
        sa.select(_OPERATORS.c.id, _OPERATORS.c.totp_secret_encrypted).where(
            _OPERATORS.c.totp_secret_encrypted.is_not(None)
        )
    ):
        plaintext = _decode_legacy(row.totp_secret_encrypted)
        if plaintext is None:
            continue
        bind.execute(
            sa.update(_OPERATORS)
            .where(_OPERATORS.c.id == row.id)
            .values(
                totp_secret_encrypted=box.seal(
                    plaintext, purpose=SecretPurpose.TOTP, subject=_as_uuid(row.id)
                )
            )
        )

    for row in bind.execute(sa.select(_WEBHOOKS.c.id, _WEBHOOKS.c.hmac_secret_encrypted)):
        plaintext = _decode_legacy(row.hmac_secret_encrypted)
        if plaintext is None:
            continue
        bind.execute(
            sa.update(_WEBHOOKS)
            .where(_WEBHOOKS.c.id == row.id)
            .values(
                hmac_secret_encrypted=box.seal(
                    plaintext, purpose=SecretPurpose.WEBHOOK_HMAC, subject=_as_uuid(row.id)
                )
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    box = _box()

    for row in bind.execute(
        sa.select(_OPERATORS.c.id, _OPERATORS.c.totp_secret_encrypted).where(
            _OPERATORS.c.totp_secret_encrypted.is_not(None)
        )
    ):
        plaintext = box.unseal(
            row.totp_secret_encrypted, purpose=SecretPurpose.TOTP, subject=_as_uuid(row.id)
        )
        if plaintext is None:
            continue
        bind.execute(
            sa.update(_OPERATORS)
            .where(_OPERATORS.c.id == row.id)
            .values(totp_secret_encrypted=base64.b64encode(plaintext.encode("ascii")))
        )

    for row in bind.execute(sa.select(_WEBHOOKS.c.id, _WEBHOOKS.c.hmac_secret_encrypted)):
        plaintext = box.unseal(
            row.hmac_secret_encrypted,
            purpose=SecretPurpose.WEBHOOK_HMAC,
            subject=_as_uuid(row.id),
        )
        if plaintext is None:
            continue
        bind.execute(
            sa.update(_WEBHOOKS)
            .where(_WEBHOOKS.c.id == row.id)
            .values(hmac_secret_encrypted=base64.b64encode(plaintext.encode("ascii")))
        )


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


def _decode_legacy(stored: bytes | None) -> str | None:
    """Decode a base64 value, skipping anything already sealed.

    Re-running the migration, or running it against a database that a newer
    application has already written to, must not double-seal. A sealed blob
    starts with the format marker and is not valid base64 of ASCII, so both
    checks are belt and braces on the same fact.
    """
    if not stored:
        return None
    if stored.startswith(b"AIVS"):
        return None
    try:
        return base64.b64decode(stored, validate=True).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return None
