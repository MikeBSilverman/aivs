"""Re-seal stored secrets under the active key-encryption key.

Run during a key rotation, with the new key in ``AIVS_SECRET_ENCRYPTION_KEY``
and the old one in ``AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS``::

    python -m aivs_server.rewrap_secrets            # report what is stale
    python -m aivs_server.rewrap_secrets --apply    # re-seal it

Then drop the previous key from the environment once a report run says nothing
is stale.

This exists because rotation that requires a flag day does not happen. Both
keys open, only the active key seals, and this walks the tables that hold
sealed values and moves them forward. It is idempotent and safe to run against a
live instance: each row is re-sealed from its own plaintext, so a row written
concurrently under the active key is simply already current.

A value that cannot be opened is reported and skipped, never overwritten. The
only thing worse than a secret sealed under a key you no longer have is that
secret replaced with one sealed under a key you do.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.auth.secretbox import SecretBox, SecretPurpose
from aivs_server.config import get_settings
from aivs_server.db.engine import session_scope
from aivs_server.db.models import Document, Operator, Webhook

logger = logging.getLogger(__name__)

__all__ = ["rewrap"]


class _Counts:
    """Tallies for one run, reported whether or not anything was written."""

    def __init__(self) -> None:
        self.current = 0
        self.stale = 0
        self.rewrapped = 0
        self.unopenable = 0


async def _rewrap_operators(
    session: AsyncSession, box: SecretBox, counts: _Counts, *, apply: bool
) -> None:
    operators = (
        await session.execute(select(Operator).where(Operator.totp_secret_encrypted.is_not(None)))
    ).scalars()

    for operator in operators:
        blob = operator.totp_secret_encrypted
        if not box.needs_rewrap(blob):
            counts.current += 1
            continue
        counts.stale += 1
        plaintext = box.unseal(blob, purpose=SecretPurpose.TOTP, subject=operator.id)
        if plaintext is None:
            counts.unopenable += 1
            logger.error("operator %s: TOTP seed could not be opened; left alone", operator.id)
            continue
        if apply:
            operator.totp_secret_encrypted = box.seal(
                plaintext, purpose=SecretPurpose.TOTP, subject=operator.id
            )
            counts.rewrapped += 1


async def _rewrap_webhooks(
    session: AsyncSession, box: SecretBox, counts: _Counts, *, apply: bool
) -> None:
    webhooks = (await session.execute(select(Webhook))).scalars()

    for webhook in webhooks:
        blob = webhook.hmac_secret_encrypted
        if not box.needs_rewrap(blob):
            counts.current += 1
            continue
        counts.stale += 1
        plaintext = box.unseal(blob, purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook.id)
        if plaintext is None:
            counts.unopenable += 1
            logger.error("webhook %s: signing key could not be opened; left alone", webhook.id)
            continue
        if apply:
            webhook.hmac_secret_encrypted = box.seal(
                plaintext, purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook.id
            )
            counts.rewrapped += 1


async def _rewrap_document_keys(
    session: AsyncSession, box: SecretBox, counts: _Counts, *, apply: bool
) -> None:
    """Each document's own key, re-sealed; what it seals is untouched, since it does not change.

    A document key that does not open is a document whose whole history is
    lost -- every version and comment is sealed under it -- and says so.
    """
    documents = (await session.execute(select(Document))).scalars()

    for document in documents:
        blob = document.dek_sealed
        if not box.needs_rewrap(blob):
            counts.current += 1
            continue
        counts.stale += 1
        plaintext = box.unseal(blob, purpose=SecretPurpose.DOCUMENT_KEY, subject=document.id)
        if plaintext is None:
            counts.unopenable += 1
            logger.error(
                "document %s: its key could not be opened; its whole history is lost; left alone",
                document.id,
            )
            continue
        if apply:
            document.dek_sealed = box.seal(
                plaintext, purpose=SecretPurpose.DOCUMENT_KEY, subject=document.id
            )
            counts.rewrapped += 1


async def rewrap(session: AsyncSession, box: SecretBox, *, apply: bool) -> _Counts:
    """Walk every table that holds sealed values, re-sealing under the active key when ``apply``.

    Takes its session and sealer rather than reaching for the process-wide ones,
    so the rotation path can be exercised by tests against a real database. A
    key-rotation tool that has only ever been run by hand is a tool that works
    until the day it is needed.
    """
    counts = _Counts()
    await _rewrap_operators(session, box, counts, apply=apply)
    await _rewrap_webhooks(session, box, counts, apply=apply)
    await _rewrap_document_keys(session, box, counts, apply=apply)
    return counts


async def _run(*, apply: bool) -> _Counts:
    """Wire ``rewrap`` to the process-wide settings and engine."""
    box = SecretBox.from_settings(get_settings())
    # ``session_scope`` commits on clean exit; a report-only run writes nothing
    # to commit, so the same path serves both modes.
    async with session_scope() as session:
        return await rewrap(session, box, apply=apply)


def _main() -> int:  # pragma: no cover - operational helper
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write the re-sealed values; without it, only report",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    counts = asyncio.run(_run(apply=args.apply))

    box = SecretBox.from_settings(get_settings())
    logger.info("active key fingerprint: %s", box.active_fingerprint)
    logger.info(
        "current=%d stale=%d rewrapped=%d unopenable=%d",
        counts.current,
        counts.stale,
        counts.rewrapped,
        counts.unopenable,
    )
    if counts.unopenable:
        logger.error(
            "%d secret(s) could not be opened by any configured key. Do not drop "
            "the previous key: it may be the one that opens them.",
            counts.unopenable,
        )
        return 1
    if counts.stale and not args.apply:
        logger.info("re-run with --apply to re-seal them")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())
