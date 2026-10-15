"""Recompute every owner tag and owner token under the configured attribution key.

Run with the application stopped and the *new* key mounted as
``AIVS_ATTRIBUTION_KEY_FILE`` (runbook section 7.4a)::

    python -m aivs_server.rekey_attribution            # report what is not on this key
    python -m aivs_server.rekey_attribution --apply    # recompute it

The key being replaced is not needed. Tags and tokens are HMACs of who filed
what, and who filed what is held in ``attribution.submitters``, so each is
recomputed from the mapping rather than converted from its old value. That is
possible because tokens never leave the server (``auth.attribution_key``):
nothing outside the database holds an old one that would stop matching.

Stopped, because a running instance would go on writing values under the old
key while this writes them under the new one. It is one transaction, so a
failure leaves everything on the old key; the instance refuses to start until
every value is on the key it is given (``main.refuse_values_under_other_keys``).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from aivs_server.auth.attribution_key import AttributionKey
from aivs_server.config import get_settings
from aivs_server.db.engine import session_scope
from aivs_server.services.attribution import RekeyCounts, rekey, values_under_other_keys

logger = logging.getLogger(__name__)

__all__ = ["run"]


async def run(key: AttributionKey, *, apply: bool) -> tuple[list[str], RekeyCounts | None]:
    """What is not on ``key``, and, when ``apply``, the counts recomputed onto it."""
    async with session_scope() as session:
        foreign = await values_under_other_keys(session, key)
        counts = await rekey(session, key) if apply else None
    return foreign, counts


def _main() -> int:  # pragma: no cover - operational helper; ``run`` is what is tested
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply", action="store_true", help="recompute every value; without it, only report"
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    key = AttributionKey.from_settings(get_settings())
    foreign, counts = asyncio.run(run(key, apply=args.apply))
    logger.info("attribution key id: %s", key.key_id)
    logger.info("not on this key: %s", ", ".join(foreign) or "nothing")
    if counts is not None:
        logger.info("recomputed: tags=%d tokens=%d", counts.tags, counts.tokens)
    elif foreign:
        logger.info("re-run with --apply, with the application stopped, to recompute them")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())
