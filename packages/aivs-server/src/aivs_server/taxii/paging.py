"""Keyset pagination for TAXII object listings.

TAXII's ``next`` token is opaque to clients, which leaves the server free to
choose. AIVS uses a signed keyset cursor rather than an offset for two reasons:

**Correctness.** Members poll continuously and content is inserted while they
page. With ``LIMIT/OFFSET``, a row added before the cursor position shifts every
later row by one and the member silently skips an object -- in this system, a
vulnerability warning they will swear they never received. A keyset cursor
anchored on ``(date_added, id)`` cannot skip or duplicate.

**Cost.** ``OFFSET`` makes the database walk and discard every preceding row, so
page 500 costs five hundred times page 1. Keyset pagination is a range scan on
``ix_distributions_circle_paging`` regardless of depth.

The cursor is signed and bound to the collection it was issued for. The
visibility filter is applied independently on every request, so a forged cursor
could never widen access -- but binding it means a cursor pasted between
collections fails loudly instead of returning a confusing empty page.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Final

from itsdangerous import BadSignature, URLSafeSerializer

__all__ = ["Cursor", "CursorError", "decode_cursor", "encode_cursor"]

#: Namespaces the signature so a token minted for pagination can never be
#: accepted somewhere else that shares the signing key.
_SALT: Final[str] = "aivs.taxii.cursor.v1"


class CursorError(ValueError):
    """A ``next`` parameter was missing, malformed, forged, or misapplied."""


@dataclass(frozen=True, slots=True)
class Cursor:
    """Position within a collection's ordered stream of distributions."""

    date_added: dt.datetime
    distribution_id: uuid.UUID
    collection_id: uuid.UUID


def encode_cursor(secret: str, cursor: Cursor) -> str:
    """Serialise and sign a cursor."""
    serializer = URLSafeSerializer(secret, salt=_SALT)
    payload = {
        "d": cursor.date_added.astimezone(dt.UTC).isoformat(),
        "i": str(cursor.distribution_id),
        "c": str(cursor.collection_id),
    }
    token: str = serializer.dumps(payload)
    return token


def decode_cursor(secret: str, token: str, expected_collection_id: uuid.UUID) -> Cursor:
    """Verify and parse a cursor, or raise :class:`CursorError`.

    Raises for a bad signature, a malformed payload, or a cursor issued for a
    different collection. The caller turns any of these into HTTP 400, which is
    what TAXII 2.1 specifies for a malformed filter parameter.
    """
    serializer = URLSafeSerializer(secret, salt=_SALT)
    try:
        payload = serializer.loads(token)
    except BadSignature as exc:
        msg = "cursor signature invalid"
        raise CursorError(msg) from exc

    if not isinstance(payload, dict):
        msg = "cursor payload malformed"
        raise CursorError(msg)

    try:
        date_added = dt.datetime.fromisoformat(str(payload["d"]))
        distribution_id = uuid.UUID(str(payload["i"]))
        collection_id = uuid.UUID(str(payload["c"]))
    except (KeyError, ValueError, TypeError) as exc:
        msg = "cursor payload malformed"
        raise CursorError(msg) from exc

    if date_added.tzinfo is None:
        msg = "cursor timestamp is not timezone-aware"
        raise CursorError(msg)

    if collection_id != expected_collection_id:
        msg = "cursor was issued for a different collection"
        raise CursorError(msg)

    return Cursor(
        date_added=date_added,
        distribution_id=distribution_id,
        collection_id=collection_id,
    )
