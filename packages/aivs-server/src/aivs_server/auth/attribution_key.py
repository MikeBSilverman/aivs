"""The attribution key: what keeps owner tags and owner tokens out of reach of SQL (Phase P).

Who filed a submission lives in the ``attribution`` schema, which the member
login will not be able to read (slice 3c). The member path still has to answer
two questions about it without that read:

- **"Is this submission mine?"** ``submissions.owner_tag`` is an HMAC of the
  filer's organisation id and the submission id. The member path recomputes it
  for the caller and compares. A tag per submission, so two tags cannot be
  matched to gather one firm's filings.
- **"Which owner does this version count as?"** ``stix_objects.owner_token``
  is an HMAC of the owner's organisation id and the STIX id, so ingest can
  compute it rather than read it back from ``attribution.object_owners``.

The key is held by the application and never by the database. A reader with
SQL alone -- injection on the member path, a stolen backup, a read replica --
can neither compute a tag or token for a guessed organisation, nor reverse one.
A hash without a key could be reversed by anyone holding the few dozen
organisation ids, which is why slice 2's tokens were random until now.

**One key, three subkeys.** HKDF-SHA256 derives the tag key, the token key and
the key id under fixed labels, so a tag can never be checked as a token and
the key id says nothing about either.

**Every value names its key.** ``1.<key id>.<mac>``: the format, the key it
was made under, and 128 bits of HMAC-SHA256. That is what lets startup refuse
an instance whose rows are under another key (a half-finished rotation) rather
than treat every member's submissions as someone else's. CLAUDE.md section 5,
"stored ciphertext says how it was made".

**Rotation.** Tokens never leave the server: they are compared with each other
in SQL and serialised nowhere. So rotating the key is recomputing every tag
and token from the mapping under the new key, which needs only the new key
(``python -m aivs_server.rekey_attribution``, runbook section 7.4a).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import uuid
from typing import TYPE_CHECKING, Final, Self

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

if TYPE_CHECKING:
    from aivs_server.config import Settings

__all__ = ["KEY_BYTES", "AttributionKey", "ForeignAttributionKeyError"]

#: The key's length: ``openssl rand -base64 32``.
KEY_BYTES: Final[int] = 32

#: The value format. Written into every tag and token; never renumber it.
_FORMAT: Final[str] = "1"
_TAG_LABEL: Final[bytes] = b"aivs/attribution/owner-tag/v1"
_TOKEN_LABEL: Final[bytes] = b"aivs/attribution/owner-token/v1"
_KEY_ID_LABEL: Final[bytes] = b"aivs/attribution/key-id/v1"
_KEY_ID_BYTES: Final[int] = 4
#: 128 bits: forging a value still needs the key, and the value fits the
#: 36-character columns tokens have always had.
_MAC_BYTES: Final[int] = 16


class ForeignAttributionKeyError(LookupError):
    """A tag or token was made under a key this instance does not hold.

    Raised rather than answered "not yours": a member whose submissions all
    answered "not yours" after a half-finished rotation would see them vanish
    with no fault anywhere.
    """


def _derive(key: bytes, label: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=label).derive(key)


def _mac(key: bytes, *parts: bytes) -> str:
    digest = hmac.new(key, b"".join(parts), hashlib.sha256).digest()[:_MAC_BYTES]
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class AttributionKey:
    """The derived subkeys of one attribution key, and the values made with them."""

    __slots__ = ("_tag_key", "_token_key", "key_id")

    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_BYTES:
            msg = f"the attribution key must be {KEY_BYTES} bytes, got {len(key)}"
            raise ValueError(msg)
        self._tag_key = _derive(key, _TAG_LABEL, 32)
        self._token_key = _derive(key, _TOKEN_LABEL, 32)
        #: Names the key in every value it makes. Derived, so it reveals nothing
        #: about the subkeys.
        self.key_id = _derive(key, _KEY_ID_LABEL, _KEY_ID_BYTES).hex()

    @classmethod
    def from_settings(cls, settings: Settings) -> Self:
        return cls(settings.attribution_key_bytes)

    def __repr__(self) -> str:
        return f"AttributionKey(key_id={self.key_id!r})"

    @property
    def prefix(self) -> str:
        """What every value made under this key starts with, for finding the others."""
        return f"{_FORMAT}.{self.key_id}."

    def owner_tag(self, org_id: uuid.UUID, submission_id: uuid.UUID) -> str:
        """The tag of ``submission_id`` filed by ``org_id``."""
        return self.prefix + _mac(self._tag_key, org_id.bytes, submission_id.bytes)

    def owner_token(self, org_id: uuid.UUID, stix_id: str) -> str:
        """The token ``org_id``'s versions of ``stix_id`` are stored with.

        The organisation id is a fixed 16 bytes, so the concatenation cannot be
        read two ways.
        """
        return self.prefix + _mac(self._token_key, org_id.bytes, stix_id.encode("utf-8"))

    def is_owner_tag(self, tag: str, org_id: uuid.UUID, submission_id: uuid.UUID) -> bool:
        """Whether ``tag`` says ``org_id`` filed ``submission_id``."""
        if not tag.startswith(self.prefix):
            msg = f"owner tag of submission {submission_id} is not under key {self.key_id}"
            raise ForeignAttributionKeyError(msg)
        return hmac.compare_digest(tag, self.owner_tag(org_id, submission_id))
