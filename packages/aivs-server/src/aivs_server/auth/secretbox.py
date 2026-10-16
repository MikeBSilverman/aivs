"""Envelope encryption for the two secrets AIVS must be able to read back.

Almost nothing here needs to be reversible. Passwords are Argon2id hashes,
session tokens are stored as SHA-256, certificates are public. Two values are
different: an operator's TOTP seed and a member's webhook HMAC key must be
recovered in plaintext to verify a code or sign a payload, so they cannot be
hashed and something has to protect them at rest.

Until this module existed they were base64, which protects against a glance and
nothing else: a database read yielded every operator's working second factor and
every member's signing key. The columns were named ``*_encrypted`` throughout,
which is why the model comments had to carry an apology.

**What this does and does not defend.** The key lives in the process
environment, beside the database credentials, so a full host compromise defeats
it. What it defeats is the realistic set: a stolen backup, a read replica, a
SQL-level disclosure, a support engineer with read access on the database and no
access to the application's environment. That is the category that shows up in
incident reports, and it is a different category from "the attacker owns
everything".

**Construction.** An AEAD chosen by configuration, with the ciphertext bound by
additional authenticated data to the row it belongs to::

    AIVS | version (1) | algorithm (1) | key fingerprint (4) | nonce | ct||tag
    aad = "<purpose>:<row id>"

The AAD is the part worth explaining. Without it a blob is a portable capability:
lift an operator's sealed TOTP seed into another operator's row and it decrypts
happily, so anyone who can write one column inherits the other person's second
factor. Bound, that ciphertext fails to authenticate. Same reasoning as the JWE
AAD in ``docs/encryption-design.md`` §4.

**Every ciphertext says how it was made.** The algorithm and the key are both
named in the header, so changing either is additive rather than a migration
under duress: existing values keep opening under the algorithm and key they were
written with, while new writes use the configured ones. A format that did not
record these would make the *first* choice permanent -- the cost of which is
never visible until the day the choice has to change, which is exactly the day
there is no time to do it carefully.

There is no "AES-512" to grow into; AES is defined for 128, 192 and 256-bit keys
only, and AES-256 is already beyond what a symmetric algorithm needs to be. The
realistic reasons to move are a weakness in GCM's nonce handling, a platform
without AES hardware where a constant-time software cipher is preferable, or a
member's cryptography policy naming something specific. ChaCha20-Poly1305 is
registered alongside AES-256-GCM for that reason, and because a mechanism with
one option in it has never been tested.

**Adding an algorithm** is one entry in ``_ALGORITHMS``: a wire id that is never
reused, a name, the key and nonce sizes, and a factory. Do not renumber existing
ids -- they are on disk.

**Rotation and migration are the same operation.** ``needs_rewrap`` reports a
value that is not on the active key *or* not on the active algorithm, so
``python -m aivs_server.rewrap_secrets`` moves a deployment onto a new algorithm
exactly as it moves one onto a new key.

**Failure is reported, not raised.** An unopenable blob returns ``None``, which
callers already treat as "no secret" -- an operator who cannot be verified fails
their second factor, which is the correct outcome. But it is logged at WARNING
with the row it came from, because the plausible cause is a misconfigured key,
and the symptom otherwise is every login failing with a message about the code
being wrong. A gate that is red for an invisible reason gets lowered.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol, Self

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

if TYPE_CHECKING:
    from collections.abc import Callable

    from aivs_server.config import Settings

__all__ = [
    "ALGORITHM_NAMES",
    "DEFAULT_ALGORITHM_NAME",
    "Algorithm",
    "SecretBox",
    "SecretPurpose",
    "algorithm_by_name",
    "supported_key_sizes",
]

logger = logging.getLogger(__name__)


class _AEAD(Protocol):
    """The slice of the AEAD interface this module uses.

    Both ``AESGCM`` and ``ChaCha20Poly1305`` satisfy it, which is what lets the
    registry treat them interchangeably without the module knowing either.
    """

    def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes: ...

    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes: ...


@dataclass(frozen=True)
class Algorithm:
    """One registered AEAD, and everything the envelope needs to know about it."""

    #: Wire identifier, written into every ciphertext. **Never reuse or renumber:
    #: these bytes are on disk in deployments we do not control.**
    id: int
    #: Configuration-facing name, e.g. ``aes-256-gcm``.
    name: str
    key_bytes: int
    nonce_bytes: int
    factory: Callable[[bytes], _AEAD]


_ALGORITHMS: Final[tuple[Algorithm, ...]] = (
    Algorithm(id=1, name="aes-256-gcm", key_bytes=32, nonce_bytes=12, factory=AESGCM),
    Algorithm(
        id=2,
        name="chacha20-poly1305",
        key_bytes=32,
        nonce_bytes=12,
        factory=ChaCha20Poly1305,
    ),
)

_BY_ID: Final[dict[int, Algorithm]] = {a.id: a for a in _ALGORITHMS}
_BY_NAME: Final[dict[str, Algorithm]] = {a.name: a for a in _ALGORITHMS}

#: What a deployment gets without saying anything. AES-256-GCM because it is
#: hardware-accelerated on every server CPU an ISAC will run this on, and because
#: it is the algorithm a bank's cryptography reviewer expects to see.
DEFAULT_ALGORITHM: Final[Algorithm] = _BY_NAME["aes-256-gcm"]
DEFAULT_ALGORITHM_NAME: Final[str] = DEFAULT_ALGORITHM.name

#: Sorted for stable, quotable error messages.
ALGORITHM_NAMES: Final[tuple[str, ...]] = tuple(sorted(_BY_NAME))


def algorithm_by_name(name: str) -> Algorithm:
    """Look up a registered algorithm, or raise naming the supported set.

    The error is the one an operator sees at startup after a typo, so it lists
    what they could have meant rather than only what they wrote.
    """
    try:
        return _BY_NAME[name]
    except KeyError:
        msg = f"unknown algorithm {name!r}; supported: {', '.join(ALGORITHM_NAMES)}"
        raise ValueError(msg) from None


def supported_key_sizes() -> frozenset[int]:
    """Every key length some registered algorithm accepts.

    Used to sanity-check a *previous* key, whose algorithm is not knowable from
    configuration -- it is whatever the values it still opens were written with.
    """
    return frozenset(a.key_bytes for a in _ALGORITHMS)


#: Format marker and envelope version. Present so a blob written by a future
#: layout is recognisable as such rather than being fed to this one and failing
#: as a bad key. The version covers the *envelope*; the algorithm byte covers
#: the cipher, and the two change for different reasons.
_MAGIC: Final[bytes] = b"AIVS"
_VERSION: Final[int] = 1
_FINGERPRINT_BYTES: Final[int] = 4
#: GCM and Poly1305 tags are both 16 bytes; the shortest possible ciphertext.
_TAG_BYTES: Final[int] = 16

_PREFIX_BYTES: Final[int] = len(_MAGIC) + 1 + 1 + _FINGERPRINT_BYTES

#: Domain separator, so a fingerprint cannot double as a hash of the key that an
#: attacker could confirm a guess against.
_FINGERPRINT_DOMAIN: Final[bytes] = b"aivs-kek-fingerprint-v1"


class SecretPurpose:
    """The AAD purpose labels, spelled once.

    A typo in a purpose string would seal a value that never opens again, and
    would do it silently at write time; there is no reason for them to be
    loose literals. Never change one: each is in the AAD of values on disk.
    """

    TOTP: Final[str] = "operator-totp"
    WEBHOOK_HMAC: Final[str] = "webhook-hmac"
    #: A document's own key (its DEK), sealed under the instance key with the
    #: document's id as the subject (Phase I).
    DOCUMENT_KEY: Final[str] = "document-key"
    #: What is sealed under a document's DEK, each bound to its row:
    #: ``<document>:<version>`` and ``<document>:<comment>``, so a ciphertext
    #: cannot be moved to another version, re-inserted, or re-threaded.
    DOCUMENT_VERSION: Final[str] = "document-version"
    DOCUMENT_COMMENT: Final[str] = "document-comment"


def _fingerprint(key: bytes) -> bytes:
    return hashlib.sha256(_FINGERPRINT_DOMAIN + key).digest()[:_FINGERPRINT_BYTES]


def _aad(purpose: str, subject: uuid.UUID | str) -> bytes:
    return f"{purpose}:{subject}".encode()


class SecretBox:
    """Seals and opens the reversible secrets.

    Sealing uses the configured algorithm and the active key. Opening uses
    whatever the ciphertext says it was written with, under whichever configured
    key matches its fingerprint -- so an algorithm change and a key change are
    both readable transitions rather than flag days.
    """

    def __init__(
        self,
        active: bytes,
        previous: bytes | None = None,
        algorithm: Algorithm = DEFAULT_ALGORITHM,
    ) -> None:
        if len(active) != algorithm.key_bytes:
            msg = (
                f"active key must be exactly {algorithm.key_bytes} bytes for "
                f"{algorithm.name}, got {len(active)}"
            )
            raise ValueError(msg)
        if previous is not None and len(previous) not in supported_key_sizes():
            # Not held to the *active* algorithm's size: the previous key exists
            # to open values written under the previous algorithm, which may not
            # be the current one.
            msg = (
                f"previous key must be one of {sorted(supported_key_sizes())} bytes, "
                f"got {len(previous)}"
            )
            raise ValueError(msg)

        self._algorithm = algorithm
        self._active_fingerprint = _fingerprint(active)
        self._keys: dict[bytes, bytes] = {self._active_fingerprint: active}
        if previous is not None:
            self._keys.setdefault(_fingerprint(previous), previous)

    @classmethod
    def from_settings(cls, settings: Settings) -> Self:
        """Build from validated configuration.

        The base64 decoding, the algorithm name and the key length are all
        checked in ``config``, so a deployment with an unusable combination
        fails at startup rather than at the first login of the day.
        """
        return cls(
            active=settings.secret_encryption_key_bytes,
            previous=settings.secret_encryption_key_previous_bytes,
            algorithm=algorithm_by_name(settings.secret_encryption_algorithm),
        )

    @property
    def algorithm(self) -> Algorithm:
        """The algorithm new values are sealed with."""
        return self._algorithm

    @property
    def active_fingerprint(self) -> str:
        """Hex fingerprint of the active key, for operator-facing diagnostics."""
        return self._active_fingerprint.hex()

    def seal(self, plaintext: str, *, purpose: str, subject: uuid.UUID | str) -> bytes:
        """Seal ``plaintext`` for the row identified by ``subject``."""
        algorithm = self._algorithm
        nonce = os.urandom(algorithm.nonce_bytes)
        cipher = algorithm.factory(self._keys[self._active_fingerprint])
        ciphertext = cipher.encrypt(nonce, plaintext.encode("utf-8"), _aad(purpose, subject))
        return (
            _MAGIC + bytes((_VERSION, algorithm.id)) + self._active_fingerprint + nonce + ciphertext
        )

    def unseal(self, blob: bytes | None, *, purpose: str, subject: uuid.UUID | str) -> str | None:
        """Open a sealed value, or return ``None`` and say why in the log.

        ``None`` for an absent value is not an error: an operator who has not
        enrolled a second factor has no seed, and simply cannot pass it.
        """
        if not blob:
            return None

        header = self._parse(blob, purpose=purpose, subject=subject)
        if header is None:
            return None
        algorithm, fingerprint, nonce, ciphertext = header

        key = self._keys.get(fingerprint)
        if key is None:
            # The overwhelmingly likely cause is a key that was rotated without
            # keeping the old one configured, or a database restored beside the
            # wrong environment. Naming the fingerprint makes that diagnosable
            # without ever printing key material.
            logger.warning(
                "no configured key matches this sealed secret",
                extra={
                    "purpose": purpose,
                    "subject": str(subject),
                    "key_fingerprint": fingerprint.hex(),
                    "algorithm": algorithm.name,
                },
            )
            return None

        if len(key) != algorithm.key_bytes:  # pragma: no cover - see below
            # Unreachable while every registered algorithm takes a 32-byte key,
            # which is why it is not covered: there is no way to configure a key
            # that matches a fingerprint and is the wrong size for the value it
            # opens. It exists for the algorithm that does not, and the reason to
            # write it now rather than then is that "then" is a rollout, and the
            # alternative failure is a raw exception from inside the cipher with
            # no row and no algorithm named.
            logger.warning(
                "configured key is the wrong size for this value's algorithm",
                extra={
                    "purpose": purpose,
                    "subject": str(subject),
                    "algorithm": algorithm.name,
                },
            )
            return None

        try:
            opened = algorithm.factory(key).decrypt(nonce, ciphertext, _aad(purpose, subject))
        except InvalidTag:
            # Either the stored bytes were altered, or this blob belongs to a
            # different row or a different purpose. All three are integrity
            # failures and none of them should be quietly treated as "absent".
            logger.warning(
                "sealed secret failed authentication",
                extra={
                    "purpose": purpose,
                    "subject": str(subject),
                    "key_fingerprint": fingerprint.hex(),
                    "algorithm": algorithm.name,
                },
            )
            return None

        try:
            return opened.decode("utf-8")
        except UnicodeDecodeError:  # pragma: no cover - only reachable via a forged key
            logger.warning(
                "sealed secret opened to non-text",
                extra={"purpose": purpose, "subject": str(subject)},
            )
            return None

    def needs_rewrap(self, blob: bytes | None) -> bool:
        """Whether this value is not on the active key *and* algorithm.

        Drives the rotation tool, and answers the two questions an operator has
        after changing either: is it safe to drop the previous key yet, and has
        everything moved onto the new algorithm.
        """
        if not blob:
            return False
        if len(blob) < _PREFIX_BYTES or not blob.startswith(_MAGIC):
            return True
        version, algorithm_id = blob[len(_MAGIC)], blob[len(_MAGIC) + 1]
        if version != _VERSION or algorithm_id != self._algorithm.id:
            return True
        return blob[len(_MAGIC) + 2 : _PREFIX_BYTES] != self._active_fingerprint

    def _parse(
        self, blob: bytes, *, purpose: str, subject: uuid.UUID | str
    ) -> tuple[Algorithm, bytes, bytes, bytes] | None:
        """Split a blob into (algorithm, fingerprint, nonce, ciphertext)."""
        if len(blob) < _PREFIX_BYTES or not blob.startswith(_MAGIC):
            logger.warning(
                "sealed secret is not in a recognised format",
                extra={"purpose": purpose, "subject": str(subject)},
            )
            return None

        version = blob[len(_MAGIC)]
        if version != _VERSION:
            # Written by a newer build, most likely mid-rollout or after a
            # rollback. Refusing beats guessing at a layout we do not have.
            logger.warning(
                "sealed secret uses an unsupported envelope version",
                extra={"purpose": purpose, "subject": str(subject), "version": version},
            )
            return None

        algorithm = _BY_ID.get(blob[len(_MAGIC) + 1])
        if algorithm is None:
            logger.warning(
                "sealed secret uses an algorithm this build does not know",
                extra={
                    "purpose": purpose,
                    "subject": str(subject),
                    "algorithm_id": blob[len(_MAGIC) + 1],
                },
            )
            return None

        body = blob[_PREFIX_BYTES:]
        if len(body) < algorithm.nonce_bytes + _TAG_BYTES:
            logger.warning(
                "sealed secret is too short for its algorithm",
                extra={"purpose": purpose, "subject": str(subject), "algorithm": algorithm.name},
            )
            return None

        fingerprint = blob[len(_MAGIC) + 2 : _PREFIX_BYTES]
        return algorithm, fingerprint, body[: algorithm.nonce_bytes], body[algorithm.nonce_bytes :]
