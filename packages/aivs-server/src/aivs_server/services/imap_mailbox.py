"""The email-to-draft mailbox, over IMAP with TLS (services.email_intake).

Kept to the five operations the intake needs, so the intake is tested against
a fake with the same shape, and this file is the only one that speaks IMAP.
Every call blocks; the intake runs each through ``asyncio.to_thread`` and never
while it holds a transaction open.

A message is moved with ``UID MOVE``, or copied and then expunged by its own
UID (``UID EXPUNGE``, UIDPLUS). A server offering neither is refused at
connect: a plain EXPUNGE removes every message anyone flagged for deletion in
the mailbox, not only ours (found by T1's review).

TLS is the only transport: ``IMAP4_SSL`` with the default context, which
verifies the server's certificate and name. There is no setting for plaintext
or for skipping verification. The credential is the mailbox's, so a man in
the middle would read every member's message.
"""

from __future__ import annotations

import imaplib
import re
import ssl
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol

__all__ = ["ImapMailbox", "Mailbox", "MailboxError", "MailboxLogin"]

_SIZE: Final[re.Pattern[bytes]] = re.compile(rb"RFC822\.SIZE (\d+)")
#: How much of an oversize message's header is fetched: a message whose header
#: is the large part must not be loaded whole to be refused.
HEADER_BYTES: Final[int] = 65_536
_MOVING: Final[frozenset[str]] = frozenset({"MOVE", "UIDPLUS"})


class MailboxError(Exception):
    """The server refused an operation the intake needs; the run stops and is retried."""


class Mailbox(Protocol):
    """What the intake does with a mailbox. Messages are addressed by UID."""

    def uids(self) -> list[str]: ...

    def size(self, uid: str) -> int: ...

    def fetch(self, uid: str) -> bytes: ...

    def fetch_header(self, uid: str) -> bytes: ...

    def move(self, uid: str, folder: str) -> None: ...


@dataclass(frozen=True, slots=True)
class MailboxLogin:
    """Where the mailbox is and how to sign in to it."""

    host: str
    port: int
    username: str
    password: str
    mailbox: str
    timeout_seconds: float


class ImapMailbox:
    """One signed-in IMAP connection with the intake's mailbox selected."""

    def __init__(self, client: imaplib.IMAP4) -> None:
        self._client = client

    @classmethod
    def connect(cls, login: MailboxLogin) -> ImapMailbox:
        """Sign in over verified TLS and select the mailbox. Blocking."""
        client = imaplib.IMAP4_SSL(
            login.host,
            login.port,
            ssl_context=ssl.create_default_context(),
            timeout=login.timeout_seconds,
        )
        mailbox = cls(client)
        mailbox._expect(client.login(login.username, login.password), "LOGIN")
        mailbox._expect(client.select(login.mailbox), "SELECT")
        if not _MOVING & set(client.capabilities):
            msg = "the IMAP server offers neither MOVE nor UIDPLUS: no message can be moved alone"
            raise MailboxError(msg)
        return mailbox

    def close(self) -> None:
        self._client.logout()

    def uids(self) -> list[str]:
        """Every message in the selected mailbox, oldest first."""
        data = self._expect(self._client.uid("SEARCH", "ALL"), "SEARCH")
        return [uid.decode("ascii") for uid in _first_bytes(data).split()]

    def size(self, uid: str) -> int:
        data = self._expect(self._client.uid("FETCH", uid, "(RFC822.SIZE)"), "FETCH SIZE")
        match = _SIZE.search(_first_bytes(data))
        if match is None:
            msg = f"no size for message {uid}"
            raise MailboxError(msg)
        return int(match.group(1))

    def fetch(self, uid: str) -> bytes:
        """The whole message, without marking it read."""
        return self._fetch_part(uid, "(BODY.PEEK[])")

    def fetch_header(self, uid: str) -> bytes:
        """The start of the header alone, for a message too large to fetch."""
        return self._fetch_part(uid, f"(BODY.PEEK[HEADER]<0.{HEADER_BYTES}>)")

    def move(self, uid: str, folder: str) -> None:
        """Move, never delete: the folder is the record of what arrived.

        ``UID MOVE`` (RFC 6851) where the server has it; otherwise a copy, then
        this message alone flagged and expunged by UID (RFC 4315).
        """
        if "MOVE" in self._client.capabilities:
            self._expect(self._client.uid("MOVE", uid, folder), "MOVE")
            return
        self._expect(self._client.uid("COPY", uid, folder), "COPY")
        self._expect(self._client.uid("STORE", uid, "+FLAGS", r"(\Deleted)"), "STORE")
        self._expect(self._client.uid("EXPUNGE", uid), "UID EXPUNGE")

    def _fetch_part(self, uid: str, part: str) -> bytes:
        data = self._expect(self._client.uid("FETCH", uid, part), "FETCH")
        for item in data:
            if isinstance(item, tuple):
                return bytes(item[1])
        msg = f"no content for message {uid}"
        raise MailboxError(msg)

    @staticmethod
    def _expect(response: tuple[str, Sequence[object]], operation: str) -> Sequence[object]:
        status, data = response
        if status != "OK":
            msg = f"IMAP {operation} refused: {status}"
            raise MailboxError(msg)
        return data


def _first_bytes(data: Sequence[object]) -> bytes:
    first = data[0] if data else b""
    if isinstance(first, tuple):
        first = first[0]
    return first if isinstance(first, bytes) else b""
