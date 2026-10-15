"""The intake's IMAP connection: verified TLS only, and messages moved, never deleted (SF-93)."""

from __future__ import annotations

import ssl

import pytest

from aivs_server.services import imap_mailbox
from aivs_server.services.imap_mailbox import ImapMailbox, MailboxError, MailboxLogin

LOGIN = MailboxLogin(
    host="imap.isac.test",
    port=993,
    username="intake",
    password="mailbox-password-for-tests",
    mailbox="INBOX",
    timeout_seconds=5,
)
MESSAGE = b"From: alice@bank.test\r\nSubject: hi\r\n\r\nbody\r\n"


class FakeClient:
    """An IMAP server's answers, recording each command."""

    def __init__(self, *, capabilities: tuple[str, ...] = ("IMAP4REV1", "MOVE")) -> None:
        self.capabilities = capabilities
        self.commands: list[tuple[str, ...]] = []
        self.refuse: set[str] = set()

    def _answer(self, name: str, data: list[object]) -> tuple[str, list[object]]:
        return ("NO", [b"refused"]) if name in self.refuse else ("OK", data)

    def login(self, user: str, password: str):
        self.commands.append(("LOGIN", user, password))
        return self._answer("LOGIN", [b"ok"])

    def select(self, mailbox: str):
        self.commands.append(("SELECT", mailbox))
        return self._answer("SELECT", [b"2"])

    def uid(self, command: str, *args: str):
        self.commands.append((command, *args))
        data: list[object] = {
            "SEARCH": [b"7 9"],
            "FETCH": [(b"7 (UID 7 RFC822.SIZE 1234 BODY[] {40}", MESSAGE), b")"],
        }.get(command, [b"done"])
        return self._answer(command, data)

    def expunge(self):
        self.commands.append(("EXPUNGE",))
        return self._answer("EXPUNGE", [b"7"])

    def logout(self):
        self.commands.append(("LOGOUT",))
        return ("BYE", [b""])


@pytest.fixture
def connected(monkeypatch):
    seen: dict[str, object] = {}
    client = FakeClient()

    def fake_ssl(host, port, *, ssl_context, timeout):
        seen.update(host=host, port=port, ssl_context=ssl_context, timeout=timeout)
        return client

    monkeypatch.setattr(imap_mailbox.imaplib, "IMAP4_SSL", fake_ssl)
    return ImapMailbox.connect(LOGIN), client, seen


@pytest.mark.requirement("SF-93")
def test_the_mailbox_is_reached_over_tls_with_the_servers_certificate_verified(connected):
    _mailbox, client, seen = connected

    context = seen["ssl_context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert (seen["host"], seen["port"]) == ("imap.isac.test", 993)
    assert client.commands[:2] == [
        ("LOGIN", "intake", "mailbox-password-for-tests"),
        ("SELECT", "INBOX"),
    ]


def test_messages_are_listed_sized_and_fetched_without_being_marked_read(connected):
    mailbox, client, _ = connected

    assert mailbox.uids() == ["7", "9"]
    assert mailbox.size("7") == 1234
    assert mailbox.fetch("7") == MESSAGE
    assert ("FETCH", "7", "(BODY.PEEK[])") in client.commands


@pytest.mark.requirement("SF-93")
def test_a_message_is_moved_where_the_server_can_and_copied_then_expunged_where_it_cannot(
    monkeypatch,
):
    for capabilities, expected in [
        (("IMAP4REV1", "MOVE"), [("MOVE", "7", "AIVS/accepted")]),
        (
            ("IMAP4REV1", "UIDPLUS"),
            [
                ("COPY", "7", "AIVS/accepted"),
                ("STORE", "7", "+FLAGS", r"(\Deleted)"),
                # This message alone: a plain EXPUNGE would erase whatever
                # anyone else had flagged in the mailbox.
                ("EXPUNGE", "7"),
            ],
        ),
    ]:
        client = FakeClient(capabilities=capabilities)
        mailbox = ImapMailbox(client)  # type: ignore[arg-type]
        mailbox.move("7", "AIVS/accepted")
        assert client.commands == expected


def test_a_refused_copy_stops_before_the_original_is_flagged():
    client = FakeClient(capabilities=("IMAP4REV1", "UIDPLUS"))
    client.refuse.add("COPY")
    mailbox = ImapMailbox(client)  # type: ignore[arg-type]

    with pytest.raises(MailboxError, match="COPY"):
        mailbox.move("7", "AIVS/accepted")
    assert [command[0] for command in client.commands] == ["COPY"]


def test_a_refused_login_is_an_error_not_an_empty_mailbox(monkeypatch):
    client = FakeClient()
    client.refuse.add("LOGIN")
    monkeypatch.setattr(imap_mailbox.imaplib, "IMAP4_SSL", lambda *_args, **_kwargs: client)

    with pytest.raises(MailboxError, match="LOGIN"):
        ImapMailbox.connect(LOGIN)


@pytest.mark.requirement("SF-93")
def test_a_server_that_cannot_move_one_message_alone_is_refused(monkeypatch):
    client = FakeClient(capabilities=("IMAP4REV1",))
    monkeypatch.setattr(imap_mailbox.imaplib, "IMAP4_SSL", lambda *_args, **_kwargs: client)

    with pytest.raises(MailboxError, match="neither MOVE nor UIDPLUS"):
        ImapMailbox.connect(LOGIN)


def test_an_oversize_messages_header_is_fetched_only_up_to_its_bound(connected):
    mailbox, client, _ = connected

    mailbox.fetch_header("7")

    assert ("FETCH", "7", "(BODY.PEEK[HEADER]<0.65536>)") in client.commands
