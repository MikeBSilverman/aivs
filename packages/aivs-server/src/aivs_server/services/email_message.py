"""Reading one emailed message: who the ISAC's mail server says sent it, and the draft it makes.

Pure functions over bytes and values, so every rule here is tested without a
mailbox or a database (services.email_intake does the I/O).

**Who sent it is the receiving server's word, not the message's.** A sender
can write any From address and any header, including an
``Authentication-Results`` naming our server. So only the *topmost* one counts:
the ISAC's receiving server adds its own above everything the sender wrote.
That holds only if it stamps every message it delivers to the mailbox, which
the runbook (section 9.7) has the operator confirm; it should also remove
inbound headers claiming its name (RFC 8601 section 5). That header must carry the authserv-id the
operator configured, exactly one ``dmarc`` result, ``pass``, and a
``header.from`` equal to the From address's domain. A forged header further
down is never read, which is the point.

**Only the plain-text part is read.** HTML is never parsed: it is where
tracking pixels, hidden text and markup that renders differently from what it
says live. One ``.json`` attachment is read as a STIX bundle; every other
attachment is named in the draft and not opened.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, replace
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from typing import Any, Final

from aivs_schemas.enums import TLP, DiscoveryScope

__all__ = [
    "EMAIL_DRAFT_SCOPE",
    "EMAIL_DRAFT_TLP",
    "DraftContent",
    "ParsedMessage",
    "aligned_dmarc_pass",
    "draft_content",
    "parse_message",
]

#: The bounds of ``SubmissionCreate``: a draft made by email is held to them
#: before it reaches the model, so it is never refused for its length.
TITLE_MIN: Final[int] = 3
TITLE_MAX: Final[int] = 300
SUMMARY_MAX: Final[int] = 5000
_NO_SUBJECT: Final[str] = "Emailed draft (no subject)"
_TRUNCATED: Final[str] = (
    "\n[The message was longer than a summary holds; the rest is in the ISAC's mailbox.]"
)
#: An email says neither, so the draft starts at the stricter end: a TLP the
#: member can only loosen, and its own estate, which claims nothing about
#: anyone else's product. Both are shown as defaults to change.
EMAIL_DRAFT_TLP: Final[TLP] = TLP.AMBER_STRICT
EMAIL_DRAFT_SCOPE: Final[DiscoveryScope] = DiscoveryScope.OWN_ESTATE
_DEFAULTS_NOTE: Final[str] = (
    f"Filed by email. The TLP ({EMAIL_DRAFT_TLP.value.replace('_', '+').upper()}) and the "
    f"discovery scope ({EMAIL_DRAFT_SCOPE.value.replace('_', ' ')}) are defaults: check "
    "both before submitting."
)


@dataclass(frozen=True, slots=True)
class Attachment:
    filename: str
    content: bytes


@dataclass(frozen=True, slots=True)
class ParsedMessage:
    """What the intake reads from a message, and nothing else."""

    #: The one From address, lower-cased; ``None`` when there is not exactly one.
    sender: str | None
    subject: str
    #: The text/plain body. ``""`` when there is none: HTML is never read.
    text: str
    attachments: tuple[Attachment, ...]
    #: Every Authentication-Results header, topmost first.
    authentication_results: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DraftContent:
    """A draft's title, summary and bundle, already within the request model's bounds."""

    title: str
    summary: str
    bundle: dict[str, Any]

    def without_bundle(self, reason: str) -> DraftContent:
        """The same draft with no objects, saying why: the member's text is kept."""
        note = f"The attached bundle was not filed: {reason}"[:500]
        return replace(self, summary=_bounded_summary(self.summary, [note]), bundle=_empty_bundle())


def parse_message(raw: bytes) -> ParsedMessage:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    return ParsedMessage(
        sender=_single_sender(message),
        subject=str(message.get("Subject", "")),
        text=_plain_text(message),
        attachments=tuple(
            Attachment(part.get_filename() or "", _payload(part))
            for part in message.iter_attachments()
        ),
        authentication_results=tuple(str(h) for h in message.get_all("Authentication-Results", [])),
    )


def aligned_dmarc_pass(message: ParsedMessage, *, authserv_id: str) -> bool:
    """Whether the receiving server recorded an aligned DMARC pass for the From address."""
    if message.sender is None or not message.authentication_results:
        return False
    stamp_id, dmarc = _read_authentication_results(message.authentication_results[0])
    if stamp_id != authserv_id.lower() or len(dmarc) != 1:
        return False
    result, header_from = dmarc[0]
    return result == "pass" and header_from == message.sender.rpartition("@")[2]


def draft_content(message: ParsedMessage) -> DraftContent:
    bundle, bundle_note = _bundle_from(message.attachments)
    unread = [a.filename or "(unnamed)" for a in message.attachments if not _is_bundle_file(a)]
    notes = [_DEFAULTS_NOTE]
    if unread:
        notes.append(f"Attachments not read: {', '.join(unread)}")
    if bundle_note:
        notes.append(bundle_note)
    return DraftContent(
        title=_title(message.subject),
        summary=_bounded_summary(message.text, notes),
        bundle=bundle,
    )


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def _single_sender(message: EmailMessage) -> str | None:
    """The From address when the header holds exactly one, else ``None``.

    A From with two addresses is legal and is exactly the shape that lets a
    message be aligned to one domain and read as another.
    """
    headers = message.get_all("From", [])
    addresses = getaddresses([str(h) for h in headers])
    if len(headers) != 1 or len(addresses) != 1:
        return None
    address = addresses[0][1].strip().lower()
    return address if address.count("@") == 1 else None


def _payload(part: EmailMessage) -> bytes:
    content = part.get_payload(decode=True)
    return content if isinstance(content, bytes) else b""


def _plain_text(message: EmailMessage) -> str:
    body = message.get_body(preferencelist=("plain",))
    if body is None:
        return ""
    content = body.get_content()
    return content if isinstance(content, str) else ""


def _read_authentication_results(header: str) -> tuple[str, list[tuple[str, str]]]:
    """The authserv-id, and each ``dmarc`` result with its ``header.from``, lower-cased."""
    segments = [part.strip() for part in _without_comments_or_quoted_text(header).split(";")]
    stamp_id = (segments[0].split() or [""])[0].lower()
    dmarc = [_dmarc(segment) for segment in segments[1:] if segment.lower().startswith("dmarc=")]
    return stamp_id, dmarc


def _without_comments_or_quoted_text(header: str) -> str:
    """The header with comments dropped and each quoted-string emptied; ``""`` if unbalanced.

    RFC 8601's grammar, as far as reading results needs it. The sender writes
    the envelope address an SPF result quotes, so a quoted ``x;dmarc=pass``
    must not read as a result of its own (T1's review), and a comment may
    nest. Anything unterminated reads as nothing, which fails closed.
    """
    kept: list[str] = []
    index = 0
    while index < len(header):
        char = header[index]
        if char == '"':
            index = _quoted_end(header, index)
            kept.append('""')
        elif char == "(":
            index = _comment_end(header, index)
            kept.append(" ")
        else:
            kept.append(char)
            index += 1
        if index < 0:
            return ""
    return "".join(kept)


def _quoted_end(text: str, start: int) -> int:
    """Just past the quoted-string opening at ``start``, or -1 if it never closes."""
    index = start + 1
    while index < len(text):
        if text[index] == '"':
            return index + 1
        index += 2 if text[index] == "\\" else 1
    return -1


def _comment_end(text: str, start: int) -> int:
    """Just past the comment opening at ``start``, nesting included, or -1."""
    depth = 0
    index = start
    while index < len(text):
        char = text[index]
        depth += _COMMENT_DEPTH.get(char, 0)
        index += 2 if char == "\\" else 1
        if depth == 0:
            return index
    return -1


_COMMENT_DEPTH: Final[dict[str, int]] = {"(": 1, ")": -1}


def _dmarc(segment: str) -> tuple[str, str]:
    tokens = segment.lower().split()
    result = tokens[0].partition("=")[2]
    header_from = next(
        (token.partition("=")[2] for token in tokens[1:] if token.startswith("header.from=")),
        "",
    )
    return result, header_from


# ---------------------------------------------------------------------------
# The draft
# ---------------------------------------------------------------------------
def _title(subject: str) -> str:
    """The subject, as one line the request model accepts."""
    printable = "".join(" " if unicodedata.category(c).startswith("C") else c for c in subject)
    title = " ".join(printable.split())[:TITLE_MAX].strip()
    return title if len(title) >= TITLE_MIN else _NO_SUBJECT


def _bounded_summary(text: str, notes: Sequence[str]) -> str:
    """The member's text, then the notes, within the summary's bound. The notes are kept whole."""
    tail = "\n\n" + "\n".join(f"-- {note}" for note in notes)
    room = SUMMARY_MAX - len(tail)
    body = text.strip()
    if len(body) > room:
        body = body[: room - len(_TRUNCATED)] + _TRUNCATED
    return body + tail


def _is_bundle_file(attachment: Attachment) -> bool:
    return attachment.filename.lower().endswith(".json")


def _bundle_from(attachments: Sequence[Attachment]) -> tuple[dict[str, Any], str | None]:
    """The first ``.json`` attachment as a bundle, or an empty one and why not."""
    candidates = [a for a in attachments if _is_bundle_file(a)]
    if not candidates:
        return _empty_bundle(), None
    first = candidates[0]
    extra = [a.filename for a in candidates[1:]]
    note = (
        f"Only {first.filename} was read as a bundle; not read: {', '.join(extra)}"
        if extra
        else None
    )
    try:
        parsed = json.loads(first.content.decode("utf-8"))
    except ValueError as exc:  # UnicodeDecodeError and JSONDecodeError are both ValueErrors
        return _empty_bundle(), f"{first.filename} is not JSON: {exc}"[:500]
    if not isinstance(parsed, dict) or parsed.get("type") != "bundle":
        return _empty_bundle(), f"{first.filename} is not a STIX bundle"
    return parsed, note


def _empty_bundle() -> dict[str, Any]:
    return {"type": "bundle", "objects": []}
