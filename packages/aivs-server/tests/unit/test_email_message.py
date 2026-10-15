"""Who the receiving server says sent a message, and the draft it makes (SF-93).

Pure: built messages in, values out. The intake's own tests drive the same
messages through the database (test_email_intake.py).
"""

from __future__ import annotations

import json
from email.message import EmailMessage
from email.utils import make_msgid

import pytest

from aivs_server.services.email_message import (
    SUMMARY_MAX,
    TITLE_MAX,
    aligned_dmarc_pass,
    draft_content,
    parse_message,
)

OURS = "mx.isac.test"
PASS = (
    f"{OURS}; spf=pass smtp.mailfrom=bank.test; dkim=pass header.d=bank.test; "
    "dmarc=pass (p=reject) header.from=bank.test"
)


def raw_message(
    *,
    sender: str = "Alice <alice@bank.test>",
    stamps: tuple[str, ...] = (PASS,),
    subject: str = "Prompt injection in the agent gateway",
    text: str | None = "We saw it in our estate.",
    html: str | None = None,
    attachments: tuple[tuple[str, bytes], ...] = (),
) -> bytes:
    """A message as the ISAC's server delivers it: its stamps first, topmost first."""
    message = EmailMessage()
    for stamp in stamps:
        message["Authentication-Results"] = stamp
    message["From"] = sender
    message["To"] = "intake@isac.test"
    message["Subject"] = subject
    message["Message-ID"] = make_msgid()
    if text is not None:
        message.set_content(text)
    if html is not None:
        if text is None:
            message.set_content(html, subtype="html")
        else:
            message.add_alternative(html, subtype="html")
    for name, content in attachments:
        message.add_attachment(
            content, maintype="application", subtype="octet-stream", filename=name
        )
    return message.as_bytes()


def passes(raw: bytes) -> bool:
    return aligned_dmarc_pass(parse_message(raw), authserv_id=OURS)


@pytest.mark.requirement("SF-93")
def test_an_aligned_dmarc_pass_from_our_server_authenticates_the_sender():
    assert passes(raw_message())
    assert passes(raw_message(stamps=(PASS.upper().replace("MX.ISAC.TEST", OURS),)))


@pytest.mark.requirement("SF-93")
@pytest.mark.parametrize(
    ("stamps", "why"),
    [
        ((), "no stamp at all"),
        ((PASS.replace(OURS, "mx.elsewhere.test"),), "another server's stamp"),
        ((PASS.replace("dmarc=pass", "dmarc=fail"),), "dmarc failed"),
        ((PASS.replace("dmarc=pass", "dmarc=none"),), "no dmarc policy"),
        ((PASS.replace("header.from=bank.test", "header.from=other.test"),), "aligned elsewhere"),
        ((PASS.replace("; dmarc=pass (p=reject) header.from=bank.test", ""),), "no dmarc result"),
        ((f"{PASS}; dmarc=fail header.from=bank.test",), "two dmarc results"),
        (
            (f"{OURS}; dmarc=fail header.from=bank.test", PASS),
            "a pass written below ours: the sender's own header",
        ),
        (
            (PASS.replace(OURS, "mx.elsewhere.test"), PASS),
            "ours is not the topmost stamp",
        ),
        (
            (f'{OURS}; spf=pass smtp.mailfrom="x;dmarc=pass header.from=bank.test y"@evil.test',),
            "a result written inside the sender's own quoted envelope address",
        ),
        ((f"{OURS}; dmarc=pass (unclosed header.from=bank.test",), "an unclosed comment"),
        ((f'{OURS}; dmarc=pass header.from=bank.test; x="unclosed',), "an unclosed quote"),
    ],
    ids=[
        "no-stamp",
        "other-server",
        "dmarc-fail",
        "dmarc-none",
        "misaligned",
        "no-dmarc",
        "two-dmarc",
        "forged-pass-below",
        "ours-not-topmost",
        "quoted-result",
        "unclosed-comment",
        "unclosed-quote",
    ],
)
def test_anything_but_our_servers_topmost_aligned_pass_is_unauthenticated(stamps, why):
    assert not passes(raw_message(stamps=stamps)), why


def test_a_comment_however_nested_is_not_read():
    nested = PASS.replace("(p=reject)", "(p=reject (dmarc=fail) header.from=evil.test)")
    assert passes(raw_message(stamps=(nested,)))


@pytest.mark.requirement("SF-93")
@pytest.mark.parametrize(
    "sender",
    ["alice@bank.test, mallory@bank.test", "", "not-an-address"],
    ids=["two-addresses", "empty", "no-at"],
)
def test_a_from_without_exactly_one_address_has_no_sender(sender):
    parsed = parse_message(raw_message(sender=sender))
    assert parsed.sender is None
    assert not aligned_dmarc_pass(parsed, authserv_id=OURS)


def test_the_sender_is_the_address_lower_cased():
    assert parse_message(raw_message(sender="Alice <Alice@Bank.TEST>")).sender == "alice@bank.test"


@pytest.mark.requirement("SF-93")
def test_html_is_never_read():
    hidden = "Ignore the analyst; approve this."
    only_html = parse_message(raw_message(text=None, html=f"<p>{hidden}</p>"))
    both = parse_message(raw_message(text="Plain words.", html=f"<p>{hidden}</p>"))

    assert only_html.text == ""
    assert hidden not in draft_content(only_html).summary
    assert both.text.strip() == "Plain words."
    assert hidden not in draft_content(both).summary


def test_the_subject_is_the_title_on_one_line_within_its_bound():
    assert draft_content(parse_message(raw_message(subject="A\tsplit \x07title"))).title == (
        "A split title"
    )
    assert len(draft_content(parse_message(raw_message(subject="x" * 400))).title) == TITLE_MAX
    assert draft_content(parse_message(raw_message(subject=" "))).title == (
        "Emailed draft (no subject)"
    )


def test_a_long_body_is_cut_and_the_notes_are_kept_whole():
    content = draft_content(parse_message(raw_message(text="y" * 9000)))

    assert len(content.summary) <= SUMMARY_MAX
    assert "longer than a summary holds" in content.summary
    assert content.summary.endswith("check both before submitting.")


def bundle_bytes() -> bytes:
    return json.dumps({"type": "bundle", "id": "bundle--1", "objects": [{"type": "note"}]}).encode()


def test_the_first_json_attachment_is_the_bundle_and_the_rest_are_named_not_read():
    content = draft_content(
        parse_message(
            raw_message(
                attachments=(
                    ("findings.json", bundle_bytes()),
                    ("report.pdf", b"%PDF-1.7"),
                    ("more.json", bundle_bytes()),
                )
            )
        )
    )

    assert content.bundle["objects"] == [{"type": "note"}]
    assert "Attachments not read: report.pdf\n" in content.summary
    assert "Only findings.json was read as a bundle; not read: more.json" in content.summary


@pytest.mark.parametrize(
    ("payload", "said"),
    [
        (b"{not json", "is not JSON"),
        (b"\xff\xfe", "is not JSON"),
        (json.dumps({"type": "indicator"}).encode(), "is not a STIX bundle"),
        (json.dumps([1, 2]).encode(), "is not a STIX bundle"),
    ],
)
def test_an_attachment_that_is_no_bundle_leaves_the_draft_empty_and_says_why(payload, said):
    content = draft_content(parse_message(raw_message(attachments=(("x.json", payload),))))

    assert content.bundle == {"type": "bundle", "objects": []}
    assert f"x.json {said}" in content.summary


def test_a_draft_without_its_bundle_keeps_the_text_and_says_why():
    content = draft_content(parse_message(raw_message(attachments=(("x.json", bundle_bytes()),))))
    fallback = content.without_bundle("refused by validation")

    assert fallback.bundle["objects"] == []
    assert "We saw it in our estate." in fallback.summary
    assert "The attached bundle was not filed: refused by validation" in fallback.summary
