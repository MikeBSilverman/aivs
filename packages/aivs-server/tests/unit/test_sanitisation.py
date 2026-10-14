"""The sanitisation assist: hits where a submitter usually gives itself away.

An assist, never a refusal; and never an oracle over who is a member, which is
why another organisation's name is deliberately *not* flagged (the pair below).
"""

from __future__ import annotations

import pytest

from aivs_schemas.enums import OrgType
from aivs_server.services.sanitisation import Hit, free_text_of, lint, redact
from tests.conftest import proxy_headers


@pytest.mark.parametrize(
    ("text", "kind", "flagged"),
    [
        ("seen from 10.20.30.40 on the edge", "private_address", "10.20.30.40"),
        ("lab range 192.168.4.0/24", "private_address", "192.168.4.0/24"),
        ("fd12:3456:789a::1 inside", "private_address", "fd12:3456:789a::1"),
        ("hit build01.corp yesterday", "internal_hostname", "build01.corp"),
        ("mail soc@meridian.example", "email_address", "soc@meridian.example"),
        ("we filed a Suspicious Activity Report", "sar_language", "Suspicious Activity Report"),
        ("shared under 314(b) with peers", "sar_language", "314(b)"),
        ("Meridian Global saw it first", "own_organisation", "Meridian Global"),
    ],
)
def test_each_kind_is_found_with_its_span(text, kind, flagged):
    hits = lint({"summary": text}, own_names=["Meridian Global", "meridian-global"])
    assert [(h.kind, h.text) for h in hits if h.kind == kind] == [(kind, flagged)]
    assert text[hits[0].start : hits[0].end] in text


@pytest.mark.parametrize(
    "text",
    [
        "exploited from 203.0.113.9, a public address",
        "the vendor's advisory at advisory.example.com",
        "a SARS-like naming scheme",
        "nothing identifying here at all",
    ],
)
def test_ordinary_text_raises_nothing(text):
    assert lint({"summary": text}, own_names=["Meridian Global"]) == []


def test_overlapping_hits_redact_cleanly():
    text = "contact ops@build.corp now"
    hits = lint({"summary": text}, own_names=[])
    assert {h.kind for h in hits} == {"email_address", "internal_hostname"}
    assert redact(text, hits) == "contact [redacted] now"


def test_prose_is_found_by_path_and_structure_is_not():
    bundle = {
        "objects": [
            {
                "id": "note--1",
                "type": "note",
                "content": "from 10.0.0.1",
                "object_refs": ["identity--10.0.0.1"],
            },
        ]
    }
    assert free_text_of(bundle) == {"note--1.content": "from 10.0.0.1"}
    assert [h.field for h in lint(free_text_of(bundle), own_names=[])] == ["note--1.content"]


def test_hit_carries_what_redaction_needs():
    [hit] = lint({"title": "x 10.1.1.1"}, own_names=[])
    assert hit == Hit("title", "private_address", 2, 10, "10.1.1.1")


@pytest.mark.db
async def test_the_endpoint_flags_the_callers_own_name_and_no_one_elses(
    client, make_org, make_cert
):
    """Flagging a peer's name would tell any member whether that peer is enrolled."""
    caller = await make_org("meridian-global", org_type=OrgType.GSIB)
    await make_org("atlantic-clearing", org_type=OrgType.GSIB)
    pem, _ = await make_cert(caller)

    response = await client.post(
        "/api/v1/submissions/lint",
        json={"summary": "meridian-global and atlantic-clearing both saw 10.9.9.9"},
        headers=proxy_headers(pem),
    )

    assert response.status_code == 200
    assert sorted((h["kind"], h["text"]) for h in response.json()) == [
        ("own_organisation", "meridian-global"),
        ("private_address", "10.9.9.9"),
    ]
