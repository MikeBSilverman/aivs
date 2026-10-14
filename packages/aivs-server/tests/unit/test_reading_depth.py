"""Reading depth on the vulnerability page: guided, standard, technical (NFR-U5, NFR-U6).

Every depth is one page over the same objects, readiness, receipt and forms;
only the rendering of the record differs. So the properties are the page's:
nothing a depth shows is outside what the caller may see, the stored
preference is read, and "new since you last read" is decided before this read
is recorded.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import AckType, AckVia
from aivs_server.db.models import Acknowledgment
from tests.unit.test_vulnerability_page import (
    PAGE,
    _fix,
    _get,
    _mitigates,
    _post,
    _share,
    build_case,
)

pytestmark = pytest.mark.db

GUIDED_HEADING = "What to do, in order"
_STIX_ID = re.compile(r"[a-z][a-z0-9-]*--[0-9a-f]{8}-")
NEW_BADGE = "New since you last read"


@pytest.fixture
async def case(
    client,
    session,
    settings,
    isac_org,
    make_org,
    make_cert,
    make_operator,
    make_circle,
    join_circle,
):
    return await build_case(
        client,
        session,
        settings,
        isac_org,
        make_org=make_org,
        make_cert=make_cert,
        make_operator=make_operator,
        make_circle=make_circle,
        join_circle=join_circle,
    )


class _VisibleText(HTMLParser):
    """The text a reader sees: element content, not attributes, scripts or styles."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._hidden = 0

    def handle_starttag(self, tag: str, _attrs: object) -> None:
        if tag in {"script", "style", "title"}:
            self._hidden += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "title"}:
            self._hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self._hidden:
            self.parts.append(data)


def _visible_text(html: str) -> str:
    parser = _VisibleText()
    parser.feed(html)
    return " ".join(" ".join(parser.parts).split())


def _page(case, depth: str | None = None) -> str:
    query = f"?id={case['stix_id']}" + (f"&depth={depth}" if depth else "")
    return f"{PAGE}{query}"


# ---------------------------------------------------------------------------
# Which depth
# ---------------------------------------------------------------------------
async def test_a_reader_with_no_preference_gets_the_standard_page(client, case):
    page = await _get(client, case["reader"], _page(case))
    assert page.status_code == 200, page.text
    assert "Timeline" in page.text
    assert GUIDED_HEADING not in page.text


@pytest.mark.requirement("NFR-U5")
async def test_the_stored_preference_is_read_and_a_link_overrides_it(client, case):
    """The dashboard's choice was stored and read by nothing until this page."""
    saved = await _post(client, case["reader"], "/portal/preferences/depth", {"depth": "guided"})
    assert saved.status_code == 303, saved.text

    preferred = await _get(client, case["reader"], _page(case))
    linked = await _get(client, case["reader"], _page(case, "standard"))

    assert GUIDED_HEADING in preferred.text
    assert GUIDED_HEADING not in linked.text
    assert "Timeline" in linked.text


async def test_an_unknown_depth_shows_the_page_rather_than_refusing_it(client, case):
    page = await _get(client, case["reader"], _page(case, "GUIDED"))
    assert page.status_code == 200, page.text
    assert "Timeline" in page.text


# ---------------------------------------------------------------------------
# What each depth may show
# ---------------------------------------------------------------------------
@pytest.mark.requirement("NFR-U5")
async def test_the_guided_page_names_no_stix_type_and_no_stix_id_through_the_route(client, case):
    """The template's own test renders it alone; the page around it has a facts
    table, related cards and a timeline that all name types and ids."""
    page = await _get(client, case["reader"], _page(case, "guided"))

    text = _visible_text(page.text)
    assert GUIDED_HEADING in text
    assert "Disable the management interface" in text
    assert _STIX_ID.search(text) is None, "a STIX identifier"
    # Type names as STIX spells them and as the standard page words them;
    # "vulnerability" is also plain English, so its id is what is checked.
    for type_name in ("course-of-action", "course of action", "relationship", "indicator"):
        assert type_name not in text.lower(), type_name


@pytest.mark.requirement("SF-8")
async def test_the_technical_record_shows_the_latest_version_the_reader_can_see(client, case):
    """The vendor revises the open fix, but distributes the revision only to the
    narrow circle the reader is not in. The record shows the version the reader
    holds; resolving the latest stored version would show the revision, or
    nothing, and either tells the reader it exists."""
    revision = {
        **case["open_fix"],
        "modified": "2026-09-01T00:00:00.000Z",
        "name": "Withheld revision",
    }
    await _share(client, case["vendor_pem"], case["isac_api"], [revision], [case["narrow"].id])

    page = await _get(client, case["reader"], _page(case, "technical"))

    assert page.status_code == 200, page.text
    assert case["open_fix"]["id"] in page.text
    assert "Disable the management interface" in page.text
    assert "Withheld revision" not in page.text
    assert "Upgrade to 4.2.1" not in page.text, "the fix shared only to the narrow circle"


@pytest.mark.parametrize("depth", ["guided", "standard", "technical"])
async def test_every_depth_records_the_read(client, session, case, depth):
    """A depth is a rendering, so the receipt an auditor asks for (SF-51) is
    written whichever one the person reads at."""
    await _get(client, case["reader"], _page(case, depth))
    receipts = await session.scalar(
        select(func.count())
        .select_from(Acknowledgment)
        .where(
            Acknowledgment.org_id == case["reader_org"].id,
            Acknowledgment.submission_id == case["shared"],
            Acknowledgment.ack_type == AckType.RETRIEVED,
            Acknowledgment.via == AckVia.PORTAL,
        )
    )
    assert receipts == 1


# ---------------------------------------------------------------------------
# New since you last read
# ---------------------------------------------------------------------------
async def test_new_since_last_read_is_decided_before_this_read_is_recorded(client, case):
    """First read: everything is new. Read again: nothing is. A fix shared after
    that: only it is. Deciding after this read's receipt is written would make
    nothing ever new, which is the one failure a reader cannot notice."""
    first = await _get(client, case["reader"], _page(case, "guided"))
    again = await _get(client, case["reader"], _page(case, "guided"))
    later_fix = _fix("Rotate the gateway's admin credentials")
    vulnerability_ref = {"id": case["stix_id"]}
    await _share(
        client,
        case["vendor_pem"],
        case["isac_api"],
        [later_fix, _mitigates(later_fix, vulnerability_ref)],
        [case["wide"].id],
    )
    after = await _get(client, case["reader"], _page(case, "guided"))

    assert NEW_BADGE in first.text
    assert NEW_BADGE not in again.text
    assert _step_is_new(after.text, "Rotate the gateway&#39;s admin credentials")
    assert not _step_is_new(after.text, "Disable the management interface")


def _step_is_new(html: str, title: str) -> bool:
    """Whether the guided step titled ``title`` carries the "new" badge."""
    item = html.split(f"<strong>{title}</strong>", maxsplit=1)[0].rsplit("<li>", 1)[-1]
    return NEW_BADGE in item


# ---------------------------------------------------------------------------
# Forms return to the depth they were sent from
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(("sent", "returned"), [("guided", "&depth=guided"), ("nonsense", "")])
async def test_a_form_returns_to_the_depth_it_was_sent_from(client, case, sent, returned):
    response = await _post(
        client,
        case["reader"],
        f"{PAGE}/actioned",
        {"vulnerability": case["stix_id"], "depth": sent},
    )
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location.endswith(returned) if returned else "depth=" not in location
