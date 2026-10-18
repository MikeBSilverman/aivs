"""Search finds only what the caller could read, and says nothing about the rest (SF-11).

Every hidden-content test compares the whole response with the one given
before that content existed, byte for byte: a search that answered "no match"
differently when something matched elsewhere would be an oracle over every
circle's content.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update

from aivs_schemas.enums import TLP, EmbargoPolicy, EmbargoStatus, OperatorRole, OrgType
from aivs_server.auth.sessions import establish_sso_session
from aivs_server.db.models import CircleMembership, Embargo, InstanceControl, StixObject
from aivs_server.main import create_app
from tests.conftest import proxy_headers
from tests.sso_support import ISSUER, sso_settings

pytestmark = [pytest.mark.db, pytest.mark.requirement("SF-11")]

SEARCH = "/api/v1/search"
PAGE = "/portal/search"


@pytest.fixture
async def world(make_org, make_cert, make_circle, join_circle):
    """A reader and a filer sharing one circle; the filer alone in a second."""
    filer = await make_org("search-filer", org_type=OrgType.GSIB)
    reader = await make_org("search-reader", org_type=OrgType.GSIB)
    shared = await make_circle("search-shared")
    private = await make_circle("search-private")
    await join_circle(filer, shared)
    await join_circle(reader, shared)
    await join_circle(filer, private)
    reader_pem, _ = await make_cert(reader)
    return {
        "filer": filer,
        "reader": reader,
        "shared": shared,
        "private": private,
        "headers": proxy_headers(reader_pem),
        "reader_pem": reader_pem,
    }


async def _search(client, headers, terms: str, **params: Any):
    return await client.get(SEARCH, params={"q": terms, **params}, headers=headers)


async def _found(client, headers, terms: str) -> list[str]:
    answered = await _search(client, headers, terms)
    assert answered.status_code == 200, answered.text
    return [hit["name"] for hit in answered.json()["hits"]]


async def _set_raw(session, stix_object: StixObject, **properties: Any) -> None:
    """Give a stored version more of its own words than the ``publish`` fixture writes."""
    await session.execute(
        update(StixObject)
        .where(StixObject.id == stix_object.id)
        .values(raw={**stix_object.raw, **properties})
    )
    await session.commit()


async def test_a_member_finds_what_was_shared_with_it(client, world, publish):
    await publish(world["filer"], world["shared"], name="Gateway auth bypass")

    answered = await _search(client, world["headers"], "gateway")

    assert answered.status_code == 200
    body = answered.json()
    assert [hit["name"] for hit in body["hits"]] == ["Gateway auth bypass"]
    assert body["more"] is False
    assert set(body["hits"][0]) == {"stix_id", "type", "name", "tlp", "shared_at", "modified"}


async def test_words_found_only_in_another_circle_answer_exactly_as_no_match(
    client, world, publish
):
    await publish(world["filer"], world["shared"], name="Gateway auth bypass")
    before = await _search(client, world["headers"], "turbine")

    await publish(world["filer"], world["private"], name="Turbine controller overflow")
    after = await _search(client, world["headers"], "turbine")

    assert before.status_code == after.status_code == 200
    assert before.content == after.content
    assert after.json() == {"hits": [], "more": False}


async def test_hidden_matches_never_take_a_visible_matchs_place(client, world, publish):
    """A match decided before visibility would fill the page with what the
    reader cannot see, and say "more" because of it."""
    await publish(world["filer"], world["shared"], name="Pump firmware flaw")
    for _ in range(2):
        await publish(world["filer"], world["private"], name="Pump firmware flaw, private")

    answered = await _search(client, world["headers"], "pump", limit=1)

    assert answered.json()["hits"][0]["name"] == "Pump firmware flaw"
    assert answered.json()["more"] is False


async def test_embargoed_content_is_not_found_until_its_release(client, world, publish):
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=3)
    await publish(world["filer"], world["shared"], name="Valve embargoed", date_added=later)
    await publish(world["filer"], world["shared"], name="Valve released")

    assert await _found(client, world["headers"], "valve") == ["Valve released"]


async def test_content_shared_while_the_reader_was_out_of_the_circle_is_not_found(
    client, session, world, publish, join_circle
):
    """Visibility is the union of the reader's intervals in the circle; the gap
    between leaving and rejoining is not in it."""
    now = dt.datetime.now(dt.UTC)
    left, rejoined = now - dt.timedelta(days=2), now - dt.timedelta(days=1)
    await session.execute(
        update(CircleMembership)
        .where(
            CircleMembership.org_id == world["reader"].id,
            CircleMembership.circle_id == world["shared"].id,
        )
        .values(left_at=left, ended_by="operator")
    )
    await session.commit()
    await join_circle(world["reader"], world["shared"], joined_at=rejoined)
    for name, shared_at in (
        ("Relay before leaving", left - dt.timedelta(hours=1)),
        ("Relay while away", left + dt.timedelta(hours=1)),
        ("Relay after rejoining", rejoined + dt.timedelta(hours=1)),
    ):
        await publish(world["filer"], world["shared"], name=name, date_added=shared_at)

    assert await _found(client, world["headers"], "relay") == [
        "Relay after rejoining",
        "Relay before leaving",
    ]


async def test_a_newer_version_not_yet_visible_is_neither_found_nor_shown(client, world, publish):
    """Its words find nothing, and the hit for the older words shows the older
    version: a latest version chosen over every stored row would say a newer
    one exists."""
    submission, first, _ = await publish(world["filer"], world["shared"], name="Breaker alpha")
    before = await _search(client, world["headers"], "bravo")
    await publish(
        world["filer"],
        world["shared"],
        stix_id=first.stix_id,
        submission=submission,
        name="Breaker bravo",
        modified=first.modified + dt.timedelta(minutes=1),
        date_added=dt.datetime.now(dt.UTC) + dt.timedelta(days=3),
    )

    after = await _search(client, world["headers"], "bravo")
    alpha = await _search(client, world["headers"], "alpha")

    assert before.content == after.content
    assert [hit["name"] for hit in alpha.json()["hits"]] == ["Breaker alpha"]
    assert alpha.json()["hits"][0]["modified"].startswith(first.modified.date().isoformat())


async def test_words_only_in_an_older_version_do_not_find_the_current_one(client, world, publish):
    submission, first, _ = await publish(world["filer"], world["shared"], name="Sensor alpha")
    await publish(
        world["filer"],
        world["shared"],
        stix_id=first.stix_id,
        submission=submission,
        name="Sensor bravo",
        modified=first.modified + dt.timedelta(minutes=1),
    )

    assert await _found(client, world["headers"], "alpha") == []
    assert await _found(client, world["headers"], "bravo") == ["Sensor bravo"]


async def test_an_object_its_owner_revoked_is_not_found(client, session, world, publish):
    submission, first, _ = await publish(world["filer"], world["shared"], name="Inverter alpha")
    _, revoked, _ = await publish(
        world["filer"],
        world["shared"],
        stix_id=first.stix_id,
        submission=submission,
        name="Inverter alpha",
        modified=first.modified + dt.timedelta(minutes=1),
    )
    await _set_raw(session, revoked, revoked=True)

    assert await _found(client, world["headers"], "inverter") == []


async def test_the_objects_own_words_are_searched_and_its_tooling_is_not(
    client, session, world, publish
):
    _, stored, _ = await publish(world["filer"], world["shared"], name="Historian flaw")
    await _set_raw(
        session,
        stored,
        description="Crafted packets crash the historian service.",
        external_references=[{"source_name": "cve", "external_id": "CVE-2026-55501"}],
        x_tooling="fuzzbench",
        extensions={"extension-definition--x": {"ai_model_name": "modelzeta"}},
    )

    assert await _found(client, world["headers"], "crafted packets") == ["Historian flaw"]
    assert await _found(client, world["headers"], "CVE-2026-55501") == ["Historian flaw"]
    assert await _found(client, world["headers"], "fuzzbench") == []
    assert await _found(client, world["headers"], "modelzeta") == []


async def test_nothing_is_found_while_distribution_is_paused(client, session, world, publish):
    await publish(world["filer"], world["shared"], name="Feeder alpha")
    control = await session.get(InstanceControl, 1)
    if control is None:
        control = InstanceControl(id=1)
        session.add(control)
    control.distribution_paused = True
    await session.commit()

    assert await _found(client, world["headers"], "feeder") == []


async def test_an_isac_reviewer_searches_every_circle(client, world, publish, isac):
    """The sector's view is what review triages against, as on the vulnerability page."""
    _isac_org, headers = isac
    await publish(world["filer"], world["private"], name="Switchgear private")

    assert await _found(client, headers, "switchgear") == ["Switchgear private"]


@pytest.mark.parametrize("terms", ["a", " ", "x" * 201])
async def test_terms_too_short_or_too_long_are_refused(client, world, terms):
    assert (await _search(client, world["headers"], terms)).status_code == 400


async def test_the_terms_reach_no_log_record(client, world, publish, reader_browser, caplog):
    """What a firm searches for says what it is worried about. The test's own
    HTTP client logs the URL it requested; that is the caller's log, not ours."""
    await publish(world["filer"], world["shared"], name="Recloser alpha")
    with caplog.at_level(logging.DEBUG):
        await _search(client, world["headers"], "recloserquery")
        page = await client.get(PAGE, params={"q": "recloserquery"}, headers=reader_browser)
    assert page.status_code == 200

    ours = [record for record in caplog.records if record.name.startswith("aivs_server")]
    assert ours
    assert not any("recloserquery" in str(vars(record)) for record in ours)


# ---------------------------------------------------------------------------
# The portal page
# ---------------------------------------------------------------------------
@pytest.fixture
async def reader_browser(client, session, settings, world, make_operator, human_headers):
    operator, _seed = await make_operator(world["reader"], roles=(OperatorRole.ANALYST,))
    headers = await human_headers(operator, world["reader_pem"])
    token = headers.pop("authorization").removeprefix("Bearer ")
    client.cookies.set(settings.session_cookie_name, token)
    return headers


async def test_the_page_links_a_vulnerability_to_its_page(client, world, publish, reader_browser):
    _, stored, _ = await publish(world["filer"], world["shared"], name="Gateway auth bypass")

    page = await client.get(PAGE, params={"q": "gateway"}, headers=reader_browser)

    assert page.status_code == 200
    assert f'href="/portal/vulnerabilities?id={stored.stix_id}"' in page.text
    assert "Everything distributed to your firm." in page.text


async def test_the_page_answers_hidden_matches_exactly_as_no_match(
    client, world, publish, reader_browser
):
    before = await client.get(PAGE, params={"q": "turbine"}, headers=reader_browser)
    await publish(world["filer"], world["private"], name="Turbine controller overflow")
    after = await client.get(PAGE, params={"q": "turbine"}, headers=reader_browser)

    assert before.status_code == after.status_code == 200
    assert _without_tokens(before.text) == _without_tokens(after.text)
    assert "Nothing you can read matches." in after.text


async def test_the_page_says_when_terms_cannot_be_searched(client, world, reader_browser):
    page = await client.get(PAGE, params={"q": "a"}, headers=reader_browser)

    assert page.status_code == 200
    assert "Not searched: search terms are 2 to 200 characters." in page.text


def _without_tokens(html: str) -> str:
    """The page with its per-render form tokens and nonces removed."""
    return "\n".join(
        line for line in html.splitlines() if "csrf_token" not in line and "nonce" not in line
    )


# ---------------------------------------------------------------------------
# An SSO session searches under its ceiling (SF-65)
# ---------------------------------------------------------------------------
@pytest.fixture
async def sso_browser(app, settings, session, make_operator, world):
    application = create_app(sso_settings(settings))
    operator, _seed = await make_operator(world["reader"], roles=(OperatorRole.ANALYST,))
    operator.federated_issuer = ISSUER
    operator.federated_subject = f"search-subject-{uuid.uuid4()}"
    established = await establish_sso_session(
        session,
        settings,
        operator=operator,
        issuer=ISSUER,
        subject=operator.federated_subject,
        device_cookie="search-device",
        amr=("pwd", "otp"),
        source_ip=None,
        user_agent=None,
        now=dt.datetime.now(dt.UTC),
    )
    await session.commit()
    browser = AsyncClient(transport=ASGITransport(app=application), base_url="https://testserver")
    browser.cookies.set(sso_settings(settings).session_cookie_name, established.token)
    browser.cookies.set(sso_settings(settings).sso_device_cookie_name, "search-device")
    async with browser:
        yield browser


async def test_an_sso_session_finds_amber_but_never_red(session, world, publish, sso_browser):
    await publish(world["filer"], world["shared"], name="Busbar amber")
    red, _, _ = await publish(world["filer"], world["shared"], name="Busbar red")
    red.tlp = TLP.RED
    await session.commit()

    page = await sso_browser.get(PAGE, params={"q": "busbar"})

    assert page.status_code == 200
    assert "Busbar amber" in page.text
    assert "Busbar red" not in page.text
    assert "Sign in with your firm&#39;s certificate to search the rest." in page.text


async def test_an_sso_session_never_finds_what_was_shared_under_an_embargo(
    session, world, publish, sso_browser
):
    """Even once released: an SSO session reads nothing that had an embargo."""
    held, _, _ = await publish(world["filer"], world["shared"], name="Capacitor released")
    released = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
    session.add(
        Embargo(
            submission_id=held.id,
            policy=EmbargoPolicy.TIMER,
            status=EmbargoStatus.RELEASED,
            release_at=released,
            released_at=released,
        )
    )
    await session.commit()

    page = await sso_browser.get(PAGE, params={"q": "capacitor"})

    assert "Capacitor released" not in page.text
    assert "Nothing you can read matches." in page.text
