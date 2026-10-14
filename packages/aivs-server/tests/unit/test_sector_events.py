"""Sector events: what may be pinned, who sees it, and what the call notes become."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import TLP, OrgType, SubmissionState
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db.models import Organization, StixObject, Submission, Webhook, WebhookDelivery
from aivs_server.notify.digest import DigestItem, render_email
from aivs_server.services.sector_events import (
    MAX_ACTION_ITEMS,
    SectorEventError,
    call_notes_bundle,
)
from tests.conftest import proxy_headers
from tests.unit.contribution_world import seed, vulnerability_raw
from tests.unit.test_portal import make_operator, sign_in

pytestmark = pytest.mark.db

API = "/api/v1"
NOW = dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.UTC)


@pytest.fixture
async def world(
    session,
    isac,
    isac_org,
    make_org,
    make_cert,
    make_circle,
    make_collection,
    join_circle,
    secret_box,
):
    _isac_org, editor = isac
    member = await make_org("event-member", org_type=OrgType.GSIB)
    member_pem, _ = await make_cert(member)
    outsider = await make_org("event-outsider", org_type=OrgType.GSIB)
    outsider_pem, _ = await make_cert(outsider)
    circle = await make_circle("event")
    await make_collection(circle)
    await join_circle(member, circle)
    record_id = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session, isac_org, vulnerability_raw(record_id, cve_status="published"), circle=circle
    )
    members_own = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session, member, vulnerability_raw(members_own, cve_status="published"), circle=circle
    )
    held_back = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session,
        isac_org,
        vulnerability_raw(held_back, cve_status="published"),
        circle=None,
        state=SubmissionState.VALIDATED,
    )
    webhook_id = uuid.uuid4()
    session.add(
        Webhook(
            id=webhook_id,
            org_id=member.id,
            url="https://member.example/hook",
            hmac_secret_encrypted=secret_box.seal(
                "webhook-signing-secret", purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook_id
            ),
            events=[],
        )
    )
    await session.commit()
    return {
        "editor": editor,
        "member": proxy_headers(member_pem),
        "outsider": proxy_headers(outsider_pem),
        "record": record_id,
        "members_own": members_own,
        "held_back": held_back,
        "circle": circle,
    }


async def _open(client, world, stix_id: str):
    return await client.post(
        f"{API}/sector-events", json={"vulnerability_stix_id": stix_id}, headers=world["editor"]
    )


# ---------------------------------------------------------------------------
# What may be pinned
# ---------------------------------------------------------------------------
async def test_an_editor_pins_the_isacs_distributed_record(client, world):
    opened = await _open(client, world, world["record"])
    assert opened.status_code == 201, opened.text


@pytest.mark.requirement("SF-77")
@pytest.mark.parametrize("which", ["members_own", "held_back"])
async def test_only_the_isacs_distributed_record_can_be_pinned(client, world, which):
    refused = await _open(client, world, world[which])
    assert refused.status_code == 409


async def test_one_open_event_per_vulnerability_and_a_closed_one_frees_it(client, world):
    first = await _open(client, world, world["record"])
    assert (await _open(client, world, world["record"])).status_code == 409
    closed = await client.post(
        f"{API}/sector-events/{first.json()['id']}/close", json={}, headers=world["editor"]
    )
    assert closed.status_code == 200
    assert (await _open(client, world, world["record"])).status_code == 201


@pytest.mark.requirement("SF-77")
async def test_a_member_is_refused_before_any_lookup(client, world):
    """The same 403 for a real event and a made-up one: the id is no oracle."""
    real = (await _open(client, world, world["record"])).json()["id"]
    for event_id in (real, str(uuid.uuid4())):
        response = await client.post(
            f"{API}/sector-events/{event_id}/close", json={}, headers=world["member"]
        )
        assert response.status_code == 403


@pytest.mark.requirement("SF-77")
# ---------------------------------------------------------------------------
# Who sees it
# ---------------------------------------------------------------------------
async def test_a_member_sees_the_event_only_if_it_can_see_the_record(client, world):
    await _open(client, world, world["record"])
    seen = await client.get(f"{API}/sector-events", headers=world["member"])
    assert [e["vulnerability_stix_id"] for e in seen.json()] == [world["record"]]
    unseen = await client.get(f"{API}/sector-events", headers=world["outsider"])
    assert unseen.json() == []


async def test_a_notice_about_a_pinned_record_says_so_and_one_after_closing_does_not(
    client, session, world, isac_org
):
    opened = await _open(client, world, world["record"])
    revised = vulnerability_raw(world["record"], cve_status="published") | {
        "modified": "2026-10-14T13:00:00.000Z"
    }
    await _distribute_version(client, session, world, isac_org, revised)
    await client.post(
        f"{API}/sector-events/{opened.json()['id']}/close", json={}, headers=world["editor"]
    )
    revised_again = revised | {"modified": "2026-10-14T14:00:00.000Z"}
    await _distribute_version(client, session, world, isac_org, revised_again)

    session.expire_all()
    deliveries = (await session.scalars(select(WebhookDelivery).order_by(WebhookDelivery.id))).all()
    assert [d.payload["sector_event"] for d in deliveries] == [True, False]


async def _distribute_version(client, session, world, isac_org, raw) -> None:
    submission = await seed(session, isac_org, raw, circle=None, state=SubmissionState.VALIDATED)
    await session.commit()
    sent = await client.post(
        f"{API}/submissions/{submission.id}/distribute",
        json={"circle_ids": [str(world["circle"].id)]},
        headers=world["editor"],
    )
    assert sent.status_code == 200, sent.text


def test_a_digest_line_about_a_pinned_record_says_so():
    item = DigestItem(
        submission_id=uuid.uuid4(),
        collection_id=uuid.uuid4(),
        visible_at=NOW,
        updates=4,
        marking=TLP.AMBER,
        title=None,
        products=["Acme Gateway"],
        sector_event=True,
    )
    _subject, body = render_email("Sector ISAC", [item], "https://aivs.example")
    assert "SECTOR EVENT: an item about Acme Gateway (updated 4 times)" in body


# ---------------------------------------------------------------------------
# Call notes
# ---------------------------------------------------------------------------
def test_call_notes_are_a_summary_note_and_one_note_per_action_item():
    bundle = call_notes_bundle(
        "vulnerability--x",
        summary="Agreed mitigations",
        action_items=["Patch", " ", "Rotate"],
        now=NOW,
    )
    notes = bundle["objects"]
    assert [n["abstract"] for n in notes] == [
        "Call summary",
        "Action item 1 of 2",
        "Action item 2 of 2",
    ]
    assert all(n["object_refs"] == ["vulnerability--x"] for n in notes)


@pytest.mark.parametrize(
    ("summary", "items"),
    [
        pytest.param(" ", [], id="no-summary"),
        pytest.param("ok", [f"item {n}" for n in range(MAX_ACTION_ITEMS + 1)], id="too-many-items"),
    ],
)
def test_call_notes_need_a_summary_and_a_bounded_list(summary, items):
    with pytest.raises(SectorEventError):
        call_notes_bundle("vulnerability--x", summary=summary, action_items=items, now=NOW)


@pytest.mark.requirement("SF-77")
async def test_call_notes_are_filed_as_a_draft_for_review_never_published(client, session, world):
    event_id = (await _open(client, world, world["record"])).json()["id"]
    filed = await client.post(
        f"{API}/sector-events/{event_id}/call-notes",
        json={
            "summary": "Agreed on the call",
            "action_items": ["Patch tonight"],
            "discovery_scope": "own_estate",
        },
        headers=world["editor"],
    )
    assert filed.status_code == 201, filed.text
    submission = await session.get(Submission, uuid.UUID(filed.json()["submission_id"]))
    assert submission.state is SubmissionState.DRAFT
    types = (
        await session.scalars(
            select(StixObject.type).where(StixObject.submission_id == submission.id)
        )
    ).all()
    assert sorted(types) == ["note", "note"]


@pytest.mark.parametrize(("who", "shown"), [("event-member", True), ("event-outsider", False)])
async def test_the_dashboard_pins_the_event_for_those_who_can_see_it(
    client, session, secret_box, world, make_cert, who, shown
):
    await _open(client, world, world["record"])
    org = await session.scalar(select(Organization).where(Organization.slug == who))
    pem, _ = await make_cert(org)
    operator, secret = await make_operator(session, secret_box, org)
    await sign_in(client, operator, secret, pem)
    page = await client.get("/portal/", headers=proxy_headers(pem))
    assert page.status_code == 200
    assert ("data-sector-event" in page.text) is shown
