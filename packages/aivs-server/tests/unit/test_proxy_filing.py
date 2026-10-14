"""An ISAC editor files a member's contribution for it (SF-68).

The risk is attribution: an analyst filing in a member's name content the
member never sent. So a proxy filing needs a consent artefact, tells the member
at once and contentlessly, and is not distributed until the member confirms or
its window passes in silence.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select

from aivs_schemas.enums import OrgStatus, OrgType, SubmissionState
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.auth.sessions import establish_session
from aivs_server.db.models import Operator, Submission, Webhook, WebhookDelivery
from aivs_server.services.proxy_filing import (
    CONFIRM_WITHIN,
    EVENT_FILED_ON_BEHALF,
    awaiting_confirmation_problem,
)
from tests.conftest import proxy_headers
from tests.unit.contribution_world import bundle_of
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world

pytestmark = pytest.mark.db

CONSENT = "5f" * 32
STAMP = "2026-08-01T00:00:00.000Z"


@pytest.fixture
async def world(
    session,
    isac,
    isac_org,
    make_org,
    make_cert,
    make_operator,
    make_circle,
    make_collection,
    join_circle,
    human_headers,
) -> SharingWorld:
    return await build_sharing_world(
        session,
        isac,
        isac_org,
        make_org=make_org,
        make_cert=make_cert,
        make_operator=make_operator,
        make_circle=make_circle,
        make_collection=make_collection,
        join_circle=join_circle,
        human_headers=human_headers,
    )


@pytest.fixture
async def member_hook(session, secret_box, world) -> Webhook:
    hook_id = uuid.uuid4()
    hook = Webhook(
        id=hook_id,
        org_id=world.member.org.id,
        url="https://member.example/aivs",
        hmac_secret_encrypted=secret_box.seal(
            "member-signing-secret", purpose=SecretPurpose.WEBHOOK_HMAC, subject=hook_id
        ),
        events=[],
    )
    session.add(hook)
    await session.commit()
    return hook


def _finding(name: str = "Prompt injection in the member's agent gateway") -> dict:
    return bundle_of(
        {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": f"vulnerability--{uuid.uuid4()}",
            "created": STAMP,
            "modified": STAMP,
            "name": name,
        }
    )


async def file_for(client, world: SharingWorld, org_id, **overrides: Any):
    body = {
        "title": "Forwarded by the member",
        "discovery_scope": "own_estate",
        "tlp": "amber",
        "bundle": _finding(),
        "on_behalf_of": str(org_id),
        "consent_sha256": CONSENT,
        **overrides,
    }
    return await client.post(f"{API}/submissions/on-behalf", json=body, headers=world.editor)


async def _stored(session, response) -> Submission:
    submission = await session.get(Submission, uuid.UUID(response.json()["id"]))
    await session.refresh(submission)
    return submission


# ---------------------------------------------------------------------------
# Filing
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-68")
async def test_a_filing_with_consent_is_the_members_and_records_who_filed_it(
    client, session, world
):
    response = await file_for(client, world, world.member.org.id)

    assert response.status_code == 201, response.text
    submission = await _stored(session, response)
    assert submission.submitter_org_id == world.member.org.id
    editor = await session.scalar(select(Operator).where(Operator.org_id == world.isac_org.id))
    assert submission.filed_by_operator_id == editor.id
    assert submission.created_by_operator_id is None
    assert submission.proxy_consent_sha256 == CONSENT
    assert submission.state is SubmissionState.SUBMITTED
    assert submission.distribute_anonymously is True, "anonymous unless the member asks"


@pytest.mark.requirement("SF-68")
@pytest.mark.parametrize(
    "consent", ["", "5F" * 32, "z" * 64, "5f" * 31], ids=["empty", "upper", "not-hex", "short"]
)
async def test_a_filing_without_a_consent_artefact_is_refused_and_nothing_is_filed(
    client, session, world, consent
):
    response = await file_for(client, world, world.member.org.id, consent_sha256=consent)

    assert response.status_code in (400, 422)
    filed = await session.scalar(
        select(Submission).where(Submission.submitter_org_id == world.member.org.id)
    )
    assert filed is None


@pytest.mark.requirement("SF-68")
async def test_the_member_is_told_at_once_and_the_notice_carries_no_content(
    client, session, world, member_hook
):
    response = await file_for(client, world, world.member.org.id)
    submission = await _stored(session, response)

    deliveries = (
        (
            await session.execute(
                select(WebhookDelivery).where(WebhookDelivery.webhook_id == member_hook.id)
            )
        )
        .scalars()
        .all()
    )

    assert [delivery.event for delivery in deliveries] == [EVENT_FILED_ON_BEHALF]
    payload = deliveries[0].payload
    assert payload["submission_id"] == str(submission.id)
    assert set(payload) == {"event", "submission_id", "confirm_by", "detail"}
    assert "Forwarded by the member" not in str(payload)


@pytest.mark.parametrize(
    "org_type", [OrgType.ADMIN, OrgType.AUTOMATION], ids=["the-isac", "a-machine"]
)
async def test_an_editor_cannot_file_for_the_isac_or_a_machine(client, world, isac_org, org_type):
    target = isac_org.id if org_type is OrgType.ADMIN else world.automation.org.id

    response = await file_for(client, world, target)

    assert response.status_code == 400


async def test_an_editor_cannot_file_for_a_suspended_member(client, world, make_org):
    suspended = await make_org("lapsed-bank", status=OrgStatus.SUSPENDED)

    response = await file_for(client, world, suspended.id)

    assert response.status_code == 400


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------
async def _validated_proxy_filing(client, session, world) -> Submission:
    response = await file_for(client, world, world.member.org.id)
    submission = await _stored(session, response)
    validated = await client.post(
        f"{API}/submissions/{submission.id}/validate", json={}, headers=world.editor
    )
    assert validated.status_code == 200, validated.text
    return submission


async def _distribute(client, world, submission):
    return await client.post(
        f"{API}/submissions/{submission.id}/distribute",
        json={"circle_ids": [str(world.circle.id)]},
        headers=world.editor,
    )


@pytest.mark.requirement("SF-68")
async def test_an_unconfirmed_filing_is_not_distributed_inside_its_window(client, session, world):
    submission = await _validated_proxy_filing(client, session, world)

    refused = await _distribute(client, world, submission)

    assert refused.status_code == 409
    assert "not yet confirmed" in refused.text


@pytest.mark.requirement("SF-68")
async def test_once_the_member_confirms_the_filing_is_distributed(client, session, world):
    submission = await _validated_proxy_filing(client, session, world)

    confirmed = await client.post(
        f"{API}/submissions/{submission.id}/confirm", json={}, headers=world.member.person
    )
    distributed = await _distribute(client, world, submission)

    assert confirmed.status_code == 200, confirmed.text
    assert distributed.status_code == 200, distributed.text


@pytest.mark.requirement("SF-68")
async def test_silence_confirms_once_the_window_has_passed(client, session, world):
    submission = await _validated_proxy_filing(client, session, world)
    deadline = submission.proxy_confirm_by

    assert awaiting_confirmation_problem(submission, deadline - dt.timedelta(seconds=1))
    assert awaiting_confirmation_problem(submission, deadline) is None


@pytest.mark.requirement("SF-68")
async def test_the_window_is_a_day_from_filing(client, session, world):
    before = dt.datetime.now(dt.UTC)
    submission = await _stored(session, await file_for(client, world, world.member.org.id))

    assert before + CONFIRM_WITHIN <= submission.proxy_confirm_by
    assert submission.proxy_confirm_by <= dt.datetime.now(dt.UTC) + CONFIRM_WITHIN


@pytest.mark.requirement("SF-68")
async def test_only_the_member_confirms_the_editor_is_refused_and_others_see_nothing(
    client, session, world
):
    submission = await _stored(session, await file_for(client, world, world.member.org.id))
    path = f"{API}/submissions/{submission.id}/confirm"

    by_editor = await client.post(path, json={}, headers=world.editor)
    by_reader = await client.post(path, json={}, headers=world.reader.person)
    absent = await client.post(
        f"{API}/submissions/{uuid.uuid4()}/confirm", json={}, headers=world.reader.person
    )

    assert by_editor.status_code == 403
    assert by_reader.status_code == absent.status_code == 404
    await session.refresh(submission)
    assert submission.proxy_confirmed_at is None


@pytest.mark.requirement("SF-68")
async def test_the_members_machine_certificate_cannot_confirm_only_a_person_can(
    client, session, world
):
    """A collector that confirmed whatever arrived would close the window unread."""
    submission = await _stored(session, await file_for(client, world, world.member.org.id))
    path = f"{API}/submissions/{submission.id}/confirm"

    by_machine = await client.post(path, json={}, headers=world.member.machine)
    await session.refresh(submission)
    unconfirmed = submission.proxy_confirmed_at
    by_person = await client.post(path, json={}, headers=world.member.person)

    assert by_machine.status_code == 403
    assert unconfirmed is None
    assert by_person.status_code == 200, by_person.text


# ---------------------------------------------------------------------------
# The portal: the notice that needs no webhook
# ---------------------------------------------------------------------------
async def _signed_in(client, session, settings, world) -> str:
    """The member's analyst signed in to the portal; returns the form token."""
    certificate = x509.load_pem_x509_certificate(world.member.pem.encode("ascii"))
    established = await establish_session(
        session,
        settings,
        operator=world.member.operator,
        cert_fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
    )
    await session.commit()
    client.cookies.set(settings.session_cookie_name, established.token)
    return established.csrf_token


@pytest.mark.requirement("SF-68")
async def test_a_member_with_no_webhook_sees_the_filing_on_its_dashboard(
    client, session, settings, world
):
    submission = await _stored(
        session, await file_for(client, world, world.member.org.id, title="Sent by email")
    )
    await _signed_in(client, session, settings, world)

    page = await client.get("/portal/", headers=proxy_headers(world.member.pem))

    assert page.status_code == 200
    assert "Filed in your name" in page.text
    assert f"/portal/submissions/{submission.id}" in page.text


@pytest.mark.requirement("SF-68")
async def test_a_person_confirms_from_the_portal_and_the_dashboard_stops_asking(
    client, session, settings, world
):
    submission = await _stored(session, await file_for(client, world, world.member.org.id))
    csrf = await _signed_in(client, session, settings, world)
    headers = proxy_headers(world.member.pem)

    detail = await client.get(f"/portal/submissions/{submission.id}", headers=headers)
    confirmed = await client.post(
        f"/portal/submissions/{submission.id}/confirm",
        data={"csrf_token": csrf},
        headers=headers,
    )
    dashboard = await client.get("/portal/", headers=headers)

    assert "Confirm we sent this" in detail.text
    assert confirmed.status_code == 303, confirmed.text
    await session.refresh(submission)
    assert submission.proxy_confirmed_at is not None
    assert "Filed in your name" not in dashboard.text


async def test_the_dashboard_does_not_ask_about_a_filing_the_member_made_itself(
    client, session, settings, world
):
    await client.post(
        f"{API}/submissions",
        json={
            "title": "Filed by the member",
            "discovery_scope": "own_estate",
            "tlp": "amber",
            "bundle": _finding(),
        },
        headers=world.member.person,
    )
    await _signed_in(client, session, settings, world)

    page = await client.get("/portal/", headers=proxy_headers(world.member.pem))

    assert "Filed in your name" not in page.text


@pytest.mark.requirement("SF-68")
async def test_the_member_withdraws_a_filing_with_its_ordinary_stop_button(client, session, world):
    submission = await _stored(session, await file_for(client, world, world.member.org.id))

    withdrawn = await client.post(
        f"{API}/submissions/{submission.id}/withdraw", json={}, headers=world.member.person
    )

    assert withdrawn.status_code == 200, withdrawn.text
    await session.refresh(submission)
    assert submission.state is SubmissionState.WITHDRAWN


async def test_a_submission_the_member_filed_itself_needs_no_confirmation(client, session, world):
    filed = await client.post(
        f"{API}/submissions",
        json={
            "title": "Filed by the member",
            "discovery_scope": "own_estate",
            "tlp": "amber",
            "bundle": _finding(),
        },
        headers=world.member.person,
    )
    submission = await _stored(session, filed)

    confirmed = await client.post(
        f"{API}/submissions/{submission.id}/confirm", json={}, headers=world.member.person
    )

    assert confirmed.status_code == 409
    assert awaiting_confirmation_problem(submission, dt.datetime.now(dt.UTC)) is None
