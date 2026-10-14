"""Revoking content that reached members without review (closes threat-model R13).

The fast lane and post-moderated circles publish before an editor reads the
content; an editor revokes afterwards. A revocation is a newer ``revoked``
version distributed where the object went (SF-9's shape), never an edit in
place, so a poller that already walked past the original receives it.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select

from aivs_schemas.enums import OperatorRole
from aivs_server.audit.log import AuditAction
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.auth.sessions import establish_session
from aivs_server.db.models import AuditLog, Webhook, WebhookDelivery
from tests.conftest import proxy_headers
from tests.unit.contribution_world import STAMP
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world, one_click

pytestmark = pytest.mark.db

REASON = "abusive content posted from a compromised session"


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


async def post_moderated_note(client, world: SharingWorld) -> tuple[str, str]:
    """A note published on submit in a post-moderated circle: (submission id, note id)."""
    enabled = await client.put(
        f"{API}/circles/{world.circle.id}/post-moderation",
        json={"enabled": True},
        headers=world.editor,
    )
    assert enabled.status_code == 204
    note_id = f"note--{uuid.uuid4()}"
    note = {
        "type": "note",
        "spec_version": "2.1",
        "id": note_id,
        "created": STAMP,
        "modified": STAMP,
        "content": "We see exploitation against our gateway.",
        "object_refs": [world.published],
    }
    filed = await client.post(
        f"{API}/submissions",
        json={
            "title": "Short note",
            "discovery_scope": "own_estate",
            "tlp": "amber",
            "distribute_anonymously": True,
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [note]},
        },
        headers=world.member.person,
    )
    assert filed.status_code == 201, filed.text
    submitted = await client.post(
        f"{API}/submissions/{filed.json()['id']}/submit", json={}, headers=world.member.person
    )
    assert submitted.json()["state"] == "distributed", submitted.text
    return filed.json()["id"], note_id


async def revoke(client, headers, submission_id, reason=REASON):
    return await client.post(
        f"{API}/submissions/{submission_id}/revoke", json={"reason": reason}, headers=headers
    )


async def versions_seen_by(client, world: SharingWorld, stix_id: str, **params: str) -> list[dict]:
    response = await client.get(
        f"/taxii2/aivs/collections/{world.collection.id}/objects/",
        params={"match[id]": stix_id, "match[version]": "all", **params},
        headers=world.reader.machine,
    )
    assert response.status_code == 200, response.text
    return response.json().get("objects", [])


# ---------------------------------------------------------------------------
# What a revocation publishes
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-66")
async def test_a_post_moderated_note_is_revoked_by_a_newer_version_members_receive(client, world):
    submission_id, note_id = await post_moderated_note(client, world)
    [original] = await versions_seen_by(client, world, note_id)

    revoked = await revoke(client, world.editor, submission_id)

    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["revoked_ids"] == [note_id]
    versions = await versions_seen_by(client, world, note_id)
    assert [bool(v.get("revoked")) for v in sorted(versions, key=lambda v: v["modified"])] == [
        False,
        True,
    ]
    newest = max(versions, key=lambda v: v["modified"])
    assert newest["modified"] > original["modified"]
    assert newest["content"] == original["content"], "a version, not an edit"


@pytest.mark.requirement("SF-66")
async def test_a_member_with_a_webhook_is_told_of_the_revocation_whatever_the_app_clock_says(
    client, session, secret_box, world, monkeypatch
):
    """A revocation is a new version, announced like one, and stamped from the
    database's clock. With that clock ahead of this replica's, the notification
    queue must compare the stamp with the stamp's own clock: compared with the
    replica's "now", the revocation looked not yet visible, and nobody was told."""
    submission_id, _note_id = await post_moderated_note(client, world)
    webhook_id = uuid.uuid4()
    session.add(
        Webhook(
            id=webhook_id,
            org_id=world.reader.org.id,
            url="https://reader.example/hook",
            hmac_secret_encrypted=secret_box.seal(
                "webhook-signing-secret", purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook_id
            ),
            events=[],
        )
    )
    await session.commit()
    ahead = dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)

    async def database_clock_ahead(_session: object) -> dt.datetime:
        return ahead

    monkeypatch.setattr("aivs_server.services.publication.database_now", database_clock_ahead)
    revoked = await revoke(client, world.editor, submission_id)

    assert revoked.status_code == 200, revoked.text
    queued = (
        await session.scalars(
            select(WebhookDelivery).where(WebhookDelivery.webhook_id == webhook_id)
        )
    ).all()
    assert len(queued) == 1


@pytest.mark.requirement("SF-66")
async def test_a_poller_past_the_original_still_receives_the_revocation(client, world):
    """SF-9's shape: a new row, so a cursor already past the original sees it."""
    submission_id, note_id = await post_moderated_note(client, world)
    first = await client.get(
        f"/taxii2/aivs/collections/{world.collection.id}/objects/",
        headers=world.reader.machine,
    )
    cursor = first.headers["X-TAXII-Date-Added-Last"]

    await revoke(client, world.editor, submission_id)
    later = await versions_seen_by(client, world, note_id, added_after=cursor)

    assert [v.get("revoked") for v in later] == [True]


async def test_a_fast_lane_click_is_revocable_too(client, world):
    clicked = await one_click(client, world.member.person, world.published)
    assert clicked.json()["lane"] == "fast"

    revoked = await revoke(client, world.editor, clicked.json()["submission_id"])

    assert revoked.status_code == 200, revoked.text


async def test_the_revocation_is_audited_with_its_reason(client, session, world):
    submission_id, note_id = await post_moderated_note(client, world)

    await revoke(client, world.editor, submission_id)

    row = await session.scalar(
        select(AuditLog).where(AuditLog.action == AuditAction.CONTRIBUTION_REVOKED)
    )
    assert row.resource_id == submission_id
    assert row.details["reason"] == REASON
    assert row.details["objects"] == [note_id]


# ---------------------------------------------------------------------------
# What is refused
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-66")
async def test_only_an_editor_revokes_the_submitter_is_refused_and_others_see_nothing(
    client, world
):
    submission_id, _note = await post_moderated_note(client, world)

    by_submitter = await revoke(client, world.member.person, submission_id)
    by_reader = await revoke(client, world.reader.person, submission_id)
    absent = await revoke(client, world.reader.person, uuid.uuid4())

    assert by_submitter.status_code == 403
    assert by_reader.status_code == absent.status_code == 404


@pytest.mark.requirement("SF-66")
async def test_reviewed_content_is_not_revoked_this_way(client, world):
    clicked = await one_click(client, world.member.machine, world.published)
    assert clicked.json()["lane"] == "review"

    refused = await revoke(client, world.editor, clicked.json()["submission_id"])

    assert refused.status_code == 409
    assert "reviewed content" in refused.text


async def test_revoking_twice_is_refused(client, world):
    submission_id, _note = await post_moderated_note(client, world)
    assert (await revoke(client, world.editor, submission_id)).status_code == 200

    again = await revoke(client, world.editor, submission_id)

    assert again.status_code == 409
    assert "already revoked" in again.text


async def test_a_revocation_without_a_reason_is_refused(client, world):
    submission_id, _note = await post_moderated_note(client, world)

    refused = await revoke(client, world.editor, submission_id, reason="no")

    assert refused.status_code == 400


# ---------------------------------------------------------------------------
# While distribution is paused
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-66")
async def test_an_editor_can_revoke_while_paused_and_members_see_the_revocation_on_resume(
    client, world
):
    submission_id, note_id = await post_moderated_note(client, world)
    paused = await client.post(
        f"{API}/instance/distribution/pause",
        json={"reason": "bad note posted"},
        headers=world.editor,
    )
    assert paused.status_code == 200, paused.text

    revoked = await revoke(client, world.editor, submission_id)
    hidden = await versions_seen_by(client, world, note_id)
    await client.post(
        f"{API}/instance/distribution/resume",
        json={"reason": "note revoked"},
        headers=world.editor,
    )
    shown = await versions_seen_by(client, world, note_id)

    assert revoked.status_code == 200, revoked.text
    assert hidden == []
    assert max(shown, key=lambda v: v["modified"]).get("revoked") is True


# ---------------------------------------------------------------------------
# The portal
# ---------------------------------------------------------------------------
async def test_an_editor_revokes_from_the_portal_and_a_failure_says_why(
    client, session, world, settings, isac_org, make_cert, make_operator
):
    submission_id, note_id = await post_moderated_note(client, world)
    pem, _ = await make_cert(isac_org)
    editor, _seed = await make_operator(isac_org, roles=(OperatorRole.ISAC_EDITOR,))
    certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
    established = await establish_session(
        session,
        settings,
        operator=editor,
        cert_fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
    )
    await session.commit()
    client.cookies.set(settings.session_cookie_name, established.token)
    browser = proxy_headers(pem)
    path = f"/portal/submissions/{submission_id}/revoke"

    page = await client.get(f"/portal/submissions/{submission_id}", headers=browser)
    too_short = await client.post(
        path, data={"csrf_token": established.csrf_token, "reason": "no"}, headers=browser
    )
    done = await client.post(
        path, data={"csrf_token": established.csrf_token, "reason": REASON}, headers=browser
    )

    assert f'action="{path}"' in page.text
    assert too_short.status_code == done.status_code == 303
    assert "aivs_notice" in json.dumps(dict(too_short.headers)), "the failure has its own outcome"
    newest = max(await versions_seen_by(client, world, note_id), key=lambda v: v["modified"])
    assert newest.get("revoked") is True
