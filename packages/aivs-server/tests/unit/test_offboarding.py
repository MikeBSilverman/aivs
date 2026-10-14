"""An organisation leaves the ISAC: what ends, what is deleted, what is kept (SF-72).

Offboarding is the one status nothing reverses. The tests drive it through the
API as membership staff, against an organisation that holds one of everything
a member can hold, and read the result back by the data inventory's classes:
operational rows are gone, people are pseudonymised, evidence is kept. A
legal hold keeps the postures until it is lifted.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import uuid
from pathlib import Path

import pytest
from sqlalchemy import func, select, text

from aivs_schemas.enums import CertStatus, OperatorRole, OrgStatus
from aivs_server.audit.log import AuditAction
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db import models
from aivs_server.db.base import Base
from aivs_server.services.detections import RULES, run_detections
from tests.authz_matrix.world import inbox_note
from tests.conftest import proxy_headers
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world, one_click
from tests.unit.test_taxii_inbox import TAXII_TYPE

pytestmark = pytest.mark.db

INVENTORY = Path(__file__).resolve().parents[4] / "docs" / "data-inventory.md"
REASON = "Membership ended at renewal."


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
async def holdings(client, session, secret_box, world) -> SharingWorld:
    """The member, holding one of everything: a posture, a webhook with a queued
    delivery, an inbox status, a contribution."""
    member = world.member
    assert (
        await client.put(
            f"{API}/postures",
            json={"vulnerability": world.published, "status": "fixed"},
            headers=member.person,
        )
    ).status_code == 200
    hook_id = uuid.uuid4()
    session.add(
        models.Webhook(
            id=hook_id,
            org_id=member.org.id,
            url="https://member.example/aivs",
            hmac_secret_encrypted=secret_box.seal(
                "member-secret", purpose=SecretPurpose.WEBHOOK_HMAC, subject=hook_id
            ),
            events=[],
        )
    )
    session.add(models.WebhookDelivery(webhook_id=hook_id, event="test", payload={}))
    org = await session.get(models.Organization, member.org.id)
    org.contact_email = "security@meridian.example"
    await session.commit()
    assert (await one_click(client, member.person, world.published)).status_code == 201
    posted = await client.post(
        f"/taxii2/aivs/collections/{world.collection.id}/objects/",
        content=json.dumps({"objects": [inbox_note(world.published)]}),
        headers={**member.machine, "content-type": TAXII_TYPE},
    )
    assert posted.status_code == 202, posted.text
    return world


async def offboard(client, world: SharingWorld, *, slug: str | None = None):
    return await client.post(
        f"{API}/orgs/{world.member.org.id}/offboard",
        json={"reason": REASON, "confirm_slug": slug or world.member.org.slug},
        headers=world.editor,
    )


async def _count(session, table: str, column: str, org_id: uuid.UUID) -> int:
    return int(
        await session.scalar(
            text(f"SELECT count(*) FROM {table} WHERE {column} = :org"),  # noqa: S608 - names from the model's own metadata
            {"org": org_id},
        )
    )


def _classes() -> dict[str, str]:
    rows = re.findall(r"^\| `([a-z_]+)` \| ([a-z]+) \|", INVENTORY.read_text("utf-8"), re.M)
    return dict(rows)


def _org_scoped(data_class: str) -> list[tuple[str, str]]:
    """Each table of ``data_class`` that holds an organisation's own rows, and its column."""
    classes = _classes()
    return [
        (name, column)
        for name, table in sorted(Base.metadata.tables.items())
        if classes.get(name) == data_class
        for column in ("org_id",)
        if column in table.columns
    ]


# ---------------------------------------------------------------------------
# What ends, what goes, what stays
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-72")
async def test_every_operational_row_of_the_member_is_deleted(client, session, holdings):
    """Read from the data inventory: a new operational table with an ``org_id`` that
    this misses fails here. Webhook deliveries are keyed by their webhook and are
    asserted by name; ``detection_state`` is the detector's own dedupe memory,
    keyed by subject, and is deliberately kept so an alert does not re-fire."""
    org_id = holdings.member.org.id
    before = {
        name: await _count(session, name, col, org_id) for name, col in _org_scoped("operational")
    }

    response = await offboard(client, holdings)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "offboarded"
    assert before["org_postures"] > 0
    assert before["webhooks"] > 0
    assert before["portal_sessions"] > 0
    assert before["taxii_status"] > 0
    deliveries = await session.scalar(select(func.count()).select_from(models.WebhookDelivery))
    assert deliveries == 0, "a webhook's queued deliveries go with it"
    after = {
        name: await _count(session, name, col, org_id) for name, col in _org_scoped("operational")
    }
    assert after == dict.fromkeys(after, 0)


@pytest.mark.requirement("SF-72")
async def test_its_people_are_pseudonymised_and_their_ids_kept(client, session, holdings):
    operator_id = holdings.member.operator.id

    await offboard(client, holdings)

    operator = await session.get(models.Operator, operator_id, populate_existing=True)
    org = await session.get(models.Organization, holdings.member.org.id, populate_existing=True)
    assert operator is not None, "the audit log names actors by id"
    assert operator.email == f"offboarded-{operator_id}@offboarded.invalid"
    assert operator.display_name == "Offboarded operator"
    assert operator.totp_secret_encrypted is None
    assert operator.password_hash == "!offboarded", "no Argon2 hash parses as this"
    assert operator.totp_enrolled_at is None
    assert operator.is_active is False
    assert org.contact_email is None
    assert org.name == holdings.member.org.name, "evidence names who it is about"


@pytest.mark.requirement("SF-72")
async def test_its_credentials_end_and_its_memberships_close_as_offboarding(
    client, session, holdings
):
    member = holdings.member

    await offboard(client, holdings)

    certificates = (
        await session.execute(
            select(models.ClientCertificate.status, models.ClientCertificate.revoked_reason).where(
                models.ClientCertificate.org_id == member.org.id
            )
        )
    ).all()
    memberships = (
        (
            await session.execute(
                select(models.CircleMembership.ended_by).where(
                    models.CircleMembership.org_id == member.org.id
                )
            )
        )
        .scalars()
        .all()
    )
    assert set(certificates) == {(CertStatus.REVOKED, "offboarded")}
    assert memberships == ["offboarding"]
    assert (await client.get(f"{API}/whoami", headers=member.machine)).status_code == 401
    assert (await client.get(f"{API}/whoami", headers=member.person)).status_code == 401


@pytest.mark.requirement("SF-72")
async def test_its_contributions_and_receipts_are_kept(client, session, holdings):
    org_id = holdings.member.org.id
    submissions = await _count(session, "submissions", "submitter_org_id", org_id)

    await offboard(client, holdings)

    assert submissions > 0
    assert await _count(session, "submissions", "submitter_org_id", org_id) == submissions


@pytest.mark.requirement("SF-72")
async def test_the_audit_row_counts_what_ended_never_its_postures(client, session, holdings):
    await offboard(client, holdings)

    row = await session.scalar(
        select(models.AuditLog).where(models.AuditLog.action == AuditAction.ORG_OFFBOARDED)
    )
    assert row.details["postures"] == "deleted"
    assert row.details["certificates_revoked"] >= 1
    assert "posture_count" not in str(row.details)
    assert not any(isinstance(value, int) for key, value in row.details.items() if "posture" in key)


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-72")
async def test_nothing_writes_another_status_over_offboarded(client, session, holdings, ca):
    org_id = holdings.member.org.id
    await offboard(client, holdings)

    activate = await client.post(f"{API}/orgs/{org_id}/activate", headers=holdings.editor)
    quarantine = await client.post(
        f"{API}/orgs/{org_id}/quarantine",
        json={"reason": "after offboarding, by mistake"},
        headers=holdings.editor,
    )
    again = await offboard(client, holdings)
    re_add = await client.post(
        f"{API}/circles/{holdings.circle.id}/members",
        json={"org_ids": [str(org_id)], "role": "contributor"},
        headers=holdings.editor,
    )
    pem, _fingerprint, _cert = ca.issue("meridian-global-after-offboarding")
    register = await client.post(
        f"{API}/orgs/{org_id}/certificates",
        json={"certificate_pem": pem, "label": "after offboarding"},
        headers=holdings.editor,
    )

    assert activate.status_code == quarantine.status_code == again.status_code == 409
    assert re_add.status_code == 404
    assert "offboarded organisations cannot be members" in re_add.text
    assert register.status_code == 403
    org = await session.get(models.Organization, org_id, populate_existing=True)
    assert org.status is OrgStatus.OFFBOARDED


async def test_a_mistyped_slug_offboards_nothing(client, session, holdings):
    response = await offboard(client, holdings, slug="meridian-globel")

    assert response.status_code == 400
    org = await session.get(models.Organization, holdings.member.org.id, populate_existing=True)
    assert org.status is OrgStatus.ACTIVE


async def test_the_hosting_isac_cannot_be_offboarded(client, world):
    response = await client.post(
        f"{API}/orgs/{world.isac_org.id}/offboard",
        json={"reason": REASON, "confirm_slug": world.isac_org.slug},
        headers=world.editor,
    )

    assert response.status_code == 409


# ---------------------------------------------------------------------------
# Legal hold
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-72")
async def test_a_legal_hold_keeps_the_postures_until_it_is_lifted(client, session, holdings):
    org_id = holdings.member.org.id
    held = await client.put(
        f"{API}/orgs/{org_id}/legal-hold",
        json={"reason": "Litigation hold, matter 2026-114."},
        headers=holdings.editor,
    )

    await offboard(client, holdings)
    kept = await _count(session, "org_postures", "org_id", org_id)
    lifted = await client.post(
        f"{API}/orgs/{org_id}/legal-hold/lift",
        json={"reason": "Matter 2026-114 closed."},
        headers=holdings.editor,
    )

    assert held.status_code == lifted.status_code == 200
    assert kept == 1
    assert await _count(session, "org_postures", "org_id", org_id) == 0


@pytest.mark.requirement("SF-80")
async def test_an_offboarded_member_leaves_every_published_count(client, session, holdings):
    """A published count holds the member's status as surely as its posture row did."""
    member = str(holdings.member.org.id)
    others = {f"other-{index}": "fixed" for index in range(5)}
    session.add(
        models.CountSnapshot(
            subject_kind=models.CountSubject.POSTURE.value,
            subject_id=holdings.published,
            taken_at=dt.datetime.now(dt.UTC),
            basis={member: "fixed", **others},
        )
    )
    await session.commit()

    assert (await offboard(client, holdings)).status_code == 200

    snapshot = await session.get(
        models.CountSnapshot, (models.CountSubject.POSTURE.value, holdings.published)
    )
    await session.refresh(snapshot)
    assert snapshot.basis == others


async def test_lifting_a_hold_on_a_member_still_in_the_isac_deletes_nothing(
    client, session, holdings
):
    org_id = holdings.member.org.id
    await client.put(
        f"{API}/orgs/{org_id}/legal-hold",
        json={"reason": "Litigation hold, matter 2026-114."},
        headers=holdings.editor,
    )

    await client.post(
        f"{API}/orgs/{org_id}/legal-hold/lift",
        json={"reason": "Matter 2026-114 closed."},
        headers=holdings.editor,
    )

    assert await _count(session, "org_postures", "org_id", org_id) == 1


@pytest.mark.requirement("SF-72")
async def test_a_members_own_admin_cannot_offboard_its_own_firm(
    client, session, world, make_operator, human_headers
):
    """Ending one's own membership is the ISAC's act; "we are compromised" is quarantine."""
    admin, _seed = await make_operator(world.member.org, roles=(OperatorRole.ORG_ADMIN,))
    headers = await human_headers(admin, world.member.pem)

    response = await client.post(
        f"{API}/orgs/{world.member.org.id}/offboard",
        json={"reason": REASON, "confirm_slug": world.member.org.slug},
        headers=headers,
    )

    assert response.status_code == 403
    org = await session.get(models.Organization, world.member.org.id, populate_existing=True)
    assert org.status is OrgStatus.ACTIVE


@pytest.mark.parametrize("route", ["offboard", "legal-hold", "legal-hold/lift"])
async def test_a_members_own_admin_cannot_offboard_or_hold(
    client, world, route, make_operator, human_headers
):
    """Membership staff only: an org_admin cannot end its own or a peer's membership."""
    admin, _seed = await make_operator(world.member.org, roles=(OperatorRole.ORG_ADMIN,))
    headers = await human_headers(admin, world.member.pem)
    method = client.put if route == "legal-hold" else client.post
    body = {"reason": REASON}
    if route == "offboard":
        body["confirm_slug"] = world.reader.org.slug

    response = await method(f"{API}/orgs/{world.reader.org.id}/{route}", json=body, headers=headers)

    assert response.status_code == 403
    assert (
        await client.get(f"{API}/whoami", headers=proxy_headers(world.reader.pem))
    ).status_code == 200


@pytest.mark.requirement("SF-72")
async def test_every_offboarding_raises_its_own_alert(client, session, world):
    """Two in one hour are two alerts, each naming its organisation."""
    for party in (world.member, world.reader):
        response = await client.post(
            f"{API}/orgs/{party.org.id}/offboard",
            json={"reason": REASON, "confirm_slug": party.org.slug},
            headers=world.editor,
        )
        assert response.status_code == 200, response.text
    rule = next(rule for rule in RULES if rule.name == "org_offboarded")

    raised = await run_detections(
        session, quarantine_policy="propose", now=dt.datetime.now(dt.UTC), rules=[rule]
    )

    assert sorted(finding.details["resource"] for finding in raised) == sorted(
        [str(world.member.org.id), str(world.reader.org.id)]
    )
