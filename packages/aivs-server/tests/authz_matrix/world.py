"""A seeded instance with a real target for every route.

Built through the real API wherever a workflow state is involved, so each
submission reaches its state the way production content does. Each route
gets its own target, so the matrix can call routes in any order: suspending
one organisation never changes what another route sees.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import CircleRole, OperatorRole, OrgStatus, OrgType, ReadingDepth
from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID
from aivs_server.auth.secretbox import SecretBox, SecretPurpose
from aivs_server.auth.sessions import establish_session, establish_sso_session
from aivs_server.config import Settings
from aivs_server.db.models import Organization, SectorEvent, Webhook
from tests.authz_matrix.principals import (
    CERTIFICATE_ORGS,
    SESSION_ROLES,
    Credentials,
    Principal,
)
from tests.conftest import ISAC_STAFF_ROLES, TEST_PROXY_SECRET, proxy_headers
from tests.sso_support import ISSUER as SSO_ISSUER
from tests.unit.contribution_world import seed as seed_record
from tests.unit.contribution_world import vulnerability_raw

API = "/api/v1/submissions"
STAMP = "2026-08-01T00:00:00.000Z"


@dataclass
class World:
    orgs: dict[str, uuid.UUID] = field(default_factory=dict)
    pems: dict[str, str] = field(default_factory=dict)
    submissions: dict[str, uuid.UUID] = field(default_factory=dict)
    circle_id: uuid.UUID | None = None
    collection_id: uuid.UUID | None = None
    object_stix_id: str = ""
    #: A vulnerability the OSV export can carry whole: a purl, a range and an
    #: agreed function condition, so an allowed caller gets a record, not a 409.
    osv_stix_id: str = ""
    unregistered_pem: str = ""
    revocable_certificate_id: uuid.UUID | None = None
    webhook_id: uuid.UUID | None = None
    #: The ISAC's published record in the circle: what the TAXII inbox takes
    #: contributions on.
    public_stix_id: str = ""
    #: A second ISAC record, for an editor to pin; and an event already open
    #: on the first, for the routes that close it or file its call notes.
    pinnable_stix_id: str = ""
    sector_event_id: uuid.UUID | None = None
    posture_id: uuid.UUID | None = None
    taxii_status_id: uuid.UUID | None = None


@dataclass
class Factories:
    """The suite's fixtures the world is built from."""

    client: AsyncClient
    session: AsyncSession
    settings: Settings
    secret_box: SecretBox
    ca: Any
    make_org: Any
    make_cert: Any
    make_circle: Any
    join_circle: Any
    make_collection: Any
    make_operator: Any


def _bundle(name: str, *, exportable: bool = False) -> tuple[dict[str, Any], str]:
    stix_id = f"vulnerability--{uuid.uuid4()}"
    vulnerability: dict[str, Any] = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id,
        "created": STAMP,
        "modified": STAMP,
        "name": name,
    }
    objects = [vulnerability, *(_exportable(vulnerability) if exportable else ())]
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    return bundle, stix_id


def _exportable(vulnerability: dict[str, Any]) -> list[dict[str, Any]]:
    """Make ``vulnerability`` one the OSV export carries whole; return its condition note."""
    vulnerability["extensions"] = {
        AIVS_INTEL_EXTENSION_ID: {
            "extension_type": "property-extension",
            "aivs_schema_version": "2.0",
            "discovery_scope": "own_product",
            "cve_status": "pre-cve",
            "affected_products": [
                {
                    "vendor": "Example",
                    "product": "xml",
                    "purl": "pkg:golang/example.com/xml",
                    "version_range": "vers:golang/<v1.4.1",
                }
            ],
        }
    }
    calls = {"ecosystem": "Go", "package": "pkg:golang/example.com/xml", "symbol": "Parse"}
    note = {
        "type": "note",
        "spec_version": "2.1",
        "id": f"note--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "content": "Exploitability conditions.",
        "object_refs": [vulnerability["id"]],
        "extensions": {
            AIVS_INTEL_EXTENSION_ID: {
                "extension_type": "property-extension",
                "aivs_schema_version": "2.1",
                "summary": "Reachable only through Parse.",
                "conditions": [{"id": "fn", "kind": "function", "any_of": [calls]}],
            }
        },
    }
    return [note]


def inbox_note(public_stix_id: str) -> dict[str, Any]:
    """A contribution on the ISAC's published record: what the inbox takes."""
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": f"note--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "content": "Seen at a member over TAXII.",
        "object_refs": [public_stix_id],
    }


async def _session_credentials(
    f: Factories, org: Organization, pem: str, roles: tuple[Any, ...]
) -> Credentials:
    # An auditor exists only with an end date (ck_operators_auditor_alone_and_expiring).
    expires = (
        dt.datetime.now(dt.UTC) + dt.timedelta(days=30) if OperatorRole.AUDITOR in roles else None
    )
    operator, _seed = await f.make_operator(org, roles=roles, role_expires_at=expires)
    # Every session principal carries the one stored reading preference, at the
    # depth that shows the most, so the whole matrix is the proof that it
    # confers nothing: a route that granted more to a reader with a preference
    # would break that principal's row.
    operator.default_depth = ReadingDepth.TECHNICAL
    certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
    established = await establish_session(
        f.session,
        f.settings,
        operator=operator,
        cert_fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
    )
    await f.session.commit()
    proxy = proxy_headers(pem)
    return Credentials(
        api_headers={**proxy, "authorization": f"Bearer {established.token}"},
        portal_headers=proxy,
        cookies={f.settings.session_cookie_name: established.token},
        csrf_token=established.csrf_token,
    )


async def _sso_credentials(f: Factories, org: Organization) -> Credentials:
    """A member analyst's SSO session: no certificate, a device cookie, the token as both."""
    operator, _seed = await f.make_operator(org, roles=(OperatorRole.ANALYST,))
    operator.federated_issuer = SSO_ISSUER
    operator.federated_subject = f"matrix-subject-{uuid.uuid4()}"
    device = "matrix-device-cookie"
    established = await establish_sso_session(
        f.session,
        f.settings,
        operator=operator,
        issuer=SSO_ISSUER,
        subject=operator.federated_subject,
        device_cookie=device,
        amr=("pwd", "otp"),
        source_ip=None,
        user_agent=None,
        now=dt.datetime.now(dt.UTC),
    )
    await f.session.commit()
    return Credentials(
        # Presented as a bearer on the machine surface, which must not take it.
        api_headers={"authorization": f"Bearer {established.token}"},
        portal_headers={},
        cookies={
            f.settings.session_cookie_name: established.token,
            f.settings.sso_device_cookie_name: device,
        },
        csrf_token=established.csrf_token,
    )


class _Seeder:
    """Moves submissions through the workflow over the real API."""

    def __init__(
        self, f: Factories, member_pem: str, editor: Credentials, circle_id: uuid.UUID
    ) -> None:
        self.client = f.client
        self.member = proxy_headers(member_pem)
        self.editor = editor.api_headers
        self.circle_id = circle_id

    async def post_moderated(self, person: dict[str, str], public_stix_id: str) -> uuid.UUID:
        """A note published on submit in the circle, for an editor to revoke."""
        enabled = await self.client.put(
            f"/api/v1/circles/{self.circle_id}/post-moderation",
            json={"enabled": True},
            headers=self.editor,
        )
        assert enabled.status_code == 204, enabled.text
        filed = await self.client.post(
            API,
            json={
                "title": "Matrix revoke",
                "discovery_scope": "own_estate",
                "tlp": "amber",
                "distribute_anonymously": True,
                "bundle": {
                    "type": "bundle",
                    "id": f"bundle--{uuid.uuid4()}",
                    "objects": [inbox_note(public_stix_id)],
                },
            },
            headers=person,
        )
        assert filed.status_code == 201, filed.text
        submitted = await self.client.post(
            f"{API}/{filed.json()['id']}/submit", json={}, headers=person
        )
        assert submitted.json()["state"] == "distributed", submitted.text
        return uuid.UUID(filed.json()["id"])

    async def create(
        self, name: str, *, anonymous: bool = False, exportable: bool = False
    ) -> tuple[uuid.UUID, str]:
        bundle, stix_id = _bundle(name, exportable=exportable)
        response = await self.client.post(
            API,
            json={
                "title": name,
                "discovery_scope": "ai_system",
                "tlp": "amber",
                "distribute_anonymously": anonymous,
                "bundle": bundle,
            },
            headers=self.member,
        )
        assert response.status_code == 201, response.text
        return uuid.UUID(response.json()["id"]), stix_id

    async def step(
        self, submission_id: uuid.UUID, verb: str, body: dict[str, Any] | None = None
    ) -> None:
        headers = self.member if verb == "submit" else self.editor
        response = await self.client.post(
            f"{API}/{submission_id}/{verb}", json=body or {}, headers=headers
        )
        assert response.status_code == 200, f"{verb}: {response.text}"

    async def distributed(
        self,
        name: str,
        *,
        anonymous: bool = False,
        exportable: bool = False,
        release_at: dt.datetime | None = None,
    ) -> tuple[uuid.UUID, str]:
        submission_id, stix_id = await self.create(name, anonymous=anonymous, exportable=exportable)
        await self.step(submission_id, "submit")
        await self.step(submission_id, "validate")
        body: dict[str, Any] = {"circle_ids": [str(self.circle_id)]}
        if release_at is not None:
            body["release_at"] = release_at.isoformat()
        await self.step(submission_id, "distribute", body)
        return submission_id, stix_id

    async def filed_on_behalf(self, member_id: uuid.UUID) -> uuid.UUID:
        bundle, _stix_id = _bundle("Matrix proxy")
        response = await self.client.post(
            f"{API}/on-behalf",
            json={
                "title": "Matrix proxy",
                "discovery_scope": "ai_system",
                "tlp": "amber",
                "bundle": bundle,
                "on_behalf_of": str(member_id),
                "consent_sha256": "c0" * 32,
            },
            headers=self.editor,
        )
        assert response.status_code == 201, response.text
        return uuid.UUID(response.json()["id"])

    async def posture(self, stix_id: str) -> uuid.UUID:
        response = await self.client.put(
            "/api/v1/postures", json={"vulnerability": stix_id}, headers=self.member
        )
        assert response.status_code == 200, response.text
        return uuid.UUID(response.json()["id"])

    async def inbox(self, collection_id: uuid.UUID | None, public_stix_id: str) -> uuid.UUID:
        response = await self.client.post(
            f"/taxii2/aivs/collections/{collection_id}/objects/",
            content=json.dumps({"objects": [inbox_note(public_stix_id)]}),
            headers={**self.member, "content-type": "application/taxii+json;version=2.1"},
        )
        assert response.status_code == 202, response.text
        return uuid.UUID(response.json()["id"])


async def build_world(f: Factories) -> tuple[World, dict[Principal, Credentials]]:
    world = World()
    orgs: dict[str, Organization] = {}

    orgs["isac"] = await f.make_org("hosting-isac", org_type=OrgType.ADMIN)
    for name, status in (
        ("member", OrgStatus.ACTIVE),
        ("peer", OrgStatus.ACTIVE),
        ("pending", OrgStatus.PENDING),
        ("suspended", OrgStatus.SUSPENDED),
        ("quarantined", OrgStatus.QUARANTINED),
        ("activate", OrgStatus.PENDING),
        ("suspend", OrgStatus.ACTIVE),
        ("quarantine", OrgStatus.ACTIVE),
        ("register", OrgStatus.ACTIVE),
        ("add", OrgStatus.ACTIVE),
        ("remove", OrgStatus.ACTIVE),
        ("quarantine_portal", OrgStatus.ACTIVE),
        ("suspend_portal", OrgStatus.ACTIVE),
        ("remove_portal", OrgStatus.ACTIVE),
        ("offboard", OrgStatus.ACTIVE),
        ("hold", OrgStatus.ACTIVE),
        ("lift", OrgStatus.ACTIVE),
    ):
        orgs[name] = await f.make_org(f"matrix-{name.replace('_', '-')}", status=status)
    orgs["add_portal"] = await f.make_org("matrix-add-portal")
    # Under a hold already, so lifting it is the request that succeeds.
    orgs["lift"].legal_hold_since = dt.datetime.now(dt.UTC)
    orgs["lift"].legal_hold_reason = "matrix: litigation hold"
    await f.session.commit()
    orgs["automation"] = await f.make_org("matrix-automation", org_type=OrgType.AUTOMATION)

    # Quarantined an hour ago, with a certificate registered since: the state
    # in which reconnection is permitted.
    reconnect = await f.make_org("matrix-reconnect", status=OrgStatus.QUARANTINED)
    reconnect.quarantined_at = dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)
    await f.session.commit()
    orgs["reconnect"] = reconnect
    await f.make_cert(reconnect)

    for name in ("isac", "member", "peer", "pending", "suspended", "quarantined", "automation"):
        world.pems[name], _ = await f.make_cert(orgs[name])
    _second_pem, revocable = await f.make_cert(orgs["peer"])
    world.revocable_certificate_id = revocable.id
    world.unregistered_pem, _fingerprint, _cert = f.ca.issue("matrix-register")
    world.orgs = {name: org.id for name, org in orgs.items()}

    circle = await f.make_circle("matrix-circle")
    # The member contributes to the circle; the peer only reads it.
    await f.join_circle(orgs["member"], circle, role=CircleRole.CONTRIBUTOR)
    for name in ("peer", "remove", "remove_portal"):
        await f.join_circle(orgs[name], circle)
    collection = await f.make_collection(circle)
    world.circle_id = circle.id
    world.collection_id = collection.id
    # The ISAC's own record, seeded directly: its filing path is not what the
    # matrix is about, and only the routes that contribute to it read it.
    world.public_stix_id = f"vulnerability--{uuid.uuid4()}"
    await seed_record(
        f.session,
        orgs["isac"],
        vulnerability_raw(world.public_stix_id, cve_status="published"),
        circle=circle,
    )
    world.pinnable_stix_id = f"vulnerability--{uuid.uuid4()}"
    await seed_record(
        f.session,
        orgs["isac"],
        vulnerability_raw(world.pinnable_stix_id, cve_status="published"),
        circle=circle,
    )
    event = SectorEvent(
        vulnerability_stix_id=world.public_stix_id, opened_at=dt.datetime.now(dt.UTC)
    )
    f.session.add(event)
    await f.session.commit()
    world.sector_event_id = event.id

    webhook_id = uuid.uuid4()
    f.session.add(
        Webhook(
            id=webhook_id,
            org_id=orgs["member"].id,
            url="https://member.matrix.example/hook",
            hmac_secret_encrypted=f.secret_box.seal(
                "matrix-signing-secret", purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook_id
            ),
            events=[],
        )
    )
    await f.session.commit()
    world.webhook_id = webhook_id

    setup_editor = await _session_credentials(f, orgs["isac"], world.pems["isac"], ISAC_STAFF_ROLES)
    seed = _Seeder(f, world.pems["member"], setup_editor, circle.id)
    await _seed_submissions(world, seed)
    member_person = await _session_credentials(
        f, orgs["member"], world.pems["member"], (OperatorRole.ANALYST,)
    )
    world.submissions["revoke"] = await seed.post_moderated(
        member_person.api_headers, world.public_stix_id
    )

    principals = await _credentials(f, world, orgs)
    return world, principals


async def _seed_submissions(world: World, seed: _Seeder) -> None:
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=3)
    world.submissions["read"], world.object_stix_id = await seed.distributed("Matrix read")
    world.submissions["osv"], world.osv_stix_id = await seed.distributed(
        "Matrix OSV", exportable=True
    )
    for name in ("patch", "submit", "withdraw"):
        world.submissions[name], _ = await seed.create(f"Matrix {name}")
    for name in ("validate", "validate_portal", "bulk", "bulk_portal"):
        world.submissions[name], _ = await seed.create(f"Matrix {name}")
        await seed.step(world.submissions[name], "submit")
    world.submissions["distribute"], _ = await seed.create("Matrix distribute")
    await seed.step(world.submissions["distribute"], "submit")
    await seed.step(world.submissions["distribute"], "validate")
    for name in ("extend", "release"):
        world.submissions[name], _ = await seed.distributed(f"Matrix {name}", release_at=later)
    world.submissions["reveal"], _ = await seed.distributed("Matrix reveal", anonymous=True)
    world.submissions["proxy"] = await seed.filed_on_behalf(world.orgs["member"])
    world.posture_id = await seed.posture(world.object_stix_id)
    world.taxii_status_id = await seed.inbox(world.collection_id, world.public_stix_id)


async def _credentials(
    f: Factories, world: World, orgs: dict[str, Organization]
) -> dict[Principal, Credentials]:
    forged = proxy_headers(world.pems["member"], proxy_secret=TEST_PROXY_SECRET + "-wrong")
    principals: dict[Principal, Credentials] = {
        Principal.ANONYMOUS: Credentials(),
        Principal.FORGED_PROXY_SECRET: Credentials(api_headers=forged, portal_headers=forged),
    }
    for principal, org_name in CERTIFICATE_ORGS.items():
        headers = proxy_headers(world.pems[org_name])
        principals[principal] = Credentials(api_headers=headers, portal_headers=headers)
    principals[Principal.SSO_MEMBER] = await _sso_credentials(f, orgs["member"])
    for principal, (org_name, role) in SESSION_ROLES.items():
        principals[principal] = await _session_credentials(
            f, orgs[org_name], world.pems[org_name], (role,)
        )
    return principals
