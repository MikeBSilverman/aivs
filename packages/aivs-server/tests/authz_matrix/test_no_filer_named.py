"""No member is told who filed an anonymous object, on any route (Phase P exit).

The principal matrix proves who may reach each route. It cannot say what a
reachable route says, and the world it seeds files most content credited. So a
firm that files only anonymously is added to the matrix world's circle, files
once through every door a member has -- the API, the portal form, a one-click,
the TAXII inbox and email -- and the ISAC distributes each filing. Then every
route is called by every other member principal, once per filing, with the
world's identifiers pointed at that filing: its submission id where a route
takes one, its objects where a route takes an object. Error bodies count as
much as content: a 404 that named the owner would be the leak.

Nothing the filer is known by may appear in any response, header or body:
its organisation id, slug, name and STIX identity, its people's ids and
addresses, or the keyed tags that link its filings to one another. The
notices the distributions sent other members are held to the same rule.

Not claims of this test: the auditor's view (``test_attribution_auditor``
pages the audit stream, which must run alone); free text the filer wrote
about itself (R37); and what an ISAC editor sees, which by design includes
the filer.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import re
import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import select, update

from aivs_schemas.enums import (
    CircleRole,
    NotificationCadence,
    OperatorRole,
    SubmissionState,
)
from aivs_server.db.models import (
    Circle,
    EmailDelivery,
    Operator,
    Organization,
    StixObject,
    Submission,
    Webhook,
    WebhookDelivery,
)
from aivs_server.notify.digest import send_due_digests
from tests.authz_matrix.principals import Credentials, Principal
from tests.authz_matrix.routes import ROUTES, RouteCase, RouteClass
from tests.authz_matrix.test_principal_matrix import _call
from tests.authz_matrix.world import (
    API,
    Factories,
    World,
    _bundle,
    _session_credentials,
    build_world,
    inbox_note,
    record_mail_domains,
)
from tests.conftest import ISAC_STAFF_ROLES, proxy_headers
from tests.unit.test_email_intake import ALICE, receive
from tests.unit.test_email_message import raw_message

pytestmark = [pytest.mark.db, pytest.mark.authz, pytest.mark.requirement("SF-85")]

#: Every member principal of another firm that holds content. The auditors are
#: left out because their one door pages the audit stream (see the docstring);
#: SSO is the analyst's portal row by construction (``_sso_member``).
READERS = (
    Principal.MEMBER_MACHINE,
    Principal.MEMBER_ANALYST,
    Principal.MEMBER_ORG_ADMIN,
    Principal.PEER_MACHINE,
)
PEER_ANALYST = "peer analyst session"

_SUBMISSION_PATH = re.compile(r"/portal/submissions/([0-9a-f-]{36})")


@dataclasses.dataclass
class Filer:
    org_id: uuid.UUID
    pem: str
    person: Credentials
    #: The submission each door made, by door.
    filings: dict[str, uuid.UUID]
    #: Everything the firm is known by, each with what it is.
    known_by: dict[str, str]


async def test_no_member_route_names_the_filer_of_anonymous_content(
    app, factories, session, attribution_key, make_operator, safe_database_role
):
    f: Factories = factories
    world, credentials = await build_world(f)
    editor = await _session_credentials(
        f,
        await session.get(Organization, world.orgs["isac"]),
        world.pems["isac"],
        ISAC_STAFF_ROLES,
    )
    await _members_take_every_notice(session, world)
    filer = await _anonymous_filer(f, world, make_operator)
    await _file_through_every_door(app, f, world, filer, attribution_key)
    for submission_id in filer.filings.values():
        await _distribute(f.client, world, filer, editor, session, submission_id)
    filer.known_by.update(await _linking_tags(session, filer))

    readers = {principal: credentials[principal] for principal in READERS}
    peer_org = await session.get(Organization, world.orgs["peer"])
    readers[PEER_ANALYST] = await _session_credentials(
        f, peer_org, world.pems["peer"], (OperatorRole.ANALYST,)
    )

    leaks: list[str] = []
    served: set[str] = set()
    for door, submission_id in filer.filings.items():
        aimed = await _aimed_at(session, world, submission_id)
        for mine in readers.values():
            bodies = await _walk(app, aimed, mine, filer.known_by, leaks)
            if any(aimed.object_stix_id in body for body in bodies):
                served.add(door)
    leaks.extend(await _notices_naming(session, filer))

    assert not leaks, "the filer of anonymous content was named:\n  " + "\n  ".join(leaks)
    # Not vacuous: each door's content reached the readers, so the bodies
    # checked above included the objects themselves, not only refusals.
    assert served == set(filer.filings), served


# ---------------------------------------------------------------------------
# The filer and its five filings
# ---------------------------------------------------------------------------
async def _anonymous_filer(f: Factories, world: World, make_operator: Any) -> Filer:
    org = await f.make_org("quietbank-kq7", name="Quietbank Kq7 Holdings")
    pem, _ = await f.make_cert(org)
    circle = await f.session.get(Circle, world.circle_id)
    await f.join_circle(org, circle, role=CircleRole.CONTRIBUTOR)
    person = await _session_credentials(f, org, pem, (OperatorRole.ANALYST,))
    await make_operator(org, email=ALICE)
    isac = await f.session.get(Organization, world.orgs["isac"])
    await record_mail_domains(f, isac, org, ALICE.rpartition("@")[2])
    people = (await f.session.scalars(select(Operator.id).where(Operator.org_id == org.id))).all()
    known_by = {
        str(org.id): "organisation id",
        org.id.hex: "organisation id (hex)",
        org.slug: "slug",
        org.name: "name",
        org.stix_identity_id: "STIX identity",
        ALICE: "a person's address",
        ALICE.rpartition("@")[2]: "its mail domain",
        **{str(person_id): "a person's id" for person_id in people},
    }
    return Filer(org_id=org.id, pem=pem, person=person, filings={}, known_by=known_by)


async def _file_through_every_door(
    app: Any, f: Factories, world: World, filer: Filer, attribution_key: Any
) -> None:
    session = f.session
    machine = proxy_headers(filer.pem)
    doors = {
        "api": lambda: _by_api(f.client, machine),
        "portal": lambda: _by_portal(app, filer),
        "one-click": lambda: _by_one_click(f.client, machine, world),
        "taxii inbox": lambda: _by_inbox(f.client, machine, world),
        "email": lambda: _by_email(session, attribution_key),
    }
    for door, file_it in doors.items():
        before = set((await session.scalars(select(Submission.id))).all())
        await file_it()
        session.expire_all()
        made = set((await session.scalars(select(Submission.id))).all()) - before
        assert len(made) == 1, f"{door}: {len(made)} submissions"
        [filer.filings[door]] = made


async def _by_api(client: AsyncClient, machine: dict[str, str]) -> None:
    # No ``distribute_anonymously``: the member's default is the point.
    bundle, _stix_id = _bundle("Quiet API filing", exportable=True)
    body = {"title": "Quiet API", "discovery_scope": "ai_system", "tlp": "amber", "bundle": bundle}
    response = await client.post(API, json=body, headers=machine)
    assert response.status_code == 201, response.text


async def _by_portal(app: Any, filer: Filer) -> None:
    bundle, _stix_id = _bundle("Quiet portal filing")
    async with _browser(app, filer.person) as http:
        response = await http.post(
            "/portal/submit",
            data={
                "title": "Quiet portal",
                "discovery_scope": "ai_system",
                "tlp": "amber",
                "bundle": json.dumps(bundle),
                "csrf_token": filer.person.csrf_token,
            },
            headers=filer.person.portal_headers,
        )
    assert response.status_code == 303, response.text
    assert _SUBMISSION_PATH.search(response.headers["location"]), response.headers


async def _by_one_click(client: AsyncClient, machine: dict[str, str], world: World) -> None:
    response = await client.post(
        "/api/v1/contributions",
        json={"target": world.public_stix_id, "kind": "seen"},
        headers=machine,
    )
    assert response.status_code == 201, response.text


async def _by_inbox(client: AsyncClient, machine: dict[str, str], world: World) -> None:
    response = await client.post(
        f"/taxii2/aivs/collections/{world.collection_id}/objects/",
        content=json.dumps({"objects": [inbox_note(world.public_stix_id)]}),
        headers={**machine, "content-type": "application/taxii+json;version=2.1"},
    )
    assert response.status_code == 202, response.text


async def _by_email(session: Any, attribution_key: Any) -> None:
    bundle, _stix_id = _bundle("Quiet emailed filing")
    raw = raw_message(
        sender=f"Alice <{ALICE}>",
        subject="Quiet email",
        attachments=(("bundle.json", json.dumps(bundle).encode()),),
    )
    assert await receive(session, attribution_key, raw) == "accepted"


async def _distribute(
    client: AsyncClient,
    world: World,
    filer: Filer,
    editor: Credentials,
    session: Any,
    submission_id: uuid.UUID,
) -> None:
    """Take a filing from wherever its door left it to distributed in the circle."""
    steps = {
        SubmissionState.DRAFT: ("submit", proxy_headers(filer.pem), {}),
        SubmissionState.SUBMITTED: ("validate", editor.api_headers, {}),
        SubmissionState.VALIDATED: (
            "distribute",
            editor.api_headers,
            {"circle_ids": [str(world.circle_id)]},
        ),
    }
    for _ in steps:
        session.expire_all()
        state = await session.scalar(select(Submission.state).where(Submission.id == submission_id))
        if state is SubmissionState.DISTRIBUTED:
            return
        verb, headers, body = steps[state]
        response = await client.post(f"{API}/{submission_id}/{verb}", json=body, headers=headers)
        assert response.status_code == 200, f"{verb}: {response.text}"
    session.expire_all()
    state = await session.scalar(select(Submission.state).where(Submission.id == submission_id))
    assert state is SubmissionState.DISTRIBUTED, state


async def _linking_tags(session: Any, filer: Filer) -> dict[str, str]:
    """The keyed values that tie the filer's submissions and objects together."""
    ids = list(filer.filings.values())
    tags = (await session.scalars(select(Submission.owner_tag).where(Submission.id.in_(ids)))).all()
    tokens = (
        await session.scalars(
            select(StixObject.owner_token).where(StixObject.submission_id.in_(ids))
        )
    ).all()
    return {
        **dict.fromkeys(tags, "a submission's owner tag"),
        **dict.fromkeys(tokens, "an object's owner token"),
    }


# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------
async def _aimed_at(session: Any, world: World, submission_id: uuid.UUID) -> World:
    """The matrix world with every identifier a route takes pointed at one filing."""
    objects = (
        await session.scalars(
            select(StixObject.stix_id).where(StixObject.submission_id == submission_id)
        )
    ).all()
    first = objects[0]
    return dataclasses.replace(
        world,
        submissions=dict.fromkeys(world.submissions, submission_id),
        object_stix_id=first,
        osv_stix_id=first,
    )


def _swept(routes: tuple[RouteCase, ...]) -> list[RouteCase]:
    # Signing out would end the reader's session for the next filing's walk;
    # it names nobody, and the matrix proves what it answers.
    return [route for route in routes if route.route_class is not RouteClass.SIGN_IN]


async def _walk(
    app: Any, world: World, mine: Credentials, known_by: dict[str, str], leaks: list[str]
) -> list[str]:
    """Call every route as one reader; record each body that names the filer."""
    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    bodies: list[str] = []
    async with AsyncClient(
        transport=transport,
        base_url="https://aivs.test",
        follow_redirects=False,
        cookies=mine.cookies,
    ) as http:
        for route in _swept(ROUTES):
            response = await _call(http, route, world, mine)
            text = _everything_said(response)
            bodies.append(text)
            leaks.extend(
                f"{route.method} {route.template} ({response.status_code}): {what}"
                for value, what in known_by.items()
                if value in text
            )
    return bodies


def _everything_said(response: Response) -> str:
    headers = "\n".join(f"{name}: {value}" for name, value in response.headers.items())
    return f"{headers}\n{response.text}"


# ---------------------------------------------------------------------------
# Notices
# ---------------------------------------------------------------------------
async def _members_take_every_notice(session: Any, world: World) -> None:
    """The peer takes a daily digest by email, so both kinds of notice are sent."""
    await session.execute(
        update(Organization)
        .where(Organization.id == world.orgs["peer"])
        .values(notification_cadence=NotificationCadence.DAILY, digest_email="soc@peer.test")
    )
    await session.commit()


async def _notices_naming(session: Any, filer: Filer) -> list[str]:
    await send_due_digests(
        session,
        now=dt.datetime.now(dt.UTC) + dt.timedelta(days=2),
        daily_hour=7,
        base_url="https://aivs.test",
        instance_name="Matrix ISAC",
        email_enabled=True,
    )
    session.expire_all()
    webhooks = (
        await session.scalars(
            select(WebhookDelivery)
            .join(Webhook, Webhook.id == WebhookDelivery.webhook_id)
            .where(Webhook.org_id != filer.org_id)
        )
    ).all()
    emails = (
        await session.scalars(select(EmailDelivery).where(EmailDelivery.org_id != filer.org_id))
    ).all()
    # Not vacuous: the member's webhook was told, and the peer's digest went.
    assert webhooks, "no webhook notice was queued for another member"
    assert emails, "no digest was queued for another member"
    said = [
        *(f"webhook {d.event}: {json.dumps(d.payload)}" for d in webhooks),
        *(f"email {e.subject}: {e.subject}\n{e.body}" for e in emails),
    ]
    return [
        f"{text.split(':', 1)[0]}: {what}"
        for text in said
        for value, what in filer.known_by.items()
        if value in text
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _browser(app: Any, person: Credentials) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app, client=("127.0.0.1", 0)),
        base_url="https://aivs.test",
        follow_redirects=False,
        cookies=person.cookies,
    )
