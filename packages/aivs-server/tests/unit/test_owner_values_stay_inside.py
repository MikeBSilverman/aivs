"""Owner tags and owner tokens never leave the server (Phase P, SF-90).

That is what lets a rekey recompute every one of them from the mapping without
the key it replaces (runbook section 7.4a): nothing outside the database holds
an old value that would stop matching. It is also what keeps them from being
an identifier a member could correlate.

So a member contributes through the real API, and then every surface that
shows that contribution -- the member's own API reads, the TAXII objects,
manifest and versions a reader polls, the portal pages that show provenance,
and a page of the auditor stream -- is read, and no tag or token may appear in
any body. ``audit_log`` is checked too: it is append-only, so a value written
there would outlive a rekey as a stale copy.
"""

from __future__ import annotations

import asyncio
import datetime as dt

import pytest
from sqlalchemy import select, text

from aivs_schemas.enums import OperatorRole
from aivs_server.db import models
from aivs_server.services.attribution import ISAC_OWNER
from tests.conftest import proxy_headers
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world, one_click
from tests.unit.test_portal import make_operator as portal_make_operator
from tests.unit.test_portal import sign_in

# The auditor stream serves only below the cluster-wide transaction horizon
# (_auditor_page), which parallel workers hold back: run serially.
pytestmark = [pytest.mark.db, pytest.mark.horizon]

EVENTS = "/api/v1/audit/events"


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


async def _owner_values(session) -> set[str]:
    """Every tag and member token in the database, and the HMAC part of each."""
    tags = (await session.scalars(select(models.Submission.owner_tag))).all()
    tokens = (
        await session.scalars(
            select(models.StixObject.owner_token).where(models.StixObject.owner_token != ISAC_OWNER)
        )
    ).all()
    values = {*tags, *tokens}
    return values | {value.rsplit(".", 1)[-1] for value in values}


async def _taxii_bodies(client, world: SharingWorld, stix_id: str) -> list[str]:
    root = f"/taxii2/aivs/collections/{world.collection.id}"
    headers = proxy_headers(world.reader.pem)
    bodies = []
    for path in (
        f"{root}/objects/",
        f"{root}/manifest/",
        f"{root}/objects/{stix_id}/",
        f"{root}/objects/{stix_id}/versions/",
    ):
        response = await client.get(path, headers=headers)
        assert response.status_code == 200, (path, response.text)
        bodies.append(response.text)
    assert stix_id in bodies[0], "the contribution reached the reader's feed"
    return bodies


async def _auditor_page(
    client, world, submission_id: str, make_operator, human_headers, make_cert
) -> str:
    """One page of the ISAC auditor's stream, once it serves this test's contribution.

    The stream serves only below the cluster's oldest open transaction, so it
    is polled (CLAUDE.md section 3), bounded, and fails rather than passing on
    a page that never reached the contribution.
    """
    auditor, _ = await make_operator(
        world.isac_org,
        roles=(OperatorRole.AUDITOR,),
        role_expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=30),
    )
    pem, _ = await make_cert(world.isac_org)
    headers = await human_headers(auditor, pem)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 60
    while True:
        page = await client.get(EVENTS, params={"limit": 500}, headers=headers)
        assert page.status_code == 200, page.text
        if submission_id in page.text:
            return page.text
        if loop.time() > deadline:
            pytest.fail("the auditor stream never served the contribution")
        await asyncio.sleep(0.5)


@pytest.mark.requirement("SF-90")
async def test_no_tag_or_token_reaches_any_reader(
    client, session, secret_box, world, make_operator, human_headers, make_cert
):
    clicked = await one_click(client, world.member.person, world.published)
    assert clicked.status_code == 201, clicked.text
    submission_id = clicked.json()["submission_id"]
    stix_id = await session.scalar(
        select(models.StixObject.stix_id).where(models.StixObject.submission_id == submission_id)
    )
    values = await _owner_values(session)
    assert any(value.startswith("1.") for value in values), "test setup: values exist"

    bodies = [
        (await client.get(f"{API}/submissions", headers=world.member.person)).text,
        (await client.get(f"{API}/submissions/{submission_id}", headers=world.member.person)).text,
        *await _taxii_bodies(client, world, stix_id),
    ]
    editor, secret = await portal_make_operator(
        session,
        secret_box,
        world.isac_org,
        roles=(OperatorRole.ISAC_EDITOR,),
        email="provenance@isac.test",
    )
    isac_pem, _ = await make_cert(world.isac_org)
    await sign_in(client, editor, secret, isac_pem)
    for path in (
        f"/portal/submissions/{submission_id}",
        f"/portal/vulnerabilities?id={world.published}",
    ):
        page = await client.get(path, headers=proxy_headers(isac_pem))
        assert page.status_code == 200, (path, page.text)
        bodies.append(page.text)
    bodies.append(
        await _auditor_page(client, world, submission_id, make_operator, human_headers, make_cert)
    )

    leaked = sorted(value for value in values for body in bodies if value in body)
    assert leaked == []


@pytest.mark.requirement("SF-90")
async def test_no_audit_row_records_a_tag_or_token(client, session, world):
    clicked = await one_click(client, world.member.person, world.published)
    assert clicked.status_code == 201, clicked.text
    values = await _owner_values(session)
    rows = (await session.execute(text("SELECT details::text FROM audit_log"))).scalars().all()
    assert rows, "test setup: the contribution was audited"

    leaked = sorted(value for value in values for row in rows if value in row)
    assert leaked == []
