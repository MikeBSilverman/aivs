"""Only ISAC staff may acknowledge their own submission (Mike's decision).

A member acknowledging its own warning is evidence of nothing, and it would
sit in the receipts and the submitter's telemetry beside the members who
really did. An ISAC employee filing an advisory may record that the ISAC
acted on it.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from aivs_schemas.enums import AckType, AckVia, OrgType
from aivs_server.db.models import Acknowledgment
from tests.conftest import proxy_headers
from tests.unit.test_submission_workflow import create_draft

pytestmark = pytest.mark.db

ACK = "/api/v1/acknowledgments"


async def test_a_member_cannot_acknowledge_its_own_submission(client, make_org, make_cert):
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    own = (await create_draft(client, pem))["id"]

    refused = await client.post(
        ACK, json={"submission_id": own, "ack_type": "actioned"}, headers=proxy_headers(pem)
    )

    assert refused.status_code == 403


async def test_isac_staff_may_acknowledge_their_own_submission(client, isac, make_cert):
    isac_org, headers = isac
    isac_pem, _ = await make_cert(isac_org)
    own = (await create_draft(client, isac_pem))["id"]

    accepted = await client.post(
        ACK, json={"submission_id": own, "ack_type": "actioned"}, headers=headers
    )

    assert accepted.status_code == 201


async def test_a_peer_that_received_it_may_still_acknowledge(client, session, make_org, make_cert):
    submitter = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(submitter)
    peer = await make_org("atlantic-clearing", org_type=OrgType.GSIB)
    peer_pem, _ = await make_cert(peer)
    submission = (await create_draft(client, pem))["id"]
    session.add(
        Acknowledgment(
            org_id=peer.id, submission_id=submission, ack_type=AckType.RETRIEVED, via=AckVia.TAXII
        )
    )
    await session.commit()

    accepted = await client.post(
        ACK,
        json={"submission_id": submission, "ack_type": "acknowledged"},
        headers=proxy_headers(peer_pem),
    )

    assert accepted.status_code == 201
    rows = (await session.execute(select(Acknowledgment.ack_type))).scalars().all()
    assert AckType.ACKNOWLEDGED in rows
