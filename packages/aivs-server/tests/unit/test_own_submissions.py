"""A member's list of its own filings holds its own and no other firm's (Phase P, SF-88).

The list is asked of ``services.attribution.submitted_by`` for the caller's
organisation: the member's own question, answered for the member alone. The
pair is another firm's filing, made at the same time, that must not appear.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import proxy_headers
from tests.unit.contribution_world import STAMP, file

pytestmark = pytest.mark.db

API = "/api/v1/submissions"


def _finding() -> dict:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "name": "A finding",
    }


@pytest.mark.requirement("SF-88")
async def test_a_members_list_holds_its_own_filings_and_no_other_firms(client, make_org, make_cert):
    member = await make_org("list-member")
    member_pem, _ = await make_cert(member)
    peer = await make_org("list-peer")
    peer_pem, _ = await make_cert(peer)
    own = await file(client, member_pem, [_finding()])
    other = await file(client, peer_pem, [_finding()])
    assert own.status_code == other.status_code == 201

    listed = await client.get(API, headers=proxy_headers(member_pem))

    assert listed.status_code == 200, listed.text
    assert [row["id"] for row in listed.json()] == [own.json()["id"]]
