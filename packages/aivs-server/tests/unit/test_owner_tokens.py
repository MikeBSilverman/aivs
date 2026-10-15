"""The owner token a version is stored with names nobody (Phase P, SF-88).

``stix_objects.owner_token`` is what the read path groups versions by -- SF-48's
read-side layer -- and the column a member login will still read once it is
refused the ``attribution`` schema. So it must group one owner's versions of
one id, and do nothing else: not equal the organisation's id, and not repeat
across ids, which would let a reader gather one firm's work.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from aivs_server.db.models import StixObject
from tests.unit.contribution_world import LATER, STAMP, file

pytestmark = pytest.mark.db

API = "/api/v1/submissions"


def vulnerability_raw(stix_id: str, modified: str) -> dict:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id,
        "created": STAMP,
        "modified": modified,
        "name": "A finding",
    }


@pytest.fixture
async def world(isac, make_org, make_cert):
    _isac_org, editor = isac
    member = await make_org("token-member")
    member_pem, _ = await make_cert(member)
    peer = await make_org("token-peer")
    peer_pem, _ = await make_cert(peer)
    return {"editor": editor, "member": member, "pem": member_pem, "peer_pem": peer_pem}


async def _filed(client, pem, *raws: dict) -> str:
    filed = await file(client, pem, list(raws))
    assert filed.status_code == 201, filed.text
    return str(filed.json()["id"])


async def _token(session, submission_id: str, stix_id: str) -> str:
    token = await session.scalar(
        select(StixObject.owner_token).where(
            StixObject.submission_id == uuid.UUID(submission_id), StixObject.stix_id == stix_id
        )
    )
    assert token is not None
    return token


@pytest.mark.requirement("SF-88")
async def test_one_owners_versions_of_one_id_share_a_token_and_nothing_more(client, session, world):
    first, second = f"vulnerability--{uuid.uuid4()}", f"vulnerability--{uuid.uuid4()}"
    filing = await _filed(
        client, world["pem"], vulnerability_raw(first, STAMP), vulnerability_raw(second, STAMP)
    )
    later = await _filed(client, world["pem"], vulnerability_raw(first, LATER))
    peers = await _filed(client, world["peer_pem"], vulnerability_raw(first, LATER))

    token = await _token(session, filing, first)

    assert await _token(session, later, first) == token, "one owner, one id: one token"
    assert await _token(session, filing, second) != token, "tokens do not repeat across ids"
    assert await _token(session, peers, first) != token, "another owner of the id: another token"
    assert str(world["member"].id) not in {token, await _token(session, filing, second)}


@pytest.mark.requirement("SF-88")
async def test_the_isacs_versions_carry_the_one_isac_token(client, session, world):
    stix_id = f"vulnerability--{uuid.uuid4()}"
    filed = await client.post(
        API,
        json={
            "title": "The ISAC's record",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "objects": [vulnerability_raw(stix_id, STAMP)],
            },
        },
        headers=world["editor"],
    )
    assert filed.status_code == 201, filed.text

    assert await _token(session, str(filed.json()["id"]), stix_id) == "isac"
