"""Telemetry back to the submitter, without pointing at anyone (plan, Phase E).

Pairs: below k everything is withheld, at k the numbers appear; one to k-1
reads "fewer than k"; the ISAC and the submitter never count as reach; a member
that joined after the content was released does not either; only the submitter
can read it; a milestone is announced once, and never below k.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import AckType, AckVia, OrgStatus, OrgType
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db.models import Acknowledgment, Webhook, WebhookDelivery
from aivs_server.services.telemetry import (
    EVENT_SUBMISSION_TELEMETRY,
    K_ANONYMITY,
    queue_milestones,
    submission_telemetry,
)
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db


@pytest.fixture
async def shared(session, make_org, make_cert, make_circle, join_circle, publish, isac_org):
    """A submission distributed into a circle of ``readers`` other members."""

    async def _build(readers: int):
        circle = await make_circle("section9")
        submitter = await make_org("submitter", org_type=OrgType.GSIB)
        pem, _ = await make_cert(submitter)
        await join_circle(submitter, circle)
        await join_circle(isac_org, circle)
        others = []
        for index in range(readers):
            org = await make_org(f"reader-{index}", org_type=OrgType.GSIB)
            await join_circle(org, circle)
            others.append(org)
        submission, _obj, _dist = await publish(submitter, circle)
        return submission, submitter, pem, others, circle

    return _build


async def _receipt(session, org, submission, ack_type=AckType.RETRIEVED):
    session.add(
        Acknowledgment(
            org_id=org.id, submission_id=submission.id, ack_type=ack_type, via=AckVia.TAXII
        )
    )
    await session.commit()


@pytest.mark.requirement("SF-15")
async def test_below_k_every_number_is_withheld(session, shared):
    submission, _s, _pem, readers, _c = await shared(K_ANONYMITY - 1)
    await _receipt(session, readers[0], submission)

    telemetry = await submission_telemetry(session, submission)

    assert telemetry.reach.value is None
    assert telemetry.retrieved.value is None
    assert "at least 5" in telemetry.retrieved.withheld


@pytest.mark.requirement("SF-15")
async def test_a_count_is_exact_only_when_k_did_and_k_did_not(session, shared):
    """Complementary suppression: from both sides of the count, at least K.

    Reach 10: five acknowledged and five did not, so 5 is exact. Two retrieved
    (too few did), and nobody acted -- an exact zero would state every firm's
    action to a submitter that knows the roster.
    """
    submission, submitter, _pem, readers, _c = await shared(2 * K_ANONYMITY)
    for reader in readers[:2]:
        await _receipt(session, reader, submission)
    for reader in readers[:K_ANONYMITY]:
        await _receipt(session, reader, submission, AckType.ACKNOWLEDGED)
    # The submitter's own action is not engagement with what it shared.
    await _receipt(session, submitter, submission, AckType.ACTIONED)

    telemetry = await submission_telemetry(session, submission)

    assert telemetry.reach.value == 2 * K_ANONYMITY, "the ISAC and the submitter are not reach"
    assert telemetry.acknowledged.value == K_ANONYMITY
    assert (telemetry.retrieved.value, telemetry.retrieved.withheld) == (None, "fewer than 5")
    assert (telemetry.actioned.value, telemetry.actioned.withheld) == (None, "fewer than 5")
    assert telemetry.later, "counters not yet computed are named, not shown as zero"


@pytest.mark.requirement("SF-15")
async def test_reach_minus_a_count_is_never_below_k(session, shared):
    """Reach 6 with 5 acknowledging would name the one firm that did not."""
    submission, _s, _pem, readers, _c = await shared(K_ANONYMITY + 1)
    for reader in readers[:K_ANONYMITY]:
        await _receipt(session, reader, submission, AckType.ACKNOWLEDGED)

    telemetry = await submission_telemetry(session, submission)

    assert telemetry.reach.value == K_ANONYMITY + 1
    assert telemetry.acknowledged.value is None
    assert telemetry.acknowledged.withheld == "all but fewer than 5"


@pytest.mark.requirement("SF-15")
async def test_an_organisation_that_cannot_read_is_not_reach(session, shared):
    """A suspended firm could not see it, so it must not make up the K.

    The pair: the same circle with every reader active reaches K.
    """
    submission, _s, _pem, readers, _c = await shared(K_ANONYMITY)
    assert (await submission_telemetry(session, submission)).reach.value == K_ANONYMITY

    readers[0].status = OrgStatus.SUSPENDED
    await session.commit()

    telemetry = await submission_telemetry(session, submission)
    assert telemetry.reach.value is None


async def test_a_member_that_joined_after_release_is_not_reach(
    session, shared, make_org, join_circle
):
    submission, _s, _pem, _readers, circle = await shared(K_ANONYMITY)
    latecomer = await make_org("latecomer", org_type=OrgType.GSIB)
    # Explicitly now: the fixture's default backdates every membership.
    await join_circle(latecomer, circle, joined_at=dt.datetime.now(dt.UTC))

    telemetry = await submission_telemetry(session, submission)

    assert telemetry.reach.value == K_ANONYMITY


@pytest.mark.requirement("SF-15")
async def test_only_the_submitter_may_read_it(client, shared, isac, make_cert):
    submission, _s, pem, readers, _c = await shared(K_ANONYMITY)
    peer_pem, _ = await make_cert(readers[0])
    _isac_org, isac_headers = isac
    path = f"/api/v1/submissions/{submission.id}/telemetry"

    own = await client.get(path, headers=proxy_headers(pem))
    peer = await client.get(path, headers=proxy_headers(peer_pem))
    by_isac = await client.get(path, headers=isac_headers)

    assert own.status_code == 200
    assert own.json()["reach"]["value"] == K_ANONYMITY
    assert peer.status_code == by_isac.status_code == 404


async def _hook(session, secret_box, org) -> uuid.UUID:
    hook_id = uuid.uuid4()
    session.add(
        Webhook(
            id=hook_id,
            org_id=org.id,
            url="https://submitter.example/hook",
            hmac_secret_encrypted=secret_box.seal(
                "s" * 32, purpose=SecretPurpose.WEBHOOK_HMAC, subject=hook_id
            ),
            events=[],
        )
    )
    await session.commit()
    return hook_id


async def _telemetry_events(session) -> list[str]:
    rows = await session.execute(
        select(WebhookDelivery.payload).where(WebhookDelivery.event == EVENT_SUBMISSION_TELEMETRY)
    )
    return [payload["milestone"] for payload in rows.scalars()]


@pytest.mark.parametrize(("readers", "announced"), [(K_ANONYMITY, ["first_retrieval"]), (2, [])])
@pytest.mark.requirement("SF-15")
async def test_a_milestone_is_announced_once_and_never_below_k(
    session, shared, secret_box, readers, announced
):
    submission, submitter, _pem, others, _c = await shared(readers)
    await _hook(session, secret_box, submitter)
    await _receipt(session, others[0], submission)
    now = dt.datetime.now(dt.UTC)

    await queue_milestones(session, now=now, lookback=dt.timedelta(days=1))
    await queue_milestones(session, now=now, lookback=dt.timedelta(days=1))

    assert await _telemetry_events(session) == announced
