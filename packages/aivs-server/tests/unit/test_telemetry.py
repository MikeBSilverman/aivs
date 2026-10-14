"""Telemetry back to the submitter, without pointing at anyone (plan, Phase E).

Pairs: below k everything is withheld, at k the numbers appear; one to k-1
reads "fewer than k"; the ISAC and the submitter never count as reach; a member
that joined after the content was released does not either; only the submitter
can read it; a milestone is announced once, and only for a count shown
exactly; reach is only organisations that could read it, and a count only
organisations in reach.
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

#: The milestone a submitter is told of once K organisations retrieved it.
RETRIEVED_K = f"retrieved_{K_ANONYMITY}"


@pytest.fixture
async def shared(
    session, make_org, make_cert, make_circle, make_collection, join_circle, publish, isac_org
):
    """A submission distributed into a circle of ``readers`` other members."""

    async def _build(readers: int):
        circle = await make_circle("section9")
        await make_collection(circle)
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


async def _unreadable(session, circle, collection, how: str) -> None:
    if how == "circle deactivated":
        circle.is_active = False
    else:
        collection.can_read = False
    await session.commit()


@pytest.mark.parametrize("how", ["circle deactivated", "collection unreadable"])
@pytest.mark.requirement("SF-15")
async def test_reach_counts_only_organisations_that_could_read_it(
    session, shared, make_org, make_circle, make_collection, join_circle, publish, how
):
    """A firm in a circle nobody can read from must not make up the K.

    Five readers and five firms whose circle cannot be read: counted as reach
    10, the five readers all retrieving was shown as an exact 5 -- every real
    reader named. The pair: the second circle readable, the same 5 is exact.
    """
    submission, submitter, _pem, readers, _c = await shared(K_ANONYMITY)
    dark = await make_circle("dark-pool")
    dark_feed = await make_collection(dark)
    for index in range(K_ANONYMITY):
        await join_circle(await make_org(f"dark-{index}", org_type=OrgType.GSIB), dark)
    await publish(submitter, dark, submission=submission)
    for reader in readers:
        await _receipt(session, reader, submission)
    assert (await submission_telemetry(session, submission)).retrieved.value == K_ANONYMITY

    await _unreadable(session, dark, dark_feed, how)

    telemetry = await submission_telemetry(session, submission)
    assert telemetry.reach.value == K_ANONYMITY
    assert telemetry.retrieved.value is None


@pytest.mark.requirement("SF-15")
async def test_a_count_counts_only_organisations_in_reach(
    session, shared, make_org, make_circle, make_collection, join_circle, publish
):
    """A count is of the firms reach describes, or "all but" means nothing.

    Five firms retrieved through a circle that was then deactivated: they are
    no longer reach, so their receipts are not "5 of the 10 who could". The
    pair: with the circle active, they are 5 of 15.
    """
    submission, submitter, _pem, _readers, _c = await shared(2 * K_ANONYMITY)
    closed = await make_circle("closed-pool")
    await make_collection(closed)
    for index in range(K_ANONYMITY):
        org = await make_org(f"closed-{index}", org_type=OrgType.GSIB)
        await join_circle(org, closed)
        await _receipt(session, org, submission)
    await publish(submitter, closed, submission=submission)
    before = await submission_telemetry(session, submission)
    assert (before.reach.value, before.retrieved.value) == (3 * K_ANONYMITY, K_ANONYMITY)

    closed.is_active = False
    await session.commit()

    telemetry = await submission_telemetry(session, submission)
    assert telemetry.reach.value == 2 * K_ANONYMITY
    assert (telemetry.retrieved.value, telemetry.retrieved.withheld) == (None, "fewer than 5")


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


async def _sweep(session) -> list[str]:
    now = dt.datetime.now(dt.UTC)
    await queue_milestones(session, now=now, lookback=dt.timedelta(days=1))
    return await _telemetry_events(session)


@pytest.mark.parametrize(("readers", "announced"), [(2 * K_ANONYMITY, [RETRIEVED_K]), (2, [])])
@pytest.mark.requirement("SF-15")
async def test_a_milestone_is_announced_once_and_never_below_k(
    session, shared, secret_box, readers, announced
):
    submission, submitter, _pem, others, _c = await shared(readers)
    await _hook(session, secret_box, submitter)
    for reader in others[:K_ANONYMITY]:
        await _receipt(session, reader, submission)

    await _sweep(session)

    assert await _sweep(session) == announced


@pytest.mark.parametrize(("retrievers", "announced"), [(1, []), (K_ANONYMITY, [RETRIEVED_K])])
@pytest.mark.requirement("SF-15")
async def test_a_milestone_is_silent_until_its_count_is_shown(
    session, shared, secret_box, retrievers, announced
):
    """Silence must not say what the count withholds.

    A "first retrieval" milestone at reach 10 that never fired told the
    submitter the count was exactly zero, which the count itself shows only as
    "fewer than 5". So no milestone is about fewer than K. The pair: five of
    ten, a count shown exactly, is announced.
    """
    submission, submitter, _pem, others, _c = await shared(2 * K_ANONYMITY)
    await _hook(session, secret_box, submitter)
    for reader in others[:retrievers]:
        await _receipt(session, reader, submission)

    assert await _sweep(session) == announced


@pytest.mark.parametrize(
    ("readers", "retrievers", "announced"),
    [
        (K_ANONYMITY + 1, K_ANONYMITY, []),
        (2 * K_ANONYMITY, 2 * K_ANONYMITY, []),
        (3 * K_ANONYMITY, 2 * K_ANONYMITY, [RETRIEVED_K, "retrieved_10"]),
    ],
)
@pytest.mark.requirement("SF-15")
async def test_a_milestone_never_fires_for_a_count_shown_as_all_but_a_few(
    session, shared, secret_box, readers, retrievers, announced
):
    """Ten of ten retrieving is shown as "all but fewer than 5", not 10.

    "retrieved_10" firing at reach 10 said every firm had, and "retrieved_5"
    at reach 6 said all but at most one had; neither count is shown exactly,
    so neither fires. The pair: ten of fifteen is a
    count shown exactly, and both fire.
    """
    submission, submitter, _pem, others, _c = await shared(readers)
    await _hook(session, secret_box, submitter)
    for reader in others[:retrievers]:
        await _receipt(session, reader, submission)

    assert sorted(await _sweep(session)) == sorted(announced)
