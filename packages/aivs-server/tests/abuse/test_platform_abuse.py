"""Abuse of the platform itself, as the sequence an adversary would run.

The authorization matrix proves role x route; it cannot prove sequences. Each
scenario here is written as the adversary's requests in order and asserts the
step at which the platform notices or refuses (plan, exit criterion 2). Each
names the detection rule it exercises, so a rule and the abuse it exists to
catch are tested together.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from aivs_schemas.enums import OrgType
from aivs_server.services.detections import RULES, Rule, run_detections
from tests.conftest import TEST_PROXY_SECRET, proxy_headers

pytestmark = [pytest.mark.db, pytest.mark.abuse]

API = "/api/v1"


def _rule(name: str, threshold: int) -> Rule:
    real = next(rule for rule in RULES if rule.name == name)
    return Rule(real.name, real.severity, real.window, threshold, real.check)


def _from(address: str, headers: dict[str, str]) -> dict[str, str]:
    """Headers as nginx sends them for a client at ``address``."""
    return {**headers, "x-real-ip": address}


async def test_a_stolen_certificate_paging_the_archive_is_noticed_then_cut_off(
    client, session, make_org, make_cert, make_circle, make_collection, join_circle, publish, isac
):
    """Rule ``bulk_retrieval``. The thief holds a genuine certificate, so every
    request is authorised; what gives it away is the volume, and what stops it
    is quarantine."""
    victim = await make_org("meridian-global", org_type=OrgType.GSIB)
    stolen_pem, _ = await make_cert(victim)
    honest = await make_org("atlantic-clearing", org_type=OrgType.GSIB)
    honest_pem, _ = await make_cert(honest)
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    for org in (victim, honest):
        await join_circle(org, circle)
    for index in range(6):
        await publish(honest, circle, name=f"finding {index}")
    objects = f"/taxii2/aivs/collections/{collection.id}/objects/"

    # 1. The thief pages the whole archive; an honest member reads one page of two.
    scraped = await client.get(objects, headers=proxy_headers(stolen_pem))
    sampled = await client.get(f"{objects}?limit=2", headers=proxy_headers(honest_pem))
    assert scraped.status_code == sampled.status_code == 200
    assert len(scraped.json()["objects"]) == 6

    # 2. The detection names the thief's organisation, and only it.
    raised = await run_detections(
        session, now=dt.datetime.now(dt.UTC), rules=[_rule("bulk_retrieval", 5)]
    )
    assert [finding.subject for finding in raised] == [str(victim.id)]

    # 3. The ISAC quarantines; the next page is refused.
    _isac_org, isac_headers = isac
    quarantined = await client.post(
        f"{API}/orgs/{victim.id}/quarantine",
        json={"reason": "bulk_retrieval detection, certificate presumed stolen"},
        headers=isac_headers,
    )
    assert quarantined.status_code == 200
    assert (await client.get(objects, headers=proxy_headers(stolen_pem))).status_code == 401


async def test_a_probe_burst_is_attributed_to_the_prober_not_to_the_proxy(
    client, session, make_org, make_cert, ca
):
    """Rule ``auth_failure_burst``. Every request reaches the application from
    nginx, so a rule keyed on the TCP peer counts every member's failures as one
    'address' and names the proxy. It must name the client nginx saw."""
    unregistered_pem, _fp, _cert = ca.issue("not-enrolled")
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    member_pem, _ = await make_cert(member)

    # 1. A prober cycles requests with a certificate nobody registered.
    for _ in range(4):
        refused = await client.get(
            f"{API}/whoami", headers=_from("198.51.100.66", proxy_headers(unregistered_pem))
        )
        assert refused.status_code == 401
    # A member with a lapsed collector fails twice from its own address.
    for _ in range(2):
        await client.get(
            f"{API}/whoami", headers=_from("203.0.113.20", proxy_headers(unregistered_pem))
        )
    assert (
        await client.get(f"{API}/whoami", headers=_from("203.0.113.20", proxy_headers(member_pem)))
    ).status_code == 200

    # 2. The detection names the prober's address, and not the member's.
    raised = await run_detections(
        session, now=dt.datetime.now(dt.UTC), rules=[_rule("auth_failure_burst", 4)]
    )
    assert [finding.subject for finding in raised] == ["198.51.100.66"]


async def test_a_forged_client_address_is_not_believed(client, session, ca):
    """The forwarded address is a fact only when the proxy vouches for it. A
    caller that cannot present the proxy secret could set any address, so its
    failures are recorded against the address actually talking to us."""
    pem, _fp, _cert = ca.issue("not-enrolled")
    forged = proxy_headers(pem, proxy_secret="not-" + TEST_PROXY_SECRET)

    for _ in range(3):
        await client.get(f"{API}/whoami", headers=_from("192.0.2.1", forged))

    raised = await run_detections(
        session, now=dt.datetime.now(dt.UTC), rules=[_rule("auth_failure_burst", 3)]
    )
    assert [finding.subject for finding in raised] != ["192.0.2.1"]
    assert len(raised) == 1, "still noticed, against the real peer"


async def test_walking_submission_ids_is_noticed_without_becoming_an_oracle(
    client, session, make_org, make_cert
):
    """Rule ``not_found_burst``. Each probe gets the same 404 an absent id
    gets, so the walker learns nothing; the ISAC learns who is walking."""
    walker = await make_org("meridian-global", org_type=OrgType.GSIB)
    walker_id = walker.id
    pem, _ = await make_cert(walker)

    responses = [
        await client.get(f"{API}/submissions/{uuid.uuid4()}", headers=proxy_headers(pem))
        for _ in range(5)
    ]

    assert {r.status_code for r in responses} == {404}
    assert len({r.text for r in responses}) == 1, "every miss reads the same"
    raised = await run_detections(
        session, now=dt.datetime.now(dt.UTC), rules=[_rule("not_found_burst", 5)]
    )
    assert [finding.subject for finding in raised] == [str(walker_id)]
