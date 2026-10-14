"""Abuse of the reading surface: exports and lead-time statements.

Each scenario is the adversary's requests in order, asserting the step at
which the platform notices or refuses, with the detection rule it exercises.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from aivs_schemas.enums import OrgType
from aivs_server.services.detections import RULES, Rule, run_detections
from tests.conftest import proxy_headers
from tests.unit.sharing import sdo, share

pytestmark = [pytest.mark.db, pytest.mark.abuse]

API = "/api/v1"


def _rule(name: str, threshold: int) -> Rule:
    real = next(rule for rule in RULES if rule.name == name)
    return Rule(real.name, real.severity, real.window, threshold, real.check)


async def test_an_export_scraper_is_noticed_then_cut_off(
    client, session, isac, make_org, make_cert, make_circle, join_circle
):
    """Rule ``bulk_retrieval``. A stolen certificate pulls the IoC pack for every
    vulnerability rather than paging TAXII. Each pack is a retrieval with a
    receipt, so the volume gives it away exactly as a scraped feed does."""
    _isac_org, isac_headers = isac
    vendor = await make_org("export-vendor", org_type=OrgType.GSIB)
    vendor_pem, _ = await make_cert(vendor)
    victim = await make_org("export-victim", org_type=OrgType.GSIB)
    stolen_pem, _ = await make_cert(victim)
    honest = await make_org("export-honest", org_type=OrgType.GSIB)
    honest_pem, _ = await make_cert(honest)
    circle = await make_circle("export-sector")
    for org in (vendor, victim, honest):
        await join_circle(org, circle)
    vulnerabilities = [sdo("vulnerability", name=f"Finding {n}") for n in range(6)]
    for vulnerability in vulnerabilities:
        await share(client, vendor_pem, isac_headers, [vulnerability], [circle.id])

    # 1. The thief pulls every pack; an honest member pulls the one it needs.
    for vulnerability in vulnerabilities:
        pulled = await client.get(
            f"{API}/vulnerabilities/ioc-pack.csv?id={vulnerability['id']}",
            headers=proxy_headers(stolen_pem),
        )
        assert pulled.status_code == 200
    needed = await client.get(
        f"{API}/vulnerabilities/ioc-pack.csv?id={vulnerabilities[0]['id']}",
        headers=proxy_headers(honest_pem),
    )
    assert needed.status_code == 200

    # 2. The detection names the thief's organisation, and only it.
    raised = await run_detections(
        session,
        quarantine_policy="propose",
        now=dt.datetime.now(dt.UTC),
        rules=[_rule("bulk_retrieval", 5)],
    )
    assert [finding.subject for finding in raised] == [str(victim.id)]

    # 3. The ISAC quarantines; the next pack is refused.
    quarantined = await client.post(
        f"{API}/orgs/{victim.id}/quarantine",
        json={"reason": "bulk_retrieval detection on exports, certificate presumed stolen"},
        headers=isac_headers,
    )
    assert quarantined.status_code == 200
    refused = await client.get(
        f"{API}/vulnerabilities/ioc-pack.csv?id={vulnerabilities[1]['id']}",
        headers=proxy_headers(stolen_pem),
    )
    assert refused.status_code == 401


async def test_walking_organisation_ids_finds_no_other_firms_statement(
    client, isac, make_org, make_cert
):
    """No rule: there is nothing to find. A member, or the ISAC, asks for lead-time
    statements by organisation id; a real firm's answers exactly as a made-up id
    does, so the walk learns neither the figures nor which ids are members."""
    _isac_org, isac_headers = isac
    target = await make_org("statement-target", org_type=OrgType.GSIB)
    prober = await make_org("statement-prober", org_type=OrgType.GSIB)
    prober_pem, _ = await make_cert(prober)
    quarter = "2026Q4"

    for headers in (proxy_headers(prober_pem), isac_headers):
        real = await client.get(
            f"{API}/organizations/{target.id}/lead-time?quarter={quarter}", headers=headers
        )
        made_up = await client.get(
            f"{API}/organizations/{uuid.uuid4()}/lead-time?quarter={quarter}", headers=headers
        )
        assert real.status_code == made_up.status_code == 404
        assert real.content == made_up.content
