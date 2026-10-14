"""Abuse of the auditor's read and the member's evidence pack, as an adversary would run it.

Phase H adds two surfaces that read records rather than content: an auditor's
stream of the audit trail and receipts, and a member's evidence pack. Each is
worth taking with a stolen credential -- the receipts stream says which firms
attend to which threats; a firm's packs are its response history -- so each
scenario asserts the step that refuses it, or the rule that notices it, and
that what the ISAC is told names an actor or a firm, never a record.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import json

import pytest

from aivs_schemas.enums import OperatorRole
from aivs_server.audit.log import AuditAction, record
from aivs_server.services.detections import RULES, run_detections
from tests.conftest import proxy_headers
from tests.unit.test_vulnerability_page import build_case

pytestmark = [pytest.mark.db, pytest.mark.abuse]

#: Low enough that a scenario reaches it in a few requests; the shipped
#: thresholds are in RULES and in runbook section 9.1.
_SMALL = 3


def _rule(name: str, threshold: int = _SMALL):
    return dataclasses.replace(
        next(rule for rule in RULES if rule.name == name), threshold=threshold
    )


async def _detect(session, rule):
    return await run_detections(
        session, quarantine_policy="propose", now=dt.datetime.now(dt.UTC), rules=[rule]
    )


@pytest.fixture
async def case(
    client,
    session,
    settings,
    isac_org,
    make_org,
    make_cert,
    make_operator,
    make_circle,
    join_circle,
):
    """The vulnerability page's world: a vulnerability, its fixes, and a reader."""
    return await build_case(
        client,
        session,
        settings,
        isac_org,
        make_org=make_org,
        make_cert=make_cert,
        make_operator=make_operator,
        make_circle=make_circle,
        join_circle=join_circle,
    )


@pytest.fixture
async def auditor(isac_org, make_cert, make_operator, human_headers):
    pem, _ = await make_cert(isac_org)
    operator, _ = await make_operator(
        isac_org,
        roles=(OperatorRole.AUDITOR,),
        role_expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=30),
    )
    return operator, await human_headers(operator, pem)


@pytest.mark.requirement("SF-78")
async def test_a_stolen_auditor_session_exploring_content_routes_is_refused_and_noticed(
    client, session, auditor
):
    """Every route but the audit read refuses it at the door; repeating that is
    the rule ``auditor_outside_audit``, which names the operator and no route."""
    operator, headers = auditor
    rule = _rule("auditor_outside_audit")
    tried = ["/api/v1/submissions", "/api/v1/circles", "/taxii2/", "/api/v1/orgs"]

    refusals = [(await client.get(path, headers=headers)).status_code for path in tried[:2]]
    quiet = await _detect(session, rule)
    refusals += [(await client.get(path, headers=headers)).status_code for path in tried[2:]]
    raised = await _detect(session, rule)

    assert refusals == [403, 403, 403, 403]
    assert quiet == []
    assert [(f.rule, f.subject) for f in raised] == [("auditor_outside_audit", str(operator.id))]
    assert "/api/v1" not in json.dumps([dataclasses.asdict(f) for f in raised], default=str)


@pytest.mark.requirement("SF-78")
async def test_a_stolen_auditor_session_pulling_the_trail_is_noticed(client, session, auditor):
    """The read is authorised; its volume is what gives it away (``auditor_bulk_read``).

    Counted in events served. The stream serves only below the cluster's
    oldest running transaction, so the scenario reads until enough have
    actually been served rather than assuming a page is full.
    """
    operator, headers = auditor
    rule = _rule("auditor_bulk_read", threshold=4)
    for n in range(6):
        await record(
            session, action=AuditAction.ACK_RECORDED, actor_type="system", details={"n": n}
        )
    await session.commit()
    quiet = await _detect(session, rule)

    served, cursor = 0, None
    deadline = asyncio.get_running_loop().time() + 60
    while served < rule.threshold and asyncio.get_running_loop().time() < deadline:
        params = {"limit": 1000, **({"cursor": cursor} if cursor else {})}
        page = (await client.get("/api/v1/audit/events", params=params, headers=headers)).json()
        served += len(page["events"])
        cursor = page["cursor"]
        await asyncio.sleep(0.2)
    raised = await _detect(session, rule)

    assert quiet == []
    assert [(f.rule, f.subject) for f in raised] == [("auditor_bulk_read", str(operator.id))]


@pytest.mark.requirement("SF-78")
async def test_an_auditor_whose_engagement_ended_cannot_keep_polling(
    client, session, isac_org, make_cert, make_operator, human_headers
):
    """The SIEM's credential outlives the engagement unless the end is enforced
    on every request: polling works, the end passes, the next poll is refused."""
    pem, _ = await make_cert(isac_org)
    operator, _ = await make_operator(
        isac_org,
        roles=(OperatorRole.AUDITOR,),
        role_expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=1),
    )
    headers = await human_headers(operator, pem)
    before = await client.get("/api/v1/audit/events", headers=headers)
    operator.role_expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
    await session.commit()
    after = await client.get("/api/v1/audit/events", headers=headers)
    assert (before.status_code, after.status_code) == (200, 401)


@pytest.mark.requirement("SF-79")
async def test_a_stolen_member_credential_harvesting_evidence_packs_is_noticed(
    client, session, case
):
    """Each pack is the firm's own and is served; drawing many is the rule
    ``evidence_pack_burst``, which names the firm and no vulnerability."""
    reader = case["reader"]
    api = {**reader.headers, "authorization": f"Bearer {next(iter(reader.cookies.values()))}"}
    rule = _rule("evidence_pack_burst")
    params = {"vulnerability": case["stix_id"]}

    drawn = [(await client.get("/api/v1/evidence-pack", params=params, headers=api)).status_code]
    quiet = await _detect(session, rule)
    drawn += [
        (await client.get("/api/v1/evidence-pack", params=params, headers=api)).status_code
        for _ in range(_SMALL)
    ]
    raised = await _detect(session, rule)

    assert set(drawn) == {200}
    assert quiet == []
    assert [(f.rule, f.subject) for f in raised] == [
        ("evidence_pack_burst", str(case["reader_org"].id))
    ]
    assert case["stix_id"] not in json.dumps([dataclasses.asdict(f) for f in raised], default=str)


async def test_a_machine_certificate_alone_cannot_read_the_trail(client, isac_org, make_cert):
    """The pair to the auditor's read: the ISAC's own certificate, with no
    auditor behind it, is refused the stream like any other non-auditor."""
    pem, _ = await make_cert(isac_org)
    refused = await client.get("/api/v1/audit/events", headers=proxy_headers(pem))
    assert refused.status_code == 403
