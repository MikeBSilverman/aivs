"""A detection may propose a quarantine; the ISAC's policy decides who acts.

Under ``propose`` (the default) the archive-scrape finding is listed on the
status page and an operator confirms it with one click; under ``enforce`` it is
applied at once and recorded as the system acting on a named rule. The pair is
the policy: the same scrape, two outcomes.
"""

from __future__ import annotations

import datetime as dt
import re

import pytest
from sqlalchemy import select

from aivs_schemas.enums import OperatorRole, OrgStatus, OrgType
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog, Organization
from aivs_server.services.detections import RULES, Rule, run_detections
from tests.conftest import proxy_headers, seed_filing
from tests.unit.test_portal_admin import sign_in

pytestmark = pytest.mark.db


def _scrape_rule() -> list[Rule]:
    real = next(rule for rule in RULES if rule.name == "bulk_retrieval")
    return [Rule(real.name, real.severity, real.window, 2, real.check)]


@pytest.fixture
async def scraper(client, make_org, make_cert, make_circle, make_collection, join_circle, publish):
    """An organisation that has just paged a whole collection."""
    thief = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(thief)
    circle = await make_circle("section9")
    collection = await make_collection(circle)
    await join_circle(thief, circle)
    for index in range(3):
        await publish(thief, circle, name=f"finding {index}")
    page = await client.get(
        f"/taxii2/aivs/collections/{collection.id}/objects/", headers=proxy_headers(pem)
    )
    assert page.status_code == 200
    return thief.id


async def _status(session, org_id) -> OrgStatus:
    session.expire_all()
    return (await session.get(Organization, org_id)).status


@pytest.mark.parametrize("policy", ["propose", "enforce"])
async def test_the_policy_decides_whether_a_scrape_quarantines_at_once(session, scraper, policy):
    await run_detections(
        session, now=dt.datetime.now(dt.UTC), quarantine_policy=policy, rules=_scrape_rule()
    )

    status = await _status(session, scraper)
    quarantines = (
        (
            await session.execute(
                select(AuditLog).where(AuditLog.action == AuditAction.ORG_QUARANTINED)
            )
        )
        .scalars()
        .all()
    )
    if policy == "propose":
        assert status is OrgStatus.ACTIVE
        assert quarantines == []
    else:
        assert status is OrgStatus.QUARANTINED
        assert [(q.actor_type, q.actor_id) for q in quarantines] == [
            ("system", "detection:bulk_retrieval")
        ], "an automatic quarantine never reads as someone's decision"


async def test_enforce_never_quarantines_the_isac_itself(session, isac_org, make_org):
    """Its own retrievals can trip the rule; quarantining it would lock the ISAC out."""
    from aivs_server.db.models import Acknowledgment, Submission  # noqa: PLC0415

    member = await make_org("member", org_type=OrgType.GSIB)
    for index in range(3):
        submission = Submission(
            state="submitted",
            tlp="amber",
            discovery_scope="ai_system",
            title=f"s{index}",
        )
        await seed_filing(session, submission, member)
        await session.flush()
        session.add(
            Acknowledgment(
                org_id=isac_org.id,
                submission_id=submission.id,
                ack_type="retrieved",
                via="taxii",
            )
        )
    await session.commit()

    raised = await run_detections(
        session, now=dt.datetime.now(dt.UTC), quarantine_policy="enforce", rules=_scrape_rule()
    )

    assert [f.subject for f in raised] == [str(isac_org.id)]
    assert await _status(session, isac_org.id) is OrgStatus.ACTIVE


async def _open_status(client, isac_org, make_cert, make_operator, *roles: OperatorRole):
    pem, _ = await make_cert(isac_org)
    operator, seed = await make_operator(isac_org, roles=roles)
    await sign_in(client, operator, seed, pem)
    page = await client.get("/portal/admin/status", headers=proxy_headers(pem))
    return pem, page


async def test_a_proposal_is_listed_and_one_click_confirms_it(
    client, session, scraper, isac_org, make_cert, make_operator
):
    await run_detections(
        session, now=dt.datetime.now(dt.UTC), quarantine_policy="propose", rules=_scrape_rule()
    )
    pem, page = await _open_status(
        client, isac_org, make_cert, make_operator, OperatorRole.ISAC_MEMBERSHIP
    )
    assert 'data-proposed="meridian-global"' in page.text
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)

    confirmed = await client.post(
        f"/portal/admin/orgs/{scraper}/quarantine",
        data={"csrf_token": token, "reason": "confirming detection bulk_retrieval"},
        headers=proxy_headers(pem),
    )
    after = await client.get("/portal/admin/status", headers=proxy_headers(pem))

    assert confirmed.status_code == 303
    assert await _status(session, scraper) is OrgStatus.QUARANTINED
    assert 'data-proposed="meridian-global"' not in after.text, "resolved, so no longer proposed"


async def test_confirming_needs_the_right_to_quarantine(
    client, scraper, isac_org, make_cert, make_operator, session
):
    _pem, page = await _open_status(
        client, isac_org, make_cert, make_operator, OperatorRole.SYSTEM_ADMIN
    )
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    analyst_pem, _ = await make_cert(isac_org)
    analyst, seed = await make_operator(isac_org, roles=(OperatorRole.ISAC_ANALYST,))
    await sign_in(client, analyst, seed, analyst_pem)

    refused = await client.post(
        f"/portal/admin/orgs/{scraper}/quarantine",
        data={"csrf_token": client.cookies.get("aivs_csrf", ""), "reason": "r"},
        headers=proxy_headers(analyst_pem),
    )

    assert token
    assert refused.status_code == 403
    assert await _status(session, scraper) is OrgStatus.ACTIVE
