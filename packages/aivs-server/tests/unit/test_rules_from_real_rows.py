"""Each detection rule, fed by rows the application writes, not hand-built ones.

The rules read audit details by key (`account`, `circles`, `resource_id`). A
rule tested only against synthetic rows goes silent the day the writer renames
the key, with every test still green (Phase A review). Here each rule runs after
the real request that produces its input, and a neighbouring request that must
not trigger it.
"""

from __future__ import annotations

import datetime as dt
import re

import pytest

from aivs_schemas.enums import OrgType
from aivs_server.services.detections import RULES, Rule, run_detections
from tests.conftest import proxy_headers
from tests.unit.test_notifications import distribute
from tests.unit.test_submission_workflow import create_draft

pytestmark = pytest.mark.db

API = "/api/v1"
REASON = {"reason": "tabletop exercise, ticket 1"}


def _rule(name: str, threshold: int | None = None) -> list[Rule]:
    real = next(rule for rule in RULES if rule.name == name)
    if threshold is None:
        return [real]
    return [Rule(real.name, real.severity, real.window, threshold, real.check)]


async def _raised(session, name: str, threshold: int | None = None) -> list[str]:
    found = await run_detections(
        session,
        quarantine_policy="propose",
        now=dt.datetime.now(dt.UTC),
        rules=_rule(name, threshold),
    )
    return [finding.subject for finding in found]


async def _fail_login(client, email: str, pem: str) -> None:
    form = await client.get("/portal/login", headers=proxy_headers(pem))
    token = re.search(r'name="csrf_token" value="([^"]+)"', form.text).group(1)
    await client.post(
        "/portal/login",
        data={
            "email": email,
            "password": "wrong-password-xx",
            "totp_code": "000000",
            "csrf_token": token,
        },
        headers=proxy_headers(pem),
    )


async def test_login_failure_burst_from_real_failed_logins(
    client, session, make_org, make_cert, make_operator
):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    target, _seed = await make_operator(org)
    other, _seed = await make_operator(org)
    for _ in range(3):
        await _fail_login(client, target.email, pem)
    await _fail_login(client, other.email, pem)

    raised = await _raised(session, "login_failure_burst", threshold=3)

    assert len(raised) == 1, "one account guessed at, not the one mistyped once"


async def test_reveal_pause_and_quarantine_each_raise_from_the_real_action(
    client, session, isac, make_org, make_cert
):
    _isac_org, headers = isac
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    created = await create_draft(client, pem, distribute_anonymously=True)

    before = {
        name: await _raised(session, name)
        for name in ("anonymity_reveal", "distribution_paused", "org_quarantined")
    }
    await client.post(f"{API}/submissions/{created['id']}/reveal", json=REASON, headers=headers)
    await client.post(f"{API}/instance/distribution/pause", json=REASON, headers=headers)
    await client.post(f"{API}/orgs/{member.id}/quarantine", json=REASON, headers=headers)
    after = {name: await _raised(session, name) for name in before}

    assert before == {name: [] for name in before}
    assert all(len(subjects) == 1 for subjects in after.values()), after


async def test_first_distribution_to_a_circle_from_a_real_distribution(
    client, session, isac, make_org, make_cert, make_circle, make_collection, join_circle
):
    _isac_org, headers = isac
    circle = await make_circle("section9")
    await make_collection(circle)
    submitter = await make_org("submitting-firm", org_type=OrgType.GSIB)
    pem, _ = await make_cert(submitter)
    await join_circle(submitter, circle)

    await distribute(client, headers, pem, circle)
    first = await _raised(session, "first_distribution_to_circle")
    await distribute(client, headers, pem, circle)
    second = await _raised(session, "first_distribution_to_circle")

    assert [subject.rsplit(":", 1)[1] for subject in first] == [str(circle.id)]
    assert second == [], "the same operator to the same circle again is routine"
