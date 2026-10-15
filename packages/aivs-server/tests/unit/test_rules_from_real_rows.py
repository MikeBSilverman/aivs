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
import uuid

import pytest
from sqlalchemy import select, text

from aivs_schemas.enums import OrgType
from aivs_server import main as main_module
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog, Submission
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


#: Every column of a submission but its identity and the stamps the server sets.
_COPIED = ", ".join(
    column.name
    for column in Submission.__table__.columns
    if column.name not in {"id", "created_at", "updated_at"}
)


async def _forge_filing(member_engine, *, like: str, named: uuid.UUID) -> uuid.UUID:
    """What SQL on the member path can do: as the member login, a submission and
    its filer row in another firm's name, with no audited creation."""
    forged = uuid.uuid4()
    async with member_engine.begin() as connection:
        await connection.execute(
            text(
                f"INSERT INTO submissions (id, {_COPIED}) "  # noqa: S608 - column names from the model
                f"SELECT :forged, {_COPIED} FROM submissions WHERE id = :like"
            ),
            {"forged": forged, "like": like},
        )
        await connection.execute(
            text("INSERT INTO attribution.submitters (submission_id, org_id) VALUES (:id, :org)"),
            {"id": forged, "org": named},
        )
    return forged


@pytest.mark.requirement("SF-91")
async def test_filer_mismatch_from_a_real_filing_and_a_forged_one(
    client, session, member_engine, make_org, make_cert
):
    filer = await make_org("filing-firm", org_type=OrgType.GSIB)
    named = await make_org("named-firm", org_type=OrgType.GSIB)
    pem, _ = await make_cert(filer)

    real = await create_draft(client, pem)
    assert await _raised(session, "filer_mismatch") == [], "an audited filing is not a finding"

    forged = await _forge_filing(member_engine, like=real["id"], named=named.id)
    assert await _raised(session, "filer_mismatch") == [str(forged)]


@pytest.mark.requirement("SF-91")
async def test_the_detection_job_raises_a_tag_no_filer_matches(
    app, client, session, settings, member_engine, make_org, make_cert
):
    """Driven through the background job itself, which is what must pass the
    keyed rules: a rule only a test names is a rule production never runs."""
    filer = await make_org("tagging-firm", org_type=OrgType.GSIB)
    named = await make_org("tag-named-firm", org_type=OrgType.GSIB)
    pem, _ = await make_cert(filer)
    real = await create_draft(client, pem)
    # The forged row copies the real row's tag, which is the filer's, not the
    # named firm's: SQL cannot compute the named firm's.
    forged = await _forge_filing(member_engine, like=real["id"], named=named.id)

    await main_module._run_detections(settings)

    raised = (
        (
            await session.execute(
                select(AuditLog.details["submission"].astext).where(
                    AuditLog.action == AuditAction.DETECTION_RAISED,
                    AuditLog.resource_id == "owner_tag_mismatch",
                )
            )
        )
        .scalars()
        .all()
    )
    assert raised == [str(forged)]
