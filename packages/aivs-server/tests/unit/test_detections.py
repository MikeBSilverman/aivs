"""The platform notices abuse of itself, and nothing fails silently (exit criteria 4, 5).

Every rule is tested as a pair: a subject over the threshold raises, a neighbour
just under it does not. Thresholds are lowered by building the same rule with
its real check function, so the logic tested is the logic that runs.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import TLP, AckType, AckVia, DiscoveryScope, OrgType, SubmissionState
from aivs_server.audit.log import AuditAction
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db.models import Acknowledgment, AuditLog, Submission, Webhook, WebhookDelivery
from aivs_server.observability import HEARTBEATS, Heartbeats, render_metrics
from aivs_server.services.detections import RULES, Rule, run_detections

pytestmark = pytest.mark.db

NOW = dt.datetime(2026, 10, 13, 12, 0, tzinfo=dt.UTC)


def _rule(name: str, threshold: int) -> Rule:
    real = next(rule for rule in RULES if rule.name == name)
    return Rule(real.name, real.severity, real.window, threshold, real.check)


def _audit(action: str, *, at: dt.datetime = NOW, **fields: object) -> AuditLog:
    return AuditLog(actor_type="anonymous", action=action, at=at, outcome="failure", **fields)


@pytest.fixture(autouse=True)
def _fresh_heartbeats():
    HEARTBEATS.clear()
    yield
    HEARTBEATS.clear()


@pytest.mark.requirement("NFR-S12")
async def test_an_address_over_the_threshold_raises_and_one_under_does_not(session):
    session.add_all(
        [_audit(AuditAction.AUTH_FAILURE, source_ip="203.0.113.9") for _ in range(3)]
        + [_audit(AuditAction.AUTH_FAILURE, source_ip="203.0.113.10") for _ in range(2)]
    )
    await session.commit()

    raised = await run_detections(
        session, quarantine_policy="propose", now=NOW, rules=[_rule("auth_failure_burst", 3)]
    )

    assert [(f.rule, f.subject, f.count) for f in raised] == [
        ("auth_failure_burst", "203.0.113.9", 3)
    ]


@pytest.mark.requirement("NFR-S12")
async def test_repeated_login_failures_against_one_account_raise(session):
    session.add_all(
        [_audit(AuditAction.LOGIN_FAILURE, details={"account": "acct-a"}) for _ in range(3)]
        + [_audit(AuditAction.LOGIN_FAILURE, details={"account": "acct-b"}) for _ in range(2)]
    )
    await session.commit()

    raised = await run_detections(
        session, quarantine_policy="propose", now=NOW, rules=[_rule("login_failure_burst", 3)]
    )

    assert [f.subject for f in raised] == ["acct-a"]


@pytest.mark.requirement("NFR-S12")
async def test_one_organisation_retrieving_far_more_than_members_do_raises(session, make_org):
    scraper = await make_org("scraper", org_type=OrgType.GSIB)
    normal = await make_org("normal", org_type=OrgType.GSIB)
    submissions = [
        Submission(
            submitter_org_id=normal.id,
            state=SubmissionState.DISTRIBUTED,
            distributed_at=NOW - dt.timedelta(hours=1),
            tlp=TLP.AMBER,
            discovery_scope=DiscoveryScope.AI_SYSTEM,
            title=f"finding {i}",
        )
        for i in range(3)
    ]
    session.add_all(submissions)
    await session.flush()

    def receipt(org_id: uuid.UUID, submission: Submission) -> Acknowledgment:
        return Acknowledgment(
            org_id=org_id,
            submission_id=submission.id,
            ack_type=AckType.RETRIEVED,
            via=AckVia.TAXII,
            created_at=NOW - dt.timedelta(minutes=5),
        )

    session.add_all([receipt(scraper.id, s) for s in submissions])
    session.add_all([receipt(normal.id, s) for s in submissions[:2]])
    await session.commit()

    raised = await run_detections(
        session, quarantine_policy="propose", now=NOW, rules=[_rule("bulk_retrieval", 3)]
    )

    assert [f.subject for f in raised] == [str(scraper.id)]


@pytest.mark.requirement("NFR-S12")
async def test_every_reveal_raises_and_old_ones_do_not(session):
    session.add_all(
        [
            _audit(AuditAction.ANONYMITY_REVEALED, resource_id="sub-recent"),
            _audit(
                AuditAction.ANONYMITY_REVEALED,
                resource_id="sub-old",
                at=NOW - dt.timedelta(days=2),
            ),
        ]
    )
    await session.commit()

    raised = await run_detections(
        session, quarantine_policy="propose", now=NOW, rules=[_rule("anonymity_reveal", 1)]
    )

    assert [f.details["resource"] for f in raised] == ["sub-recent"]


@pytest.mark.requirement("NFR-S12")
@pytest.mark.requirement("NFR-O5")
async def test_a_degraded_component_raises_and_a_healthy_one_does_not(session):
    HEARTBEATS.register("stalled", dt.timedelta(seconds=30), now=NOW - dt.timedelta(minutes=10))
    HEARTBEATS.register("healthy", dt.timedelta(seconds=30), now=NOW - dt.timedelta(minutes=10))
    HEARTBEATS.success("healthy", now=NOW - dt.timedelta(seconds=10))

    raised = await run_detections(
        session, quarantine_policy="propose", now=NOW, rules=[_rule("component_degraded", 1)]
    )

    assert [f.subject for f in raised] == ["stalled"]


@pytest.mark.requirement("NFR-S12")
async def test_a_finding_raises_once_per_window_and_again_after_it(session):
    """An alert that repeats every minute for the length of its window is one
    people learn to ignore."""
    session.add_all([_audit(AuditAction.AUTH_FAILURE, source_ip="198.51.100.1") for _ in range(3)])
    await session.commit()
    rule = _rule("auth_failure_burst", 3)

    first = await run_detections(session, quarantine_policy="propose", now=NOW, rules=[rule])
    again = await run_detections(
        session, quarantine_policy="propose", now=NOW + dt.timedelta(minutes=1), rules=[rule]
    )
    session.add_all(
        [
            _audit(AuditAction.AUTH_FAILURE, source_ip="198.51.100.1", at=NOW + rule.window)
            for _ in range(3)
        ]
    )
    await session.commit()
    later = await run_detections(
        session,
        quarantine_policy="propose",
        now=NOW + rule.window + dt.timedelta(minutes=1),
        rules=[rule],
    )

    assert len(first) == 1
    assert again == []
    assert len(later) == 1


@pytest.mark.requirement("NFR-S12")
async def test_a_finding_is_audited_logged_as_ocsf_and_cef_and_sent_to_the_isac_only(
    session, make_org, secret_box, caplog
):
    """Three consumers, none of them given content: the audit trail, a SIEM or
    MSP reading forwarded logs, and the ISAC's own webhook -- never a member's."""
    isac = await make_org("hosting-isac", org_type=OrgType.ADMIN)
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    hooks = {}
    for org in (isac, member):
        hook_id = uuid.uuid4()
        hooks[org.slug] = hook_id
        session.add(
            Webhook(
                id=hook_id,
                org_id=org.id,
                url=f"https://{org.slug}.example/hook",
                hmac_secret_encrypted=secret_box.seal(
                    "s" * 32,
                    purpose=SecretPurpose.WEBHOOK_HMAC,
                    subject=hook_id,
                ),
                events=[],
            )
        )
    session.add_all([_audit(AuditAction.AUTH_FAILURE, source_ip="192.0.2.7") for _ in range(3)])
    await session.commit()

    with caplog.at_level(logging.WARNING, logger="aivs_server.security"):
        await run_detections(
            session, quarantine_policy="propose", now=NOW, rules=[_rule("auth_failure_burst", 3)]
        )

    audit = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "detection.raised")))
        .scalars()
        .all()
    )
    assert [row.details["rule"] for row in audit] == ["auth_failure_burst"]

    [line] = [r for r in caplog.records if r.name == "aivs_server.security"]
    assert line.ocsf["class_uid"] == 2004
    assert line.cef.startswith("CEF:0|AIVS|AIVS|1|auth_failure_burst|")

    deliveries = (await session.execute(select(WebhookDelivery))).scalars().all()
    assert {d.webhook_id for d in deliveries} == {hooks["hosting-isac"]}


# ---------------------------------------------------------------------------
# Health reporting
# ---------------------------------------------------------------------------
@pytest.mark.requirement("NFR-O3")
def test_component_states_starting_ok_and_degraded():
    beats = Heartbeats()
    interval = dt.timedelta(seconds=30)
    beats.register("new", interval, now=NOW)
    beats.register("running", interval, now=NOW - dt.timedelta(minutes=5))
    beats.success("running", now=NOW - dt.timedelta(seconds=20))
    beats.register("failing", interval, now=NOW - dt.timedelta(minutes=5))
    beats.failure("failing", TimeoutError("value that must not appear"), now=NOW)

    states = {r.name: r for r in beats.report(now=NOW)}

    assert states["new"].state == "starting"
    assert states["running"].state == "ok"
    assert states["failing"].state == "degraded"
    assert "TimeoutError" in states["failing"].reason
    assert "must not appear" not in states["failing"].reason, "error types, never messages"


@pytest.mark.requirement("NFR-O5")
def test_metrics_report_each_component_and_the_backlogs():
    beats = Heartbeats()
    beats.register("embargo_sweeper", dt.timedelta(seconds=30), now=NOW)
    beats.success("embargo_sweeper", now=NOW)

    text = render_metrics(beats.report(now=NOW), pending_deliveries=4, pending_embargoes=2)

    assert 'aivs_component_up{component="embargo_sweeper"} 1' in text
    assert "aivs_webhook_deliveries_pending 4" in text
    assert "aivs_embargoes_pending 2" in text


@pytest.mark.requirement("NFR-O3")
async def test_readyz_names_a_degraded_component_without_failing_the_probe(
    client, safe_database_role
):
    """Degraded background work keeps the instance serving; it is reported by
    name, so "up" and "every part working" are never the same answer. Times are
    relative to the real clock, which /readyz reads."""
    now = dt.datetime.now(dt.UTC)
    HEARTBEATS.register("embargo_sweeper", dt.timedelta(seconds=10), now=now)
    HEARTBEATS.success("embargo_sweeper", now=now)
    healthy = (await client.get("/readyz")).json()

    HEARTBEATS.register(
        "webhook_dispatcher", dt.timedelta(seconds=10), now=now - dt.timedelta(minutes=5)
    )
    response = await client.get("/readyz")

    assert healthy["status"] == "ready"
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["components"]["webhook_dispatcher"]["state"] == "degraded"
    assert body["components"]["embargo_sweeper"]["state"] == "ok"
