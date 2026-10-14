"""Noticing abuse of the platform itself.

The audit log was evidence only: a credential-stuffing run, a member
certificate paging the whole archive, or someone revealing an anonymous
submitter at 3 a.m. were all recorded and none was noticed. Each rule here reads
the audit log or the receipts over a window and returns what it found; the
engine raises each finding once per window and emits it three ways, so the ISAC
and whoever monitors it can consume it without custom work:

* an ``detection.raised`` audit row -- the evidentiary record;
* one structured line on the ``aivs_server.security`` logger carrying the
  finding as an OCSF Detection Finding and as a CEF string -- what a SIEM or an
  MSP ingests when the deployment forwards logs over syslog;
* a contentless webhook to the ISAC's own subscribed endpoints.

Findings carry identifiers and counts, never content (CLAUDE.md section 5 on
logs). Every rule has a test that raises it and a test that does not.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from aivs_schemas.enums import AckType, OrgType
from aivs_server.audit.log import AuditAction, record
from aivs_server.db.models import (
    Acknowledgment,
    AuditLog,
    DetectionState,
    Organization,
    Webhook,
    WebhookDelivery,
)
from aivs_server.notify.dispatcher import KEY_UNAVAILABLE_ERROR
from aivs_server.observability import HEARTBEATS
from aivs_server.services.org_status import load_org_for_update
from aivs_server.services.quarantine import QuarantineError, quarantine_org_automatically

__all__ = [
    "EVENT_DETECTION_RAISED",
    "PROPOSED_QUARANTINE",
    "RULES",
    "Finding",
    "QuarantinePolicy",
    "run_detections",
]

security_logger = logging.getLogger("aivs_server.security")

EVENT_DETECTION_RAISED: Final[str] = "detection.raised"

#: OCSF Detection Finding (class 2004, category Findings). Severity ids per OCSF.
_OCSF_CLASS_UID: Final[int] = 2004
_OCSF_SEVERITY: Final[dict[str, int]] = {"low": 2, "medium": 3, "high": 4, "critical": 5}
#: CEF severity, 0-10.
_CEF_SEVERITY: Final[dict[str, int]] = {"low": 3, "medium": 5, "high": 8, "critical": 10}


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing a rule noticed. ``subject`` is what it is about: an address,
    an account reference, an organisation id, an audit row id."""

    rule: str
    severity: str
    subject: str
    summary: str
    count: int = 1
    details: dict[str, Any] = field(default_factory=dict)


#: How a rule's proposed quarantine is acted on: shown on the status page for a
#: human to confirm, or applied at once. The ISAC chooses; the default is the
#: one that does less (plan, Phase A).
QuarantinePolicy = Literal["propose", "enforce"]

#: ``details["proposed_action"]`` on a finding that recommends a quarantine.
PROPOSED_QUARANTINE: Final[str] = "quarantine"

RuleCheck = Callable[[AsyncSession, dt.datetime, dt.timedelta, int], Awaitable[list[Finding]]]


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    severity: str
    window: dt.timedelta
    threshold: int
    check: RuleCheck


async def _audit_bursts(
    session: AsyncSession,
    *,
    action: str,
    group_by: Any,
    since: dt.datetime,
    threshold: int,
) -> list[tuple[str, int]]:
    rows = (
        await session.execute(
            select(group_by, func.count())
            .where(AuditLog.action == action, AuditLog.at >= since, group_by.is_not(None))
            .group_by(group_by)
            .having(func.count() >= threshold)
        )
    ).all()
    return [(str(subject), int(count)) for subject, count in rows]


async def _auth_failure_burst(
    session: AsyncSession, now: dt.datetime, window: dt.timedelta, threshold: int
) -> list[Finding]:
    """Many refused authentications from one address: probing or a broken collector."""
    bursts = await _audit_bursts(
        session,
        action=AuditAction.AUTH_FAILURE,
        group_by=AuditLog.source_ip,
        since=now - window,
        threshold=threshold,
    )
    return [
        Finding(
            rule="auth_failure_burst",
            severity="medium",
            subject=address,
            summary=f"{count} refused authentications from {address} in {window}",
            count=count,
        )
        for address, count in bursts
    ]


async def _login_failure_burst(
    session: AsyncSession, now: dt.datetime, window: dt.timedelta, threshold: int
) -> list[Finding]:
    """Many failed portal logins against one account: password guessing."""
    bursts = await _audit_bursts(
        session,
        action=AuditAction.LOGIN_FAILURE,
        group_by=AuditLog.details["account"].astext,
        since=now - window,
        threshold=threshold,
    )
    return [
        Finding(
            rule="login_failure_burst",
            severity="high",
            subject=account,
            summary=f"{count} failed portal logins against one account in {window}",
            count=count,
        )
        for account, count in bursts
    ]


async def _not_found_burst(
    session: AsyncSession, now: dt.datetime, window: dt.timedelta, threshold: int
) -> list[Finding]:
    """Many lookups of absent or invisible resources by one organisation.

    Every id-addressable route answers 404 rather than 403 so it is not an
    existence oracle. Walking the identifier space anyway shows up here.
    """
    bursts = await _audit_bursts(
        session,
        action=AuditAction.ACCESS_NOT_FOUND,
        group_by=AuditLog.org_id,
        since=now - window,
        threshold=threshold,
    )
    return [
        Finding(
            rule="not_found_burst",
            severity="medium",
            subject=org_id,
            summary=f"{count} lookups of absent or invisible resources by one org in {window}",
            count=count,
        )
        for org_id, count in bursts
    ]


async def _contribution_flood(
    session: AsyncSession, now: dt.datetime, window: dt.timedelta, threshold: int
) -> list[Finding]:
    """An organisation that hit its hourly allowance for unreviewed contributions (SF-66).

    Read from the audited refusals rather than from a count of contributions,
    so the rule fires exactly when the limit bites, whatever the instance sets
    ``contribution_hourly_limit`` to. A member clicking never gets there; a
    script, or a stolen certificate, does.
    """
    bursts = await _audit_bursts(
        session,
        action=AuditAction.CONTRIBUTION_RATE_LIMITED,
        group_by=AuditLog.org_id,
        since=now - window,
        threshold=threshold,
    )
    return [
        Finding(
            rule="contribution_flood",
            severity="medium",
            subject=org_id,
            summary=f"one organisation was refused {count} unreviewed contribution(s) in {window}",
            count=count,
        )
        for org_id, count in bursts
    ]


async def _first_distribution_to_circle(
    session: AsyncSession, now: dt.datetime, window: dt.timedelta, threshold: int
) -> list[Finding]:
    """An operator distributing to a circle for the first time.

    The checker half of maker/checker: a new route for content to take is
    worth a second pair of eyes, whoever took it. Routine distributions to a
    circle the same editor has used before raise nothing.
    """
    del threshold
    recent = (
        select(
            AuditLog.at,
            AuditLog.actor_id,
            func.jsonb_array_elements_text(AuditLog.details["circles"]).label("circle"),
        )
        .where(
            AuditLog.action == AuditAction.SUBMISSION_DISTRIBUTED,
            AuditLog.at >= now - window,
            AuditLog.actor_id.is_not(None),
        )
        .subquery()
    )
    earlier = aliased(AuditLog)
    seen_before = (
        select(earlier.id)
        .where(
            earlier.action == AuditAction.SUBMISSION_DISTRIBUTED,
            earlier.actor_id == recent.c.actor_id,
            earlier.at < recent.c.at,
            earlier.details["circles"].has_key(recent.c.circle),
        )
        .exists()
    )
    rows = await session.execute(
        select(recent.c.actor_id, recent.c.circle).where(~seen_before).distinct()
    )
    return [
        Finding(
            rule="first_distribution_to_circle",
            severity="medium",
            subject=f"{actor_id}:{circle}",
            summary="an operator distributed to a circle for the first time",
            details={"operator": str(actor_id), "circle": circle},
        )
        for actor_id, circle in rows.all()
    ]


async def _signing_key_unavailable(
    session: AsyncSession, now: dt.datetime, window: dt.timedelta, threshold: int
) -> list[Finding]:
    """Notifications held because their signing key cannot be opened.

    The dispatcher defers them rather than spending an attempt, which is right
    for a configuration fault on our side, and retries every few minutes for as
    long as it lasts. Without this the member simply stops hearing, and the
    only trace is an ERROR line every few minutes.
    """
    del now, window
    rows = (
        await session.execute(
            select(WebhookDelivery.webhook_id, func.count())
            .where(
                WebhookDelivery.delivered_at.is_(None),
                WebhookDelivery.error == KEY_UNAVAILABLE_ERROR,
            )
            .group_by(WebhookDelivery.webhook_id)
            .having(func.count() >= threshold)
        )
    ).all()
    return [
        Finding(
            rule="signing_key_unavailable",
            severity="high",
            subject=str(webhook_id),
            summary=f"{count} notification(s) held: their signing key cannot be opened",
            count=int(count),
        )
        for webhook_id, count in rows
    ]


async def _bulk_retrieval(
    session: AsyncSession, now: dt.datetime, window: dt.timedelta, threshold: int
) -> list[Finding]:
    """One organisation retrieving far more than members do: a scraped archive."""
    rows = (
        await session.execute(
            select(Acknowledgment.org_id, func.count(func.distinct(Acknowledgment.submission_id)))
            .where(
                Acknowledgment.ack_type == AckType.RETRIEVED,
                Acknowledgment.created_at >= now - window,
            )
            .group_by(Acknowledgment.org_id)
            .having(func.count(func.distinct(Acknowledgment.submission_id)) >= threshold)
        )
    ).all()
    return [
        Finding(
            rule="bulk_retrieval",
            severity="high",
            subject=str(org_id),
            summary=f"one organisation retrieved {count} submissions in {window}",
            count=int(count),
            # A scraped archive is a stolen certificate until shown otherwise.
            details={"proposed_action": PROPOSED_QUARANTINE, "proposed_org": str(org_id)},
        )
        for org_id, count in rows
    ]


async def _component_degraded(
    session: AsyncSession, now: dt.datetime, window: dt.timedelta, threshold: int
) -> list[Finding]:
    """A background component that has stopped succeeding: the silent failure.

    If the detection loop itself is the one that died, this cannot fire --
    which is why /readyz and the aivs_component_up metric report the same
    registry, for monitoring that does not depend on this process's loops.
    """
    del session, window, threshold
    return [
        Finding(
            rule="component_degraded",
            severity="high",
            subject=report.name,
            summary=f"{report.name} is degraded: {report.reason}",
        )
        for report in HEARTBEATS.report(now=now)
        if report.state == "degraded"
    ]


def _every_occurrence(rule: str, action: str, severity: str, summary: str) -> RuleCheck:
    """A rule that raises on each audit row of ``action`` -- acts worth an alert every time."""

    async def check(
        session: AsyncSession, now: dt.datetime, window: dt.timedelta, threshold: int
    ) -> list[Finding]:
        del threshold
        rows = (
            await session.execute(
                select(AuditLog.id, AuditLog.resource_id).where(
                    AuditLog.action == action, AuditLog.at >= now - window
                )
            )
        ).all()
        return [
            Finding(
                rule=rule,
                severity=severity,
                subject=str(row_id),
                summary=summary,
                details={"resource": resource_id},
            )
            for row_id, resource_id in rows
        ]

    return check


RULES: Final[tuple[Rule, ...]] = (
    Rule("component_degraded", "high", dt.timedelta(minutes=30), 1, _component_degraded),
    Rule("auth_failure_burst", "medium", dt.timedelta(minutes=10), 20, _auth_failure_burst),
    Rule("login_failure_burst", "high", dt.timedelta(minutes=15), 10, _login_failure_burst),
    Rule("bulk_retrieval", "high", dt.timedelta(hours=1), 200, _bulk_retrieval),
    Rule(
        "signing_key_unavailable",
        "high",
        dt.timedelta(hours=6),
        1,
        _signing_key_unavailable,
    ),
    Rule("not_found_burst", "medium", dt.timedelta(minutes=10), 50, _not_found_burst),
    Rule("contribution_flood", "medium", dt.timedelta(hours=1), 1, _contribution_flood),
    Rule(
        "first_distribution_to_circle",
        "medium",
        dt.timedelta(hours=1),
        1,
        _first_distribution_to_circle,
    ),
    Rule(
        "anonymity_reveal",
        "high",
        dt.timedelta(hours=1),
        1,
        _every_occurrence(
            "anonymity_reveal",
            AuditAction.ANONYMITY_REVEALED,
            "high",
            "an anonymous submitter was revealed",
        ),
    ),
    Rule(
        "distribution_paused",
        "critical",
        dt.timedelta(hours=1),
        1,
        _every_occurrence(
            "distribution_paused",
            AuditAction.DISTRIBUTION_PAUSED,
            "critical",
            "distribution was paused instance-wide",
        ),
    ),
    Rule(
        "operator_bootstrapped",
        "high",
        dt.timedelta(hours=1),
        1,
        _every_occurrence(
            "operator_bootstrapped",
            AuditAction.OPERATOR_BOOTSTRAPPED,
            "high",
            "an operator was created from the host with the bootstrap command",
        ),
    ),
    Rule(
        "org_quarantined",
        "high",
        dt.timedelta(hours=1),
        1,
        _every_occurrence(
            "org_quarantined",
            AuditAction.ORG_QUARANTINED,
            "high",
            "an organisation was quarantined",
        ),
    ),
)


async def _already_raised(
    session: AsyncSession, finding: Finding, now: dt.datetime, window: dt.timedelta
) -> bool:
    state = await session.get(DetectionState, (finding.rule, finding.subject))
    if state is not None and state.last_raised_at > now - window:
        return True
    if state is None:
        session.add(DetectionState(rule=finding.rule, subject=finding.subject, last_raised_at=now))
    else:
        state.last_raised_at = now
    return False


def _ocsf(finding: Finding, now: dt.datetime) -> dict[str, Any]:
    return {
        "class_uid": _OCSF_CLASS_UID,
        "category_uid": 2,
        "activity_id": 1,
        "type_uid": _OCSF_CLASS_UID * 100 + 1,
        "time": int(now.timestamp() * 1000),
        "severity_id": _OCSF_SEVERITY[finding.severity],
        "finding_info": {"uid": f"{finding.rule}:{finding.subject}", "title": finding.rule},
        "message": finding.summary,
        "count": finding.count,
        "metadata": {"product": {"name": "AIVS", "vendor_name": "AIVS"}, "version": "1.1.0"},
    }


def _cef(finding: Finding) -> str:
    def escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace("|", "\\|")

    return (
        f"CEF:0|AIVS|AIVS|1|{escape(finding.rule)}|{escape(finding.summary)}|"
        f"{_CEF_SEVERITY[finding.severity]}|cnt={finding.count} "
        f"suid={finding.subject.replace('=', '\\=')}"
    )


async def _queue_alert(session: AsyncSession, finding: Finding, now: dt.datetime) -> None:
    """Contentless webhook to the ISAC's own subscribed endpoints."""
    hooks = (
        (
            await session.execute(
                select(Webhook)
                .join(Organization, Organization.id == Webhook.org_id)
                .where(Organization.org_type == OrgType.ADMIN, Webhook.is_active.is_(True))
            )
        )
        .scalars()
        .all()
    )
    for hook in hooks:
        if hook.events and EVENT_DETECTION_RAISED not in hook.events:
            continue
        session.add(
            WebhookDelivery(
                webhook_id=hook.id,
                event=EVENT_DETECTION_RAISED,
                payload={
                    "event": EVENT_DETECTION_RAISED,
                    "rule": finding.rule,
                    "severity": finding.severity,
                    "raised_at": now.isoformat(),
                    "detail": "see the admin status page",
                },
            )
        )


async def _emit(session: AsyncSession, finding: Finding, now: dt.datetime) -> None:
    await record(
        session,
        action=AuditAction.DETECTION_RAISED,
        resource_type="detection",
        resource_id=finding.rule,
        details={
            "rule": finding.rule,
            "severity": finding.severity,
            "subject": finding.subject,
            "count": finding.count,
            "summary": finding.summary,
            **finding.details,
        },
    )
    security_logger.warning(
        finding.summary,
        extra={"ocsf": _ocsf(finding, now), "cef": _cef(finding), "rule": finding.rule},
    )
    await _queue_alert(session, finding, now)


async def _enforce_quarantine(session: AsyncSession, finding: Finding, now: dt.datetime) -> None:
    """Apply a proposed quarantine. Refusals (the ISAC itself, an organisation
    not active) are logged and leave the finding as a proposal."""
    organisation = await load_org_for_update(session, uuid.UUID(finding.details["proposed_org"]))
    if organisation is None:
        return
    try:
        await quarantine_org_automatically(
            session, organisation=organisation, rule=finding.rule, now=now
        )
    except QuarantineError as exc:
        security_logger.warning(
            "proposed quarantine not applied",
            extra={"rule": finding.rule, "reason": str(exc)},
        )


async def run_detections(
    session: AsyncSession,
    *,
    now: dt.datetime,
    quarantine_policy: QuarantinePolicy,
    rules: Sequence[Rule] = RULES,
) -> list[Finding]:
    """Evaluate every rule once; raise what is new. Returns what was raised. Commits."""
    raised: list[Finding] = []
    for rule in rules:
        for finding in await rule.check(session, now, rule.window, rule.threshold):
            if await _already_raised(session, finding, now, rule.window):
                continue
            await _emit(session, finding, now)
            if (
                quarantine_policy == "enforce"
                and finding.details.get("proposed_action") == PROPOSED_QUARANTINE
            ):
                await _enforce_quarantine(session, finding, now)
            raised.append(finding)
    await session.commit()
    return raised
