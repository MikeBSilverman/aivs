"""Contributions that reach members without an editor's review (Phase E, "making members share").

Every contribution is an ordinary submission: attribution, anonymity, the TLP
floor and inheritance, owner-only versioning and the disclosure split all apply
on every lane. What differs is who decides it may be published.

**The lane rule.** A contribution is published at once, by the server, only if
all of these hold; otherwise it goes to the ISAC's review queue like anything
else:

- it says nothing in free text -- the server built it from a click, so there
  is no prose for an editor to read;
- it is about public content: a vulnerability the ISAC's record says is
  published, or an object filed as a contribution on one, never RED;
- a person filed it, from a member's session, not a machine identity;
- it goes only into circles the member may contribute to, among those the
  object reached: a reader-only membership (a government or vendor circle)
  keeps its editor;
- it is not a vendor's opinion, which is where a vendor would argue its own
  product down.

**Post-moderation.** An editor may let a circle take short contributions --
``note``, ``opinion``, ``sighting``, an RFI ``grouping`` -- on public content
in it without review; an editor reviews them afterwards. The same lane rule
applies apart from free text, which is the point of the circle's choice.

**One hourly limit.** Everything published without review, plus every TAXII
inbox filing, counts against ``contribution_hourly_limit`` per organisation.
Past it, a one-click is refused and a post-moderated contribution waits for
review; either way the refusal is audited, which the ``contribution_flood``
detection reads (SF-66).
"""

from __future__ import annotations

import datetime as dt
import enum
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import (
    TLP,
    TLP_RESTRICTIVENESS,
    DiscoveryScope,
    OrgType,
    SubmissionLane,
    SubmissionSource,
    SubmissionState,
)
from aivs_schemas.extension.builders import format_stix_timestamp
from aivs_server.audit.log import AuditAction, record, record_independently
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import distribution_visibility_clause, writable_circle_ids
from aivs_server.db.models import (
    Circle,
    Distribution,
    StixObject,
    Submission,
    TaxiiStatus,
)
from aivs_server.notify.events import queue_visibility_notifications
from aivs_server.services.disclosure import cve_status
from aivs_server.services.distribution import distribute_submission
from aivs_server.services.references import referenced_ids
from aivs_server.services.submissions import (
    apply_transition,
    check_content_rules,
    create_submission,
    record_transition,
)

__all__ = [
    "ContributionRateLimitedError",
    "OneClick",
    "Target",
    "TargetNotFoundError",
    "contribute",
    "fast_lane_problem",
    "publishable_circles",
    "resolve_target",
    "submit_submission",
    "within_hourly_allowance",
]

#: Object types a post-moderated circle may take without review.
POST_MODERABLE_TYPES: Final[frozenset[str]] = frozenset({"note", "opinion", "sighting", "grouping"})

#: The ``grouping.context`` that makes a grouping a request for information.
RFI_CONTEXT: Final[str] = "rfi"

_HOUR: Final[dt.timedelta] = dt.timedelta(hours=1)


class TargetNotFoundError(LookupError):
    """The object does not exist, or the caller cannot see it. One error for both."""


class ContributionRateLimitedError(Exception):
    """The organisation has used its hourly allowance."""


class OneClick(enum.StrEnum):
    """What a click on an object page says, and the STIX the server builds for it."""

    #: "We see this too": a sighting with no location (``where_sighted_refs``
    #: would name the member).
    SEEN = "seen"
    #: "Works": an agreeing opinion.
    WORKS = "works"
    #: "Doesn't work": a disagreeing opinion.
    FAILS = "fails"


@dataclass(frozen=True, slots=True)
class Target:
    """An object a caller may contribute about, as that caller sees it."""

    stix_id: str
    tlp: TLP
    circle_ids: frozenset[uuid.UUID]
    is_public: bool


def _is_public(raw: Mapping[str, Any], scope: DiscoveryScope) -> bool:
    """Public content: a published vulnerability, or a contribution filed on one."""
    if raw.get("type") == "vulnerability":
        return cve_status(raw) == "published"
    return scope is DiscoveryScope.DISCLOSED_THIRD_PARTY


async def resolve_target(
    session: AsyncSession, ctx: AuthContext, stix_id: str, *, now: dt.datetime
) -> Target | None:
    """The object as ``ctx`` may see it now, or ``None`` if it may not see it at all.

    The TLP is the strictest any visible version carries, so a contribution
    built from it can never be looser than its referent (SF-49).
    """
    rows = (
        await session.execute(
            select(StixObject.raw, StixObject.modified, Submission.tlp, Submission.discovery_scope)
            .add_columns(Distribution.circle_id)
            .join(Distribution, Distribution.stix_object_id == StixObject.id)
            .join(Submission, Submission.id == StixObject.submission_id)
            .where(StixObject.stix_id == stix_id, distribution_visibility_clause(ctx, now))
        )
    ).all()
    if not rows:
        return None
    latest = max(rows, key=lambda row: row.modified)
    strictest = max((TLP(row.tlp) for row in rows), key=lambda tlp: TLP_RESTRICTIVENESS[tlp])
    return Target(
        stix_id=stix_id,
        tlp=strictest,
        circle_ids=frozenset(row.circle_id for row in rows),
        is_public=_is_public(latest.raw, DiscoveryScope(latest.discovery_scope)),
    )


def fast_lane_problem(ctx: AuthContext, target: Target, *, object_type: str) -> str | None:
    """Why this contribution must be reviewed rather than published at once, or ``None``."""
    if ctx.operator_id is None:
        return "filed by a machine identity"
    if ctx.org_type is OrgType.AUTOMATION:
        return "filed by an automation organisation"
    if ctx.org_type is OrgType.VENDOR and object_type == "opinion":
        return "a vendor's opinion"
    if target.tlp is TLP.RED:
        return "about RED content"
    if not target.is_public:
        return "about content that is not public"
    if not publishable_circles(ctx, target):
        return "in no circle the organisation may contribute to"
    return None


def publishable_circles(ctx: AuthContext, target: Target) -> frozenset[uuid.UUID]:
    """The circles a contribution on ``target`` may reach without review."""
    return target.circle_ids & writable_circle_ids(ctx)


async def within_hourly_allowance(
    session: AsyncSession, org_id: uuid.UUID, *, limit: int, now: dt.datetime
) -> bool:
    """Whether ``org_id`` may publish one more contribution without review this hour."""
    since = now - _HOUR
    unreviewed = await session.scalar(
        select(func.count())
        .select_from(Submission)
        .where(
            Submission.submitter_org_id == org_id,
            Submission.lane != SubmissionLane.REVIEW,
            Submission.created_at >= since,
        )
    )
    inbox = await session.scalar(
        select(func.count())
        .select_from(TaxiiStatus)
        .where(TaxiiStatus.org_id == org_id, TaxiiStatus.request_timestamp >= since)
    )
    return (unreviewed or 0) + (inbox or 0) < limit


async def record_rate_limited(ctx: AuthContext, *, lane: str, limit: int) -> None:
    """Audit the refusal in its own transaction, so it survives the refused request."""
    await record_independently(
        action=AuditAction.CONTRIBUTION_RATE_LIMITED,
        ctx=ctx,
        resource_type="organization",
        resource_id=str(ctx.org_id),
        details={"lane": lane, "hourly_limit": limit},
    )


def _one_click_object(kind: OneClick, target_id: str, now: dt.datetime) -> dict[str, Any]:
    stamp = format_stix_timestamp(now)
    common = {"spec_version": "2.1", "created": stamp, "modified": stamp}
    if kind is OneClick.SEEN:
        return {
            "type": "sighting",
            "id": f"sighting--{uuid.uuid4()}",
            "sighting_of_ref": target_id,
            **common,
        }
    return {
        "type": "opinion",
        "id": f"opinion--{uuid.uuid4()}",
        "opinion": "agree" if kind is OneClick.WORKS else "disagree",
        "object_refs": [target_id],
        **common,
    }


async def publish_without_review(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    *,
    lane: SubmissionLane,
    circle_ids: Iterable[uuid.UUID],
) -> None:
    """Validate and distribute a contribution the lane rule admitted, in one transaction.

    The content rules every validation checks still run (owner-only
    versioning, the disclosure split, TLP inheritance); what is skipped is the
    editor, which the lane rule stands in for. Distribution is the ordinary
    one, under the publication lock.
    """
    # The objects were added in this transaction and autoflush is off.
    await session.flush()
    await check_content_rules(session, submission)
    reason = f"{lane.value} lane: published without review"
    if submission.state is SubmissionState.DRAFT:
        await record_transition(session, ctx, submission, SubmissionState.SUBMITTED, reason=reason)
    await record_transition(session, ctx, submission, SubmissionState.VALIDATED, reason=reason)
    submission.lane = lane
    targets = sorted(circle_ids, key=str)
    await distribute_submission(session, ctx, submission, circle_ids=targets)
    await record_transition(session, ctx, submission, SubmissionState.DISTRIBUTED, reason=reason)
    await queue_visibility_notifications(
        session,
        submission_id=submission.id,
        circle_ids=targets,
        visible_at=dt.datetime.now(dt.UTC),
    )
    await record(
        session,
        action=AuditAction.CONTRIBUTION_PUBLISHED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={"lane": lane.value, "circles": [str(circle_id) for circle_id in targets]},
    )


async def contribute(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    target_id: str,
    kind: OneClick,
    hourly_limit: int,
    now: dt.datetime,
) -> Submission:
    """File a one-click contribution, published at once if the lane rule allows.

    Anonymous by default: a click is the cheapest thing to share, and the one
    a member should never have to weigh.
    """
    target = await resolve_target(session, ctx, target_id, now=now)
    if target is None:
        raise TargetNotFoundError(target_id)
    built = _one_click_object(kind, target_id, now)
    lane_problem = fast_lane_problem(ctx, target, object_type=str(built["type"]))
    if lane_problem is None and not await within_hourly_allowance(
        session, ctx.org_id, limit=hourly_limit, now=now
    ):
        await record_rate_limited(ctx, lane=SubmissionLane.FAST.value, limit=hourly_limit)
        raise ContributionRateLimitedError(ctx.org_id)

    submission = await create_submission(
        session,
        ctx,
        title=f"One-click: {kind.value} on {target_id}",
        summary=None,
        tlp=target.tlp,
        # It is the member's own experience: seen in, or tried in, its estate.
        discovery_scope=DiscoveryScope.OWN_ESTATE,
        distribute_anonymously=True,
        bundle={"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [built]},
        filed_for=None,
        via="one-click",
    )
    if lane_problem is None:
        await publish_without_review(
            session,
            ctx,
            submission,
            lane=SubmissionLane.FAST,
            circle_ids=publishable_circles(ctx, target),
        )
    else:
        await apply_transition(
            session, ctx, submission, SubmissionState.SUBMITTED, reason=f"review: {lane_problem}"
        )
    return submission


# ---------------------------------------------------------------------------
# Post-moderation
# ---------------------------------------------------------------------------
def _post_moderable(raws: list[Mapping[str, Any]], ctx: AuthContext) -> bool:
    for raw in raws:
        object_type = raw.get("type")
        if object_type not in POST_MODERABLE_TYPES:
            return False
        if object_type == "grouping" and raw.get("context") != RFI_CONTEXT:
            return False
        if object_type == "opinion" and ctx.org_type is OrgType.VENDOR:
            return False
    return bool(raws)


async def _post_moderated_circles(
    session: AsyncSession, ctx: AuthContext, raws: list[Mapping[str, Any]], *, now: dt.datetime
) -> frozenset[uuid.UUID]:
    """Circles that take every referent of these objects without review, or none."""
    referenced = referenced_ids(raws)
    if not referenced:
        return frozenset()
    open_circles = frozenset(
        (await session.execute(select(Circle.id).where(Circle.post_moderated.is_(True))))
        .scalars()
        .all()
    )
    common: frozenset[uuid.UUID] = open_circles
    for stix_id in sorted(referenced):
        target = await resolve_target(session, ctx, stix_id, now=now)
        if target is None or fast_lane_problem(ctx, target, object_type="note") is not None:
            return frozenset()
        common &= publishable_circles(ctx, target)
    return common


async def submit_submission(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    *,
    reason: str | None,
    hourly_limit: int,
    now: dt.datetime,
) -> Submission:
    """Hand a draft to the ISAC, publishing it at once if a post-moderated circle takes it.

    Both surfaces that submit come through here, so the post-moderation rule
    has one home.
    """
    await apply_transition(session, ctx, submission, SubmissionState.SUBMITTED, reason=reason)
    if submission.source is not SubmissionSource.MEMBER or ctx.operator_id is None:
        return submission
    raws = list(
        (
            await session.execute(
                select(StixObject.raw).where(StixObject.submission_id == submission.id)
            )
        )
        .scalars()
        .all()
    )
    if not _post_moderable(raws, ctx):
        return submission
    circles = await _post_moderated_circles(session, ctx, raws, now=now)
    if not circles:
        return submission
    if not await within_hourly_allowance(session, ctx.org_id, limit=hourly_limit, now=now):
        await record_rate_limited(ctx, lane=SubmissionLane.POST_MODERATED.value, limit=hourly_limit)
        return submission
    await publish_without_review(
        session, ctx, submission, lane=SubmissionLane.POST_MODERATED, circle_ids=circles
    )
    return submission
