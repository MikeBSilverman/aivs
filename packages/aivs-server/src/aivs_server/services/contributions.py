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
- a person filed it, from a member's session: not a machine identity, and
  not the ISAC's own organisation or its automation, which file through
  review;
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
import logging
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import func, select, text
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
from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID, format_stix_timestamp
from aivs_server.audit.log import AuditAction, record, record_independently
from aivs_server.auth.attribution_key import AttributionKey
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import (
    distribution_visibility_clause,
    files_through_an_editor,
    writable_circle_ids,
)
from aivs_server.db.clock import database_now
from aivs_server.db.models import (
    Circle,
    Distribution,
    StixObject,
    Submission,
)
from aivs_server.notify.events import queue_visibility_notifications
from aivs_server.services.attribution import submissions_filed_by
from aivs_server.services.disclosure import cve_status, published_in_the_isacs_view
from aivs_server.services.distribution import DistributionError, distribute_submission
from aivs_server.services.member_staff_reads import inbox_posts_since
from aivs_server.services.ownership import ISAC_OWNER
from aivs_server.services.publication import PublicationPausedError
from aivs_server.services.references import external_references_by_type, referenced_ids
from aivs_server.services.submissions import (
    SubmissionError,
    apply_transition,
    check_content_rules,
    create_submission,
    record_transition,
)

__all__ = [
    "ISAC_CLICK_NEEDS_AN_EDITOR",
    "ContributionRateLimitedError",
    "FilingNeedsAnEditorError",
    "OneClick",
    "Target",
    "TargetNotFoundError",
    "contribute",
    "fast_lane_problem",
    "filer_problem",
    "publish_if_post_moderated",
    "publishable_circles",
    "resolve_target",
    "submit_submission",
    "within_hourly_allowance",
]

logger = logging.getLogger(__name__)

#: Object types a post-moderated circle may take without review.
POST_MODERABLE_TYPES: Final[frozenset[str]] = frozenset({"note", "opinion", "sighting", "grouping"})

#: Organisation types whose people may take a shortcut lane: the members. Not
#: the ISAC's own organisation or its automation, which file through review.
SHORTCUT_LANE_ORG_TYPES: Final[frozenset[OrgType]] = frozenset(
    {
        OrgType.GSIB,
        OrgType.SECTION9,
        OrgType.CRIT_INFRA,
        OrgType.VENDOR,
        OrgType.RESEARCHER,
        OrgType.GOVERNMENT,
    }
)

#: The ``grouping.context`` that makes a grouping a request for information.
RFI_CONTEXT: Final[str] = "rfi"

_HOUR: Final[dt.timedelta] = dt.timedelta(hours=1)

#: Advisory-lock space for the per-organisation allowance ("AIVS"); the object
#: key is the organisation. Two int4 keys, so it cannot collide with the
#: publication lock's single bigint key.
_ALLOWANCE_LOCK_SPACE: Final[int] = 0x41495653

#: What a member is told when a contribution the lane rule admitted turns out to
#: need an editor for a reason only the ISAC's view of the content shows. One
#: constant: the reason itself would describe content the member cannot see
#: (a stricter or embargoed version, a hidden record's state, who owns an id).
NEEDS_AN_EDITOR: Final[str] = "review: an editor will check it before it is shared"

#: Refusals of the ISAC's-view checks, and of distribution, that send a
#: shortcut to review instead of answering the member with their reason.
_REVIEW_INSTEAD: Final[tuple[type[Exception], ...]] = (
    SubmissionError,
    DistributionError,
    PublicationPausedError,
)


class TargetNotFoundError(LookupError):
    """The object does not exist, or the caller cannot see it. One error for both."""


class ContributionRateLimitedError(Exception):
    """The organisation has used its hourly allowance."""


#: What ISAC staff without the editor role are told when they click. ISAC
#: staff, not an outsider, so saying what to do confirms nothing.
ISAC_CLICK_NEEDS_AN_EDITOR: Final[str] = (
    "The ISAC's own contributions are filed by an ISAC editor; ask one to file this."
)


class FilingNeedsAnEditorError(PermissionError):
    """ISAC staff without the editor role clicked: filing it would submit an
    ISAC filing, which is an editor's verb (Mike, Q15)."""


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


def _is_public(rows: list[Any]) -> bool:
    """Public content: the ISAC's published record of a vulnerability, or a contribution on one.

    For a vulnerability, only the ISAC's own latest visible version counts --
    the same owner the disclosure split reads. Reading whoever's version was
    latest let a member's own vulnerability, distributed saying "published",
    open the fast lane on itself.
    """
    latest = max(rows, key=lambda row: row.modified)
    if latest.raw.get("type") != "vulnerability":
        return DiscoveryScope(latest.discovery_scope) is DiscoveryScope.DISCLOSED_THIRD_PARTY
    isac_rows = [row for row in rows if row.owner == ISAC_OWNER]
    if not isac_rows:
        return False
    return cve_status(max(isac_rows, key=lambda row: row.modified).raw) == "published"


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
            .add_columns(Distribution.circle_id, StixObject.owner_token.label("owner"))
            .join(Distribution, Distribution.stix_object_id == StixObject.id)
            .join(Submission, Submission.id == StixObject.submission_id)
            .where(StixObject.stix_id == stix_id, distribution_visibility_clause(ctx, now))
        )
    ).all()
    if not rows:
        return None
    strictest = max((TLP(row.tlp) for row in rows), key=lambda tlp: TLP_RESTRICTIVENESS[tlp])
    return Target(
        stix_id=stix_id,
        tlp=strictest,
        circle_ids=frozenset(row.circle_id for row in rows),
        is_public=_is_public(list(rows)),
    )


def filer_problem(ctx: AuthContext) -> str | None:
    """Why this filer takes no shortcut lane, or ``None`` for a person at a member organisation.

    An allow-list of member types. The ISAC files through review: it is one
    owner of every record it holds, so owner-only versioning cannot tell its
    analyst from its editor, and refusing only the automation type let an
    analyst, membership officer or system admin -- none of whom may
    distribute -- publish in the ISAC's name, or replace an editor's record,
    wherever the ISAC held a contributor membership.
    """
    if ctx.operator_id is None:
        return "filed by a machine identity"
    if ctx.org_type not in SHORTCUT_LANE_ORG_TYPES:
        return "filed by the ISAC, which files through review"
    return None


def fast_lane_problem(ctx: AuthContext, target: Target, *, object_type: str) -> str | None:
    """Why this contribution must be reviewed rather than published at once, or ``None``."""
    filer = filer_problem(ctx)
    if filer is not None:
        return filer
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
    """Whether ``org_id`` may publish one more contribution without review this hour.

    Takes the organisation's allowance lock for the rest of the transaction
    first. Without it, parallel requests each counted limit - 1 and all went
    through. Unreviewed publications count by when they were *published*:
    counting by creation let drafts made an hour earlier be submitted together
    against an empty allowance.
    """
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:space, hashtext(:org))"),
        {"space": _ALLOWANCE_LOCK_SPACE, "org": str(org_id)},
    )
    since = now - _HOUR
    unreviewed = await session.scalar(
        select(func.count())
        .select_from(Submission)
        .where(
            Submission.id.in_(await submissions_filed_by(org_id)),
            Submission.lane != SubmissionLane.REVIEW,
            Submission.distributed_at >= since,
        )
    )
    inbox = await inbox_posts_since(org_id, since)
    return (unreviewed or 0) + inbox < limit


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
    key: AttributionKey,
    lane: SubmissionLane,
    circle_ids: Iterable[uuid.UUID],
) -> bool:
    """Validate and distribute a contribution the lane rule admitted, or file it for review.

    The content rules every validation checks still run (owner-only
    versioning, the disclosure split, TLP inheritance), from the ISAC's view,
    which sees more than the member. When one refuses, or distribution does,
    the contribution waits for an editor and the member is told only
    ``NEEDS_AN_EDITOR``: answering with the reason told a member that a
    stricter or embargoed version of what it clicked on existed, and its TLP.
    The work happens in a savepoint, so a refusal leaves the submission
    exactly as the review lane would. Returns whether it was published.
    """
    # The objects were added in this transaction and autoflush is off.
    await session.flush()
    try:
        async with session.begin_nested():
            await _validate_and_distribute(
                session, ctx, submission, lane=lane, circle_ids=circle_ids, key=key
            )
    except _REVIEW_INSTEAD as refusal:
        await _file_for_review(session, ctx, submission, key=key)
        await _keep_the_reason(session, ctx, submission, lane=lane, refusal=refusal)
        return False
    return True


async def _keep_the_reason(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    *,
    lane: SubmissionLane,
    refusal: Exception,
) -> None:
    """Record which rule sent a shortcut to review, where only the ISAC reads it.

    The audit row carries the reason, for the editor who picks it up. The log
    line carries the submission and the kind of refusal only: the reason
    names objects, and logs leave the platform beside the caller's identity.
    """
    rule = type(refusal).__name__
    logger.info(
        "shortcut sent to review: %s",
        rule,
        extra={"submission_id": str(submission.id), "lane": lane.value, "rule": rule},
    )
    await record(
        session,
        action=AuditAction.CONTRIBUTION_SENT_TO_REVIEW,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={"lane": lane.value, "rule": rule, "reason": str(refusal)},
    )


async def _file_for_review(
    session: AsyncSession, ctx: AuthContext, submission: Submission, key: AttributionKey
) -> None:
    # The savepoint's rollback expired what it changed; reload before reading.
    await session.refresh(submission)
    submission.lane = SubmissionLane.REVIEW
    if submission.state is SubmissionState.DRAFT:
        await apply_transition(
            session, ctx, submission, SubmissionState.SUBMITTED, reason=NEEDS_AN_EDITOR, key=key
        )


async def _validate_and_distribute(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    *,
    lane: SubmissionLane,
    circle_ids: Iterable[uuid.UUID],
    key: AttributionKey,
) -> None:
    await check_content_rules(session, submission, key)
    await _refuse_unless_published_in_the_isacs_view(session, submission)
    reason = f"{lane.value} lane: published without review"
    if submission.state is SubmissionState.DRAFT:
        await record_transition(session, ctx, submission, SubmissionState.SUBMITTED, reason=reason)
    await record_transition(session, ctx, submission, SubmissionState.VALIDATED, reason=reason)
    submission.lane = lane
    targets = sorted(circle_ids, key=str)
    result = await distribute_submission(session, ctx, submission, circle_ids=targets, key=key)
    await record_transition(session, ctx, submission, SubmissionState.DISTRIBUTED, reason=reason)
    # The distribution's own stamp, as "now" too: a database-clock instant
    # compared with the notifier's default app-clock "now" read as "not yet
    # visible" on a replica running behind, and nobody was told.
    await queue_visibility_notifications(
        session,
        key=key,
        submission_id=submission.id,
        circle_ids=targets,
        visible_at=result.date_added,
        now=result.date_added,
    )
    await record(
        session,
        action=AuditAction.CONTRIBUTION_PUBLISHED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={"lane": lane.value, "circles": [str(circle_id) for circle_id in targets]},
    )


async def _refuse_unless_published_in_the_isacs_view(
    session: AsyncSession, submission: Submission
) -> None:
    """Every vulnerability the contribution is about is still published, as the ISAC sees it.

    The lane rule read "public" from the member's view, which cannot see a
    newer validated or embargoed version; this is the same question from the
    ISAC's. Its refusal goes to review like the other ISAC-view checks.
    """
    raws = (
        (
            await session.execute(
                select(StixObject.raw).where(StixObject.submission_id == submission.id)
            )
        )
        .scalars()
        .all()
    )
    now = await database_now(session)
    for stix_id in sorted(external_references_by_type(raws, "vulnerability")):
        if not await published_in_the_isacs_view(
            session, stix_id, exclude_submission_id=submission.id, now=now
        ):
            msg = f"the ISAC's current record of {stix_id} does not say published"
            raise SubmissionError(msg)


async def contribute(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    target_id: str,
    kind: OneClick,
    hourly_limit: int,
    now: dt.datetime,
    key: AttributionKey,
) -> Submission:
    """File a one-click contribution, published at once if the lane rule allows.

    Anonymous by default: a click is the cheapest thing to share, and the one
    a member should never have to weigh.
    """
    target = await resolve_target(session, ctx, target_id, now=now)
    if target is None:
        raise TargetNotFoundError(target_id)
    # After the lookup, so a target the caller cannot see still answers 404.
    if files_through_an_editor(ctx):
        raise FilingNeedsAnEditorError(target_id)
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
        # The owner's default: anonymous for a member, the ISAC's own for the ISAC.
        distribute_anonymously=None,
        bundle={"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [built]},
        filed_for=None,
        via="one-click",
        key=key,
    )
    if lane_problem is None:
        await publish_without_review(
            session,
            ctx,
            submission,
            lane=SubmissionLane.FAST,
            circle_ids=publishable_circles(ctx, target),
            key=key,
        )
    else:
        await apply_transition(
            session,
            ctx,
            submission,
            SubmissionState.SUBMITTED,
            reason=f"review: {lane_problem}",
            key=key,
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
        if object_type == "note" and _states_exploitability(raw):
            return False
    return bool(raws)


def _states_exploitability(raw: Mapping[str, Any]) -> bool:
    """A note carrying exploitability conditions (plan, Phase N).

    A condition tells most members they are not affected; a wrong one,
    published unread, is a false negative across the sector. Such a note is
    always reviewed, however open its circle.
    """
    extensions = raw.get("extensions")
    return isinstance(extensions, Mapping) and AIVS_INTEL_EXTENSION_ID in extensions


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
    key: AttributionKey,
) -> Submission:
    """Hand a draft to the ISAC. Does not commit.

    Publication by post-moderation is a second step in a transaction of its
    own (``member_staff_writes.publish_own_post_moderated``), once this one
    has committed: see that module for why.
    """
    await apply_transition(
        session, ctx, submission, SubmissionState.SUBMITTED, reason=reason, key=key
    )
    return submission


async def publish_if_post_moderated(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    *,
    hourly_limit: int,
    now: dt.datetime,
    key: AttributionKey,
) -> bool:
    """Publish a submitted contribution at once if a post-moderated circle takes it.

    Both surfaces that submit come through here, so the post-moderation rule
    has one home. Whether it was published; otherwise it waits for review.
    The caller holds the submission under a row lock and has checked that it
    is still submitted.
    """
    if submission.source is not SubmissionSource.MEMBER or ctx.operator_id is None:
        return False
    raws = list(
        (
            await session.execute(
                select(StixObject.raw).where(StixObject.submission_id == submission.id)
            )
        )
        .scalars()
        .all()
    )
    if TLP(submission.tlp) is TLP.RED or not _post_moderable(raws, ctx):
        # RED is named people on named devices: it is never published unread,
        # whatever the referents' TLP. Checking only the targets let a RED note
        # on a GREEN record reach a whole circle with no editor.
        return False
    circles = await _post_moderated_circles(session, ctx, raws, now=now)
    if not circles:
        return False
    if not await within_hourly_allowance(session, ctx.org_id, limit=hourly_limit, now=now):
        await record_rate_limited(ctx, lane=SubmissionLane.POST_MODERATED.value, limit=hourly_limit)
        return False
    return await publish_without_review(
        session, ctx, submission, lane=SubmissionLane.POST_MODERATED, circle_ids=circles, key=key
    )
