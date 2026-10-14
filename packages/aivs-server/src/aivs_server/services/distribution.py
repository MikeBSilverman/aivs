"""Distribution: making a submission's objects visible to sharing circles.

This is the moment content stops being one firm's draft and becomes something
every member of a circle receives. Four properties are enforced here, and each
one exists because getting it wrong is expensive rather than merely untidy.

**One transaction, under the publication lock.** Every distribution row for a
submission is written in the caller's single transaction, so a member paging a
circle sees the batch atomically. Within one batch the monotonic ``seq``
tiebreaker keeps ordering stable. *Across* batches neither is enough: two
distributions can stamp and commit in opposite orders, and a member polling
between the commits is issued a cursor past the batch that commits last.
``services.publication`` serialises them; see that module.

**Visibility is a timestamp, not a flag.** An embargo is expressed by writing
``date_added`` in the future. Nothing is gated on a scheduler having run, so a
scheduler that is down delays notification but cannot leak content early.

**TLP floors are enforced per circle.** A circle may declare a minimum
restrictiveness; content looser than that is refused rather than quietly
downgraded.

**The content rules hold at the moment of release.** Owner-only versioning,
the disclosure split, TLP inheritance and others' registered identifiers were
checked at validate; they are checked again here, because the target's state
can change in between -- a disclosure withdrawn, a newer version distributed
by its owner -- and, for content distributed now, this is the last point at
which it can still be refused. An embargo's release asks the same question
again (``services.content_rules``, ``services.embargo``). The submission's TLP
marking is then stamped onto every object, as attribution is.

**Anonymity is applied to the stored object.** When a submitter asks to be
withheld, ``created_by_ref`` is rewritten to the hosting ISAC's identity at
distribution time, so the attribution consumers see is the one they should. The
submitter remains recorded internally, which is what lets the ISAC answer
questions its members cannot.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import TLP, OrgType, SubmissionState, tlp_at_least_as_restrictive
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import (
    Circle,
    Distribution,
    Organization,
    StixObject,
    Submission,
)
from aivs_server.services.content_rules import content_problem
from aivs_server.services.embargo import record_embargo
from aivs_server.services.markings import stamp_tlp_marking
from aivs_server.services.ownership import is_isac_owner
from aivs_server.services.proxy_filing import awaiting_confirmation_problem
from aivs_server.services.publication import (
    earliest_publication_instant,
    hold_publication_lock,
    release_out_of_range,
)
from aivs_server.services.submissions import self_identifying_problem
from aivs_server.taxii.resources import truncate_to_taxii_precision

__all__ = ["DistributionError", "DistributionResult", "distribute_submission"]


class DistributionError(ValueError):
    """A distribution was refused for a reason the operator can act on."""


class DistributionResult:
    """What a distribution actually did."""

    __slots__ = ("circles", "date_added", "embargoed", "rows_skipped", "rows_written")

    def __init__(
        self,
        *,
        circles: list[uuid.UUID],
        date_added: dt.datetime,
        embargoed: bool,
        rows_written: int,
        rows_skipped: int,
    ) -> None:
        self.circles = circles
        self.date_added = date_added
        self.embargoed = embargoed
        self.rows_written = rows_written
        self.rows_skipped = rows_skipped


async def _isac_identity(session: AsyncSession) -> str | None:
    """Return the hosting ISAC's STIX identity, used for anonymous attribution."""
    return (
        await session.execute(
            select(Organization.stix_identity_id)
            .where(Organization.org_type == OrgType.ADMIN)
            .order_by(Organization.created_at)
            .limit(1)
        )
    ).scalar_one_or_none()


async def _submitter_identity(session: AsyncSession, submission: Submission) -> str:
    """Return the submitting organisation's STIX identity.

    Every enrolled organisation is given one at enrolment, so this is expected to
    resolve; a submission whose submitter has no identity cannot be attributed
    honestly and is refused rather than distributed unattributed.
    """
    identity = (
        await session.execute(
            select(Organization.stix_identity_id).where(
                Organization.id == submission.submitter_org_id
            )
        )
    ).scalar_one_or_none()

    if not identity:
        msg = (
            "the submitting organisation has no STIX identity to attribute "
            "content to; re-enrol it before distributing"
        )
        raise DistributionError(msg)
    return identity


async def _attributed_identity(session: AsyncSession, submission: Submission) -> str:
    """The identity a named (not anonymous) submission is attributed to: its owner's.

    The submitter's own, except for the ISAC's automation, which files as the
    ISAC (``is_isac_owner``, the definition ownership uses): its KEV version of
    the ISAC's record is the ISAC's record, and carries the ISAC's name rather
    than a machine's.
    """
    submitter_type = await session.scalar(
        select(Organization.org_type).where(Organization.id == submission.submitter_org_id)
    )
    if not is_isac_owner(submitter_type):
        return await _submitter_identity(session, submission)
    identity = await _isac_identity(session)
    if identity is None:
        msg = (
            "the ISAC's automation files as the ISAC, and no administrative "
            "organisation is enrolled to attribute it to"
        )
        raise DistributionError(msg)
    return identity


async def _apply_attribution(
    session: AsyncSession, submission: Submission, objects: list[StixObject]
) -> None:
    """Set ``created_by_ref`` on every object to what the server knows to be true.

    Attribution is the server's to assign on both paths, and for mirror-image
    reasons. Anonymously, it becomes the hosting ISAC's identity so the submitter
    is not named. Attributed, it becomes the submitter's own identity -- ingest
    never inspected the field, so a member could otherwise name any identity they
    liked, including a peer's, which is readable from any object that peer has
    shared into a common circle. Every member of the target circles would then
    receive the finding attributed to a firm that never filed it, and because no
    consumer-facing surface exposes ``submitter_org_id``, the named firm could
    neither see nor contest it.

    Reassigned rather than deleted: an object with no attribution at all is more
    suspicious to a consumer than one attributed to whoever vouched for it.
    """
    if submission.distribute_anonymously:
        # Checked again here, not only at ingest. Distribution is the last point
        # at which the anonymity promise can still be kept, and the flag can be
        # set by a write that carried no bundle to inspect. Rewriting
        # created_by_ref over a bundle that still contains the submitter's own
        # identity SDO would deliver their name to every circle member while the
        # envelope claims the ISAC authored it.
        problem = self_identifying_problem(
            (stored.raw for stored in objects),
            own_identity_id=await _submitter_identity(session, submission),
        )
        if problem is not None:
            raise DistributionError(problem)

        identity = await _isac_identity(session)
        if identity is None:
            msg = (
                "anonymous distribution requires an administrative organisation "
                "to attribute content to; none is enrolled"
            )
            raise DistributionError(msg)
    else:
        identity = await _attributed_identity(session, submission)

    for stored in objects:
        if stored.raw.get("created_by_ref") != identity:
            stored.raw = {**stored.raw, "created_by_ref": identity}


async def _refuse_content_problems(
    session: AsyncSession, submission: Submission, objects: list[StixObject], *, now: dt.datetime
) -> None:
    """The content rules as they stand now: see ``services.content_rules``."""
    problem = await content_problem(
        session, submission, [stored.raw for stored in objects], now=now
    )
    if problem is not None:
        raise DistributionError(problem)


def _stamp_markings(submission: Submission, objects: list[StixObject]) -> None:
    """Set every object's TLP marking from the submission, refusing a conflicting one (SF-49)."""
    for stored in objects:
        try:
            stamped = stamp_tlp_marking(stored.raw, TLP(submission.tlp))
        except ValueError as exc:
            raise DistributionError(str(exc)) from exc
        if stamped != stored.raw:
            stored.raw = stamped


def _validate_release_time(release_at: dt.datetime | None, now: dt.datetime) -> None:
    """Refuse a release time that cannot mean what it says.

    A backdated ``release_at`` writes a ``date_added`` below cursors members
    have already passed, and ``added_after`` polling never looks backwards. The
    content would then be permanently invisible to precisely the members who are
    collecting correctly -- while the receipts table showed they simply never
    fetched it, so the failure would look like the member's.

    Refused rather than silently clamped to ``now``: clamping would make the
    audit record disagree with the operator's stated intent about when content
    went live.
    """
    if release_at is None:
        return
    if release_at.tzinfo is None:
        msg = "release_at must be timezone-aware"
        raise DistributionError(msg)
    too_late = release_out_of_range(release_at)
    if too_late is not None:
        raise DistributionError(too_late)
    if release_at < now:
        msg = (
            f"release_at is in the past ({release_at.isoformat()}); an embargo cannot "
            "be backdated, and doing so would hide the content from members who have "
            "already polled past that time"
        )
        raise DistributionError(msg)


async def _resolve_target_circles(
    session: AsyncSession, submission: Submission, circle_ids: Sequence[uuid.UUID]
) -> list[Circle]:
    """Resolve the target circles, refusing any that cannot lawfully receive this.

    Both checks fail the whole distribution rather than silently dropping a
    circle. A partial distribution is the worst outcome available: the operator
    believes every named circle was served, and the members of the omitted one
    are never warned.
    """
    circles = list(
        (
            await session.execute(
                select(Circle).where(Circle.id.in_(list(circle_ids)), Circle.is_active.is_(True))
            )
        )
        .scalars()
        .all()
    )

    found = {circle.id for circle in circles}
    missing = sorted(str(circle_id) for circle_id in circle_ids if circle_id not in found)
    if missing:
        msg = f"unknown or inactive circle(s): {', '.join(missing)}"
        raise DistributionError(msg)

    for circle in circles:
        if not tlp_at_least_as_restrictive(TLP(submission.tlp), TLP(circle.minimum_tlp)):
            # Refused rather than quietly downgraded. A circle's floor is a
            # handling commitment its members rely on.
            msg = (
                f"circle '{circle.slug}' requires {circle.minimum_tlp.value} or tighter; "
                f"this submission is marked {submission.tlp.value}"
            )
            raise DistributionError(msg)

    return circles


async def distribute_submission(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    *,
    circle_ids: Sequence[uuid.UUID],
    release_at: dt.datetime | None = None,
    now: dt.datetime | None = None,
) -> DistributionResult:
    """Make ``submission``'s objects visible in the given circles.

    The caller is responsible for having authorized the transition and for
    committing exactly once afterwards; this function deliberately does not
    commit, so that the whole batch lands atomically. See the module docstring.
    """
    # The lock first, and the clock is the database's, read under it: see
    # services.publication. ``now`` is injectable for tests only.
    locked_at = await hold_publication_lock(session, refuse_while_paused=True)
    now = now or locked_at

    if submission.state is not SubmissionState.VALIDATED:
        msg = (
            f"only a validated submission may be distributed; this one is "
            f"'{submission.state.value}'"
        )
        raise DistributionError(msg)

    _validate_release_time(release_at, now)
    waiting = awaiting_confirmation_problem(submission, now)
    if waiting is not None:
        raise DistributionError(waiting)

    # Truncated because TAXII timestamps carry milliseconds. Without this a
    # member echoing X-TAXII-Date-Added-Last back as added_after receives the
    # last object again on every poll. Never earlier than the next millisecond:
    # see earliest_publication_instant.
    earliest = earliest_publication_instant(now)
    requested = truncate_to_taxii_precision(release_at) if release_at else earliest
    date_added = max(requested, earliest)
    # Held past the earliest instant, not merely past `now`: every stamp is at
    # least a millisecond ahead of `now`, and testing against `now` recorded
    # every immediate distribution as an embargo, which the sweeper then
    # "released" and announced to every member a second time.
    embargoed = date_added > earliest

    circles = await _resolve_target_circles(session, submission, circle_ids)
    found = {circle.id for circle in circles}

    objects = list(
        (await session.execute(select(StixObject).where(StixObject.submission_id == submission.id)))
        .scalars()
        .all()
    )
    if not objects:
        msg = "submission carries no STIX objects to distribute"
        raise DistributionError(msg)

    await _refuse_content_problems(session, submission, objects, now=now)
    await _apply_attribution(session, submission, objects)
    _stamp_markings(submission, objects)

    # Rows for *these* objects that are already live in a target circle, so a
    # re-distribution of the same submission does not deliver it twice.
    #
    # Scoped to this submission's own StixObject ids, deliberately. An earlier
    # version keyed this on (circle, stix_id, modified) across every submission,
    # which conflicted with the per-submission uniqueness of stix_objects: two
    # organisations may legitimately hold the same stix_id, so one member's
    # object would suppress another's and circle members would receive whichever
    # arrived first, under an id that claims to be the other. Matching on the
    # concrete object id cannot do that, and the unique constraint on
    # (stix_object_id, circle_id) is what actually prevents double delivery.
    object_ids = [stored.id for stored in objects]
    already = {
        (circle_id, stix_object_id)
        for circle_id, stix_object_id in (
            await session.execute(
                select(Distribution.circle_id, Distribution.stix_object_id).where(
                    Distribution.circle_id.in_(list(found)),
                    Distribution.stix_object_id.in_(object_ids),
                )
            )
        ).all()
    }

    rows_written = 0
    rows_skipped = 0
    for circle in circles:
        for stored in objects:
            if (circle.id, stored.id) in already:
                rows_skipped += 1
                continue
            session.add(
                Distribution(
                    stix_object_id=stored.id,
                    circle_id=circle.id,
                    submission_id=submission.id,
                    date_added=date_added,
                )
            )
            rows_written += 1

    if embargoed:
        # A future visibility timestamp is an embargo; record it so the operator
        # console and the audit trail can say so. The record is bookkeeping --
        # the timestamp above is what actually holds the content back.
        await record_embargo(session, submission_id=submission.id, release_at=date_added)

    if rows_written == 0:
        # Every object was already live in every target circle. Reporting
        # success here would tell an operator a distribution went out when
        # nothing was delivered, which is the one thing they must not be
        # misinformed about.
        msg = (
            "nothing to distribute: every object in this submission is already "
            "visible in all of the requested circles"
        )
        raise DistributionError(msg)

    await record(
        session,
        action=AuditAction.SUBMISSION_DISTRIBUTED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={
            "circles": sorted(str(circle.id) for circle in circles),
            "circle_slugs": sorted(circle.slug for circle in circles),
            "objects": len(objects),
            "rows_written": rows_written,
            "rows_skipped": rows_skipped,
            "date_added": date_added.isoformat(),
            "embargoed": embargoed,
            "anonymous": submission.distribute_anonymously,
        },
    )

    return DistributionResult(
        circles=[circle.id for circle in circles],
        date_added=date_added,
        embargoed=embargoed,
        rows_written=rows_written,
        rows_skipped=rows_skipped,
    )
