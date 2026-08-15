"""Distribution: making a submission's objects visible to sharing circles.

This is the moment content stops being one firm's draft and becomes something
every member of a circle receives. Four properties are enforced here, and each
one exists because getting it wrong is expensive rather than merely untidy.

**One transaction.** Every distribution row for a submission is written in the
caller's single transaction. This is not tidiness: a member paging a circle
concurrently must see the batch atomically. If the rows committed separately, a
member could page past a timestamp and only then have an earlier-sorting row of
the same batch land behind their cursor -- silently never delivered. The
monotonic ``seq`` tiebreaker makes same-batch ordering stable; committing
atomically is the other half of that guarantee.

**Visibility is a timestamp, not a flag.** An embargo is expressed by writing
``date_added`` in the future. Nothing is gated on a scheduler having run, so a
scheduler that is down delays notification but cannot leak content early.

**TLP floors are enforced per circle.** A circle may declare a minimum
restrictiveness; content looser than that is refused rather than quietly
downgraded.

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
from aivs_server.services.embargo import record_embargo
from aivs_server.taxii.resources import truncate_to_taxii_precision

__all__ = ["DistributionError", "DistributionResult", "distribute_submission"]


class DistributionError(ValueError):
    """A distribution was refused for a reason the operator can act on."""


class DistributionResult:
    """What a distribution actually did."""

    __slots__ = ("circles", "date_added", "rows_skipped", "rows_written")

    def __init__(
        self,
        *,
        circles: list[uuid.UUID],
        date_added: dt.datetime,
        rows_written: int,
        rows_skipped: int,
    ) -> None:
        self.circles = circles
        self.date_added = date_added
        self.rows_written = rows_written
        self.rows_skipped = rows_skipped

    @property
    def embargoed(self) -> bool:
        return self.date_added > dt.datetime.now(dt.UTC)


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
    now = now or dt.datetime.now(dt.UTC)

    if submission.state is not SubmissionState.VALIDATED:
        msg = (
            f"only a validated submission may be distributed; this one is "
            f"'{submission.state.value}'"
        )
        raise DistributionError(msg)

    _validate_release_time(release_at, now)

    # Truncated because TAXII timestamps carry milliseconds. Without this a
    # member echoing X-TAXII-Date-Added-Last back as added_after receives the
    # last object again on every poll.
    date_added = truncate_to_taxii_precision(release_at or now)

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

    if submission.distribute_anonymously:
        identity = await _isac_identity(session)
        if identity is None:
            msg = (
                "anonymous distribution requires an administrative organisation "
                "to attribute content to; none is enrolled"
            )
            raise DistributionError(msg)
        for stored in objects:
            if stored.raw.get("created_by_ref") != identity:
                # Reassign rather than delete the property: an object with no
                # attribution at all is more suspicious to a consumer than one
                # attributed to the ISAC that vouched for it.
                stored.raw = {**stored.raw, "created_by_ref": identity}

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

    if date_added > now:
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
            "embargoed": date_added > now,
            "anonymous": submission.distribute_anonymously,
        },
    )

    return DistributionResult(
        circles=[circle.id for circle in circles],
        date_added=date_added,
        rows_written=rows_written,
        rows_skipped=rows_skipped,
    )
