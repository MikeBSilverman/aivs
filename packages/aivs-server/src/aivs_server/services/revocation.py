"""An editor revokes a contribution that reached members without review.

The fast lane and post-moderated circles publish before an editor reads the
content (``services.contributions``); this is the after-the-fact half of that
bargain. Revoking does not edit or delete what members already hold: a TIP
merges by ``id`` and ``modified``, and a poller that already walked past a row
never sees it change (SF-9). So a revocation is a **newer version** of each
object with ``revoked: true``, written into the same submission (the member
stays the owner, so SF-48 holds without an exception) and distributed to every
circle the object reached, under the publication lock like any other row.

**Allowed while distribution is paused.** A pause hides everything; a revoked
version stamped during it becomes visible on resume together with what it
revokes, so a poller takes the revoked version as current. Refusing would leave
an editor who paused *because* of a bad note unable to retract it before
resuming. This is the same argument that lets an embargo be extended during a
pause.

Reviewed content is not revoked here: an editor validated it, and a
retraction of reviewed content is a new version filed and reviewed like any
other.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import SubmissionLane, SubmissionState
from aivs_schemas.extension.builders import format_stix_timestamp
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import is_isac_editor, require
from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.notify.events import queue_visibility_notifications
from aivs_server.services.publication import earliest_publication_instant, hold_publication_lock
from aivs_server.services.submissions import SubmissionError, index_columns

__all__ = ["REVOCABLE_LANES", "RevocationResult", "revocable", "revoke_contribution"]

#: The lanes that skip an editor before publication, and so get one after it.
REVOCABLE_LANES: Final[frozenset[SubmissionLane]] = frozenset(
    {SubmissionLane.FAST, SubmissionLane.POST_MODERATED}
)

_ONE_MILLISECOND: Final[dt.timedelta] = dt.timedelta(milliseconds=1)

#: The API's request model says the same; the portal's form reaches here directly.
_MIN_REASON: Final[int] = 10


@dataclass(frozen=True, slots=True)
class RevocationResult:
    revoked_ids: list[str]
    circle_count: int
    date_added: dt.datetime


def revocable(submission: Submission) -> bool:
    """Whether ``submission`` is content this module revokes. Says nothing of who may."""
    return submission.lane in REVOCABLE_LANES and submission.state is SubmissionState.DISTRIBUTED


def _refuse_unrevocable(submission: Submission) -> None:
    if submission.lane not in REVOCABLE_LANES:
        msg = (
            "only content published without review is revoked this way; reviewed "
            "content is retracted by a new version, filed and reviewed"
        )
        raise SubmissionError(msg)
    if submission.state is not SubmissionState.DISTRIBUTED:
        msg = f"only distributed content can be revoked; this is '{submission.state.value}'"
        raise SubmissionError(msg)


async def _current_versions(
    session: AsyncSession, submission: Submission
) -> dict[str, tuple[StixObject, set[uuid.UUID]]]:
    """Each object's latest distributed version, with the circles it reached."""
    rows = (
        await session.execute(
            select(StixObject, Distribution.circle_id)
            .join(Distribution, Distribution.stix_object_id == StixObject.id)
            .where(StixObject.submission_id == submission.id)
        )
    ).all()
    latest: dict[str, tuple[StixObject, set[uuid.UUID]]] = {}
    for stored, circle_id in rows:
        held = latest.get(stored.stix_id)
        if held is None or stored.modified > held[0].modified:
            latest[stored.stix_id] = (stored, {circle_id})
        elif stored.modified == held[0].modified:
            held[1].add(circle_id)
    return latest


def _revoked_version(stored: StixObject, stamp: dt.datetime) -> StixObject:
    modified = max(stamp, stored.modified + _ONE_MILLISECOND)
    raw = {**stored.raw, "modified": format_stix_timestamp(modified), "revoked": True}
    return StixObject(
        stix_id=stored.stix_id,
        type=stored.type,
        spec_version=stored.spec_version,
        created=stored.created,
        modified=modified,
        submission_id=stored.submission_id,
        raw=raw,
        **index_columns(raw),
    )


async def revoke_contribution(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    *,
    reason: str,
    now: dt.datetime | None = None,
) -> RevocationResult:
    """Publish a revoked version of every object in ``submission``. Editors only.

    The caller holds ``submission`` under a row lock and commits once. The
    stamp is taken from the database's clock under the publication lock, as
    distribution's is (``db/clock.py``): a revocation stamped from an app
    replica's clock could land below a cursor a member already holds, and the
    member would never receive it. ``now`` is injectable for tests only.
    """
    require(is_isac_editor(ctx), "revoke_requires_isac_editor")
    if len(reason.strip()) < _MIN_REASON:
        msg = (
            f"say why, in at least {_MIN_REASON} characters: the reason is what the audit log keeps"
        )
        raise SubmissionError(msg)
    _refuse_unrevocable(submission)
    locked_at = await hold_publication_lock(session, refuse_while_paused=False)
    now = now or locked_at
    stamp = earliest_publication_instant(now)

    current = await _current_versions(session, submission)
    live = {stix_id: held for stix_id, held in current.items() if not held[0].raw.get("revoked")}
    if not live:
        msg = "every object in this submission is already revoked"
        raise SubmissionError(msg)

    circles: set[uuid.UUID] = set()
    for stored, reached in live.values():
        version = _revoked_version(stored, stamp)
        session.add(version)
        await session.flush()
        for circle_id in reached:
            session.add(
                Distribution(
                    stix_object_id=version.id,
                    circle_id=circle_id,
                    submission_id=submission.id,
                    date_added=stamp,
                )
            )
        circles |= reached

    await queue_visibility_notifications(
        session,
        submission_id=submission.id,
        circle_ids=sorted(circles, key=str),
        visible_at=stamp,
        now=stamp,
    )
    revoked_ids = sorted(live)
    await record(
        session,
        action=AuditAction.CONTRIBUTION_REVOKED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={
            "reason": reason,
            "objects": revoked_ids,
            "circles": sorted(str(circle_id) for circle_id in circles),
            "lane": submission.lane.value,
            "date_added": stamp.isoformat(),
        },
    )
    return RevocationResult(revoked_ids=revoked_ids, circle_count=len(circles), date_added=stamp)
