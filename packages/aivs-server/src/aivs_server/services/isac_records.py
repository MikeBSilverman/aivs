"""The ISAC's own canonical vulnerability records, as its automation reads them to version them.

The KEV enrichment script files a newer version of each of the ISAC's records
that KEV lists. It runs as the automation organisation, which reads no circle,
so it needs a read of exactly those records: the ISAC's own, chosen by owner
(``ownership.owner_key``), never by ``created_by_ref``. Distribution rewrites
``created_by_ref`` to the ISAC's identity on every *anonymous* member
submission too, so selecting on it would hand the automation members' content
and invite it to version that content as the ISAC's.

Only the newest version of each record is returned, and only when that newest
version may be read (``policy.isac_record_read_clause``). If the newest is
still under embargo the record is left out entirely rather than answered with
the version before it: a KEV version built on the older content would carry a
later ``modified`` and replace the embargoed content in every TIP on release.
A record with a version still in review (submitted or validated, not yet
distributed or withdrawn) is left out for the same reason: once both are out,
the KEV version built on the older content would outrank the reviewed one. Any
version in review holds the record back, not only one with a later
``modified``: the read fails closed, and a review that resolves releases it.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from aivs_schemas.enums import VISIBLE_SUBMISSION_STATES, SubmissionSource, SubmissionState
from aivs_server.auth.policy import isac_record_read_clause
from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.services.ownership import ISAC_OWNER, owner_key

__all__ = ["IsacRecords", "latest_isac_vulnerabilities"]

#: States in which a version is on its way to distribution and may still get there.
#: Not DRAFT, deliberately: a draft nobody sends would otherwise hold the KEV
#: script back from that record forever. A draft correction overtaken by a KEV
#: version is not lost silently either: newest-version-only (SF-82,
#: ``ownership.stale_version_problem``) refuses it at validate and distribution,
#: and the editor refiles it with a later ``modified``.
_IN_REVIEW_STATES = (SubmissionState.SUBMITTED, SubmissionState.VALIDATED)


def _newest_isac_versions() -> Any:
    """The id of the newest distributed, visible-state version of each ISAC vulnerability."""
    distributed = exists().where(Distribution.stix_object_id == StixObject.id)
    return (
        select(StixObject.id)
        .join(Submission, Submission.id == StixObject.submission_id)
        .where(
            StixObject.type == "vulnerability",
            owner_key(Submission.submitter_org_id) == ISAC_OWNER,
            Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)),
            distributed,
        )
        .distinct(StixObject.stix_id)
        .order_by(StixObject.stix_id, StixObject.modified.desc())
    )


def _has_version_in_review() -> Any:
    """Whether the ISAC has a version of this object's record in review."""
    pending = aliased(StixObject)
    pending_submission = aliased(Submission)
    return (
        exists()
        .where(
            pending.stix_id == StixObject.stix_id,
            pending_submission.id == pending.submission_id,
            owner_key(pending_submission.submitter_org_id) == ISAC_OWNER,
            pending_submission.state.in_(_IN_REVIEW_STATES),
        )
        .correlate(StixObject)
    )


def _has_waiting_kev_draft() -> Any:
    """Whether the automation's own draft of this record waits for an editor.

    It holds the record back (Q35): without that, every run files another draft
    of it. Only the automation's (source ``system``); an editor's or analyst's
    forgotten draft still holds nothing. The cost is that KEV updates to the
    record stall until an editor acts, so the stall is counted and shown --
    in the script's summary and on the status page -- rather than silent.
    """
    pending = aliased(StixObject)
    pending_submission = aliased(Submission)
    return (
        exists()
        .where(
            pending.stix_id == StixObject.stix_id,
            pending_submission.id == pending.submission_id,
            owner_key(pending_submission.submitter_org_id) == ISAC_OWNER,
            pending_submission.state == SubmissionState.DRAFT,
            pending_submission.source == SubmissionSource.SYSTEM,
        )
        .correlate(StixObject)
    )


@dataclass(frozen=True)
class IsacRecords:
    #: The newest readable version of each record the automation may version now.
    objects: list[dict[str, Any]]
    #: Records left out only because the automation's own draft of them waits.
    waiting_drafts: int


async def latest_isac_vulnerabilities(session: AsyncSession, *, now: dt.datetime) -> IsacRecords:
    """The newest version of each of the ISAC's vulnerability records, where it may be read."""
    newest = _newest_isac_versions().subquery()
    rows = await session.execute(
        select(StixObject.raw, _has_waiting_kev_draft())
        .distinct(StixObject.stix_id)
        .join(Submission, Submission.id == StixObject.submission_id)
        .join(Distribution, Distribution.stix_object_id == StixObject.id)
        .where(
            StixObject.id.in_(select(newest.c.id)),
            isac_record_read_clause(now),
            ~_has_version_in_review(),
        )
        .order_by(StixObject.stix_id)
    )
    found = rows.all()
    return IsacRecords(
        objects=[dict(raw) for raw, waiting in found if not waiting],
        waiting_drafts=sum(1 for _raw, waiting in found if waiting),
    )
