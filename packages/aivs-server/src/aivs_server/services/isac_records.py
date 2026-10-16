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
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy import ColumnElement, and_, exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from aivs_schemas.enums import VISIBLE_SUBMISSION_STATES, SubmissionSource, SubmissionState
from aivs_schemas.extension.builders import CONDITION_IMPORT_REFERENCE
from aivs_server.auth.policy import isac_record_read_clause
from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.services.ownership import ISAC_OWNER

__all__ = [
    "HeldBackNote",
    "ImportedNote",
    "ImportedNotes",
    "IsacRecords",
    "latest_imported_condition_notes",
    "latest_isac_vulnerabilities",
]

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
            StixObject.owner_token == ISAC_OWNER,
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
            pending.owner_token == ISAC_OWNER,
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
            pending.owner_token == ISAC_OWNER,
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


# ---------------------------------------------------------------------------
# The condition import's own notes (Phase N intake)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ImportedNote:
    #: The newest readable version, which the import compares and versions.
    raw: dict[str, Any]
    #: Whether that version came from the automation. One an editor filed is
    #: the analyst's correction, and the import leaves it alone.
    machine_filed: bool


@dataclass(frozen=True)
class HeldBackNote:
    """An imported note the import must not file again: what it is about, from where."""

    note_id: str
    about: list[str]
    source: str | None


@dataclass(frozen=True)
class ImportedNotes:
    notes: list[ImportedNote]
    held_back: list[HeldBackNote]


def _imported_isac_note() -> ColumnElement[bool]:
    """A note the ISAC owns that carries the import's reference: the import's own filings.

    Owned by the ISAC, so a member's note is never in either list, however it
    is marked: the read answers what the refile check needs and nothing more.
    """
    return and_(
        StixObject.type == "note",
        StixObject.owner_token == ISAC_OWNER,
        StixObject.raw["external_references"].contains(
            [{"source_name": CONDITION_IMPORT_REFERENCE}]
        ),
    )


def _newest_imported_versions() -> Any:
    """The id of the newest distributed, visible-state version of each imported note."""
    distributed = exists().where(Distribution.stix_object_id == StixObject.id)
    return (
        select(StixObject.id)
        .join(Submission, Submission.id == StixObject.submission_id)
        .where(
            _imported_isac_note(),
            Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)),
            distributed,
        )
        .distinct(StixObject.stix_id)
        .order_by(StixObject.stix_id, StixObject.modified.desc())
    )


def _still_counts() -> ColumnElement[bool]:
    """A version that keeps its note from being filed afresh.

    Distributed or on its way there, or the automation's own draft (Q35, as
    for KEV). A withdrawn version, or an editor's abandoned draft, holds
    nothing: the import then files the note again, as KEV refiles a record.
    """
    distributed = exists().where(Distribution.stix_object_id == StixObject.id)
    return or_(
        Submission.state.in_(_IN_REVIEW_STATES),
        and_(
            Submission.state == SubmissionState.DRAFT,
            Submission.source == SubmissionSource.SYSTEM,
        ),
        and_(Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)), distributed),
    )


def _held_back(raw: Mapping[str, Any]) -> HeldBackNote:
    references = raw.get("external_references") or []
    source = next(
        (
            ref.get("external_id")
            for ref in references
            if isinstance(ref, Mapping) and ref.get("source_name") == CONDITION_IMPORT_REFERENCE
        ),
        None,
    )
    return HeldBackNote(
        note_id=str(raw["id"]), about=list(raw.get("object_refs") or []), source=source
    )


async def latest_imported_condition_notes(
    session: AsyncSession, *, now: dt.datetime
) -> ImportedNotes:
    """The import's own notes: those it may version now, and those it must leave be.

    A note is served under the vulnerability read's rules: its newest
    distributed version, readable, with nothing in review and no automation
    draft waiting. Every other imported note is held back -- in review, a
    draft waiting, or a newest version the import may not read (embargoed,
    RED). Held back rather than left out: to the import, a note it cannot
    see is a note it has not filed, and it would file it again.
    """
    newest = _newest_imported_versions().subquery()
    served_rows = (
        await session.execute(
            select(StixObject.raw, Submission.source)
            .join(Submission, Submission.id == StixObject.submission_id)
            .join(Distribution, Distribution.stix_object_id == StixObject.id)
            .where(
                StixObject.id.in_(select(newest.c.id)),
                isac_record_read_clause(now),
                ~_has_version_in_review(),
                ~_has_waiting_kev_draft(),
            )
            .distinct(StixObject.stix_id)
            .order_by(StixObject.stix_id)
        )
    ).all()
    notes = [
        ImportedNote(raw=dict(raw), machine_filed=source is SubmissionSource.SYSTEM)
        for raw, source in served_rows
    ]
    served = {note.raw["id"] for note in notes}
    known = (
        await session.execute(
            select(StixObject.raw)
            .join(Submission, Submission.id == StixObject.submission_id)
            .where(_imported_isac_note(), _still_counts())
            .distinct(StixObject.stix_id)
            .order_by(StixObject.stix_id, StixObject.modified.desc())
        )
    ).scalars()
    held_back = [_held_back(raw) for raw in known if raw["id"] not in served]
    return ImportedNotes(notes=notes, held_back=held_back)
