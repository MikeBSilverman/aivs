"""Who filed a submission: the one module that reads or writes it (Phase P, Mike Q16).

The submitter of a submission is ISAC-only and treated as TLP:RED: shown to the
ISAC's intel staff, never to another member, never inferable from an error
(plan section P). Every question about it -- whose is this, is it the
caller's, which are the caller's, which organisation does a query group by --
is asked here and nowhere else, so that what can reach the mapping is this
file and not the thirty modules that ask. A test refuses any other reader in
``src/`` (``tests/unit/test_attribution_boundary.py``).

Two kinds of caller:

- **Staff-side** questions (validate, distribute, the review queue, notices)
  get the submitter itself: ``submitter_of``, ``submitter_column``.
- **The member's own** questions (its list of submissions, whether it may act
  on one) are answered only for the asking organisation: ``is_submitted_by``,
  ``submitted_by``. They never return another organisation's id.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from aivs_server.db.models import Submission

__all__ = [
    "FilingRecord",
    "creator_column",
    "filing_record",
    "is_submitted_by",
    "record_filing",
    "submitted_by",
    "submitter_column",
    "submitter_of",
    "submitter_shown_to",
    "submitters_of",
]


@dataclass(frozen=True, slots=True)
class FilingRecord:
    """Who filed a submission, and for whom.

    ``created_by`` is the person who filed it in the submitter's name, ``None``
    for a machine. ``proxy_editor`` and ``proxy_consent`` are set together, on
    an ISAC analyst's filing for a member (SF-68): the analyst, and the SHA-256
    of the member's consent artefact.
    """

    org_id: uuid.UUID
    created_by: uuid.UUID | None
    proxy_editor: uuid.UUID | None
    proxy_consent: str | None


def record_filing(submission: Submission, record: FilingRecord) -> None:
    """Attach ``record`` to a submission that is being created, before its first flush."""
    submission.submitter_org_id = record.org_id
    submission.created_by_operator_id = record.created_by
    submission.filed_by_operator_id = record.proxy_editor
    submission.proxy_consent_sha256 = record.proxy_consent


async def submitter_of(_session: AsyncSession, submission: Submission) -> uuid.UUID:
    """The organisation that filed ``submission``. Staff-side only."""
    return submission.submitter_org_id


async def submitters_of(
    _session: AsyncSession, submissions: Iterable[Submission]
) -> dict[uuid.UUID, uuid.UUID]:
    """Each submission's submitting organisation, by submission id. Staff-side only."""
    return {submission.id: submission.submitter_org_id for submission in submissions}


async def filing_record(_session: AsyncSession, submission: Submission) -> FilingRecord:
    """Everything recorded about who filed ``submission``. Staff-side only."""
    return FilingRecord(
        org_id=submission.submitter_org_id,
        created_by=submission.created_by_operator_id,
        proxy_editor=submission.filed_by_operator_id,
        proxy_consent=submission.proxy_consent_sha256,
    )


async def submitter_shown_to(
    session: AsyncSession, submission: Submission, org_id: uuid.UUID
) -> uuid.UUID | None:
    """The submitter as a caller at ``org_id`` sees it on an ordinary read, or ``None``.

    An anonymous submission's submitter is shown to that submitter alone.
    Every other reader -- ISAC staff included -- names it only through the
    reveal, which is audited with its reason (``POST /submissions/{id}/reveal``).
    """
    submitter = await submitter_of(session, submission)
    if submission.distribute_anonymously and submitter != org_id:
        return None
    return submitter


async def is_submitted_by(
    _session: AsyncSession, submission: Submission, org_id: uuid.UUID
) -> bool:
    """Whether ``org_id`` filed ``submission``: the member's own question, about itself."""
    return submission.submitter_org_id == org_id


def submitted_by(org_id: uuid.UUID) -> Select[tuple[uuid.UUID]]:
    """The ids of the submissions ``org_id`` filed, for ``Submission.id.in_(...)``."""
    return select(Submission.id).where(Submission.submitter_org_id == org_id)


def submitter_column(entity: Any = Submission) -> ColumnElement[uuid.UUID]:
    """The submitting organisation of ``entity`` (``Submission`` or an alias of it), in SQL.

    Staff-side queries group, join and compare by it. A member-side query
    never selects it: what a member's query needs is answered by
    ``submitted_by`` for the member alone.
    """
    column: ColumnElement[uuid.UUID] = entity.submitter_org_id
    return column


def creator_column(entity: Any = Submission) -> ColumnElement[uuid.UUID | None]:
    """The person who filed ``entity`` in its submitter's name, in SQL. Staff-side only."""
    column: ColumnElement[uuid.UUID | None] = entity.created_by_operator_id
    return column
