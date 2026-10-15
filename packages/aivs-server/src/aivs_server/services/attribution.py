"""Who filed a submission: the one module that reads or writes it (Phase P, Mike Q16).

The submitter of a submission is ISAC-only and treated as TLP:RED: shown to the
ISAC's intel staff, never to another member, never inferable from an error
(plan section P). It is held apart from ``submissions``, in the
``attribution`` schema (``SubmissionFiler``, ``ObjectOwner``). Every question
about it -- whose is this, is it the caller's, which are the caller's, which
owner does a version count as -- is asked here and nowhere else, so what can
reach the mapping is this file and not the thirty modules that ask. A test
refuses any other reader in ``src/`` (``tests/unit/test_attribution_boundary.py``).

Two kinds of caller:

- **Staff-side** questions (validate, distribute, the review queue, notices)
  get the submitter itself: ``submitter_of``, ``submitters_of``,
  ``submitter_column``, ``creator_column``.
- **The member's own** questions (its list of submissions, whether it may act
  on one) are answered only for the asking organisation: ``is_submitted_by``,
  ``submitted_by``, ``submitter_shown_to``. They never return another
  organisation's id.

``owner_tokens_for`` is ingest's: the token each version is stored with, so
that "the same owner's versions of this object" can be asked of
``stix_objects`` alone, without the mapping.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Select, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from aivs_server.db.models import ObjectOwner, Submission, SubmissionFiler

__all__ = [
    "ISAC_OWNER",
    "FilingRecord",
    "creator_column",
    "filing_record",
    "is_submitted_by",
    "owner_tokens_for",
    "record_filing",
    "submitted_by",
    "submitter_column",
    "submitter_of",
    "submitter_shown_to",
    "submitters_of",
]

#: The owner token of every version the ISAC or its automation files: they are
#: one owner (``services.ownership``), and the ISAC's authorship is public.
ISAC_OWNER: Final[str] = "isac"


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


async def record_filing(
    session: AsyncSession, submission: Submission, record: FilingRecord
) -> None:
    """Record who filed ``submission``, once its row exists (after its first flush)."""
    session.add(
        SubmissionFiler(
            submission_id=submission.id,
            org_id=record.org_id,
            created_by_operator_id=record.created_by,
            filed_by_operator_id=record.proxy_editor,
            proxy_consent_sha256=record.proxy_consent,
        )
    )
    await session.flush()


async def _filer(session: AsyncSession, submission_id: uuid.UUID) -> SubmissionFiler:
    filer = await session.get(SubmissionFiler, submission_id)
    if filer is None:
        # Every submission is created with its filer in one transaction. One
        # without it is a fault, and answering "nobody filed it" would let
        # each caller decide what nobody means.
        msg = f"submission {submission_id} has no recorded filer"
        raise LookupError(msg)
    return filer


async def submitter_of(session: AsyncSession, submission: Submission) -> uuid.UUID:
    """The organisation that filed ``submission``. Staff-side only."""
    return (await _filer(session, submission.id)).org_id


async def submitters_of(
    session: AsyncSession, submissions: Iterable[Submission]
) -> dict[uuid.UUID, uuid.UUID]:
    """Each submission's submitting organisation, by submission id. Staff-side only."""
    ids = [submission.id for submission in submissions]
    rows = await session.execute(
        select(SubmissionFiler.submission_id, SubmissionFiler.org_id).where(
            SubmissionFiler.submission_id.in_(ids)
        )
    )
    return dict(rows.tuples().all())


async def filing_record(session: AsyncSession, submission: Submission) -> FilingRecord:
    """Everything recorded about who filed ``submission``. Staff-side only."""
    filer = await _filer(session, submission.id)
    return FilingRecord(
        org_id=filer.org_id,
        created_by=filer.created_by_operator_id,
        proxy_editor=filer.filed_by_operator_id,
        proxy_consent=filer.proxy_consent_sha256,
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


async def is_submitted_by(session: AsyncSession, submission: Submission, org_id: uuid.UUID) -> bool:
    """Whether ``org_id`` filed ``submission``: the member's own question, about itself."""
    filed = await session.scalar(
        select(SubmissionFiler.submission_id).where(
            SubmissionFiler.submission_id == submission.id, SubmissionFiler.org_id == org_id
        )
    )
    return filed is not None


def submitted_by(org_id: uuid.UUID) -> Select[tuple[uuid.UUID]]:
    """The ids of the submissions ``org_id`` filed, for ``Submission.id.in_(...)``."""
    return select(SubmissionFiler.submission_id).where(SubmissionFiler.org_id == org_id)


def submitter_column(entity: Any = Submission) -> ColumnElement[uuid.UUID]:
    """The submitting organisation of ``entity`` (``Submission`` or an alias of it), in SQL.

    Staff-side queries group, join and compare by it. A member-side query
    never selects it: what a member's query needs is answered by
    ``submitted_by`` for the member alone.
    """
    return (
        select(SubmissionFiler.org_id)
        .where(SubmissionFiler.submission_id == entity.id)
        .scalar_subquery()
    )


def creator_column(entity: Any = Submission) -> ColumnElement[uuid.UUID | None]:
    """The person who filed ``entity`` in its submitter's name, in SQL. Staff-side only."""
    return (
        select(SubmissionFiler.created_by_operator_id)
        .where(SubmissionFiler.submission_id == entity.id)
        .scalar_subquery()
    )


async def owner_tokens_for(
    session: AsyncSession, org_id: uuid.UUID, stix_ids: Iterable[str], *, owner_is_isac: bool
) -> dict[str, str]:
    """The owner token ``org_id``'s versions of each id are stored with (``ObjectOwner``).

    The ISAC's are ``ISAC_OWNER``. A member's are found or made, one per id:
    inserted with ``ON CONFLICT DO NOTHING`` and read back, so two filings of
    one new id racing each other agree on one token.
    """
    ids = sorted(set(stix_ids))
    if owner_is_isac:
        return dict.fromkeys(ids, ISAC_OWNER)
    if not ids:
        return {}
    await session.execute(
        insert(ObjectOwner)
        .values(
            [
                {"owner_token": str(uuid.uuid4()), "stix_id": stix_id, "org_id": org_id}
                for stix_id in ids
            ]
        )
        .on_conflict_do_nothing(index_elements=["stix_id", "org_id"])
    )
    rows = await session.execute(
        select(ObjectOwner.stix_id, ObjectOwner.owner_token).where(
            ObjectOwner.org_id == org_id, ObjectOwner.stix_id.in_(ids)
        )
    )
    return dict(rows.tuples().all())
