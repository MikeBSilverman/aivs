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
  ``submissions_filed_by``, ``submitter_shown_to``. They never return another
  organisation's id.

``owner_tokens_for`` is ingest's: the token each version is stored with, so
that "the same owner's versions of this object" can be asked of
``stix_objects`` alone, without the mapping.

Tags and tokens are HMACs under the attribution key (``auth.attribution_key``,
SF-90), which the database never holds: the member path computes them, and SQL
can neither compute nor reverse one. ``rekey`` recomputes every one of them
under a new key from the mapping, and ``values_under_other_keys`` is what
startup asks before it serves anything.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final, cast

from sqlalchemy import String, func, select, update
from sqlalchemy import cast as sql_cast
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from aivs_server.audit.log import AuditAction
from aivs_server.auth.attribution_key import AttributionKey
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import uses_staff_database
from aivs_server.db.engine import get_sessionmaker
from aivs_server.db.models import AuditLog, StixObject, Submission, SubmissionFiler

__all__ = [
    "ISAC_OWNER",
    "FilerNotKnownToCallerError",
    "FilingRecord",
    "RekeyCounts",
    "creator_column",
    "filed_by",
    "filer_known_to",
    "filing_record",
    "filings_with_a_wrong_tag",
    "filings_without_their_record",
    "is_submitted_by",
    "owner_tokens_for",
    "record_filing",
    "rekey",
    "submissions_filed_by",
    "submitter_column",
    "submitter_of",
    "submitter_shown_to",
    "submitters_of",
    "values_under_other_keys",
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
    session: AsyncSession, key: AttributionKey, submission: Submission, record: FilingRecord
) -> None:
    """Add the new ``submission``, tagged with its filer, and record who filed it.

    The tag is bound to the submission's id, which SQLAlchemy would otherwise
    choose only at INSERT; so the id is chosen here, before the row exists
    (CLAUDE.md section 5, "a value bound to a row id").
    """
    # The annotation says UUID; before the INSERT the attribute is None.
    if cast("uuid.UUID | None", submission.id) is None:
        submission.id = uuid.uuid4()
    submission.owner_tag = key.owner_tag(record.org_id, submission.id)
    session.add(submission)
    await session.flush()
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


class FilerNotKnownToCallerError(LookupError):
    """A member's request asked who filed a submission it did not file.

    The member path cannot read the mapping (Phase P), and every route checks
    the caller's rights before it gets here, so this is a fault in the route,
    not a refusal to report.
    """


async def filer_known_to(
    session: AsyncSession, key: AttributionKey, ctx: AuthContext, submission: Submission
) -> uuid.UUID:
    """Who filed ``submission``, learned the way ``ctx`` may learn it.

    The caller itself when the tag says so, without reading the mapping, which
    holds inside the transaction that filed it and on the member login. Read
    from the mapping only on the staff login, for the ISAC acting on another
    organisation's filing.
    """
    if is_submitted_by(key, submission, ctx.org_id):
        return ctx.org_id
    if not uses_staff_database(ctx):
        msg = f"organisation {ctx.org_id} did not file submission {submission.id}"
        raise FilerNotKnownToCallerError(msg)
    filer: uuid.UUID = await submitter_of(session, submission)
    return filer


async def submitter_shown_to(
    session: AsyncSession, key: AttributionKey, submission: Submission, ctx: AuthContext
) -> uuid.UUID | None:
    """The submitter as ``ctx`` sees it on an ordinary read, or ``None``.

    An anonymous submission's submitter is shown to that submitter alone.
    Every other reader -- ISAC staff included -- names it only through the
    reveal, which is audited with its reason (``POST /submissions/{id}/reveal``).

    A member is answered from the tag and never reads the mapping (Phase P):
    the submitter it may be shown is itself. It sees no other firm's filing
    (``policy.can_view_submission``), so for one it is shown nobody.
    """
    if is_submitted_by(key, submission, ctx.org_id):
        return ctx.org_id
    if not uses_staff_database(ctx) or submission.distribute_anonymously:
        return None
    submitter: uuid.UUID = await submitter_of(session, submission)
    return submitter


def is_submitted_by(key: AttributionKey, submission: Submission, org_id: uuid.UUID) -> bool:
    """Whether ``org_id`` filed ``submission``: the member's own question, about itself.

    Answered from the submission's tag, without reading the mapping, so it
    holds within the transaction that filed the submission and on a login that
    cannot read ``attribution``. A tag under another key raises
    ``ForeignAttributionKeyError``: a fault, not "no".
    """
    return key.is_owner_tag(submission.owner_tag, org_id, submission.id)


async def submissions_filed_by(org_id: uuid.UUID) -> list[uuid.UUID]:
    """The ids of the submissions ``org_id`` filed: a member's own list, read staff side.

    On a session of its own, on the staff login, over committed rows. The
    member login is refused ``attribution`` (Phase P slice 3c), and a member's
    lists are the one read of it a member's request still makes; so the read
    happens here, for the asking organisation only, and only ids leave. A
    filing made earlier in the caller's own, uncommitted transaction is not
    in the list: no caller asks for one.
    """
    async with get_sessionmaker()() as staff:
        filed = await staff.scalars(
            select(SubmissionFiler.submission_id).where(SubmissionFiler.org_id == org_id)
        )
        return list(filed)


def submitter_column(entity: Any = Submission) -> ColumnElement[uuid.UUID]:
    """The submitting organisation of ``entity`` (``Submission`` or an alias of it), in SQL.

    Staff-side queries group, join and compare by it. A member-side query
    never selects it: what a member's query needs is answered by
    ``submissions_filed_by`` for the member alone.
    """
    return (
        select(SubmissionFiler.org_id)
        .where(SubmissionFiler.submission_id == entity.id)
        .scalar_subquery()
    )


def filed_by(org_id: uuid.UUID, submission_id: Any) -> ColumnElement[bool]:
    """``submission_id`` was filed by ``org_id``, in SQL. Staff side only.

    The organisation filter on each of ``member_staff_reads``' reads of a
    member's own submission: the one guard on a staff connection opened on a
    member's behalf.
    """
    return (
        select(SubmissionFiler.submission_id)
        .where(SubmissionFiler.submission_id == submission_id, SubmissionFiler.org_id == org_id)
        .exists()
    )


async def filings_without_their_record(
    session: AsyncSession, *, since: dt.datetime
) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """Filings since ``since`` whose filer is not the one their creation was audited for.

    ``(submission id, recorded filer)``. Staff side only. The member login may
    insert into ``attribution.submitters`` -- it records its own filings -- and
    may not read it, so SQL injected on the member path could record a filing
    in another firm's name, or a whole submission with no audit row at all.
    Every filing the application makes goes through ``create_submission``,
    which writes the filer and a ``submission.created`` row naming the
    authenticated organisation, or the member a proxy filing is for, in one
    transaction; a filer that no such row names was not recorded by it.
    """
    audited_filer = func.coalesce(
        AuditLog.details["filed_for"].astext, sql_cast(AuditLog.org_id, String)
    )
    its_creation = (
        select(AuditLog.id)
        .where(
            AuditLog.action == AuditAction.SUBMISSION_CREATED,
            AuditLog.resource_id == sql_cast(SubmissionFiler.submission_id, String),
            audited_filer == sql_cast(SubmissionFiler.org_id, String),
        )
        .exists()
    )
    rows = await session.execute(
        select(SubmissionFiler.submission_id, SubmissionFiler.org_id)
        .join(Submission, Submission.id == SubmissionFiler.submission_id)
        .where(Submission.created_at >= since, ~its_creation)
        .order_by(SubmissionFiler.submission_id)
    )
    return [(submission_id, org_id) for submission_id, org_id in rows.all()]


async def filings_with_a_wrong_tag(
    session: AsyncSession, key: AttributionKey, *, since: dt.datetime
) -> list[tuple[uuid.UUID, uuid.UUID | None]]:
    """Submissions since ``since`` whose owner tag is not their recorded filer's.

    ``(submission id, recorded filer or None)``. Staff side only. A tag that
    names no organisation gives nobody the submitter's verbs
    (``submissions.is_isac_filing``), which is safe and silent; this is where
    the corruption is noticed instead. The member login may write a tag and
    cannot compute one, so a wrong tag is a row the application did not write,
    or a filing with no filer at all.
    """
    rows = await session.execute(
        select(Submission.id, Submission.owner_tag, SubmissionFiler.org_id)
        .outerjoin(SubmissionFiler, SubmissionFiler.submission_id == Submission.id)
        .where(Submission.created_at >= since)
        .order_by(Submission.id)
    )
    return [
        (submission_id, filer)
        for submission_id, tag, filer in rows.all()
        if filer is None or tag != key.owner_tag(filer, submission_id)
    ]


def creator_column(entity: Any = Submission) -> ColumnElement[uuid.UUID | None]:
    """The person who filed ``entity`` in its submitter's name, in SQL. Staff-side only."""
    return (
        select(SubmissionFiler.created_by_operator_id)
        .where(SubmissionFiler.submission_id == entity.id)
        .scalar_subquery()
    )


def owner_tokens_for(
    key: AttributionKey, org_id: uuid.UUID, stix_ids: Iterable[str], *, owner_is_isac: bool
) -> dict[str, str]:
    """The owner token ``org_id``'s versions of each id are stored with.

    The ISAC's are ``ISAC_OWNER``. A member's are computed, so two filings of
    one new id agree on one token without reading anything back.
    """
    ids = set(stix_ids)
    if owner_is_isac:
        return dict.fromkeys(ids, ISAC_OWNER)
    return {stix_id: key.owner_token(org_id, stix_id) for stix_id in ids}


async def values_under_other_keys(session: AsyncSession, key: AttributionKey) -> list[str]:
    """Which columns hold a tag or token not made under ``key``; empty when none do.

    Startup refuses an instance where this is not empty: a half-finished
    rotation would make ingest store a member's new versions under a token
    that no longer matches its old ones, so its own object would read as
    another owner's.
    """
    pattern = f"{key.prefix}%"
    foreign_tag = await session.scalar(
        select(Submission.id).where(Submission.owner_tag.not_like(pattern)).limit(1)
    )
    foreign_token = await session.scalar(
        select(StixObject.id)
        .where(StixObject.owner_token != ISAC_OWNER, StixObject.owner_token.not_like(pattern))
        .limit(1)
    )
    found = {"submissions.owner_tag": foreign_tag, "stix_objects.owner_token": foreign_token}
    return [column for column, row in found.items() if row is not None]


@dataclass(frozen=True, slots=True)
class RekeyCounts:
    tags: int
    tokens: int


async def rekey(session: AsyncSession, key: AttributionKey) -> RekeyCounts:
    """Recompute every tag and every member's token under ``key``. The caller commits.

    Only the mapping is needed, never the key being replaced: a version's owner
    is the filer of its submission (a revocation is written into the same
    submission, ``services.revocation``), and the ISAC's token names no key.
    """
    filers = (
        await session.execute(select(SubmissionFiler.submission_id, SubmissionFiler.org_id))
    ).all()
    tags = [
        {"id": submission_id, "owner_tag": key.owner_tag(org_id, submission_id)}
        for submission_id, org_id in filers
    ]
    versions = (
        await session.execute(
            select(StixObject.id, StixObject.stix_id, SubmissionFiler.org_id)
            .join(SubmissionFiler, SubmissionFiler.submission_id == StixObject.submission_id)
            .where(StixObject.owner_token != ISAC_OWNER)
        )
    ).all()
    tokens = [
        {"id": version_id, "owner_token": key.owner_token(org_id, stix_id)}
        for version_id, stix_id, org_id in versions
    ]
    if tags:
        await session.execute(update(Submission), tags)
    if tokens:
        await session.execute(update(StixObject), tokens)
    return RekeyCounts(tags=len(tags), tokens=len(tokens))
