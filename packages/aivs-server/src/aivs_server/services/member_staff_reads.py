"""The one place a member's request opens the staff login (Phase P, slice 3c).

The member login may write, and may not read, every table that says who filed
what: ``attribution`` and the tables that would say it by another route
(``db.grants.MEMBER_GRANTS``). Every member organisation shares that login, so
a read it could make for one member, SQL injected on the member path could
make for all of them. Yet a member is entitled to its own rows in those
tables: its submission's history, its TAXII status resources, its connection's
last retrieval, its telemetry, its first-pass findings, its auditor's trail;
and since slice 3e, which holds the member login to nothing on ``operators``
or ``org_postures`` and to writing ``acknowledgments``, its own signed-in
person's name and reading depth, its own receipts and its own postures (R26).
Each function here
answers one of those questions on a staff session of its own.

Every function holds one invariant, and nothing else here makes it true:

* for a member caller it opens its own staff session, keyed on ``ctx.org_id``
  (or the organisation it is given), returns only that organisation's rows,
  and never returns the session;
* for a caller already on the staff login (``policy.uses_staff_database``) it
  reads on that caller's own session, unfiltered, as the ISAC always has.

The organisation filter is therefore the only guard on a staff connection, and
each function's has a test that a peer's rows never come back and a mutation
that drops it. ``tests/unit/test_staff_session_reach.py`` refuses the staff
sessionmaker in any request-reachable module but this one and
``services.attribution``, so a new staff read on a member's behalf has to come
here and be written to the invariant.

Reads see committed rows only. Each caller was checked for whether it needs one
written earlier in its own transaction; none does, and each says why.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import AsyncIterator, Iterable, Sequence
from contextlib import asynccontextmanager

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import PostureStatus, ReadingDepth
from aivs_server.audit.log import AuditAction
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import audit_scope, uses_staff_database
from aivs_server.db.engine import get_sessionmaker
from aivs_server.db.models import (
    AuditLog,
    CountSnapshot,
    CountSubject,
    Operator,
    OrgPosture,
    SubmissionTransition,
    SubmissionTriage,
    TaxiiStatus,
    Webhook,
    WebhookDelivery,
)
from aivs_server.services.acknowledgments import retrieved_submission_ids
from aivs_server.services.attribution import filed_by
from aivs_server.services.audit_stream import Cursor, Page, audit_events, receipt_events
from aivs_server.services.evidence_pack import EvidencePack, evidence_pack
from aivs_server.services.posture_reads import (
    own_posture,
    own_posture_count,
    own_posture_status,
    own_postures,
)
from aivs_server.services.vulnerability_objects import last_read_at

__all__ = [
    "audit_page",
    "first_pass_of",
    "inbox_posts_since",
    "last_retrieval",
    "own_actioned_count",
    "own_default_depth",
    "own_display_name",
    "own_evidence_pack",
    "own_last_portal_read",
    "own_posture_of",
    "own_posture_on",
    "own_postures_of",
    "own_retrievals",
    "own_webhooks",
    "receipt_page",
    "submission_history",
    "taxii_status_of",
    "telemetry_snapshot",
    "webhook_delivery_counts",
]


@asynccontextmanager
async def _reader(ctx: AuthContext) -> AsyncIterator[AsyncSession | None]:
    """The session to read on: the caller's own when it is staff, else a staff session.

    Yields ``None`` in place of the session for a staff caller, so each
    function below says in one place which branch adds the organisation filter.
    """
    if uses_staff_database(ctx):
        yield None
        return
    async with get_sessionmaker()() as staff:
        yield staff


async def submission_history(
    session: AsyncSession, ctx: AuthContext, submission_id: uuid.UUID
) -> list[SubmissionTransition]:
    """A submission's transitions, oldest first; for a member, only on its own filing.

    Each row names the organisation that acted, beside the submission. A
    member sees its own filing's history and no other's.
    """
    query = (
        select(SubmissionTransition)
        .where(SubmissionTransition.submission_id == submission_id)
        .order_by(SubmissionTransition.at, SubmissionTransition.id)
    )
    async with _reader(ctx) as staff:
        if staff is None:
            return list((await session.execute(query)).scalars())
        query = query.where(filed_by(ctx.org_id, submission_id))
        return list((await staff.execute(query)).scalars())


async def first_pass_of(
    session: AsyncSession, ctx: AuthContext, submission_id: uuid.UUID
) -> SubmissionTriage | None:
    """The newest first-pass read of a submission; for a member, only of its own filing.

    A finding names the field where the text names its own submitter, which
    with the stored text says who filed it.
    """
    query = (
        select(SubmissionTriage)
        .where(SubmissionTriage.submission_id == submission_id)
        .order_by(SubmissionTriage.transition_id.desc())
        .limit(1)
    )
    async with _reader(ctx) as staff:
        if staff is None:
            row: SubmissionTriage | None = await session.scalar(query)
            return row
        own: SubmissionTriage | None = await staff.scalar(
            query.where(filed_by(ctx.org_id, submission_id))
        )
        return own


async def telemetry_snapshot(
    session: AsyncSession, ctx: AuthContext, submission_id: uuid.UUID
) -> CountSnapshot | None:
    """The last published telemetry counts of a submission; for a member, only its own.

    A snapshot's basis is the organisations in reach, which leaves out the
    submitter: the circle member missing from it filed the submission.
    """
    query = select(CountSnapshot).where(
        CountSnapshot.subject_kind == CountSubject.TELEMETRY.value,
        CountSnapshot.subject_id == str(submission_id),
    )
    async with _reader(ctx) as staff:
        if staff is None:
            row: CountSnapshot | None = await session.scalar(query)
            return row
        own: CountSnapshot | None = await staff.scalar(
            query.where(filed_by(ctx.org_id, submission_id))
        )
        return own


async def taxii_status_of(
    session: AsyncSession, ctx: AuthContext, status_id: uuid.UUID
) -> TaxiiStatus | None:
    """A TAXII status resource, if the caller's organisation made the request."""
    query = select(TaxiiStatus).where(TaxiiStatus.id == status_id)
    async with _reader(ctx) as staff:
        reader = session if staff is None else staff
        row: TaxiiStatus | None = await reader.scalar(query.where(TaxiiStatus.org_id == ctx.org_id))
        return row


async def inbox_posts_since(org_id: uuid.UUID, since: dt.datetime) -> int:
    """How many objects POSTs ``org_id`` made to the inbox since ``since``.

    Counted over committed rows, under the caller's allowance lock: the
    previous holder of the lock has committed, and the caller's own POST is
    recorded after the count.
    """
    async with get_sessionmaker()() as staff:
        count = await staff.scalar(
            select(func.count())
            .select_from(TaxiiStatus)
            .where(TaxiiStatus.org_id == org_id, TaxiiStatus.request_timestamp >= since)
        )
    return count or 0


async def last_retrieval(
    session: AsyncSession, ctx: AuthContext, collection_id: uuid.UUID
) -> dt.datetime | None:
    """When the caller's organisation last collected content from ``collection_id``.

    Read from the audit log, whose rows name the acting organisation beside
    what it did.
    """
    query = select(func.max(AuditLog.at)).where(
        AuditLog.org_id == ctx.org_id,
        AuditLog.action == AuditAction.OBJECTS_RETRIEVED,
        AuditLog.resource_type == "collection",
        AuditLog.resource_id == str(collection_id),
    )
    async with _reader(ctx) as staff:
        reader = session if staff is None else staff
        last: dt.datetime | None = await reader.scalar(query)
        return last


async def webhook_delivery_counts(
    session: AsyncSession, ctx: AuthContext
) -> Sequence[tuple[Webhook, dt.datetime | None, int]]:
    """Each of the caller's webhooks, its last delivery, and how many wait undelivered.

    A delivery's payload names the submission it announces, and a telemetry
    event goes to the submitter's webhooks alone.
    """
    delivered = func.max(WebhookDelivery.delivered_at)
    undelivered = func.count(WebhookDelivery.id).filter(WebhookDelivery.delivered_at.is_(None))
    query = (
        select(Webhook, delivered, undelivered)
        .outerjoin(WebhookDelivery, WebhookDelivery.webhook_id == Webhook.id)
        .where(Webhook.org_id == ctx.org_id)
        .group_by(Webhook.id)
        .order_by(Webhook.created_at)
    )
    async with _reader(ctx) as staff:
        reader = session if staff is None else staff
        rows = (await reader.execute(query)).all()
        return [(webhook, last, int(pending)) for webhook, last, pending in rows]


async def audit_page(
    session: AsyncSession, ctx: AuthContext, *, after: Cursor | None, limit: int
) -> Page:
    """A page of the audit trail within the caller's scope (``policy.audit_scope``).

    A member's auditor reads its own organisation's rows; the ISAC's reads the
    instance, on its own session. Both branches ask ``audit_scope``, so
    the policy stays the one description of whose rows a caller reads.
    """
    async with _reader(ctx) as staff:
        if staff is None:
            return await audit_events(session, scope=audit_scope(ctx), after=after, limit=limit)
        return await audit_events(staff, scope=audit_scope(ctx), after=after, limit=limit)


async def own_display_name(session: AsyncSession, ctx: AuthContext) -> str | None:
    """The signed-in person's name; ``None`` for a machine, or a person who has gone.

    Keyed on the operator authentication resolved, and on its organisation.
    """
    if ctx.operator_id is None:
        return None
    query = select(Operator.display_name).where(
        Operator.id == ctx.operator_id, Operator.org_id == ctx.org_id
    )
    async with _reader(ctx) as staff:
        name: str | None = await (staff or session).scalar(query)
        return name


async def own_default_depth(session: AsyncSession, ctx: AuthContext) -> ReadingDepth | None:
    """The signed-in person's chosen reading depth, if any; a machine has none.

    Keyed on the operator authentication resolved, and on its organisation.
    """
    if ctx.operator_id is None:
        return None
    query = select(Operator.default_depth).where(
        Operator.id == ctx.operator_id, Operator.org_id == ctx.org_id
    )
    async with _reader(ctx) as staff:
        depth: ReadingDepth | None = await (staff or session).scalar(query)
        return depth


async def receipt_page(
    session: AsyncSession, ctx: AuthContext, *, after: Cursor | None, limit: int
) -> Page:
    """A page of receipts within the caller's scope (``policy.audit_scope``).

    A member's auditor reads its own organisation's receipts; the ISAC's reads
    the instance, on its own session.
    """
    async with _reader(ctx) as staff:
        return await receipt_events(
            staff or session, scope=audit_scope(ctx), after=after, limit=limit
        )


async def own_retrievals(
    session: AsyncSession, ctx: AuthContext, submission_ids: frozenset[uuid.UUID]
) -> frozenset[uuid.UUID]:
    """Which of ``submission_ids`` the server has recorded reaching the caller's organisation."""
    async with _reader(ctx) as staff:
        return await retrieved_submission_ids(staff or session, ctx.org_id, submission_ids)


async def own_last_portal_read(
    session: AsyncSession, ctx: AuthContext, submission_ids: Iterable[uuid.UUID]
) -> dt.datetime | None:
    """When a person at the caller's organisation last read these submissions in the portal."""
    async with _reader(ctx) as staff:
        return await last_read_at(staff or session, ctx.org_id, submission_ids)


async def own_evidence_pack(
    session: AsyncSession, ctx: AuthContext, vulnerability_stix_id: str, *, now: dt.datetime
) -> EvidencePack | None:
    """The caller's own evidence pack (``services.evidence_pack``): its receipts and posture.

    Built for ``ctx``'s organisation from what it could read, as it always was;
    on the staff login because the pack holds the member's receipts and posture.
    """
    async with _reader(ctx) as staff:
        return await evidence_pack(staff or session, ctx, vulnerability_stix_id, now=now)


async def own_postures_of(session: AsyncSession, ctx: AuthContext) -> list[OrgPosture]:
    """Every posture the caller's organisation holds (``posture.own_postures``)."""
    async with _reader(ctx) as staff:
        return await own_postures(staff or session, ctx)


async def own_posture_of(
    session: AsyncSession, ctx: AuthContext, posture_id: uuid.UUID
) -> OrgPosture | None:
    """One posture, if it is the caller's organisation's (``posture.own_posture``)."""
    async with _reader(ctx) as staff:
        return await own_posture(staff or session, ctx, posture_id)


async def own_posture_on(session: AsyncSession, ctx: AuthContext, stix_id: str) -> str | None:
    """The caller's organisation's posture status on one vulnerability."""
    async with _reader(ctx) as staff:
        return await own_posture_status(staff or session, ctx, stix_id)


async def own_actioned_count(
    session: AsyncSession,
    ctx: AuthContext,
    stix_ids: Sequence[str],
    statuses: frozenset[PostureStatus],
) -> int:
    """How many of ``stix_ids`` the caller's organisation holds a posture in ``statuses`` on."""
    async with _reader(ctx) as staff:
        return await own_posture_count(staff or session, ctx, stix_ids, statuses)


async def own_webhooks(session: AsyncSession, ctx: AuthContext) -> list[Webhook]:
    """The caller's organisation's webhooks, oldest first. Never another's (slice 3g)."""
    query = select(Webhook).where(Webhook.org_id == ctx.org_id).order_by(Webhook.created_at)
    async with _reader(ctx) as staff:
        return list((await (staff or session).scalars(query)).all())
