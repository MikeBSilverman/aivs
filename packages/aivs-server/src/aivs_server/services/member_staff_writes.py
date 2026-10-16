"""The one place a member's request writes on the staff login (Phase P, slice 3c).

The member login holds UPDATE on no column of ``organizations`` that matters
(``db.grants.MEMBER_GRANTS``). Every member organisation shares that login,
so a column it could update on its own row, SQL injected on the member path
could update on every member's: lift the quarantine or suspension the ISAC
put on a firm, quarantine a peer, or point a peer's digest at another mailbox.
Yet a member does change its own row: it quarantines itself ("we are
compromised, cut us off") and sets its notification settings. And since slice
3e, which holds the member login to nothing on ``operators``, a person sets
their own reading depth here too; and since the member login holds nothing on
``org_postures`` and only writes ``acknowledgments``, a member's own posture
and its asserted receipts ("we've acted") are written here, through the
services that own them (R26). And since slice 3f, which holds the member login
to reading ``distributions`` and to no UPDATE of ``stix_objects.raw``, a
member's unreviewed publication -- a one-click, a post-moderated note -- is
made here too (R33): with INSERT on ``distributions`` and UPDATE on ``raw``,
SQL on the member path could publish any object into any circle, or rewrite
the content of one already distributed. And the member login holds no
UPDATE on ``client_certificates``: with it, SQL on the member path could
revoke every firm's certificate, or bring a revoked, compromised one back onto
the authenticated path (R35). An organisation administrator revoking its
own certificate does it here. Each function here makes one such change on a
staff session of its own.

**Publication stays one transaction** (CLAUDE.md section 5): the hourly
allowance's lock and count, the visibility rows, the state changes and the
audit rows all commit together in the staff transaction, so two parallel
publications cannot each count the limit minus one. A one-click holds no row
lock beforehand, so its whole filing runs there. A post-moderated submit is
two steps: the member's transition to submitted commits first, on the member
login, and only then is the submission published here. That order is
forced, not chosen: the submit routes hold the submission's row lock on the
member session, and a staff transaction taking the same lock would wait on a
member transaction that is waiting for it -- a deadlock across two
connections that Postgres cannot see. The second step re-reads the
submission under its own lock and publishes only what is still submitted and
still the caller's, so a return by the triage job in between wins.

Every function holds one invariant, and nothing else here makes it true:

* for a member caller it opens its own staff session, writes only the row of
  ``ctx.org_id``, records the audit row in the same transaction, commits, and
  never returns the session;
* for a caller already on the staff login (``policy.uses_staff_database``) it
  writes on that caller's own session, and the caller commits, as before.

Each goes through the service that knows the state it changes
(``services.quarantine``, ``services.member_settings``), never around it.
``tests/unit/test_staff_session_reach.py`` admits this module by name.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import AckType, AckVia, NotificationCadence, ReadingDepth, SubmissionState
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.attribution_key import AttributionKey
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import uses_staff_database
from aivs_server.db.clock import database_now
from aivs_server.db.engine import get_sessionmaker
from aivs_server.db.models import (
    Acknowledgment,
    ClientCertificate,
    Organization,
    OrgPosture,
    Submission,
)
from aivs_server.services.acknowledgments import assert_receipt
from aivs_server.services.attribution import is_submitted_by
from aivs_server.services.certificates import revoke_certificate
from aivs_server.services.contributions import OneClick, contribute, publish_if_post_moderated
from aivs_server.services.member_settings import (
    change_notification_settings,
    store_default_depth,
)
from aivs_server.services.org_status import load_org_for_update
from aivs_server.services.posture import VexStatement, record_posture
from aivs_server.services.quarantine import quarantine_org
from aivs_server.services.submissions import load_submission

__all__ = [
    "assert_own_receipt",
    "contribute_own",
    "publish_own_post_moderated",
    "quarantine_organisation",
    "record_own_posture",
    "revoke_own_certificate",
    "set_notification_settings",
    "set_own_default_depth",
]


@asynccontextmanager
async def _writer(session: AsyncSession, ctx: AuthContext) -> AsyncIterator[AsyncSession]:
    """The session to write on: the caller's own when it is staff, else a staff session.

    A staff session is committed on a clean exit and rolled back on an error;
    the caller's own is left to the caller, which commits it as it always has.
    """
    if uses_staff_database(ctx):
        yield session
        return
    async with get_sessionmaker()() as staff:
        try:
            yield staff
            await staff.commit()
        except BaseException:
            await staff.rollback()
            raise


async def quarantine_organisation(
    session: AsyncSession, ctx: AuthContext, *, org_id: uuid.UUID, reason: str
) -> Organization | None:
    """Quarantine ``org_id``; for a member, its own organisation and no other.

    ``None`` if the organisation is not found. ``QuarantineError`` as
    ``quarantine_org`` raises it. A member's ``org_id`` is ignored for its own:
    policy already admits a member only for itself (``can_quarantine_org``),
    and on the staff login that check is not the only thing keeping a peer's
    row out of reach.
    """
    async with _writer(session, ctx) as writer:
        target = org_id if uses_staff_database(ctx) else ctx.org_id
        organisation = await load_org_for_update(writer, target)
        if organisation is None:
            return None
        await quarantine_org(
            writer, ctx, organisation=organisation, reason=reason, now=await database_now(writer)
        )
        return organisation


async def set_notification_settings(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    cadence: NotificationCadence,
    digest_email: str | None,
) -> Organization | None:
    """Set the caller's own organisation's cadence and mailbox, and record it.

    ``None`` if the organisation has gone. The audit row is written with the
    change, on the same session, so the two commit together.
    """
    async with _writer(session, ctx) as writer:
        organisation = await change_notification_settings(
            writer, ctx, cadence=cadence, digest_email=digest_email
        )
        if organisation is None:
            return None
        await record(
            writer,
            action=AuditAction.NOTIFICATION_SETTINGS_SET,
            ctx=ctx,
            resource_type="organization",
            resource_id=str(organisation.id),
            details={"cadence": cadence.value, "digest_email": digest_email is not None},
        )
        return organisation


async def set_own_default_depth(
    session: AsyncSession, ctx: AuthContext, depth: ReadingDepth | None
) -> bool:
    """Store the signed-in person's reading depth; ``False`` if they or their org have gone."""
    async with _writer(session, ctx) as writer:
        return await store_default_depth(writer, ctx, depth)


async def assert_own_receipt(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    *,
    ack_type: AckType,
    via: AckVia,
    note: str | None,
    now: dt.datetime,
    key: AttributionKey,
) -> Acknowledgment:
    """Record a receipt for the caller's organisation (``acknowledgments.assert_receipt``).

    ``assert_receipt`` reads the organisation's own retrievals and today's
    receipt, which the member login may not, and records the audit row with it.
    """
    async with _writer(session, ctx) as writer:
        return await assert_receipt(
            writer, ctx, submission, ack_type=ack_type, via=via, note=note, now=now, key=key
        )


async def record_own_posture(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    vulnerability_id: str,
    statement: VexStatement,
    now: dt.datetime,
) -> OrgPosture:
    """Set the caller's organisation's posture (``posture.record_posture``), with its audit row.

    The row is returned loaded, server defaults included: for a member it
    belongs to a session already closed, and the caller cannot refresh it.
    """
    async with _writer(session, ctx) as writer:
        row = await record_posture(
            writer, ctx, vulnerability_id=vulnerability_id, statement=statement, now=now
        )
        await writer.refresh(row)
        return row


async def contribute_own(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    target_id: str,
    kind: OneClick,
    hourly_limit: int,
    key: AttributionKey,
) -> Submission:
    """File a one-click contribution in the caller's name (``contributions.contribute``).

    The whole filing -- allowance, the submission, its publication or its
    filing for review -- is one transaction; a refusal leaves nothing.
    """
    async with _writer(session, ctx) as writer:
        return await contribute(
            writer,
            ctx,
            target_id=target_id,
            kind=kind,
            hourly_limit=hourly_limit,
            now=await database_now(writer),
            key=key,
        )


async def publish_own_post_moderated(
    session: AsyncSession,
    ctx: AuthContext,
    submission_id: uuid.UUID,
    *,
    hourly_limit: int,
    key: AttributionKey,
) -> bool:
    """Publish the caller's just-submitted contribution if a post-moderated circle takes it.

    Run after the submit has committed. Re-reads the submission under its own
    lock: one no longer submitted (the triage job returned it meanwhile), or
    not the caller's, is not published. Whether it was published.
    """
    async with _writer(session, ctx) as writer:
        submission = await load_submission(writer, submission_id, for_update=True)
        if (
            submission is None
            or submission.state is not SubmissionState.SUBMITTED
            or not is_submitted_by(key, submission, ctx.org_id)
        ):
            return False
        return await publish_if_post_moderated(
            writer,
            ctx,
            submission,
            hourly_limit=hourly_limit,
            now=await database_now(writer),
            key=key,
        )


async def revoke_own_certificate(
    session: AsyncSession, ctx: AuthContext, certificate_id: uuid.UUID
) -> ClientCertificate | None:
    """Revoke a certificate of an organisation the caller manages (``certificates``).

    ``None`` when it is absent or another's: for a member, any certificate but
    its own organisation's (``policy.can_manage_org``). Returned loaded, since
    for a member its session is closed by the time the caller reads it.
    """
    async with _writer(session, ctx) as writer:
        row = await revoke_certificate(writer, ctx, certificate_id, now=await database_now(writer))
        if row is not None:
            await writer.flush()
            await writer.refresh(row)
        return row
