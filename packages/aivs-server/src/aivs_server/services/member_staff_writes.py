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
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import AckType, AckVia, NotificationCadence, ReadingDepth, SubmissionState
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.attribution_key import AttributionKey
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import PolicyDeniedError, can_view_submission, uses_staff_database
from aivs_server.auth.secretbox import SecretBox, SecretPurpose
from aivs_server.db.clock import database_now
from aivs_server.db.engine import get_sessionmaker
from aivs_server.db.models import (
    Acknowledgment,
    Circle,
    ClientCertificate,
    Organization,
    OrgPosture,
    Submission,
    TaxiiCollection,
    TaxiiStatus,
    Webhook,
)
from aivs_server.db.org_lock import org_still_active
from aivs_server.services.acknowledgments import assert_receipt
from aivs_server.services.attribution import is_submitted_by
from aivs_server.services.certificates import revoke_certificate
from aivs_server.services.contributions import (
    OneClick,
    contribute,
    publish_if_post_moderated,
    submit_submission,
)
from aivs_server.services.inbox import receive_envelope
from aivs_server.services.member_settings import (
    change_notification_settings,
    store_default_depth,
)
from aivs_server.services.org_status import load_org_for_update
from aivs_server.services.posture import VexStatement, record_posture
from aivs_server.services.proxy_filing import confirm_proxy_filing
from aivs_server.services.quarantine import quarantine_org
from aivs_server.services.submissions import apply_transition, load_submission, update_submission

__all__ = [
    "assert_own_receipt",
    "confirm_own_proxy_filing",
    "contribute_own",
    "delete_own_webhook",
    "quarantine_organisation",
    "receive_own_envelope",
    "record_own_posture",
    "register_own_webhook",
    "revoke_own_certificate",
    "set_notification_settings",
    "set_own_default_depth",
    "submit_own_submission",
    "transition_own_submission",
    "update_own_submission",
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


# ---------------------------------------------------------------------------
# A member's own filing (slice 3g: the member login updates no submission)
# ---------------------------------------------------------------------------
async def _filing_locked(
    writer: AsyncSession, ctx: AuthContext, submission_id: uuid.UUID, key: AttributionKey
) -> Submission | None:
    """The submission under its row lock on ``writer``, or ``None`` if the caller may not see it.

    The lock is taken here, on the session that writes, never on the member's:
    a staff transaction locking a row a member transaction already holds would
    wait on a transaction waiting for it, across two connections Postgres
    cannot see together. Absent and not visible are one answer, as the routes
    give.
    """
    submission = await load_submission(writer, submission_id, for_update=True)
    if submission is None or not can_view_submission(
        ctx, submission, owner_is_caller=is_submitted_by(key, submission, ctx.org_id)
    ):
        return None
    return submission


async def update_own_submission(
    session: AsyncSession,
    ctx: AuthContext,
    submission_id: uuid.UUID,
    *,
    changes: dict[str, Any],
    key: AttributionKey,
) -> Submission | None:
    """Amend a draft (``submissions.update_submission``): its fields and its bundle."""
    async with _writer(session, ctx) as writer:
        submission = await _filing_locked(writer, ctx, submission_id, key)
        if submission is None:
            return None
        await update_submission(writer, ctx, submission, changes=changes, key=key)
        await writer.flush()
        await writer.refresh(submission)
        return submission


async def transition_own_submission(
    session: AsyncSession,
    ctx: AuthContext,
    submission_id: uuid.UUID,
    target: SubmissionState,
    *,
    reason: str | None,
    key: AttributionKey,
) -> Submission | None:
    """Move a submission to ``target`` (``submissions.apply_transition``, which holds the rules)."""
    async with _writer(session, ctx) as writer:
        submission = await _filing_locked(writer, ctx, submission_id, key)
        if submission is None:
            return None
        await apply_transition(writer, ctx, submission, target, reason=reason, key=key)
        await writer.flush()
        await writer.refresh(submission)
        return submission


async def submit_own_submission(
    session: AsyncSession,
    ctx: AuthContext,
    submission_id: uuid.UUID,
    *,
    reason: str | None,
    hourly_limit: int,
    key: AttributionKey,
) -> Submission | None:
    """Hand a draft to the ISAC, and publish it if a post-moderated circle takes it.

    One transaction, under one lock: the transition, the allowance's lock and
    count, and the publication (CLAUDE.md section 5). A publication refused
    leaves it submitted, waiting for an editor.
    """
    async with _writer(session, ctx) as writer:
        submission = await _filing_locked(writer, ctx, submission_id, key)
        if submission is None:
            return None
        await submit_submission(writer, ctx, submission, reason=reason, key=key)
        await publish_if_post_moderated(
            writer,
            ctx,
            submission,
            hourly_limit=hourly_limit,
            now=await database_now(writer),
            key=key,
        )
        await writer.flush()
        await writer.refresh(submission)
        return submission


async def confirm_own_proxy_filing(
    session: AsyncSession, ctx: AuthContext, submission_id: uuid.UUID, *, key: AttributionKey
) -> Submission | None:
    """A person at the member confirms a filing made in its name (``proxy_filing``)."""
    async with _writer(session, ctx) as writer:
        submission = await _filing_locked(writer, ctx, submission_id, key)
        if submission is None:
            return None
        await confirm_proxy_filing(writer, ctx, submission, now=await database_now(writer), key=key)
        await writer.flush()
        await writer.refresh(submission)
        return submission


async def receive_own_envelope(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    collection: TaxiiCollection,
    circle: Circle,
    envelope: Any,
    hourly_limit: int,
    key: AttributionKey,
) -> TaxiiStatus:
    """File a TAXII inbox envelope in the caller's name (``inbox.receive_envelope``).

    Whole, as a one-click is: it creates the submission and then sets its
    source and lane and submits it, which the member login may not update.
    """
    async with _writer(session, ctx) as writer:
        status = await receive_envelope(
            writer,
            ctx,
            collection=collection,
            circle=circle,
            envelope=envelope,
            hourly_limit=hourly_limit,
            now=await database_now(writer),
            key=key,
        )
        await writer.flush()
        await writer.refresh(status)
        return status


# ---------------------------------------------------------------------------
# A member's own webhooks (slice 3g: the member login holds nothing on them)
# ---------------------------------------------------------------------------
async def register_own_webhook(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    url: str,
    events: list[str],
    secret_box: SecretBox,
) -> tuple[Webhook, str]:
    """Register a webhook for the caller's organisation; it and its signing secret.

    The caller has checked who may register and the URL. ``PolicyDeniedError``
    if the organisation has left since the request authenticated.
    """
    async with _writer(session, ctx) as writer:
        if not await org_still_active(writer, ctx.org_id):
            denial = "webhook_org_not_active"
            raise PolicyDeniedError(denial)
        secret = secrets.token_urlsafe(32)
        # Generated here rather than left to the column default, because the
        # seal is bound to it and a default is applied only at INSERT.
        webhook_id = uuid.uuid4()
        webhook = Webhook(
            id=webhook_id,
            org_id=ctx.org_id,
            url=url,
            hmac_secret_encrypted=secret_box.seal(
                secret, purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook_id
            ),
            events=events,
            is_active=True,
        )
        writer.add(webhook)
        await record(
            writer,
            action=AuditAction.WEBHOOK_CREATED,
            ctx=ctx,
            resource_type="webhook",
            details={"events": events or ["*"]},
        )
        await writer.flush()
        await writer.refresh(webhook)
        return webhook, secret


async def delete_own_webhook(
    session: AsyncSession, ctx: AuthContext, webhook_id: uuid.UUID
) -> bool:
    """Remove one of the caller's organisation's webhooks; ``False`` if it has none by that id."""
    async with _writer(session, ctx) as writer:
        webhook = await writer.get(Webhook, webhook_id)
        if webhook is None or webhook.org_id != ctx.org_id:
            return False
        await writer.delete(webhook)
        await record(
            writer,
            action=AuditAction.WEBHOOK_DELETED,
            ctx=ctx,
            resource_type="webhook",
            resource_id=str(webhook_id),
        )
        return True
