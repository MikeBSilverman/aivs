"""Email-to-draft: a member's person emails the ISAC, and a draft appears (O, slice 3; SF-93).

Mike's answer to Q39 was to start with mail, so AIVS reads one mailbox the
ISAC already runs (``services.imap_mailbox``). Four rules, each a way this
kind of door usually goes wrong:

* **Pull, never listen.** No listener faces the internet; the mailbox is read
  over verified TLS.
* **The sender is the receiving server's word** (``services.email_message``),
  and then a registered person at a member organisation that may transact,
  allowed to draft (``policy.can_draft_by_email``), within its hourly allowance.
* **A draft, never a submission.** One message makes one draft for the
  sender's organisation, and nothing moves until a person submits it in the
  portal, where the first pass reads it. The way in is ``AuthMethod.EMAIL``,
  off the certificate-bound path, so the checks ingest makes from the
  sender's view see what an SSO session would.
* **No reply, and no content kept.** A reply to a refused message would mail
  the person a spoofer impersonated and confirm the address is read. One
  ``inbound_emails`` row and one audit row per message carry the outcome and
  a reason code; the message itself stays in the mailbox, moved to a folder.

Each message is decided and recorded in its own transaction, and moved only
after it commits. A run that stops in between finds the message recorded on
the next run and only moves it, so nothing is filed twice.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import logging
import uuid
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgStatus
from aivs_schemas.models import SubmissionCreate
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.attribution_key import AttributionKey
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.memberships import load_circle_grants
from aivs_server.auth.policy import can_draft_by_email
from aivs_server.config import Settings
from aivs_server.db.clock import database_now
from aivs_server.db.models import InboundEmail, Operator, Organization
from aivs_server.services.email_message import (
    EMAIL_DRAFT_SCOPE,
    EMAIL_DRAFT_TLP,
    DraftContent,
    ParsedMessage,
    aligned_dmarc_pass,
    draft_content,
    parse_message,
)
from aivs_server.services.imap_mailbox import Mailbox, MailboxLogin
from aivs_server.services.instance import distribution_is_paused
from aivs_server.services.submissions import STORAGE_ERRORS, SubmissionError, create_submission

__all__ = ["MailIntake", "Refusal", "read_mailbox", "receive_message", "receive_oversize"]

logger = logging.getLogger(__name__)

#: How many messages one run reads; the rest wait for the next run.
_BATCH: Final[int] = 50
#: How many it looks at to find them: a message left in place (its storing
#: failed) does not count against the batch, so fifty of them at the front of
#: the mailbox cannot hold back everything behind them (T1's review).
_LOOKED_AT: Final[int] = 4 * _BATCH
_HOUR: Final[dt.timedelta] = dt.timedelta(hours=1)
#: Advisory-lock namespace for one organisation's email allowance, so two
#: processes reading one mailbox cannot both count limit - 1.
_ALLOWANCE_LOCK_SPACE: Final[int] = 0x41495645

ACCEPTED: Final[str] = "accepted"
REFUSED: Final[str] = "refused"

Sessions = Callable[[], AbstractAsyncContextManager[AsyncSession]]


class Refusal(StrEnum):
    """Why a message made no draft. Recorded and audited; never sent to anyone."""

    TOO_LARGE = "too_large"
    #: The From header does not hold exactly one address.
    UNREADABLE_SENDER = "unreadable_sender"
    #: The message could not be parsed at all: refused and moved, never retried.
    UNREADABLE = "unreadable"
    #: No aligned DMARC pass from the ISAC's own receiving server.
    UNAUTHENTICATED = "unauthenticated"
    UNKNOWN_SENDER = "unknown_sender"
    ORGANISATION_INACTIVE = "organisation_inactive"
    NOT_PERMITTED = "not_permitted"
    RATE_LIMITED = "rate_limited"


@dataclass(frozen=True, slots=True)
class MailIntake:
    """What the intake needs from settings, and nothing else."""

    login: MailboxLogin
    authserv_id: str
    accepted_folder: str
    refused_folder: str
    max_message_bytes: int
    hourly_limit: int

    @classmethod
    def from_settings(cls, settings: Settings) -> MailIntake | None:
        """``None`` unless the mailbox is named with everything needed to read and trust it."""
        password = settings.email_intake_imap_password
        if (
            settings.email_intake_imap_host is None
            or settings.email_intake_imap_username is None
            or password is None
            or settings.email_intake_authserv_id is None
        ):
            return None
        return cls(
            login=MailboxLogin(
                host=settings.email_intake_imap_host,
                port=settings.email_intake_imap_port,
                username=settings.email_intake_imap_username,
                password=password.get_secret_value(),
                mailbox=settings.email_intake_mailbox,
                timeout_seconds=settings.email_intake_timeout_seconds,
            ),
            authserv_id=settings.email_intake_authserv_id,
            accepted_folder=settings.email_intake_accepted_folder,
            refused_folder=settings.email_intake_refused_folder,
            max_message_bytes=settings.email_intake_max_message_bytes,
            hourly_limit=settings.email_intake_hourly_limit,
        )

    def folder_for(self, outcome: str) -> str:
        return self.accepted_folder if outcome == ACCEPTED else self.refused_folder


@dataclass(frozen=True, slots=True)
class _Sender:
    """Who a message is from, as far as the intake got in finding out."""

    refusal: Refusal | None
    context: AuthContext | None = None
    org_id: uuid.UUID | None = None
    operator_id: uuid.UUID | None = None


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------
async def read_mailbox(
    mailbox: Mailbox, *, intake: MailIntake, key: AttributionKey, sessions: Sessions
) -> int:
    """Read each waiting message once, file or refuse it, then move it. How many were read."""
    uids = await asyncio.to_thread(mailbox.uids)
    read = 0
    for uid in uids[:_LOOKED_AT]:
        if read >= _BATCH:
            break
        async with sessions() as session:
            if await distribution_is_paused(session):
                break
        outcome = await _read_one(mailbox, uid, intake=intake, key=key, sessions=sessions)
        if outcome is None:
            continue
        await asyncio.to_thread(mailbox.move, uid, intake.folder_for(outcome))
        read += 1
    return read


async def _read_one(
    mailbox: Mailbox, uid: str, *, intake: MailIntake, key: AttributionKey, sessions: Sessions
) -> str | None:
    """The message's recorded outcome, or ``None`` if it could not be stored and stays put.

    A message that cannot be parsed is a refusal like any other, recorded and
    moved. One whose storing fails (a database error, usually passing) is
    logged and left for the next run, and does not count against this one's
    batch.
    """
    size = await asyncio.to_thread(mailbox.size, uid)
    oversize = size > intake.max_message_bytes
    raw = await asyncio.to_thread(mailbox.fetch_header if oversize else mailbox.fetch, uid)
    async with sessions() as session:
        try:
            if oversize:
                outcome = await receive_oversize(session, raw, now=await database_now(session))
            else:
                outcome = await receive_message(
                    session, raw, intake=intake, key=key, now=await database_now(session)
                )
            await session.commit()
        except (ValueError, LookupError, DBAPIError) as exc:
            await session.rollback()
            logger.warning("intake message %s left in the mailbox: %s", uid, type(exc).__name__)
            return None
    return outcome


# ---------------------------------------------------------------------------
# One message
# ---------------------------------------------------------------------------
async def receive_message(
    session: AsyncSession, raw: bytes, *, intake: MailIntake, key: AttributionKey, now: dt.datetime
) -> str:
    """Decide, record and (if accepted) file one message. Its outcome. Does not commit."""
    digest = hashlib.sha256(raw).hexdigest()
    recorded = await _recorded_outcome(session, digest)
    if recorded is not None:
        return recorded
    read = _readable(raw)
    if read is None:
        sender = _Sender(Refusal.UNREADABLE)
    else:
        sender = await _sender(session, read[0], intake=intake, now=now)
    if sender.refusal is None and not await _within_allowance(
        session, sender.org_id, limit=intake.hourly_limit, now=now
    ):
        sender = _Sender(Refusal.RATE_LIMITED, None, sender.org_id, sender.operator_id)
    row = await _claim(session, digest, sender, now=now)
    if row is None:
        return await _recorded_outcome(session, digest) or REFUSED
    if read is not None and sender.context is not None and sender.refusal is None:
        await _file_draft(session, sender.context, read[1], key=key)
    await _audit(session, row, sender)
    return row.outcome


def _readable(raw: bytes) -> tuple[ParsedMessage, DraftContent] | None:
    """The message and its draft, or ``None`` if the parser cannot read it.

    The one place the intake catches everything. The standard library's email
    parser, given hostile bytes, raises whatever its code path reaches
    (``AttributeError`` for ``From: x:;y``, ``LookupError`` for an unknown
    charset), and a message that escaped here would stay first in the inbox
    and stop every later run for every member (T1's review). Nothing is
    recorded about it but its digest and the reason.
    """
    try:
        message = parse_message(raw)
        return message, draft_content(message)
    except Exception:  # noqa: BLE001 - see the docstring: any parser failure is "unreadable"
        return None


async def receive_oversize(session: AsyncSession, header: bytes, *, now: dt.datetime) -> str:
    """Refuse a message too large to fetch, recorded by its header. Does not commit."""
    digest = hashlib.sha256(b"header\0" + header).hexdigest()
    sender = _Sender(Refusal.TOO_LARGE)
    row = await _claim(session, digest, sender, now=now)
    if row is None:
        return REFUSED
    await _audit(session, row, sender)
    return REFUSED


async def _recorded_outcome(session: AsyncSession, digest: str) -> str | None:
    outcome: str | None = await session.scalar(
        select(InboundEmail.outcome).where(InboundEmail.message_sha256 == digest)
    )
    return outcome


async def _claim(
    session: AsyncSession, digest: str, sender: _Sender, *, now: dt.datetime
) -> InboundEmail | None:
    """Record the message, or ``None`` if another reader recorded it first.

    Flushed at once, before any draft is filed: a second process reading the
    same message waits here on the unique index and then fails, so it never
    files a second draft.
    """
    row = InboundEmail(
        message_sha256=digest,
        received_at=now,
        outcome=REFUSED if sender.refusal else ACCEPTED,
        reason=sender.refusal.value if sender.refusal else None,
        org_id=sender.org_id,
        operator_id=sender.operator_id,
    )
    try:
        async with session.begin_nested():
            session.add(row)
            await session.flush()
    except IntegrityError:
        return None
    return row


# ---------------------------------------------------------------------------
# The sender
# ---------------------------------------------------------------------------
async def _sender(
    session: AsyncSession, message: ParsedMessage, *, intake: MailIntake, now: dt.datetime
) -> _Sender:
    """Who sent this, and whether they may draft by email: each refusal named for its check."""
    if message.sender is None:
        return _Sender(Refusal.UNREADABLE_SENDER)
    if not aligned_dmarc_pass(message, authserv_id=intake.authserv_id):
        return _Sender(Refusal.UNAUTHENTICATED)
    operator = await _registered_person(session, message.sender)
    if operator is None:
        return _Sender(Refusal.UNKNOWN_SENDER)
    organisation = await session.get(Organization, operator.org_id)
    if organisation is None or organisation.status is not OrgStatus.ACTIVE:
        return _Sender(Refusal.ORGANISATION_INACTIVE, None, operator.org_id, operator.id)
    context = await _context(session, operator, organisation)
    if not operator.is_active or not can_draft_by_email(context, now):
        return _Sender(Refusal.NOT_PERMITTED, None, operator.org_id, operator.id)
    return _Sender(None, context, operator.org_id, operator.id)


async def _registered_person(session: AsyncSession, address: str) -> Operator | None:
    """The one operator registered at this address, compared without case.

    Two rows differing only in case would make the address ambiguous, and an
    ambiguous sender is no sender.
    """
    rows = (
        await session.scalars(select(Operator).where(func.lower(Operator.email) == address))
    ).all()
    return rows[0] if len(rows) == 1 else None


async def _context(
    session: AsyncSession, operator: Operator, organisation: Organization
) -> AuthContext:
    return AuthContext(
        org_id=organisation.id,
        org_slug=organisation.slug,
        org_type=organisation.org_type,
        org_status=organisation.status,
        auth_method=AuthMethod.EMAIL,
        circles=await load_circle_grants(session, organisation.id),
        operator_id=operator.id,
        operator_roles=frozenset(operator.roles),
        role_expires_at=operator.role_expires_at,
    )


async def _within_allowance(
    session: AsyncSession, org_id: uuid.UUID | None, *, limit: int, now: dt.datetime
) -> bool:
    """Whether this organisation may make one more draft by email this hour."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:space, hashtext(:org))"),
        {"space": _ALLOWANCE_LOCK_SPACE, "org": str(org_id)},
    )
    accepted = await session.scalar(
        select(func.count())
        .select_from(InboundEmail)
        .where(
            InboundEmail.org_id == org_id,
            InboundEmail.outcome == ACCEPTED,
            InboundEmail.received_at >= now - _HOUR,
        )
    )
    return (accepted or 0) < limit


# ---------------------------------------------------------------------------
# The draft and the record
# ---------------------------------------------------------------------------
async def _file_draft(
    session: AsyncSession, ctx: AuthContext, content: DraftContent, *, key: AttributionKey
) -> None:
    """File the draft with its bundle, or without it when the bundle is refused.

    A refused message gets no reply, so refusing the whole draft for its
    attachment would lose the member's text without telling anyone. The
    draft says why the bundle was left out instead.
    """
    try:
        async with session.begin_nested():
            await _create(session, ctx, content, key=key)
    except (SubmissionError, ValueError) as exc:
        reason = str(exc)
    except STORAGE_ERRORS:
        # A database error's text carries its SQL, which is not the member's
        # to read (T1's review); validation's text is about the member's own
        # content.
        reason = "it could not be stored"
    else:
        return
    await _create(session, ctx, content.without_bundle(reason), key=key)


async def _create(
    session: AsyncSession, ctx: AuthContext, content: DraftContent, *, key: AttributionKey
) -> None:
    # The request model the API and the portal use, so the three doors agree
    # on what a legal draft is.
    payload = SubmissionCreate.model_validate(
        {
            "title": content.title,
            "summary": content.summary,
            "tlp": EMAIL_DRAFT_TLP,
            "discovery_scope": EMAIL_DRAFT_SCOPE,
            "bundle": content.bundle,
        }
    )
    await create_submission(
        session,
        ctx,
        key=key,
        title=payload.title,
        summary=payload.summary,
        tlp=payload.tlp,
        discovery_scope=payload.discovery_scope,
        distribute_anonymously=None,
        bundle=payload.bundle,
        filed_for=None,
        via="email",
    )


async def _audit(session: AsyncSession, row: InboundEmail, sender: _Sender) -> None:
    """The outcome and its reason; never the subject, the body, or a refused From.

    A refused message's From is whoever the sender claimed to be, which is the
    person a spoofer impersonated.
    """
    accepted = row.outcome == ACCEPTED
    await record(
        session,
        action=AuditAction.EMAIL_INTAKE_ACCEPTED if accepted else AuditAction.EMAIL_INTAKE_REFUSED,
        ctx=sender.context if accepted else None,
        actor_type=None if accepted else "system",
        actor_id=None if accepted else "email_intake",
        org_id=None if accepted else row.org_id,
        resource_type="inbound_email",
        resource_id=str(row.id),
        outcome="success" if accepted else "denied",
        details={"reason": row.reason, "message_sha256": row.message_sha256},
    )
