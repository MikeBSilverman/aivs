"""An ISAC editor files a member's contribution for it (SF-68).

Members email the ISAC rather than file; without this, that contribution
reaches nobody. With it, the risk is the opposite: an editor attributing to a
member content the member never sent. So a proxy filing needs three things the
member can check:

- a **consent artefact**, hashed and stored with the filing (the forwarded
  mail, or the member's click), so the attribution traces to something the
  member did;
- a **contentless notice** to the member's own endpoints -- "filed on your
  behalf; confirm or withdraw" -- the moment it is filed, and on its portal
  dashboard, which needs no webhook;
- a **window**: the filing is not distributed until a person at the member
  confirms, or until ``CONFIRM_WITHIN`` passes in silence. Withdrawing uses
  the member's ordinary stop button.

Anonymous by default, as every contribution is.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgStatus, OrgType, SubmissionState
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import can_confirm_proxy_filing, is_isac_editor, require
from aivs_server.db.models import Organization, Submission, Webhook, WebhookDelivery
from aivs_server.services.submissions import (
    ProxyFiling,
    SubmissionError,
    create_submission,
    record_transition,
)

__all__ = [
    "CONFIRM_WITHIN",
    "EVENT_FILED_ON_BEHALF",
    "awaiting_confirmation",
    "awaiting_confirmation_problem",
    "confirm_proxy_filing",
    "file_on_behalf",
]

#: How long a member has to confirm or withdraw before silence confirms.
CONFIRM_WITHIN: Final[dt.timedelta] = dt.timedelta(hours=24)

EVENT_FILED_ON_BEHALF: Final[str] = "submission.filed_on_behalf"

_SHA256_HEX: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

#: Organisations an editor may file for: those that contribute in their own
#: name. Never the ISAC itself, and never a machine.
_FILEABLE_FOR: Final[frozenset[OrgType]] = frozenset(OrgType) - {
    OrgType.ADMIN,
    OrgType.AUTOMATION,
}


async def _member_for(session: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = await session.get(Organization, org_id)
    if org is None or org.org_type not in _FILEABLE_FOR or org.status is not OrgStatus.ACTIVE:
        msg = "an editor may file only for an active member organisation"
        raise SubmissionError(msg)
    return org


def _queue_notice(session: AsyncSession, hooks: list[Webhook], submission: Submission) -> None:
    """The member hears at once, contentlessly, that something was filed in its name."""
    confirm_by = submission.proxy_confirm_by
    for hook in hooks:
        if hook.events and EVENT_FILED_ON_BEHALF not in hook.events:
            continue
        session.add(
            WebhookDelivery(
                webhook_id=hook.id,
                event=EVENT_FILED_ON_BEHALF,
                payload={
                    "event": EVENT_FILED_ON_BEHALF,
                    "submission_id": str(submission.id),
                    "confirm_by": confirm_by.isoformat() if confirm_by else None,
                    "detail": "filed on your behalf by the ISAC: confirm or withdraw it",
                },
            )
        )


async def file_on_behalf(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    org_id: uuid.UUID,
    consent_sha256: str,
    content: dict[str, Any],
    now: dt.datetime,
) -> Submission:
    """File ``content`` for ``org_id`` and hand it to review. Editors only.

    ``content`` carries the ordinary filing fields (title, summary, TLP,
    scope, anonymity, bundle).
    """
    require(is_isac_editor(ctx), "proxy_filing_requires_isac_editor")
    if not _SHA256_HEX.match(consent_sha256):
        msg = "consent_sha256 must be the SHA-256 of the consent artefact, in lower-case hex"
        raise SubmissionError(msg)
    member = await _member_for(session, org_id)

    submission = await create_submission(
        session,
        ctx,
        filed_for=ProxyFiling(
            org_id=member.id, consent_sha256=consent_sha256, confirm_by=now + CONFIRM_WITHIN
        ),
        via="proxy",
        **content,
    )
    await record_transition(
        session, ctx, submission, SubmissionState.SUBMITTED, reason="filed on the member's behalf"
    )
    hooks = list(
        (
            await session.execute(
                select(Webhook).where(Webhook.org_id == member.id, Webhook.is_active.is_(True))
            )
        )
        .scalars()
        .all()
    )
    _queue_notice(session, hooks, submission)
    await record(
        session,
        action=AuditAction.SUBMISSION_FILED_ON_BEHALF,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={"for_org_id": str(member.id), "consent_sha256": consent_sha256},
    )
    return submission


async def confirm_proxy_filing(
    session: AsyncSession, ctx: AuthContext, submission: Submission, *, now: dt.datetime
) -> Submission:
    """A person at the member confirms a filing made in its name. Nobody else."""
    require(can_confirm_proxy_filing(ctx, submission), "proxy_confirm_requires_member_person")
    if submission.filed_by_operator_id is None:
        msg = "this submission was not filed on your behalf"
        raise SubmissionError(msg)
    if submission.proxy_confirmed_at is None:
        submission.proxy_confirmed_at = now
        await record(
            session,
            action=AuditAction.SUBMISSION_PROXY_CONFIRMED,
            ctx=ctx,
            resource_type="submission",
            resource_id=str(submission.id),
            details={},
        )
    return submission


def awaiting_confirmation(submission: Submission, now: dt.datetime) -> bool:
    """Whether this is a proxy filing still inside its window, unconfirmed."""
    if submission.filed_by_operator_id is None or submission.proxy_confirmed_at is not None:
        return False
    return submission.proxy_confirm_by is None or now < submission.proxy_confirm_by


def awaiting_confirmation_problem(submission: Submission, now: dt.datetime) -> str | None:
    """Why a proxy filing may not be distributed yet, or ``None``."""
    if not awaiting_confirmation(submission, now):
        return None
    deadline = submission.proxy_confirm_by
    after = deadline.isoformat() if deadline is not None else "its window"
    return (
        "filed on a member's behalf and not yet confirmed: it may be distributed once the "
        f"member confirms, or after {after}"
    )
