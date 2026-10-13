"""Append-only audit logging.

The audit trail is not a debugging aid; it is the product. An ISAC's answer to
"did you warn us, and did we collect it" is this table, so writes to it have to
survive things that ordinary writes do not.

Two entry points, and choosing the wrong one loses records:

:func:`record` joins the caller's transaction. Correct for successful actions,
because the audit row and the change it describes must commit or fail together
-- a log entry for a write that rolled back would be a lie.

:func:`record_independently` opens its own connection and commits immediately.
Correct for denials, authentication failures, and errors, all of which are
followed by a rollback that would otherwise erase the very record of the
attempt. A rejected request leaves no other trace, so losing this one is losing
the incident.

Immutability is enforced in the database (a trigger that raises on UPDATE,
DELETE, and TRUNCATE, plus a restricted grant on the application role) rather
than by convention here -- see the initial migration. This module can only ever
append.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from collections.abc import Mapping
from typing import Any, Final

from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.auth.context import AuthContext
from aivs_server.config import Settings
from aivs_server.db.engine import get_sessionmaker
from aivs_server.db.models import AuditLog

__all__ = [
    "AuditAction",
    "account_reference",
    "record",
    "record_denial",
    "record_independently",
]

logger = logging.getLogger(__name__)

#: Keys whose values are never written to the audit detail payload, at any
#: nesting depth. The audit log is widely readable within the hosting ISAC and
#: is retained indefinitely; a secret that lands here is a secret that has been
#: disclosed and cannot be redacted afterwards, because the table is immutable
#: by design.
_REDACTED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "password_hash",
        "new_password",
        "current_password",
        "totp",
        "totp_secret",
        "totp_code",
        "secret",
        "hmac_secret",
        "token",
        "session_token",
        "csrf_token",
        "api_key",
        "private_key",
        "authorization",
        "cookie",
        "set-cookie",
        "proxy_auth",
    }
)

_REDACTED_PLACEHOLDER: Final[str] = "[redacted]"

#: Bound on the serialised detail payload. Audit rows are retained forever;
#: an unbounded blob per request is how an audit table becomes the reason an
#: instance runs out of disk.
_MAX_DETAIL_DEPTH: Final[int] = 6
_MAX_STRING_LEN: Final[int] = 2000


class AuditAction:
    """Stable action names.

    Strings rather than an enum: the audit log outlives any given release, and a
    historical row naming an action this version no longer performs must still
    be readable. New actions are added here so they stay greppable.
    """

    # Authentication and session
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    LOGIN_SUCCESS = "portal.login.success"
    LOGIN_FAILURE = "portal.login.failure"
    LOGOUT = "portal.logout"
    SESSION_REJECTED = "portal.session.rejected"

    # Authorization
    ACCESS_DENIED = "authz.denied"

    # Organisation and certificate lifecycle
    ANONYMITY_REVEALED = "anonymity.reveal"
    ORG_CREATED = "org.created"
    OPERATOR_CREATED = "operator.created"
    ORG_STATUS_CHANGED = "org.status_changed"
    CERT_REGISTERED = "cert.registered"
    CERT_REVOKED = "cert.revoked"

    # Circles
    CIRCLE_CREATED = "circle.created"
    CIRCLE_MEMBER_ADDED = "circle.member_added"
    CIRCLE_MEMBER_REMOVED = "circle.member_removed"

    # Submission workflow
    SUBMISSION_CREATED = "submission.created"
    SUBMISSION_UPDATED = "submission.updated"
    SUBMISSION_TRANSITIONED = "submission.transitioned"
    SUBMISSION_DISTRIBUTED = "submission.distributed"

    # Embargo
    EMBARGO_SET = "embargo.set"
    EMBARGO_RELEASED = "embargo.released"
    EMBARGO_EXTENDED = "embargo.extended"

    # Content access
    OBJECTS_RETRIEVED = "taxii.objects_retrieved"
    ACK_RECORDED = "ack.recorded"

    # Webhooks
    WEBHOOK_CREATED = "webhook.created"
    WEBHOOK_DELETED = "webhook.deleted"
    WEBHOOK_DELIVERY_FAILED = "webhook.delivery_failed"


def redact(value: Any, _depth: int = 0) -> Any:
    """Return ``value`` with sensitive keys removed and size bounded.

    Applied to every detail payload before it is written. Recursion is depth-
    limited so that a self-referential or deeply nested structure cannot turn an
    audit write into a stack overflow.
    """
    if _depth >= _MAX_DETAIL_DEPTH:
        return "[truncated: max depth]"

    if isinstance(value, Mapping):
        return {
            str(key): (
                _REDACTED_PLACEHOLDER
                if str(key).lower() in _REDACTED_KEYS
                else redact(item, _depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item, _depth + 1) for item in value[:100]]
    if isinstance(value, str):
        if len(value) <= _MAX_STRING_LEN:
            return value
        return value[:_MAX_STRING_LEN] + "...[truncated]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, uuid.UUID):
        return str(value)
    return redact(str(value), _depth + 1)


def _build_row(
    *,
    action: str,
    actor_type: str,
    actor_id: str | None,
    org_id: uuid.UUID | None,
    resource_type: str | None,
    resource_id: str | None,
    outcome: str,
    request_id: str | None,
    source_ip: str | None,
    details: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return {
        "action": action,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "org_id": org_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "outcome": outcome,
        "request_id": request_id,
        "source_ip": source_ip,
        "details": redact(dict(details or {})),
    }


def account_reference(email: str, settings: Settings) -> str:
    """A stable, non-reversible reference to an account name, for audit details.

    The audit log is immutable, so an email address written into it can never be
    removed -- a departed operator could not be pseudonymised, and a typo'd
    address belonging to someone else would stay there for good. A keyed hash
    still lets a reviewer, or a detection rule, see that forty failures were
    against the *same* account, without recording which. Keyed with the session
    secret so it cannot be reversed by hashing a list of known addresses.
    """
    digest = hmac.new(
        settings.session_secret.get_secret_value().encode("utf-8"),
        b"audit-account:" + email.strip().lower().encode("utf-8"),
        hashlib.sha256,
    )
    return digest.hexdigest()[:24]


async def record(
    session: AsyncSession,
    *,
    action: str,
    ctx: AuthContext | None = None,
    actor_type: str | None = None,
    actor_id: str | None = None,
    org_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    outcome: str = "success",
    request_id: str | None = None,
    source_ip: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> None:
    """Append an audit row inside the caller's transaction.

    Use for actions that succeeded: the row commits with the change it
    describes, so the log cannot claim something happened that was rolled back.
    """
    row = _build_row(
        action=action,
        actor_type=actor_type or (ctx.actor_type if ctx else "system"),
        actor_id=actor_id or (ctx.actor_id if ctx else None),
        org_id=org_id or (ctx.org_id if ctx else None),
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        request_id=request_id or (ctx.request_id if ctx else None),
        source_ip=source_ip or (ctx.source_ip if ctx else None),
        details=details,
    )
    await session.execute(insert(AuditLog).values(**row))


async def record_independently(
    *,
    action: str,
    ctx: AuthContext | None = None,
    actor_type: str | None = None,
    actor_id: str | None = None,
    org_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    outcome: str = "failure",
    request_id: str | None = None,
    source_ip: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> None:
    """Append an audit row in its own transaction, committed immediately.

    Use for denials, authentication failures, and errors, where the request's
    own transaction is about to be rolled back and would take the record of the
    attempt with it.

    A failure to write the audit row is logged and swallowed. That is a
    deliberate trade: this path runs while an error is already being handled,
    and raising here would replace a clean 403 with a 500 and tell the caller
    that their denied request perturbed the server.
    """
    row = _build_row(
        action=action,
        actor_type=actor_type or (ctx.actor_type if ctx else "anonymous"),
        actor_id=actor_id or (ctx.actor_id if ctx else None),
        org_id=org_id or (ctx.org_id if ctx else None),
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        request_id=request_id or (ctx.request_id if ctx else None),
        source_ip=source_ip or (ctx.source_ip if ctx else None),
        details=details,
    )
    try:
        factory = get_sessionmaker()
        async with factory() as session:
            await session.execute(insert(AuditLog).values(**row))
            await session.commit()
    except Exception:
        logger.exception(
            "failed to write independent audit record",
            extra={"audit_action": action, "audit_outcome": outcome},
        )


async def record_denial(
    *,
    reason: str,
    action: str = AuditAction.ACCESS_DENIED,
    ctx: AuthContext | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    route: str | None = None,
) -> None:
    """Record an authorization denial.

    ``reason`` is the stable token from :class:`~aivs_server.auth.policy.PolicyDeniedError`.
    It is written here and never returned to the caller.
    """
    await record_independently(
        action=action,
        ctx=ctx,
        outcome="denied",
        resource_type=resource_type,
        resource_id=resource_id,
        request_id=request_id,
        source_ip=source_ip,
        details={"reason": reason, "route": route},
    )
