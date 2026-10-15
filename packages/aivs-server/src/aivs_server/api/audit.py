"""The auditor's read: the audit trail and receipts, as a cursor a person or a SIEM polls.

``GET /api/v1/audit/events`` and ``GET /api/v1/audit/receipts`` return a page
of events and the cursor to continue from; polling with the last cursor
returns what has been written since. Each event carries its link in a hash
chain that runs across pages (``services.audit_stream``).

Refused, before anything about the request is examined, unless the caller is
an auditor whose access has not ended (``policy.can_read_audit``); scoped by
``policy.audit_scope``. Every read is itself audited, with the stream and the
number of events. What the stream serves of those records is the instance's
audit-stream mode (``services.audit_stream_mode``), and in either mode a page
that served only reads, or nothing, is recorded as ``audit.read.quiet`` and
never served, so a poller always reaches an empty page.
"""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.deps import AuditorContext, SessionDep
from aivs_server.auth.policy import audit_scope, can_read_audit, require
from aivs_server.db.clock import database_now
from aivs_server.services.audit_stream import (
    MAX_PAGE,
    CursorError,
    Page,
    decode_cursor,
    receipt_events,
)
from aivs_server.services.member_staff_reads import audit_page

__all__ = ["router"]

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

_BAD_CURSOR: Final = HTTPException(status.HTTP_400_BAD_REQUEST, detail="Malformed cursor")


class StreamPage(BaseModel):
    events: list[dict[str, Any]]
    #: Pass back as ``cursor`` to continue. Unchanged when nothing new has
    #: committed below the stream's horizon.
    cursor: str


@router.get("/events", response_model=StreamPage)
async def events(
    ctx: AuditorContext,
    session: SessionDep,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 100,
) -> StreamPage:
    """The audit trail, in commit order, within the caller's scope.

    Reads of the trail are served by the instance's audit-stream mode. In
    ``condensed`` (the default) ``audit.read`` rows are left out and an hourly
    ``audit.read.summary`` row per reader is served instead. In ``full`` they
    are served as written. In both, a page that served only reads, or nothing,
    is recorded as ``audit.read.quiet``, which is never served, so a poller
    reaches an empty page; the summaries count those pages, and the ISAC's
    ``auditor_bulk_read`` rule counts every kind. A change of mode is served as
    ``audit_stream.mode_changed`` and applies to reads written after it, so
    cursors and the hash chain are unaffected.
    """
    await _require_auditor(session, ctx)
    after = _parse(cursor, "audit")
    # A member's auditor reads its own organisation's rows on a staff session
    # (the member login may only write the audit log); the read is recorded
    # on this request's own session and committed before the page is
    # returned, so a page served is a read recorded and a failed read records
    # nothing.
    page = await audit_page(session, ctx, after=after, limit=limit)
    return await _served(session, ctx, "audit", page)


@router.get("/receipts", response_model=StreamPage)
async def receipts(
    ctx: AuditorContext,
    session: SessionDep,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 100,
) -> StreamPage:
    """Receipts, in commit order, within the caller's scope."""
    await _require_auditor(session, ctx)
    after = _parse(cursor, "receipts")
    page = await receipt_events(session, scope=audit_scope(ctx), after=after, limit=limit)
    return await _served(session, ctx, "receipts", page)


async def _require_auditor(session: AsyncSession, ctx: AuthContext) -> None:
    require(can_read_audit(ctx, await database_now(session)), "read_audit")


def _parse(cursor: str | None, stream: str) -> Any:
    if cursor is None:
        return None
    try:
        return decode_cursor(cursor, stream)
    except CursorError:
        raise _BAD_CURSOR from None


async def _served(session: AsyncSession, ctx: AuthContext, stream: str, page: Page) -> StreamPage:
    await record(
        session,
        action=AuditAction.AUDIT_READ_QUIET if _is_quiet(stream, page) else AuditAction.AUDIT_READ,
        ctx=ctx,
        resource_type="audit_stream",
        resource_id=stream,
        details={"stream": stream, "count": len(page.events)},
    )
    await session.commit()
    return StreamPage(events=list(page.events), cursor=page.cursor.encode())


def _is_quiet(stream: str, page: Page) -> bool:
    """A page that served nothing, or on the audit stream only reads.

    Its record is never served, in either mode. Recorded as a read, it would be
    the next page's content in ``full`` mode, and two pollers reading each
    other's reads would never reach an empty page.
    """
    if stream != "audit":
        return not page.events
    return all(event["action"] == AuditAction.AUDIT_READ for event in page.events)
