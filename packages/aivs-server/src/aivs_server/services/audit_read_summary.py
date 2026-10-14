"""Summaries of who read the audit trail, served in both audit-stream modes.

In ``condensed`` mode the stream serves no ``audit.read`` rows, and in either
mode it serves no ``audit.read.quiet`` ones, so without this a SIEM would see
reads of the trail only as the ISAC's ``auditor_bulk_read`` alert. Each run
writes one ``audit.read.summary`` row per reader: pages served, quiet pages,
events served, first and last read, streams.

**What a run covers is a range of transactions, not a clock hour.** Each run
covers reads written by transactions from the previous run's upper bound up
to the stream's horizon, and records that range in its rows. Below the horizon
nothing can still commit, so a read that committed late is in the next run
rather than in an hour already summarised, and none is counted twice. The
watermark lives in the summary rows themselves, so there is no state to drift
from what was written.

Reading summaries is a read, and a summary of that is served on the next run:
each run adds at most one row per reader, so a poller draining the stream
still reaches an empty page.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import BigInteger, Text, cast, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.audit.log import AuditAction, record
from aivs_server.db.models import AuditLog
from aivs_server.services.instance import distribution_is_paused

__all__ = ["summarise_audit_reads"]

#: One summariser at a time across replicas; a second skips its run.
_SUMMARY_LOCK_KEY: Final[int] = 0x41495653_00000003  # "AIVS", lock 3

_READS: Final[tuple[str, ...]] = (AuditAction.AUDIT_READ, AuditAction.AUDIT_READ_QUIET)

_HORIZON = cast(cast(func.pg_snapshot_xmin(func.pg_current_snapshot()), Text), BigInteger)


@dataclass(frozen=True)
class _Reader:
    actor_id: str | None
    org_id: Any
    details: dict[str, Any]


async def summarise_audit_reads(session: AsyncSession) -> int:
    """Write this run's summaries; the number written. Commits.

    Skips the run while distribution is paused: the stop button stops what
    acts unattended (CLAUDE.md section 5), and the next run after resuming
    covers the paused stretch, since its range starts at the last watermark.
    """
    if not await _holds_summary_lock(session) or await distribution_is_paused(session):
        return 0
    since = await _watermark(session)
    until = int(await session.scalar(select(_HORIZON)) or 0)
    readers = await _readers(session, since, until) if until > since else []
    for reader in readers:
        await record(
            session,
            action=AuditAction.AUDIT_READ_SUMMARY,
            actor_type="system",
            org_id=reader.org_id,
            resource_type="audit_reader",
            resource_id=reader.actor_id,
            details={**reader.details, "covers_from_xact": since, "covers_to_xact": until},
        )
    await session.commit()
    return len(readers)


async def _holds_summary_lock(session: AsyncSession) -> bool:
    held = await session.scalar(
        text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": _SUMMARY_LOCK_KEY}
    )
    return bool(held)


async def _watermark(session: AsyncSession) -> int:
    """Where the last run stopped: the upper bound its summaries recorded."""
    last = await session.scalar(
        select(func.max(AuditLog.details["covers_to_xact"].as_integer())).where(
            AuditLog.action == AuditAction.AUDIT_READ_SUMMARY
        )
    )
    return int(last or 0)


async def _readers(session: AsyncSession, since: int, until: int) -> list[_Reader]:
    """Each reader's reads written by transactions in ``[since, until)``."""
    is_page = AuditLog.action == AuditAction.AUDIT_READ
    is_quiet = AuditLog.action == AuditAction.AUDIT_READ_QUIET
    rows = await session.execute(
        select(
            AuditLog.actor_type,
            AuditLog.actor_id,
            AuditLog.org_id,
            func.count().filter(is_page),
            func.count().filter(is_quiet),
            func.coalesce(func.sum(AuditLog.details["count"].as_integer()), 0),
            func.min(AuditLog.at),
            func.max(AuditLog.at),
            func.array_agg(func.distinct(AuditLog.details["stream"].as_string())),
        )
        .where(
            AuditLog.action.in_(_READS),
            AuditLog.xact_id >= since,
            AuditLog.xact_id < until,
        )
        .group_by(AuditLog.actor_type, AuditLog.actor_id, AuditLog.org_id)
        .order_by(AuditLog.actor_id)
    )
    return [
        _Reader(
            actor_id=actor_id,
            org_id=org_id,
            details={
                "pages": int(pages),
                "quiet_pages": int(quiet),
                "events": int(events),
                "first_at": first_at.isoformat(),
                "last_at": last_at.isoformat(),
                "streams": sorted(stream for stream in streams if stream),
                "reader_type": actor_type,
            },
        )
        for actor_type, actor_id, org_id, pages, quiet, events, first_at, last_at, streams in rows
    ]
