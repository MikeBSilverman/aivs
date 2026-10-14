"""Sector events: one living advisory, pinned while the sector works it.

Several times a year the whole membership works one vulnerability at once.
The ISAC revises its advisory all day; members need the current version in
front of them, not a hunt through a feed. An editor pins the ISAC's canonical
record for that vulnerability. Every entitled member then sees it at the top of
its dashboard, and every notice and digest line about it says it is part of the
event. Versions still coalesce at each member's cadence (``notify.digest``).

**Only the ISAC's own, distributed record can be pinned.** A member's object is
the member's to version, and pinning something not yet distributed would
announce that it exists.

**Members see an event only if they can see the vulnerability.** The listing
goes through the visibility gatherer, so an event pinned on a record shared
with three circles is invisible -- not refused, absent -- to everyone else. A
listing that showed every event would be an index of what the ISAC holds.

**Call notes are content, filed like content.** The template turns a call's
summary and action items into STIX ``note`` objects referencing the advisory,
filed as an ordinary ISAC draft: reviewed, marked and distributed through the
workflow, never published by this module.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import VISIBLE_SUBMISSION_STATES
from aivs_schemas.extension.builders import format_stix_timestamp
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import is_isac_editor, require
from aivs_server.db.models import Organization, SectorEvent, StixObject, Submission
from aivs_server.services.ownership import ISAC_OWNER_TYPES
from aivs_server.services.vulnerability_objects import (
    VulnerabilityHiddenError,
    gather_vulnerability,
)

__all__ = [
    "MAX_ACTION_ITEMS",
    "PinnedEvent",
    "SectorEventError",
    "call_notes_bundle",
    "close_sector_event",
    "open_sector_event",
    "pinned_events",
    "subjects_in_open_events",
]

#: A call's action items, bounded: a list longer than this is a document.
MAX_ACTION_ITEMS: Final[int] = 25


class SectorEventError(ValueError):
    """An event that cannot be opened or closed, with the reason an editor can act on."""


@dataclass(frozen=True)
class PinnedEvent:
    event_id: uuid.UUID
    vulnerability_stix_id: str
    title: str
    opened_at: dt.datetime
    updated: str


async def open_sector_event(
    session: AsyncSession, ctx: AuthContext, vulnerability_stix_id: str, *, now: dt.datetime
) -> SectorEvent:
    """Pin the ISAC's distributed record for ``vulnerability_stix_id``. Editors only.

    Does not commit. A second open event on the same vulnerability is refused
    here, and again by the database's partial unique index if two race.
    """
    require(is_isac_editor(ctx), "sector_event_requires_isac_editor")
    if not await _is_distributed_isac_record(session, vulnerability_stix_id):
        msg = "only a distributed ISAC vulnerability record can be pinned as a sector event"
        raise SectorEventError(msg)
    if await _open_event(session, vulnerability_stix_id) is not None:
        msg = "that vulnerability is already pinned; close the open event first"
        raise SectorEventError(msg)
    event = SectorEvent(
        vulnerability_stix_id=vulnerability_stix_id,
        opened_by_operator_id=ctx.operator_id,
        opened_at=now,
    )
    session.add(event)
    await session.flush()
    await record(
        session,
        action=AuditAction.SECTOR_EVENT_OPENED,
        ctx=ctx,
        resource_type="sector_event",
        resource_id=str(event.id),
        details={"vulnerability": vulnerability_stix_id},
    )
    return event


async def close_sector_event(
    session: AsyncSession, ctx: AuthContext, event_id: uuid.UUID, *, now: dt.datetime
) -> SectorEvent | None:
    """Unpin an event. Editors only. ``None`` if there is no such event. Does not commit."""
    require(is_isac_editor(ctx), "sector_event_requires_isac_editor")
    event = await session.scalar(
        select(SectorEvent).where(SectorEvent.id == event_id).with_for_update()
    )
    if event is None:
        return None
    if event.closed_at is not None:
        msg = "that sector event is already closed"
        raise SectorEventError(msg)
    event.closed_at = now
    event.closed_by_operator_id = ctx.operator_id
    await record(
        session,
        action=AuditAction.SECTOR_EVENT_CLOSED,
        ctx=ctx,
        resource_type="sector_event",
        resource_id=str(event.id),
        details={"vulnerability": event.vulnerability_stix_id},
    )
    return event


async def pinned_events(
    session: AsyncSession, ctx: AuthContext, *, now: dt.datetime
) -> list[PinnedEvent]:
    """The open events ``ctx`` may see, each named from the version ``ctx`` can see."""
    events = (
        await session.scalars(
            select(SectorEvent)
            .where(SectorEvent.closed_at.is_(None))
            .order_by(SectorEvent.opened_at.desc())
        )
    ).all()
    pinned = []
    for event in events:
        try:
            objects = await gather_vulnerability(session, ctx, event.vulnerability_stix_id, now=now)
        except VulnerabilityHiddenError:
            continue
        raw = objects.vulnerability.raw
        pinned.append(
            PinnedEvent(
                event_id=event.id,
                vulnerability_stix_id=event.vulnerability_stix_id,
                title=str(raw.get("name") or event.vulnerability_stix_id),
                opened_at=event.opened_at,
                updated=str(raw.get("modified", "")),
            )
        )
    return pinned


async def subjects_in_open_events(session: AsyncSession, subjects: Sequence[str]) -> set[str]:
    """Which of these notice subjects (vulnerability ids) are pinned right now."""
    if not subjects:
        return set()
    rows = await session.scalars(
        select(SectorEvent.vulnerability_stix_id).where(
            SectorEvent.closed_at.is_(None),
            SectorEvent.vulnerability_stix_id.in_(list(subjects)),
        )
    )
    return set(rows.all())


def call_notes_bundle(
    advisory_stix_id: str,
    *,
    summary: str,
    action_items: Sequence[str],
    now: dt.datetime,
) -> dict[str, Any]:
    """A call's summary and action items as STIX ``note`` objects on the advisory.

    One note for the summary, and one per action item, so a member's TIP can
    track each item on its own. Pure: the caller files the bundle as a draft.
    """
    items = [item.strip() for item in action_items if item.strip()]
    if not summary.strip():
        msg = "the call notes need a summary"
        raise SectorEventError(msg)
    if len(items) > MAX_ACTION_ITEMS:
        msg = f"at most {MAX_ACTION_ITEMS} action items; attach a document for more"
        raise SectorEventError(msg)
    stamp = format_stix_timestamp(now)
    notes = [_note(advisory_stix_id, "Call summary", summary.strip(), stamp)]
    notes += [
        _note(advisory_stix_id, f"Action item {number} of {len(items)}", item, stamp)
        for number, item in enumerate(items, start=1)
    ]
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": notes}


def _note(advisory_stix_id: str, abstract: str, content: str, stamp: str) -> dict[str, Any]:
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": f"note--{uuid.uuid4()}",
        "created": stamp,
        "modified": stamp,
        "abstract": abstract,
        "content": content,
        "object_refs": [advisory_stix_id],
    }


async def _is_distributed_isac_record(session: AsyncSession, stix_id: str) -> bool:
    """Whether the ISAC (or its automation) holds a distributed version of ``stix_id``.

    Distributed means a submission in a visible state; that state is only ever
    set with the distribution rows, so the state alone is the test.
    """
    isac_orgs = select(Organization.id).where(Organization.org_type.in_(tuple(ISAC_OWNER_TYPES)))
    found = await session.scalar(
        select(
            exists().where(
                StixObject.stix_id == stix_id,
                StixObject.type == "vulnerability",
                Submission.id == StixObject.submission_id,
                Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)),
                Submission.submitter_org_id.in_(isac_orgs),
            )
        )
    )
    return bool(found)


async def _open_event(session: AsyncSession, stix_id: str) -> SectorEvent | None:
    event: SectorEvent | None = await session.scalar(
        select(SectorEvent).where(
            SectorEvent.vulnerability_stix_id == stix_id, SectorEvent.closed_at.is_(None)
        )
    )
    return event
