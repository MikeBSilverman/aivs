"""Read-only queries behind ``scenario.sh``.

Deliberately routed through the application's own visibility logic
(``auth.policy.visible_content_clause``) rather than through queries written for
the demo. A demonstration that reimplements the rule it is demonstrating proves
nothing about the system; this one shows exactly what a member's TAXII poll
would return, because it asks the same question the server asks.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import os
import sys

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aivs_schemas.enums import AckType, AckVia, CircleRole
from aivs_server.auth.policy import visible_content_clause
from aivs_server.db.models import (
    Acknowledgment,
    Circle,
    CircleMembership,
    Distribution,
    Organization,
    StixObject,
    Submission,
)
from aivs_server.services.attribution import submitter_of
from aivs_server.services.receipts import record_retrievals

DATABASE_URL = os.environ.get(
    "AIVS_DEMO_DATABASE_URL",
    "postgresql+psycopg://aivs@127.0.0.1:55432/aivs_demo",
)


def out(line: str = "") -> None:
    print(line)  # noqa: T201 - this script's entire purpose is printing


async def community(session: AsyncSession) -> None:
    rows = (
        await session.execute(
            select(Organization.name, Organization.org_type, Circle.name, CircleMembership.role)
            .join(CircleMembership, CircleMembership.org_id == Organization.id, isouter=True)
            .join(Circle, Circle.id == CircleMembership.circle_id, isouter=True)
            .order_by(Organization.name, Circle.name)
        )
    ).all()

    current = None
    for org_name, org_type, circle_name, role in rows:
        if org_name != current:
            out(f"  {org_name}  ({str(org_type).replace('_', ' ')})")
            current = org_name
        if circle_name:
            label = "contributes to" if role is CircleRole.CONTRIBUTOR else "reads"
            out(f"      {label:>14}  {circle_name}")
    out()
    out("  Ridgeline Utilities is deliberately outside the two tighter circles.")


async def submission(session: AsyncSession) -> None:
    record = (await session.execute(select(Submission))).scalars().first()
    if record is None:
        out("  (nothing seeded)")
        return

    submitter = await session.get(Organization, await submitter_of(session, record))
    objects = (
        (await session.execute(select(StixObject).where(StixObject.submission_id == record.id)))
        .scalars()
        .all()
    )

    out(f"  {record.title}")
    out(f"  filed by {submitter.name if submitter else '?'}")
    out(f"  marking  {str(record.tlp).replace('_', '+').upper()}")
    out(f"  scope    {str(record.discovery_scope).replace('_', ' ')}")
    out()
    for item in sorted(objects, key=lambda o: (o.type, o.name or "")):
        if item.type == "vulnerability":
            out(f"      vulnerability   {item.name}")
    chain = sum(1 for item in objects if item.type == "relationship")
    out(f"      {chain} 'chains-to' relationships joining them in exploit order")


async def _visible_counts(session: AsyncSession, now: dt.datetime) -> list[tuple[str, int]]:
    """How many objects each organisation can see right now."""
    results: list[tuple[str, int]] = []
    orgs = (await session.execute(select(Organization).order_by(Organization.name))).scalars().all()
    for org in orgs:
        circle_ids = (
            (
                await session.execute(
                    select(CircleMembership.circle_id).where(CircleMembership.org_id == org.id)
                )
            )
            .scalars()
            .all()
        )
        count = (
            await session.scalar(
                select(func.count(func.distinct(Distribution.stix_object_id)))
                .select_from(Distribution)
                .join(Submission, Submission.id == Distribution.submission_id)
                .where(visible_content_clause(circle_ids, now))
            )
        ) or 0
        results.append((org.name, count))
    return results


async def visibility(session: AsyncSession) -> None:
    now = dt.datetime.now(dt.UTC)
    for name, count in await _visible_counts(session, now):
        state = f"{count} object(s) visible" if count else "nothing visible"
        out(f"  {name:36} {state}")


async def seconds_until_release(session: AsyncSession) -> None:
    earliest = await session.scalar(select(func.min(Distribution.date_added)))
    if earliest is None:
        out("0")
        return
    remaining = (earliest - dt.datetime.now(dt.UTC)).total_seconds()
    out(str(max(0, int(remaining) + 1)))


async def poll(session: AsyncSession) -> None:
    """Simulate each member collecting, which is what writes a receipt."""
    now = dt.datetime.now(dt.UTC)
    orgs = (await session.execute(select(Organization).order_by(Organization.name))).scalars().all()
    for org in orgs:
        circle_ids = (
            (
                await session.execute(
                    select(CircleMembership.circle_id).where(CircleMembership.org_id == org.id)
                )
            )
            .scalars()
            .all()
        )
        submission_ids = (
            (
                await session.execute(
                    select(Distribution.submission_id)
                    .join(Submission, Submission.id == Distribution.submission_id)
                    .where(visible_content_clause(circle_ids, now))
                    .distinct()
                )
            )
            .scalars()
            .all()
        )
        if submission_ids:
            written = await record_retrievals(
                session,
                org_id=org.id,
                submission_ids=submission_ids,
                via=AckVia.TAXII,
                actor_ref="demo-collector",
                now=now,
            )
            await session.commit()
            out(
                f"  {org.name:36} collected {len(submission_ids)} submission(s) ({written} receipt)"
            )
        else:
            out(f"  {org.name:36} nothing to collect")


async def receipts(session: AsyncSession) -> None:
    rows = (
        await session.execute(
            select(
                Organization.name,
                Acknowledgment.ack_type,
                Acknowledgment.via,
                func.min(Acknowledgment.created_at),
            )
            .join(Organization, Organization.id == Acknowledgment.org_id)
            .group_by(Organization.name, Acknowledgment.ack_type, Acknowledgment.via)
            .order_by(Organization.name)
        )
    ).all()

    if not rows:
        out("  (no receipts yet)")
        return

    for name, ack_type, via, first_at in rows:
        verb = "retrieved" if ack_type is AckType.RETRIEVED else str(ack_type)
        out(f"  {name:36} {verb:12} via {via!s:6} at {first_at:%Y-%m-%d %H:%M:%S} UTC")


COMMANDS = {
    "community": community,
    "submission": submission,
    "visibility": visibility,
    "seconds_until_release": seconds_until_release,
    "poll": poll,
    "receipts": receipts,
}


async def main() -> int:
    # argv is [script, command]; anything else is a usage error.
    expected_argv = 2
    if len(sys.argv) != expected_argv or sys.argv[1] not in COMMANDS:
        out(f"usage: _query.py [{'|'.join(COMMANDS)}]")
        return 2

    engine = create_async_engine(DATABASE_URL)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    try:
        async with factory() as session:
            await COMMANDS[sys.argv[1]](session)
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
