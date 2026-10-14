"""The TAXII inbox: a member's platform contributes by sync (SF-69).

A G-SIB's MISP or OpenCTI can POST objects to a collection it may write to,
and contribute with no custom code. That makes the inbox a machine write path
into the review queue, so each POST is an ordinary submission and nothing more:

- **always reviewed.** It lands ``submitted``, never published, whatever it
  holds: a machine's content never takes the fast lane;
- **source ``system``.** Filed by a platform, not a person, whatever the
  envelope says, so the AI gate applies at validate (SF-6);
- **a contribution on public content.** An envelope carries no scope, so the
  inbox files ``disclosed_third_party``, and the disclosure split, TLP
  inheritance and owner-only versioning apply as on any filing. So a finding
  of the member's own (a ``vulnerability``) is refused by the disclosure
  split, as on any third-party filing: pre-CVE findings come through the
  native API, which asks for a scope;
- **the circle's floor.** An envelope carries no submission TLP either; the
  collection's circle floor is used, which the circle already requires;
- **anonymous**, as every contribution is by default, which also refuses
  ``identity`` objects (SF-50);
- **rate-limited**, against the same hourly allowance as everything published
  without review.

A ``status`` resource records each POST, readable by the organisation that made
it and answering 404 to anyone else.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Final

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import (
    TLP,
    DiscoveryScope,
    SubmissionLane,
    SubmissionSource,
    SubmissionState,
)
from aivs_schemas.extension.builders import MAX_BUNDLE_OBJECTS
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import PolicyDeniedError
from aivs_server.db.models import Circle, TaxiiCollection, TaxiiStatus
from aivs_server.db.org_lock import org_still_active
from aivs_server.services.contributions import (
    ContributionRateLimitedError,
    record_rate_limited,
    within_hourly_allowance,
)
from aivs_server.services.submissions import SubmissionError, apply_transition, create_submission

__all__ = ["INBOX_SCOPE", "receive_envelope", "status_of"]

#: The scope every inbox filing carries; see the module docstring.
INBOX_SCOPE: Final[DiscoveryScope] = DiscoveryScope.DISCLOSED_THIRD_PARTY


def _objects_of(envelope: Any) -> list[dict[str, Any]]:
    objects = envelope.get("objects") if isinstance(envelope, dict) else None
    if not isinstance(objects, list) or not objects:
        msg = "an envelope carries a non-empty 'objects' list"
        raise SubmissionError(msg)
    if len(objects) > MAX_BUNDLE_OBJECTS:
        msg = f"an envelope may carry at most {MAX_BUNDLE_OBJECTS} objects"
        raise SubmissionError(msg)
    return objects


async def receive_envelope(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    collection: TaxiiCollection,
    circle: Circle,
    envelope: Any,
    hourly_limit: int,
    now: dt.datetime,
) -> TaxiiStatus:
    """File an envelope as one submitted submission and record its status.

    The caller has already established that ``ctx`` may write to the
    collection.
    """
    objects = _objects_of(envelope)
    if not await org_still_active(session, ctx.org_id):
        denial = "inbox_org_not_active"
        raise PolicyDeniedError(denial)
    if not await within_hourly_allowance(session, ctx.org_id, limit=hourly_limit, now=now):
        await record_rate_limited(ctx, lane="taxii_inbox", limit=hourly_limit)
        raise ContributionRateLimitedError(ctx.org_id)

    submission = await create_submission(
        session,
        ctx,
        title=f"TAXII inbox: {len(objects)} object(s) to {circle.slug}",
        summary=None,
        tlp=TLP(circle.minimum_tlp),
        discovery_scope=INBOX_SCOPE,
        distribute_anonymously=True,
        bundle={"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects},
        filed_for=None,
        via="taxii",
    )
    submission.source = SubmissionSource.SYSTEM
    submission.lane = SubmissionLane.REVIEW
    await apply_transition(
        session, ctx, submission, SubmissionState.SUBMITTED, reason="TAXII inbox"
    )

    status = TaxiiStatus(
        org_id=ctx.org_id,
        submission_id=submission.id,
        status="complete",
        total_count=len(objects),
        success_count=len(objects),
        failure_count=0,
        pending_count=0,
        successes=[
            {"id": obj.get("id"), "version": obj.get("modified") or obj.get("created")}
            for obj in objects
        ],
        failures=[],
        pendings=[],
        request_timestamp=now,
    )
    session.add(status)
    await session.flush()
    await record(
        session,
        action=AuditAction.TAXII_INBOX_RECEIVED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={"collection_id": str(collection.id), "objects": len(objects)},
    )
    return status


async def status_of(
    session: AsyncSession, ctx: AuthContext, status_id: uuid.UUID
) -> TaxiiStatus | None:
    """The status resource, if the caller's organisation made the request; else ``None``."""
    row = await session.get(TaxiiStatus, status_id)
    if row is None or row.org_id != ctx.org_id:
        return None
    return row
