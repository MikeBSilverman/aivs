"""Validating a review group in one audited action.

A KEV enrichment run files forty submissions at once; validating them one by
one turns the checkpoint into forty clicks of rubber stamp. An editor may
instead validate a group -- one organisation's filings of one kind, as the
review queue groups them -- in one action, recorded once.

**What a group may never carry is decided where every validation is.** Each
submission still goes through ``apply_transition`` with no acknowledged
changes, so one that makes a consequential machine change (the AI gate) is
refused exactly as a single validate would refuse it, and the whole group with
it: bulk validation is for the routine, and the gate's rule lives in one place
(CLAUDE.md section 5, "validate-time rules live in apply_transition").

The group is all or nothing, in one transaction the caller commits. Rows are
locked in id order, so two editors validating overlapping groups wait for each
other instead of deadlocking.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Final

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import SubmissionState
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import can_validate_in_bulk, require
from aivs_server.db.models import Submission
from aivs_server.services.submissions import SubmissionError, apply_transition, load_submission

__all__ = ["MAX_GROUP_SIZE", "GroupMemberNotFoundError", "validate_group"]

#: The review queue shows at most this many; a group larger than the queue
#: was not read by anyone.
MAX_GROUP_SIZE: Final[int] = 200


class GroupMemberNotFoundError(LookupError):
    """A submission in the group does not exist."""


async def validate_group(
    session: AsyncSession, ctx: AuthContext, submission_ids: Sequence[uuid.UUID]
) -> list[Submission]:
    """Validate every submission in one review group, or none of them."""
    require(can_validate_in_bulk(ctx), "bulk_validate")
    ids = sorted(set(submission_ids))
    if not 0 < len(ids) <= MAX_GROUP_SIZE:
        msg = f"a group is between 1 and {MAX_GROUP_SIZE} submissions, not {len(ids)}"
        raise SubmissionError(msg)

    submissions = [await _locked(session, submission_id) for submission_id in ids]
    _require_one_group(submissions)
    for submission in submissions:
        await apply_transition(session, ctx, submission, SubmissionState.VALIDATED)

    first = submissions[0]
    await record(
        session,
        action=AuditAction.SUBMISSION_BULK_VALIDATED,
        ctx=ctx,
        resource_type="organization",
        resource_id=str(first.submitter_org_id),
        details={"source": first.source.value, "submission_ids": [str(s.id) for s in submissions]},
    )
    return submissions


async def _locked(session: AsyncSession, submission_id: uuid.UUID) -> Submission:
    submission = await load_submission(session, submission_id, for_update=True)
    if submission is None:
        raise GroupMemberNotFoundError(submission_id)
    return submission


def _require_one_group(submissions: Sequence[Submission]) -> None:
    """One organisation's filings, all by a person or all by an automation."""
    groups = {(submission.submitter_org_id, submission.source) for submission in submissions}
    if len(groups) != 1:
        msg = (
            "bulk validation takes one review group: one organisation's filings, "
            "all by a member or all by an automation"
        )
        raise SubmissionError(msg)
