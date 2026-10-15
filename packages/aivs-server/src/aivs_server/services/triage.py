"""The first pass, run each time a member hands a submission to the ISAC (plan, Phase O).

Automation routes, annotates and returns; it never decides what members
receive. A submission handed to the ISAC is read once per submit by
:func:`~aivs_server.services.first_pass.first_pass`. Its findings are kept
for the reviewers and shown to the submitter. When a finding means the
content is wrong or no tool can use it, a member's own submission is
returned to it with what to change, before an analyst spends a minute on it.

What may be returned, and when, is deliberately narrow (Q38, draft):

- only the codes in :data:`RETURNING`, which the member can fix by itself;
- only a member's own filing: the ISAC's, an automation's and a proxy filing
  are triaged for the reviewers and never sent back to someone who did not
  write them;
- never something urgent (an SSVC "Act" decision, or KEV-listed), which goes
  to review with its notes, because urgency beats tidiness;
- never the same content twice: resubmitted unchanged, it goes to review.
  The member stays in control.

Runs off the request path, on the dispatcher's shape, and checks the pause:
a returned submission tells its member something, and a stop button stops
the announcements too (CLAUDE.md section 5).

The oracle rule. Every finding comes from the submission's own objects and
its submitter's own name, never from the ISAC's view, so none of them can
say anything about content the submitter cannot see. :data:`MEMBER_FACING`
is the list a submitter may be shown; a check that ever reads the ISAC's view
must produce a code outside it.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import (
    SubmissionSource,
    SubmissionState,
    TriageDisposition,
)
from aivs_schemas.extension.builders import AIVS_EXTENSION_ID, AIVS_INTEL_EXTENSION_ID
from aivs_server.audit.log import AuditAction, record
from aivs_server.db.models import (
    Organization,
    StixObject,
    Submission,
    SubmissionTransition,
    SubmissionTriage,
)
from aivs_server.services.first_pass import Finding, FindingCode, first_pass
from aivs_server.services.instance import distribution_is_paused
from aivs_server.services.submissions import is_isac_filing, load_submission, record_transition

__all__ = [
    "MEMBER_FACING",
    "RETURNING",
    "RULES_VERSION",
    "content_digest",
    "decide",
    "latest_triage",
    "shown_findings",
    "triage_pending",
    "triage_submission",
]

#: Which rules produced a row. Bump it when a check changes what it finds.
RULES_VERSION: Final[str] = "first-pass/1"

#: Findings that send a member's own submission back (Q38, draft): wrong, or
#: unusable by any tool. Every other finding goes to review with the notes.
RETURNING: Final[frozenset[FindingCode]] = frozenset(
    {
        FindingCode.DATED_IN_FUTURE,
        FindingCode.PRODUCT_NOT_MACHINE_READABLE,
        FindingCode.FIX_WITHOUT_FIXED_VERSIONS,
    }
)

#: Every code a submitter may read. All of them today: the first pass reads
#: nothing but the submission's own objects.
MEMBER_FACING: Final[frozenset[FindingCode]] = frozenset(FindingCode)

#: How many submissions one run reads; the rest wait for the next run.
_BATCH: Final[int] = 50


async def triage_pending(session: AsyncSession, *, now: dt.datetime) -> int:
    """Read each submission handed to the ISAC since it was last read; how many were read.

    Each is committed on its own, so one that fails does not hold back the rest.
    """
    if await distribution_is_paused(session):
        return 0
    read = 0
    for submission_id in await _pending(session):
        if await triage_submission(session, submission_id, now=now) is not None:
            read += 1
        await session.commit()
    return read


async def triage_submission(
    session: AsyncSession, submission_id: uuid.UUID, *, now: dt.datetime
) -> SubmissionTriage | None:
    """Read one submission under its row lock, or ``None`` if there is nothing to read.

    The lock is the one a member's withdrawal or resubmission takes, so a
    submission is never returned underneath its submitter's own move.
    """
    submission = await load_submission(session, submission_id, for_update=True)
    if submission is None or submission.state is not SubmissionState.SUBMITTED:
        return None
    transition_id = await _latest_submit(session, submission.id)
    if transition_id is None or await _already_read(session, transition_id):
        return None

    objects = await _objects(session, submission)
    digest = content_digest(objects)
    findings = first_pass(objects, own_names=await _own_names(session, submission), now=now)
    disposition = decide(
        findings,
        returnable=await _returnable(session, submission),
        urgent=_is_urgent(objects),
        returned_before=await _returned_before(session, submission.id, digest),
    )
    row = SubmissionTriage(
        submission_id=submission.id,
        transition_id=transition_id,
        content_sha256=digest,
        disposition=disposition,
        findings=[_stored(finding) for finding in findings],
        rules_version=RULES_VERSION,
    )
    session.add(row)
    if disposition is TriageDisposition.NEEDS_CHANGES:
        await record_transition(
            session, None, submission, SubmissionState.RETURNED, reason=_reason(findings)
        )
    await _audit(session, submission, disposition, findings)
    return row


def decide(
    findings: Iterable[Finding], *, returnable: bool, urgent: bool, returned_before: bool
) -> TriageDisposition:
    """Back to the member only when every condition for a return holds; review otherwise."""
    blocking = {finding.code for finding in findings} & RETURNING
    if blocking and returnable and not urgent and not returned_before:
        return TriageDisposition.NEEDS_CHANGES
    return TriageDisposition.READY_FOR_REVIEW


def content_digest(objects: Sequence[Mapping[str, Any]]) -> str:
    """The same objects, in any order, give the same digest."""
    canonical = sorted(json.dumps(obj, sort_keys=True, separators=(",", ":")) for obj in objects)
    return hashlib.sha256("\n".join(canonical).encode("utf-8")).hexdigest()


async def latest_triage(session: AsyncSession, submission_id: uuid.UUID) -> SubmissionTriage | None:
    """The newest read of a submission, if it has been read."""
    row: SubmissionTriage | None = await session.scalar(
        select(SubmissionTriage)
        .where(SubmissionTriage.submission_id == submission_id)
        .order_by(SubmissionTriage.transition_id.desc())
        .limit(1)
    )
    return row


def shown_findings(row: SubmissionTriage, *, reviewer: bool) -> list[dict[str, str]]:
    """A read's findings as one caller may see them: all to a reviewer, the
    member-facing codes to anyone else (the oracle rule)."""
    if reviewer:
        return list(row.findings)
    member_facing = {code.value for code in MEMBER_FACING}
    return [finding for finding in row.findings if finding["code"] in member_facing]


# ---------------------------------------------------------------------------
# What to read
# ---------------------------------------------------------------------------
def _latest_submit_of(submission_id: Any) -> Any:
    return (
        select(func.max(SubmissionTransition.id))
        .where(
            SubmissionTransition.submission_id == submission_id,
            SubmissionTransition.to_state == SubmissionState.SUBMITTED,
        )
        .scalar_subquery()
    )


async def _pending(session: AsyncSession) -> list[uuid.UUID]:
    """Submissions with the ISAC whose latest submit has not been read, oldest first."""
    latest = _latest_submit_of(Submission.id)
    query = (
        select(Submission.id)
        .where(
            Submission.state == SubmissionState.SUBMITTED,
            ~exists().where(SubmissionTriage.transition_id == latest),
        )
        .order_by(Submission.created_at)
        .limit(_BATCH)
    )
    return list((await session.execute(query)).scalars())


async def _latest_submit(session: AsyncSession, submission_id: uuid.UUID) -> int | None:
    return await session.scalar(select(_latest_submit_of(submission_id)))


async def _already_read(session: AsyncSession, transition_id: int) -> bool:
    found = await session.scalar(
        select(SubmissionTriage.id).where(SubmissionTriage.transition_id == transition_id)
    )
    return found is not None


async def _objects(session: AsyncSession, submission: Submission) -> list[Mapping[str, Any]]:
    rows = await session.execute(
        select(StixObject.raw).where(StixObject.submission_id == submission.id)
    )
    return list(rows.scalars())


async def _own_names(session: AsyncSession, submission: Submission) -> list[str]:
    submitter = await session.get(Organization, submission.submitter_org_id)
    return [submitter.name, submitter.slug] if submitter is not None else []


# ---------------------------------------------------------------------------
# Whether a return is allowed
# ---------------------------------------------------------------------------
async def _returnable(session: AsyncSession, submission: Submission) -> bool:
    """A member's own filing, written by the member: the only kind sent back to its writer."""
    return (
        submission.source is SubmissionSource.MEMBER
        and submission.filed_by_operator_id is None
        and not await is_isac_filing(session, submission)
    )


def _is_urgent(objects: Iterable[Mapping[str, Any]]) -> bool:
    """The submission itself says act now: urgency beats tidiness."""
    for obj in objects:
        extensions = obj.get("extensions") or {}
        body = extensions.get(AIVS_INTEL_EXTENSION_ID) or extensions.get(AIVS_EXTENSION_ID)
        if isinstance(body, Mapping) and (
            body.get("ssvc_decision") == "Act" or body.get("kev_listed") is True
        ):
            return True
    return False


async def _returned_before(session: AsyncSession, submission_id: uuid.UUID, digest: str) -> bool:
    """This content was sent back once already: resubmitted as it is, it goes to review."""
    found = await session.scalar(
        select(SubmissionTriage.id).where(
            SubmissionTriage.submission_id == submission_id,
            SubmissionTriage.content_sha256 == digest,
            SubmissionTriage.disposition == TriageDisposition.NEEDS_CHANGES,
        )
    )
    return found is not None


# ---------------------------------------------------------------------------
# What is written
# ---------------------------------------------------------------------------
def _stored(finding: Finding) -> dict[str, str]:
    return {"code": finding.code.value, "path": finding.path, "detail": finding.detail}


def _reason(findings: Iterable[Finding]) -> str:
    codes = sorted({finding.code.value for finding in findings} & set(RETURNING))
    return f"first pass ({RULES_VERSION}): {', '.join(codes)}"


async def _audit(
    session: AsyncSession,
    submission: Submission,
    disposition: TriageDisposition,
    findings: Sequence[Finding],
) -> None:
    """Which rules ran and what they decided; the codes, never the content they quote."""
    await record(
        session,
        action=AuditAction.SUBMISSION_TRIAGED,
        org_id=submission.submitter_org_id,
        resource_type="submission",
        resource_id=str(submission.id),
        details={
            "disposition": disposition.value,
            "codes": sorted({finding.code.value for finding in findings}),
            "rules_version": RULES_VERSION,
        },
    )
