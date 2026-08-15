"""Submission lifecycle: creation, amendment, and workflow transitions.

The state machine itself is declared once in ``aivs_schemas.enums`` and the
right to perform a given move is decided once in ``auth.policy``. This module
owns neither; it orchestrates them and records what happened.

Two rules are enforced here and are the reason the module exists:

**Content is validated on the way in, not on the way out.** A malformed bundle
is rejected while the submitter is still editing a draft, rather than at
distribution time when an ISAC operator is trying to release it and the
submitter may be unreachable.

**Every transition writes history in the same transaction as the state change.**
A submission whose ``state`` says ``distributed`` but whose transition log does
not is unreconstructable, and the transition log is evidence.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Final

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import SubmissionState, is_transition_allowed
from aivs_schemas.extension.builders import AIVS_EXTENSION_ID, validate_bundle
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import PolicyDeniedError, can_transition_submission, require
from aivs_server.db.models import StixObject, Submission, SubmissionTransition

__all__ = [
    "SubmissionError",
    "apply_transition",
    "create_submission",
    "replace_submission_objects",
    "update_submission",
]


#: CVSS base scores are 0.0-10.0; anything else is not a score and is
#: dropped rather than stored, so an object is never findable under a
#: severity that is not true of it.
_CVSS_MAX: Final[float] = 10.0


class SubmissionError(ValueError):
    """A submission operation was rejected for a reason the caller can fix."""


def _parse_stix_timestamp(value: Any, field: str, stix_id: str) -> dt.datetime:
    """Parse a STIX timestamp from an inbound object.

    STIX timestamps are UTC with a literal ``Z``. Anything unparseable is a
    rejection rather than a fallback to "now": inventing a timestamp for a
    versioned object silently corrupts its ordering for every consumer.
    """
    if not isinstance(value, str):
        msg = f"object {stix_id} has a non-string '{field}'"
        raise SubmissionError(msg)
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        msg = f"object {stix_id} has an unparseable '{field}': {value!r}"
        raise SubmissionError(msg) from exc
    if parsed.tzinfo is None:
        msg = f"object {stix_id} has a '{field}' without a timezone"
        raise SubmissionError(msg)
    return parsed.astimezone(dt.UTC)


def _extract_indexed_fields(obj: dict[str, Any]) -> dict[str, Any]:
    """Pull the handful of columns AIVS indexes out of a STIX object.

    ``raw`` stays canonical; these are for search and filtering only. Anything
    unexpected is left null rather than coerced, because a wrong extracted value
    is worse than a missing one -- it makes the object findable under a
    description that is not true of it.
    """
    name = obj.get("name")
    extracted: dict[str, Any] = {
        "name": name if isinstance(name, str) else None,
        "cve_id": None,
        "cvss_score": None,
    }

    for reference in obj.get("external_references") or []:
        if not isinstance(reference, dict):
            continue
        if reference.get("source_name") == "cve":
            external_id = reference.get("external_id")
            if isinstance(external_id, str) and external_id.startswith("CVE-"):
                extracted["cve_id"] = external_id[:40]
                break

    body = (obj.get("extensions") or {}).get(AIVS_EXTENSION_ID)
    if isinstance(body, dict):
        score = body.get("cvss_v4_base_score")
        if isinstance(score, (int, float)) and 0 <= score <= _CVSS_MAX:
            extracted["cvss_score"] = float(score)
        if extracted["cve_id"] is None:
            cve_id = body.get("cve_id")
            if isinstance(cve_id, str):
                extracted["cve_id"] = cve_id[:40]

    return extracted


async def replace_submission_objects(
    session: AsyncSession, submission: Submission, bundle: dict[str, Any]
) -> int:
    """Validate a bundle and store its objects against ``submission``.

    Replaces any objects the submission already had, which is what an amended
    draft needs. Only ever called for drafts: once a submission is distributed
    its objects are referenced by distribution rows and are immutable.
    """
    if submission.state is not SubmissionState.DRAFT:
        msg = "objects may only be replaced while a submission is a draft"
        raise SubmissionError(msg)

    # Validates every object in the bundle, including ones AIVS does not read,
    # and enforces the extension allowlist.
    validate_bundle(bundle)

    await session.execute(delete(StixObject).where(StixObject.submission_id == submission.id))

    seen: set[tuple[str, dt.datetime]] = set()
    rows: list[StixObject] = []

    for obj in bundle.get("objects") or []:
        stix_id = obj.get("id")
        if not isinstance(stix_id, str) or "--" not in stix_id:
            msg = f"object has a missing or malformed 'id': {stix_id!r}"
            raise SubmissionError(msg)

        stix_type = obj.get("type")
        if not isinstance(stix_type, str):
            msg = f"object {stix_id} has a missing or malformed 'type'"
            raise SubmissionError(msg)

        created_raw = obj.get("created")
        modified_raw = obj.get("modified", created_raw)
        if created_raw is None:
            # Marking definitions and some meta objects legitimately carry no
            # modified; they must still carry created.
            msg = f"object {stix_id} has no 'created' timestamp"
            raise SubmissionError(msg)

        created = _parse_stix_timestamp(created_raw, "created", stix_id)
        modified = _parse_stix_timestamp(modified_raw, "modified", stix_id)

        key = (stix_id, modified)
        if key in seen:
            # The same version twice in one bundle would violate the per-
            # submission uniqueness constraint; report it as the client error it
            # is rather than surfacing a database exception.
            msg = f"bundle contains {stix_id} at version {modified.isoformat()} more than once"
            raise SubmissionError(msg)
        seen.add(key)

        rows.append(
            StixObject(
                stix_id=stix_id,
                type=stix_type,
                spec_version=obj.get("spec_version", "2.1"),
                created=created,
                modified=modified,
                submission_id=submission.id,
                raw=obj,
                **_extract_indexed_fields(obj),
            )
        )

    session.add_all(rows)
    return len(rows)


async def create_submission(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    title: str,
    summary: str | None,
    tlp: Any,
    discovery_scope: Any,
    distribute_anonymously: bool,
    bundle: dict[str, Any],
) -> Submission:
    """Create a draft submission owned by the caller's organisation.

    The submitter is taken from the authenticated context, never from the
    request body: a member must not be able to file content in another firm's
    name.
    """
    submission = Submission(
        submitter_org_id=ctx.org_id,
        created_by_operator_id=ctx.operator_id,
        state=SubmissionState.DRAFT,
        tlp=tlp,
        discovery_scope=discovery_scope,
        distribute_anonymously=distribute_anonymously,
        title=title,
        summary=summary,
    )
    session.add(submission)
    await session.flush()

    object_count = await replace_submission_objects(session, submission, bundle)

    session.add(
        SubmissionTransition(
            submission_id=submission.id,
            from_state=None,
            to_state=SubmissionState.DRAFT,
            actor_org_id=ctx.org_id,
            actor_operator_id=ctx.operator_id,
            reason="created",
        )
    )
    await record(
        session,
        action=AuditAction.SUBMISSION_CREATED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={
            "title": title,
            "tlp": str(tlp),
            "discovery_scope": str(discovery_scope),
            "object_count": object_count,
            "anonymous": distribute_anonymously,
        },
    )
    return submission


async def update_submission(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    *,
    changes: dict[str, Any],
) -> Submission:
    """Amend a draft submission.

    Refuses outside the draft state. Once a submission has been handed to the
    ISAC for validation, changing it underneath that review would mean the
    content approved is not the content distributed.
    """
    if submission.state is not SubmissionState.DRAFT:
        msg = f"a submission in state '{submission.state.value}' can no longer be edited"
        raise SubmissionError(msg)
    if submission.submitter_org_id != ctx.org_id:
        denial = "submission_not_owned"
        raise PolicyDeniedError(denial)

    bundle = changes.pop("bundle", None)
    for field, value in changes.items():
        setattr(submission, field, value)

    if bundle is not None:
        await replace_submission_objects(session, submission, bundle)

    await record(
        session,
        action=AuditAction.SUBMISSION_UPDATED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={"fields": sorted(changes), "bundle_replaced": bundle is not None},
    )
    return submission


async def apply_transition(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    target: SubmissionState,
    *,
    reason: str | None = None,
) -> Submission:
    """Move a submission to ``target``, recording the move.

    Two independent gates, in this order: the move must be legal in the state
    machine, and the caller must hold the right to perform that particular move.
    Checking legality first means an authorized caller attempting an impossible
    move gets a comprehensible error rather than a denial.
    """
    if not is_transition_allowed(submission.state, target):
        msg = f"cannot move a submission from '{submission.state.value}' to '{target.value}'"
        raise SubmissionError(msg)

    require(
        can_transition_submission(ctx, submission, target),
        f"transition_{submission.state.value}_to_{target.value}",
    )

    previous = submission.state
    submission.state = target
    if target is SubmissionState.DISTRIBUTED and submission.distributed_at is None:
        submission.distributed_at = dt.datetime.now(dt.UTC)

    session.add(
        SubmissionTransition(
            submission_id=submission.id,
            from_state=previous,
            to_state=target,
            actor_org_id=ctx.org_id,
            actor_operator_id=ctx.operator_id,
            reason=reason,
        )
    )
    await record(
        session,
        action=AuditAction.SUBMISSION_TRANSITIONED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={"from": previous.value, "to": target.value, "reason": reason},
    )
    return submission


async def load_submission(session: AsyncSession, submission_id: uuid.UUID) -> Submission | None:
    """Fetch a submission by id, or ``None``."""
    return (
        await session.execute(select(Submission).where(Submission.id == submission_id))
    ).scalar_one_or_none()
