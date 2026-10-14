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
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import delete, func, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import ACCEPTED_DISCOVERY_SCOPES, SubmissionState, is_transition_allowed
from aivs_schemas.extension.builders import (
    AIVS_EXTENSION_ID,
    AIVS_INTEL_EXTENSION_ID,
    validate_bundle,
)
from aivs_schemas.models import DISCOVERY_SCOPE_REFUSAL
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import PolicyDeniedError, can_transition_submission, require
from aivs_server.db.models import Organization, StixObject, Submission, SubmissionTransition
from aivs_server.services.indexing import intel_index_fields
from aivs_server.taxii.resources import truncate_to_taxii_precision

__all__ = [
    "STORAGE_ERRORS",
    "SubmissionError",
    "apply_transition",
    "create_submission",
    "foreign_identity_ids",
    "replace_submission_objects",
    "self_identifying_problem",
    "update_submission",
]


#: CVSS base scores are 0.0-10.0; anything else is not a score and is
#: dropped rather than stored, so an object is never findable under a
#: severity that is not true of it.
_CVSS_MAX: Final[float] = 10.0

#: Storage bounds for the columns these values land in (see db/models.py).
#: Enforced at ingest so oversized member content is a validation error naming
#: the object, not a database exception surfacing as a server fault.
_MAX_STIX_ID: Final[int] = 100
_MAX_STIX_TYPE: Final[int] = 60
_MAX_OBJECT_NAME: Final[int] = 300


#: Database-level rejections of submitter-supplied content: a value too long
#: for its column, or one that violates a check constraint, means the bundle is
#: malformed -- the caller's problem, not a server fault. Every ingest surface
#: catches these and answers 400; the message is not echoed, because it would
#: expose column names and constraint definitions. One definition, because the
#: portal and the API disagreed about exactly this (finding #7).
STORAGE_ERRORS: Final = (IntegrityError, DBAPIError)


class SubmissionError(ValueError):
    """A submission operation was rejected for a reason the caller can fix."""


def _parse_stix_timestamp(value: Any, field: str, stix_id: str) -> dt.datetime:
    """Parse a STIX timestamp from an inbound object.

    STIX timestamps are UTC with a literal ``Z``. Anything unparseable is a
    rejection rather than a fallback to "now": inventing a timestamp for a
    versioned object silently corrupts its ordering for every consumer.

    Truncated to the millisecond TAXII renders at, for the same reason
    ``date_added`` is. ``modified`` is what a client sends back as
    ``match[version]``, and that filter compares for exact equality -- so an
    object stored with microseconds was advertised in the manifest as
    ``…123Z`` and then matched nothing when the client asked for exactly the
    version it had just been told about. Storing what can be advertised keeps
    the two descriptions the same one.
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
    try:
        in_utc = parsed.astimezone(dt.UTC)
    except OverflowError as exc:
        # 9999-12-31T23:30:00-01:00 parses, and has no UTC form. OverflowError is
        # not a ValueError, so it reached the catch-all as a server fault.
        msg = f"object {stix_id} has a '{field}' outside the representable range: {value!r}"
        raise SubmissionError(msg) from exc
    return truncate_to_taxii_precision(in_utc)


def _extract_indexed_fields(obj: dict[str, Any]) -> dict[str, Any]:
    """Pull the handful of columns AIVS indexes out of a STIX object.

    ``raw`` stays canonical; these are for search and filtering only. Anything
    unexpected is left null rather than coerced, because a wrong extracted value
    is worse than a missing one -- it makes the object findable under a
    description that is not true of it.
    """
    name = obj.get("name")
    extracted: dict[str, Any] = {
        # Truncated rather than rejected: `name` is a search convenience, not
        # identity, and `raw` keeps the full value. Refusing a vulnerability
        # report over a long title would be the wrong trade.
        "name": name[:_MAX_OBJECT_NAME] if isinstance(name, str) else None,
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

    # 1.0 and 2.0 describe a vulnerability's CVE and score with the same
    # property names, and validation refuses an object carrying both.
    extensions = obj.get("extensions") or {}
    body = extensions.get(AIVS_EXTENSION_ID) or extensions.get(AIVS_INTEL_EXTENSION_ID)
    if isinstance(body, dict):
        score = body.get("cvss_v4_base_score")
        if isinstance(score, (int, float)) and 0 <= score <= _CVSS_MAX:
            extracted["cvss_score"] = float(score)
        if extracted["cve_id"] is None:
            cve_id = body.get("cve_id")
            if isinstance(cve_id, str):
                extracted["cve_id"] = cve_id[:40]

    extracted.update(intel_index_fields(obj))
    return extracted


def identity_object_ids(objects: Iterable[Any]) -> list[str]:
    """Ids of every ``identity`` SDO in a sequence of raw STIX objects."""
    return [
        obj.get("id", "<no id>")
        for obj in objects
        if isinstance(obj, dict) and obj.get("type") == "identity"
    ]


def _mentions(value: Any, identifier: str) -> bool:
    """Whether ``identifier`` appears as any string value inside ``value``."""
    if isinstance(value, str):
        return value.lower() == identifier
    if isinstance(value, dict):
        return any(_mentions(item, identifier) for item in value.values())
    if isinstance(value, list):
        return any(_mentions(item, identifier) for item in value)
    return False


def _objects_naming(objects: Iterable[Any], own_identity_id: str) -> list[str]:
    """Objects that reference ``own_identity_id`` anywhere but ``created_by_ref``.

    ``created_by_ref`` is excluded because distribution rewrites it; every other
    reference -- ``where_sighted_refs``, a relationship's ``target_ref``,
    ``object_refs``, a custom property -- is served verbatim. Compared without
    case, because a consuming platform may treat identifiers that way.
    """
    identifier = own_identity_id.lower()
    return [
        obj.get("id", "<no id>")
        for obj in objects
        if isinstance(obj, dict)
        and _mentions({k: v for k, v in obj.items() if k != "created_by_ref"}, identifier)
    ]


def self_identifying_problem(objects: Iterable[Any], *, own_identity_id: str) -> str | None:
    """Why this content would identify an anonymous submitter anyway, or ``None``.

    ``distribute_anonymously`` is a promise the *server* makes -- "the ISAC still
    knows; consumers do not" -- and the pipeline can only keep the part it
    controls, the ``created_by_ref`` it rewrites. Everything else is
    redistributed verbatim, so two structural things defeat it: the submitter's
    own ``identity`` SDO, and any reference to the submitter's registered
    identifier ("sighted at us" is natural to write, and members know the id
    from the submitter's attributed content). The server holds that identifier,
    so it can refuse both.

    Refused rather than stripped: removing objects or references would change
    the meaning of what the submitter authored. Free text is still beyond it --
    a description naming the firm is the submitter's responsibility and the
    validating operator's to catch. That limit is documented, not papered over.

    One function for ingest and distribution, which raise in their own types.
    """
    listed = list(objects)
    identities = identity_object_ids(listed)
    if identities:
        return (
            "an anonymous submission must not carry identity objects, which are "
            f"redistributed verbatim and would name the submitter: {', '.join(identities)}. "
            "Remove them, or submit without distribute_anonymously."
        )
    naming = _objects_naming(listed, own_identity_id)
    if naming:
        return (
            "an anonymous submission must not reference the submitter's own identity, "
            f"which is redistributed verbatim and names it: {', '.join(naming)}"
        )
    return None


def reject_self_identifying_content(objects: Iterable[Any], *, own_identity_id: str) -> None:
    problem = self_identifying_problem(objects, own_identity_id=own_identity_id)
    if problem is not None:
        raise SubmissionError(problem)


async def submitter_identity_id(session: AsyncSession, submitter_org_id: uuid.UUID) -> str:
    identity = await session.scalar(
        select(Organization.stix_identity_id).where(Organization.id == submitter_org_id)
    )
    if identity is None:
        msg = "the submitting organisation has no registered identity"
        raise SubmissionError(msg)
    return identity


async def foreign_identity_ids(
    session: AsyncSession, objects: Iterable[Any], *, submitter_org_id: uuid.UUID
) -> list[str]:
    """Identity SDOs that use an identifier registered to a different organisation.

    Distribution rewrites ``created_by_ref`` and serves the rest of the bundle
    verbatim, so an ``identity`` object carrying a peer's registered
    ``stix_identity_id`` reaches every recipient's TIP as that peer's identity
    -- whatever name and sector the submitter wrote into it -- and the peer can
    neither see nor contest it. The same reasoning already refused inbound
    extension definitions and forged TLP markings; it had not been applied to
    identities. Identities that are not registered here (a vendor's, say) are
    left alone: they claim nothing about a member.

    A registered identifier is a random UUID a member only learns from content
    shared with it, so refusing one discloses nothing the caller lacked.
    """
    # Lower-cased: an upper-case spelling of a peer's identifier is the same
    # identifier to a consumer that compares without case.
    claimed = {identifier.lower() for identifier in identity_object_ids(objects)}
    if not claimed:
        return []
    owners = (
        await session.execute(
            select(Organization.stix_identity_id).where(
                func.lower(Organization.stix_identity_id).in_(claimed),
                Organization.id != submitter_org_id,
            )
        )
    ).scalars()
    return sorted(owners)


async def _reject_stored_self_identifying_content(
    session: AsyncSession, submission: Submission
) -> None:
    """Run the anonymity check against the objects already stored.

    Used where no bundle accompanies the change, so there is nothing to inspect
    but what is in the database.
    """
    raws = (
        (
            await session.execute(
                select(StixObject.raw).where(StixObject.submission_id == submission.id)
            )
        )
        .scalars()
        .all()
    )
    reject_self_identifying_content(
        raws, own_identity_id=await submitter_identity_id(session, submission.submitter_org_id)
    )


@dataclass(frozen=True, slots=True)
class _ParsedObject:
    """One bundle object, checked against everything storage and STIX require."""

    stix_id: str
    stix_type: str
    spec_version: str
    created: dt.datetime
    modified: dt.datetime


def _parse_object(obj: dict[str, Any]) -> _ParsedObject:
    """Check one object and return the fields it is stored under.

    Each refusal names the object, so a member's malformed bundle is a 400 that
    says what to fix rather than a database error surfacing as a server fault.
    """
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
    if modified < created:
        # STIX requires modified >= created. Beyond validity, a backwards pair
        # inverts `match[version]=last`, which resolves max(modified): a
        # submitter's corrected object would lose to their original.
        msg = (
            f"object {stix_id} has 'modified' ({modified.isoformat()}) earlier "
            f"than 'created' ({created.isoformat()})"
        )
        raise SubmissionError(msg)

    _check_column_bounds(stix_id, stix_type)

    spec_version = obj.get("spec_version", "2.1")
    if spec_version != "2.1":
        msg = f"object {stix_id} declares spec_version {spec_version!r}; AIVS stores 2.1 only"
        raise SubmissionError(msg)

    return _ParsedObject(stix_id, stix_type, spec_version, created, modified)


def _check_column_bounds(stix_id: str, stix_type: str) -> None:
    """Bounds matching the storage columns, checked before storage sees them."""
    for value, limit, field in (
        (stix_id, _MAX_STIX_ID, "id"),
        (stix_type, _MAX_STIX_TYPE, "type"),
    ):
        if len(value) > limit:
            msg = f"object '{value[:60]}...' has a '{field}' longer than {limit} characters"
            raise SubmissionError(msg)


async def _reject_identity_problems(
    session: AsyncSession, submission: Submission, objects: list[Any]
) -> None:
    """Refuse a bundle that names its anonymous submitter, or impersonates a peer."""
    if submission.distribute_anonymously:
        reject_self_identifying_content(
            objects,
            own_identity_id=await submitter_identity_id(session, submission.submitter_org_id),
        )

    impersonated = await foreign_identity_ids(
        session, objects, submitter_org_id=submission.submitter_org_id
    )
    if impersonated:
        msg = (
            "identity objects may not use an identifier registered to another "
            f"organisation: {', '.join(impersonated)}"
        )
        raise SubmissionError(msg)


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
    objects = bundle.get("objects") or []
    await _reject_identity_problems(session, submission, objects)

    await session.execute(delete(StixObject).where(StixObject.submission_id == submission.id))

    seen: set[tuple[str, dt.datetime]] = set()
    rows: list[StixObject] = []
    for obj in objects:
        parsed = _parse_object(obj)
        key = (parsed.stix_id, parsed.modified)
        if key in seen:
            # The same version twice in one bundle would violate the per-
            # submission uniqueness constraint; report it as the client error it
            # is rather than surfacing a database exception.
            msg = (
                f"bundle contains {parsed.stix_id} at version "
                f"{parsed.modified.isoformat()} more than once"
            )
            raise SubmissionError(msg)
        seen.add(key)
        rows.append(
            StixObject(
                stix_id=parsed.stix_id,
                type=parsed.stix_type,
                spec_version=parsed.spec_version,
                created=parsed.created,
                modified=parsed.modified,
                submission_id=submission.id,
                raw=obj,
                **_extract_indexed_fields(obj),
            )
        )

    session.add_all(rows)
    return len(rows)


def _require_accepted_scope(discovery_scope: Any) -> None:
    """Refuse a scope that may not be filed, in the request models' own words.

    The request models refuse first on every surface that has one; this is the
    check every writer passes through, so a caller that skips the models -- a
    script, a future inbox -- cannot store a reserved scope either.
    """
    if discovery_scope not in ACCEPTED_DISCOVERY_SCOPES:
        msg = f"discovery_scope: {DISCOVERY_SCOPE_REFUSAL}"
        raise SubmissionError(msg)


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
    via: str = "api",
) -> Submission:
    """Create a draft submission owned by the caller's organisation.

    ``via`` records which surface filed it. It is a detail on the single audit
    record this function writes, rather than a second record written by the
    caller: one event belongs in one row of a table that cannot be corrected.

    The submitter is taken from the authenticated context, never from the
    request body: a member must not be able to file content in another firm's
    name.
    """
    _require_accepted_scope(discovery_scope)
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
            "via": via,
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
    if "discovery_scope" in changes:
        _require_accepted_scope(changes["discovery_scope"])

    bundle = changes.pop("bundle", None)
    for field, value in changes.items():
        setattr(submission, field, value)

    if bundle is not None:
        await replace_submission_objects(session, submission, bundle)
    elif submission.distribute_anonymously:
        # Anonymity is a property of the submission as it stands, not of the
        # write that happened to carry a bundle. PATCH {"distribute_anonymously":
        # true} with no bundle turns the flag on over objects that were stored
        # while it was off -- and those may legitimately include the submitter's
        # own identity SDO, which is allowed for an attributed submission. Left
        # unchecked, that name is redistributed verbatim to every circle member
        # alongside a finding the submitter was told was anonymous.
        await _reject_stored_self_identifying_content(session, submission)

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


async def load_submission(
    session: AsyncSession, submission_id: uuid.UUID, *, for_update: bool = False
) -> Submission | None:
    """Fetch a submission by id, or ``None``.

    ``for_update`` takes a row lock, and every route that goes on to *change*
    the submission must use it. Without it, transitions are an unguarded
    read-modify-write: two requests both read ``validated``, both pass their
    guards, and the second UPDATE overwrites the first with no predicate on the
    state that was observed.

    The case that makes this matter is not hypothetical. Withdrawal is the
    submitter's only stop button, and "hold on, do not send that" is precisely
    the moment a submitter's withdraw and an operator's distribute are issued
    seconds apart. Losing that update distributes content the submitter
    retracted, and writes a transition history whose ``from_state`` never
    existed.
    """
    query = select(Submission).where(Submission.id == submission_id)
    if for_update:
        query = query.with_for_update()
    return (await session.execute(query)).scalar_one_or_none()
