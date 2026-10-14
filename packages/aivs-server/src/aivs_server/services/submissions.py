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

from aivs_schemas.enums import (
    TLP,
    OrgType,
    SubmissionSource,
    SubmissionState,
    is_transition_allowed,
)
from aivs_schemas.extension.builders import (
    AIVS_EXTENSION_ID,
    AIVS_INTEL_EXTENSION_ID,
    validate_bundle,
)
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import PolicyDeniedError, can_transition_submission, require
from aivs_server.db.models import Organization, StixObject, Submission, SubmissionTransition
from aivs_server.services.disclosure import DisclosureScope, disclosure_problem
from aivs_server.services.indexing import intel_index_fields
from aivs_server.services.markings import looser_than_referents_problem
from aivs_server.services.ownership import foreign_owned_versions_problem
from aivs_server.services.provenance import (
    consequential_changes,
    reviewer_identity_id,
    stamp_review,
    unacknowledged_changes_problem,
)
from aivs_server.services.references import referenced_ids
from aivs_server.taxii.resources import truncate_to_taxii_precision

__all__ = [
    "STORAGE_ERRORS",
    "ProxyFiling",
    "SubmissionError",
    "apply_transition",
    "check_content_rules",
    "contribution_problem",
    "create_submission",
    "foreign_identity_ids",
    "record_transition",
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
    located = _sightings_saying_where(listed)
    if located:
        return (
            "an anonymous sighting must not say where it was seen; where_sighted_refs names "
            f"the organisation that saw it: {', '.join(located)}"
        )
    authored = _objects_with_authors(listed)
    if authored:
        return (
            "an anonymous submission must not name authors, which are redistributed "
            f"verbatim: {', '.join(authored)}"
        )
    return None


def _sightings_saying_where(objects: Iterable[Any]) -> list[str]:
    """Sightings that name where they were seen (SF-50)."""
    return [
        obj.get("id", "<no id>")
        for obj in objects
        if isinstance(obj, dict) and obj.get("type") == "sighting" and obj.get("where_sighted_refs")
    ]


def _objects_with_authors(objects: Iterable[Any]) -> list[str]:
    """Notes and opinions that carry author names, free text naming people (SF-50)."""
    return [
        obj.get("id", "<no id>")
        for obj in objects
        if isinstance(obj, dict) and obj.get("type") in {"note", "opinion"} and obj.get("authors")
    ]


def sightings_elsewhere_problem(objects: Iterable[Any], *, own_identity_id: str) -> str | None:
    """Why an attributed submission's sightings may not be filed, or ``None`` (SF-50).

    A sighting says "this was seen at that identity". Filed by one member about
    another, it tells every circle member the other firm saw it -- a fact the
    other firm never shared and cannot contest. So a submitter may report only
    its own sightings.
    """
    own = own_identity_id.lower()
    elsewhere = [
        obj.get("id", "<no id>")
        for obj in objects
        if isinstance(obj, dict)
        and obj.get("type") == "sighting"
        and any(str(ref).lower() != own for ref in obj.get("where_sighted_refs") or [])
    ]
    if not elsewhere:
        return None
    return (
        "a sighting may name only the organisation filing it in where_sighted_refs: "
        f"{', '.join(elsewhere)}"
    )


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
    own_identity_id = await submitter_identity_id(session, submission.submitter_org_id)
    if submission.distribute_anonymously:
        reject_self_identifying_content(objects, own_identity_id=own_identity_id)
    else:
        located_elsewhere = sightings_elsewhere_problem(objects, own_identity_id=own_identity_id)
        if located_elsewhere is not None:
            raise SubmissionError(located_elsewhere)

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


def source_for(ctx: AuthContext) -> SubmissionSource:
    """Who is filing, from the principal: an automation organisation is ``system``."""
    if ctx.org_type is OrgType.AUTOMATION:
        return SubmissionSource.SYSTEM
    return SubmissionSource.MEMBER


async def contribution_problem(
    session: AsyncSession,
    submission: Submission,
    objects: list[Any],
    *,
    visible_to: AuthContext | None,
    now: dt.datetime,
) -> str | None:
    """Why this content may not be filed under this submission's scope and TLP, or ``None``.

    The disclosure split and the TLP inheritance rule together, from one view:
    the submitter's at ingest (``visible_to`` its context), the ISAC's at
    validate and distribution (``visible_to=None``).
    """
    disclosure = await disclosure_problem(
        session,
        discovery_scope=submission.discovery_scope,
        objects=objects,
        scope=DisclosureScope(visible_to=visible_to, exclude_submission_id=submission.id, now=now),
    )
    if disclosure is not None:
        return disclosure
    return await looser_than_referents_problem(
        session,
        tlp=TLP(submission.tlp),
        referenced=referenced_ids(objects),
        visible_to=visible_to,
        now=now,
    )


async def _stored_raws(session: AsyncSession, submission: Submission) -> list[Any]:
    return list(
        (
            await session.execute(
                select(StixObject.raw).where(StixObject.submission_id == submission.id)
            )
        )
        .scalars()
        .all()
    )


async def _refuse_contribution_problem(
    session: AsyncSession,
    visible_to: AuthContext | None,
    submission: Submission,
    objects: list[Any],
) -> None:
    problem = await contribution_problem(
        session, submission, objects, visible_to=visible_to, now=dt.datetime.now(dt.UTC)
    )
    if problem is not None:
        raise SubmissionError(problem)


@dataclass(frozen=True, slots=True)
class ProxyFiling:
    """An ISAC analyst filing for a member (SF-68): who, and on what consent.

    ``consent_sha256`` binds the filing to the member's consent artefact -- the
    forwarded mail or the click -- which the ISAC keeps; ``confirm_by`` is when
    silence counts as confirmation.
    """

    org_id: uuid.UUID
    consent_sha256: str
    confirm_by: dt.datetime


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
    filed_for: ProxyFiling | None,
    via: str = "api",
) -> Submission:
    """Create a draft submission owned by the caller's organisation, or the one it files for.

    ``via`` records which surface filed it. It is a detail on the single audit
    record this function writes, rather than a second record written by the
    caller: one event belongs in one row of a table that cannot be corrected.

    The submitter is taken from the authenticated context, never from the
    request body: a member must not be able to file content in another firm's
    name. The one exception is ``filed_for``, which only an ISAC editor's
    proxy filing passes (``services.proxy_filing``), and which records the
    editor and the member's consent beside it. Required rather than defaulted,
    so every caller says which it is.
    """
    submission = Submission(
        submitter_org_id=filed_for.org_id if filed_for else ctx.org_id,
        created_by_operator_id=None if filed_for else ctx.operator_id,
        filed_by_operator_id=ctx.operator_id if filed_for else None,
        proxy_consent_sha256=filed_for.consent_sha256 if filed_for else None,
        proxy_confirm_by=filed_for.confirm_by if filed_for else None,
        state=SubmissionState.DRAFT,
        source=SubmissionSource.MEMBER if filed_for else source_for(ctx),
        tlp=tlp,
        discovery_scope=discovery_scope,
        distribute_anonymously=distribute_anonymously,
        title=title,
        summary=summary,
    )
    session.add(submission)
    await session.flush()

    object_count = await replace_submission_objects(session, submission, bundle)
    # An analyst filing for a member is ISAC staff, who see everything; the
    # rules are then checked from that view, as validate will check them.
    await _refuse_contribution_problem(
        session, None if filed_for else ctx, submission, bundle.get("objects") or []
    )

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
            "filed_for": str(filed_for.org_id) if filed_for else None,
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
    elif submission.distribute_anonymously:
        # Anonymity is a property of the submission as it stands, not of the
        # write that happened to carry a bundle. PATCH {"distribute_anonymously":
        # true} with no bundle turns the flag on over objects that were stored
        # while it was off -- and those may legitimately include the submitter's
        # own identity SDO, which is allowed for an attributed submission. Left
        # unchecked, that name is redistributed verbatim to every circle member
        # alongside a finding the submitter was told was anonymous.
        await _reject_stored_self_identifying_content(session, submission)

    # Checked against the submission as it now stands, whatever the change was:
    # a PATCH of the scope or the TLP alone changes what the stored objects may
    # lawfully be, as much as a new bundle does.
    objects = (
        (bundle.get("objects") or [])
        if bundle is not None
        else await _stored_raws(session, submission)
    )
    await _refuse_contribution_problem(session, ctx, submission, objects)

    await record(
        session,
        action=AuditAction.SUBMISSION_UPDATED,
        ctx=ctx,
        resource_type="submission",
        resource_id=str(submission.id),
        details={"fields": sorted(changes), "bundle_replaced": bundle is not None},
    )
    return submission


async def _prepare_validation(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    acknowledged_changes: frozenset[str],
) -> None:
    """Refuse content the ISAC may not accept, then record who reviewed it.

    In order: owner-only versioning (SF-48), the disclosure split and TLP
    inheritance from the ISAC's view of everything (SF-7, SF-49), the AI gate
    (SF-6). Only then is the reviewer stamped, so a refused validation writes
    nothing.
    """
    rows = list(
        (await session.execute(select(StixObject).where(StixObject.submission_id == submission.id)))
        .scalars()
        .all()
    )
    raws = [row.raw for row in rows]
    now = dt.datetime.now(dt.UTC)
    for problem in (
        await foreign_owned_versions_problem(
            session, raws, owner_org_id=submission.submitter_org_id
        ),
        await contribution_problem(session, submission, raws, visible_to=None, now=now),
        unacknowledged_changes_problem(
            await consequential_changes(session, submission, raws), acknowledged_changes
        ),
    ):
        if problem is not None:
            raise SubmissionError(problem)

    if ctx.operator_id is None:
        # Validation is human-only (auth.policy); a review with no person
        # behind it has nobody to name.
        msg = "validation needs a signed-in editor to name as the reviewer"
        raise SubmissionError(msg)
    reviewer = reviewer_identity_id(ctx.operator_id)
    for row in rows:
        row.raw = stamp_review(row.raw, reviewer=reviewer, now=now)


async def apply_transition(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    target: SubmissionState,
    *,
    reason: str | None = None,
    acknowledged_changes: frozenset[str] = frozenset(),
) -> Submission:
    """Move a submission to ``target``, recording the move.

    Two independent gates, in this order: the move must be legal in the state
    machine, and the caller must hold the right to perform that particular move.
    Checking legality first means an authorized caller attempting an impossible
    move gets a comprehensible error rather than a denial.

    Validation is where the ISAC accepts content, so the content rules are
    checked here too (:func:`_prepare_validation`), on every path that
    validates: the API and the portal both come through this function.
    ``acknowledged_changes`` are the consequential machine changes the editor
    has named; an empty set is the safe default, refusing any that exist.
    """
    if not is_transition_allowed(submission.state, target):
        msg = f"cannot move a submission from '{submission.state.value}' to '{target.value}'"
        raise SubmissionError(msg)

    require(
        can_transition_submission(ctx, submission, target),
        f"transition_{submission.state.value}_to_{target.value}",
    )

    if target is SubmissionState.VALIDATED:
        await _prepare_validation(session, ctx, submission, acknowledged_changes)

    await record_transition(session, ctx, submission, target, reason=reason)
    return submission


async def record_transition(
    session: AsyncSession,
    ctx: AuthContext,
    submission: Submission,
    target: SubmissionState,
    *,
    reason: str | None,
) -> None:
    """Make the move and write its history, in the caller's transaction.

    No authorization: :func:`apply_transition` checks the editorial right, and
    the one other caller, the fast lane (``services.contributions``), checks the
    lane rule that stands in for it. Legality in the state machine is checked
    here, because no path may skip it.
    """
    if not is_transition_allowed(submission.state, target):
        msg = f"cannot move a submission from '{submission.state.value}' to '{target.value}'"
        raise SubmissionError(msg)
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


async def check_content_rules(session: AsyncSession, submission: Submission) -> None:
    """Owner-only versioning, the disclosure split and TLP inheritance, from the ISAC's view.

    What validate checks of any submission's content, without the parts that
    need a human reviewer (the AI gate, the reviewer stamp). The fast lane runs
    this before publishing what no editor looked at.
    """
    raws = await _stored_raws(session, submission)
    for problem in (
        await foreign_owned_versions_problem(
            session, raws, owner_org_id=submission.submitter_org_id
        ),
        await contribution_problem(
            session, submission, raws, visible_to=None, now=dt.datetime.now(dt.UTC)
        ),
    ):
        if problem is not None:
            raise SubmissionError(problem)


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
