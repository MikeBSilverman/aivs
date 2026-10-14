"""Request and response models for the native API.

These are the contract between an AIVS server and everything that talks to it,
including member firms' own integrations. Two conventions apply throughout and
are worth stating once.

**Input models forbid unknown fields.** ``extra="forbid"`` turns a typo in a
client's request into a 400 rather than a silently ignored field. For a system
where a mistyped ``distribute_anonymously`` would mean a firm's identity is
disclosed when they believed it was withheld, silence is the wrong default.

**Input and output models are separate types, never one model reused.** A single
model serving both directions is how a server ends up accepting a field it meant
to be read-only -- ``state``, ``submitter_org_id``, ``distributed_at``. Here the
input models simply do not have those fields to accept.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from aivs_schemas.enums import (
    RULE_ELIGIBLE_ORG_TYPES,
    TLP,
    AckType,
    AckVia,
    CircleRole,
    DiscoveryScope,
    EmbargoPolicy,
    EmbargoStatus,
    OperatorRole,
    OrgStatus,
    OrgType,
    QuarantineBacklog,
    SubmissionState,
)

__all__ = [
    "AcknowledgmentCreate",
    "AcknowledgmentOut",
    "CircleCreate",
    "CircleMemberAdd",
    "CircleOut",
    "DistributeRequest",
    "EmbargoOut",
    "EmbargoUpsert",
    "OrganizationCreate",
    "OrganizationOut",
    "ReceiptOut",
    "SubmissionCreate",
    "SubmissionDetail",
    "SubmissionOut",
    "SubmissionUpdate",
    "TransitionRequest",
    "ValidateRequest",
    "WhoAmI",
]


class _In(BaseModel):
    """Base for request bodies: strict, and no unknown fields."""

    model_config = ConfigDict(extra="forbid", strict=False, str_strip_whitespace=True)


class _Out(BaseModel):
    """Base for response bodies."""

    model_config = ConfigDict(from_attributes=True)


# Bounded so a title cannot be used to push an unbounded string into the audit
# log, the portal, and every member's TIP.
#
# `_NO_CONTROL_CHARACTERS` on the single-line fields: these are redistributed to
# other organisations and printed by the reference CLI one record per line, so an
# embedded newline forges a row for a submission that does not exist and a
# carriage return overwrites a real one. The CLI escapes on output as well --
# this is the half that keeps the data clean rather than the display -- and
# `Summary` is deliberately exempt because it is genuinely multi-line prose.
_NO_CONTROL_CHARACTERS = r"^[^\x00-\x1f\x7f]+$"

Title = Annotated[str, Field(min_length=3, max_length=300, pattern=_NO_CONTROL_CHARACTERS)]
Summary = Annotated[str, Field(max_length=5000)]
Reason = Annotated[str, Field(max_length=2000, pattern=_NO_CONTROL_CHARACTERS)]
Slug = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")]
DisplayName = Annotated[str, Field(min_length=1, max_length=200, pattern=_NO_CONTROL_CHARACTERS)]

#: Deliberately permissive about what an address may contain and strict about
#: the shape: one @, no whitespace, no control characters. Full RFC 5322 is not
#: the goal -- rejecting things that are plainly not addresses is.
_EMAIL_SHAPE = r"^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+\.[^\s@\x00-\x1f\x7f]+$"


# ---------------------------------------------------------------------------
# Submissions
# ---------------------------------------------------------------------------
class SubmissionCreate(_In):
    """Create a draft submission.

    The bundle is validated on receipt rather than at distribution time, so a
    submitter learns their content is malformed while they are still editing it
    -- not when an ISAC operator tries to release it.
    """

    title: Title
    summary: Summary | None = None
    tlp: TLP = TLP.AMBER
    discovery_scope: DiscoveryScope
    #: When true the distribution pipeline attributes outbound objects to the
    #: hosting ISAC rather than the submitter. The ISAC still knows; consumers
    #: do not.
    distribute_anonymously: bool = False
    #: A STIX 2.1 bundle. Every object in it is validated, not only the ones
    #: AIVS reads.
    bundle: dict[str, Any]

    @field_validator("bundle")
    @classmethod
    def _bundle_is_a_bundle(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Reject anything that is not shaped like a bundle before deeper checks.

        Full STIX validation happens in the service layer, which owns the
        extension allowlist. This is the cheap structural check that keeps
        obviously-wrong input from reaching it.
        """
        if value.get("type") != "bundle":
            msg = "bundle must be a STIX bundle (type: 'bundle')"
            raise ValueError(msg)
        return value


class SubmissionUpdate(_In):
    """Amend a draft. Only fields that are present are changed."""

    title: Title | None = None
    summary: Summary | None = None
    tlp: TLP | None = None
    discovery_scope: DiscoveryScope | None = None
    distribute_anonymously: bool | None = None
    bundle: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _at_least_one_field(self) -> SubmissionUpdate:
        if not self.model_dump(exclude_none=True):
            msg = "no fields to update"
            raise ValueError(msg)
        return self


class TransitionRequest(_In):
    """Body for the workflow verbs. A reason is recorded in the audit trail."""

    reason: Reason | None = None


class ValidateRequest(TransitionRequest):
    """Accept a submission, naming any consequential machine changes the editor accepts.

    ``acknowledge`` lists ``<stix id>:<property>`` labels, exactly as a refused
    validation reports them. Only an automation organisation's submissions can
    need one (SF-6); for anything else the list is ignored.
    """

    acknowledge: Annotated[list[Annotated[str, Field(max_length=200)]], Field(max_length=500)] = []


class DistributeRequest(_In):
    """Release a validated submission into one or more circles.

    ``release_at`` in the future creates an embargo: the objects are written
    with that visibility timestamp, so they are inert until it arrives even if
    no scheduler is running.
    """

    circle_ids: Annotated[list[uuid.UUID], Field(min_length=1, max_length=100)]
    release_at: dt.datetime | None = None
    reason: Reason | None = None

    @field_validator("circle_ids")
    @classmethod
    def _no_duplicates(cls, value: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(set(value)) != len(value):
            msg = "circle_ids must not contain duplicates"
            raise ValueError(msg)
        return value

    @field_validator("release_at")
    @classmethod
    def _release_at_is_aware(cls, value: dt.datetime | None) -> dt.datetime | None:
        """A naive release time is refused rather than assumed to be UTC.

        Guessing a timezone on an embargo boundary is how content is published
        hours early.
        """
        if value is not None and value.tzinfo is None:
            msg = "release_at must include a timezone offset"
            raise ValueError(msg)
        return value


class SubmissionOut(_Out):
    """Summary view of a submission."""

    id: uuid.UUID
    title: str
    summary: str | None
    state: SubmissionState
    tlp: TLP
    discovery_scope: DiscoveryScope
    distribute_anonymously: bool
    #: ``None`` when withheld: an anonymous submission's submitter is shown to
    #: the submitter alone. ISAC staff who need it use the reveal action, which
    #: is audited with its reason (``POST /submissions/{id}/reveal``).
    submitter_org_id: uuid.UUID | None
    created_at: dt.datetime
    updated_at: dt.datetime
    distributed_at: dt.datetime | None
    superseded_by_id: uuid.UUID | None


class QuarantineRequest(_In):
    """Why an organisation is being cut off. Recorded in the audit log."""

    reason: Annotated[str, Field(min_length=10, max_length=1000)]


class OffboardRequest(_In):
    """Why an organisation is leaving, and its slug typed out: nothing reverses this."""

    reason: Annotated[str, Field(min_length=10, max_length=1000)]
    confirm_slug: Slug


class LegalHoldRequest(_In):
    """Why a hold is placed or lifted. Recorded in the audit log."""

    reason: Annotated[str, Field(min_length=10, max_length=1000)]


class ReconnectRequest(_In):
    reason: Annotated[str, Field(min_length=10, max_length=1000)]
    #: Whether content shared during the quarantine reaches the member.
    backlog: QuarantineBacklog = QuarantineBacklog.DELIVER


class InstanceControlChange(_In):
    """Why distribution is being paused or resumed. Recorded in the audit log."""

    reason: Annotated[str, Field(min_length=10, max_length=1000)]


class InstanceControlOut(_Out):
    distribution_paused: bool


class RevealRequest(_In):
    """Why the anonymous submitter of a submission must be named."""

    #: Recorded in the audit log. Required and non-trivial, because revealing an
    #: anonymous submitter is the one act that breaks the promise the platform
    #: made them, and a reviewer must be able to judge it later.
    reason: Annotated[str, Field(min_length=10, max_length=1000)]


class RevealOut(_Out):
    """The submitter of an anonymous submission, for the editor who asked."""

    submission_id: uuid.UUID
    submitter_org_id: uuid.UUID
    submitter_slug: str


class TransitionOut(_Out):
    """One entry in a submission's workflow history."""

    from_state: SubmissionState | None
    to_state: SubmissionState
    reason: str | None
    at: dt.datetime


class SubmissionDetail(SubmissionOut):
    """Full view, including workflow history and the object inventory."""

    object_count: int
    stix_ids: list[str]
    circle_ids: list[uuid.UUID]
    transitions: list[TransitionOut]
    embargo: EmbargoOut | None


# ---------------------------------------------------------------------------
# Embargo
# ---------------------------------------------------------------------------
class EmbargoUpsert(_In):
    """Set or replace a submission's embargo."""

    policy: EmbargoPolicy
    release_at: dt.datetime | None = None
    coordination_notes: Annotated[str, Field(max_length=5000)] | None = None

    @model_validator(mode="after")
    def _timer_needs_a_time(self) -> EmbargoUpsert:
        if self.policy is EmbargoPolicy.TIMER and self.release_at is None:
            msg = "a timer embargo requires release_at"
            raise ValueError(msg)
        if self.release_at is not None and self.release_at.tzinfo is None:
            msg = "release_at must include a timezone offset"
            raise ValueError(msg)
        return self


class EmbargoOut(_Out):
    id: uuid.UUID
    policy: EmbargoPolicy
    status: EmbargoStatus
    release_at: dt.datetime | None
    released_at: dt.datetime | None
    coordination_notes: str | None


# ---------------------------------------------------------------------------
# Acknowledgments and receipts
# ---------------------------------------------------------------------------
class AcknowledgmentCreate(_In):
    """A member's explicit assertion about a submission.

    ``retrieved`` is deliberately not accepted here: that value is written by
    the server when content is actually delivered, and letting a member assert
    it would let them manufacture evidence of a delivery that never happened.
    """

    submission_id: uuid.UUID
    ack_type: Literal[AckType.ACKNOWLEDGED, AckType.ACTIONED]
    note: Annotated[str, Field(max_length=2000)] | None = None


class AcknowledgmentOut(_Out):
    id: uuid.UUID
    org_id: uuid.UUID
    submission_id: uuid.UUID
    ack_type: AckType
    via: AckVia
    note: str | None
    created_at: dt.datetime


class ReceiptOut(_Out):
    """Who engaged with a submission, and when.

    The regulatory artefact: an ISAC's answer to "did you warn us, and did we
    collect it".
    """

    org_id: uuid.UUID
    org_slug: str
    ack_type: AckType
    via: AckVia
    first_at: dt.datetime
    latest_at: dt.datetime
    occurrences: int


# ---------------------------------------------------------------------------
# Circles and organisations
# ---------------------------------------------------------------------------
_RULE_ELIGIBLE: frozenset[str] = frozenset(org_type.value for org_type in RULE_ELIGIBLE_ORG_TYPES)


class CircleCreate(_In):
    slug: Slug
    name: DisplayName
    description: Annotated[str, Field(max_length=2000)] | None = None
    minimum_tlp: TLP = TLP.AMBER
    #: Organisation types whose active members join automatically. Empty means
    #: membership is entirely manual. Members added by the rule receive content
    #: shared from the moment they join, never the circle's back catalogue.
    auto_member_org_types: Annotated[list[OrgType], Field(max_length=8)] = []

    @field_validator("auto_member_org_types")
    @classmethod
    def _rule_admits_only_eligible_types(cls, value: list[OrgType]) -> list[OrgType]:
        refused = sorted({org_type.value for org_type in value} - _RULE_ELIGIBLE)
        if refused:
            msg = (
                f"a membership rule may not admit {', '.join(refused)}; those are added "
                "to a circle by name, never by rule"
            )
            raise ValueError(msg)
        return value


class CircleOut(_Out):
    id: uuid.UUID
    slug: str
    name: str
    description: str | None
    minimum_tlp: TLP
    is_active: bool
    auto_member_org_types: list[str] = []


class CircleMemberAdd(_In):
    """Add one or more organisations to a circle.

    Accepts identifiers, slugs, or both. Slugs are here because that is the form
    the list already exists in wherever the operator is copying it from -- a
    regulator's roster, an existing community-of-interest sheet -- and making
    them resolve thirty UUIDs first is how a bulk endpoint goes unused.
    """

    org_ids: Annotated[list[uuid.UUID], Field(max_length=500)] = []
    org_slugs: Annotated[list[Slug], Field(max_length=500)] = []
    role: CircleRole = CircleRole.MEMBER
    #: Backdate the membership start. For restoration only -- an organisation
    #: re-added after an administrative mistake, or moved during a certificate
    #: rotation, keeping the history it legitimately had. It grants access to
    #: content shared before the row existed, so it is recorded in the audit
    #: trail as the deliberate act it is.
    joined_at: dt.datetime | None = None

    @model_validator(mode="after")
    def _names_at_least_one(self) -> CircleMemberAdd:
        if not self.org_ids and not self.org_slugs:
            msg = "name at least one organisation, by org_ids or org_slugs"
            raise ValueError(msg)
        return self

    @field_validator("joined_at")
    @classmethod
    def _joined_at_is_aware(cls, value: dt.datetime | None) -> dt.datetime | None:
        if value is not None and value.tzinfo is None:
            msg = "joined_at must include a timezone offset"
            raise ValueError(msg)
        return value


class OrganizationCreate(_In):
    slug: Slug
    name: DisplayName
    org_type: OrgType
    #: Validated as an address rather than as a bounded string. The bound still
    #: matches the column; the pattern is what stops a 320-character blob with a
    #: newline in it from being stored under a field named for an email.
    contact_email: Annotated[str, Field(max_length=320, pattern=_EMAIL_SHAPE)] | None = None

    @field_validator("org_type")
    @classmethod
    def _not_a_second_isac(cls, value: OrgType) -> OrgType:
        # The hosting ISAC is created once, by the bootstrap command.
        if value is OrgType.ADMIN:
            msg = (
                "the hosting ISAC's organisation is created by the bootstrap command, not enrolled"
            )
            raise ValueError(msg)
        return value


class OrganizationOut(_Out):
    id: uuid.UUID
    slug: str
    name: str
    org_type: OrgType
    status: OrgStatus
    stix_identity_id: str
    created_at: dt.datetime


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
class WhoAmICircle(_Out):
    id: uuid.UUID
    role: CircleRole


class WhoAmI(_Out):
    """What the server believes about the caller."""

    instance: str
    org_id: uuid.UUID
    org_slug: str
    org_type: OrgType
    org_status: OrgStatus
    operator_id: uuid.UUID | None = None
    operator_roles: list[OperatorRole] = []
    circles: list[WhoAmICircle]
    server_time: dt.datetime
