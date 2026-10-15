"""ORM model definitions -- the authoritative shape of an AIVS instance.

Two conventions are applied deliberately throughout and are worth stating once
rather than repeating at every table:

**Nothing of evidentiary value is deletable.** Foreign keys use ``RESTRICT``
rather than ``CASCADE`` except for rows that are pure ephemera (sessions,
webhook delivery attempts) or pure configuration (webhook registrations). The
receipts, transitions, and audit trail are the product's regulatory value; a
stray cascade that quietly erased them would be a defect, not a convenience.

**The audit log has no foreign keys at all.** It records *what an actor did at a
point in time*, which must remain readable even if the referenced org, operator,
or submission is later altered. Constraining it would couple the record of
history to the current state of the world, which is precisely what an audit log
must not do.
"""

from __future__ import annotations

import datetime as dt
import uuid
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, ExcludeConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aivs_schemas.enums import (
    RULE_ELIGIBLE_ORG_TYPES,
    TLP,
    AckType,
    AckVia,
    CertStatus,
    CircleRole,
    DiscoveryScope,
    EmbargoPolicy,
    EmbargoStatus,
    NotificationCadence,
    OperatorRole,
    OrgStatus,
    OrgType,
    PostureStatus,
    ReadingDepth,
    SsvcPriority,
    SubmissionLane,
    SubmissionSource,
    SubmissionState,
    TriageDisposition,
    VexJustification,
)
from aivs_server.db.base import Base, TimestampMixin, pg_enum

if TYPE_CHECKING:  # pragma: no cover
    pass

__all__ = [
    "Acknowledgment",
    "AuditLog",
    "Circle",
    "CircleMembership",
    "ClientCertificate",
    "DetectionState",
    "Distribution",
    "EmailDelivery",
    "Embargo",
    "InstanceControl",
    "Operator",
    "OrgPosture",
    "Organization",
    "PendingNotice",
    "PortalSession",
    "SectorEvent",
    "StixObject",
    "Submission",
    "SubmissionTransition",
    "SubmissionTriage",
    "TaxiiCollection",
    "TaxiiStatus",
    "Webhook",
    "WebhookDelivery",
]

# A SHA-256 fingerprint rendered as lowercase hex. Enforced in the database so
# that a bug in the parsing layer cannot store a mixed-case or truncated value
# that would then silently fail to match on lookup.
_SHA256_HEX = "^[0-9a-f]{64}$"


#: The current transaction's id as a bigint, for ``xact_id`` columns.
_CURRENT_XACT_ID = "(pg_current_xact_id())::text::bigint"


class Organization(TimestampMixin, Base):
    """A member firm, or the hosting ISAC itself (``org_type == ADMIN``)."""

    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    org_type: Mapped[OrgType] = mapped_column(pg_enum(OrgType, "org_type"), nullable=False)
    status: Mapped[OrgStatus] = mapped_column(
        pg_enum(OrgStatus, "org_status"), nullable=False, default=OrgStatus.PENDING
    )
    #: When a quarantine began; ``None`` when not quarantined. Needed at
    #: reconnection to close the membership interval at the right moment if the
    #: backlog is not to be delivered.
    quarantined_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    #: A legal hold: while set, offboarding keeps what it would otherwise delete
    #: (the organisation's postures), and lifting it on an offboarded
    #: organisation deletes them then. Set and lifted by ISAC membership staff.
    legal_hold_since: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    legal_hold_reason: Mapped[str | None] = mapped_column(Text)
    #: The org's STIX ``identity`` SDO id, used as ``created_by_ref`` on objects
    #: it submits (except where the submission is distributed anonymously).
    stix_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    #: The ISAC directory group whose members belong to this organisation, as the
    #: member IdP names it in the group claim. Set at enrolment by membership
    #: staff; a sign-in naming a group that maps to no organisation grants nothing.
    directory_object_id: Mapped[str | None] = mapped_column(String(200), nullable=True, unique=True)
    contact_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    #: How often the organisation is told content became visible to it. The
    #: default is today's behaviour: one notice per submission, at once.
    notification_cadence: Mapped[NotificationCadence] = mapped_column(
        pg_enum(NotificationCadence, "notification_cadence"),
        nullable=False,
        default=NotificationCadence.IMMEDIATE,
        server_default=NotificationCadence.IMMEDIATE.value,
    )
    #: The mailbox the organisation's digest is emailed to, if it wants one.
    #: A routing address the member chose (a SOC queue), not a person's, and
    #: only ever sent the contentless digest (``notify.digest``).
    digest_email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "(legal_hold_since IS NULL) = (legal_hold_reason IS NULL)",
            name="legal_hold_has_reason",
        ),
        CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'", name="slug_format"),
        CheckConstraint(
            "stix_identity_id ~ '^identity--[0-9a-f-]{36}$'", name="stix_identity_format"
        ),
        # One hosting ISAC per instance. Policy keys ISAC powers on the type,
        # not on an id, so a second admin-type organisation would be a second
        # ISAC whose operators hold every ISAC role they are given.
        Index(
            "uq_organizations_one_admin",
            "org_type",
            unique=True,
            postgresql_where=text("org_type = 'admin'"),
        ),
        # One automation organisation, for the same reason: ownership counts
        # its versions as the ISAC's by type (services/ownership.py), so a
        # second one would be a second identity able to version the ISAC's
        # canonical records.
        Index(
            "uq_organizations_one_automation",
            "org_type",
            unique=True,
            postgresql_where=text("org_type = 'automation'"),
        ),
    )

    certificates: Mapped[list[ClientCertificate]] = relationship(back_populates="organization")
    operators: Mapped[list[Operator]] = relationship(back_populates="organization")


class Operator(TimestampMixin, Base):
    """A human user at a member organisation.

    Authentication is password + TOTP, but the session is additionally bound to
    the organisation identified by the transport-layer client certificate -- see
    ``auth.sessions``. Neither factor alone grants access.
    """

    __tablename__ = "operators"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    #: Every role this operator holds. A set, because a small ISAC's staff wear
    #: several hats and a large one's do not; which is a policy the ISAC sets by
    #: assigning roles, not one the schema should make for it.
    roles: Mapped[list[OperatorRole]] = mapped_column(
        ARRAY(pg_enum(OperatorRole, "operator_role")),
        nullable=False,
        default=lambda: [OperatorRole.ANALYST],
    )
    #: Argon2id hash. Never a raw password, never a reversible encryption.
    #: ``None`` for an operator who signs in only through the ISAC's identity
    #: provider. Local sign-in with no hash always fails (passwords.verify_password).
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: TOTP shared secret, sealed by ``auth.secretbox``: AES-256-GCM under a key
    #: held in the process environment, with the operator's id as additional
    #: authenticated data so a seed cannot be moved between rows. The column
    #: name was inaccurate for as long as this was base64; it is accurate now.
    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(nullable=True)
    totp_enrolled_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: Throttling state for online password guessing.
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: The TOTP time step of the last code accepted at login. A code for this
    #: step or an earlier one is refused, so each code signs in once (RFC 6238
    #: section 5.2). Written in the login's own row-locked transaction, so two
    #: concurrent logins with one code cannot both pass.
    last_totp_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    #: The federated identity this operator signs in as: issuer and subject,
    #: never email, because addresses are reassigned and subjects are not
    #: (identity-federation.md §4). Both or neither.
    federated_issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    federated_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: The depth this person's vulnerability pages open at when the link names
    #: none. The one stored reading preference: it picks a rendering of what
    #: the operator may already see and confers nothing, which the
    #: authorization matrix proves by running with it set.
    default_depth: Mapped[ReadingDepth | None] = mapped_column(
        pg_enum(ReadingDepth, "reading_depth"), nullable=True
    )
    #: When this operator's access ends. Required for an auditor, who is
    #: engaged for a review rather than employed to operate; checked at every
    #: session resolution and by ``policy.can_read_audit`` against the
    #: caller's ``now``.
    role_expires_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    organization: Mapped[Organization] = relationship(back_populates="operators")

    __table_args__ = (
        UniqueConstraint(
            "federated_issuer", "federated_subject", name="uq_operators_federated_identity"
        ),
        CheckConstraint(
            "(federated_issuer IS NULL) = (federated_subject IS NULL)",
            name="federated_identity_complete",
        ),
        # An auditor holds that role alone, and never without an end date.
        CheckConstraint(
            "NOT ('auditor' = ANY (roles)) "
            "OR (cardinality(roles) = 1 AND role_expires_at IS NOT NULL)",
            name="auditor_alone_and_expiring",
        ),
    )


class ClientCertificate(TimestampMixin, Base):
    """An X.509 client certificate authorising machine access for one org.

    The SHA-256 fingerprint is the identity key, not the subject DN: DNs are
    reissued and reused, fingerprints are not. Revocation is a status flip here,
    checked on every request, which is why the MVP needs no CRL or OCSP
    responder -- the authoritative answer is one indexed lookup away.
    """

    __tablename__ = "client_certificates"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    subject_dn: Mapped[str] = mapped_column(Text, nullable=False)
    issuer_dn: Mapped[str] = mapped_column(Text, nullable=False)
    serial_hex: Mapped[str] = mapped_column(String(80), nullable=False)
    not_before: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[CertStatus] = mapped_column(
        pg_enum(CertStatus, "cert_status"), nullable=False, default=CertStatus.ACTIVE
    )
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    label: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(f"fingerprint_sha256 ~ '{_SHA256_HEX}'", name="fingerprint_format"),
        CheckConstraint("not_after > not_before", name="validity_ordered"),
        CheckConstraint(
            "(status = 'active' AND revoked_at IS NULL) "
            "OR (status = 'revoked' AND revoked_at IS NOT NULL)",
            name="revocation_consistent",
        ),
        # No separate index on fingerprint_sha256: the unique constraint above
        # already provides one, and the authentication lookup uses it.
    )

    organization: Mapped[Organization] = relationship(back_populates="certificates")


#: RULE_ELIGIBLE_ORG_TYPES as a SQL array literal, sorted so the constraint text is stable.
_RULE_ELIGIBLE_SQL = ", ".join(
    f"'{org_type.value}'" for org_type in sorted(RULE_ELIGIBLE_ORG_TYPES)
)


class Circle(TimestampMixin, Base):
    """A sharing circle -- the unit of trust tiering (e.g. Section 9, GSIB)."""

    __tablename__ = "circles"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: A submission may not be distributed into this circle under a marking
    #: looser than its floor. Lets an operator declare "Section 9 content is
    #: AMBER+STRICT or tighter" once, structurally, instead of per submission.
    minimum_tlp: Mapped[TLP] = mapped_column(pg_enum(TLP, "tlp"), nullable=False, default=TLP.AMBER)
    #: A sandbox: for a member's day-one TIP verification and later exercises.
    #: Its content is real to the TAXII path -- that is what is being tested --
    #: and left out of every figure the ISAC reports: telemetry's reach and
    #: counts, and lead time. Set at creation, never changed after, so a
    #: circle's figures do not change meaning halfway through its life.
    is_sandbox: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    #: Whether short contributions on public content in this circle publish on
    #: submit, for an editor to revoke afterwards. Off unless an editor turns
    #: it on (``services.contributions``).
    post_moderated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: Organisation types whose active members belong here automatically, e.g.
    #: ``["section9"]``. Empty means membership is entirely manual.
    #:
    #: The rule is *materialised* into ordinary ``circle_memberships`` rows
    #: rather than evaluated at read time. That costs a reconciliation step, and
    #: buys the thing an ISAC actually needs: "who could see this on 3 March?"
    #: stays a query against stored rows with a join date, rather than a
    #: reconstruction of what every organisation's attributes used to be.
    auto_member_org_types: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=list, server_default=text("'{}'::text[]")
    )

    __table_args__ = (
        CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'", name="slug_format"),
        # The last of three enforcements of RULE_ELIGIBLE_ORG_TYPES, for writes
        # that do not come through the request model -- a migration, a repair.
        CheckConstraint(
            f"auto_member_org_types <@ ARRAY[{_RULE_ELIGIBLE_SQL}]::text[]",
            name="rule_admits_eligible_types",
        ),
    )

    memberships: Mapped[list[CircleMembership]] = relationship(back_populates="circle")


class CircleMembership(TimestampMixin, Base):
    """Which organisations belong to which circle, and with what rights."""

    __tablename__ = "circle_memberships"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    circle_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("circles.id", ondelete="CASCADE"), nullable=False
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    role: Mapped[CircleRole] = mapped_column(
        pg_enum(CircleRole, "circle_role"), nullable=False, default=CircleRole.MEMBER
    )
    #: When this organisation's access to the circle begins. Content that
    #: *became readable* before it -- whose ``date_added`` is earlier -- is not
    #: readable by them; see ``visible_content_clause``.
    #:
    #: That is the release, not the distribution: an embargoed row's
    #: ``date_added`` is its release instant. Deliberately. Content is
    #: addressed to the circle as it stands when it goes live, the moment it
    #: becomes anyone's to read. Testing at distribution instead would deny it
    #: to a vendor added to a coordination circle during the embargo -- the
    #: party the embargo was waiting for -- and, once it rejoined, hand a firm
    #: removed during the embargo content that first became readable while it
    #: was out. An organisation outside at distribution and back before release
    #: reads it, like any other member who joined during the embargo.
    #:
    #: Deliberately a column of its own rather than a reading of ``created_at``.
    #: This one is load-bearing for authorization, and it is settable: an
    #: organisation re-added after an administrative mistake, or migrated during
    #: a certificate rotation, must be able to keep the history it legitimately
    #: had. ``created_at`` records when the row was written and must go on
    #: meaning only that.
    #:
    #: Every writer sets it, from the database's clock (``db.clock``); the
    #: server default is the transaction's start, which is a different instant
    #: from the one ``left_at`` and ``date_added`` are read at.
    joined_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    #: True when this row was created by the circle's ``auto_member_org_types``
    #: rule rather than by an operator naming this organisation.
    #:
    #: Reconciliation only ever adds or removes rows it owns. An organisation an
    #: operator added by hand is never withdrawn because a rule stopped matching
    #: it, and one an operator deliberately removed is not silently reinstated on
    #: the next reconcile -- which is the behaviour that would make an operator
    #: stop trusting the feature.
    managed_by_rule: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    #: When this interval of membership ended; ``None`` while it is open.
    #:
    #: A membership is an interval, not a row that exists or does not. Leaving
    #: closes it; rejoining opens a new one, so the gap between is never
    #: readable and the earlier interval's content is not lost. Suspension and
    #: quarantine do not touch it at all -- they are organisation *status*,
    #: refused on every request -- which is what keeps a lapsed renewal from
    #: silently costing a member years of a circle's back catalogue.
    left_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    #: Who closed the interval: ``operator`` or ``rule``. A rule never reopens a
    #: membership an operator closed; without this the next reconcile quietly
    #: reinstated a firm an operator had removed by hand.
    ended_by: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        # One open interval per organisation per circle ...
        Index(
            "uq_circle_memberships_open_interval",
            "circle_id",
            "org_id",
            unique=True,
            postgresql_where=text("left_at IS NULL"),
        ),
        # ... and no two intervals that overlap. Without this a joined_at
        # repair could backdate an interval over an earlier one. It does not
        # stop a start moving back into the gap *after* an earlier interval
        # (adjacent ranges do not overlap); add_circle_members refuses that.
        ExcludeConstraint(
            ("circle_id", "="),
            ("org_id", "="),
            (func.tstzrange(text("joined_at"), text("left_at"), "[)"), "&&"),
            name="ex_circle_memberships_no_overlap",
            using="gist",
        ),
        CheckConstraint("left_at IS NULL OR left_at > joined_at", name="interval_ordered"),
        CheckConstraint("(left_at IS NULL) = (ended_by IS NULL)", name="ended_by_with_left_at"),
        CheckConstraint(
            "ended_by IS NULL OR ended_by IN ('operator', 'rule', 'offboarding')",
            name="ended_by_known",
        ),
        Index("ix_circle_memberships_org_id_circle_id", "org_id", "circle_id"),
    )

    circle: Mapped[Circle] = relationship(back_populates="memberships")


class TaxiiCollection(TimestampMixin, Base):
    """A TAXII 2.1 collection, which is the public projection of one circle.

    The ``id`` is the UUID members put in their TAXII client configuration, so
    it is stable for the life of the deployment.
    """

    __tablename__ = "taxii_collections"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    circle_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("circles.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    alias: Mapped[str | None] = mapped_column(String(120), nullable=True, unique=True)
    can_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    can_write: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        # A collection is the public projection of exactly one circle, and the
        # visibility query returns a circle's entire content through it. Two
        # active collections over the same circle would therefore serve the same
        # objects twice under different ids and split retrieval receipts
        # confusingly across them. Enforce one active collection per circle in
        # the schema rather than trusting operators to. Partial, so retiring a
        # collection and creating its replacement is not blocked.
        Index(
            "uq_taxii_collections_one_active_per_circle",
            "circle_id",
            unique=True,
            postgresql_where=text("is_active"),
        ),
    )

    circle: Mapped[Circle] = relationship()


class Submission(TimestampMixin, Base):
    """A unit of shared intelligence moving through the disclosure workflow."""

    __tablename__ = "submissions"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    submitter_org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    #: Null when submitted machine-to-machine over mTLS rather than by a person.
    created_by_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT"), nullable=True
    )
    state: Mapped[SubmissionState] = mapped_column(
        pg_enum(SubmissionState, "submission_state"),
        nullable=False,
        default=SubmissionState.DRAFT,
        index=True,
    )
    tlp: Mapped[TLP] = mapped_column(pg_enum(TLP, "tlp"), nullable=False, default=TLP.AMBER)
    discovery_scope: Mapped[DiscoveryScope] = mapped_column(
        pg_enum(DiscoveryScope, "discovery_scope"), nullable=False
    )
    #: The ISAC reviewer working this submission, if anyone has taken it.
    assignee_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), nullable=True
    )
    #: An editor's priority. ``None`` means the default derived from the SSVC
    #: decision points (services.priority), computed when shown so it follows
    #: the content rather than freezing at filing.
    priority: Mapped[SsvcPriority | None] = mapped_column(
        pg_enum(SsvcPriority, "ssvc_priority"), nullable=True
    )
    #: Derived from the filing principal when the submission is created, never
    #: from anything the submission says: an automation organisation's filing
    #: is ``system`` however it describes itself. Read by the AI gate at
    #: validate (``services.provenance``).
    source: Mapped[SubmissionSource] = mapped_column(
        pg_enum(SubmissionSource, "submission_source"),
        nullable=False,
        default=SubmissionSource.MEMBER,
        server_default=SubmissionSource.MEMBER.value,
    )
    #: How it reached members: reviewed, a one-click fast-lane contribution, or
    #: post-moderated. The non-review lanes share one hourly limit per
    #: organisation, counted from this column (``services.contributions``).
    lane: Mapped[SubmissionLane] = mapped_column(
        pg_enum(SubmissionLane, "submission_lane"),
        nullable=False,
        default=SubmissionLane.REVIEW,
        server_default=SubmissionLane.REVIEW.value,
    )
    #: Set when an ISAC analyst filed this for the member it is attributed to
    #: (SF-68). The member may confirm or withdraw it; until it does, or until
    #: ``proxy_confirm_by`` passes, it is not distributed.
    filed_by_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT"), nullable=True
    )
    #: SHA-256 of the member's consent: the forwarded mail, or the click. The
    #: artefact itself stays with the ISAC; this binds the filing to it.
    proxy_consent_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    proxy_confirm_by: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    proxy_confirmed_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: When true the distribution pipeline rewrites ``created_by_ref`` on
    #: outbound objects to the hosting ISAC's identity and withholds the
    #: submitter from every consumer-facing view. Receipts still resolve
    #: internally, so the ISAC can answer questions the members cannot.
    distribute_anonymously: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    superseded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("submissions.id", ondelete="RESTRICT"), nullable=True
    )
    distributed_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "superseded_by_id IS NULL OR superseded_by_id <> id", name="no_self_supersede"
        ),
        CheckConstraint(
            "(state <> 'distributed') OR (distributed_at IS NOT NULL)",
            name="distributed_has_timestamp",
        ),
        CheckConstraint(
            "(filed_by_operator_id IS NULL) = (proxy_consent_sha256 IS NULL)",
            name="proxy_filing_has_consent",
        ),
        Index("ix_submissions_org_state", "submitter_org_id", "state"),
    )

    embargo: Mapped[Embargo | None] = relationship(back_populates="submission", uselist=False)
    stix_objects: Mapped[list[StixObject]] = relationship(back_populates="submission")


class SubmissionTransition(Base):
    """Immutable record of every workflow state change.

    Append-only by construction: the table has no ``updated_at`` and the
    application never issues an UPDATE against it.
    """

    __tablename__ = "submission_transitions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    submission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("submissions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    from_state: Mapped[SubmissionState | None] = mapped_column(
        pg_enum(SubmissionState, "submission_state"), nullable=True
    )
    to_state: Mapped[SubmissionState] = mapped_column(
        pg_enum(SubmissionState, "submission_state"), nullable=False
    )
    actor_org_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    actor_operator_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class SubmissionTriage(Base):
    """What the first pass found when a submission was handed to the ISAC (Phase O).

    One row per submit, keyed by the transition into ``submitted`` that it
    read, so a resubmission is read again and a crashed run never reads one
    twice. Rows are the record of what the ISAC told a member, and of every
    automated return: kept, never updated.
    """

    __tablename__ = "submission_triage"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("submissions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    transition_id: Mapped[int] = mapped_column(
        ForeignKey("submission_transitions.id", ondelete="RESTRICT"), nullable=False, unique=True
    )
    #: SHA-256 over the content read, so returning the same content twice can be refused.
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    disposition: Mapped[TriageDisposition] = mapped_column(
        pg_enum(TriageDisposition, "triage_disposition"), nullable=False
    )
    #: ``[{"code", "path", "detail"}]``, as ``services.first_pass`` produced them.
    findings: Mapped[list[dict[str, str]]] = mapped_column(JSONB, nullable=False)
    #: Which rules ran: stored output says how it was made (CLAUDE.md section 5).
    rules_version: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class StixObject(Base):
    """One version of one STIX object.

    Storage is JSONB plus a handful of extracted columns. Keeping the canonical
    form opaque means evolving the AIVS STIX extension never requires a table
    migration, and a member's object round-trips byte-for-identical rather than
    being lossily reassembled from relational columns.
    """

    __tablename__ = "stix_objects"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    stix_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    #: STIX ``modified`` timestamp; together with ``stix_id`` this identifies a
    #: specific version, which is what TAXII's ``match[version]`` filters on.
    modified: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    spec_version: Mapped[str] = mapped_column(String(10), nullable=False, default="2.1")
    submission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("submissions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    # -- Extracted for indexing and search only; ``raw`` remains canonical. --
    name: Mapped[str | None] = mapped_column(String(300), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    # Extension 2.0 and standard STIX properties, extracted by
    # services.indexing; its docstring names the reader of each.
    remediation_category: Mapped[str | None] = mapped_column(String(40), nullable=True)
    pattern_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    valid_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cwe_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String(20)), nullable=True)

    __table_args__ = (
        # Uniqueness is per submission, not global. A STIX object version is
        # globally unique by STIX semantics, so a global constraint looks right
        # -- but it would make one organisation's submission fail because
        # *another* organisation had already submitted an object with the same
        # id, disclosing across the member boundary that they had. Producer-
        # generated UUIDs make accidental collision negligible; a deliberate one
        # is probing, and it must not be answered. Duplicate delivery into a
        # single circle is prevented at distribution time instead, which is where
        # it actually matters.
        UniqueConstraint(
            "submission_id", "stix_id", "modified", name="uq_stix_objects_submission_version"
        ),
        CheckConstraint("spec_version = '2.1'", name="spec_version_supported"),
        CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="cvss_score_range",
        ),
        Index("ix_stix_objects_raw_gin", "raw", postgresql_using="gin"),
    )

    submission: Mapped[Submission] = relationship(back_populates="stix_objects")


class Distribution(Base):
    """Materialised visibility: this object is readable in this circle from this instant.

    This table is the single reason TAXII pagination stays correct across
    embargo lifts. ``date_added`` is stamped when the object becomes visible *to
    this circle* -- distribution time, or embargo release time if that is later
    -- so a member's ``added_after`` cursor never skips content that became
    visible after they last polled. Computing visibility dynamically instead
    would make ``date_added`` non-monotonic and silently drop objects from
    members' feeds.
    """

    __tablename__ = "distributions"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    stix_object_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("stix_objects.id", ondelete="RESTRICT"), nullable=False
    )
    circle_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("circles.id", ondelete="RESTRICT"), nullable=False
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("submissions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    date_added: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    #: Monotonic insertion order, used as the *tiebreaker* within a single
    #: ``date_added`` value for keyset pagination. This must not be the primary
    #: key: the primary key is a random UUID, and a random tiebreaker breaks the
    #: no-skip guarantee. When many rows share one ``date_added`` -- which is
    #: exactly what an embargo release of a batch produces, all stamped with the
    #: single ``release_at`` truncated to the same millisecond -- a random
    #: tiebreaker lets a row committed after a member paged past that millisecond
    #: sort *below* the cursor and be silently skipped. An identity sequence
    #: increases with insertion order, so the sort key only ever moves forward.
    #:
    #: This makes same-batch skips impossible, and nothing more. Identity values
    #: are assigned at INSERT, not at COMMIT, so ``seq`` orders inserts, not
    #: visibility: two concurrent distributions can commit in the opposite order
    #: to the one they inserted in, and a member polling between the commits is
    #: issued a cursor past the batch that commits last. This comment once said
    #: the single-transaction rule closed that; it closes it within one batch
    #: only. Across batches, ``services.publication`` does.
    seq: Mapped[int] = mapped_column(BigInteger, Identity(), nullable=False, unique=True)

    __table_args__ = (
        UniqueConstraint(
            "stix_object_id", "circle_id", name="uq_distributions_stix_object_id_circle_id"
        ),
        # The keyset-pagination index. Column order mirrors the ORDER BY in
        # taxii.queries exactly; changing one without the other silently turns
        # every member poll into a sequential scan.
        Index("ix_distributions_circle_paging", "circle_id", "date_added", "seq"),
    )


class Embargo(TimestampMixin, Base):
    """Release control for a submission.

    The scheduler that flips ``status`` is a convenience, not the enforcement
    point: visibility is gated at read time on ``distributions.date_added``. If
    the scheduler dies, nothing leaks early and the backlog self-heals on
    restart.
    """

    __tablename__ = "embargoes"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("submissions.id", ondelete="RESTRICT"), nullable=False, unique=True
    )
    policy: Mapped[EmbargoPolicy] = mapped_column(
        pg_enum(EmbargoPolicy, "embargo_policy"), nullable=False
    )
    status: Mapped[EmbargoStatus] = mapped_column(
        pg_enum(EmbargoStatus, "embargo_status"), nullable=False, default=EmbargoStatus.PENDING
    )
    release_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    released_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    coordination_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        CheckConstraint(
            "(policy <> 'timer') OR (release_at IS NOT NULL)", name="timer_requires_release_at"
        ),
        CheckConstraint(
            "(status NOT IN ('released', 'lifted_early')) OR (released_at IS NOT NULL)",
            name="released_has_timestamp",
        ),
    )

    submission: Mapped[Submission] = relationship(back_populates="embargo")


class Acknowledgment(Base):
    """Evidence that a member received, acknowledged, or acted on a submission.

    ``RETRIEVED`` rows are written by the server when content is actually
    delivered; the rest are member assertions. This is the table a regulator
    would be shown.
    """

    __tablename__ = "acknowledgments"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("submissions.id", ondelete="RESTRICT"), nullable=False
    )
    ack_type: Mapped[AckType] = mapped_column(pg_enum(AckType, "ack_type"), nullable=False)
    via: Mapped[AckVia] = mapped_column(pg_enum(AckVia, "ack_via"), nullable=False)
    #: Certificate fingerprint or operator id that produced the acknowledgment.
    actor_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Date-bucket used to collapse automatic retrieval receipts to one row per
    #: org per submission per day. Without it a member polling every minute
    #: would write 1,440 rows a day per object and drown the useful signal.
    dedupe_day: Mapped[dt.date | None] = mapped_column(nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    #: The writing transaction's id. The receipts stream (``services.audit_stream``)
    #: pages on ``(xact_id, id)`` and serves only rows below the oldest
    #: transaction still running: ``id`` alone comes from a sequence, so a
    #: transaction holding a lower id can commit after a reader has passed it,
    #: and the row would never be delivered (CLAUDE.md section 5, keyset).
    xact_id: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=text(_CURRENT_XACT_ID)
    )

    __table_args__ = (
        # `via` is part of the key: a portal read on a day the member's TAXII
        # client already polled is a different fact (a person looked), and
        # without it the second was silently absorbed (SF-51).
        UniqueConstraint(
            "org_id",
            "submission_id",
            "ack_type",
            "via",
            "dedupe_day",
            name="uq_acknowledgments_daily_dedupe",
        ),
        Index("ix_acknowledgments_submission_org", "submission_id", "org_id"),
        Index("ix_acknowledgments_stream", "xact_id", "id"),
    )


class TaxiiStatus(Base):
    """A TAXII 2.1 status resource tracking an asynchronous object POST."""

    __tablename__ = "taxii_status"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    submission_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("submissions.id", ondelete="RESTRICT"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    total_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pending_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    successes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    failures: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    pendings: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    request_timestamp: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (CheckConstraint("status IN ('pending', 'complete')", name="status_valid"),)


class Webhook(TimestampMixin, Base):
    """A member's registered notification endpoint."""

    __tablename__ = "webhooks"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    #: HMAC key the receiver uses to verify payload authenticity. The plaintext
    #: is shown to the member exactly once, at creation, and sealed by
    #: ``auth.secretbox`` thereafter, bound to this webhook's id.
    hmac_secret_encrypted: Mapped[bytes] = mapped_column(nullable=False)
    events: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (CheckConstraint("url LIKE 'https://%'", name="url_https_only"),)


class WebhookDelivery(Base):
    """One notification queued for one webhook, and how its delivery went.

    Written inside the transaction that made content visible, which is what
    makes notification durable: a process that dies before delivering has still
    recorded that it owes one, and the dispatcher picks it up on restart. The
    alternative -- firing after commit and hoping -- loses exactly the
    notifications that matter, since a crash mid-distribution is when a member
    most needs telling.
    """

    __tablename__ = "webhook_deliveries"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    webhook_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("webhooks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event: Mapped[str] = mapped_column(String(80), nullable=False)
    #: The contentless notification body. Carries identifiers and nothing else --
    #: no title, no TLP, no object content. See ``notify.events``.
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: When the dispatcher may next try. Null means "as soon as possible".
    next_attempt_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # The dispatcher's drain query: undelivered, due, oldest first.
        Index(
            "ix_webhook_deliveries_pending",
            "next_attempt_at",
            "id",
            postgresql_where=text("delivered_at IS NULL"),
        ),
    )


class SectorEvent(Base):
    """A sector event: one of the ISAC's canonical vulnerabilities, pinned while it lasts.

    Several a year, an advisory is revised all day while every member works the
    same problem. Pinning it puts the one living advisory at the top of every
    entitled member's dashboard, and marks every notice about it, so a member
    reads the current version rather than hunting for it. An editor opens and
    closes it; the vulnerability itself is versioned as usual.
    """

    __tablename__ = "sector_events"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    vulnerability_stix_id: Mapped[str] = mapped_column(String(100), nullable=False)
    opened_by_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), nullable=True
    )
    opened_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_by_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), nullable=True
    )
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # One open event per vulnerability: two pins on one advisory is one
        # event recorded twice, and closing one would leave the other.
        Index(
            "uq_sector_events_one_open",
            "vulnerability_stix_id",
            unique=True,
            postgresql_where=text("closed_at IS NULL"),
        ),
    )


class PendingNotice(Base):
    """A visibility notice held for an organisation's next digest.

    One row per organisation and *subject*: a vulnerability's STIX id when the
    submission versions one, else the submission itself. Versions of one
    advisory arriving inside a window update the row rather than adding one,
    so a sector event revised all afternoon is one line in the digest. Deleted
    when the digest is queued; never a record of what was read.
    """

    __tablename__ = "pending_notices"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    subject: Mapped[str] = mapped_column(String(120), nullable=False)
    #: The latest submission that made the subject visible to the organisation.
    submission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("submissions.id", ondelete="CASCADE"), nullable=False
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("taxii_collections.id", ondelete="CASCADE"), nullable=False
    )
    visible_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    #: How many submissions about the subject this window coalesced.
    versions: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (UniqueConstraint("org_id", "subject", name="uq_pending_notices_org_subject"),)


class EmailDelivery(Base):
    """One digest email queued for one organisation's mailbox, and how it went.

    Queued in the transaction that built the digest, drained by the email
    dispatcher, retried with backoff like a webhook delivery. The body is the
    contentless digest and nothing else.
    """

    __tablename__ = "email_deliveries"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    recipient: Mapped[str] = mapped_column(String(320), nullable=False)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index(
            "ix_email_deliveries_pending",
            "next_attempt_at",
            "id",
            postgresql_where=text("delivered_at IS NULL"),
        ),
    )


class PortalSession(Base):
    """A logged-in analyst's browser session.

    Only the SHA-256 of the session token is stored, so a database disclosure
    does not hand an attacker live sessions. ``cert_fingerprint`` binds the
    session to the organisation's transport certificate: presenting a stolen
    cookie from outside that org's network path fails the per-request check in
    ``auth.sessions``.
    """

    __tablename__ = "portal_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    operator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("operators.id", ondelete="CASCADE"), nullable=False, index=True
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    #: NOT NULL: an unbound session would be a cookie that authenticates on its
    #: own, which is the opposite of what this column exists for.
    #: The client certificate a certificate-bound session is tied to; ``None``
    #: for an SSO session, which is tied to the IdP subject and a device instead.
    cert_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: An SSO session's identity: the member issuer and subject it signed in as.
    idp_issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    idp_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: SHA-256 of the device cookie the SSO session was established with.
    device_cookie_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: The IdP's ``amr`` claim at sign-in: how the person authenticated, for
    #: the evidence pack's "which factor" question.
    amr: Mapped[list[str] | None] = mapped_column(ARRAY(String(40)), nullable=True)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(f"token_hash ~ '{_SHA256_HEX}'", name="token_hash_format"),
        # Exactly one binding: a certificate, or an IdP subject on a device.
        # A row with neither would be a cookie alone; a row with both would be
        # two session kinds at once, and each resolver checks only its own.
        CheckConstraint(
            "(cert_fingerprint IS NOT NULL AND idp_issuer IS NULL AND idp_subject IS NULL "
            "AND device_cookie_hash IS NULL) OR (cert_fingerprint IS NULL "
            "AND idp_issuer IS NOT NULL AND idp_subject IS NOT NULL "
            "AND device_cookie_hash IS NOT NULL)",
            name="exactly_one_binding",
        ),
    )


class DetectionState(Base):
    """When each (rule, subject) last raised a detection, so it raises once per window.

    Without it a rule evaluated every minute over a ten-minute window would
    raise the same burst ten times, and an alert that repeats itself is an alert
    people learn to ignore.
    """

    __tablename__ = "detection_state"

    rule: Mapped[str] = mapped_column(String(80), primary_key=True)
    subject: Mapped[str] = mapped_column(String(200), primary_key=True)
    last_raised_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SubmissionMilestone(Base):
    """A telemetry milestone already announced to a submission's submitter.

    So "your submission reached 10 organisations" is sent once, not on every
    pass. Holds no content: which submission, which milestone, when.
    """

    __tablename__ = "submission_milestones"

    submission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("submissions.id", ondelete="CASCADE"), primary_key=True
    )
    milestone: Mapped[str] = mapped_column(String(40), primary_key=True)
    reached_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CountSubject(StrEnum):
    """What a published count describes."""

    #: Members' VEX statuses on one distributed vulnerability, for ISAC reviewers.
    POSTURE = "posture"
    #: Reach and receipts of one distributed submission, for its submitter.
    TELEMETRY = "telemetry"


class CountSnapshot(Base):
    """The k-anonymous counts last published for one subject (R2-C1).

    Counts read live could be subtracted. Read before and after one firm's
    posture write, or around an editor suspending a firm, a count that moves by
    one says what that firm did. So readers get this snapshot, and
    ``services.count_snapshots`` replaces it only once at least K organisations'
    contributions differ from it. One firm's change then never moves a
    published number alone.

    ``basis`` maps each counted organisation's id to its contribution (a
    posture status, or the receipt types it holds). The counts are derived from
    it, and the next snapshot is compared with it organisation by organisation:
    comparing totals would miss two changes that cancel. It is never served,
    and offboarding removes the organisation from it.
    """

    __tablename__ = "count_snapshots"
    __table_args__ = (
        CheckConstraint("subject_kind IN ('posture', 'telemetry')", name="count_subject_known"),
    )

    subject_kind: Mapped[str] = mapped_column(String(20), primary_key=True)
    subject_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    taken_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    basis: Mapped[dict[str, str]] = mapped_column(JSONB, nullable=False)


class InstanceControl(Base):
    """Instance-wide switches an incident needs. Exactly one row, id 1.

    ``distribution_paused`` is the stop button: while it is set, nothing is
    published and nothing is served. Both halves matter. Refusing new
    publications alone does not stop an embargo stamped days ago from becoming
    visible when its time arrives -- visibility is the clock, not a writer -- so
    the read-side visibility clause consults this row too.
    """

    __tablename__ = "instance_controls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    distribution_paused: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    paused_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    paused_by_operator_id: Mapped[uuid.UUID | None] = mapped_column()
    pause_reason: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (CheckConstraint("id = 1", name="single_row"),)


class AuditLog(Base):
    """Append-only record of every security-relevant action.

    Deliberately has **no foreign keys** -- see the module docstring. Immutability
    is enforced in the database by a trigger that raises on UPDATE, DELETE, and
    TRUNCATE, and belt-and-braces by granting the application's role only INSERT
    and SELECT. Both are created in the initial migration.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    actor_type: Mapped[str] = mapped_column(String(30), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    org_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(60), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, default="success")
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    #: The writing transaction's id. The audit stream (``services.audit_stream``)
    #: pages on ``(xact_id, id)`` and serves only rows below the oldest
    #: transaction still running: ``id`` alone comes from a sequence, so a
    #: transaction holding a lower id can commit after a reader has passed it,
    #: and the row would never be delivered (CLAUDE.md section 5, keyset).
    xact_id: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=text(_CURRENT_XACT_ID)
    )

    __table_args__ = (
        CheckConstraint(
            "actor_type IN ('organization', 'operator', 'system', 'anonymous')",
            name="actor_type_valid",
        ),
        CheckConstraint("outcome IN ('success', 'failure', 'denied')", name="outcome_valid"),
        Index("ix_audit_log_org_at", "org_id", "at"),
        Index("ix_audit_log_stream", "xact_id", "id"),
    )


class AuditStreamModeChange(Base):
    """Each choice of what the audit stream serves of its own reading. Append-only.

    A history, not a flag: an ``audit.read`` row is served when the mode in
    force at *its* ``xact_id`` was ``full`` (``services.audit_stream``).
    Everything the stream serves lies below the horizon, so the served
    sequence is a function of immutable rows. A cursor issued before a change
    continues, and an export from genesis after it reproduces every hash
    exported before it. A flag read at serve time would re-sort history, and
    the chain an auditor kept would no longer match. No row means
    ``condensed``.
    """

    __tablename__ = "audit_stream_modes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    xact_id: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=text(_CURRENT_XACT_ID)
    )
    changed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    changed_by_operator_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint("mode IN ('full', 'condensed')", name="mode_known"),
        Index("ix_audit_stream_modes_xact", "xact_id", "id"),
    )


class OrgPosture(Base):
    """One organisation's VEX status for one vulnerability (SF-70).

    Private to that organisation: no other member and no one at the ISAC reads
    a row. The ISAC and submitters see counts, suppressed below k. A table
    rather than STIX because no STIX object holds a private per-organisation
    assertion that is never distributed.
    """

    __tablename__ = "org_postures"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    vulnerability_stix_id: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[PostureStatus] = mapped_column(
        pg_enum(PostureStatus, "posture_status"), nullable=False
    )
    #: VEX: why a ``not_affected`` product is not affected.
    justification: Mapped[VexJustification | None] = mapped_column(
        pg_enum(VexJustification, "vex_justification"), nullable=True
    )
    #: VEX: how the vulnerability does or does not reach this estate.
    impact_statement: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: VEX: what the organisation is doing about an ``affected`` product.
    action_statement: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: VEX: the products the statement is about, as the organisation names them
    #: (a PURL, a CPE, or a plain name). Empty means its estate as a whole.
    products: Mapped[list[str]] = mapped_column(
        ARRAY(String(200)), nullable=False, default=list, server_default=text("'{}'")
    )
    detection_deployed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    #: Ours: when the organisation last confirmed the posture holds. Written by
    #: the server when the member says it validated, never supplied as a time.
    validated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Ours: the organisation's own note on what it checked.
    evidence_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_by_operator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("org_id", "vulnerability_stix_id", name="uq_org_postures_org_vuln"),
        Index("ix_org_postures_vuln", "vulnerability_stix_id"),
        # VEX's own rules, held by the database so an export is always a valid
        # VEX document: a justification only explains not_affected, a
        # not_affected statement says why, and an affected one says what is
        # being done (OpenVEX 0.2.0, "Status Justifications" and
        # "action_statement").
        CheckConstraint(
            "justification IS NULL OR status = 'not_affected'",
            name="justification_only_when_not_affected",
        ),
        CheckConstraint(
            "status <> 'not_affected' OR justification IS NOT NULL OR impact_statement IS NOT NULL",
            name="not_affected_says_why",
        ),
        CheckConstraint(
            "status <> 'affected' OR action_statement IS NOT NULL",
            name="affected_says_what_is_done",
        ),
    )
