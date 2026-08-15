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
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aivs_schemas.enums import (
    TLP,
    AckType,
    AckVia,
    CertStatus,
    CircleRole,
    DiscoveryScope,
    EmbargoPolicy,
    EmbargoStatus,
    OperatorRole,
    OrgStatus,
    OrgType,
    SubmissionState,
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
    "Distribution",
    "Embargo",
    "Operator",
    "Organization",
    "PortalSession",
    "StixObject",
    "Submission",
    "SubmissionTransition",
    "TaxiiCollection",
    "TaxiiStatus",
    "Webhook",
    "WebhookDelivery",
]

# A SHA-256 fingerprint rendered as lowercase hex. Enforced in the database so
# that a bug in the parsing layer cannot store a mixed-case or truncated value
# that would then silently fail to match on lookup.
_SHA256_HEX = "^[0-9a-f]{64}$"


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
    #: The org's STIX ``identity`` SDO id, used as ``created_by_ref`` on objects
    #: it submits (except where the submission is distributed anonymously).
    stix_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    contact_email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    __table_args__ = (
        CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'", name="slug_format"),
        CheckConstraint(
            "stix_identity_id ~ '^identity--[0-9a-f-]{36}$'", name="stix_identity_format"
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
    role: Mapped[OperatorRole] = mapped_column(
        pg_enum(OperatorRole, "operator_role"), nullable=False, default=OperatorRole.ANALYST
    )
    #: Argon2id hash. Never a raw password, never a reversible encryption.
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    #: TOTP shared secret, encrypted at rest by the application.
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

    organization: Mapped[Organization] = relationship(back_populates="operators")


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
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'", name="slug_format"),
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

    __table_args__ = (
        UniqueConstraint("circle_id", "org_id", name="uq_circle_memberships_circle_id_org_id"),
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
    #: This makes same-batch skips impossible. The distribution service must
    #: additionally write all rows for one submission in a single transaction, so
    #: that MVCC presents the batch atomically to a concurrent reader; that
    #: obligation is enforced where the rows are written, not here.
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

    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "submission_id",
            "ack_type",
            "dedupe_day",
            name="uq_acknowledgments_daily_dedupe",
        ),
        Index("ix_acknowledgments_submission_org", "submission_id", "org_id"),
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
    #: HMAC key the receiver uses to verify payload authenticity. Encrypted at
    #: rest; the plaintext is shown to the member exactly once, at creation.
    hmac_secret_encrypted: Mapped[bytes] = mapped_column(nullable=False)
    events: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (CheckConstraint("url LIKE 'https://%'", name="url_https_only"),)


class WebhookDelivery(Base):
    """One delivery attempt of one event to one webhook."""

    __tablename__ = "webhook_deliveries"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    webhook_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("webhooks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event: Mapped[str] = mapped_column(String(80), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
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
    cert_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
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

    __table_args__ = (CheckConstraint(f"token_hash ~ '{_SHA256_HEX}'", name="token_hash_format"),)


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

    __table_args__ = (
        CheckConstraint(
            "actor_type IN ('organization', 'operator', 'system', 'anonymous')",
            name="actor_type_valid",
        ),
        CheckConstraint("outcome IN ('success', 'failure', 'denied')", name="outcome_valid"),
        Index("ix_audit_log_org_at", "org_id", "at"),
    )
