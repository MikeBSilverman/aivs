"""Shared vocabulary for AIVS.

Every enum here is a wire contract: the values are persisted in PostgreSQL enum
types, serialised into JSON APIs, and consumed by member firms' clients. Adding
a member is a compatible change; renaming or removing one is not, and requires a
migration plus a schema version bump.

``StrEnum`` is used throughout so that values compare and serialise as their
plain string form without callers reaching for ``.value`` -- which in practice is
where mismatches between the database, the API, and the tests creep in.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

__all__ = [
    "SUBMISSION_TRANSITIONS",
    "TERMINAL_SUBMISSION_STATES",
    "TLP",
    "TLP_RESTRICTIVENESS",
    "VISIBLE_SUBMISSION_STATES",
    "AIDiscoveryMethod",
    "AckType",
    "AckVia",
    "CVEStatus",
    "CertStatus",
    "CircleRole",
    "DiscoveryScope",
    "EmbargoPolicy",
    "EmbargoStatus",
    "OperatorRole",
    "OrgStatus",
    "OrgType",
    "SubmissionState",
    "is_transition_allowed",
    "tlp_at_least_as_restrictive",
]


class OrgType(StrEnum):
    """Classification of a member organisation.

    ``ADMIN`` is the hosting ISAC's own operations org: the tenant operator, not
    a sharing participant.
    """

    GSIB = "gsib"
    SECTION9 = "section9"
    CRIT_INFRA = "crit_infra"
    ADMIN = "admin"


class OrgStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"


#: Organisation types a circle's membership *rule* may admit automatically.
#:
#: A rule makes enrolment an access grant, so it is limited to the sector
#: member types whose eligibility the ISAC decides at enrolment. Never the ISAC's
#: own organisation (which reads by joining visibly, like anyone), and -- as the
#: plan adds them -- never vendors, researchers, government bodies, service
#: providers or automation identities: each of those is admitted to a circle by
#: a deliberate, named act or not at all. Enforced by the request model both
#: surfaces use, a database check, and reconciliation itself.
RULE_ELIGIBLE_ORG_TYPES: frozenset[OrgType] = frozenset(
    {OrgType.GSIB, OrgType.SECTION9, OrgType.CRIT_INFRA}
)


class OperatorRole(StrEnum):
    """A role a human operator holds. An operator may hold several.

    Two families. Within a member organisation, ``ANALYST`` and ``ORG_ADMIN``.
    At the hosting ISAC, four roles that are deliberately *not* ordered, because
    the point of splitting them is that holding one does not imply another:

    * ``ISAC_ANALYST`` -- the review queue and every submission's record; drafts,
      assigns, proposes. Never validates, distributes or reveals.
    * ``ISAC_EDITOR`` -- the editorial verbs: validate, distribute, embargo,
      reveal an anonymous submitter, create circles and set their floors.
    * ``ISAC_MEMBERSHIP`` -- enrolment, activation, suspension, quarantine,
      circle rosters, certificates. Reads organisations and counts; never
      content.
    * ``SYSTEM_ADMIN`` -- runs the instance: operators and settings. Lost the
      editorial verbs it used to hold.

    A small ISAC gives one person several of these; a larger one keeps them
    apart. That is the ISAC's decision, made when it assigns roles. Every one
    of them requires a human session -- see ``auth.policy``, the only place a
    role is interpreted.
    """

    ANALYST = "analyst"
    ORG_ADMIN = "org_admin"
    SYSTEM_ADMIN = "system_admin"
    ISAC_ANALYST = "isac_analyst"
    ISAC_EDITOR = "isac_editor"
    ISAC_MEMBERSHIP = "isac_membership"


class CertStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class CircleRole(StrEnum):
    """An organisation's role within one sharing circle.

    ``MEMBER`` may read; ``CONTRIBUTOR`` may also submit.

    ``CIRCLE_ADMIN`` **no longer administers anything**, and the name is kept
    only because removing a value from a PostgreSQL enum is disruptive out of
    proportion to the tidiness. It currently confers exactly what
    ``CONTRIBUTOR`` does. Admitting an organisation to a circle is the hosting
    ISAC's alone -- see ``auth.policy.can_administer_circle`` for why -- and the
    value is reserved against that decision being revisited rather than
    describing a capability the system grants today. Prefer ``CONTRIBUTOR``
    unless you are deliberately marking a firm for a future delegation model.
    """

    MEMBER = "member"
    CONTRIBUTOR = "contributor"
    CIRCLE_ADMIN = "circle_admin"


class SubmissionState(StrEnum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    VALIDATED = "validated"
    DISTRIBUTED = "distributed"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


class TLP(StrEnum):
    """Traffic Light Protocol 2.0 designations."""

    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber_strict"
    RED = "red"


class DiscoveryScope(StrEnum):
    """What the submitter's relationship to the affected system is.

    This is the control that keeps AIVS clear of the coordinated-disclosure
    consent problem: v1 accepts findings in the submitter's own products and
    estate, and findings about AI systems generally -- not undisclosed
    vulnerabilities in uninvolved third parties' software.
    """

    OWN_PRODUCT = "own_product"
    OWN_ESTATE = "own_estate"
    AI_SYSTEM = "ai_system"


class EmbargoPolicy(StrEnum):
    TIMER = "timer"
    COORDINATED = "coordinated"
    MANUAL = "manual"


class EmbargoStatus(StrEnum):
    PENDING = "pending"
    RELEASED = "released"
    EXTENDED = "extended"
    LIFTED_EARLY = "lifted_early"


class AckType(StrEnum):
    """Depth of a member's engagement with a submission.

    ``RETRIEVED`` is written automatically by the server when a member's client
    actually pulls the object; the other two are explicit member assertions.
    Together these form the "we warned you, and here is when they collected it"
    record that makes AIVS defensible to a regulator.
    """

    RETRIEVED = "retrieved"
    ACKNOWLEDGED = "acknowledged"
    ACTIONED = "actioned"


class AckVia(StrEnum):
    TAXII = "taxii"
    API = "api"
    PORTAL = "portal"


class AIDiscoveryMethod(StrEnum):
    """How the AI system found the finding. Hyphenated to match STIX style."""

    SAST_HARNESS = "sast-harness"
    DAST = "dast"
    FUZZING = "fuzzing"
    EXPLOIT_CHAIN_SEARCH = "exploit-chain-search"
    MODEL_AUDIT = "model-audit"
    RED_TEAM = "red-team"
    MANUAL_REVIEW = "manual-review"
    OTHER = "other"


class CVEStatus(StrEnum):
    """Where the finding sits relative to public CVE issuance.

    AIVS exists to serve the ``PRE_CVE`` window; the later values let a
    submission stay useful as it progresses toward publication.
    """

    PRE_CVE = "pre-cve"
    REQUESTED = "requested"
    ASSIGNED = "assigned"
    PUBLISHED = "published"


# ---------------------------------------------------------------------------
# Submission state machine
#
# Declared here rather than in the server so that the server, the tests, the
# CLI, and the portal all agree on exactly one definition of a legal move.
# Anything not listed is forbidden; there is no implicit self-transition.
# ---------------------------------------------------------------------------
SUBMISSION_TRANSITIONS: Final[Mapping[SubmissionState, frozenset[SubmissionState]]] = (
    MappingProxyType(
        {
            SubmissionState.DRAFT: frozenset(
                {SubmissionState.SUBMITTED, SubmissionState.WITHDRAWN}
            ),
            SubmissionState.SUBMITTED: frozenset(
                {SubmissionState.VALIDATED, SubmissionState.WITHDRAWN}
            ),
            SubmissionState.VALIDATED: frozenset(
                {SubmissionState.DISTRIBUTED, SubmissionState.WITHDRAWN}
            ),
            # Once distributed, a submission can never be un-distributed: members
            # already hold the content, so withdrawal would be a false promise.
            # It can only be replaced by a newer version.
            SubmissionState.DISTRIBUTED: frozenset({SubmissionState.SUPERSEDED}),
            SubmissionState.SUPERSEDED: frozenset(),
            SubmissionState.WITHDRAWN: frozenset(),
        }
    )
)

TERMINAL_SUBMISSION_STATES: Final[frozenset[SubmissionState]] = frozenset(
    {SubmissionState.SUPERSEDED, SubmissionState.WITHDRAWN}
)

#: States in which a submission's objects may appear in a TAXII collection.
#: Superseded content stays readable -- members who pulled it need its history,
#: and removing it would silently break their ``added_after`` polling.
VISIBLE_SUBMISSION_STATES: Final[frozenset[SubmissionState]] = frozenset(
    {SubmissionState.DISTRIBUTED, SubmissionState.SUPERSEDED}
)

#: Higher means more restrictive. Used to check that a submission is never
#: distributed into a circle under a marking looser than the submitter chose.
TLP_RESTRICTIVENESS: Final[Mapping[TLP, int]] = MappingProxyType(
    {
        TLP.CLEAR: 0,
        TLP.GREEN: 1,
        TLP.AMBER: 2,
        TLP.AMBER_STRICT: 3,
        TLP.RED: 4,
    }
)


def is_transition_allowed(current: SubmissionState, target: SubmissionState) -> bool:
    """Return whether moving a submission from ``current`` to ``target`` is legal."""
    return target in SUBMISSION_TRANSITIONS[current]


def tlp_at_least_as_restrictive(candidate: TLP, floor: TLP) -> bool:
    """Return whether ``candidate`` is no looser than ``floor``."""
    return TLP_RESTRICTIVENESS[candidate] >= TLP_RESTRICTIVENESS[floor]
