"""AIVS shared contract package.

Imported by the server, the reference client, and by member firms integrating
against an AIVS instance. Everything exported here is a compatibility surface:
treat additions as cheap and changes as expensive.
"""

from __future__ import annotations

from aivs_schemas.enums import (
    AckType,
    AckVia,
    AIDiscoveryMethod,
    CertStatus,
    CircleRole,
    CVEStatus,
    DiscoveryScope,
    EmbargoPolicy,
    EmbargoStatus,
    OperatorRole,
    OrgStatus,
    OrgType,
    SubmissionState,
    TLP,
    is_transition_allowed,
    tlp_at_least_as_restrictive,
)

__version__ = "0.1.0"

#: Version of the AIVS STIX property-extension carried in distributed objects.
#: Bumped independently of the package version; see docs/stix-extension.md.
AIVS_EXTENSION_VERSION = "1.0"

__all__ = [
    "AIVS_EXTENSION_VERSION",
    "AckType",
    "AckVia",
    "AIDiscoveryMethod",
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
    "TLP",
    "__version__",
    "is_transition_allowed",
    "tlp_at_least_as_restrictive",
]
