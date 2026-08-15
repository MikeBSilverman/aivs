"""The authenticated caller's identity, as data.

``AuthContext`` answers *who is calling*. It deliberately contains no method
that answers *may they do this* -- every such question lives in
``auth.policy``. Keeping the two apart is what makes the authorization matrix
tests meaningful: there is exactly one module to enumerate.

The context is frozen. A handler cannot widen its own caller's privileges by
mutating it, accidentally or otherwise.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from aivs_schemas.enums import CircleRole, OperatorRole, OrgStatus, OrgType

__all__ = ["AuthContext", "AuthMethod", "CircleGrant"]


class AuthMethod(StrEnum):
    """How the caller proved their identity."""

    #: Machine-to-machine: a client certificate terminated by the proxy.
    MTLS = "mtls"
    #: A human in the portal: password + TOTP session, additionally bound to the
    #: organisation's client certificate.
    PORTAL_SESSION = "portal_session"


@dataclass(frozen=True, slots=True)
class CircleGrant:
    """What a caller holds in one circle: a role, and when it started.

    One value rather than two parallel mappings on ``AuthContext``. Both are
    read on the authorization path -- the role decides what may be written, the
    start decides what may be read -- and two mappings keyed the same way are
    exactly the shape that drifts apart under a later edit.
    """

    role: CircleRole
    #: Content distributed to the circle before this moment is not readable by
    #: this caller. See ``policy.visible_content_clause``.
    joined_at: dt.datetime


@dataclass(frozen=True, slots=True)
class AuthContext:
    """Identity and memberships of the current caller."""

    org_id: uuid.UUID
    org_slug: str
    org_type: OrgType
    org_status: OrgStatus
    auth_method: AuthMethod

    #: Circle membership: what is held in each, and since when. Empty is normal:
    #: a newly enrolled org belongs to no circle and must therefore see nothing.
    circles: Mapping[uuid.UUID, CircleGrant] = field(default_factory=lambda: MappingProxyType({}))

    #: Present for MTLS callers; also present for portal sessions, which are
    #: bound to the certificate that established the network path.
    cert_fingerprint: str | None = None

    #: Present only for portal sessions.
    operator_id: uuid.UUID | None = None
    operator_role: OperatorRole | None = None

    #: Correlates this request across the audit log and application logs.
    request_id: str = ""
    source_ip: str | None = None

    def __post_init__(self) -> None:
        # Freeze the mapping so a handler cannot grant itself a circle by
        # mutating what it was handed.
        if not isinstance(self.circles, MappingProxyType):
            object.__setattr__(self, "circles", MappingProxyType(dict(self.circles)))

    @property
    def circle_ids(self) -> frozenset[uuid.UUID]:
        """Identifiers of every circle this caller's organisation belongs to."""
        return frozenset(self.circles)

    @property
    def actor_type(self) -> str:
        """Audit-log actor classification."""
        return "operator" if self.operator_id is not None else "organization"

    @property
    def actor_id(self) -> str:
        """Audit-log actor identifier."""
        if self.operator_id is not None:
            return str(self.operator_id)
        return self.cert_fingerprint or str(self.org_id)
