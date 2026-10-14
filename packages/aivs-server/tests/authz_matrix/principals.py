"""The kinds of caller the matrix proves, one credential factory each.

A principal is a *kind* of caller, not a person: what it presents (nothing, a
certificate, a session) and which organisation and roles stand behind it. Each
session principal is exercised over both of its channels -- the API as a bearer
token, the portal as a cookie -- because a member's analyst reaches both.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from aivs_schemas.enums import OperatorRole


class Principal(enum.StrEnum):
    ANONYMOUS = "anonymous"
    FORGED_PROXY_SECRET = "forged proxy secret"
    PENDING_ORG = "pending organisation"
    SUSPENDED_ORG = "suspended organisation"
    QUARANTINED_ORG = "quarantined organisation"
    MEMBER_MACHINE = "member machine certificate"
    PEER_MACHINE = "another member's machine certificate"
    MEMBER_ANALYST = "member analyst session"
    MEMBER_ORG_ADMIN = "member org_admin session"
    ADMIN_CERTIFICATE = "admin organisation certificate alone"
    AUTOMATION_MACHINE = "automation machine certificate"
    ISAC_ANALYST = "ISAC analyst session"
    ISAC_EDITOR = "ISAC editor session"
    ISAC_MEMBERSHIP = "ISAC membership session"
    SYSTEM_ADMIN = "system_admin session"
    #: A member's analyst signed in through the ISAC's IdP over ordinary TLS:
    #: no certificate, bound to its IdP subject and a device cookie.
    SSO_MEMBER = "member SSO session"


#: Principals the plan names that have no implementation yet. They are listed,
#: not faked: a fixture for a role the server cannot hold would prove the
#: fixture, and the row it filled would read as a guarantee. Each is added to
#: :class:`Principal`, with its expected row, in the phase that builds it.
PLANNED_PRINCIPALS: dict[str, str] = {
    "ISAC auditor session": "added with Phase H",
    "researcher organisation": "added with Phase E",
    "government organisation": "added with Phase E",
    "approved delegated provider (MSSP)": "added with Phase K",
    "unapproved delegated provider": "added with Phase K",
}


@dataclass(frozen=True)
class Credentials:
    """What a principal presents on each surface."""

    #: Headers on every request: the proxy's identity headers, and for a session
    #: principal on the API, ``Authorization: Bearer``.
    api_headers: dict[str, str] = field(default_factory=dict)
    #: Headers on portal requests: the proxy's identity headers only.
    portal_headers: dict[str, str] = field(default_factory=dict)
    #: Portal cookies, for a session principal.
    cookies: dict[str, str] = field(default_factory=dict)
    #: The portal form token, for a session principal.
    csrf_token: str = "not-a-session"


#: Session principals: the organisation they belong to and the role they hold.
SESSION_ROLES: dict[Principal, tuple[str, OperatorRole]] = {
    Principal.MEMBER_ANALYST: ("member", OperatorRole.ANALYST),
    Principal.MEMBER_ORG_ADMIN: ("member", OperatorRole.ORG_ADMIN),
    Principal.ISAC_ANALYST: ("isac", OperatorRole.ISAC_ANALYST),
    Principal.ISAC_EDITOR: ("isac", OperatorRole.ISAC_EDITOR),
    Principal.ISAC_MEMBERSHIP: ("isac", OperatorRole.ISAC_MEMBERSHIP),
    Principal.SYSTEM_ADMIN: ("isac", OperatorRole.SYSTEM_ADMIN),
}

#: Certificate-only principals: the organisation whose certificate they present.
CERTIFICATE_ORGS: dict[Principal, str] = {
    Principal.PENDING_ORG: "pending",
    Principal.SUSPENDED_ORG: "suspended",
    Principal.QUARANTINED_ORG: "quarantined",
    Principal.MEMBER_MACHINE: "member",
    Principal.PEER_MACHINE: "peer",
    Principal.ADMIN_CERTIFICATE: "isac",
    Principal.AUTOMATION_MACHINE: "automation",
}
