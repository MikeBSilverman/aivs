"""Creating the humans who use the system.

One function, used by the bootstrap command now and by the operator-management
screens when they exist, so the rules for what an operator *is* -- a sealed
second factor bound to its own id, a hashed password of minimum length, roles
the organisation is allowed to hold -- live in one place.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OperatorRole, OrgType
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.passwords import generate_totp_secret, hash_password
from aivs_server.auth.secretbox import SecretBox, SecretPurpose
from aivs_server.db.models import Operator, Organization

__all__ = ["ISAC_ONLY_ROLES", "OperatorError", "create_operator"]

#: Roles that mean something only at the hosting ISAC. Granting one to a member
#: firm's operator would be inert -- policy checks the organisation first -- but
#: an inert grant is a claim the system does not keep, and it would read as real
#: to anyone auditing who holds what.
ISAC_ONLY_ROLES: frozenset[OperatorRole] = frozenset(
    {
        OperatorRole.SYSTEM_ADMIN,
        OperatorRole.ISAC_ANALYST,
        OperatorRole.ISAC_EDITOR,
        OperatorRole.ISAC_MEMBERSHIP,
    }
)


class OperatorError(ValueError):
    """An operator could not be created as asked."""


async def create_operator(
    session: AsyncSession,
    ctx: AuthContext | None,
    *,
    organisation: Organization,
    email: str,
    display_name: str,
    password: str,
    roles: Iterable[OperatorRole],
    secret_box: SecretBox,
) -> tuple[Operator, str]:
    """Create an operator. Returns it and the TOTP seed, to be shown exactly once.

    The id is generated here, before sealing, because the seed is sealed with
    the operator's own id as additional data and a column default is not applied
    until INSERT -- a seal made against ``None`` would never open (CLAUDE.md
    section 5). Does not commit.
    """
    held = frozenset(roles)
    if not held:
        msg = "an operator needs at least one role"
        raise OperatorError(msg)
    misplaced = held & ISAC_ONLY_ROLES
    if misplaced and organisation.org_type is not OrgType.ADMIN:
        msg = (
            f"{', '.join(sorted(role.value for role in misplaced))} can only be held at "
            "the hosting ISAC"
        )
        raise OperatorError(msg)

    seed = generate_totp_secret()
    operator_id = uuid.uuid4()
    operator = Operator(
        id=operator_id,
        org_id=organisation.id,
        email=email.strip().lower(),
        display_name=display_name,
        roles=sorted(held),
        password_hash=hash_password(password),
        totp_secret_encrypted=secret_box.seal(
            seed, purpose=SecretPurpose.TOTP, subject=operator_id
        ),
        is_active=True,
    )
    session.add(operator)
    await record(
        session,
        action=AuditAction.OPERATOR_CREATED,
        ctx=ctx,
        org_id=organisation.id,
        resource_type="operator",
        resource_id=str(operator_id),
        # Roles, not the email: the audit log is immutable, and a person's
        # address in it could never be removed when they leave.
        details={"roles": sorted(role.value for role in held)},
    )
    return operator, seed
