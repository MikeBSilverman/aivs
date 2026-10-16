"""Who a verified member-tenant identity is in AIVS, and which organisation it acts for.

Every check is permit-only (CLAUDE.md section 5): a sign-in proceeds only when
the identity's groups name exactly one active member organisation, and the
operator it maps to belongs to that organisation. Anything else is refused,
never downgraded:

- A group that maps to the hosting ISAC's own organisation is refused. The
  member tenant can never yield staff authority, whatever its groups say;
  that is the point of the issuer deciding authority
  (identity-federation.md §2).
- A group that maps to no organisation grants nothing. A person in two
  members' groups is refused rather than guessed at.
- The operator is found by issuer and subject. Email is used once, to link a
  pre-provisioned operator on first sign-in, and never again (§4); and only
  an address in one of the organisation's recorded mail domains is linked or
  created (``services.mail_domains``, Q41), so a member's IdP cannot claim
  another firm's person.
- A first sign-in with no operator creates one when JIT provisioning is on.
  It gets ``ANALYST`` and nothing more: the directory says who is a member,
  not who may edit other firms' content (§5).
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OperatorRole, OrgStatus, OrgType
from aivs_server.auth.oidc import SsoRejectedError, VerifiedIdentity
from aivs_server.db.models import Operator, Organization
from aivs_server.services.mail_domains import address_in_organisation_domains

__all__ = ["SignIn", "resolve_member_sign_in"]


@dataclass(frozen=True)
class SignIn:
    operator: Operator
    organization: Organization
    provisioned: bool


async def resolve_member_sign_in(
    session: AsyncSession, identity: VerifiedIdentity, *, jit_provisioning: bool
) -> SignIn:
    """The operator and organisation a verified identity signs in as. Does not commit."""
    organization = await _organisation_for(session, identity.groups)
    operator = await _linked_operator(session, identity)
    if operator is not None:
        _require_same_organisation(operator, organization)
        return SignIn(operator, organization, provisioned=False)
    if not jit_provisioning:
        reason = "not_provisioned"
        raise SsoRejectedError(reason)
    operator, provisioned = await _link_or_create(session, identity, organization)
    return SignIn(operator, organization, provisioned=provisioned)


async def _organisation_for(session: AsyncSession, groups: tuple[str, ...]) -> Organization:
    matched = (
        list(
            (
                await session.execute(
                    select(Organization).where(Organization.directory_object_id.in_(groups))
                )
            )
            .scalars()
            .all()
        )
        if groups
        else []
    )
    if any(org.org_type is OrgType.ADMIN for org in matched):
        reason = "staff_group_on_member_issuer"
        raise SsoRejectedError(reason)
    if not matched:
        reason = "no_mapped_organisation"
        raise SsoRejectedError(reason)
    if len(matched) > 1:
        reason = "ambiguous_organisation"
        raise SsoRejectedError(reason)
    organization = matched[0]
    if organization.status is not OrgStatus.ACTIVE:
        reason = "organisation_inactive"
        raise SsoRejectedError(reason)
    return organization


async def _linked_operator(session: AsyncSession, identity: VerifiedIdentity) -> Operator | None:
    return (
        await session.execute(
            select(Operator).where(
                Operator.federated_issuer == identity.issuer,
                Operator.federated_subject == identity.subject,
            )
        )
    ).scalar_one_or_none()


def _require_same_organisation(operator: Operator, organization: Organization) -> None:
    """A person who moved firms in the directory does not carry the old firm's operator."""
    if not operator.is_active:
        reason = "operator_inactive"
        raise SsoRejectedError(reason)
    if operator.org_id != organization.id:
        reason = "organisation_changed"
        raise SsoRejectedError(reason)


async def _link_or_create(
    session: AsyncSession, identity: VerifiedIdentity, organization: Organization
) -> tuple[Operator, bool]:
    if identity.email is None:
        reason = "no_email_claim"
        raise SsoRejectedError(reason)
    email = identity.email.strip().lower()
    # The IdP asserts the address; the ISAC decides which domains are this
    # firm's. Without this a member tenant could link another firm's person,
    # and with the email intake on, file that person's mail as its own (R30).
    if not await address_in_organisation_domains(session, address=email, org_id=organization.id):
        reason = "email_outside_organisation_domains"
        raise SsoRejectedError(reason)
    existing = (
        await session.execute(select(Operator).where(Operator.email == email))
    ).scalar_one_or_none()
    if existing is not None:
        _require_linkable(existing, organization)
        existing.federated_issuer = identity.issuer
        existing.federated_subject = identity.subject
        return existing, False
    created = Operator(
        org_id=organization.id,
        email=email,
        display_name=(identity.name or email)[:200],
        roles=[OperatorRole.ANALYST],
        password_hash=None,
        federated_issuer=identity.issuer,
        federated_subject=identity.subject,
        is_active=True,
    )
    session.add(created)
    await session.flush()
    return created, True


def _require_linkable(operator: Operator, organization: Organization) -> None:
    """A pre-provisioned operator links once, to its own organisation, while unlinked."""
    if operator.org_id != organization.id or operator.federated_issuer is not None:
        reason = "email_belongs_to_another_identity"
        raise SsoRejectedError(reason)
    if not operator.is_active:
        reason = "operator_inactive"
        raise SsoRejectedError(reason)
