"""Which mail domains are which member's (Q41; threat model R30).

An email address names a person in two places: the email intake files a
message into the organisation of the person registered at its From address,
and a first SSO sign-in links or creates a person by the IdP's ``email``
claim. Neither asked whether the address could be the organisation's, so
whoever could register an address (an ISAC operator, or a member's IdP that
can set claims for its users) decided where another firm's person's mail
landed, and the address being unique kept the real firm from registering it.

Now an address counts for an organisation only in a domain the ISAC has
recorded as that organisation's. Membership staff record them at onboarding;
an organisation with none takes no mail and links no new SSO person, which is
the fail-closed reading of "nobody has said which domains are theirs".

Domains are compared exactly, after the one normalisation both sides get
(lower case; an internationalised name as its A-label), so a subdomain is
its own entry and every domain the ISAC accepts is one it wrote down.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Final

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgStatus
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import Organization, OrgMailDomain

__all__ = [
    "MailDomainError",
    "add_mail_domain",
    "address_domain",
    "address_in_organisation_domains",
    "mail_domains_of",
    "parse_mail_domain",
    "remove_mail_domain",
]

_MAX_DOMAIN: Final[int] = 253
_MAX_LABEL: Final[int] = 63
_LABEL_CHARACTERS: Final[frozenset[str]] = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


class MailDomainError(ValueError):
    """A domain that cannot be recorded, or removed, as given; the message says why."""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def parse_mail_domain(text: str) -> str:
    """The domain in the one form it is stored and compared in, or ``MailDomainError``.

    A trailing dot is the DNS root and is dropped; anything else that is not
    a host name (an address, a wildcard, a single label, an IP literal) is
    refused rather than repaired, because a repaired value is one the ISAC
    did not type.
    """
    candidate = text.strip().lower().removesuffix(".")
    try:
        ascii_form = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        reason = "not a valid domain name"
        raise MailDomainError(reason) from exc
    if not _is_host_name(ascii_form):
        reason = "not a domain name of two or more labels (for example example.com)"
        raise MailDomainError(reason)
    return ascii_form


def _is_host_name(domain: str) -> bool:
    labels = domain.split(".")
    return (
        len(domain) <= _MAX_DOMAIN
        and len(labels) >= 2  # noqa: PLR2004 - a domain of one label is a top-level domain
        and all(_is_label(label) for label in labels)
        and not labels[-1].isdigit()
    )


def _is_label(label: str) -> bool:
    return (
        0 < len(label) <= _MAX_LABEL
        and set(label) <= _LABEL_CHARACTERS
        and not label.startswith("-")
        and not label.endswith("-")
    )


def address_domain(address: str) -> str | None:
    """The domain of an address, normalised as recorded domains are; ``None`` if it has none."""
    local, at, domain = address.rpartition("@")
    if not at or not local:
        return None
    try:
        return parse_mail_domain(domain)
    except MailDomainError:
        return None


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
async def address_in_organisation_domains(
    session: AsyncSession, *, address: str, org_id: uuid.UUID
) -> bool:
    """Whether ``address`` is in a domain recorded as this organisation's."""
    domain = address_domain(address)
    if domain is None:
        return False
    holder = await session.scalar(
        select(OrgMailDomain.org_id).where(OrgMailDomain.domain == domain)
    )
    return holder == org_id


async def mail_domains_of(session: AsyncSession, org_id: uuid.UUID) -> list[str]:
    """The organisation's recorded domains, in order."""
    rows = await session.scalars(
        select(OrgMailDomain.domain)
        .where(OrgMailDomain.org_id == org_id)
        .order_by(OrgMailDomain.domain)
    )
    return list(rows.all())


# ---------------------------------------------------------------------------
# Writing (membership staff; the caller checks policy and commits)
# ---------------------------------------------------------------------------
async def add_mail_domain(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    organisation: Organization,
    domain: str,
    now: dt.datetime,
) -> str:
    """Record ``domain`` as the organisation's, locked by the caller. Returns it as stored.

    A domain already recorded for another organisation is refused, naming
    that organisation: the caller is ISAC staff, who can see every member,
    and two firms claiming one domain is a question for them to settle. Two
    staff adding one domain at once both reach the INSERT; the primary key
    refuses the second, and the caller reports that as the same conflict.
    """
    if organisation.status is OrgStatus.OFFBOARDED:
        # Offboarding deleted its domains so another member can be given them;
        # the caller holds the organisation's row lock, so this cannot race it.
        reason = f"{organisation.slug} has been offboarded"
        raise MailDomainError(reason)
    stored = parse_mail_domain(domain)
    holder = await session.get(OrgMailDomain, stored)
    if holder is not None:
        await _refuse_held(session, holder, organisation)
    session.add(
        OrgMailDomain(
            domain=stored,
            org_id=organisation.id,
            added_at=now,
            added_by_operator_id=ctx.operator_id,
        )
    )
    await _audit(session, ctx, AuditAction.ORG_MAIL_DOMAIN_ADDED, organisation, stored)
    return stored


async def _refuse_held(
    session: AsyncSession, holder: OrgMailDomain, organisation: Organization
) -> None:
    if holder.org_id == organisation.id:
        reason = f"{holder.domain} is already recorded for {organisation.slug}"
        raise MailDomainError(reason)
    other = await session.get(Organization, holder.org_id)
    other_slug = other.slug if other is not None else str(holder.org_id)
    reason = f"{holder.domain} is recorded for {other_slug}; remove it there first"
    raise MailDomainError(reason)


async def remove_mail_domain(
    session: AsyncSession, ctx: AuthContext, *, organisation: Organization, domain: str
) -> str:
    """Stop counting ``domain`` as the organisation's. Returns it as it was stored.

    People already registered in it keep their accounts; the intake refuses
    their mail and SSO links no new one there. An SSO person already linked
    signs in by issuer and subject, which the domain never decided.
    """
    stored = parse_mail_domain(domain)
    removed = await session.execute(
        delete(OrgMailDomain)
        .where(OrgMailDomain.domain == stored, OrgMailDomain.org_id == organisation.id)
        .returning(OrgMailDomain.domain)
    )
    if removed.scalar_one_or_none() is None:
        reason = f"{stored} is not recorded for {organisation.slug}"
        raise MailDomainError(reason)
    await _audit(session, ctx, AuditAction.ORG_MAIL_DOMAIN_REMOVED, organisation, stored)
    return stored


async def _audit(
    session: AsyncSession,
    ctx: AuthContext,
    action: str,
    organisation: Organization,
    domain: str,
) -> None:
    await record(
        session,
        action=action,
        ctx=ctx,
        resource_type="organization",
        resource_id=organisation.slug,
        details={"domain": domain},
    )
