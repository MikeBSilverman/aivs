"""Create the hosting ISAC's organisation, first certificate and first operator.

    python -m aivs_server.bootstrap_operator \\
        --org-slug example-isac --org-name "Example ISAC" \\
        --email ops@example-isac.org --name "Ops Lead" \\
        --role system_admin --role isac_editor --role isac_membership \\
        --certificate deploy/ca/out/clients/example-isac/example-isac.crt

Every ISAC power requires a signed-in human, and enrolling an organisation,
registering a certificate or creating an operator are themselves ISAC powers.
On a fresh instance nobody can exercise them, so the first of each is made
here, by whoever holds the host and the key-encryption key -- which is exactly
the party that could do it with SQL anyway, now with validation, sealing and an
audit record instead.

It refuses to touch a member organisation: this is how the ISAC starts, not a
way round the portal for creating anyone else's operators. The password is read
from the terminal, never the command line, which would leave it in shell
history and the process table. The TOTP provisioning URI is printed once.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import getpass
import logging
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OperatorRole, OrgStatus, OrgType
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.passwords import totp_provisioning_uri
from aivs_server.auth.secretbox import SecretBox
from aivs_server.config import Settings, get_settings
from aivs_server.db.engine import session_scope
from aivs_server.db.models import Operator, Organization
from aivs_server.services.certificates import register_certificate
from aivs_server.services.operators import create_operator

__all__ = ["BootstrapError", "BootstrapResult", "bootstrap"]

logger = logging.getLogger(__name__)


class BootstrapError(ValueError):
    """The bootstrap was refused; the message says why."""


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    organisation_id: uuid.UUID
    operator_id: uuid.UUID
    totp_seed: str
    created_organisation: bool


async def _isac_organisation(
    session: AsyncSession, *, slug: str, name: str | None
) -> tuple[Organization, bool]:
    """Find the ISAC's organisation by slug, creating it on a fresh instance."""
    found = (
        await session.execute(select(Organization).where(Organization.slug == slug))
    ).scalar_one_or_none()
    if found is not None:
        if found.org_type is not OrgType.ADMIN:
            msg = f"'{slug}' is a member organisation; the bootstrap creates ISAC operators only"
            raise BootstrapError(msg)
        return found, False

    existing_admin = (
        await session.execute(
            select(Organization.slug).where(Organization.org_type == OrgType.ADMIN)
        )
    ).scalar_one_or_none()
    if existing_admin is not None:
        msg = f"this instance already has an ISAC organisation, '{existing_admin}'"
        raise BootstrapError(msg)
    if not name:
        msg = f"no organisation '{slug}' exists; pass --org-name to create the ISAC's"
        raise BootstrapError(msg)

    organisation = Organization(
        slug=slug,
        name=name,
        org_type=OrgType.ADMIN,
        status=OrgStatus.ACTIVE,
        stix_identity_id=f"identity--{uuid.uuid4()}",
    )
    session.add(organisation)
    await session.flush()
    await record(
        session,
        action=AuditAction.ORG_CREATED,
        resource_type="organization",
        resource_id=slug,
        details={"org_type": OrgType.ADMIN.value, "via": "bootstrap"},
    )
    return organisation, True


async def _active_system_admins(session: AsyncSession, organisation: Organization) -> int:
    return int(
        await session.scalar(
            select(func.count())
            .select_from(Operator)
            .where(
                Operator.org_id == organisation.id,
                Operator.is_active.is_(True),
                Operator.roles.contains([OperatorRole.SYSTEM_ADMIN]),
            )
        )
        or 0
    )


async def _register_new_certificate(
    session: AsyncSession, settings: Settings, organisation: Organization, certificate_pem: str
) -> None:
    """Register the certificate, refusing by name one that is already registered.

    Refused even when it is already the ISAC's own: registering it again adds
    nothing, and a revoked one must not come back this way. The unique
    fingerprint is the authority, so the insert is flushed here, where the only
    row that can violate it is this one, rather than surfacing as a constraint
    violation at commit. (A session that autoflushes may raise it inside the
    registration itself, so that is inside the ``try`` too.)
    """
    try:
        await register_certificate(
            session,
            None,
            organisation=organisation,
            certificate_pem=certificate_pem,
            label="bootstrap",
            issuing_ca=settings.issuing_ca_certificate,
            now=dt.datetime.now(dt.UTC),
        )
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        msg = (
            "that certificate is already registered; omit --certificate when adding "
            "an operator to an ISAC that has one"
        )
        raise BootstrapError(msg) from exc


async def bootstrap(
    session: AsyncSession,
    settings: Settings,
    *,
    org_slug: str,
    org_name: str | None,
    email: str,
    display_name: str,
    password: str,
    roles: list[OperatorRole],
    certificate_pem: str | None,
    additional: bool,
) -> BootstrapResult:
    """Create what a fresh instance lacks, in one transaction. Commits.

    Once the instance has an active system admin, refused unless
    ``additional``: whoever holds the host and the key-encryption key can mint
    ISAC editors this way, which is the power the human-only role rules keep
    from the host. Until operators can be created in the portal this is also
    the only way to add one, so it is not refused outright; instead every run
    writes ``operator.bootstrapped`` and raises the ``operator_bootstrapped``
    detection, so an operator minted from the host is announced to the ISAC
    every time.
    """
    organisation, created = await _isac_organisation(session, slug=org_slug, name=org_name)
    existing_admins = await _active_system_admins(session, organisation)
    if existing_admins and not additional:
        msg = (
            f"this instance already has {existing_admins} active system admin(s); "
            "pass --additional to create another operator (it is recorded and alerted)"
        )
        raise BootstrapError(msg)

    taken = (
        await session.execute(select(Operator.id).where(Operator.email == email.strip().lower()))
    ).scalar_one_or_none()
    if taken is not None:
        msg = "an operator with that email already exists"
        raise BootstrapError(msg)

    if certificate_pem is not None:
        await _register_new_certificate(session, settings, organisation, certificate_pem)

    operator, seed = await create_operator(
        session,
        None,
        organisation=organisation,
        email=email,
        display_name=display_name,
        password=password,
        roles=roles,
        secret_box=SecretBox.from_settings(settings),
    )
    await record(
        session,
        action=AuditAction.OPERATOR_BOOTSTRAPPED,
        # "system" is what the constraint allows; the actor id says which.
        actor_type="system",
        actor_id="bootstrap_operator",
        org_id=organisation.id,
        resource_type="operator",
        resource_id=str(operator.id),
        details={
            "roles": [role.value for role in roles],
            "additional": additional,
            "existing_system_admins": existing_admins,
            "created_organisation": created,
        },
    )
    await session.commit()
    return BootstrapResult(
        organisation_id=organisation.id,
        operator_id=operator.id,
        totp_seed=seed,
        created_organisation=created,
    )


def _read_password() -> str:  # pragma: no cover - interactive
    first = getpass.getpass("Password for the new operator: ")
    second = getpass.getpass("Again: ")
    if first != second:
        msg = "the two passwords did not match"
        raise BootstrapError(msg)
    return first


def _parse_args() -> argparse.Namespace:  # pragma: no cover - operational helper
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--org-slug", required=True)
    parser.add_argument("--org-name", help="create the ISAC organisation with this name")
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", required=True, help="the operator's display name")
    parser.add_argument(
        "--role",
        action="append",
        required=True,
        choices=[role.value for role in OperatorRole],
        help="repeatable",
    )
    parser.add_argument("--certificate", help="PEM client certificate to register for the ISAC")
    parser.add_argument(
        "--additional",
        action="store_true",
        help="create a further operator although system admins exist (recorded and alerted)",
    )
    return parser.parse_args()


def _main() -> int:  # pragma: no cover - operational helper
    args = _parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = get_settings()
    certificate_pem = None
    if args.certificate:
        certificate_pem = Path(args.certificate).read_text(encoding="utf-8")

    async def _run() -> BootstrapResult:
        async with session_scope() as session:
            return await bootstrap(
                session,
                settings,
                org_slug=args.org_slug,
                org_name=args.org_name,
                email=args.email,
                display_name=args.name,
                password=_read_password(),
                roles=[OperatorRole(role) for role in args.role],
                certificate_pem=certificate_pem,
                additional=args.additional,
            )

    try:
        result = asyncio.run(_run())
    except (BootstrapError, ValueError) as exc:
        logger.error("refused: %s", exc)  # noqa: TRY400 - an expected refusal; a traceback would bury the reason
        return 1

    # Printed once, to the terminal that ran this, and never stored in clear.
    print(  # noqa: T201 - the one place this value is shown
        totp_provisioning_uri(
            result.totp_seed, operator_email=args.email, instance_name=settings.instance_name
        )
    )
    logger.info("operator %s created", result.operator_id)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())
