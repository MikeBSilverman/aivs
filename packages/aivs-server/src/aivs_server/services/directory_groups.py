"""Which ISAC directory group's members are an organisation's people (SSO, SF-65).

A member sign-in names its directory groups, and ``services.sso`` matches them
against ``organizations.directory_object_id``. Config and the federation design
said membership staff set that column at enrolment, but nothing in the
application wrote it: SSO worked only for an operator willing to edit the
database, which is the kind of change no audit row records. This is the
writer, for membership staff, audited, with the previous value in the row.

Two organisations cannot share a group (the column is unique), because a
person in it would then map to two members and be refused. The hosting ISAC's
own organisation may be given one: ``services.sso`` refuses a member-tenant
sign-in naming it, which is how a staff group showing up in the member tenant
is caught rather than silently ignored.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import OrgStatus
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import Organization

__all__ = ["DirectoryGroupError", "set_directory_group"]


class DirectoryGroupError(ValueError):
    """A mapping that cannot be set as asked; the message says why."""


async def set_directory_group(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    organisation: Organization,
    directory_object_id: str | None,
) -> None:
    """Map ``organisation`` to a directory group, or unmap it. Locked by the caller.

    Does not commit. A group another organisation holds fails at flush on the
    unique index; the caller reports that as a conflict.
    """
    if organisation.status is OrgStatus.OFFBOARDED:
        reason = f"{organisation.slug} has been offboarded"
        raise DirectoryGroupError(reason)
    previous = organisation.directory_object_id
    organisation.directory_object_id = directory_object_id
    await session.flush()
    await record(
        session,
        action=AuditAction.ORG_DIRECTORY_GROUP_SET,
        ctx=ctx,
        resource_type="organization",
        resource_id=organisation.slug,
        details={"directory_object_id": directory_object_id, "previous": previous},
    )
