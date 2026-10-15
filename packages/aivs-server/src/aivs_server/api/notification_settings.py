"""An organisation's own notification settings: how often it is told, and where.

Changed by the same people who may register its webhooks (``can_register_webhook``):
the cadence decides when its collectors and people hear about content, which
is the same decision as where they hear it.
"""

from __future__ import annotations

import re
from typing import Annotated, Final

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from aivs_schemas.enums import NotificationCadence
from aivs_server.auth.deps import AuthenticatedContext, SessionDep, SettingsDep
from aivs_server.auth.policy import can_register_webhook, require
from aivs_server.db.models import Organization
from aivs_server.services.member_staff_writes import set_notification_settings

__all__ = ["router"]

router = APIRouter(prefix="/api/v1", tags=["notifications"])

#: A mailbox, plainly: no spaces, no line breaks, one @. Deliberately narrower
#: than RFC 5322; a SOC queue address fits it.
_MAILBOX: Final[re.Pattern[str]] = re.compile(
    r"^[^\s@]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$"
)


class NotificationSettingsOut(BaseModel):
    cadence: NotificationCadence
    digest_email: str | None


class NotificationSettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cadence: NotificationCadence
    digest_email: Annotated[str | None, Field(max_length=320)] = None


@router.get("/notification-settings", response_model=NotificationSettingsOut)
async def read_settings(ctx: AuthenticatedContext, session: SessionDep) -> NotificationSettingsOut:
    """The caller's own organisation's settings. Never another's."""
    org = await session.get(Organization, ctx.org_id)
    if org is None:  # pragma: no cover - an authenticated context names a real org
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    return NotificationSettingsOut(cadence=org.notification_cadence, digest_email=org.digest_email)


@router.put("/notification-settings", response_model=NotificationSettingsOut)
async def change_settings(
    payload: NotificationSettingsIn,
    ctx: AuthenticatedContext,
    session: SessionDep,
    settings: SettingsDep,
) -> NotificationSettingsOut:
    """Set the cadence, and the digest mailbox if the organisation wants one.

    A mailbox needs a digest cadence: email is a digest channel, and one email
    per submission is the flood the cadence exists to stop.
    """
    require(
        can_register_webhook(ctx, automation_webhooks_enabled=settings.automation_webhooks_enabled),
        "notification_settings",
    )
    if payload.digest_email is not None:
        if _MAILBOX.match(payload.digest_email) is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail="That is not a mailbox address."
            )
        if payload.cadence is NotificationCadence.IMMEDIATE:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail="A digest mailbox needs an hourly or daily cadence.",
            )
    # On the staff login for a member: its login may not change any
    # organisation's settings, or SQL on it could redirect a peer's digest.
    org = await set_notification_settings(
        session, ctx, cadence=payload.cadence, digest_email=payload.digest_email
    )
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
    await session.commit()
    return NotificationSettingsOut(cadence=org.notification_cadence, digest_email=org.digest_email)
