"""Text documents in the portal (Phase I, slice I2; SF-99).

The same doors as ``api.documents``, for a signed-in person: every decision is
``services.documents``'s, from the person's own grant. An unknown document and
one the person may not see are the same 404. Sharing names someone in the
person's own firm from a list, and another firm only by the sharing code that
firm handed over -- the portal never lists other firms, since that would show
the circle membership graph.

A sharing code is shown once, on the page that rotated it, and never put in a
notice cookie: the notice is signed, not encrypted.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Form, HTTPException, Request, Response, status

from aivs_schemas.enums import (
    DOCUMENT_TRANSITIONS,
    TLP,
    DocumentPermission,
    DocumentState,
    GrantPrincipal,
)
from aivs_server.auth.context import AuthContext
from aivs_server.auth.deps import SessionDep, SettingsDep
from aivs_server.auth.policy import can_write_documents, is_org_admin, require
from aivs_server.auth.secretbox import SecretBox
from aivs_server.config import RecipientLookup
from aivs_server.db.clock import database_now
from aivs_server.portal.shared import (
    base_context,
    current_session,
    operator_name,
    redirect_within_portal,
    render,
    require_csrf,
    set_notice,
    stamp,
)
from aivs_server.services import documents
from aivs_server.services.documents import (
    DocumentNotFoundError,
    DocumentRefusedError,
    DocumentStaleError,
)

__all__ = ["router"]

router = APIRouter(prefix="/portal", include_in_schema=False)

_NOT_FOUND = HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
_STALE = "Someone saved a newer version while you were editing. Your text was not saved."


def _page(document_id: uuid.UUID) -> str:
    return f"/portal/documents/{document_id}"


async def _list_context(
    request: Request, settings: SettingsDep, session: SessionDep, ctx: AuthContext
) -> dict[str, Any]:
    now = await database_now(session)
    context = base_context(request, settings, ctx, await operator_name(session, ctx), "documents")
    context.update(
        {
            "documents": await documents.list_documents(session, ctx, now=now),
            "can_write": can_write_documents(ctx),
            "is_org_admin": is_org_admin(ctx),
            "code_rotated_at": (
                stamp(await documents.sharing_code_rotated_at(session, ctx))
                if is_org_admin(ctx)
                else None
            ),
            "tlps": [tlp.value for tlp in TLP],
            "stamp": stamp,
        }
    )
    return context


@router.get("/documents")
async def documents_page(request: Request, settings: SettingsDep, session: SessionDep) -> Response:
    """Your own drafts, and the documents shared with your firm or with you."""
    ctx, _csrf = await current_session(request, settings)
    return render(request, "documents.html", await _list_context(request, settings, session, ctx))


@router.post("/documents")
async def create_document(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
    title: Annotated[str, Form(max_length=documents.MAX_TITLE_CHARS)],
    tlp: Annotated[TLP, Form()],
    body: Annotated[str, Form(max_length=documents.MAX_BODY_CHARS)],
    abstract: Annotated[str, Form(max_length=2000)] = "",
) -> Response:
    ctx, csrf_hash = await current_session(request, settings)
    require_csrf(csrf_token, csrf_hash)
    require(can_write_documents(ctx), "documents_are_written_by_a_person")
    try:
        document_id = await documents.create_document(
            session,
            ctx,
            box=SecretBox.from_settings(settings),
            title=title,
            abstract=abstract or None,
            tlp=tlp,
            body=body,
            now=await database_now(session),
        )
        await session.commit()
    except DocumentRefusedError as exc:
        response = redirect_within_portal("/portal/documents")
        set_notice(response, settings, "error", f"Not created: {exc}")
        return response
    response = redirect_within_portal(_page(document_id))
    set_notice(
        response, settings, "success", "Draft created. Only you can see it until you share it."
    )
    return response


@router.post("/documents/sharing-code")
async def rotate_sharing_code(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
) -> Response:
    """A new code, shown on this page once; the old one stops working."""
    ctx, csrf_hash = await current_session(request, settings)
    require_csrf(csrf_token, csrf_hash)
    code = await documents.rotate_sharing_code(session, ctx, now=await database_now(session))
    await session.commit()
    context = await _list_context(request, settings, session, ctx)
    context["new_code"] = code
    return render(request, "documents.html", context)


@router.get("/documents/{document_id}")
async def document_page(
    document_id: uuid.UUID,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    version: int | None = None,
) -> Response:
    """The document, its comments, and -- for the owner's editors -- who it is shared with."""
    ctx, _csrf = await current_session(request, settings)
    now = await database_now(session)
    try:
        view = await documents.read_document(
            session,
            ctx,
            document_id,
            box=SecretBox.from_settings(settings),
            now=now,
            version_number=version,
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    owner_editor = view.permission is DocumentPermission.EDIT and ctx.org_id == view.owner_org_id
    context = base_context(request, settings, ctx, await operator_name(session, ctx), "documents")
    context.update(
        {
            "document": view,
            "can_edit": view.permission is DocumentPermission.EDIT and can_write_documents(ctx),
            "can_comment": can_write_documents(ctx),
            "owner_editor": owner_editor and can_write_documents(ctx),
            "grants": (
                await documents.list_grants(session, ctx, document_id, now=now)
                if owner_editor and can_write_documents(ctx)
                else []
            ),
            "principals": (
                await documents.nameable_principals(
                    session, ctx, lookup=settings.document_recipient_lookup
                )
                if owner_editor
                else []
            ),
            "picker": settings.document_recipient_lookup is RecipientLookup.PICKER,
            "next_states": _next_states(view.state),
            "stamp": stamp,
        }
    )
    return render(request, "document.html", context)


def _next_states(state: DocumentState) -> list[str]:
    """The moves a person can make here; finishing publishes, built in I3."""
    offered = DOCUMENT_TRANSITIONS[state] - {DocumentState.FINISHED}
    return sorted(target.value for target in offered)


async def _write(request: Request, settings: SettingsDep, csrf_token: str) -> AuthContext:
    ctx, csrf_hash = await current_session(request, settings)
    require_csrf(csrf_token, csrf_hash)
    require(can_write_documents(ctx), "documents_are_written_by_a_person")
    return ctx


@router.post("/documents/{document_id}/body")
async def save_version(
    document_id: uuid.UUID,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
    body: Annotated[str, Form(max_length=documents.MAX_BODY_CHARS)],
    expected_version: Annotated[int, Form(ge=1)],
) -> Response:
    ctx = await _write(request, settings, csrf_token)
    response = redirect_within_portal(_page(document_id))
    try:
        number = await documents.save_version(
            session,
            ctx,
            document_id,
            box=SecretBox.from_settings(settings),
            body=body,
            expected_version=expected_version,
            now=await database_now(session),
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    except DocumentStaleError:
        set_notice(response, settings, "error", _STALE)
        return response
    except DocumentRefusedError as exc:
        set_notice(response, settings, "error", f"Not saved: {exc}")
        return response
    set_notice(response, settings, "success", f"Saved as version {number}.")
    return response


@router.post("/documents/{document_id}/comments")
async def add_comment(
    document_id: uuid.UUID,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
    version_number: Annotated[int, Form(ge=1)],
    body: Annotated[str, Form(max_length=documents.MAX_COMMENT_CHARS)],
) -> Response:
    ctx = await _write(request, settings, csrf_token)
    response = redirect_within_portal(_page(document_id))
    try:
        await documents.add_comment(
            session,
            ctx,
            document_id,
            box=SecretBox.from_settings(settings),
            version_number=version_number,
            body=body,
            now=await database_now(session),
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    except DocumentRefusedError as exc:
        set_notice(response, settings, "error", f"Not posted: {exc}")
        return response
    set_notice(response, settings, "success", "Comment posted.")
    return response


def _principal(target: str) -> tuple[GrantPrincipal, uuid.UUID] | None:
    """``organization:<id>`` or ``operator:<id>`` from the own-firm list, else ``None``."""
    kind, _sep, raw = target.partition(":")
    try:
        return GrantPrincipal(kind), uuid.UUID(raw)
    except ValueError:
        return None


@router.post("/documents/{document_id}/grants")
async def grant_access(
    document_id: uuid.UUID,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
    permission: Annotated[DocumentPermission, Form()],
    target: Annotated[str, Form(max_length=100)] = "",
    sharing_code: Annotated[str, Form(max_length=100)] = "",
    expires_on: Annotated[dt.date | None, Form()] = None,
) -> Response:
    """Share with someone picked from the list, or another firm by its code."""
    ctx = await _write(request, settings, csrf_token)
    response = redirect_within_portal(_page(document_id))
    named = _principal(target) if target else None
    if (named is None) == (not sharing_code):
        set_notice(
            response,
            settings,
            "error",
            "Pick someone from the list, or enter another firm's sharing code.",
        )
        return response
    expires_at = dt.datetime.combine(expires_on, dt.time.min, tzinfo=dt.UTC) if expires_on else None
    try:
        await documents.grant_access(
            session,
            ctx,
            document_id,
            principal=named[0] if named else GrantPrincipal.ORGANIZATION,
            principal_id=named[1] if named else None,
            sharing_code=sharing_code or None,
            lookup=settings.document_recipient_lookup,
            permission=permission,
            expires_at=expires_at,
            now=await database_now(session),
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    except DocumentRefusedError as exc:
        set_notice(response, settings, "error", f"Not shared: {exc}")
        return response
    set_notice(response, settings, "success", "Shared.")
    return response


@router.post("/documents/{document_id}/grants/{grant_id}/revoke")
async def revoke_grant(
    document_id: uuid.UUID,
    grant_id: uuid.UUID,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
) -> Response:
    ctx = await _write(request, settings, csrf_token)
    try:
        await documents.revoke_grant(
            session, ctx, document_id, grant_id, now=await database_now(session)
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    response = redirect_within_portal(_page(document_id))
    set_notice(response, settings, "success", "No longer shared.")
    return response


@router.post("/documents/{document_id}/transition")
async def transition_document(
    document_id: uuid.UUID,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
    to: Annotated[DocumentState, Form()],
) -> Response:
    ctx = await _write(request, settings, csrf_token)
    response = redirect_within_portal(_page(document_id))
    try:
        await documents.transition_document(
            session, ctx, document_id, to=to, now=await database_now(session)
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    except DocumentRefusedError as exc:
        set_notice(response, settings, "error", f"Not changed: {exc}")
        return response
    set_notice(response, settings, "success", f"The document is now {to.value.replace('_', ' ')}.")
    return response
