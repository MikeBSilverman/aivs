"""Text documents over the API (Phase I, slice I2; SF-99).

Each route is a thin door onto ``services.documents``, which decides from the
caller's own grant and answers anything it may not know of with one not-found.
Writing anything -- a document, a version, a comment, a grant -- needs a
signed-in person (``policy.can_write_documents``), checked before the
document is looked up: a certificate alone is refused with the same 403
whichever document it names.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field

from aivs_schemas.enums import TLP, DocumentPermission, DocumentState, GrantPrincipal
from aivs_server.auth.context import AuthContext
from aivs_server.auth.deps import AuthenticatedContext, SessionDep, SettingsDep
from aivs_server.auth.policy import can_write_documents, require
from aivs_server.auth.secretbox import SecretBox
from aivs_server.db.clock import database_now
from aivs_server.services import documents
from aivs_server.services.documents import (
    DocumentNotFoundError,
    DocumentRefusedError,
    DocumentStaleError,
)

__all__ = ["router"]

router = APIRouter(prefix="/api/v1/documents", tags=["documents"])

_NOT_FOUND = HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
_STALE = "the document has changed since you read it; read it again and reapply your change"


class _In(BaseModel):
    # Not stripped: a body's whitespace is the author's.
    model_config = ConfigDict(extra="forbid")


class DocumentIn(_In):
    title: Annotated[str, Field(min_length=1, max_length=documents.MAX_TITLE_CHARS)]
    abstract: Annotated[str, Field(max_length=2000)] | None = None
    tlp: TLP
    body: Annotated[str, Field(min_length=1, max_length=documents.MAX_BODY_CHARS)]


class VersionIn(_In):
    body: Annotated[str, Field(min_length=1, max_length=documents.MAX_BODY_CHARS)]
    #: The ``version`` the caller read; a save over a newer one is a 409.
    expected_version: Annotated[int, Field(ge=1)]


class CommentIn(_In):
    version_number: Annotated[int, Field(ge=1)]
    body: Annotated[str, Field(min_length=1, max_length=documents.MAX_COMMENT_CHARS)]


class GrantIn(_In):
    """Within the owner's firm a principal is named by id; another firm only by
    the sharing code it handed over (its consent to be found)."""

    principal_type: GrantPrincipal
    principal_id: uuid.UUID | None = None
    sharing_code: Annotated[str, Field(min_length=1, max_length=100)] | None = None
    permission: DocumentPermission
    expires_at: dt.datetime | None = None


class TransitionIn(_In):
    to: DocumentState


class CreatedOut(BaseModel):
    id: uuid.UUID


class VersionOut(BaseModel):
    number: int


class CommentOut(BaseModel):
    id: uuid.UUID
    version_number: int
    author_operator_id: uuid.UUID
    body: str
    created_at: dt.datetime


class DocumentOut(BaseModel):
    id: uuid.UUID
    owner_org_id: uuid.UUID
    owner_name: str
    title: str
    abstract: str | None
    tlp: TLP
    state: DocumentState
    version: int
    version_number: int
    content_sha256: str
    body: str
    permission: DocumentPermission
    comments: list[CommentOut]


class DocumentSummaryOut(BaseModel):
    id: uuid.UUID
    title: str
    state: DocumentState
    tlp: TLP
    owner_name: str
    permission: DocumentPermission
    updated_at: dt.datetime


class GrantOut(BaseModel):
    id: uuid.UUID
    principal_type: GrantPrincipal
    principal_id: uuid.UUID
    principal_name: str
    permission: DocumentPermission
    expires_at: dt.datetime | None
    revoked_at: dt.datetime | None


def _person(ctx: AuthContext) -> None:
    require(can_write_documents(ctx), "documents_are_written_by_a_person")


def _refused(exc: Exception) -> HTTPException:
    """A refusal to a caller who may see the document: its reason names nothing new."""
    if isinstance(exc, DocumentStaleError):
        return HTTPException(status.HTTP_409_CONFLICT, detail=_STALE)
    return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))


class SharingCodeOut(BaseModel):
    #: Shown this once: only its hash is kept.
    code: str


class SharingCodeStatusOut(BaseModel):
    rotated_at: dt.datetime | None


@router.post("/sharing-code", status_code=status.HTTP_201_CREATED, response_model=SharingCodeOut)
async def rotate_sharing_code(ctx: AuthenticatedContext, session: SessionDep) -> SharingCodeOut:
    """A new code for other firms to share documents with yours; the old one stops working.

    Your organisation's org admins only. The code is shown this once.
    """
    code = await documents.rotate_sharing_code(session, ctx, now=await database_now(session))
    await session.commit()
    return SharingCodeOut(code=code)


@router.get("/sharing-code", response_model=SharingCodeStatusOut)
async def sharing_code_status(
    ctx: AuthenticatedContext, session: SessionDep
) -> SharingCodeStatusOut:
    """When your firm's code was last rotated; never the code."""
    return SharingCodeStatusOut(rotated_at=await documents.sharing_code_rotated_at(session, ctx))


@router.get("", response_model=list[DocumentSummaryOut])
async def list_documents(
    ctx: AuthenticatedContext, session: SessionDep
) -> list[DocumentSummaryOut]:
    """The caller's own drafts and the documents shared with it."""
    found = await documents.list_documents(session, ctx, now=await database_now(session))
    return [DocumentSummaryOut.model_validate(item, from_attributes=True) for item in found]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=CreatedOut)
async def create_document(
    payload: DocumentIn, ctx: AuthenticatedContext, session: SessionDep, settings: SettingsDep
) -> CreatedOut:
    """A new draft, the author's alone until it is shared."""
    _person(ctx)
    try:
        document_id = await documents.create_document(
            session,
            ctx,
            box=SecretBox.from_settings(settings),
            title=payload.title,
            abstract=payload.abstract,
            tlp=payload.tlp,
            body=payload.body,
            now=await database_now(session),
        )
        await session.commit()
    except DocumentRefusedError as exc:
        raise _refused(exc) from exc
    return CreatedOut(id=document_id)


@router.get("/{document_id}", response_model=DocumentOut)
async def read_document(
    document_id: uuid.UUID,
    ctx: AuthenticatedContext,
    session: SessionDep,
    settings: SettingsDep,
    version: Annotated[int | None, Query(ge=1)] = None,
) -> DocumentOut:
    """The latest version, or the one asked for; a receipt is written for the read."""
    try:
        view = await documents.read_document(
            session,
            ctx,
            document_id,
            box=SecretBox.from_settings(settings),
            now=await database_now(session),
            version_number=version,
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    return DocumentOut.model_validate(view, from_attributes=True)


@router.put("/{document_id}/body", response_model=VersionOut)
async def save_version(
    document_id: uuid.UUID,
    payload: VersionIn,
    ctx: AuthenticatedContext,
    session: SessionDep,
    settings: SettingsDep,
) -> VersionOut:
    """A new version, from an editor who read the latest."""
    _person(ctx)
    try:
        number = await documents.save_version(
            session,
            ctx,
            document_id,
            box=SecretBox.from_settings(settings),
            body=payload.body,
            expected_version=payload.expected_version,
            now=await database_now(session),
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    except (DocumentRefusedError, DocumentStaleError) as exc:
        raise _refused(exc) from exc
    return VersionOut(number=number)


@router.post(
    "/{document_id}/comments", status_code=status.HTTP_201_CREATED, response_model=CreatedOut
)
async def add_comment(
    document_id: uuid.UUID,
    payload: CommentIn,
    ctx: AuthenticatedContext,
    session: SessionDep,
    settings: SettingsDep,
) -> CreatedOut:
    """A comment from anyone the document is shared with."""
    _person(ctx)
    try:
        comment_id = await documents.add_comment(
            session,
            ctx,
            document_id,
            box=SecretBox.from_settings(settings),
            version_number=payload.version_number,
            body=payload.body,
            now=await database_now(session),
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    except DocumentRefusedError as exc:
        raise _refused(exc) from exc
    return CreatedOut(id=comment_id)


@router.get("/{document_id}/grants", response_model=list[GrantOut])
async def list_grants(
    document_id: uuid.UUID, ctx: AuthenticatedContext, session: SessionDep
) -> list[GrantOut]:
    """Who the document is shared with, to the owner firm's editors."""
    _person(ctx)
    try:
        grants = await documents.list_grants(
            session, ctx, document_id, now=await database_now(session)
        )
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    return [GrantOut.model_validate(grant, from_attributes=True) for grant in grants]


@router.post(
    "/{document_id}/grants", status_code=status.HTTP_201_CREATED, response_model=CreatedOut
)
async def grant_access(
    document_id: uuid.UUID, payload: GrantIn, ctx: AuthenticatedContext, session: SessionDep
) -> CreatedOut:
    """Share the document with one principal the owner may name (SF-2)."""
    _person(ctx)
    try:
        grant_id = await documents.grant_access(
            session,
            ctx,
            document_id,
            principal=payload.principal_type,
            principal_id=payload.principal_id,
            sharing_code=payload.sharing_code,
            permission=payload.permission,
            expires_at=payload.expires_at,
            now=await database_now(session),
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    except DocumentRefusedError as exc:
        raise _refused(exc) from exc
    return CreatedOut(id=grant_id)


@router.delete("/{document_id}/grants/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_grant(
    document_id: uuid.UUID, grant_id: uuid.UUID, ctx: AuthenticatedContext, session: SessionDep
) -> Response:
    """End one grant."""
    _person(ctx)
    try:
        await documents.revoke_grant(
            session, ctx, document_id, grant_id, now=await database_now(session)
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{document_id}/transition", status_code=status.HTTP_204_NO_CONTENT)
async def transition_document(
    document_id: uuid.UUID, payload: TransitionIn, ctx: AuthenticatedContext, session: SessionDep
) -> Response:
    """Move the document along its machine: to review, back to draft, or archived."""
    _person(ctx)
    try:
        await documents.transition_document(
            session, ctx, document_id, to=payload.to, now=await database_now(session)
        )
        await session.commit()
    except DocumentNotFoundError:
        raise _NOT_FOUND from None
    except DocumentRefusedError as exc:
        raise _refused(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
