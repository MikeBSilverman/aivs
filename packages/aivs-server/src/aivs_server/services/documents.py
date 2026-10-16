"""Text documents and their document-only grants (Phase I).

A document is a directed share. Its owner organisation names who may read or
edit it, one organisation or one person at a time, and nobody else learns it
exists: an absent document, a document the caller holds no grant on, and a
principal the owner may not name all answer one way (:class:`DocumentNotFoundError`).

**One door, on the staff login.** The member login is granted nothing on any
document table (``db.grants.MEMBER_GRANTS``), so SQL on the member path cannot
list another firm's documents, owners or titles. Every function here opens its
own staff session for a member caller and decides from the caller's grant, the
3e/3g shape; ``tests/unit/test_staff_session_reach.py`` admits this module.

**Who may read** (:func:`_permission`), judged at every read with ``now``
injected, never by a sweeper:

- the caller's organisation is active, and the caller may read the document's
  TLP at all (an SSO or email session holds to AMBER+STRICT, as for content);
- the person who created it edits it;
- anyone else, the owner organisation's own people included, holds an open
  grant: not revoked, not expired, naming the caller's organisation, or the
  caller as a person who is still active in it -- a grant to a person ends
  when the person leaves, whatever its organisation's grant still allows.

So a draft is its author's until shared, inside its own firm as outside it.
Granting, revoking and archiving are for the owner organisation's editors:
a grantee elsewhere cannot pass the document on.

**Who may be named** (:func:`_may_name`, SF-2): the owner's own organisation,
its own people, and organisations of an allowed type that share an *open*
membership interval with it in an active circle. Anything else -- including a
type added later, a service provider among them, until it is allowed on
purpose -- is refused as the constant not-found.

**Keys.** Each document has its own key (DEK), sealed under the instance key
with the document's id. Every version and comment is sealed under the DEK and
bound to its row (``<document>:<version>``, ``<document>:<comment>``), so a
ciphertext cannot be moved between rows. A DEK lives as long as its document;
one that no longer opens means the whole history is lost, and is reported, not
treated as absent. Bodies are plain text: no stored markup.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import os
import uuid
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Final

from sqlalchemy import ColumnElement, and_, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from aivs_schemas.enums import (
    DOCUMENT_TRANSITIONS,
    OPEN_DOCUMENT_STATES,
    TLP,
    DocumentPermission,
    DocumentState,
    GrantPrincipal,
    OrgStatus,
    OrgType,
)
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import is_active, uses_staff_database, within_tlp_ceiling
from aivs_server.auth.secretbox import SecretBox, SecretPurpose
from aivs_server.db.engine import get_sessionmaker
from aivs_server.db.models import (
    Circle,
    CircleMembership,
    Document,
    DocumentComment,
    DocumentGrant,
    DocumentRead,
    DocumentVersion,
    Operator,
    Organization,
)

__all__ = [
    "DOCUMENT_GRANTEE_ORG_TYPES",
    "DocumentNotFoundError",
    "DocumentRefusedError",
    "DocumentStaleError",
    "DocumentUnreadableError",
    "DocumentView",
    "add_comment",
    "close_for_offboarded",
    "create_document",
    "grant_access",
    "read_document",
    "revoke_grant",
    "save_version",
    "transition_document",
]

MAX_BODY_CHARS: Final[int] = 200_000
MAX_TITLE_CHARS: Final[int] = 300
MAX_COMMENT_CHARS: Final[int] = 4_000
#: Comments one person may write in an hour, as a socket message is bounded.
COMMENTS_PER_HOUR: Final[int] = 60
_HOUR: Final[dt.timedelta] = dt.timedelta(hours=1)
_DEK_BYTES: Final[int] = 32

#: Organisation types a document may be shared with, besides the owner's own.
#: An allow-list: a type added later (a service provider, when K adds one) is
#: refused until it is added here deliberately, so documents never become the
#: way round a delegation programme.
DOCUMENT_GRANTEE_ORG_TYPES: Final[frozenset[OrgType]] = frozenset(
    {
        OrgType.GSIB,
        OrgType.SECTION9,
        OrgType.CRIT_INFRA,
        OrgType.VENDOR,
        OrgType.RESEARCHER,
        OrgType.GOVERNMENT,
    }
)

_RANK: Final[dict[DocumentPermission, int]] = {
    DocumentPermission.VIEW: 1,
    DocumentPermission.EDIT: 2,
}


class DocumentNotFoundError(LookupError):
    """No such document, or none the caller may know of: one answer for all."""


class DocumentStaleError(Exception):
    """Saved over a newer version than the one the caller read."""


class DocumentRefusedError(Exception):
    """A caller who may see the document asked for something it may not do.

    Only raised once the caller is known to hold a grant, so its message names
    nothing the caller could not already see.
    """


class DocumentUnreadableError(RuntimeError):
    """The document's key no longer opens: its whole history is lost."""


@dataclass(frozen=True)
class CommentView:
    id: uuid.UUID
    version_number: int
    author_operator_id: uuid.UUID
    body: str
    created_at: dt.datetime


@dataclass(frozen=True)
class DocumentView:
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
    comments: tuple[CommentView, ...]


# ---------------------------------------------------------------------------
# The session
# ---------------------------------------------------------------------------
@asynccontextmanager
async def _staff(session: AsyncSession, ctx: AuthContext) -> AsyncIterator[AsyncSession]:
    """The caller's own session when it is staff, else a staff session of its own.

    A staff session is committed on a clean exit and rolled back on an error;
    the caller's own is left to the caller.
    """
    if uses_staff_database(ctx):
        yield session
        return
    async with get_sessionmaker()() as staff:
        try:
            yield staff
            await staff.commit()
        except BaseException:
            await staff.rollback()
            raise


# ---------------------------------------------------------------------------
# Who may read, and who may be named
# ---------------------------------------------------------------------------
def _open_grant(ctx: AuthContext, now: dt.datetime) -> ColumnElement[bool]:
    """A grant naming the caller that has not been revoked or expired."""
    person = aliased(Operator)
    to_person = and_(
        DocumentGrant.principal_type == GrantPrincipal.OPERATOR,
        DocumentGrant.principal_operator_id == ctx.operator_id,
        exists().where(
            person.id == DocumentGrant.principal_operator_id,
            person.is_active.is_(True),
            person.org_id == ctx.org_id,
        ),
    )
    to_organisation = and_(
        DocumentGrant.principal_type == GrantPrincipal.ORGANIZATION,
        DocumentGrant.principal_org_id == ctx.org_id,
    )
    return and_(
        DocumentGrant.revoked_at.is_(None),
        or_(DocumentGrant.expires_at.is_(None), DocumentGrant.expires_at > now),
        or_(to_organisation, to_person) if ctx.operator_id is not None else to_organisation,
    )


async def _permission(
    db: AsyncSession, ctx: AuthContext, document: Document, *, now: dt.datetime
) -> DocumentPermission | None:
    """What ``ctx`` may do with ``document`` now, or ``None``: then it does not exist for it."""
    if not is_active(ctx) or not within_tlp_ceiling(ctx, document.tlp):
        return None
    if ctx.org_id == document.owner_org_id and ctx.operator_id == document.author_operator_id:
        return DocumentPermission.EDIT
    held = (
        await db.scalars(
            select(DocumentGrant.permission).where(
                DocumentGrant.document_id == document.id, _open_grant(ctx, now)
            )
        )
    ).all()
    return max(held, key=_RANK.__getitem__, default=None)


async def _may_name(
    db: AsyncSession, owner_org_id: uuid.UUID, principal: GrantPrincipal, principal_id: uuid.UUID
) -> bool:
    """Whether the owner may grant to this principal (SF-2), as an allow-list."""
    if principal is GrantPrincipal.OPERATOR:
        person = await db.get(Operator, principal_id)
        return person is not None and person.org_id == owner_org_id and person.is_active
    if principal_id == owner_org_id:
        return True
    organisation = await db.get(Organization, principal_id)
    if organisation is None or organisation.status is not OrgStatus.ACTIVE:
        return False
    if organisation.org_type not in DOCUMENT_GRANTEE_ORG_TYPES:
        return False
    return await _share_an_open_circle(db, owner_org_id, principal_id)


async def _share_an_open_circle(db: AsyncSession, first: uuid.UUID, second: uuid.UUID) -> bool:
    """Both organisations hold an open interval in one active circle."""
    theirs = aliased(CircleMembership)
    shared = await db.scalar(
        select(CircleMembership.id)
        .join(theirs, theirs.circle_id == CircleMembership.circle_id)
        .join(Circle, Circle.id == CircleMembership.circle_id)
        .where(
            CircleMembership.org_id == first,
            CircleMembership.left_at.is_(None),
            theirs.org_id == second,
            theirs.left_at.is_(None),
            Circle.is_active.is_(True),
        )
        .limit(1)
    )
    return shared is not None


async def _load(db: AsyncSession, document_id: uuid.UUID, *, for_update: bool) -> Document | None:
    query = select(Document).where(Document.id == document_id)
    if for_update:
        query = query.with_for_update().execution_options(populate_existing=True)
    document: Document | None = await db.scalar(query)
    return document


async def _visible(
    db: AsyncSession,
    ctx: AuthContext,
    document_id: uuid.UUID,
    *,
    at_least: DocumentPermission,
    now: dt.datetime,
    for_update: bool,
) -> tuple[Document, DocumentPermission]:
    """The document and the caller's permission on it, or the one not-found."""
    document = await _load(db, document_id, for_update=for_update)
    if document is None:
        raise DocumentNotFoundError
    permission = await _permission(db, ctx, document, now=now)
    if permission is None or _RANK[permission] < _RANK[at_least]:
        raise DocumentNotFoundError
    return document, permission


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------
def _new_key(box: SecretBox, document_id: uuid.UUID) -> tuple[bytes, bytes]:
    """A fresh DEK and its sealed form, bound to the document's id."""
    dek = os.urandom(_DEK_BYTES)
    sealed = box.seal(
        base64.b64encode(dek).decode("ascii"),
        purpose=SecretPurpose.DOCUMENT_KEY,
        subject=document_id,
    )
    return dek, sealed


def _content_box(box: SecretBox, document: Document) -> SecretBox:
    """The box keyed by the document's DEK; a DEK that does not open loses the history."""
    opened = box.unseal(
        document.dek_sealed, purpose=SecretPurpose.DOCUMENT_KEY, subject=document.id
    )
    if opened is None:
        msg = str(document.id)
        raise DocumentUnreadableError(msg)
    return SecretBox(active=base64.b64decode(opened), algorithm=box.algorithm)


def _sha256(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------
def _person(ctx: AuthContext) -> uuid.UUID:
    """Documents are written by people: a certificate alone reads, never writes."""
    if ctx.operator_id is None:
        msg = "documents are written by a signed-in person"
        raise DocumentRefusedError(msg)
    return ctx.operator_id


def _bounded(text: str, limit: int, what: str) -> str:
    if not text.strip():
        msg = f"the {what} is empty"
        raise DocumentRefusedError(msg)
    if len(text) > limit:
        msg = f"the {what} is longer than {limit} characters"
        raise DocumentRefusedError(msg)
    return text


async def create_document(
    session: AsyncSession,
    ctx: AuthContext,
    *,
    box: SecretBox,
    title: str,
    abstract: str | None,
    tlp: TLP,
    body: str,
    now: dt.datetime,
) -> uuid.UUID:
    """A new draft owned by the caller's organisation, with its first version."""
    author = _person(ctx)
    if not is_active(ctx) or not within_tlp_ceiling(ctx, tlp):
        msg = f"a {tlp.value} document cannot be written from this session"
        raise DocumentRefusedError(msg)
    document_id = uuid.uuid4()
    dek, sealed = _new_key(box, document_id)
    async with _staff(session, ctx) as db:
        db.add(
            Document(
                id=document_id,
                owner_org_id=ctx.org_id,
                author_operator_id=author,
                state=DocumentState.DRAFT,
                tlp=tlp,
                title=_bounded(title, MAX_TITLE_CHARS, "title"),
                abstract=abstract,
                dek_sealed=sealed,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        await db.flush()
        content = SecretBox(active=dek, algorithm=box.algorithm)
        _add_version(db, content, document_id, 1, _bounded(body, MAX_BODY_CHARS, "body"), author)
        await _audit(db, ctx, AuditAction.DOCUMENT_CREATED, document_id, {"tlp": tlp.value})
    return document_id


def _add_version(
    db: AsyncSession,
    content: SecretBox,
    document_id: uuid.UUID,
    number: int,
    body: str,
    author: uuid.UUID,
) -> None:
    db.add(
        DocumentVersion(
            document_id=document_id,
            number=number,
            content_sha256=_sha256(body),
            body_sealed=content.seal(
                body,
                purpose=SecretPurpose.DOCUMENT_VERSION,
                subject=f"{document_id}:{number}",
            ),
            author_operator_id=author,
        )
    )


async def save_version(
    session: AsyncSession,
    ctx: AuthContext,
    document_id: uuid.UUID,
    *,
    box: SecretBox,
    body: str,
    expected_version: int,
    now: dt.datetime,
) -> int:
    """A new version from an editor who read the latest one; else ``DocumentStaleError``."""
    author = _person(ctx)
    async with _staff(session, ctx) as db:
        document, _held = await _visible(
            db, ctx, document_id, at_least=DocumentPermission.EDIT, now=now, for_update=True
        )
        _require_open(document)
        if document.version != expected_version:
            raise DocumentStaleError
        number = await _latest_number(db, document_id) + 1
        _add_version(
            db,
            _content_box(box, document),
            document_id,
            number,
            _bounded(body, MAX_BODY_CHARS, "body"),
            author,
        )
        document.version += 1
        document.updated_at = now
        await _audit(db, ctx, AuditAction.DOCUMENT_VERSION_SAVED, document_id, {"number": number})
    return number


def _require_open(document: Document) -> None:
    if document.state not in OPEN_DOCUMENT_STATES:
        msg = f"the document is {document.state.value}; it no longer changes"
        raise DocumentRefusedError(msg)


async def _latest_number(db: AsyncSession, document_id: uuid.UUID) -> int:
    latest = await db.scalar(
        select(func.max(DocumentVersion.number)).where(DocumentVersion.document_id == document_id)
    )
    return int(latest or 0)


async def add_comment(
    session: AsyncSession,
    ctx: AuthContext,
    document_id: uuid.UUID,
    *,
    box: SecretBox,
    version_number: int,
    body: str,
    now: dt.datetime,
) -> uuid.UUID:
    """A comment from anyone who may read the document, bounded in size and rate."""
    author = _person(ctx)
    comment_id = uuid.uuid4()
    async with _staff(session, ctx) as db:
        document, _held = await _visible(
            db, ctx, document_id, at_least=DocumentPermission.VIEW, now=now, for_update=False
        )
        _require_open(document)
        if not 1 <= version_number <= await _latest_number(db, document_id):
            msg = "there is no such version to comment on"
            raise DocumentRefusedError(msg)
        if await _comments_this_hour(db, author, now=now) >= COMMENTS_PER_HOUR:
            msg = "too many comments in the last hour; try again later"
            raise DocumentRefusedError(msg)
        db.add(
            DocumentComment(
                id=comment_id,
                document_id=document_id,
                version_number=version_number,
                body_sealed=_content_box(box, document).seal(
                    _bounded(body, MAX_COMMENT_CHARS, "comment"),
                    purpose=SecretPurpose.DOCUMENT_COMMENT,
                    subject=f"{document_id}:{comment_id}",
                ),
                author_operator_id=author,
                created_at=now,
            )
        )
        await _audit(db, ctx, AuditAction.DOCUMENT_COMMENTED, document_id, {})
    return comment_id


async def _comments_this_hour(db: AsyncSession, author: uuid.UUID, *, now: dt.datetime) -> int:
    count = await db.scalar(
        select(func.count())
        .select_from(DocumentComment)
        .where(
            DocumentComment.author_operator_id == author, DocumentComment.created_at > now - _HOUR
        )
    )
    return int(count or 0)


async def grant_access(
    session: AsyncSession,
    ctx: AuthContext,
    document_id: uuid.UUID,
    *,
    principal: GrantPrincipal,
    principal_id: uuid.UUID,
    permission: DocumentPermission,
    expires_at: dt.datetime | None,
    now: dt.datetime,
) -> uuid.UUID:
    """Share the document with one principal the owner may name; else the one not-found.

    Only the owner organisation's editors grant: a grantee elsewhere cannot
    pass the document on, so no grant ever reaches past the owner's choice.
    """
    granter = _person(ctx)
    async with _staff(session, ctx) as db:
        document, _held = await _visible(
            db, ctx, document_id, at_least=DocumentPermission.EDIT, now=now, for_update=True
        )
        if ctx.org_id != document.owner_org_id:
            raise DocumentNotFoundError
        _require_open(document)
        if not await _may_name(db, document.owner_org_id, principal, principal_id):
            raise DocumentNotFoundError
        if expires_at is not None and expires_at <= now:
            msg = "a grant cannot expire in the past"
            raise DocumentRefusedError(msg)
        grant = DocumentGrant(
            id=uuid.uuid4(),
            document_id=document_id,
            principal_type=principal,
            principal_org_id=principal_id if principal is GrantPrincipal.ORGANIZATION else None,
            principal_operator_id=principal_id if principal is GrantPrincipal.OPERATOR else None,
            permission=permission,
            expires_at=expires_at,
            granted_by_operator_id=granter,
            created_at=now,
        )
        db.add(grant)
        details = {"principal_type": principal.value, "permission": permission.value}
        await _audit(db, ctx, AuditAction.DOCUMENT_GRANTED, document_id, details)
    return grant.id


async def revoke_grant(
    session: AsyncSession,
    ctx: AuthContext,
    document_id: uuid.UUID,
    grant_id: uuid.UUID,
    *,
    now: dt.datetime,
) -> None:
    """End one grant on a document the caller's organisation owns."""
    remover = _person(ctx)
    async with _staff(session, ctx) as db:
        document, _held = await _visible(
            db, ctx, document_id, at_least=DocumentPermission.EDIT, now=now, for_update=True
        )
        if ctx.org_id != document.owner_org_id:
            raise DocumentNotFoundError
        grant = await db.scalar(
            select(DocumentGrant)
            .where(DocumentGrant.id == grant_id, DocumentGrant.document_id == document_id)
            .with_for_update()
        )
        if grant is None or grant.revoked_at is not None:
            raise DocumentNotFoundError
        grant.revoked_at = now
        grant.revoked_by = str(remover)
        await _audit(db, ctx, AuditAction.DOCUMENT_GRANT_REVOKED, document_id, {})


async def transition_document(
    session: AsyncSession,
    ctx: AuthContext,
    document_id: uuid.UUID,
    *,
    to: DocumentState,
    now: dt.datetime,
) -> None:
    """Move a document along its machine. Archiving is the owner's; finishing is built in I3."""
    _person(ctx)
    async with _staff(session, ctx) as db:
        document, _held = await _visible(
            db, ctx, document_id, at_least=DocumentPermission.EDIT, now=now, for_update=True
        )
        if to not in DOCUMENT_TRANSITIONS[document.state]:
            msg = f"a {document.state.value} document cannot become {to.value}"
            raise DocumentRefusedError(msg)
        if to is DocumentState.FINISHED:
            msg = "finishing a document publishes it, which is not built yet"
            raise DocumentRefusedError(msg)
        if to is DocumentState.ARCHIVED and ctx.org_id != document.owner_org_id:
            msg = "only the owner archives a document"
            raise DocumentRefusedError(msg)
        details = {"from": document.state.value, "to": to.value}
        document.state = to
        document.version += 1
        document.updated_at = now
        await _audit(db, ctx, AuditAction.DOCUMENT_TRANSITIONED, document_id, details)


# ---------------------------------------------------------------------------
# The read
# ---------------------------------------------------------------------------
async def read_document(
    session: AsyncSession,
    ctx: AuthContext,
    document_id: uuid.UUID,
    *,
    box: SecretBox,
    now: dt.datetime,
    version_number: int | None,
) -> DocumentView:
    """The document as the caller may read it, with a receipt written for the read."""
    async with _staff(session, ctx) as db:
        document, permission = await _visible(
            db, ctx, document_id, at_least=DocumentPermission.VIEW, now=now, for_update=False
        )
        content = _content_box(box, document)
        version = await _version(db, document_id, version_number)
        body = content.unseal(
            version.body_sealed,
            purpose=SecretPurpose.DOCUMENT_VERSION,
            subject=f"{document_id}:{version.number}",
        )
        if body is None:
            msg = f"{document_id}:{version.number}"
            raise DocumentUnreadableError(msg)
        comments = await _comments(db, content, document_id)
        owner = await db.get(Organization, document.owner_org_id)
        db.add(
            DocumentRead(
                document_id=document_id,
                version_number=version.number,
                org_id=ctx.org_id,
                operator_id=ctx.operator_id,
                read_at=now,
            )
        )
        return DocumentView(
            id=document.id,
            owner_org_id=document.owner_org_id,
            owner_name=owner.name if owner is not None else "",
            title=document.title,
            abstract=document.abstract,
            tlp=document.tlp,
            state=document.state,
            version=document.version,
            version_number=version.number,
            content_sha256=version.content_sha256,
            body=body,
            permission=permission,
            comments=comments,
        )


async def _version(db: AsyncSession, document_id: uuid.UUID, number: int | None) -> DocumentVersion:
    query = select(DocumentVersion).where(DocumentVersion.document_id == document_id)
    if number is None:
        query = query.order_by(DocumentVersion.number.desc()).limit(1)
    else:
        query = query.where(DocumentVersion.number == number)
    version: DocumentVersion | None = await db.scalar(query)
    if version is None:
        raise DocumentNotFoundError
    return version


async def _comments(
    db: AsyncSession, content: SecretBox, document_id: uuid.UUID
) -> tuple[CommentView, ...]:
    rows = (
        await db.scalars(
            select(DocumentComment)
            .where(DocumentComment.document_id == document_id)
            .order_by(DocumentComment.created_at, DocumentComment.id)
        )
    ).all()
    views = []
    for row in rows:
        body = content.unseal(
            row.body_sealed,
            purpose=SecretPurpose.DOCUMENT_COMMENT,
            subject=f"{document_id}:{row.id}",
        )
        if body is None:
            msg = f"{document_id}:{row.id}"
            raise DocumentUnreadableError(msg)
        views.append(
            CommentView(row.id, row.version_number, row.author_operator_id, body, row.created_at)
        )
    return tuple(views)


# ---------------------------------------------------------------------------
# Offboarding
# ---------------------------------------------------------------------------
async def close_for_offboarded(
    session: AsyncSession, org_id: uuid.UUID, *, now: dt.datetime
) -> int:
    """An organisation has left: its documents are archived and every grant touching it ends.

    Archived, not deleted: a document is content its grantees received, kept
    like any content (``docs/data-inventory.md``). Every grant on its
    documents, and every grant naming it or one of its people, is revoked by
    ``offboarded``. Returns how many grants were closed. On the caller's
    session, which offboarding holds on the staff login.
    """
    owned = select(Document.id).where(Document.owner_org_id == org_id)
    its_people = select(Operator.id).where(Operator.org_id == org_id)
    grants = (
        await session.scalars(
            select(DocumentGrant)
            .where(
                DocumentGrant.revoked_at.is_(None),
                or_(
                    DocumentGrant.document_id.in_(owned),
                    DocumentGrant.principal_org_id == org_id,
                    DocumentGrant.principal_operator_id.in_(its_people),
                ),
            )
            .with_for_update()
        )
    ).all()
    for grant in grants:
        grant.revoked_at = now
        grant.revoked_by = "offboarded"
    documents = (
        await session.scalars(
            select(Document)
            .where(Document.owner_org_id == org_id, Document.state != DocumentState.ARCHIVED)
            .with_for_update()
        )
    ).all()
    for document in documents:
        document.state = DocumentState.ARCHIVED
        document.updated_at = now
    return len(grants)


async def _audit(
    db: AsyncSession,
    ctx: AuthContext,
    action: str,
    document_id: uuid.UUID,
    details: Mapping[str, object],
) -> None:
    await record(
        db,
        action=action,
        ctx=ctx,
        org_id=ctx.org_id,
        resource_type="document",
        resource_id=str(document_id),
        details=details,
    )
