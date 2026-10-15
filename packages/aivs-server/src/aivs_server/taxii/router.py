"""TAXII 2.1 endpoints.

The surface members actually integrate against. Everything here is constrained
by the specification, so where a choice looks odd it is usually the spec's
choice rather than ours; those places are commented.

Collections are the public projection of sharing circles. A collection is
visible to a caller only if their organisation belongs to the circle behind it,
and its contents are filtered by the same visibility rule that governs embargo.
There is no administrative bypass: an ISAC that wants to read a circle joins it,
visibly, rather than silently appearing in every member's feed.
"""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import ColumnElement, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import AckVia
from aivs_schemas.extension.builders import (
    BundleValidationError,
    ExtensionValidationError,
    UnknownExtensionError,
)
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.auth.deps import AttributionKeyDep, AuthenticatedContext, SessionDep, SettingsDep
from aivs_server.auth.policy import (
    Intervals,
    can_read_circle,
    can_submit_to_circle,
    readable_circle_ids,
    tlp_ceiling_clause,
)
from aivs_server.config import Settings
from aivs_server.db.clock import database_now
from aivs_server.db.models import Circle, TaxiiCollection
from aivs_server.services.contributions import ContributionRateLimitedError
from aivs_server.services.inbox import receive_envelope, status_of
from aivs_server.services.publication import wait_for_publications
from aivs_server.services.receipts import record_retrievals
from aivs_server.services.submissions import STORAGE_ERRORS, SubmissionError
from aivs_server.taxii import resources
from aivs_server.taxii.filters import FilterError, parse_filters
from aivs_server.taxii.paging import Cursor, CursorError, decode_cursor, encode_cursor
from aivs_server.taxii.queries import build_object_listing_query, build_version_listing_query

#: Content problems in an inbox envelope, reported back to the platform as 400.
INBOX_CLIENT_ERRORS: Final = (
    SubmissionError,
    BundleValidationError,
    ExtensionValidationError,
    UnknownExtensionError,
)

__all__ = ["API_ROOT", "router"]

#: AIVS exposes a single API root. Multiple roots exist in TAXII to partition
#: unrelated tenants, and an AIVS instance is single-tenant by design.
#:
#: It sits under /taxii2/ so that it inherits the JSON-only Content-Security-
#: Policy that deploy/nginx/nginx.conf applies to that location. Serving it from
#: a sibling path would silently fall through to the permissive default block.
API_ROOT: Final[str] = "taxii2/aivs"

router = APIRouter(tags=["taxii"])


# ---------------------------------------------------------------------------
# Content negotiation
# ---------------------------------------------------------------------------
def require_taxii_accept(request: Request) -> None:
    """Enforce the TAXII media type on the ``Accept`` header.

    TAXII 2.1 requires clients to ask for ``application/taxii+json;version=2.1``
    and requires a 406 when the server cannot satisfy the request. Wildcards are
    accepted because browsers and curl send them and refusing those makes the
    service needlessly hard to explore during onboarding.
    """
    accept = request.headers.get("accept", "")
    if not accept.strip():
        return
    acceptable = ("application/taxii+json", "application/*", "*/*")
    for part in accept.split(","):
        media = part.split(";")[0].strip().lower()
        if media in acceptable:
            return
    raise HTTPException(
        status_code=status.HTTP_406_NOT_ACCEPTABLE,
        detail="Accept must include application/taxii+json;version=2.1",
    )


TaxiiAccept = Annotated[None, Depends(require_taxii_accept)]


def _taxii_response(payload: dict[str, Any], status_code: int = 200) -> Response:
    """Serialise a TAXII resource with the required content type."""
    return Response(
        content=json.dumps(payload, separators=(",", ":")),
        status_code=status_code,
        media_type=resources.TAXII_MEDIA_TYPE,
    )


# ---------------------------------------------------------------------------
# Collection resolution
# ---------------------------------------------------------------------------
def _served_collection() -> tuple[ColumnElement[bool], ...]:
    """The conditions under which a collection is served at all, to anyone.

    One definition for the listing and the lookup. The listing once checked
    the circle alone, so a collection marked ``can_read=false`` was offered to
    every member of its circle and then answered 404 when they followed it.
    ``can_read`` is enforced, not merely advertised: it was once stored and
    displayed but never consulted, so a collection marked unreadable served its
    circle's full content anyway.
    """
    return (
        TaxiiCollection.is_active.is_(True),
        TaxiiCollection.can_read.is_(True),
        Circle.is_active.is_(True),
    )


async def _load_readable_collection(
    session: AsyncSession, ctx: AuthContext, collection_id: uuid.UUID
) -> tuple[TaxiiCollection, Circle, Intervals]:
    """Return a collection the caller may read, with the caller's join time.

    The join time comes back with the collection because every query built from
    it needs both: the circle says *what* may be read, and the join time says
    *from when*. Returning them together means a caller cannot pick up one and
    forget the other.

    A collection the caller cannot read is reported as 404 rather than 403. That
    is deliberate and TAXII permits it: distinguishing "exists but forbidden"
    from "does not exist" would let any member enumerate every circle on the
    instance, and the set of sharing circles is itself sensitive.
    """
    row = (
        await session.execute(
            select(TaxiiCollection, Circle)
            .join(Circle, Circle.id == TaxiiCollection.circle_id)
            .where(TaxiiCollection.id == collection_id, *_served_collection())
        )
    ).first()

    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collection not found")

    collection, circle = row
    grant = ctx.circles.get(circle.id)
    if grant is None or not can_read_circle(ctx, circle.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collection not found")
    return collection, circle, grant.intervals


def _collection_payload(collection: TaxiiCollection, ctx: AuthContext) -> dict[str, Any]:
    """Render a collection resource, with write capability resolved per caller.

    ``can_write`` reflects what *this* caller may do, not an abstract property
    of the collection: a read-only member and a contributor see different values
    for the same collection, which is what lets a client decide whether to offer
    submission at all.
    """
    return resources.collection_resource(
        collection_id=str(collection.id),
        title=collection.title,
        description=collection.description,
        alias=collection.alias,
        can_read=collection.can_read,
        can_write=collection.can_write and can_submit_to_circle(ctx, collection.circle_id),
        media_types=[resources.STIX_MEDIA_TYPE],
    )


# ---------------------------------------------------------------------------
# Discovery and API root
# ---------------------------------------------------------------------------
@router.get("/taxii2/")
async def discovery(
    _: TaxiiAccept,
    _ctx: AuthenticatedContext,  # declared to enforce authentication
    settings: SettingsDep,
) -> Response:
    """Discovery resource (TAXII 2.1 section 4.1).

    Authenticated like everything else: the set of API roots an instance
    exposes is not something an unauthenticated caller needs to learn.
    """
    base = settings.public_base_url.rstrip("/")
    return _taxii_response(
        resources.discovery_resource(
            title=settings.instance_name,
            description="ISAC vulnerability intelligence, from pre-CVE early warning onward",
            api_roots=[f"{base}/{API_ROOT}/"],
            default=f"{base}/{API_ROOT}/",
        )
    )


@router.get(f"/{API_ROOT}/")
async def api_root(
    _: TaxiiAccept,
    _ctx: AuthenticatedContext,  # declared to enforce authentication
    settings: SettingsDep,
) -> Response:
    """API root resource (section 4.2)."""
    return _taxii_response(
        resources.api_root_resource(
            title=f"{settings.instance_name} feed",
            description="Circles this organisation participates in",
            max_content_length=settings.max_body_bytes,
        )
    )


# ---------------------------------------------------------------------------
# Collections
# ---------------------------------------------------------------------------
@router.get(f"/{API_ROOT}/collections/")
async def list_collections(
    _: TaxiiAccept, ctx: AuthenticatedContext, session: SessionDep
) -> Response:
    """List the collections this caller may read (section 5.1).

    Only collections whose circle the caller belongs to appear. A member cannot
    learn that other circles exist from this endpoint.
    """
    circle_ids = readable_circle_ids(ctx)
    if not circle_ids:
        return _taxii_response(resources.collections_resource([]))

    rows = (
        (
            await session.execute(
                select(TaxiiCollection)
                .join(Circle, Circle.id == TaxiiCollection.circle_id)
                .where(TaxiiCollection.circle_id.in_(circle_ids), *_served_collection())
                .order_by(TaxiiCollection.title)
            )
        )
        .scalars()
        .all()
    )
    return _taxii_response(
        resources.collections_resource([_collection_payload(row, ctx) for row in rows])
    )


@router.get(f"/{API_ROOT}/collections/{{collection_id}}/")
async def get_collection(
    collection_id: uuid.UUID,
    _: TaxiiAccept,
    ctx: AuthenticatedContext,
    session: SessionDep,
) -> Response:
    """Fetch one collection (section 5.2)."""
    collection, _circle, _intervals = await _load_readable_collection(session, ctx, collection_id)
    return _taxii_response(_collection_payload(collection, ctx))


# ---------------------------------------------------------------------------
# Objects
# ---------------------------------------------------------------------------
def _parse_request_filters(request: Request, settings: Settings) -> Any:
    """Parse and validate query parameters, turning failures into 400."""
    grouped: dict[str, list[str]] = defaultdict(list)
    for key, value in request.query_params.multi_items():
        grouped[key].append(value)
    try:
        return parse_filters(
            grouped,
            default_limit=settings.taxii_default_page_size,
            max_limit=settings.taxii_max_page_size,
        )
    except FilterError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


def _resolve_cursor(
    settings: Settings, token: str | None, collection_id: uuid.UUID
) -> Cursor | None:
    if token is None:
        return None
    try:
        return decode_cursor(settings.session_secret.get_secret_value(), token, collection_id)
    except CursorError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


def _date_added_headers(response: Response, rows: list[Any]) -> None:
    """Set the TAXII date-added headers.

    Required on every 200 from the objects, manifest, and versions endpoints.
    Members use them to bound their next ``added_after`` poll, so omitting them
    quietly breaks incremental collection.
    """
    if not rows:
        return
    # min/max rather than first/last. Every listing now orders by
    # (date_added, seq), where the two coincide; the versions endpoint once
    # ordered by `modified`, which put First above Last, and a header that
    # follows the page's order instead of its bounds is wrong again the day a
    # listing sorts by anything else.
    stamps = [row.date_added for row in rows]
    response.headers["X-TAXII-Date-Added-First"] = resources.to_taxii_timestamp(min(stamps))
    response.headers["X-TAXII-Date-Added-Last"] = resources.to_taxii_timestamp(max(stamps))


@router.get(f"/{API_ROOT}/collections/{{collection_id}}/objects/")
async def list_objects(
    collection_id: uuid.UUID,
    request: Request,
    _: TaxiiAccept,
    ctx: AuthenticatedContext,
    session: SessionDep,
    settings: SettingsDep,
) -> Response:
    """List objects in a collection (section 5.4).

    Every successful retrieval writes receipts recording that this organisation
    collected this content -- see ``services.receipts``.
    """
    _collection, circle, intervals = await _load_readable_collection(session, ctx, collection_id)
    filters = _parse_request_filters(request, settings)
    cursor = _resolve_cursor(settings, filters.next_cursor, collection_id)
    limit = filters.limit or settings.taxii_default_page_size
    # No paging cursor may be computed while a publication is in flight, and
    # "now" is the database's clock, read under the lock: a replica's own
    # clock running fast showed embargoes early and issued cursors above rows
    # still to be stamped. See services.publication.
    now = await wait_for_publications(session)

    rows = list(
        (
            await session.execute(
                build_object_listing_query(
                    circle_id=circle.id,
                    intervals=intervals,
                    ceiling=tlp_ceiling_clause(ctx),
                    filters=filters,
                    now=now,
                    cursor=cursor,
                    limit=limit,
                )
            )
        ).all()
    )

    has_more = len(rows) > limit
    page = rows[:limit]

    next_cursor = None
    if has_more and page:
        next_cursor = encode_cursor(
            settings.session_secret.get_secret_value(),
            Cursor(
                date_added=page[-1].date_added,
                seq=page[-1].seq,
                collection_id=collection_id,
            ),
        )

    if page:
        await record_retrievals(
            session,
            org_id=ctx.org_id,
            submission_ids=[row.submission_id for row in page],
            via=AckVia.TAXII,
            actor_ref=ctx.cert_fingerprint,
            now=now,
        )
        await record(
            session,
            action=AuditAction.OBJECTS_RETRIEVED,
            ctx=ctx,
            resource_type="collection",
            resource_id=str(collection_id),
            details={"object_count": len(page)},
        )
        await session.commit()

    response = _taxii_response(
        resources.envelope_resource(
            [row.raw for row in page], more=has_more, next_cursor=next_cursor
        )
    )
    _date_added_headers(response, page)
    return response


@router.get(f"/{API_ROOT}/collections/{{collection_id}}/objects/{{object_id}}/")
async def get_object(
    collection_id: uuid.UUID,
    object_id: str,
    request: Request,
    _: TaxiiAccept,
    ctx: AuthenticatedContext,
    session: SessionDep,
    settings: SettingsDep,
) -> Response:
    """Fetch one object's visible versions (section 5.6).

    Returns an envelope, not a bare object: TAXII requires STIX content to be
    enveloped even when there is exactly one of it.
    """
    _collection, circle, intervals = await _load_readable_collection(session, ctx, collection_id)
    filters = _parse_request_filters(request, settings)
    # The cursor was parsed and then discarded here, so an object with more
    # visible versions than one page was reported as `more: true` with no `next`
    # to follow -- and a token the client supplied anyway was silently ignored,
    # while the same token on /objects/ and /manifest/ is a 400. Same handling on
    # all three.
    cursor = _resolve_cursor(settings, filters.next_cursor, collection_id)
    limit = filters.limit or settings.taxii_default_page_size
    # No paging cursor may be computed while a publication is in flight, and
    # "now" is the database's clock, read under the lock: a replica's own
    # clock running fast showed embargoes early and issued cursors above rows
    # still to be stamped. See services.publication.
    now = await wait_for_publications(session)

    rows = list(
        (
            await session.execute(
                build_object_listing_query(
                    circle_id=circle.id,
                    intervals=intervals,
                    ceiling=tlp_ceiling_clause(ctx),
                    filters=filters,
                    now=now,
                    cursor=cursor,
                    limit=limit,
                    stix_id=object_id,
                )
            )
        ).all()
    )

    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found")

    has_more = len(rows) > limit
    page = rows[:limit]

    next_cursor = None
    if has_more and page:
        next_cursor = encode_cursor(
            settings.session_secret.get_secret_value(),
            Cursor(
                date_added=page[-1].date_added,
                seq=page[-1].seq,
                collection_id=collection_id,
            ),
        )

    await record_retrievals(
        session,
        org_id=ctx.org_id,
        submission_ids=[row.submission_id for row in page],
        via=AckVia.TAXII,
        actor_ref=ctx.cert_fingerprint,
        now=now,
    )
    await session.commit()

    response = _taxii_response(
        resources.envelope_resource(
            [row.raw for row in page], more=has_more, next_cursor=next_cursor
        )
    )
    _date_added_headers(response, page)
    return response


@router.get(f"/{API_ROOT}/collections/{{collection_id}}/objects/{{object_id}}/versions/")
async def get_object_versions(
    collection_id: uuid.UUID,
    object_id: str,
    request: Request,
    _: TaxiiAccept,
    ctx: AuthenticatedContext,
    session: SessionDep,
    settings: SettingsDep,
) -> Response:
    """List the visible versions of one object (section 5.8).

    ``limit``, ``added_after`` and ``next`` are honoured here, with the paging
    the objects listing has. The handler once took no request at all, so a
    client asking for 500 versions received one default page with nothing to
    follow; and it later paged in ``modified`` order, which ``added_after``
    cannot continue without skipping (see ``build_version_listing_query``).
    """
    _collection, circle, intervals = await _load_readable_collection(session, ctx, collection_id)
    filters = _parse_request_filters(request, settings)
    cursor = _resolve_cursor(settings, filters.next_cursor, collection_id)
    limit = filters.limit or settings.taxii_default_page_size
    # No paging cursor may be computed while a publication is in flight, and
    # "now" is the database's clock, read under the lock: a replica's own
    # clock running fast showed embargoes early and issued cursors above rows
    # still to be stamped. See services.publication.
    now = await wait_for_publications(session)

    rows = list(
        (
            await session.execute(
                build_version_listing_query(
                    circle_id=circle.id,
                    intervals=intervals,
                    ceiling=tlp_ceiling_clause(ctx),
                    stix_id=object_id,
                    now=now,
                    cursor=cursor,
                    limit=limit,
                    added_after=filters.added_after,
                )
            )
        ).all()
    )

    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found")

    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = None
    if has_more:
        next_cursor = encode_cursor(
            settings.session_secret.get_secret_value(),
            Cursor(date_added=page[-1].date_added, seq=page[-1].seq, collection_id=collection_id),
        )
    response = _taxii_response(
        resources.versions_resource(
            [resources.to_taxii_timestamp(row.modified) for row in page],
            more=has_more,
            next_cursor=next_cursor,
        )
    )
    _date_added_headers(response, page)
    return response


@router.get(f"/{API_ROOT}/collections/{{collection_id}}/manifest/")
async def get_manifest(
    collection_id: uuid.UUID,
    request: Request,
    _: TaxiiAccept,
    ctx: AuthenticatedContext,
    session: SessionDep,
    settings: SettingsDep,
) -> Response:
    """Manifest of a collection's visible objects (section 5.3).

    Same filters and paging as the objects endpoint, but returns metadata only.
    Retrieving a manifest is deliberately **not** recorded as a retrieval
    receipt: the member has learned that content exists, not what it says, and
    an ISAC should not be able to tell a regulator a firm "received" a warning
    on the strength of a metadata listing.
    """
    _collection, circle, intervals = await _load_readable_collection(session, ctx, collection_id)
    filters = _parse_request_filters(request, settings)
    cursor = _resolve_cursor(settings, filters.next_cursor, collection_id)
    limit = filters.limit or settings.taxii_default_page_size
    # No paging cursor may be computed while a publication is in flight, and
    # "now" is the database's clock, read under the lock: a replica's own
    # clock running fast showed embargoes early and issued cursors above rows
    # still to be stamped. See services.publication.
    now = await wait_for_publications(session)

    rows = list(
        (
            await session.execute(
                build_object_listing_query(
                    circle_id=circle.id,
                    intervals=intervals,
                    ceiling=tlp_ceiling_clause(ctx),
                    filters=filters,
                    now=now,
                    cursor=cursor,
                    limit=limit,
                )
            )
        ).all()
    )

    has_more = len(rows) > limit
    page = rows[:limit]

    next_cursor = None
    if has_more and page:
        next_cursor = encode_cursor(
            settings.session_secret.get_secret_value(),
            Cursor(
                date_added=page[-1].date_added,
                seq=page[-1].seq,
                collection_id=collection_id,
            ),
        )

    response = _taxii_response(
        resources.manifest_resource(
            [
                resources.manifest_record(
                    stix_id=row.stix_id,
                    date_added=row.date_added,
                    version=resources.to_taxii_timestamp(row.modified),
                    media_type=resources.STIX_MEDIA_TYPE,
                )
                for row in page
            ],
            more=has_more,
            next_cursor=next_cursor,
        )
    )
    _date_added_headers(response, page)
    return response


# ---------------------------------------------------------------------------
# The inbox: the TAXII write path, SF-69
# ---------------------------------------------------------------------------
def _require_taxii_content_type(request: Request) -> None:
    """A POST must say it carries a TAXII envelope (section 3.2)."""
    content_type = request.headers.get("content-type", "")
    if not content_type.startswith("application/taxii+json"):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="send the envelope as application/taxii+json;version=2.1",
        )


@router.post(f"/{API_ROOT}/collections/{{collection_id}}/objects/")
async def add_objects(
    collection_id: uuid.UUID,
    request: Request,
    _: TaxiiAccept,
    ctx: AuthenticatedContext,
    session: SessionDep,
    key: AttributionKeyDep,
    settings: SettingsDep,
) -> Response:
    """Contribute objects to a collection (section 5.5), as one submission for review.

    Readable but not writable answers 403, as TAXII says; a collection the
    caller cannot read answers 404 like an absent one. See ``services.inbox``
    for what a POST becomes.
    """
    collection, circle, _intervals = await _load_readable_collection(session, ctx, collection_id)
    if not (collection.can_write and can_submit_to_circle(ctx, circle.id)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not writable")
    # After authorization, so a caller who may not write learns nothing more
    # from a wrong media type than from a right one.
    _require_taxii_content_type(request)
    try:
        envelope = json.loads(await request.body())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="not JSON") from exc
    try:
        received = await receive_envelope(
            session,
            ctx,
            collection=collection,
            circle=circle,
            envelope=envelope,
            hourly_limit=settings.contribution_hourly_limit,
            now=await database_now(session),
            key=key,
        )
        await session.commit()
    except ContributionRateLimitedError:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="this organisation's hourly allowance for contributions is used",
        ) from None
    except INBOX_CLIENT_ERRORS as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except STORAGE_ERRORS as exc:
        # A value the database refuses (a NUL, a string past its column) is the
        # platform's malformed envelope, as on every other ingest path: a 400.
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Envelope content rejected by storage"
        ) from exc
    return _taxii_response(_status_payload(received), status_code=status.HTTP_202_ACCEPTED)


@router.get(f"/{API_ROOT}/status/{{status_id}}/")
async def get_status(
    status_id: uuid.UUID, _: TaxiiAccept, ctx: AuthenticatedContext, session: SessionDep
) -> Response:
    """A POST's status (section 4.3): the organisation that made it only; others 404."""
    found = await status_of(session, ctx, status_id)
    if found is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Status not found")
    return _taxii_response(_status_payload(found))


def _status_payload(row: Any) -> dict[str, Any]:
    return resources.status_resource(
        status_id=str(row.id),
        status=row.status,
        total_count=row.total_count,
        success_count=row.success_count,
        failure_count=row.failure_count,
        pending_count=row.pending_count,
        request_timestamp=row.request_timestamp,
        successes=row.successes,
        failures=row.failures,
        pendings=row.pendings,
    )
