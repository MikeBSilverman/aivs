"""The hosting ISAC's administrative screens.

Enrolling member firms and running sharing circles without reaching for
``curl``. Registering and revoking certificates is not here yet: it is on the
native API (``/api/v1/orgs/{id}/certificates``, ``/api/v1/certificates/{id}/revoke``),
which ISAC membership staff reach with their portal session as a bearer token.
This docstring used to claim the portal covered it.

This exists because the API-only version of these operations was, in practice, a
barrier to deploying AIVS at all. An ISAC evaluating the product does not have an
engineer on hand to compose administrative requests, and "you administer it over
the REST API" is a reasonable thing to say about a library and an unreasonable
thing to say about a product an organisation is meant to operate.

**No new authorization.** Every route here calls the same policy predicates the
native API does and then the same service functions, so the portal cannot become
a second, weaker door to the same operations. Where a route needs the hosting
ISAC, it says ``require(<the role predicate>(ctx), ...)`` before it acts, not after.

**Reads before writes, and names before identifiers.** A group is easier to
select and correspondingly easier to be wrong about, so the circle screen
resolves a membership rule to the actual list of organisations it currently
matches. The moment before releasing embargoed intelligence to a group is the
moment to make that group concrete.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from aivs_schemas.enums import CertStatus, CircleRole, OrgStatus, OrgType
from aivs_schemas.models import CircleCreate
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.deps import SessionDep, SettingsDep
from aivs_server.auth.policy import (
    can_view_instance_status,
    is_isac_editor,
    is_isac_membership,
    require,
)
from aivs_server.auth.secretbox import SecretBox
from aivs_server.db.models import (
    Circle,
    CircleMembership,
    ClientCertificate,
    Organization,
    TaxiiCollection,
)
from aivs_server.portal.shared import (
    base_context,
    current_session,
    operator_name,
    render,
    require_csrf,
    set_notice,
)
from aivs_server.services.circles import (
    CircleMembershipError,
    add_circle_members,
    reconcile_circle,
    remove_circle_member,
    resolve_organisations,
)
from aivs_server.services.instance_status import gather_status

__all__ = ["router"]

router = APIRouter(prefix="/portal/admin", tags=["portal-admin"])


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER)


def _parse_names(raw: str) -> tuple[list[uuid.UUID], list[str]]:
    """Split a pasted roster into identifiers and slugs.

    Operators paste lists, and what they paste is whatever they already have --
    a column from a spreadsheet, a comma-separated line from an email. Accepting
    both separators and sorting UUIDs from slugs here means the form does not
    have to ask which kind they are pasting.
    """
    tokens = [token.strip() for token in raw.replace(",", "\n").split("\n") if token.strip()]
    ids: list[uuid.UUID] = []
    slugs: list[str] = []
    for token in tokens:
        try:
            ids.append(uuid.UUID(token))
        except ValueError:
            slugs.append(token)
    return ids, slugs


# ---------------------------------------------------------------------------
# Organisations
# ---------------------------------------------------------------------------
@router.get("/orgs", response_class=HTMLResponse)
async def orgs_screen(request: Request, settings: SettingsDep, session: SessionDep) -> Response:
    """Every enrolled organisation, with its certificates."""
    ctx, _csrf = await current_session(request, settings, session)
    require(is_isac_membership(ctx), "portal_admin_orgs")

    orgs = (await session.execute(select(Organization).order_by(Organization.slug))).scalars().all()
    certificate_counts: dict[uuid.UUID, int] = {
        row.org_id: row.total
        for row in (
            await session.execute(
                select(
                    ClientCertificate.org_id,
                    func.count().label("total"),
                )
                .where(ClientCertificate.status == CertStatus.ACTIVE)
                .group_by(ClientCertificate.org_id)
            )
        ).all()
    }

    context = base_context(request, settings, ctx, await operator_name(session, ctx), "admin-orgs")
    context.update(
        {
            "orgs": [
                {
                    "id": str(org.id),
                    "slug": org.slug,
                    "name": org.name,
                    "org_type": org.org_type.value,
                    "status": org.status.value,
                    "certificates": certificate_counts.get(org.id, 0),
                }
                for org in orgs
            ],
            "org_types": [org_type.value for org_type in OrgType],
        }
    )
    return render(request, "admin_orgs.html", context)


@router.post("/orgs")
async def enrol_org(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
    slug: Annotated[str, Form()],
    name: Annotated[str, Form()],
    org_type: Annotated[str, Form()],
    contact_email: Annotated[str, Form()] = "",
) -> Response:
    """Enrol an organisation. It starts pending, exactly as over the API."""
    ctx, csrf_hash = await current_session(request, settings, session)
    require_csrf(csrf_token, csrf_hash)
    require(is_isac_membership(ctx), "portal_admin_orgs")

    response = _redirect("/portal/admin/orgs")
    try:
        organization = Organization(
            slug=slug.strip(),
            name=name.strip(),
            org_type=OrgType(org_type),
            contact_email=contact_email.strip() or None,
            status=OrgStatus.PENDING,
            stix_identity_id=f"identity--{uuid.uuid4()}",
        )
        session.add(organization)
        await record(
            session,
            action=AuditAction.ORG_CREATED,
            ctx=ctx,
            resource_type="organization",
            resource_id=slug,
            details={"org_type": org_type, "via": "portal"},
        )
        await session.commit()
    except (IntegrityError, ValueError) as exc:
        await session.rollback()
        set_notice(response, settings, "error", f"Could not enrol {slug}: {exc}")
        return response

    set_notice(response, settings, "info", f"Enrolled {slug}. Activate it to grant access.")
    return response


@router.post("/orgs/{org_id}/{action}")
async def org_status(
    org_id: uuid.UUID,
    action: str,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
) -> Response:
    """Activate or suspend an organisation.

    Reconciliation runs through the same service the API uses, so a rule-managed
    circle picks up an activation here exactly as it would there.
    """
    ctx, csrf_hash = await current_session(request, settings, session)
    require_csrf(csrf_token, csrf_hash)
    require(is_isac_membership(ctx), "portal_admin_orgs")

    if action not in ("activate", "suspend"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

    organization = await session.get(Organization, org_id)
    if organization is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

    from aivs_server.services.circles import (  # noqa: PLC0415 - avoids an import cycle
        reconcile_circles_for_org,
    )

    previous = organization.status
    organization.status = OrgStatus.ACTIVE if action == "activate" else OrgStatus.SUSPENDED
    # Flushed before reconciling: autoflush is off, so the rule would otherwise
    # be evaluated against the status this organisation had a moment ago.
    await session.flush()
    await reconcile_circles_for_org(session, ctx, organisation=organization)

    await record(
        session,
        action=AuditAction.ORG_STATUS_CHANGED,
        ctx=ctx,
        resource_type="organization",
        resource_id=str(org_id),
        details={"from": previous.value, "to": organization.status.value, "via": "portal"},
    )
    await session.commit()

    response = _redirect("/portal/admin/orgs")
    set_notice(
        response, settings, "info", f"{organization.slug} is now {organization.status.value}."
    )
    return response


# ---------------------------------------------------------------------------
# Circles
# ---------------------------------------------------------------------------
@router.get("/circles", response_class=HTMLResponse)
async def circles_screen(request: Request, settings: SettingsDep, session: SessionDep) -> Response:
    """Every circle, with its membership count and rule."""
    ctx, _csrf = await current_session(request, settings, session)
    require(is_isac_editor(ctx) or is_isac_membership(ctx), "portal_admin_circles")

    circles = (await session.execute(select(Circle).order_by(Circle.slug))).scalars().all()
    counts: dict[uuid.UUID, int] = {
        row.circle_id: row.total
        for row in (
            await session.execute(
                select(
                    CircleMembership.circle_id,
                    func.count().label("total"),
                )
                .where(CircleMembership.left_at.is_(None))
                .group_by(CircleMembership.circle_id)
            )
        ).all()
    }

    context = base_context(
        request, settings, ctx, await operator_name(session, ctx), "admin-circles"
    )
    context.update(
        {
            "circles": [
                {
                    "id": str(circle.id),
                    "slug": circle.slug,
                    "name": circle.name,
                    "minimum_tlp": circle.minimum_tlp.value,
                    "is_active": circle.is_active,
                    "members": counts.get(circle.id, 0),
                    "rule": ", ".join(circle.auto_member_org_types),
                }
                for circle in circles
            ],
            "org_types": [org_type.value for org_type in OrgType if org_type is not OrgType.ADMIN],
            "tlps": ["clear", "green", "amber", "amber_strict", "red"],
        }
    )
    return render(request, "admin_circles.html", context)


@router.post("/circles")
async def create_circle_screen(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
    slug: Annotated[str, Form()],
    name: Annotated[str, Form()],
    minimum_tlp: Annotated[str, Form()] = "amber",
    auto_member_org_types: Annotated[list[str], Form()] = [],  # noqa: B006 - FastAPI form list
) -> Response:
    """Create a circle, its collection, and populate any rule immediately."""
    ctx, csrf_hash = await current_session(request, settings, session)
    require_csrf(csrf_token, csrf_hash)
    require(is_isac_editor(ctx), "portal_admin_circles")

    response = _redirect("/portal/admin/circles")
    try:
        # The API's request model, so the portal cannot store a rule the API
        # would refuse. It took raw form strings straight into the column,
        # including the ISAC's own `admin` type.
        payload = CircleCreate.model_validate(
            {
                "slug": slug.strip(),
                "name": name.strip(),
                "minimum_tlp": minimum_tlp,
                "auto_member_org_types": list(auto_member_org_types),
            }
        )
    except ValidationError as exc:
        error = exc.errors(include_input=False)[0]
        set_notice(response, settings, "error", f"Could not create {slug}: {error['msg']}")
        return response

    try:
        circle = Circle(
            slug=payload.slug,
            name=payload.name,
            minimum_tlp=payload.minimum_tlp,
            auto_member_org_types=[org_type.value for org_type in payload.auto_member_org_types],
        )
        session.add(circle)
        await session.flush()
        session.add(
            TaxiiCollection(
                circle_id=circle.id,
                title=circle.name,
                alias=circle.slug,
                can_read=True,
                # See api.admin.create_circle: there is no TAXII write endpoint,
                # so advertising one sends off-the-shelf clients at a 405.
                can_write=False,
            )
        )
        await record(
            session,
            action=AuditAction.CIRCLE_CREATED,
            ctx=ctx,
            resource_type="circle",
            resource_id=slug,
            details={
                "minimum_tlp": minimum_tlp,
                "auto_member_org_types": list(auto_member_org_types),
                "via": "portal",
            },
        )
        await reconcile_circle(session, ctx, circle=circle)
        await session.commit()
    except (IntegrityError, ValueError) as exc:
        await session.rollback()
        set_notice(response, settings, "error", f"Could not create {slug}: {exc}")
        return response

    set_notice(response, settings, "info", f"Created circle {slug}.")
    return response


@router.get("/circles/{circle_id}", response_class=HTMLResponse)
async def circle_detail(
    circle_id: uuid.UUID, request: Request, settings: SettingsDep, session: SessionDep
) -> Response:
    """One circle's membership, by name.

    The membership is listed with each organisation's join date, because that is
    what bounds what they can read and an operator answering "why can they not
    see this?" needs it in front of them.
    """
    ctx, _csrf = await current_session(request, settings, session)
    require(is_isac_editor(ctx) or is_isac_membership(ctx), "portal_admin_circles")

    circle = await session.get(Circle, circle_id)
    if circle is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

    rows = (
        await session.execute(
            select(CircleMembership, Organization)
            .join(Organization, Organization.id == CircleMembership.org_id)
            .where(
                CircleMembership.circle_id == circle_id,
                CircleMembership.left_at.is_(None),
            )
            .order_by(Organization.slug)
        )
    ).all()

    context = base_context(
        request, settings, ctx, await operator_name(session, ctx), "admin-circles"
    )
    context.update(
        {
            "circle": {
                "id": str(circle.id),
                "slug": circle.slug,
                "name": circle.name,
                "minimum_tlp": circle.minimum_tlp.value,
                "rule": ", ".join(circle.auto_member_org_types),
            },
            "members": [
                {
                    "org_id": str(org.id),
                    "slug": org.slug,
                    "name": org.name,
                    "org_type": org.org_type.value,
                    "status": org.status.value,
                    "role": membership.role.value,
                    "joined_at": membership.joined_at.strftime("%Y-%m-%d %H:%M"),
                    "managed_by_rule": membership.managed_by_rule,
                }
                for membership, org in rows
            ],
            "roles": [role.value for role in CircleRole],
        }
    )
    return render(request, "admin_circle_detail.html", context)


def _parse_joined_at(value: str) -> dt.datetime | None:
    """Parse the optional repair date (YYYY-MM-DD, UTC midnight). Empty means none."""
    value = value.strip()
    if not value:
        return None
    try:
        day = dt.date.fromisoformat(value)
    except ValueError as exc:
        msg = "membership start must be a date, YYYY-MM-DD"
        raise ValueError(msg) from exc
    return dt.datetime.combine(day, dt.time(), tzinfo=dt.UTC)


@router.post("/circles/{circle_id}/members")
async def add_members_screen(
    circle_id: uuid.UUID,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
    roster: Annotated[str, Form()],
    role: Annotated[str, Form()] = "member",
    joined_at: Annotated[str, Form()] = "",
) -> Response:
    """Add a pasted roster of organisations to a circle.

    ``joined_at`` is the audited repair for an administrative mistake -- a firm
    removed in error, restored with the history it had. Empty means "from now".
    """
    ctx, csrf_hash = await current_session(request, settings, session)
    require_csrf(csrf_token, csrf_hash)
    require(is_isac_membership(ctx), "portal_admin_circles")

    circle = await session.get(Circle, circle_id)
    if circle is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

    response = _redirect(f"/portal/admin/circles/{circle_id}")
    org_ids, org_slugs = _parse_names(roster)

    try:
        backdate = _parse_joined_at(joined_at)
        organisations = await resolve_organisations(session, org_ids=org_ids, org_slugs=org_slugs)
        added = await add_circle_members(
            session,
            ctx,
            circle=circle,
            organisations=organisations,
            role=CircleRole(role),
            joined_at=backdate,
        )
        await session.commit()
    except (CircleMembershipError, ValueError) as exc:
        await session.rollback()
        set_notice(response, settings, "error", str(exc))
        return response
    except IntegrityError:
        # The exclusion constraint: a start date reaching into a period when
        # the organisation was out of the circle. Refused by the database, so
        # the gap cannot be handed over by a typo.
        await session.rollback()
        set_notice(
            response,
            settings,
            "error",
            "That start date overlaps an earlier period of membership; it cannot "
            "reach back past the date the organisation last left.",
        )
        return response

    skipped = len(organisations) - len(added)
    message = f"Added {len(added)} organisation(s) to {circle.slug}."
    if skipped:
        message += f" {skipped} already belonged."
    set_notice(response, settings, "info", message)
    return response


@router.post("/circles/{circle_id}/members/{org_id}/remove")
async def remove_member_screen(
    circle_id: uuid.UUID,
    org_id: uuid.UUID,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
) -> Response:
    """Remove one organisation from a circle."""
    ctx, csrf_hash = await current_session(request, settings, session)
    require_csrf(csrf_token, csrf_hash)
    require(is_isac_membership(ctx), "portal_admin_circles")

    closed = await remove_circle_member(
        session, ctx, circle_id=circle_id, org_id=org_id, now=dt.datetime.now(dt.UTC), via="portal"
    )
    response = _redirect(f"/portal/admin/circles/{circle_id}")
    if not closed:
        set_notice(response, settings, "error", "That organisation is not a member.")
        return response
    await session.commit()

    set_notice(
        response,
        settings,
        "info",
        "Removed. Content they already collected is theirs; this stops future delivery.",
    )
    return response


# ---------------------------------------------------------------------------
# Instance status
# ---------------------------------------------------------------------------
@router.get("/status", response_class=HTMLResponse)
async def status_screen(request: Request, settings: SettingsDep, session: SessionDep) -> Response:
    """Health, queues, usage and what needs attention, laid out for a person.

    The same facts ``/readyz`` and ``/metrics`` expose, from the same functions,
    so the page cannot say "fine" while the probe says "degraded".
    """
    ctx, _csrf = await current_session(request, settings, session)
    require(can_view_instance_status(ctx), "portal_admin_status")

    facts = await gather_status(
        session, now=dt.datetime.now(dt.UTC), box=SecretBox.from_settings(settings)
    )
    context = base_context(
        request, settings, ctx, await operator_name(session, ctx), "admin-status"
    )
    context["status"] = facts
    return render(request, "admin_status.html", context)
