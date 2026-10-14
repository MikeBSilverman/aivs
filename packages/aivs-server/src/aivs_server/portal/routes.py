"""The analyst portal.

Server-rendered HTML, no SPA, no build step. That is a security decision as much
as a delivery one: the Content-Security-Policy is ``default-src 'none'`` with
same-origin styles and scripts and no ``unsafe-inline``, which is only
achievable because nothing here needs to execute in the browser.

Every mutating route requires a CSRF token bound to the session, and every route
resolves the session against the client certificate on *this* request — so a
cookie replayed from outside the organisation's certificate-bearing path is
refused, and a revoked certificate ends the analyst's session on their next
click rather than at the end of its TTL.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from pydantic import ValidationError
from sqlalchemy import func, select

from aivs_schemas.enums import TLP, CertStatus, OrgStatus, SubmissionState
from aivs_schemas.models import SubmissionCreate
from aivs_server.audit.log import AuditAction, account_reference, record_independently
from aivs_server.auth.context import AuthContext
from aivs_server.auth.deps import SessionDep, SettingsDep, request_source_ip
from aivs_server.auth.policy import (
    can_review_submissions,
    can_transition_submission,
    can_view_submission,
    can_view_submission_receipts,
    readable_circle_grants,
    require,
    visible_content_clause,
)
from aivs_server.auth.secretbox import SecretBox
from aivs_server.auth.sessions import (
    SessionRejectedError,
    authenticate_operator,
    establish_session,
    revoke_session,
)
from aivs_server.config import Settings
from aivs_server.db.models import (
    Acknowledgment,
    Circle,
    ClientCertificate,
    Distribution,
    Organization,
    StixObject,
    Submission,
    SubmissionTransition,
)
from aivs_server.notify.events import queue_visibility_notifications
from aivs_server.portal.shared import (
    LOGIN_FAILED,
    TEMPLATES,
    base_context,
    client_fingerprint,
    current_session,
    operator_name,
    redirect_within_portal,
    render,
    require_csrf,
    set_notice,
    stamp,
    tlp_label,
)
from aivs_server.portal.submitter_view import lint_hits, telemetry_rows
from aivs_server.services.contributions import submit_submission
from aivs_server.services.distribution import DistributionError, distribute_submission
from aivs_server.services.provenance import consequential_changes
from aivs_server.services.publication import PublicationPausedError
from aivs_server.services.submissions import (
    STORAGE_ERRORS,
    SubmissionError,
    apply_transition,
    create_submission,
    load_submission,
)

__all__ = ["router"]

router = APIRouter(prefix="/portal", tags=["portal"])


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, settings: SettingsDep) -> Response:
    """Render the sign-in form.

    A CSRF token is minted per render and stored in a short-lived cookie, so the
    login form is protected before a session exists.
    """
    token = uuid.uuid4().hex
    response = TEMPLATES.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "instance_name": settings.instance_name,
            "csrf_token": token,
            "error": None,
            "email": None,
            "notices": [],
        },
    )
    response.set_cookie(
        "aivs_login_csrf",
        hashlib.sha256(token.encode("utf-8")).hexdigest(),
        max_age=600,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/portal",
    )
    return response


@router.post("/login")
async def login(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    totp_code: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
) -> Response:
    """Verify credentials and establish a session bound to the certificate."""
    expected = request.cookies.get("aivs_login_csrf", "")
    require_csrf(csrf_token, expected)

    fingerprint = client_fingerprint(request, settings)
    if fingerprint is None:
        # No certificate, no session: the binding established below is what makes
        # the password and the transport two independent factors.
        return await _login_failure(request, settings, email, "no_client_certificate")

    # Status is checked here, not only in resolve_session on the next request.
    # nginx has no CRL -- revocation is authoritative in this database -- so the
    # holder of a revoked certificate still completes the handshake. Without
    # these two predicates they reached the full credential check, which made
    # login a working password/TOTP oracle for exactly the compromised-certificate
    # case revocation exists for, reset the operator's lockout counter on
    # success, and wrote a LOGIN_SUCCESS audit row for an access that policy
    # grants nothing.
    org = (
        await session.execute(
            select(Organization)
            .join(ClientCertificate, ClientCertificate.org_id == Organization.id)
            .where(
                ClientCertificate.fingerprint_sha256 == fingerprint,
                ClientCertificate.status == CertStatus.ACTIVE,
                Organization.status == OrgStatus.ACTIVE,
            )
        )
    ).scalar_one_or_none()

    if org is None:
        return await _login_failure(request, settings, email, "no_client_certificate")

    try:
        operator = await authenticate_operator(
            session,
            email=email,
            password=password,
            totp_code=totp_code,
            org_id=org.id,
            secret_box=SecretBox.from_settings(settings),
        )
    except SessionRejectedError as exc:
        return await _login_failure(request, settings, email, exc.reason)

    established = await establish_session(
        session,
        settings,
        operator=operator,
        cert_fingerprint=fingerprint,
        source_ip=request_source_ip(request, settings),
        user_agent=request.headers.get("user-agent"),
    )
    await record_independently(
        action=AuditAction.LOGIN_SUCCESS,
        actor_type="operator",
        actor_id=str(operator.id),
        org_id=org.id,
        outcome="success",
        request_id=request.scope.get("aivs_request_id"),
        source_ip=request_source_ip(request, settings),
    )

    response = redirect_within_portal("/portal/")
    response.set_cookie(
        settings.session_cookie_name,
        established.token,
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/portal",
    )
    response.set_cookie(
        "aivs_csrf",
        established.csrf_token,
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/portal",
    )
    response.delete_cookie("aivs_login_csrf", path="/portal")
    return response


async def _login_failure(request: Request, settings: Settings, email: str, reason: str) -> Response:
    """Render the one failure message, and record the specific reason privately."""
    await record_independently(
        action=AuditAction.LOGIN_FAILURE,
        actor_type="anonymous",
        outcome="failure",
        request_id=request.scope.get("aivs_request_id"),
        source_ip=request_source_ip(request, settings),
        details={"reason": reason, "account": account_reference(email, settings)},
    )
    token = uuid.uuid4().hex
    response = TEMPLATES.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "instance_name": settings.instance_name,
            "csrf_token": token,
            "error": LOGIN_FAILED,
            "email": email,
            "notices": [],
        },
        status_code=status.HTTP_401_UNAUTHORIZED,
    )
    response.set_cookie(
        "aivs_login_csrf",
        hashlib.sha256(token.encode("utf-8")).hexdigest(),
        max_age=600,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/portal",
    )
    return response


@router.post("/logout")
async def logout(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
) -> Response:
    """End the session and clear its cookies.

    POST with a CSRF token, like every other state change here. Revoking a
    session is a write, and it was the one route that did it on a GET. The
    SameSite=Strict cookie meant a cross-site request carried no session and hit
    the no-op branch, so this was never exploitable -- but that made the
    protection incidental, resting on a cookie attribute rather than on the check
    every sibling route performs.
    """
    ctx, csrf_hash = await current_session(request, settings, session)
    require_csrf(csrf_token, csrf_hash)
    del ctx

    token = request.cookies.get(settings.session_cookie_name)
    if token:
        await revoke_session(session, token=token)
        await record_independently(
            action=AuditAction.LOGOUT,
            outcome="success",
            request_id=request.scope.get("aivs_request_id"),
            source_ip=request_source_ip(request, settings),
        )
    response = redirect_within_portal("/portal/login")
    response.delete_cookie(settings.session_cookie_name, path="/portal")
    response.delete_cookie("aivs_csrf", path="/portal")
    return response


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, settings: SettingsDep, session: SessionDep) -> Response:
    """What this analyst's firm can see, and what it has filed."""
    ctx, _csrf_hash = await current_session(request, settings, session)
    now = dt.datetime.now(dt.UTC)
    circle_grants = readable_circle_grants(ctx)

    available = 0
    recent: list[dict[str, Any]] = []
    if circle_grants:
        rows = (
            await session.execute(
                select(Distribution.date_added, StixObject.name, Submission.tlp)
                .join(StixObject, StixObject.id == Distribution.stix_object_id)
                .join(Submission, Submission.id == Distribution.submission_id)
                # The shared predicate, not a restatement of it. Written out by
                # hand, this had two of its three conditions and was missing the
                # submission-state term -- the portal and the TAXII feed would
                # have disagreed about what a member can see the moment a state
                # outside VISIBLE_SUBMISSION_STATES became reachable.
                .where(visible_content_clause(circle_grants, now))
                .order_by(Distribution.date_added.desc())
                .limit(10)
            )
        ).all()
        recent = [
            {
                "date_added": stamp(row.date_added),
                "name": row.name or "(unnamed object)",
                "tlp": str(row.tlp),
                "tlp_label": tlp_label(row.tlp),
            }
            for row in rows
        ]
        available = (
            await session.scalar(
                select(func.count(func.distinct(Distribution.submission_id)))
                .join(Submission, Submission.id == Distribution.submission_id)
                .where(visible_content_clause(circle_grants, now))
            )
        ) or 0

    ours = (
        await session.scalar(
            select(func.count())
            .select_from(Submission)
            .where(Submission.submitter_org_id == ctx.org_id)
        )
    ) or 0

    awaiting = 0
    if can_review_submissions(ctx):
        awaiting = (
            await session.scalar(
                select(func.count())
                .select_from(Submission)
                .where(Submission.state == SubmissionState.SUBMITTED)
            )
        ) or 0

    organization = await session.get(Organization, ctx.org_id)
    context = base_context(request, settings, ctx, await operator_name(session, ctx), "dashboard")
    context.update(
        {
            "org_name": organization.name if organization else ctx.org_slug,
            "stats": {
                "available": available,
                "ours": ours,
                "circles": len(circle_grants),
                "awaiting_review": awaiting,
            },
            "recent": recent,
        }
    )
    return render(request, "dashboard.html", context)


# ---------------------------------------------------------------------------
# Submissions
# ---------------------------------------------------------------------------
def _submission_row(item: Submission) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "title": item.title,
        "state": str(item.state),
        "tlp": str(item.tlp),
        "tlp_label": tlp_label(item.tlp),
        "scope": str(item.discovery_scope).replace("_", " "),
        "created_at": stamp(item.created_at),
    }


@router.get("/submissions", response_class=HTMLResponse)
async def list_submissions(
    request: Request, settings: SettingsDep, session: SessionDep
) -> Response:
    """Submissions filed by this analyst's organisation."""
    ctx, _csrf_hash = await current_session(request, settings, session)
    rows = (
        (
            await session.execute(
                select(Submission)
                .where(Submission.submitter_org_id == ctx.org_id)
                .order_by(Submission.created_at.desc())
                .limit(200)
            )
        )
        .scalars()
        .all()
    )

    context = base_context(request, settings, ctx, await operator_name(session, ctx), "submissions")
    context.update(
        {
            "heading": "Your submissions",
            "subheading": "Everything your firm has filed.",
            "submissions": [_submission_row(row) for row in rows],
            "empty_message": "Your firm has not filed anything yet.",
        }
    )
    return render(request, "submissions.html", context)


@router.get("/review", response_class=HTMLResponse)
async def review_queue(request: Request, settings: SettingsDep, session: SessionDep) -> Response:
    """The hosting ISAC's validation queue.

    This is the human checkpoint that keeps AIVS clear of the
    coordinated-disclosure consent problem, so it gets its own screen rather
    than being a filter on a list.
    """
    ctx, _csrf_hash = await current_session(request, settings, session)
    if not can_review_submissions(ctx):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

    rows = (
        (
            await session.execute(
                select(Submission)
                .where(Submission.state.in_((SubmissionState.SUBMITTED, SubmissionState.VALIDATED)))
                .order_by(Submission.created_at)
                .limit(200)
            )
        )
        .scalars()
        .all()
    )

    context = base_context(request, settings, ctx, await operator_name(session, ctx), "review")
    context.update(
        {
            "heading": "Review queue",
            "subheading": "Nothing reaches members until it passes through here.",
            "submissions": [_submission_row(row) for row in rows],
            "empty_message": "Nothing is waiting for review.",
        }
    )
    return render(request, "submissions.html", context)


@router.get("/submissions/{submission_id}", response_class=HTMLResponse)
async def submission_detail(
    submission_id: uuid.UUID,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
) -> Response:
    """One submission, its history, and the actions this analyst may take."""
    ctx, csrf_hash = await current_session(request, settings, session)
    submission = await load_submission(session, submission_id)
    if submission is None or not can_view_submission(ctx, submission):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

    object_count = (
        await session.scalar(
            select(func.count())
            .select_from(StixObject)
            .where(StixObject.submission_id == submission.id)
        )
    ) or 0

    transitions = (
        (
            await session.execute(
                select(SubmissionTransition)
                .where(SubmissionTransition.submission_id == submission.id)
                .order_by(SubmissionTransition.at)
            )
        )
        .scalars()
        .all()
    )

    actions, circles = await _available_actions(session, ctx, submission)

    receipts: list[dict[str, Any]] | None = None
    if can_view_submission_receipts(ctx):
        rows = (
            await session.execute(
                select(
                    Organization.slug,
                    Acknowledgment.ack_type,
                    Acknowledgment.via,
                    func.min(Acknowledgment.created_at).label("first_at"),
                    func.count().label("occurrences"),
                )
                .join(Organization, Organization.id == Acknowledgment.org_id)
                .where(Acknowledgment.submission_id == submission.id)
                .group_by(Organization.slug, Acknowledgment.ack_type, Acknowledgment.via)
                .order_by(Organization.slug)
            )
        ).all()
        receipts = [
            {
                "org_slug": row.slug,
                "ack_type": str(row.ack_type),
                "via": str(row.via),
                "first_at": stamp(row.first_at),
                "occurrences": row.occurrences,
            }
            for row in rows
        ]

    context = base_context(request, settings, ctx, await operator_name(session, ctx), "submissions")
    context.update(
        {
            "submission": {
                **_submission_row(submission),
                "summary": submission.summary,
                "object_count": object_count,
                "anonymous": submission.distribute_anonymously,
                "distributed_at": stamp(submission.distributed_at),
            },
            "transitions": [
                {
                    "at": stamp(entry.at),
                    "from_state": str(entry.from_state) if entry.from_state else None,
                    "to_state": str(entry.to_state),
                    "reason": entry.reason,
                }
                for entry in transitions
            ],
            "actions": actions,
            "distribute_circles": circles,
            "receipts": receipts,
            "telemetry": await telemetry_rows(session, ctx, submission),
            "lint_hits": await lint_hits(session, ctx, submission),
            "csrf_token": request.cookies.get("aivs_csrf", ""),
        }
    )
    del csrf_hash
    return render(request, "submission_detail.html", context)


async def _available_actions(
    session: SessionDep, ctx: AuthContext, submission: Submission
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Which workflow verbs this caller may perform, and where they may release.

    Derived from the policy predicates rather than restated, so a button never
    appears for something the API would refuse.
    """
    verbs = [
        (SubmissionState.SUBMITTED, "submit", "Send for review", True),
        (SubmissionState.VALIDATED, "validate", "Accept for sharing", True),
        (SubmissionState.WITHDRAWN, "withdraw", "Withdraw", False),
    ]
    actions = [
        {"verb": verb, "label": label, "primary": primary, "acknowledge": []}
        for target, verb, label, primary in verbs
        if can_transition_submission(ctx, submission, target)
    ]
    for action in actions:
        if action["verb"] == "validate":
            # The AI gate's changes, each a checkbox the editor ticks by name:
            # a routine click must not carry a consequential machine change.
            raws = (
                (
                    await session.execute(
                        select(StixObject.raw).where(StixObject.submission_id == submission.id)
                    )
                )
                .scalars()
                .all()
            )
            action["acknowledge"] = await consequential_changes(session, submission, list(raws))

    circles: list[dict[str, Any]] = []
    if can_transition_submission(ctx, submission, SubmissionState.DISTRIBUTED):
        rows = (
            (
                await session.execute(
                    select(Circle).where(Circle.is_active.is_(True)).order_by(Circle.name)
                )
            )
            .scalars()
            .all()
        )
        circles = [
            {"id": str(row.id), "name": row.name, "minimum_tlp": tlp_label(row.minimum_tlp)}
            for row in rows
        ]

    return actions, circles


# ---------------------------------------------------------------------------
# Workflow actions
# ---------------------------------------------------------------------------
def _parse_distribute_form(form: Any) -> tuple[list[uuid.UUID], dt.datetime | None]:
    """Read the distribute form, or raise :class:`SubmissionError`.

    ``release_at`` arrives from an HTML ``datetime-local`` input, which carries
    no offset. It is interpreted as UTC and labelled as such in the form, rather
    than guessed from the browser -- a guess here would shift an embargo by
    whatever the analyst's timezone happens to be.
    """
    selected = [value for value in form.getlist("circle_ids") if isinstance(value, str)]
    if not selected:
        message = "select at least one circle to distribute to"
        raise SubmissionError(message)

    try:
        circle_ids = [uuid.UUID(value) for value in selected]
    except ValueError as exc:
        message = "a selected circle identifier was malformed"
        raise SubmissionError(message) from exc

    raw_release = str(form.get("release_at") or "").strip()
    if not raw_release:
        return circle_ids, None

    try:
        release_at = dt.datetime.fromisoformat(raw_release)
    except ValueError as exc:
        message = "the hold-until time could not be read"
        raise SubmissionError(message) from exc

    return circle_ids, release_at.replace(tzinfo=dt.UTC)


@router.post("/submissions/{submission_id}/{verb}")
async def perform_action(
    submission_id: uuid.UUID,
    verb: str,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()],
) -> Response:
    """Perform a workflow verb from the detail screen.

    Authorization is not re-implemented here: the same service functions the
    native API uses are called, so the portal cannot become a second, weaker
    door to the same operations.
    """
    ctx, csrf_hash = await current_session(request, settings, session)
    require_csrf(csrf_token, csrf_hash)

    submission = await load_submission(session, submission_id, for_update=True)
    if submission is None or not can_view_submission(ctx, submission):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

    targets = {
        "submit": SubmissionState.SUBMITTED,
        "validate": SubmissionState.VALIDATED,
        "withdraw": SubmissionState.WITHDRAWN,
    }
    if verb != "distribute" and verb not in targets:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

    if verb == "distribute":
        # Refuse before acting, exactly as the native API does. distribute_submission
        # performs no authorization of its own -- its contract puts that on the
        # caller -- and the only check made so far is can_view_submission, which
        # passes for the submitter. Relying on apply_transition to raise afterwards
        # meant the visibility rows, the attribution rewrite and the audit record
        # were all written first and then rolled back: correct only for as long as
        # nothing catches that exception.
        require(
            can_transition_submission(ctx, submission, SubmissionState.DISTRIBUTED),
            "portal_distribute",
        )

    response = redirect_within_portal(f"/portal/submissions/{submission_id}")

    try:
        # Form parsing lives inside the try: its failures ("select at least one
        # circle", "the hold-until time could not be read") are ordinary operator
        # mistakes raised as SubmissionError, and outside the block they reached
        # the catch-all handler and became a 500.
        if verb == "distribute":
            circle_ids, release_at = _parse_distribute_form(await request.form())
            await distribute_submission(
                session, ctx, submission, circle_ids=circle_ids, release_at=release_at
            )
            await apply_transition(session, ctx, submission, SubmissionState.DISTRIBUTED)
            # The same queue the API path writes, in the same transaction as the
            # visibility rows. Omitted here originally, so a distribution made
            # from this screen -- the one ISAC analysts actually work in --
            # notified nobody, silently. The asymmetry was sharpest in the case
            # that matters: an *embargoed* distribution was still announced,
            # because the sweeper queues at release, so only immediate
            # distributions went unannounced.
            await queue_visibility_notifications(
                session,
                submission_id=submission.id,
                circle_ids=list(circle_ids),
                visible_at=release_at or dt.datetime.now(dt.UTC),
            )
        elif verb == "submit":
            await submit_submission(
                session,
                ctx,
                submission,
                reason=None,
                hourly_limit=settings.contribution_hourly_limit,
                now=dt.datetime.now(dt.UTC),
            )
        elif verb == "validate":
            acknowledged = frozenset(
                str(value) for value in (await request.form()).getlist("acknowledge")
            )
            await apply_transition(
                session, ctx, submission, targets[verb], acknowledged_changes=acknowledged
            )
        else:
            await apply_transition(session, ctx, submission, targets[verb])
        await session.commit()
    except (SubmissionError, DistributionError, PublicationPausedError, ValueError) as exc:
        await session.rollback()
        await record_independently(
            action=AuditAction.ACCESS_DENIED,
            ctx=ctx,
            outcome="failure",
            resource_type="submission",
            resource_id=str(submission_id),
            details={"verb": verb, "error": str(exc)},
        )
        set_notice(response, settings, "error", str(exc))

    return response


# ---------------------------------------------------------------------------
# Filing
# ---------------------------------------------------------------------------
@router.get("/submit", response_class=HTMLResponse)
async def submit_form(request: Request, settings: SettingsDep, session: SessionDep) -> Response:
    ctx, _csrf_hash = await current_session(request, settings, session)
    context = base_context(request, settings, ctx, await operator_name(session, ctx), "submit")
    context.update({"form": {}, "error": None, "csrf_token": request.cookies.get("aivs_csrf", "")})
    return render(request, "submit.html", context)


def _first_validation_message(exc: ValidationError) -> str:
    """One readable line from a request-model error, naming the field."""
    error = exc.errors(include_input=False)[0]
    field = ".".join(str(part) for part in error.get("loc", ())) or "submission"
    return f"{field}: {error.get('msg', 'invalid value')}"


@router.post("/submit", response_class=HTMLResponse)
async def submit_finding(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
    title: Annotated[str, Form()],
    discovery_scope: Annotated[str, Form()],
    tlp: Annotated[str, Form()],
    bundle: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    summary: Annotated[str, Form()] = "",
    distribute_anonymously: Annotated[str, Form()] = "",
) -> Response:
    """Create a draft from the form.

    Calls the same service the API does, so the validation a member gets here is
    the validation they would get there.
    """
    ctx, csrf_hash = await current_session(request, settings, session)
    require_csrf(csrf_token, csrf_hash)

    form_values = {"title": title, "summary": summary, "bundle": bundle}

    def failure(message: str) -> Response:
        context = base_context(request, settings, ctx, "", "submit")
        context.update(
            {
                "form": form_values,
                "error": message,
                "csrf_token": request.cookies.get("aivs_csrf", ""),
            }
        )
        return TEMPLATES.TemplateResponse(
            request, "submit.html", context, status_code=status.HTTP_400_BAD_REQUEST
        )

    try:
        parsed = json.loads(bundle)
    except json.JSONDecodeError as exc:
        return failure(f"The bundle is not valid JSON: {exc.msg} (line {exc.lineno}).")

    # The API's own request model, so the two ingest surfaces cannot disagree
    # about what a legal submission is. They did: the form carried no length
    # bounds, an over-long title reached the database, and the member got an
    # opaque 500 instead of their form back (finding #7).
    # The scope goes to the model as the string the form sent. Converting it to
    # the enum first refused an unknown value with the enum's message and let a
    # reserved one through to the model's, so the form told the two apart.
    try:
        payload = SubmissionCreate.model_validate(
            {
                "title": title,
                "summary": summary or None,
                "tlp": TLP(tlp),
                "discovery_scope": discovery_scope,
                "distribute_anonymously": bool(distribute_anonymously),
                "bundle": parsed,
            }
        )
    except ValidationError as exc:
        return failure(_first_validation_message(exc))
    except ValueError as exc:
        return failure(str(exc))

    try:
        submission = await create_submission(
            session,
            ctx,
            title=payload.title,
            summary=payload.summary,
            tlp=payload.tlp,
            discovery_scope=payload.discovery_scope,
            distribute_anonymously=payload.distribute_anonymously,
            bundle=payload.bundle,
            filed_for=None,
            via="portal",
        )
        # One commit, so the submission and the record of it land together. A
        # second SUBMISSION_CREATED row used to be written here after the first
        # commit: two rows for one event in a table that cannot be corrected,
        # and a failure between them left the submission recorded only once.
        await session.commit()
    except (SubmissionError, ValueError) as exc:
        await session.rollback()
        return failure(str(exc))
    except STORAGE_ERRORS:
        await session.rollback()
        return failure(
            "Part of the submission is longer or otherwise different from what can "
            "be stored. Check the length of names and descriptions in the bundle."
        )

    return redirect_within_portal(f"/portal/submissions/{submission.id}")
