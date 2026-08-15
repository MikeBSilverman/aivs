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
from pathlib import Path
from typing import Annotated, Any, Final

from fastapi import APIRouter, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import func, select

from aivs_schemas.enums import TLP, CertStatus, DiscoveryScope, OrgStatus, SubmissionState
from aivs_schemas.tlp import TLP_NAMES
from aivs_server.audit.log import AuditAction, record_independently
from aivs_server.auth.context import AuthContext
from aivs_server.auth.deps import SessionDep, SettingsDep
from aivs_server.auth.mtls import CertificateRejectedError, extract_client_certificate
from aivs_server.auth.passwords import constant_time_equals
from aivs_server.auth.policy import (
    can_transition_submission,
    can_view_submission,
    can_view_submission_receipts,
    is_system_admin,
    readable_circle_ids,
    require,
    visible_content_clause,
)
from aivs_server.auth.sessions import (
    SessionRejectedError,
    authenticate_operator,
    establish_session,
    resolve_session,
    revoke_session,
)
from aivs_server.config import Settings
from aivs_server.db.models import (
    Acknowledgment,
    Circle,
    ClientCertificate,
    Distribution,
    Operator,
    Organization,
    StixObject,
    Submission,
    SubmissionTransition,
)
from aivs_server.services.distribution import DistributionError, distribute_submission
from aivs_server.services.submissions import (
    SubmissionError,
    apply_transition,
    create_submission,
    load_submission,
)

__all__ = ["router"]

router = APIRouter(prefix="/portal", tags=["portal"])

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

#: One message for every login failure. Which of the three inputs was wrong is
#: half the credential.
_LOGIN_FAILED = "Those credentials were not accepted."


# ---------------------------------------------------------------------------
# Session plumbing
# ---------------------------------------------------------------------------
def _client_fingerprint(request: Request, settings: Settings) -> str | None:
    """Fingerprint of the certificate on this request, or ``None``.

    The portal is reached through the same mTLS proxy as everything else, so
    this is the organisation's identity. Absent means the deployment is not
    behind the proxy, which the session binding then refuses.
    """
    headers = {key.lower(): value for key, value in request.headers.items()}
    peer = request.client.host if request.client else None
    try:
        return extract_client_certificate(settings, headers, peer).fingerprint_sha256
    except CertificateRejectedError:
        return None


async def _current_session(
    request: Request, settings: Settings, session: SessionDep
) -> tuple[AuthContext, str]:
    """Resolve the signed-in analyst, or redirect to the login page."""
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise _redirect_to_login()
    try:
        return await resolve_session(
            session,
            settings,
            token=token,
            cert_fingerprint=_client_fingerprint(request, settings),
            request_id=request.scope.get("aivs_request_id", ""),
            source_ip=request.client.host if request.client else None,
        )
    except SessionRejectedError as exc:
        await record_independently(
            action=AuditAction.SESSION_REJECTED,
            outcome="denied",
            request_id=request.scope.get("aivs_request_id"),
            source_ip=request.client.host if request.client else None,
            details={"reason": exc.reason, "path": request.url.path},
        )
        raise _redirect_to_login() from exc


def _redirect_to_login() -> HTTPException:
    """A redirect expressed as an exception, so callers can raise it inline."""
    return HTTPException(
        status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/portal/login"}
    )


def _require_csrf(submitted: str, expected_hash: str) -> None:
    """Reject a form post whose CSRF token does not match the session.

    Compared as digests in constant time. A missing or wrong token is a 403 with
    no detail: a cross-site attempt should learn nothing about why it failed.
    """
    digest = hashlib.sha256(submitted.encode("utf-8")).hexdigest()
    if not constant_time_equals(digest, expected_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Invalid form token")


def _base_context(
    request: Request, settings: Settings, ctx: AuthContext, operator_name: str, active: str
) -> dict[str, Any]:
    return {
        "request": request,
        "instance_name": settings.instance_name,
        "org_slug": ctx.org_slug,
        "operator_name": operator_name,
        "is_admin": is_system_admin(ctx),
        "active": active,
        "notices": _take_notices(request),
        # Every authenticated page carries the sign-out form, so the token
        # belongs in the shared context rather than being threaded through each
        # route. Pages that mint their own still override it.
        "csrf_token": request.cookies.get("aivs_csrf", ""),
    }


#: Cookie carrying a one-shot notice across the redirect that follows a POST.
#: Signed so the message rendered back to the operator is one this server wrote,
#: and cleared as soon as it is read.
_NOTICE_COOKIE: Final[str] = "aivs_notice"
_NOTICE_SALT: Final[str] = "aivs.portal.notice.v1"
_NOTICE_MAX_AGE: Final[int] = 60


def _set_notice(response: Response, settings: Settings, level: str, message: str) -> None:
    """Attach a one-shot notice to a redirect response."""
    serializer = URLSafeTimedSerializer(
        settings.session_secret.get_secret_value(), salt=_NOTICE_SALT
    )
    response.set_cookie(
        _NOTICE_COOKIE,
        serializer.dumps({"level": level, "message": message}),
        max_age=_NOTICE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/portal",
    )


def _take_notices(request: Request) -> list[dict[str, str]]:
    """Read and consume any pending notice.

    Without this, a workflow verb that failed redirected to the same page as one
    that succeeded, with nothing to distinguish them -- so an operator who tried
    to distribute to a circle whose TLP floor refused the submission was shown
    the detail page and no message, and would reasonably conclude the members had
    been warned.
    """
    raw = request.cookies.get(_NOTICE_COOKIE)
    if not raw:
        return []

    settings: Settings = request.app.state.settings
    serializer = URLSafeTimedSerializer(
        settings.session_secret.get_secret_value(), salt=_NOTICE_SALT
    )
    try:
        payload = serializer.loads(raw, max_age=_NOTICE_MAX_AGE)
    except BadSignature:
        return []

    if not isinstance(payload, dict):
        return []
    level = str(payload.get("level", "error"))
    message = str(payload.get("message", ""))
    if not message:
        return []

    # Consumed, so _render clears it. A notice that survived the page it was
    # written for would reappear on the next reload and describe a failure that
    # had already been reported.
    request.state.aivs_notice_consumed = True
    return [{"level": level, "message": message}]


def _render(request: Request, template: str, context: dict[str, Any]) -> Response:
    """Render a portal template, clearing any notice this page just displayed."""
    response = _TEMPLATES.TemplateResponse(request, template, context)
    if getattr(request.state, "aivs_notice_consumed", False):
        response.delete_cookie(_NOTICE_COOKIE, path="/portal")
    return response


async def _operator_name(session: SessionDep, ctx: AuthContext) -> str:
    if ctx.operator_id is None:
        return ctx.org_slug
    operator = await session.get(Operator, ctx.operator_id)
    return operator.display_name if operator else ctx.org_slug


def _tlp_label(value: Any) -> str:
    try:
        return TLP_NAMES[TLP(str(value))]
    except (ValueError, KeyError):
        return str(value)


def _stamp(value: dt.datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M") if value else ""


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
    response = _TEMPLATES.TemplateResponse(
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
    _require_csrf(csrf_token, expected)

    fingerprint = _client_fingerprint(request, settings)
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
        )
    except SessionRejectedError as exc:
        return await _login_failure(request, settings, email, exc.reason)

    established = await establish_session(
        session,
        settings,
        operator=operator,
        cert_fingerprint=fingerprint,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    await record_independently(
        action=AuditAction.LOGIN_SUCCESS,
        actor_type="operator",
        actor_id=str(operator.id),
        org_id=org.id,
        outcome="success",
        request_id=request.scope.get("aivs_request_id"),
        source_ip=request.client.host if request.client else None,
    )

    response = RedirectResponse("/portal/", status_code=status.HTTP_303_SEE_OTHER)
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
        source_ip=request.client.host if request.client else None,
        details={"reason": reason, "email": email},
    )
    token = uuid.uuid4().hex
    response = _TEMPLATES.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "instance_name": settings.instance_name,
            "csrf_token": token,
            "error": _LOGIN_FAILED,
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
    ctx, csrf_hash = await _current_session(request, settings, session)
    _require_csrf(csrf_token, csrf_hash)
    del ctx

    token = request.cookies.get(settings.session_cookie_name)
    if token:
        await revoke_session(session, token=token)
        await record_independently(
            action=AuditAction.LOGOUT,
            outcome="success",
            request_id=request.scope.get("aivs_request_id"),
            source_ip=request.client.host if request.client else None,
        )
    response = RedirectResponse("/portal/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(settings.session_cookie_name, path="/portal")
    response.delete_cookie("aivs_csrf", path="/portal")
    return response


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, settings: SettingsDep, session: SessionDep) -> Response:
    """What this analyst's firm can see, and what it has filed."""
    ctx, _csrf_hash = await _current_session(request, settings, session)
    now = dt.datetime.now(dt.UTC)
    circle_ids = readable_circle_ids(ctx)

    available = 0
    recent: list[dict[str, Any]] = []
    if circle_ids:
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
                .where(visible_content_clause(circle_ids, now))
                .order_by(Distribution.date_added.desc())
                .limit(10)
            )
        ).all()
        recent = [
            {
                "date_added": _stamp(row.date_added),
                "name": row.name or "(unnamed object)",
                "tlp": str(row.tlp),
                "tlp_label": _tlp_label(row.tlp),
            }
            for row in rows
        ]
        available = (
            await session.scalar(
                select(func.count(func.distinct(Distribution.submission_id)))
                .join(Submission, Submission.id == Distribution.submission_id)
                .where(visible_content_clause(circle_ids, now))
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
    if is_system_admin(ctx):
        awaiting = (
            await session.scalar(
                select(func.count())
                .select_from(Submission)
                .where(Submission.state == SubmissionState.SUBMITTED)
            )
        ) or 0

    organization = await session.get(Organization, ctx.org_id)
    context = _base_context(request, settings, ctx, await _operator_name(session, ctx), "dashboard")
    context.update(
        {
            "org_name": organization.name if organization else ctx.org_slug,
            "stats": {
                "available": available,
                "ours": ours,
                "circles": len(circle_ids),
                "awaiting_review": awaiting,
            },
            "recent": recent,
        }
    )
    return _render(request, "dashboard.html", context)


# ---------------------------------------------------------------------------
# Submissions
# ---------------------------------------------------------------------------
def _submission_row(item: Submission) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "title": item.title,
        "state": str(item.state),
        "tlp": str(item.tlp),
        "tlp_label": _tlp_label(item.tlp),
        "scope": str(item.discovery_scope).replace("_", " "),
        "created_at": _stamp(item.created_at),
    }


@router.get("/submissions", response_class=HTMLResponse)
async def list_submissions(
    request: Request, settings: SettingsDep, session: SessionDep
) -> Response:
    """Submissions filed by this analyst's organisation."""
    ctx, _csrf_hash = await _current_session(request, settings, session)
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

    context = _base_context(
        request, settings, ctx, await _operator_name(session, ctx), "submissions"
    )
    context.update(
        {
            "heading": "Your submissions",
            "subheading": "Everything your firm has filed.",
            "submissions": [_submission_row(row) for row in rows],
            "empty_message": "Your firm has not filed anything yet.",
        }
    )
    return _render(request, "submissions.html", context)


@router.get("/review", response_class=HTMLResponse)
async def review_queue(request: Request, settings: SettingsDep, session: SessionDep) -> Response:
    """The hosting ISAC's validation queue.

    This is the human checkpoint that keeps AIVS clear of the
    coordinated-disclosure consent problem, so it gets its own screen rather
    than being a filter on a list.
    """
    ctx, _csrf_hash = await _current_session(request, settings, session)
    if not is_system_admin(ctx):
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

    context = _base_context(request, settings, ctx, await _operator_name(session, ctx), "review")
    context.update(
        {
            "heading": "Review queue",
            "subheading": "Nothing reaches members until it passes through here.",
            "submissions": [_submission_row(row) for row in rows],
            "empty_message": "Nothing is waiting for review.",
        }
    )
    return _render(request, "submissions.html", context)


@router.get("/submissions/{submission_id}", response_class=HTMLResponse)
async def submission_detail(
    submission_id: uuid.UUID,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
) -> Response:
    """One submission, its history, and the actions this analyst may take."""
    ctx, csrf_hash = await _current_session(request, settings, session)
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
    if can_view_submission_receipts(ctx, submission):
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
                "first_at": _stamp(row.first_at),
                "occurrences": row.occurrences,
            }
            for row in rows
        ]

    context = _base_context(
        request, settings, ctx, await _operator_name(session, ctx), "submissions"
    )
    context.update(
        {
            "submission": {
                **_submission_row(submission),
                "summary": submission.summary,
                "object_count": object_count,
                "anonymous": submission.distribute_anonymously,
                "distributed_at": _stamp(submission.distributed_at),
            },
            "transitions": [
                {
                    "at": _stamp(entry.at),
                    "from_state": str(entry.from_state) if entry.from_state else None,
                    "to_state": str(entry.to_state),
                    "reason": entry.reason,
                }
                for entry in transitions
            ],
            "actions": actions,
            "distribute_circles": circles,
            "receipts": receipts,
            "csrf_token": request.cookies.get("aivs_csrf", ""),
        }
    )
    del csrf_hash
    return _render(request, "submission_detail.html", context)


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
        {"verb": verb, "label": label, "primary": primary}
        for target, verb, label, primary in verbs
        if can_transition_submission(ctx, submission, target)
    ]

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
            {"id": str(row.id), "name": row.name, "minimum_tlp": _tlp_label(row.minimum_tlp)}
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
    ctx, csrf_hash = await _current_session(request, settings, session)
    _require_csrf(csrf_token, csrf_hash)

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

    response = RedirectResponse(
        f"/portal/submissions/{submission_id}", status_code=status.HTTP_303_SEE_OTHER
    )

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
        else:
            await apply_transition(session, ctx, submission, targets[verb])
        await session.commit()
    except (SubmissionError, DistributionError, ValueError) as exc:
        await session.rollback()
        await record_independently(
            action=AuditAction.ACCESS_DENIED,
            ctx=ctx,
            outcome="failure",
            resource_type="submission",
            resource_id=str(submission_id),
            details={"verb": verb, "error": str(exc)},
        )
        _set_notice(response, settings, "error", str(exc))

    return response


# ---------------------------------------------------------------------------
# Filing
# ---------------------------------------------------------------------------
@router.get("/submit", response_class=HTMLResponse)
async def submit_form(request: Request, settings: SettingsDep, session: SessionDep) -> Response:
    ctx, _csrf_hash = await _current_session(request, settings, session)
    context = _base_context(request, settings, ctx, await _operator_name(session, ctx), "submit")
    context.update({"form": {}, "error": None, "csrf_token": request.cookies.get("aivs_csrf", "")})
    return _render(request, "submit.html", context)


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
    ctx, csrf_hash = await _current_session(request, settings, session)
    _require_csrf(csrf_token, csrf_hash)

    form_values = {"title": title, "summary": summary, "bundle": bundle}

    def failure(message: str) -> Response:
        context = _base_context(request, settings, ctx, "", "submit")
        context.update(
            {
                "form": form_values,
                "error": message,
                "csrf_token": request.cookies.get("aivs_csrf", ""),
            }
        )
        return _TEMPLATES.TemplateResponse(
            request, "submit.html", context, status_code=status.HTTP_400_BAD_REQUEST
        )

    try:
        parsed = json.loads(bundle)
    except json.JSONDecodeError as exc:
        return failure(f"The bundle is not valid JSON: {exc.msg} (line {exc.lineno}).")

    try:
        submission = await create_submission(
            session,
            ctx,
            title=title,
            summary=summary or None,
            tlp=TLP(tlp),
            discovery_scope=DiscoveryScope(discovery_scope),
            distribute_anonymously=bool(distribute_anonymously),
            bundle=parsed,
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

    return RedirectResponse(
        f"/portal/submissions/{submission.id}", status_code=status.HTTP_303_SEE_OTHER
    )
