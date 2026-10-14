"""Making members share: one-click contributions, posture, proxy filing, post-moderation.

Every route here files or reads through the services that hold the rules
(``services.contributions``, ``services.posture``, ``services.proxy_filing``);
the routes translate their outcomes. An object or posture the caller may not
see answers 404, exactly as an absent one does.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from aivs_schemas.enums import (
    TLP,
    DiscoveryScope,
    PostureStatus,
    SubmissionState,
    VexJustification,
)
from aivs_schemas.extension.builders import (
    BundleValidationError,
    ExtensionValidationError,
    UnknownExtensionError,
)
from aivs_schemas.models import SubmissionCreate, SubmissionOut
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.deps import AuthenticatedContext, SessionDep, SettingsDep
from aivs_server.auth.policy import (
    can_review_submissions,
    can_view_submission,
    is_isac_editor,
    require,
)
from aivs_server.db.models import Circle
from aivs_server.services.contributions import (
    ContributionRateLimitedError,
    OneClick,
    TargetNotFoundError,
    contribute,
)
from aivs_server.services.posture import (
    PostureError,
    VexStatement,
    own_posture,
    own_postures,
    posture_summary,
    record_posture,
)
from aivs_server.services.proxy_filing import confirm_proxy_filing, file_on_behalf
from aivs_server.services.submissions import STORAGE_ERRORS, SubmissionError, load_submission
from aivs_server.services.vex_export import openvex_document

__all__ = ["router"]

router = APIRouter(prefix="/api/v1", tags=["contributions"])

_NOT_FOUND = HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")
_CLIENT_ERRORS = (
    SubmissionError,
    BundleValidationError,
    ExtensionValidationError,
    UnknownExtensionError,
)
_RATE_LIMITED = HTTPException(
    status.HTTP_429_TOO_MANY_REQUESTS,
    detail="this organisation's hourly allowance for unreviewed contributions is used",
)


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ContributionIn(_In):
    #: In the body, never the path: request lines are logged with the caller's
    #: identity and forwarded off the platform, and "firm X sighted V at t" is
    #: exactly what a member's click must not leave behind there (SF-66).
    target: Annotated[str, Field(min_length=1, max_length=100)]
    kind: OneClick


class ContributionOut(BaseModel):
    submission_id: uuid.UUID
    state: SubmissionState
    lane: str


#: Prose a member writes for itself and its regulator: multi-line, bounded, and
#: free of NUL, which PostgreSQL refuses in text and would otherwise turn a
#: member's typo into a server error.
_Statement = Annotated[str, Field(min_length=1, max_length=2000, pattern=r"^[^\x00]+$")]
#: One line per product: a PURL, a CPE, or a name.
_Product = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f]+$")]


class PostureIn(_In):
    #: In the body, never the path: request lines are logged with the caller's
    #: identity and forwarded off the platform (SF-70).
    vulnerability: Annotated[str, Field(min_length=1, max_length=100)]
    #: The one-click's default: never ``affected`` unless the member says so.
    status: PostureStatus = PostureStatus.UNDER_INVESTIGATION
    justification: VexJustification | None = None
    impact_statement: _Statement | None = None
    action_statement: _Statement | None = None
    products: Annotated[list[_Product], Field(max_length=50)] = []
    detection_deployed: bool = False
    #: "We confirmed, now, that this holds." The server records when.
    validated: bool = False
    evidence_note: _Statement | None = None

    def statement(self) -> VexStatement:
        return VexStatement(
            status=self.status,
            justification=self.justification,
            impact_statement=self.impact_statement,
            action_statement=self.action_statement,
            products=tuple(self.products),
            detection_deployed=self.detection_deployed,
            validated=self.validated,
            evidence_note=self.evidence_note,
        )


class PostureOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vulnerability_stix_id: str
    status: PostureStatus
    justification: VexJustification | None
    impact_statement: str | None
    action_statement: str | None
    products: list[str]
    detection_deployed: bool
    validated_at: dt.datetime | None
    evidence_note: str | None
    updated_at: dt.datetime


class CountOut(BaseModel):
    value: int | None
    withheld: str | None


class PostureSummaryOut(BaseModel):
    vulnerability: str
    total: CountOut
    by_status: dict[PostureStatus, CountOut]


class PostModerationIn(_In):
    enabled: bool


class OnBehalfIn(SubmissionCreate):
    """A filing an editor makes for a member, with the member's consent artefact."""

    on_behalf_of: uuid.UUID
    consent_sha256: Annotated[str, Field(min_length=64, max_length=64)]
    #: Anonymous unless the member asked to be named (SF-68).
    distribute_anonymously: bool = True


def _present(submission: Any, ctx: Any) -> SubmissionOut:
    """The submission as this caller may see it: an anonymous submitter to itself alone.

    The rule the submissions API applies, here too: the editor who filed for
    a member names it, like any ISAC reader, only through the audited reveal.
    """
    out = SubmissionOut.model_validate(submission)
    if submission.distribute_anonymously and submission.submitter_org_id != ctx.org_id:
        out = out.model_copy(update={"submitter_org_id": None})
    return out


# ---------------------------------------------------------------------------
# One click
# ---------------------------------------------------------------------------
@router.post("/contributions", status_code=status.HTTP_201_CREATED, response_model=ContributionOut)
async def one_click(
    payload: ContributionIn,
    ctx: AuthenticatedContext,
    session: SessionDep,
    settings: SettingsDep,
) -> ContributionOut:
    """ "We see this too", "works", "doesn't work": the server builds the STIX.

    Published at once when the lane rule allows; otherwise filed for review.
    """
    try:
        submission = await contribute(
            session,
            ctx,
            target_id=payload.target,
            kind=payload.kind,
            hourly_limit=settings.contribution_hourly_limit,
            now=dt.datetime.now(dt.UTC),
        )
        await session.commit()
    except TargetNotFoundError:
        raise _NOT_FOUND from None
    except ContributionRateLimitedError:
        raise _RATE_LIMITED from None
    except _CLIENT_ERRORS as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return ContributionOut(
        submission_id=submission.id, state=submission.state, lane=submission.lane.value
    )


# ---------------------------------------------------------------------------
# Posture
# ---------------------------------------------------------------------------
@router.put("/postures", response_model=PostureOut)
async def set_posture(payload: PostureIn, ctx: AuthenticatedContext, session: SessionDep) -> Any:
    """Set this organisation's posture on a vulnerability it can see. Private to it."""
    try:
        row = await record_posture(
            session,
            ctx,
            vulnerability_id=payload.vulnerability,
            statement=payload.statement(),
            now=dt.datetime.now(dt.UTC),
        )
        await session.commit()
    except TargetNotFoundError:
        raise _NOT_FOUND from None
    except PostureError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    await session.refresh(row)
    return row


@router.get("/postures", response_model=list[PostureOut])
async def list_postures(ctx: AuthenticatedContext, session: SessionDep) -> Any:
    """This organisation's own postures. Nobody else's, whoever asks."""
    return await own_postures(session, ctx)


@router.get("/postures/openvex")
async def export_postures(ctx: AuthenticatedContext, session: SessionDep) -> dict[str, Any]:
    """This organisation's own postures as an OpenVEX document. Nobody else's.

    Declared before ``/postures/{posture_id}``, which would otherwise take
    "openvex" for an id and refuse it as malformed.
    """
    document = await openvex_document(session, ctx, now=dt.datetime.now(dt.UTC))
    # The act, never the content or the number of statements: the audit log is
    # the ISAC's, and a count of postures is a fact about the firm's exposure.
    await record(
        session,
        action=AuditAction.POSTURE_EXPORTED,
        ctx=ctx,
        resource_type="posture",
        resource_id=str(ctx.org_id),
        details={},
    )
    await session.commit()
    return document


@router.get("/postures/{posture_id}", response_model=PostureOut)
async def get_posture(posture_id: uuid.UUID, ctx: AuthenticatedContext, session: SessionDep) -> Any:
    """One posture row: its own organisation only. Everyone else, the ISAC included, 404."""
    row = await own_posture(session, ctx, posture_id)
    if row is None:
        raise _NOT_FOUND
    return row


@router.get("/vulnerabilities/{stix_id}/posture-summary", response_model=PostureSummaryOut)
async def get_posture_summary(
    stix_id: str, ctx: AuthenticatedContext, session: SessionDep
) -> PostureSummaryOut:
    """Counts per status for the ISAC's reviewers, each withheld below k.

    The id may sit in this path: the caller is the ISAC, and the request says
    nothing about any member.
    """
    if not can_review_submissions(ctx):
        raise _NOT_FOUND
    summary = await posture_summary(session, stix_id)
    if summary is None:
        raise _NOT_FOUND
    return PostureSummaryOut(
        vulnerability=stix_id,
        total=CountOut(value=summary.total.value, withheld=summary.total.withheld),
        by_status={
            status_: CountOut(value=count.value, withheld=count.withheld)
            for status_, count in summary.by_status.items()
        },
    )


# ---------------------------------------------------------------------------
# Post-moderation
# ---------------------------------------------------------------------------
@router.put("/circles/{circle_id}/post-moderation", status_code=status.HTTP_204_NO_CONTENT)
async def set_post_moderation(
    circle_id: uuid.UUID, payload: PostModerationIn, ctx: AuthenticatedContext, session: SessionDep
) -> None:
    """Let a circle take short contributions on public content without review. Editors only."""
    require(is_isac_editor(ctx), "post_moderation_requires_isac_editor")
    circle = await session.get(Circle, circle_id, with_for_update=True)
    if circle is None:
        raise _NOT_FOUND
    circle.post_moderated = payload.enabled
    await record(
        session,
        action=AuditAction.CIRCLE_POST_MODERATION_SET,
        ctx=ctx,
        resource_type="circle",
        resource_id=str(circle.id),
        details={"enabled": payload.enabled},
    )
    await session.commit()


# ---------------------------------------------------------------------------
# Analyst-proxy filing
# ---------------------------------------------------------------------------
@router.post(
    "/submissions/on-behalf", status_code=status.HTTP_201_CREATED, response_model=SubmissionOut
)
async def file_for_member(
    payload: OnBehalfIn, ctx: AuthenticatedContext, session: SessionDep
) -> SubmissionOut:
    """File a member's contribution for it, on its consent (SF-68). Editors only."""
    content = {
        "title": payload.title,
        "summary": payload.summary,
        "tlp": TLP(payload.tlp),
        "discovery_scope": DiscoveryScope(payload.discovery_scope),
        "distribute_anonymously": payload.distribute_anonymously,
        "bundle": payload.bundle,
    }
    try:
        submission = await file_on_behalf(
            session,
            ctx,
            org_id=payload.on_behalf_of,
            consent_sha256=payload.consent_sha256,
            content=content,
            now=dt.datetime.now(dt.UTC),
        )
        await session.commit()
    except _CLIENT_ERRORS as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except STORAGE_ERRORS as exc:
        await session.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="Submission content rejected by storage"
        ) from exc
    await session.refresh(submission)
    return _present(submission, ctx)


@router.post("/submissions/{submission_id}/confirm", response_model=SubmissionOut)
async def confirm(
    submission_id: uuid.UUID, ctx: AuthenticatedContext, session: SessionDep
) -> SubmissionOut:
    """The member confirms a filing made in its name."""
    submission = await load_submission(session, submission_id, for_update=True)
    if submission is None or not can_view_submission(ctx, submission):
        raise _NOT_FOUND
    try:
        await confirm_proxy_filing(session, ctx, submission, now=dt.datetime.now(dt.UTC))
    except SubmissionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await session.commit()
    await session.refresh(submission)
    return _present(submission, ctx)
