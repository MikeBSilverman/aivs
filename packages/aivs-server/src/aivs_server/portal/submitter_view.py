"""What the submission page shows its submitter alone: telemetry and the lint.

Both answer the submitter's own questions -- "did it matter?" before, "does my
text give me away?" -- and neither is shown to anyone else. Telemetry is
addressed to the submitter only (``api/telemetry.py`` says why the ISAC is not
its reader), and the lint checks the submitter's own name, which is nobody
else's concern.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import SubmissionState
from aivs_server.auth.context import AuthContext
from aivs_server.db.models import Organization, StixObject, Submission
from aivs_server.services.sanitisation import free_text_of, lint
from aivs_server.services.telemetry import Count, submission_telemetry

__all__ = ["lint_hits", "telemetry_rows"]

#: The portal's names for the engagement counts, in reading order.
_LABELS = (
    ("reach", "Organisations that could see it"),
    ("retrieved", "Collected it"),
    ("acknowledged", "Acknowledged it"),
    ("actioned", "Acted on it"),
)

#: Kinds of hit, as a submitter would say them.
_KIND_LABELS = {
    "own_organisation": "your organisation's name",
    "private_address": "an internal address",
    "internal_hostname": "an internal hostname",
    "email_address": "an email address",
    "sar_language": "suspicious-activity-report language",
}


def _shown(count: Count) -> dict[str, Any]:
    return {"value": count.value, "withheld": count.withheld}


async def telemetry_rows(
    session: AsyncSession, ctx: AuthContext, submission: Submission
) -> dict[str, Any] | None:
    """The submitter's telemetry, or ``None`` for anyone else or before distribution."""
    if submission.submitter_org_id != ctx.org_id:
        return None
    telemetry = await submission_telemetry(session, submission)
    if not telemetry.distributed:
        return None
    return {
        "rows": [{"label": label, **_shown(getattr(telemetry, name))} for name, label in _LABELS],
        "later": list(telemetry.later),
        "as_of": None
        if telemetry.as_of is None
        else telemetry.as_of.strftime("%Y-%m-%d %H:%M UTC"),
    }


async def _stored_free_text(session: AsyncSession, submission: Submission) -> dict[str, str]:
    objects = (
        await session.execute(
            select(StixObject.raw).where(StixObject.submission_id == submission.id)
        )
    ).scalars()
    fields = {"title": submission.title, "summary": submission.summary or ""}
    return fields | free_text_of({"objects": list(objects)})


async def lint_hits(
    session: AsyncSession, ctx: AuthContext, submission: Submission
) -> list[dict[str, str]] | None:
    """Spans in the submitter's own draft worth a second look, or ``None``.

    Only while it is a draft, when the submitter can still change it; after
    that the answer would be a worry with nothing to do about it.
    """
    if submission.submitter_org_id != ctx.org_id or submission.state != SubmissionState.DRAFT:
        return None
    organisation = await session.get(Organization, ctx.org_id)
    own_names = [ctx.org_slug, organisation.name] if organisation else [ctx.org_slug]
    hits = lint(await _stored_free_text(session, submission), own_names=own_names)
    return [{"field": hit.field, "kind": _KIND_LABELS[hit.kind], "text": hit.text} for hit in hits]
