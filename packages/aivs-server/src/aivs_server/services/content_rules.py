"""The content rules that hold at the moment content becomes readable.

Owner-only versioning (SF-48), newest-version-only (SF-82), an object's
anonymity fixed by its first distribution (SF-85), the disclosure split (SF-7),
TLP inheritance
(SF-49) and identifiers registered to another organisation are each checked at
validate. They are checked again when content becomes readable, because what
they are decided by can change in between -- a disclosure withdrawn, a
referent re-marked stricter, an organisation enrolled under an identifier the
bundle used -- and that moment is the last at which the content can still be
refused.

Content becomes readable twice over: at distribution, and, for an embargo, at
release, which can be days later. Both ask here, so the list of rules has one
definition: a rule added to one path and not the other is the gap this module
exists to close (W-P1: release relied on the check made at distribution).

Asked from the ISAC's view of everything (``visible_to=None``): the actor is
the ISAC, and nothing here is shown to a member.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.db.models import Submission
from aivs_server.services.anonymity import anonymity_change_problem
from aivs_server.services.ownership import foreign_owned_versions_problem, stale_version_problem
from aivs_server.services.submissions import contribution_problem, foreign_identity_ids

__all__ = ["content_problem"]


async def content_problem(
    session: AsyncSession,
    submission: Submission,
    objects: Sequence[Mapping[str, Any]],
    *,
    now: dt.datetime,
) -> str | None:
    """Why ``submission``'s ``objects`` may not become readable now, or ``None``."""
    raws = list(objects)
    owned = await foreign_owned_versions_problem(
        session, raws, owner_org_id=submission.submitter_org_id
    )
    if owned is not None:
        return owned
    stale = await stale_version_problem(session, submission)
    if stale is not None:
        return stale
    anonymity = await anonymity_change_problem(session, submission)
    if anonymity is not None:
        return anonymity
    contribution = await contribution_problem(session, submission, raws, visible_to=None, now=now)
    if contribution is not None:
        return contribution
    return await _foreign_identity_problem(session, submission, raws)


async def _foreign_identity_problem(
    session: AsyncSession, submission: Submission, objects: list[Mapping[str, Any]]
) -> str | None:
    """Identity objects whose identifier is registered to another organisation."""
    impersonated = await foreign_identity_ids(
        session, objects, submitter_org_id=submission.submitter_org_id
    )
    if impersonated:
        return (
            "identity objects may not use an identifier registered to another "
            f"organisation: {', '.join(impersonated)}"
        )
    return None
