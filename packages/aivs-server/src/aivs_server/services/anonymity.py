"""An object keeps the anonymity of its first distributed version (W2-C1).

Only the owner versions an object (``services.ownership``), so every version of
one ``stix_id`` is known to come from one organisation. An attributed version
followed by an anonymous one therefore links them: the anonymous version is
the credited firm's. The reverse names the anonymous version's submitter
after the fact, to every member who already holds it. Anonymity being the
default (Mike, Q16) makes the second the likelier mistake: a member that later
wants credit for a finding it filed anonymously.

So once a version of an object has been distributed, every later version
carries the same choice, and a member that wants the other one files a new
object. A draft, or a version withdrawn before distribution, pinned nothing:
no member ever held it.

Compared only with the owner's own distributed versions (the same owner token
on the same id, ``services.ownership``), so the refusal tells
a member nothing about an object it does not own -- whether another firm's
version exists is ``ownership.foreign_owned_versions_problem``'s to answer, at
validate, where the actor is the ISAC. That is what lets this check run at
ingest too, where the member can still fix the bundle. The ISAC's own filings
are attributed to the ISAC whatever the flag says, so there is nothing to
link and they are not checked.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.services.attribution import ISAC_OWNER

__all__ = ["anonymity_change_problem"]


async def anonymity_change_problem(session: AsyncSession, submission: Submission) -> str | None:
    """Why ``submission`` would change an object's anonymity, or ``None``."""
    first_choices = await _first_distributed_choices(session, submission)
    changed = sorted(
        (stix_id, anonymous)
        for stix_id, anonymous in first_choices.items()
        if anonymous != submission.distribute_anonymously
    )
    if not changed:
        return None
    listed = ", ".join(f"{stix_id} ({_described(anonymous)})" for stix_id, anonymous in changed)
    return (
        "an object keeps the anonymity of its first distributed version, so a later "
        f"version cannot change it; file a new object instead: {listed}"
    )


async def _first_distributed_choices(
    session: AsyncSession, submission: Submission
) -> dict[str, bool]:
    """For each object in ``submission``, the anonymity its owner first distributed it under.

    First by ``(date_added, seq)``, the order members received them in. The
    submission's own rows are left out, so an embargo release is not compared
    with itself. The same owner is the same owner token on the same id; the
    ISAC's (``ISAC_OWNER``) are skipped, there being nothing to link.
    """
    own = aliased(StixObject)
    other = aliased(StixObject)
    other_submission = aliased(Submission)
    rows = await session.execute(
        select(other.stix_id, other_submission.distribute_anonymously)
        .distinct(other.stix_id)
        .join(
            own,
            (own.stix_id == other.stix_id) & (own.owner_token == other.owner_token),
        )
        .join(Distribution, Distribution.stix_object_id == other.id)
        .join(other_submission, other_submission.id == other.submission_id)
        .where(
            own.submission_id == submission.id,
            own.owner_token != ISAC_OWNER,
            other.submission_id != submission.id,
        )
        .order_by(other.stix_id, Distribution.date_added, Distribution.seq)
    )
    return dict(rows.tuples().all())


def _described(anonymous: bool) -> str:
    return "distributed anonymously" if anonymous else "distributed with its submitter credited"
