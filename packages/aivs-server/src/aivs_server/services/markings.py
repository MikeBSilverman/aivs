"""TLP markings are stamped by the server, and a contribution inherits its referents' (SF-49).

TLP is a column on the submission, decided by the submitter and checked against
each circle's floor. Two gaps followed from leaving the objects themselves
alone:

**The objects did not say how to handle them.** A member's TIP reads
``object_marking_refs``; the submission column never leaves the server. An
object distributed AMBER+STRICT with no marking reaches a TIP that treats it as
unmarked, and one carrying a CLEAR marking the submitter wrote reaches it as
shareable with anyone. So at distribution the submission's TLP marking is
stamped onto every object, exactly as ``created_by_ref`` is rewritten, and an
object already carrying a *different* TLP marking is refused rather than
silently corrected: the submitter said two things, and the server will not pick
one for them.

The stamp sets ``object_marking_refs`` only. A TLP in ``granular_markings``
applies to the properties it selects and is read over the object's own, so a
granular TLP other than the submission's is refused too, wherever the content
rules run (ingest, validate, distribution).

**A derivative could launder its referent.** A CLEAR ``opinion`` on an
AMBER+STRICT vulnerability repeats, at CLEAR, that the vulnerability exists and
what someone thinks of it. A contribution's TLP must be at least as restrictive
as every object it references. At ingest only against referents the submitter
can see (its own, and what has been distributed to it), so the refusal says
nothing about objects it cannot; at validate and distribution against all of
them, by the ISAC, which sees everything.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Mapping
from typing import Any, Final

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import TLP, TLP_RESTRICTIVENESS, tlp_at_least_as_restrictive
from aivs_schemas.tlp import is_tlp_marking_id, marking_id_for
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import distribution_visibility_clause
from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.services.attribution import submitted_by

__all__ = ["granular_tlp_problem", "looser_than_referents_problem", "stamp_tlp_marking"]

#: Object types that carry no handling marking of their own: definitions, not
#: content.
_UNMARKED_TYPES: Final[frozenset[str]] = frozenset({"marking-definition"})


def stamp_tlp_marking(raw: Mapping[str, Any], tlp: TLP) -> dict[str, Any]:
    """``raw`` with the submission's TLP marking, or ``ValueError`` on a conflict.

    Other markings (a statement marking, say) are kept: they add to TLP rather
    than compete with it.
    """
    if raw.get("type") in _UNMARKED_TYPES:
        return dict(raw)
    stamped = marking_id_for(tlp)
    existing = [ref for ref in raw.get("object_marking_refs") or [] if isinstance(ref, str)]
    conflicting = sorted({ref for ref in existing if is_tlp_marking_id(ref) and ref != stamped})
    if conflicting:
        msg = (
            f"object {raw.get('id', '<no id>')} is marked {', '.join(conflicting)} but the "
            f"submission is {tlp.value}; remove the marking or change the submission's TLP"
        )
        raise ValueError(msg)
    others = [ref for ref in existing if ref != stamped]
    return {**raw, "object_marking_refs": [stamped, *others]}


def _granular_marking_refs(raw: Mapping[str, Any]) -> list[str]:
    granular = raw.get("granular_markings")
    if not isinstance(granular, list):
        return []
    return [
        marking["marking_ref"]
        for marking in granular
        if isinstance(marking, Mapping) and isinstance(marking.get("marking_ref"), str)
    ]


def granular_tlp_problem(objects: Iterable[Mapping[str, Any]], tlp: TLP) -> str | None:
    """Why objects may not carry their granular TLP markings at ``tlp``, or ``None`` (SF-49).

    A granular marking applies a TLP to the properties it selects, and a TIP
    honours it over the object's own marking. The stamp sets the object's
    marking only, so a CLEAR granular marking inside an AMBER submission went
    out unchanged and made its content shareable with anyone. Refused, as an
    object-level conflict is, rather than stripped: the submitter said two
    things. A granular marking at the submission's TLP says one, and is kept.
    """
    stamped = marking_id_for(tlp)
    conflicting = sorted(
        str(raw.get("id", "<no id>"))
        for raw in objects
        if any(is_tlp_marking_id(ref) and ref != stamped for ref in _granular_marking_refs(raw))
    )
    if not conflicting:
        return None
    return (
        f"objects carry a TLP in granular_markings other than the submission's {tlp.value}: "
        f"{', '.join(conflicting)}. TLP is set per submission; remove the granular TLP "
        "marking or change the submission's TLP"
    )


async def _referent_tlps(
    session: AsyncSession, referenced: set[str], *, visible_to: AuthContext | None, now: dt.datetime
) -> dict[str, TLP]:
    """The strictest TLP each referenced id carries, among the rows in scope.

    ``visible_to=None`` is the ISAC's view: every distributed row. Otherwise
    only rows that caller may read, and its own submissions in any state.
    """
    query = (
        select(StixObject.stix_id, Submission.tlp)
        .join(Submission, Submission.id == StixObject.submission_id)
        .outerjoin(Distribution, Distribution.stix_object_id == StixObject.id)
        .where(StixObject.stix_id.in_(referenced))
    )
    if visible_to is None:
        query = query.where(Distribution.id.is_not(None))
    else:
        query = query.where(
            or_(
                Submission.id.in_(submitted_by(visible_to.org_id)),
                distribution_visibility_clause(visible_to, now),
            )
        )
    strictest: dict[str, TLP] = {}
    for stix_id, tlp in (await session.execute(query)).all():
        current = strictest.get(stix_id)
        if current is None or TLP_RESTRICTIVENESS[tlp] > TLP_RESTRICTIVENESS[current]:
            strictest[stix_id] = tlp
    return strictest


async def looser_than_referents_problem(
    session: AsyncSession,
    *,
    tlp: TLP,
    referenced: Iterable[str],
    visible_to: AuthContext | None,
    now: dt.datetime,
) -> str | None:
    """Why a contribution at ``tlp`` may not reference these objects, or ``None``."""
    ids = set(referenced)
    if not ids:
        return None
    tlps = await _referent_tlps(session, ids, visible_to=visible_to, now=now)
    stricter = sorted(
        f"{stix_id} ({referent.value})"
        for stix_id, referent in tlps.items()
        if not tlp_at_least_as_restrictive(tlp, referent)
    )
    if not stricter:
        return None
    return (
        f"this submission is {tlp.value}, looser than objects it references: "
        f"{', '.join(stricter)}. A contribution is at least as restrictive as what it is about."
    )
