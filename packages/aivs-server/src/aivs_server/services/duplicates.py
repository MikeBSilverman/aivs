"""Possible duplicates of a submission's vulnerabilities: same CVE, package, platform or weakness.

Who is compared against what is the security property here. A member's
candidates are its own other submissions and what has been distributed to it,
nothing more: a duplicate check over everything stored would answer "has anyone
already reported a finding in this product?", which is the existence oracle
SF-47 forbids. The ISAC's reviewers compare against everything, because
recognising the same finding filed twice is their job.

The keys, strongest first: ``cve_id``; a ``purl`` or ``cpe`` in
``affected_products``; a shared CWE id. A CWE alone is weak -- many findings
share CWE-79 -- so each candidate says which key matched, and the reader
weighs it.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Select, false, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import SubmissionState
from aivs_schemas.extension.builders import AIVS_EXTENSION_ID, AIVS_INTEL_EXTENSION_ID
from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import can_review_submissions, distribution_visibility_clause
from aivs_server.db.models import Distribution, StixObject, Submission
from aivs_server.services.attribution import submitted_by

__all__ = ["Candidate", "duplicate_candidates"]

_MAX_CANDIDATES: Final[int] = 50
_EXTENSIONS: Final[tuple[str, ...]] = (AIVS_INTEL_EXTENSION_ID, AIVS_EXTENSION_ID)


@dataclass(frozen=True)
class Candidate:
    match_on: str
    value: str
    stix_id: str
    #: Only where the caller may open the record: its own, or any for the ISAC.
    submission_id: uuid.UUID | None


@dataclass(frozen=True)
class _Keys:
    cve_ids: frozenset[str]
    purls: frozenset[str]
    cpes: frozenset[str]
    cwe_ids: frozenset[str]


async def duplicate_candidates(
    session: AsyncSession, ctx: AuthContext, submission: Submission, *, now: dt.datetime
) -> list[Candidate]:
    """Vulnerabilities, outside ``submission``, that share a key with one inside it."""
    keys = await _keys_of(session, submission.id)
    sees_everything = can_review_submissions(ctx)
    candidates: list[Candidate] = []
    for match_on, value, condition in _conditions(keys):
        rows = (
            await session.execute(
                _scope(ctx, sees_everything, now)
                .where(condition, StixObject.submission_id != submission.id)
                .limit(_MAX_CANDIDATES)
            )
        ).all()
        candidates.extend(
            Candidate(
                match_on, value, stix_id, _openable(sub_id, own, sees_everything=sees_everything)
            )
            for stix_id, sub_id, own in rows
        )
    return _distinct(candidates)[:_MAX_CANDIDATES]


def _scope(ctx: AuthContext, sees_everything: bool, now: dt.datetime) -> Select[Any]:
    """The vulnerabilities ``ctx`` may be told about: its own, plus what reached it.

    Each row says whether it is the caller's own, never whose it is.
    """
    own = Submission.id.in_(submitted_by(ctx.org_id))
    query = (
        select(StixObject.stix_id, Submission.id, own.label("own"))
        .join(Submission, Submission.id == StixObject.submission_id)
        .where(StixObject.type == "vulnerability", Submission.state != SubmissionState.WITHDRAWN)
    )
    if sees_everything:
        return query
    received = (
        select(Distribution.stix_object_id)
        .join(Submission, Submission.id == Distribution.submission_id)
        .where(distribution_visibility_clause(ctx, now))
    )
    return query.where(or_(own, StixObject.id.in_(received)))


def _openable(submission_id: uuid.UUID, own: bool, *, sees_everything: bool) -> uuid.UUID | None:
    return submission_id if sees_everything or own else None


def _conditions(keys: _Keys) -> Iterable[tuple[str, str, Any]]:
    for cve_id in sorted(keys.cve_ids):
        yield "cve_id", cve_id, StixObject.cve_id == cve_id
    for purl in sorted(keys.purls):
        yield "purl", purl, _affected_product_has("purl", purl)
    for cpe in sorted(keys.cpes):
        yield "cpe", cpe, _affected_product_has("cpe", cpe)
    for cwe_id in sorted(keys.cwe_ids):
        yield "cwe", cwe_id, StixObject.cwe_ids.contains([cwe_id])


def _affected_product_has(field: str, value: str) -> Any:
    return or_(
        false(),
        *(
            StixObject.raw.contains({"extensions": {ext: {"affected_products": [{field: value}]}}})
            for ext in _EXTENSIONS
        ),
    )


async def _keys_of(session: AsyncSession, submission_id: uuid.UUID) -> _Keys:
    rows = (
        await session.execute(
            select(StixObject.cve_id, StixObject.cwe_ids, StixObject.raw).where(
                StixObject.submission_id == submission_id, StixObject.type == "vulnerability"
            )
        )
    ).all()
    cve_ids = {cve_id for cve_id, _cwe, _raw in rows if cve_id}
    cwe_ids = {cwe for _cve, cwes, _raw in rows for cwe in (cwes or [])}
    products = [product for _cve, _cwe, raw in rows for product in _affected_products(raw)]
    return _Keys(
        cve_ids=frozenset(cve_ids),
        purls=frozenset(p["purl"] for p in products if isinstance(p.get("purl"), str)),
        cpes=frozenset(p["cpe"] for p in products if isinstance(p.get("cpe"), str)),
        cwe_ids=frozenset(cwe_ids),
    )


def _affected_products(raw: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    extensions = raw.get("extensions") or {}
    for ext in _EXTENSIONS:
        body = extensions.get(ext)
        if isinstance(body, Mapping) and isinstance(body.get("affected_products"), list):
            return [p for p in body["affected_products"] if isinstance(p, Mapping)]
    return []


def _distinct(candidates: list[Candidate]) -> list[Candidate]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Candidate] = []
    for candidate in candidates:
        key = (candidate.match_on, candidate.value, candidate.stix_id)
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique
