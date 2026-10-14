"""A member's postures as an OpenVEX document: its own, for its own tools and regulator.

A serialiser over ``org_postures`` (SF-70): only the caller's organisation's
rows, so the export is exactly what the posture API already lets it read. The
rows are valid VEX by construction -- the database holds VEX's rules -- so this
module only maps names.

What is ours stays out. ``detection_deployed``, ``validated_at`` and
``evidence_note`` have no OpenVEX field, and an unknown property in a VEX
document is something a consumer either rejects or silently drops; the posture
API returns them for the member's own use.

A vulnerability is named by its CVE where the caller can still see a version
that carries one, and by its STIX id otherwise. A posture outlives the reader's
visibility of the record it is about -- a member that left a circle keeps its
own statements -- and the export must not reach past that visibility to name
it.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterable, Mapping
from typing import Any, Final
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aivs_server.auth.context import AuthContext
from aivs_server.auth.policy import distribution_visibility_clause
from aivs_server.db.models import Distribution, Organization, OrgPosture, StixObject, Submission
from aivs_server.services.posture import own_postures

__all__ = ["OPENVEX_CONTEXT", "openvex_document"]

OPENVEX_CONTEXT: Final[str] = "https://openvex.dev/ns/v0.2.0"

#: A statement with no products is about the organisation's estate as a whole;
#: OpenVEX requires at least one product, so the estate is named as one.
_ESTATE: Final[str] = "urn:aivs:estate:{slug}"


def _product(name: str) -> dict[str, Any]:
    """An OpenVEX product: a PURL or CPE as an identifier, anything else as a URN."""
    if name.startswith("pkg:"):
        return {"@id": name, "identifiers": {"purl": name}}
    if name.startswith("cpe:2.3:"):
        return {"@id": name, "identifiers": {"cpe23": name}}
    return {"@id": f"urn:aivs:product:{quote(name, safe='')}"}


def _statement(row: OrgPosture, cve_ids: Mapping[str, str], slug: str) -> dict[str, Any]:
    products = [_product(name) for name in row.products] or [{"@id": _ESTATE.format(slug=slug)}]
    statement: dict[str, Any] = {
        "vulnerability": {
            "@id": row.vulnerability_stix_id,
            "name": cve_ids.get(row.vulnerability_stix_id, row.vulnerability_stix_id),
        },
        "products": products,
        "status": row.status.value,
        "timestamp": row.updated_at.isoformat(),
    }
    optional = {
        "justification": row.justification.value if row.justification else None,
        "impact_statement": row.impact_statement,
        "action_statement": row.action_statement,
    }
    statement.update({key: value for key, value in optional.items() if value})
    return statement


async def _visible_cve_ids(
    session: AsyncSession, ctx: AuthContext, stix_ids: Iterable[str], now: dt.datetime
) -> dict[str, str]:
    """The CVE id of each vulnerability, from a version the caller can still see."""
    wanted = set(stix_ids)
    if not wanted:
        return {}
    rows = await session.execute(
        select(StixObject.stix_id, StixObject.cve_id)
        .join(Distribution, Distribution.stix_object_id == StixObject.id)
        .join(Submission, Submission.id == Distribution.submission_id)
        .where(
            StixObject.stix_id.in_(wanted),
            StixObject.cve_id.is_not(None),
            distribution_visibility_clause(ctx, now),
        )
        .order_by(StixObject.stix_id, StixObject.modified.desc())
        .distinct(StixObject.stix_id)
    )
    return {stix_id: cve_id for stix_id, cve_id in rows.tuples() if cve_id is not None}


async def openvex_document(
    session: AsyncSession, ctx: AuthContext, *, now: dt.datetime
) -> dict[str, Any]:
    """The caller's organisation's postures, as one OpenVEX 0.2.0 document."""
    rows = await own_postures(session, ctx)
    organisation = await session.get(Organization, ctx.org_id)
    author = organisation.name if organisation else ctx.org_slug
    cve_ids = await _visible_cve_ids(session, ctx, (row.vulnerability_stix_id for row in rows), now)
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": author,
        "timestamp": now.isoformat(),
        "version": 1,
        "tooling": "AIVS",
        "statements": [_statement(row, cve_ids, ctx.org_slug) for row in rows],
    }
