"""The columns extracted from extension 2.0 and the standard STIX properties.

``raw`` stays canonical: these exist so the readers that filter on them need not
open every object's JSON. Each reads exactly one place in ``raw``, and a test
holds each column equal to that place (NFR-M2). Anything not where it is
expected is left ``None`` rather than coerced: a wrong extracted value makes an
object findable under a description that is not true of it.

Who reads each, all in phase E unless noted:

- ``remediation_category`` -- readiness, for the remediation, mitigation and
  validation groups.
- ``pattern_type`` -- readiness, for the detection group; the IoC pack (F).
- ``valid_until`` -- readiness and the IoC pack exclude expired indicators
  (SF-46).
- ``cwe_ids`` -- duplicate detection at intake.

There were two more, ``ssvc_exploitation`` and ``kev_listed``, dropped in
``102b931e1599`` because nothing filtered on them: the priority and the KEV
readers need the whole object and read ``raw``. Add a column here only with
the reader that filters on it.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from typing import Any, Final

from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID
from aivs_server.taxii.resources import truncate_to_taxii_precision

__all__ = ["INTEL_INDEX_COLUMNS", "intel_index_fields"]

#: Every column this module fills. A test asserts each is a real column.
INTEL_INDEX_COLUMNS: Final[tuple[str, ...]] = (
    "remediation_category",
    "pattern_type",
    "valid_until",
    "cwe_ids",
)

#: Bounds on what is copied into a column, matching the column widths. ``raw``
#: is already schema-validated, so these are a last guard against a value the
#: schema let through being longer than its column.
_SHORT: Final[int] = 40
_MAX_CWE_IDS: Final[int] = 50
_CWE_WIDTH: Final[int] = 20


def intel_index_fields(obj: Mapping[str, Any]) -> dict[str, Any]:
    """The 2.0 index columns for one raw STIX object; ``None`` where it says nothing."""
    body = _intel_body(obj)
    object_type = obj.get("type")
    return {
        "remediation_category": _string(body, "category")
        if object_type == "course-of-action"
        else None,
        "pattern_type": _string(obj, "pattern_type") if object_type == "indicator" else None,
        "valid_until": _timestamp(obj, "valid_until") if object_type == "indicator" else None,
        "cwe_ids": _cwe_ids(obj) if object_type == "vulnerability" else None,
    }


def _intel_body(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    body = (obj.get("extensions") or {}).get(AIVS_INTEL_EXTENSION_ID)
    return body if isinstance(body, Mapping) else {}


def _string(source: Mapping[str, Any], key: str) -> str | None:
    value = source.get(key)
    return value if isinstance(value, str) and len(value) <= _SHORT else None


def _timestamp(source: Mapping[str, Any], key: str) -> dt.datetime | None:
    """A STIX timestamp, at the millisecond precision TAXII carries (CLAUDE.md §5)."""
    value = source.get(key)
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return truncate_to_taxii_precision(parsed.astimezone(dt.UTC))


def _cwe_ids(obj: Mapping[str, Any]) -> list[str] | None:
    """CWE ids from the object's own ``cwe`` references, in order, without repeats."""
    found: list[str] = []
    for reference in obj.get("external_references") or []:
        if not isinstance(reference, Mapping) or reference.get("source_name") != "cwe":
            continue
        external_id = reference.get("external_id")
        if (
            isinstance(external_id, str)
            and len(external_id) <= _CWE_WIDTH
            and external_id not in found
        ):
            found.append(external_id)
    return found[:_MAX_CWE_IDS] or None
