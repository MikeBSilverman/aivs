"""Parsing and validation of TAXII 2.1 URL filter parameters.

The filter grammar is small but has several rules that are easy to implement
almost-correctly, each of which produces a subtly wrong feed rather than an
obvious failure:

* ``match`` values are comma-separated and OR together; different ``match``
  fields AND together.
* A given field must not appear more than once. ``?match[type]=a&match[type]=b``
  is malformed, not a union.
* ``match[version]`` accepts the keywords ``all``, ``first``, ``last`` and
  explicit STIX timestamps. ``all`` must not be combined with anything else.
* When ``match[version]`` is absent the default is ``last`` -- **not** all
  versions. A server that returns every version by default floods members with
  superseded content.
* Malformed parameters are HTTP 400, not silently ignored.

Unknown ``match`` fields are ignored rather than rejected, which the
specification explicitly permits and which keeps AIVS interoperable with clients
that send vendor extensions.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

__all__ = [
    "FilterError",
    "TaxiiFilters",
    "VersionSelector",
    "parse_filters",
]

#: Fields AIVS understands in a ``match[...]`` parameter.
_KNOWN_MATCH_FIELDS: Final[frozenset[str]] = frozenset({"id", "type", "version", "spec_version"})

#: STIX timestamp, as accepted in ``match[version]``.
_TIMESTAMP_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
)

#: STIX identifiers, as accepted in ``match[id]``. Bounded so a filter cannot be
#: used to push an unbounded list of values into a SQL IN clause.
_STIX_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9-]{3,60}--[0-9a-fA-F-]{36}$")

#: STIX object type, as accepted in ``match[type]``.
_STIX_TYPE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9-]{2,59}$")

#: Upper bound on comma-separated values in a single match field. Without it a
#: member could send tens of thousands of identifiers in one query string.
MAX_MATCH_VALUES: Final[int] = 100


class VersionSelector(StrEnum):
    """Which versions of an object to return."""

    ALL = "all"
    FIRST = "first"
    LAST = "last"


class FilterError(ValueError):
    """A filter parameter was malformed. The caller returns HTTP 400."""


@dataclass(frozen=True, slots=True)
class TaxiiFilters:
    """Validated filter parameters for an object or manifest listing."""

    added_after: dt.datetime | None = None
    limit: int | None = None
    next_cursor: str | None = None
    ids: tuple[str, ...] = ()
    types: tuple[str, ...] = ()
    spec_versions: tuple[str, ...] = ()
    #: Keyword selectors requested. Defaults to ``{LAST}`` per the specification.
    version_selectors: frozenset[VersionSelector] = field(
        default_factory=lambda: frozenset({VersionSelector.LAST})
    )
    #: Explicit versions requested as STIX timestamps.
    version_timestamps: tuple[dt.datetime, ...] = ()

    @property
    def wants_all_versions(self) -> bool:
        return VersionSelector.ALL in self.version_selectors


def _single(values: Sequence[str], name: str) -> str:
    """Return the sole value for ``name``, or raise.

    A repeated parameter is malformed rather than a union: silently taking the
    first or last occurrence would give two clients sending the same query
    different results.
    """
    if len(values) != 1:
        msg = f"parameter '{name}' must appear exactly once"
        raise FilterError(msg)
    return values[0]


def _split_match(raw: str, name: str) -> list[str]:
    """Split a comma-separated match value and bound its length."""
    parts = [part for part in raw.split(",") if part != ""]
    if not parts:
        msg = f"parameter 'match[{name}]' has no values"
        raise FilterError(msg)
    if len(parts) > MAX_MATCH_VALUES:
        msg = f"parameter 'match[{name}]' accepts at most {MAX_MATCH_VALUES} values"
        raise FilterError(msg)
    return parts


def _parse_timestamp(raw: str, name: str) -> dt.datetime:
    """Parse a STIX/TAXII timestamp, which is always UTC with a literal Z."""
    if not _TIMESTAMP_PATTERN.match(raw):
        msg = f"parameter '{name}' is not a valid timestamp"
        raise FilterError(msg)
    try:
        return dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        msg = f"parameter '{name}' is not a valid timestamp"
        raise FilterError(msg) from exc


def _require_all_match(
    parts: list[str], pattern: re.Pattern[str], parameter: str, description: str
) -> None:
    """Raise unless every value matches ``pattern``."""
    for part in parts:
        if not pattern.match(part):
            msg = f"parameter '{parameter}' contains an invalid {description}"
            raise FilterError(msg)


def _parse_versions(
    raw_values: list[str],
) -> tuple[frozenset[VersionSelector], tuple[dt.datetime, ...]]:
    """Interpret the ``match[version]`` values.

    Returns the keyword selectors and any explicit timestamps, enforcing that
    ``all`` stands alone and that no value is repeated.
    """
    if len(raw_values) != len(set(raw_values)):
        msg = "parameter 'match[version]' must not repeat a value"
        raise FilterError(msg)

    selectors: set[VersionSelector] = set()
    timestamps: list[dt.datetime] = []

    for value in raw_values:
        match value:
            case "all":
                selectors.add(VersionSelector.ALL)
            case "first":
                selectors.add(VersionSelector.FIRST)
            case "last":
                selectors.add(VersionSelector.LAST)
            case _:
                timestamps.append(_parse_timestamp(value, "match[version]"))

    if VersionSelector.ALL in selectors and (len(selectors) > 1 or timestamps):
        msg = "parameter 'match[version]' value 'all' must not be combined with others"
        raise FilterError(msg)

    return frozenset(selectors), tuple(timestamps)


def _parse_match_fields(query_params: Mapping[str, Sequence[str]]) -> dict[str, Any]:
    """Interpret every ``match[...]`` parameter.

    Split out from :func:`parse_filters` so each function stays readable. The
    returned mapping is spread directly into :class:`TaxiiFilters`, so its keys
    are that dataclass's field names.
    """
    parsed: dict[str, Any] = {
        "ids": (),
        "types": (),
        "spec_versions": (),
        "version_selectors": frozenset({VersionSelector.LAST}),
        "version_timestamps": (),
    }

    for key, values in query_params.items():
        if not (key.startswith("match[") and key.endswith("]")):
            continue
        name = key[len("match[") : -1]
        if name not in _KNOWN_MATCH_FIELDS:
            # Permitted by the specification, and better for interoperability
            # than refusing a client's vendor extension.
            continue

        parts = _split_match(_single(values, key), name)

        match name:
            case "id":
                _require_all_match(parts, _STIX_ID_PATTERN, "match[id]", "STIX identifier")
                parsed["ids"] = tuple(parts)
            case "type":
                _require_all_match(parts, _STIX_TYPE_PATTERN, "match[type]", "STIX type")
                parsed["types"] = tuple(parts)
            case "spec_version":
                # AIVS stores only STIX 2.1. A request naming another spec
                # version yields an empty result rather than an error, so a
                # multi-version client can probe without special-casing us.
                parsed["spec_versions"] = tuple(parts)
            case "version":
                selectors, timestamps = _parse_versions(parts)
                parsed["version_selectors"] = selectors
                parsed["version_timestamps"] = timestamps

    return parsed


def parse_filters(
    query_params: Mapping[str, Sequence[str]],
    *,
    default_limit: int,
    max_limit: int,
) -> TaxiiFilters:
    """Validate raw query parameters into a :class:`TaxiiFilters`.

    ``query_params`` maps each parameter name to *every* value supplied for it,
    so a duplicated parameter can be detected and refused rather than silently
    resolved to one occurrence.
    """
    added_after: dt.datetime | None = None
    if "added_after" in query_params:
        added_after = _parse_timestamp(
            _single(query_params["added_after"], "added_after"), "added_after"
        )

    limit = default_limit
    if "limit" in query_params:
        raw_limit = _single(query_params["limit"], "limit")
        try:
            limit = int(raw_limit)
        except ValueError as exc:
            msg = "parameter 'limit' must be an integer"
            raise FilterError(msg) from exc
        if limit < 1:
            msg = "parameter 'limit' must be a positive integer"
            raise FilterError(msg)
    # Capped unconditionally, outside the branch above. Applying the cap only to
    # a client-supplied limit meant a default larger than the maximum produced
    # bigger pages for clients that asked for nothing than for clients that
    # asked -- the opposite of what the two settings say.
    #
    # Capped silently rather than rejected: the specification allows a server to
    # return fewer objects than asked for, and the envelope's `more` flag tells
    # the client to keep paging.
    limit = min(limit, max_limit)

    next_cursor: str | None = None
    if "next" in query_params:
        next_cursor = _single(query_params["next"], "next")

    return TaxiiFilters(
        added_after=added_after,
        limit=limit,
        next_cursor=next_cursor,
        **_parse_match_fields(query_params),
    )
