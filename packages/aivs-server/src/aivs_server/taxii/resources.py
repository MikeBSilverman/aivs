"""TAXII 2.1 resource shapes.

Built as explicit dictionaries rather than serialised models, because the
specification has several rules that a generic serialiser gets wrong:

* Property names are normative and case-sensitive (TAXII 2.1 section 3.8).
* An empty ``collections``, ``versions``, or ``manifest`` result must **omit the
  key entirely** -- the response body is ``{}``, not ``{"collections": []}``.
  Members' off-the-shelf TAXII clients notice the difference.
* ``more`` is optional and its absence means ``false``, so emitting
  ``"more": false`` is legal but noisier than the spec's own examples.

Every function here returns a plain ``dict`` so the exact wire shape is visible
at the point it is constructed, which is what makes the conformance tests
readable against the specification text.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Final

__all__ = [
    "STIX_MEDIA_TYPE",
    "TAXII_MEDIA_TYPE",
    "api_root_resource",
    "collection_resource",
    "collections_resource",
    "discovery_resource",
    "envelope_resource",
    "error_resource",
    "manifest_resource",
    "status_resource",
    "truncate_to_taxii_precision",
    "versions_resource",
]

#: The TAXII media type, required on requests (``Accept``) and responses
#: (``Content-Type``), including error responses.
TAXII_MEDIA_TYPE: Final[str] = "application/taxii+json;version=2.1"

#: The media type of the STIX content carried inside TAXII envelopes.
STIX_MEDIA_TYPE: Final[str] = "application/stix+json;version=2.1"


def discovery_resource(
    *,
    title: str,
    api_roots: list[str],
    description: str | None = None,
    contact: str | None = None,
    default: str | None = None,
) -> dict[str, Any]:
    """Build a ``discovery`` resource (TAXII 2.1 section 4.1.1).

    Only ``title`` is required. ``default`` must be one of ``api_roots`` when
    present, which the caller guarantees by construction.
    """
    resource: dict[str, Any] = {"title": title}
    if description is not None:
        resource["description"] = description
    if contact is not None:
        resource["contact"] = contact
    if default is not None:
        resource["default"] = default
    if api_roots:
        resource["api_roots"] = api_roots
    return resource


def api_root_resource(
    *,
    title: str,
    max_content_length: int,
    description: str | None = None,
    versions: list[str] | None = None,
) -> dict[str, Any]:
    """Build an ``api-root`` resource (section 4.2.1).

    ``versions`` must include the TAXII 2.1 media type; ``max_content_length``
    is required and is how a member discovers the body size limit rather than
    finding it by being rejected.
    """
    return {
        "title": title,
        **({"description": description} if description is not None else {}),
        "versions": versions or [TAXII_MEDIA_TYPE],
        "max_content_length": max_content_length,
    }


def collection_resource(
    *,
    collection_id: str,
    title: str,
    can_read: bool,
    can_write: bool,
    description: str | None = None,
    alias: str | None = None,
    media_types: list[str] | None = None,
) -> dict[str, Any]:
    """Build a ``collection`` resource (section 5.2.1).

    ``media_types`` is omitted when it would be the default single entry, which
    the specification defines as equivalent.
    """
    resource: dict[str, Any] = {
        "id": collection_id,
        "title": title,
        "can_read": can_read,
        "can_write": can_write,
    }
    if description is not None:
        resource["description"] = description
    if alias is not None:
        resource["alias"] = alias
    if media_types is not None:
        resource["media_types"] = media_types
    return resource


def collections_resource(collections: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a ``collections`` resource (section 5.1.1).

    An empty list omits the key entirely, per the specification.
    """
    return {"collections": collections} if collections else {}


def envelope_resource(
    objects: list[dict[str, Any]],
    *,
    more: bool = False,
    next_cursor: str | None = None,
) -> dict[str, Any]:
    """Build an ``envelope`` (section 3.7).

    STIX content is always wrapped in an envelope, even for a single object, and
    an empty result is an empty envelope rather than a 404.
    """
    envelope: dict[str, Any] = {}
    if more:
        envelope["more"] = True
        if next_cursor is not None:
            envelope["next"] = next_cursor
    if objects:
        envelope["objects"] = objects
    return envelope


def manifest_resource(
    records: list[dict[str, Any]], *, more: bool = False, next_cursor: str | None = None
) -> dict[str, Any]:
    """Build a ``manifest`` resource (section 5.3.1).

    An empty record list omits the key entirely.
    """
    resource: dict[str, Any] = {}
    if more:
        resource["more"] = True
        if next_cursor is not None:
            resource["next"] = next_cursor
    if records:
        resource["objects"] = records
    return resource


def manifest_record(
    *, stix_id: str, date_added: dt.datetime, version: str, media_type: str | None = None
) -> dict[str, Any]:
    """Build one ``manifest-record`` (section 5.3.1)."""
    record: dict[str, Any] = {
        "id": stix_id,
        "date_added": to_taxii_timestamp(date_added),
        "version": version,
    }
    if media_type is not None:
        record["media_type"] = media_type
    return record


def versions_resource(
    versions: list[str], *, more: bool = False, next_cursor: str | None = None
) -> dict[str, Any]:
    """Build a ``versions`` resource (section 5.8.1).

    An empty version list omits the key entirely.
    """
    resource: dict[str, Any] = {}
    if more:
        resource["more"] = True
        if next_cursor is not None:
            resource["next"] = next_cursor
    if versions:
        resource["versions"] = versions
    return resource


def status_resource(
    *,
    status_id: str,
    status: str,
    total_count: int,
    success_count: int,
    failure_count: int,
    pending_count: int,
    request_timestamp: dt.datetime | None = None,
    successes: list[dict[str, Any]] | None = None,
    failures: list[dict[str, Any]] | None = None,
    pendings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a ``status`` resource (section 4.3.1).

    The four count properties are required even when zero; the corresponding
    detail lists are optional.
    """
    resource: dict[str, Any] = {
        "id": status_id,
        "status": status,
        "total_count": total_count,
        "success_count": success_count,
        "failure_count": failure_count,
        "pending_count": pending_count,
    }
    if request_timestamp is not None:
        resource["request_timestamp"] = to_taxii_timestamp(request_timestamp)
    if successes:
        resource["successes"] = successes
    if failures:
        resource["failures"] = failures
    if pendings:
        resource["pendings"] = pendings
    return resource


def error_resource(
    *,
    title: str,
    http_status: int | None = None,
    description: str | None = None,
    error_id: str | None = None,
    error_code: str | None = None,
) -> dict[str, Any]:
    """Build an ``error`` resource (section 3.6.1).

    Only ``title`` is required. ``description`` is deliberately left to the
    caller and is omitted for authorization failures: an error body is not the
    place to explain which check refused a request.
    """
    resource: dict[str, Any] = {"title": title}
    if http_status is not None:
        resource["http_status"] = str(http_status)
    if description is not None:
        resource["description"] = description
    if error_id is not None:
        resource["error_id"] = error_id
    if error_code is not None:
        resource["error_code"] = error_code
    return resource


def to_taxii_timestamp(value: dt.datetime) -> str:
    """Render an aware datetime as a TAXII/STIX timestamp.

    Millisecond precision with a literal ``Z``. A naive datetime raises rather
    than being assumed to be UTC -- these timestamps drive members' polling
    cursors, and a silent timezone assumption there loses content.
    """
    if value.tzinfo is None:
        msg = "refusing to serialise a naive datetime as a TAXII timestamp"
        raise ValueError(msg)
    utc = value.astimezone(dt.UTC)
    return f"{utc.strftime('%Y-%m-%dT%H:%M:%S')}.{utc.microsecond // 1000:03d}Z"


def truncate_to_taxii_precision(value: dt.datetime) -> dt.datetime:
    """Round a timestamp down to the precision TAXII can express.

    TAXII and STIX timestamps carry milliseconds. ``date_added`` is stored at
    PostgreSQL's microsecond precision, so without this a member who echoes the
    ``X-TAXII-Date-Added-Last`` header back as ``added_after`` -- exactly what
    incremental polling is supposed to do -- gets a cutoff microseconds *earlier*
    than the value stored, and receives the last object again on every poll.

    Every write of ``distributions.date_added`` must pass through here so that
    what a member reads back round-trips to precisely what was stored.
    """
    return value.replace(microsecond=(value.microsecond // 1000) * 1000)
