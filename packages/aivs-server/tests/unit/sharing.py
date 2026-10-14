"""Sharing content through the real workflow, for tests of what readers get.

A reader is only as right as the rows its writer produced (CLAUDE.md section
2), so the guided-depth, export and lead-time tests file, submit, validate and
distribute through the API rather than inserting rows by hand.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterable, Sequence
from typing import Any

from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID
from tests.conftest import proxy_headers

API = "/api/v1/submissions"
STAMP = "2026-08-01T00:00:00.000Z"


def stamp(when: dt.datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def sdo(stix_type: str, **properties: Any) -> dict[str, Any]:
    return {
        "type": stix_type,
        "spec_version": "2.1",
        "id": f"{stix_type}--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        **properties,
    }


def intel(**body: Any) -> dict[str, Any]:
    """The 2.0 extension block with ``body`` in it."""
    return {
        AIVS_INTEL_EXTENSION_ID: {
            "extension_type": "property-extension",
            "aivs_schema_version": "2.0",
            **body,
        }
    }


def vulnerability_intel(**body: Any) -> dict[str, Any]:
    """A 2.0 vulnerability extension with what the schema requires, plus ``body``."""
    return intel(
        discovery_scope="own_product",
        cve_status="pre-cve",
        affected_products=[{"vendor": "Acme", "product": "Gateway"}],
        **body,
    )


def indicator(name: str, *, valid_until: dt.datetime, **properties: Any) -> dict[str, Any]:
    valid_from = valid_until - dt.timedelta(days=30)
    return sdo(
        "indicator",
        name=name,
        pattern_type="stix",
        pattern="[file:hashes.'SHA-256' = 'aa']",
        valid_from=stamp(valid_from),
        valid_until=stamp(valid_until),
        **properties,
    )


def relates(source: dict[str, Any], target: dict[str, Any], kind: str) -> dict[str, Any]:
    return sdo(
        "relationship", relationship_type=kind, source_ref=source["id"], target_ref=target["id"]
    )


async def share(
    client: Any,
    pem: str,
    isac_headers: dict[str, str],
    objects: Sequence[dict[str, Any]],
    circle_ids: Iterable[uuid.UUID],
    *,
    distribute: bool = True,
    tlp: str = "amber",
    title: str = "Shared for a reader test",
) -> str:
    """File, submit and validate a bundle, then distribute it unless told not to."""
    created = await client.post(
        API,
        json={
            "title": title,
            "discovery_scope": "own_product",
            "tlp": tlp,
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(objects)},
        },
        headers=proxy_headers(pem),
    )
    assert created.status_code == 201, created.text
    submission_id = str(created.json()["id"])
    submitted = await client.post(
        f"{API}/{submission_id}/submit", json={}, headers=proxy_headers(pem)
    )
    assert submitted.status_code == 200, submitted.text
    validated = await client.post(f"{API}/{submission_id}/validate", json={}, headers=isac_headers)
    assert validated.status_code == 200, validated.text
    if distribute:
        distributed = await client.post(
            f"{API}/{submission_id}/distribute",
            json={"circle_ids": [str(c) for c in circle_ids]},
            headers=isac_headers,
        )
        assert distributed.status_code == 200, distributed.text
    return submission_id
