"""What's available for a vulnerability is computed from what the caller can see (SF-8).

The table pins the rules; the pairs drive the real pipeline -- filed, validated
and distributed through the API -- because readiness is only as right as the
rows the writer produced (CLAUDE.md section 2).
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest

from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID
from aivs_server.services.readiness import Availability, Readiness, ReadinessInput, assess
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

NOW = dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.UTC)
A, N, U = Availability.AVAILABLE, Availability.NONE_AVAILABLE, Availability.UNAVAILABLE
API = "/api/v1/submissions"
STAMP = "2026-08-01T00:00:00.000Z"


def coa(
    category: str, *, stix_id: str = "coa-1", modified: int = 0, revoked: bool = False
) -> ReadinessInput:
    return ReadinessInput(
        stix_id=stix_id,
        modified=NOW + dt.timedelta(seconds=modified),
        stix_type="course-of-action",
        remediation_category=category,
        revoked=revoked,
    )


def indicator(
    valid_until: dt.datetime | None, *, pattern_type: str | None = "sigma"
) -> ReadinessInput:
    return ReadinessInput(
        stix_id="ind-1",
        modified=NOW,
        stix_type="indicator",
        pattern_type=pattern_type,
        valid_until=valid_until,
    )


@pytest.mark.parametrize(
    ("objects", "expected"),
    [
        ([], Readiness(U, U, U, U)),
        ([coa("vendor_fix")], Readiness(A, U, U, U)),
        ([coa("workaround")], Readiness(U, A, U, U)),
        ([coa("mitigation")], Readiness(U, A, U, U)),
        ([coa("validation")], Readiness(U, U, U, A)),
        ([coa("rollback")], Readiness(U, U, U, U)),
        ([coa("none_available")], Readiness(N, U, U, U)),
        ([coa("no_fix_planned")], Readiness(N, U, U, U)),
        ([coa("no_fix_planned"), coa("vendor_fix", stix_id="coa-2")], Readiness(A, U, U, U)),
        ([indicator(NOW + dt.timedelta(days=1))], Readiness(U, U, A, U)),
        ([indicator(NOW)], Readiness(U, U, U, U)),  # expired at this instant
        ([indicator(None)], Readiness(U, U, U, U)),  # no expiry: cannot vouch it is current
        ([indicator(NOW + dt.timedelta(days=1), pattern_type=None)], Readiness(U, U, U, U)),
        ([coa("workaround"), coa("rollback", modified=1)], Readiness(U, U, U, U)),  # revised
        ([coa("workaround", modified=1), coa("rollback")], Readiness(U, A, U, U)),
        ([coa("vendor_fix", revoked=True)], Readiness(U, U, U, U)),
    ],
)
def test_readiness_follows_the_rules(objects, expected):
    assert assess(objects, NOW) == expected


# ---------------------------------------------------------------------------
# Through the pipeline
# ---------------------------------------------------------------------------
def _sdo(stix_type: str, **properties: Any) -> dict[str, Any]:
    return {
        "type": stix_type,
        "spec_version": "2.1",
        "id": f"{stix_type}--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        **properties,
    }


async def _share(client, pem, isac_headers, objects, circle_ids) -> None:
    """File, submit, validate and distribute a bundle, as the workflow does."""
    created = await client.post(
        API,
        json={
            "title": "Readiness",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects},
        },
        headers=proxy_headers(pem),
    )
    assert created.status_code == 201, created.text
    submission_id = created.json()["id"]
    assert (
        await client.post(f"{API}/{submission_id}/submit", json={}, headers=proxy_headers(pem))
    ).status_code == 200
    assert (
        await client.post(f"{API}/{submission_id}/validate", json={}, headers=isac_headers)
    ).status_code == 200
    distributed = await client.post(
        f"{API}/{submission_id}/distribute",
        json={"circle_ids": [str(c) for c in circle_ids]},
        headers=isac_headers,
    )
    assert distributed.status_code == 200, distributed.text


@pytest.fixture
async def case(client, isac, make_org, make_cert, make_circle, join_circle):
    """A vulnerability in a wide circle; its only fix in a narrow one the reader is not in."""
    _isac_org, isac_headers = isac
    vendor = await make_org("readiness-vendor")
    vendor_pem, _ = await make_cert(vendor)
    reader = await make_org("readiness-reader")
    reader_pem, _ = await make_cert(reader)
    wide = await make_circle("readiness-wide")
    narrow = await make_circle("readiness-narrow")
    for org in (vendor, reader):
        await join_circle(org, wide)
    await join_circle(vendor, narrow)

    vulnerability = _sdo("vulnerability", name="Gateway auth bypass")
    fix = _sdo(
        "course-of-action",
        name="Upgrade to 4.2.1",
        extensions={
            AIVS_INTEL_EXTENSION_ID: {
                "extension_type": "property-extension",
                "aivs_schema_version": "2.0",
                "category": "vendor_fix",
            }
        },
    )
    mitigates = _sdo(
        "relationship",
        relationship_type="mitigates",
        source_ref=fix["id"],
        target_ref=vulnerability["id"],
    )
    await _share(client, vendor_pem, isac_headers, [vulnerability], [wide.id])
    await _share(client, vendor_pem, isac_headers, [fix, mitigates], [narrow.id])
    return {
        "url": f"/api/v1/vulnerabilities/readiness?id={vulnerability['id']}",
        "reader": proxy_headers(reader_pem),
        "reader_org": reader,
        "narrow": narrow,
        "isac": isac_headers,
    }


@pytest.mark.requirement("SF-8")
async def test_a_member_outside_the_fixs_circle_is_not_told_a_fix_exists(client, case):
    seen = await client.get(case["url"], headers=case["reader"])
    assert seen.status_code == 200, seen.text
    assert seen.json()["remediation"] == "unavailable"


@pytest.mark.requirement("SF-8")
async def test_the_isac_sees_the_fix_it_distributed(client, case):
    seen = await client.get(case["url"], headers=case["isac"])
    assert seen.status_code == 200, seen.text
    assert seen.json()["remediation"] == "available"


@pytest.mark.requirement("SF-8")
async def test_joining_the_fixs_circle_makes_it_available(client, case, join_circle):
    await join_circle(case["reader_org"], case["narrow"])
    seen = await client.get(case["url"], headers=case["reader"])
    assert seen.json()["remediation"] == "available"


async def test_an_invisible_vulnerability_and_a_missing_one_answer_alike(
    client, case, make_org, make_cert
):
    outsider = await make_org("readiness-outsider")
    pem, _ = await make_cert(outsider)
    invisible = await client.get(case["url"], headers=proxy_headers(pem))
    missing = await client.get(
        f"/api/v1/vulnerabilities/readiness?id=vulnerability--{uuid.uuid4()}",
        headers=proxy_headers(pem),
    )
    malformed = await client.get(
        "/api/v1/vulnerabilities/readiness?id=not-an-id", headers=proxy_headers(pem)
    )
    assert invisible.status_code == missing.status_code == malformed.status_code == 404
    assert invisible.content == missing.content == malformed.content
