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
from aivs_server.services.exploitability import ExploitabilityStatus
from aivs_server.services.readiness import Availability, Readiness, ReadinessInput, assess
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

NOW = dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.UTC)
A, N, U = Availability.AVAILABLE, Availability.NONE_AVAILABLE, Availability.UNAVAILABLE
L = Availability.LAPSED
NOT_ESTABLISHED = ExploitabilityStatus.NOT_ESTABLISHED
YESTERDAY, TODAY = "2026-10-13", "2026-10-14"
API = "/api/v1/submissions"
STAMP = "2026-08-01T00:00:00.000Z"


def coa(
    category: str,
    *,
    stix_id: str = "coa-1",
    modified: int = 0,
    revoked: bool = False,
    review_by: str | None = None,
) -> ReadinessInput:
    return ReadinessInput(
        stix_id=stix_id,
        modified=NOW + dt.timedelta(seconds=modified),
        stix_type="course-of-action",
        remediation_category=category,
        revoked=revoked,
        review_by=review_by,
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
        ([], Readiness(U, U, U, U, U)),
        ([coa("vendor_fix")], Readiness(A, U, U, U, U)),
        ([coa("workaround")], Readiness(U, A, U, U, U)),
        ([coa("mitigation")], Readiness(U, A, U, U, U)),
        ([coa("validation")], Readiness(U, U, U, A, U)),
        ([coa("rollback")], Readiness(U, U, U, U, U)),
        ([coa("none_available")], Readiness(N, U, U, U, U)),
        ([coa("no_fix_planned")], Readiness(N, U, U, U, U)),
        ([coa("no_fix_planned"), coa("vendor_fix", stix_id="coa-2")], Readiness(A, U, U, U, U)),
        ([indicator(NOW + dt.timedelta(days=1))], Readiness(U, U, A, U, U)),
        ([indicator(NOW)], Readiness(U, U, U, U, U)),  # expired at this instant
        ([indicator(None)], Readiness(U, U, U, U, U)),  # no expiry: cannot vouch it is current
        ([indicator(NOW + dt.timedelta(days=1), pattern_type=None)], Readiness(U, U, U, U, U)),
        ([coa("workaround"), coa("rollback", modified=1)], Readiness(U, U, U, U, U)),  # revised
        ([coa("workaround", modified=1), coa("rollback")], Readiness(U, A, U, U, U)),
        ([coa("vendor_fix", revoked=True)], Readiness(U, U, U, U, U)),
    ],
)
def test_readiness_follows_the_rules(objects, expected):
    assert assess(objects, NOW, exploitability=NOT_ESTABLISHED) == expected


def _lapsed(**since: dt.date | None) -> dict[str, dt.date | None]:
    return since


@pytest.mark.requirement("SF-8")
@pytest.mark.parametrize(
    ("objects", "expected"),
    [
        # Vouched for through the whole of its review_by day.
        ([coa("vendor_fix", review_by=TODAY)], Readiness(A, U, U, U, U)),
        # A lapsed claim is stale, not reversed: neither "available" nor "none".
        (
            [coa("vendor_fix", review_by=YESTERDAY)],
            Readiness(L, U, U, U, U, _lapsed(remediation=dt.date(2026, 10, 13))),
        ),
        (
            [coa("none_available", review_by=YESTERDAY)],
            Readiness(L, U, U, U, U, _lapsed(remediation=dt.date(2026, 10, 13))),
        ),
        (
            [coa("workaround", review_by=YESTERDAY)],
            Readiness(U, L, U, U, U, _lapsed(mitigation=dt.date(2026, 10, 13))),
        ),
        # A current claim answers the group, whichever way it points.
        (
            [coa("vendor_fix", review_by=YESTERDAY), coa("no_fix_planned", stix_id="coa-2")],
            Readiness(N, U, U, U, U),
        ),
        (
            [coa("none_available", review_by=YESTERDAY), coa("vendor_fix", stix_id="coa-2")],
            Readiness(A, U, U, U, U),
        ),
        # The last day anyone vouched for one of the group's claims.
        (
            [
                coa("vendor_fix", review_by="2026-09-01"),
                coa("vendor_fix", stix_id="coa-2", review_by="2026-10-01"),
            ],
            Readiness(L, U, U, U, U, _lapsed(remediation=dt.date(2026, 10, 1))),
        ),
        # A date that is not one: lapsed, with no date to give.
        (
            [coa("vendor_fix", review_by="2026-13-45")],
            Readiness(L, U, U, U, U, _lapsed(remediation=None)),
        ),
        # Knowing how to undo a fix is no claim, stale or not.
        ([coa("rollback", review_by=YESTERDAY)], Readiness(U, U, U, U, U)),
    ],
)
def test_a_claim_past_its_review_date_is_reported_stale_not_reversed(objects, expected):
    assert assess(objects, NOW, exploitability=NOT_ESTABLISHED) == expected


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


# ---------------------------------------------------------------------------
# A stale claim, through the pipeline
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-8")
async def test_a_fix_past_its_review_date_reaches_members_as_not_confirmed(
    client, isac, make_org, make_cert, make_circle, join_circle
):
    """The vendor's own course of action, filed with a ``review_by`` long past,
    as the extension carries it: the member is told the claim is stale and
    since when -- not that a fix exists, and not that none does."""
    _isac_org, isac_headers = isac
    vendor = await make_org("stale-vendor")
    vendor_pem, _ = await make_cert(vendor)
    reader = await make_org("stale-reader")
    reader_pem, _ = await make_cert(reader)
    circle = await make_circle("stale-circle")
    for org in (vendor, reader):
        await join_circle(org, circle)
    vulnerability = _sdo("vulnerability", name="Gateway auth bypass")
    fix = _sdo(
        "course-of-action",
        name="Upgrade to 4.2.1",
        extensions={
            AIVS_INTEL_EXTENSION_ID: {
                "extension_type": "property-extension",
                "aivs_schema_version": "2.0",
                "category": "vendor_fix",
                "review_by": "2020-01-31",
            }
        },
    )
    mitigates = _sdo(
        "relationship",
        relationship_type="mitigates",
        source_ref=fix["id"],
        target_ref=vulnerability["id"],
    )
    await _share(client, vendor_pem, isac_headers, [vulnerability, fix, mitigates], [circle.id])

    seen = await client.get(
        f"/api/v1/vulnerabilities/readiness?id={vulnerability['id']}",
        headers=proxy_headers(reader_pem),
    )

    assert seen.status_code == 200, seen.text
    body = seen.json()
    assert body["remediation"] == "lapsed"
    assert body["not_confirmed_since"] == {"remediation": "2020-01-31"}


@pytest.mark.requirement("SF-84")
@pytest.mark.parametrize(
    ("exploitability", "scoping"),
    [
        (ExploitabilityStatus.AGREED, A),
        (ExploitabilityStatus.CONTESTED, U),
        (ExploitabilityStatus.NOT_ESTABLISHED, U),
    ],
)
def test_scoping_is_available_only_when_the_visible_conditions_agree(exploitability, scoping):
    """Contested conditions do not tell a member whether it is affected, and no
    conditions is no statement at all: neither is NONE_AVAILABLE."""
    assert assess([], NOW, exploitability=exploitability).scoping is scoping
