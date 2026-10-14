"""Each 2.0 index column equals the place in ``raw`` it is extracted from (NFR-M2).

Driven through the real ingest -- a bundle POSTed to the API, the stored row read
back -- because a column tested on a hand-built row proves the fixture, not the
writer (CLAUDE.md section 2). Each column is checked both ways: an object that
carries the value stores it, and one that does not stores ``None``.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy import select

from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID, AIVS_PROVENANCE_EXTENSION_ID
from aivs_server.db.models import StixObject
from aivs_server.services.indexing import INTEL_INDEX_COLUMNS
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1/submissions"
STAMP = "2026-08-01T00:00:00.000Z"


def _sdo(stix_type: str, **properties: Any) -> dict[str, Any]:
    return {
        "type": stix_type,
        "spec_version": "2.1",
        "id": f"{stix_type}--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        **properties,
    }


def _intel(**body: Any) -> dict[str, Any]:
    return {
        AIVS_INTEL_EXTENSION_ID: {
            "extension_type": "property-extension",
            "aivs_schema_version": "2.0",
            **body,
        }
    }


VULNERABILITY = _sdo(
    "vulnerability",
    name="Gateway auth bypass",
    external_references=[
        {"source_name": "cwe", "external_id": "CWE-287"},
        {"source_name": "cwe", "external_id": "CWE-306"},
        {"source_name": "cwe", "external_id": "CWE-287"},
    ],
    extensions=_intel(
        discovery_scope="own_product",
        cve_status="assigned",
        cve_id="CVE-2026-40001",
        affected_products=[{"vendor": "Acme", "product": "Gateway"}],
        cvss_v4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        cvss_v4_base_score=9.3,
        ssvc_exploitation="active",
        kev_listed=True,
        kev_date_added="2026-08-02",
    ),
)
COURSE_OF_ACTION = _sdo(
    "course-of-action", name="Disable the admin port", extensions=_intel(category="workaround")
)
INDICATOR = _sdo(
    "indicator",
    name="Gateway exploit hash",
    pattern="[file:hashes.'SHA-256' = 'aa']",
    pattern_type="stix",
    valid_from=STAMP,
    valid_until="2027-02-01T12:30:45.123456Z",
)
PLAIN_VULNERABILITY = _sdo("vulnerability", name="Nothing indexed here")


async def _file(client: Any, pem: str, *objects: dict[str, Any]) -> Any:
    return await client.post(
        API,
        json={
            "title": "Index columns",
            "discovery_scope": "own_product",
            "tlp": "amber",
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(objects)},
        },
        headers=proxy_headers(pem),
    )


@pytest.fixture
async def stored(client, session, make_org, make_cert) -> dict[str, StixObject]:
    """The four objects, filed once through the API and read back by type and name."""
    org = await make_org("indexing-member")
    pem, _ = await make_cert(org)
    response = await _file(
        client, pem, VULNERABILITY, COURSE_OF_ACTION, INDICATOR, PLAIN_VULNERABILITY
    )
    assert response.status_code == 201, response.text
    rows = (await session.execute(select(StixObject))).scalars().all()
    return {row.name or "": row for row in rows}


def test_every_index_column_is_a_column_of_stix_objects():
    assert set(INTEL_INDEX_COLUMNS) <= set(StixObject.__table__.columns.keys())


@pytest.mark.requirement("NFR-M2")
async def test_remediation_category_is_the_course_of_actions_category(stored):
    row = stored["Disable the admin port"]
    assert row.remediation_category == row.raw["extensions"][AIVS_INTEL_EXTENSION_ID]["category"]
    assert stored["Gateway auth bypass"].remediation_category is None


@pytest.mark.requirement("NFR-M2")
async def test_pattern_type_is_the_indicators_pattern_type(stored):
    row = stored["Gateway exploit hash"]
    assert row.pattern_type == row.raw["pattern_type"] == "stix"
    assert stored["Disable the admin port"].pattern_type is None


@pytest.mark.requirement("NFR-M2")
async def test_valid_until_is_the_indicators_expiry_at_taxii_precision(stored):
    row = stored["Gateway exploit hash"]
    assert row.raw["valid_until"] == "2027-02-01T12:30:45.123456Z"
    assert row.valid_until == dt.datetime(2027, 2, 1, 12, 30, 45, 123000, tzinfo=dt.UTC)
    assert stored["Gateway auth bypass"].valid_until is None


@pytest.mark.requirement("NFR-M2")
async def test_ssvc_exploitation_and_kev_listed_are_the_vulnerabilitys_own(stored):
    row = stored["Gateway auth bypass"]
    body = row.raw["extensions"][AIVS_INTEL_EXTENSION_ID]
    assert row.ssvc_exploitation == body["ssvc_exploitation"] == "active"
    assert row.kev_listed is body["kev_listed"] is True
    plain = stored["Nothing indexed here"]
    assert plain.ssvc_exploitation is None
    assert plain.kev_listed is None


@pytest.mark.requirement("NFR-M2")
async def test_cwe_ids_are_the_cwe_references_in_order_without_repeats(stored):
    row = stored["Gateway auth bypass"]
    in_raw = [r["external_id"] for r in row.raw["external_references"] if r["source_name"] == "cwe"]
    assert row.cwe_ids == list(dict.fromkeys(in_raw)) == ["CWE-287", "CWE-306"]
    assert stored["Nothing indexed here"].cwe_ids is None


@pytest.mark.requirement("NFR-M2")
async def test_a_2_0_vulnerability_indexes_its_cve_and_score_as_1_0_does(stored):
    row = stored["Gateway auth bypass"]
    body = row.raw["extensions"][AIVS_INTEL_EXTENSION_ID]
    assert row.cve_id == body["cve_id"]
    assert float(row.cvss_score) == body["cvss_v4_base_score"]


@pytest.mark.requirement("SF-46")
async def test_an_indicator_without_an_expiry_is_refused_at_the_api(client, make_org, make_cert):
    org = await make_org("expiry-member")
    pem, _ = await make_cert(org)
    unbounded = {key: value for key, value in INDICATOR.items() if key != "valid_until"}
    refused = await _file(client, pem, unbounded)
    assert refused.status_code == 400
    assert "valid_until" in refused.json()["title"]
    assert (await _file(client, pem, INDICATOR)).status_code == 201


@pytest.mark.requirement("SF-6")
async def test_a_claimed_review_is_refused_at_the_api(client, make_org, make_cert):
    org = await make_org("review-member")
    pem, _ = await make_cert(org)
    claimed = {
        **COURSE_OF_ACTION,
        "extensions": {
            **COURSE_OF_ACTION["extensions"],
            AIVS_PROVENANCE_EXTENSION_ID: {
                "extension_type": "property-extension",
                "reviewed_at": STAMP,
            },
        },
    }
    refused = await _file(client, pem, claimed)
    assert refused.status_code == 400
    assert "reviewed_at" in refused.json()["title"]
    assert (await _file(client, pem, COURSE_OF_ACTION)).status_code == 201
