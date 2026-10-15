"""The first pass over a submission (plan, Phase O, slice 1).

Each check as a pair: the object that earns the finding beside the one that
does not, so a check that fired on everything fails as surely as one that
fired on nothing. Then who may read the findings.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID
from aivs_server.services.first_pass import FindingCode, first_pass
from tests.conftest import proxy_headers
from tests.unit.test_vulnerability_page import build_case

NOW = dt.datetime(2026, 10, 15, 12, 0, tzinfo=dt.UTC)


def _obj(stix_type: str, body: dict[str, Any] | None = None, **raw: Any) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "type": stix_type,
        "id": f"{stix_type}--1",
        "created": "2026-10-01T00:00:00.000Z",
        "modified": "2026-10-01T00:00:00.000Z",
        **raw,
    }
    if body is not None:
        obj["extensions"] = {AIVS_INTEL_EXTENSION_ID: body}
    return obj


def _codes(*objects: dict[str, Any]) -> set[FindingCode]:
    return {finding.code for finding in first_pass(objects, own_names=["Meridian"], now=NOW)}


PRODUCT = {"vendor": "Acme", "product": "Gateway", "purl": "pkg:generic/acme/gateway"}
SEVERE = {"cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
CHECK = {"tool": "curl", "query_or_command": "curl -I x", "expected_result": "403"}


def calls(package: str) -> dict[str, Any]:
    return {
        "id": "fn",
        "kind": "function",
        "any_of": [{"ecosystem": "Go", "package": package, "symbol": "Parse"}],
        "how_to_check": CHECK,
    }


@pytest.mark.parametrize(
    ("objects", "code", "present"),
    [
        (
            [_obj("course-of-action", {"category": "workaround"})],
            FindingCode.MITIGATION_WITHOUT_CHECK,
            True,
        ),
        (
            [_obj("course-of-action", {"category": "workaround", "validation_check": CHECK})],
            FindingCode.MITIGATION_WITHOUT_CHECK,
            False,
        ),
        (
            [
                _obj("vulnerability", {**SEVERE, "affected_products": [PRODUCT]}),
                _obj("course-of-action", {"category": "vendor_fix"}),
            ],
            FindingCode.FIX_WITHOUT_FIXED_VERSIONS,
            True,
        ),
        (
            [
                _obj(
                    "vulnerability",
                    {**SEVERE, "affected_products": [{**PRODUCT, "fixed_versions": ["4.2.1"]}]},
                ),
                _obj("course-of-action", {"category": "vendor_fix"}),
            ],
            FindingCode.FIX_WITHOUT_FIXED_VERSIONS,
            False,
        ),
        (
            [
                _obj(
                    "vulnerability",
                    {**SEVERE, "affected_products": [{"vendor": "Acme", "product": "Gateway"}]},
                )
            ],
            FindingCode.PRODUCT_NOT_MACHINE_READABLE,
            True,
        ),
        (
            [_obj("vulnerability", {**SEVERE, "affected_products": [PRODUCT]})],
            FindingCode.PRODUCT_NOT_MACHINE_READABLE,
            False,
        ),
        ([_obj("vulnerability", {"affected_products": [PRODUCT]})], FindingCode.NO_SEVERITY, True),
        (
            [_obj("vulnerability", {**SEVERE, "affected_products": [PRODUCT]})],
            FindingCode.NO_SEVERITY,
            False,
        ),
        ([_obj("note", modified="2027-01-01T00:00:00.000Z")], FindingCode.DATED_IN_FUTURE, True),
        ([_obj("note", modified="2026-10-15T12:04:00.000Z")], FindingCode.DATED_IN_FUTURE, False),
        (
            [
                _obj(
                    "note",
                    {"conditions": [{"id": "os", "kind": "platform", "any_of": [{"os": "linux"}]}]},
                )
            ],
            FindingCode.CONDITION_WITHOUT_CHECK,
            True,
        ),
        (
            [
                _obj(
                    "note",
                    {
                        "conditions": [
                            {
                                "id": "os",
                                "kind": "platform",
                                "any_of": [{"os": "linux"}],
                                "how_to_check": CHECK,
                            }
                        ]
                    },
                )
            ],
            FindingCode.CONDITION_WITHOUT_CHECK,
            False,
        ),
        (
            [
                _obj("vulnerability", {**SEVERE, "affected_products": [PRODUCT]}),
                _obj(
                    "note",
                    {"conditions": [calls("pkg:generic/acme/sdk@1.0")]},
                    object_refs=["vulnerability--1"],
                ),
            ],
            FindingCode.FUNCTION_OUTSIDE_PRODUCTS,
            True,
        ),
        (
            [
                _obj("vulnerability", {**SEVERE, "affected_products": [PRODUCT]}),
                _obj(
                    "note",
                    {"conditions": [calls("pkg:generic/acme/gateway@4.2.0")]},
                    object_refs=["vulnerability--1"],
                ),
            ],
            FindingCode.FUNCTION_OUTSIDE_PRODUCTS,
            False,
        ),
        (
            [_obj("note", content="Seen at Meridian's Leeds office.")],
            FindingCode.SANITISATION,
            True,
        ),
        ([_obj("note", content="Seen at a member's office.")], FindingCode.SANITISATION, False),
    ],
)
def test_each_check_fires_on_its_case_and_not_its_pair(objects, code, present):
    assert (code in _codes(*objects)) is present


def test_a_finding_says_where_to_look():
    (finding,) = first_pass(
        [_obj("course-of-action", {"category": "mitigation"})], own_names=[], now=NOW
    )
    assert finding.path == "course-of-action--1.validation_check"


# ---------------------------------------------------------------------------
# Who reads it
# ---------------------------------------------------------------------------
@pytest.fixture
async def case(
    client,
    session,
    settings,
    isac_org,
    make_org,
    make_cert,
    make_operator,
    make_circle,
    join_circle,
):
    return await build_case(
        client,
        session,
        settings,
        isac_org,
        make_org=make_org,
        make_cert=make_cert,
        make_operator=make_operator,
        make_circle=make_circle,
        join_circle=join_circle,
    )


@pytest.mark.db
async def test_the_isacs_reviewers_read_the_first_pass(client, case):
    path = f"/api/v1/submissions/{case['shared']}/first-pass"

    response = await client.get(path, headers=case["isac_api"])

    assert response.status_code == 200
    assert {finding["code"] for finding in response.json()} >= {"no_severity"}


@pytest.mark.db
async def test_the_submitter_is_not_told_yet(client, case):
    """Slice 1 tunes the checks on the ISAC's side before a member hears any."""
    path = f"/api/v1/submissions/{case['shared']}/first-pass"

    response = await client.get(path, headers=proxy_headers(case["vendor_pem"]))

    assert response.status_code == 404
