"""The OSV export: a complete record or a refusal, never a smaller record (plan, Phase N).

A scanner reads an OSV record's silence as "not affected". Each refusal below
is a record that, sent, would have cleared members the view does not clear.

``osv/schema-1.9.1.json`` is OSV's own validation schema, vendored unchanged
from github.com/ossf/osv-schema at tag v1.9.1 (Apache-2.0; sha256
15b10dbb4c4e31c7aae11d22cdd991a9a374758db7c8389e62b3cc37cac92653).
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID
from aivs_server.services.exploitability import ConditionSource, combine
from aivs_server.services.osv_export import OSV_SCHEMA_VERSION, OsvRefusedError, osv_record
from tests.unit.test_exploitability import ON_LINUX, SETTING_ON, _api, conditions_note
from tests.unit.test_vulnerability_page import _share, build_case

OSV_SCHEMA = json.loads((Path(__file__).parent / "osv" / "schema-1.9.1.json").read_text())
WHEN = dt.datetime(2026, 10, 15, 9, 30, tzinfo=dt.UTC)
VULNERABILITY_ID = "vulnerability--0f9c0000-0000-4000-8000-000000000001"

CALLS_PARSER = {
    "id": "fn",
    "kind": "function",
    "any_of": [
        {"ecosystem": "Go", "package": "pkg:golang/example.com/xml", "symbol": "ParseStrict"},
        {"ecosystem": "Go", "package": "pkg:golang/example.com/xml", "symbol": "Decoder.Strict"},
    ],
}
GO_PRODUCT = {
    "vendor": "Example",
    "product": "xml",
    "purl": "pkg:golang/example.com/xml",
    "version_range": "vers:golang/>=v1.2.0|<v1.4.1",
}


def vulnerability(*products: dict[str, Any], **raw: Any) -> dict[str, Any]:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": VULNERABILITY_ID,
        "created": "2026-10-01T00:00:00.000Z",
        "modified": "2026-10-02T00:00:00.000Z",
        "name": "XML external entities in strict parsing",
        "description": "Strict parsing resolves external entities.",
        "external_references": [{"source_name": "cve", "external_id": "CVE-2026-4242"}],
        "extensions": {
            AIVS_INTEL_EXTENSION_ID: {
                "extension_type": "property-extension",
                "aivs_schema_version": "2.0",
                "discovery_scope": "own_product",
                "cve_status": "published",
                "cve_id": "CVE-2026-4242",
                "affected_products": list(products) if products else [GO_PRODUCT],
            }
        },
        **raw,
    }


def stated(note_id: str, *conditions: dict[str, Any]) -> ConditionSource:
    return ConditionSource(
        note_id=note_id,
        modified=WHEN,
        summary="s",
        conditions=conditions,
        unknowns=(),
        reproduced=None,
    )


AGREED = combine([stated("note--a", CALLS_PARSER, SETTING_ON, ON_LINUX)])


def refusal(vuln: dict[str, Any], view=AGREED) -> str:
    with pytest.raises(OsvRefusedError) as refused:
        osv_record(vuln, view)
    return refused.value.reason


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-86")
def test_an_agreed_function_condition_exports_a_valid_osv_record():
    record = osv_record(vulnerability(), AGREED)

    jsonschema.validate(record, OSV_SCHEMA)
    assert record["schema_version"] == OSV_SCHEMA_VERSION
    assert record["id"] == "x_AIVS-0f9c0000-0000-4000-8000-000000000001"
    assert record["aliases"] == ["CVE-2026-4242"]
    assert record["modified"] == "2026-10-15T09:30:00.000Z"  # the note is the latest change
    assert record["published"] == "2026-10-01T00:00:00.000Z"
    assert record["affected"] == [
        {
            "package": {
                "ecosystem": "Go",
                "name": "example.com/xml",
                "purl": "pkg:golang/example.com/xml",
            },
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.2.0"}, {"fixed": "1.4.1"}]}],
            "ecosystem_specific": {
                "imports": [
                    {"path": "example.com/xml", "symbols": ["ParseStrict", "Decoder.Strict"]}
                ]
            },
        }
    ]


@pytest.mark.requirement("SF-86")
def test_conditions_osv_cannot_carry_are_left_out_which_only_widens_the_record():
    """The view needs the setting and Linux as well; the record says neither,
    so a scanner flags more members than the view does, never fewer."""
    text = json.dumps(osv_record(vulnerability(), AGREED))

    assert "AllowExternalEntities" not in text
    assert "linux" not in text


@pytest.mark.parametrize(
    ("purl", "ecosystem", "name"),
    [
        ("pkg:golang/example.com/xml@v1.2.0", "Go", "example.com/xml"),
        ("pkg:npm/%40acme/parser", "npm", "@acme/parser"),
        ("pkg:npm/@acme/parser@2.0.0", "npm", "@acme/parser"),
        ("pkg:maven/org.acme/parser?type=jar", "Maven", "org.acme:parser"),
        ("pkg:pypi/acme-parser", "PyPI", "acme-parser"),
        ("pkg:composer/acme/parser", "Packagist", "acme/parser"),
    ],
)
def test_a_purl_names_the_package_as_osv_does(purl, ecosystem, name):
    scheme = {"Go": "golang", "npm": "npm", "Maven": "maven", "PyPI": "pypi"}.get(
        ecosystem, "composer"
    )
    product = {"purl": purl, "version_range": f"vers:{scheme}/<2.0.0"}

    package = osv_record(vulnerability(product), AGREED)["affected"][0]["package"]

    assert (package["ecosystem"], package["name"]) == (ecosystem, name)
    assert "@" not in package["purl"].removeprefix("pkg:npm/@")


# ---------------------------------------------------------------------------
# Versions: each vers range converts to the same set of versions, or refuses
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-86")
@pytest.mark.parametrize(
    ("vers", "ranges"),
    [
        ("vers:npm/<2.0.0", [[{"introduced": "0"}, {"fixed": "2.0.0"}]]),
        ("vers:npm/<=2.0.0", [[{"introduced": "0"}, {"last_affected": "2.0.0"}]]),
        ("vers:npm/>=1.0.0", [[{"introduced": "1.0.0"}]]),
        ("vers:npm/*", [[{"introduced": "0"}]]),
        ("vers:npm/1.0.3", [[{"introduced": "1.0.3"}, {"last_affected": "1.0.3"}]]),
        (
            "vers:npm/>=1.0.0|<=1.5.0|>=2.0.0|<2.2.0",
            [
                [{"introduced": "1.0.0"}, {"last_affected": "1.5.0"}],
                [{"introduced": "2.0.0"}, {"fixed": "2.2.0"}],
            ],
        ),
        ("vers:semver/>=1.0.0|<1.1.0", [[{"introduced": "1.0.0"}, {"fixed": "1.1.0"}]]),
    ],
)
def test_a_vers_range_converts_interval_by_interval(vers, ranges):
    product = {"purl": "pkg:npm/parser", "version_range": vers}

    record = osv_record(vulnerability(product), AGREED)

    jsonschema.validate(record, OSV_SCHEMA)
    assert [r["events"] for r in record["affected"][0]["ranges"]] == ranges


@pytest.mark.requirement("SF-86")
@pytest.mark.parametrize(
    "vers",
    [
        "vers:npm/>1.0.0",  # OSV's introduced is inclusive
        "vers:npm/!=1.0.0",  # a hole OSV events cannot state
        "vers:npm/>=1.0.0|>=2.0.0",  # two lower bounds in a row
        "vers:npm/>=1.0.0|<2.0.0|<3.0.0",  # an upper bound with no lower one
        "vers:npm/<2.0.0|*",  # every version, after a bound
        "vers:pypi/<2.0.0",  # PyPI's ordering, not npm's
    ],
)
def test_a_range_that_does_not_convert_exactly_is_refused(vers):
    product = {"purl": "pkg:npm/parser", "version_range": vers}

    assert vers in refusal(vulnerability(product))


# ---------------------------------------------------------------------------
# Refusals: what the scanner would have read as "not affected"
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-86")
def test_nothing_is_exported_until_the_sources_agree():
    unstated = combine([])
    contested = combine([stated("note--a", CALLS_PARSER), stated("note--b", SETTING_ON)])

    assert "nobody has stated" in refusal(vulnerability(), unstated)
    assert "disagree" in refusal(vulnerability(), contested)


@pytest.mark.requirement("SF-86")
def test_agreed_conditions_with_no_function_are_refused():
    assert "function" in refusal(vulnerability(), combine([stated("note--a", SETTING_ON)]))


@pytest.mark.requirement("SF-86")
def test_one_product_the_record_cannot_carry_refuses_the_whole_record():
    """Leaving it out would tell the scanner that product is safe."""
    unnamed = {"vendor": "Example", "product": "xml appliance", "version_range": "vers:npm/<2"}

    assert "no package URL" in refusal(vulnerability(GO_PRODUCT, unnamed))


@pytest.mark.requirement("SF-86")
@pytest.mark.parametrize(
    ("product", "reason"),
    [
        ({"purl": "pkg:golang/example.com/xml"}, "no version range"),
        ({"purl": "pkg:deb/debian/libxml", "version_range": "vers:deb/<2"}, "ecosystem"),
    ],
)
def test_a_product_without_a_range_or_in_an_unknown_ecosystem_is_refused(product, reason):
    assert reason in refusal(vulnerability(product))


@pytest.mark.requirement("SF-86")
def test_a_vulnerability_with_no_products_is_refused():
    vuln = vulnerability()
    vuln["extensions"][AIVS_INTEL_EXTENSION_ID]["affected_products"] = []

    assert "no affected product" in refusal(vuln)


# ---------------------------------------------------------------------------
# The endpoint
# ---------------------------------------------------------------------------
ENDPOINT = "/api/v1/vulnerabilities/osv"
pytestdb = pytest.mark.db


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
    """The vulnerability page's case: a wide circle the reader is in, a narrow one it is not."""
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


def _exportable(note_vulnerability_id: str | None = None) -> tuple[dict, dict]:
    vuln = vulnerability(id=f"vulnerability--{uuid.uuid4()}")
    note = conditions_note(note_vulnerability_id or vuln["id"], CALLS_PARSER)
    return vuln, note


@pytestdb
@pytest.mark.requirement("SF-86")
async def test_a_member_exports_what_is_shared_with_it(client, case):
    vuln, note = _exportable()
    await _share(client, case["vendor_pem"], case["isac_api"], [vuln, note], [case["wide"].id])

    response = await client.get(ENDPOINT, params={"id": vuln["id"]}, headers=_api(case["reader"]))

    assert response.status_code == 200, response.text
    jsonschema.validate(response.json(), OSV_SCHEMA)
    assert response.json()["affected"][0]["ecosystem_specific"]["imports"][0]["symbols"] == [
        "ParseStrict",
        "Decoder.Strict",
    ]


@pytestdb
@pytest.mark.requirement("SF-86")
async def test_a_condition_shared_only_elsewhere_exports_nothing(client, case):
    """The symbols are in a circle the reader is not in: it is told why, and
    the reason is the one any unestablished view gets."""
    vuln, note = _exportable()
    await _share(client, case["vendor_pem"], case["isac_api"], [vuln], [case["wide"].id])
    await _share(client, case["vendor_pem"], case["isac_api"], [note], [case["narrow"].id])

    response = await client.get(ENDPOINT, params={"id": vuln["id"]}, headers=_api(case["reader"]))

    assert response.status_code == 409
    assert "nobody has stated" in response.json()["title"]


@pytestdb
@pytest.mark.requirement("SF-86")
async def test_an_invisible_a_missing_and_a_malformed_id_answer_alike(client, case):
    vuln, note = _exportable()
    await _share(client, case["vendor_pem"], case["isac_api"], [vuln, note], [case["narrow"].id])
    headers = _api(case["reader"])

    answers = [
        await client.get(ENDPOINT, params={"id": stix_id}, headers=headers)
        for stix_id in (vuln["id"], f"vulnerability--{uuid.uuid4()}", "vulnerability--nope")
    ]

    assert {(a.status_code, a.content) for a in answers} == {(404, answers[0].content)}
