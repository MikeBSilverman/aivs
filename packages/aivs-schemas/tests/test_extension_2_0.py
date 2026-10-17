"""Extension 2.0, the provenance extension, and the rules each object type carries.

Each test is a pair where the property allows one: the refused case beside the
accepted one, so a validator that refused everything would fail as surely as
one that accepted everything.
"""

from __future__ import annotations

import copy
import datetime as dt
from typing import Any

import pytest

from aivs_schemas.enums import ACCEPTED_DISCOVERY_SCOPES
from aivs_schemas.extension.builders import (
    AIVS_EXTENSION_ID,
    AIVS_INTEL_EXTENSION_ID,
    AIVS_PROVENANCE_EXTENSION_ID,
    INTEL_EXTENSION_TYPES,
    SERVER_WRITTEN_PROVENANCE,
    AivsIntelExtension,
    AivsProvenanceExtension,
    ExtensionValidationError,
    ObjectPolicyError,
    extension_json_schema,
    intel_extension_definition_sdo,
    intel_json_schema,
    provenance_extension_definition_sdo,
    provenance_json_schema,
    validate_stix_object,
)
from aivs_schemas.extension.policy import (
    INDICATOR_PATTERN_TYPES,
    MAX_INDICATOR_LIFETIME,
    NETWORK_INDICATOR_LIFETIME,
    STIX_CYBER_OBSERVABLE_TYPES,
)

VALID_FROM = dt.datetime(2026, 8, 1, tzinfo=dt.UTC)


def stamp(value: dt.datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def vulnerability(**body: Any) -> dict[str, Any]:
    extension = {
        "extension_type": "property-extension",
        "aivs_schema_version": "2.0",
        "discovery_scope": "own_product",
        "cve_status": "pre-cve",
        "affected_products": [{"vendor": "Acme", "product": "Gateway"}],
        **body,
    }
    return {
        "type": "vulnerability",
        "id": "vulnerability--0f9c0000-0000-4000-8000-000000000001",
        "extensions": {AIVS_INTEL_EXTENSION_ID: extension},
    }


def course_of_action(**body: Any) -> dict[str, Any]:
    extension = {
        "extension_type": "property-extension",
        "aivs_schema_version": "2.0",
        "category": "workaround",
        **body,
    }
    return {
        "type": "course-of-action",
        "id": "course-of-action--0f9c0000-0000-4000-8000-000000000002",
        "extensions": {AIVS_INTEL_EXTENSION_ID: extension},
    }


def indicator(
    *,
    pattern: str = "[file:hashes.'SHA-256' = 'aa']",
    pattern_type: str = "stix",
    lifetime: dt.timedelta | None = dt.timedelta(days=30),
    **extra: Any,
) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "type": "indicator",
        "id": "indicator--0f9c0000-0000-4000-8000-000000000003",
        "pattern": pattern,
        "pattern_type": pattern_type,
        "valid_from": stamp(VALID_FROM),
        **extra,
    }
    if lifetime is not None:
        obj["valid_until"] = stamp(VALID_FROM + lifetime)
    return obj


def refused(obj: dict[str, Any], error: type[Exception] = ExtensionValidationError) -> None:
    with pytest.raises(error):
        validate_stix_object(obj)


# ---------------------------------------------------------------------------
# vulnerability
# ---------------------------------------------------------------------------
def test_a_2_0_vulnerability_with_the_new_vocabularies_is_accepted():
    validate_stix_object(
        vulnerability(
            ssvc_exploitation="active",
            ssvc_automatable="no",
            ssvc_technical_impact="total",
            ssvc_decision="Act",
            epss_score=0.42,
            epss_percentile=0.97,
            epss_date="2026-08-01",
            kev_listed=True,
            kev_date_added="2026-08-02",
            kev_due_date="2026-08-23",
            kev_ransomware_use="Known",
            novel_attack_vector=True,
            cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ssvc_exploitation", "PoC"),  # CISA's values are lower-case; no near-misses
        ("ssvc_decision", "act"),  # and its decisions capitalised, verbatim
        ("kev_ransomware_use", "known"),
        ("epss_score", 1.5),
        ("cvss_v3_vector", "CVSS:4.0/AV:N"),
    ],
)
def test_a_value_outside_the_standards_vocabulary_is_refused(field, value):
    body = {field: value}
    if field == "epss_score":
        body["epss_date"] = "2026-08-01"
    if field == "kev_ransomware_use":
        body |= {"kev_listed": True, "kev_date_added": "2026-08-02"}
    refused(vulnerability(**body))


def test_a_kev_date_on_a_vulnerability_kev_does_not_list_is_refused():
    refused(vulnerability(kev_listed=False, kev_date_added="2026-08-02"))
    refused(vulnerability(kev_date_added="2026-08-02"))
    validate_stix_object(vulnerability(kev_listed=False))


def test_a_kev_listing_without_its_date_is_refused():
    refused(vulnerability(kev_listed=True))
    validate_stix_object(vulnerability(kev_listed=True, kev_date_added="2026-08-02"))


def test_an_epss_score_without_its_model_date_is_refused():
    refused(vulnerability(epss_score=0.1))
    validate_stix_object(vulnerability(epss_score=0.1, epss_date="2026-08-01"))


def test_affected_versions_are_a_vers_range_and_free_text_is_refused():
    free_text = [{"vendor": "Acme", "product": "Gateway", "version_range": "before 4.2"}]
    vers = [
        {
            "vendor": "Acme",
            "product": "Gateway",
            "version_range": "vers:semver/>=4.0.0|<4.2.1",
            "fixed_versions": ["4.2.1"],
        }
    ]
    refused(vulnerability(affected_products=free_text))
    validate_stix_object(vulnerability(affected_products=vers))


def test_the_1_0_rules_still_hold_in_2_0():
    """Carried, not loosened: a CVE id before assignment is still refused."""
    refused(vulnerability(cve_id="CVE-2026-12345"))
    validate_stix_object(vulnerability(cve_status="assigned", cve_id="CVE-2026-12345"))


def test_a_vulnerability_carrying_both_versions_is_refused_and_either_alone_is_not():
    one = vulnerability()
    both = copy.deepcopy(one)
    both["extensions"][AIVS_EXTENSION_ID] = {
        "extension_type": "property-extension",
        "aivs_schema_version": "1.0",
        "discovery_scope": "own_product",
        "cve_status": "pre-cve",
        "affected_products": [{"vendor": "Acme", "product": "Gateway"}],
    }
    only_1_0 = {**one, "extensions": {AIVS_EXTENSION_ID: both["extensions"][AIVS_EXTENSION_ID]}}
    refused(both, ObjectPolicyError)
    validate_stix_object(one)
    validate_stix_object(only_1_0)


def test_cve_and_cwe_references_must_be_in_their_schemes_format():
    good = {
        "type": "vulnerability",
        "id": "vulnerability--0f9c0000-0000-4000-8000-000000000009",
        "external_references": [
            {"source_name": "cve", "external_id": "CVE-2026-1234"},
            {"source_name": "cwe", "external_id": "CWE-79"},
            {"source_name": "vendor", "external_id": "anything goes here"},
        ],
    }
    validate_stix_object(good)
    for bad in ("cwe-79", "CWE-79; drop", "79"):
        obj = copy.deepcopy(good)
        obj["external_references"][1]["external_id"] = bad
        refused(obj, ObjectPolicyError)


# ---------------------------------------------------------------------------
# course-of-action
# ---------------------------------------------------------------------------
def test_a_course_of_action_names_its_csaf_category():
    validate_stix_object(
        course_of_action(
            restart_required="service",
            action_type="config_change",
            residual_risk="Local users can still reach the admin port.",
            validation_check={
                "tool": "curl",
                "query_or_command": "curl -sI https://gw/admin",
                "expected_result": "HTTP/1.1 403",
            },
        )
    )
    for category in ("validation", "rollback"):  # the two of ours
        validate_stix_object(course_of_action(category=category))
    refused(course_of_action(category="hotfix"))
    no_category = course_of_action()
    del no_category["extensions"][AIVS_INTEL_EXTENSION_ID]["category"]
    refused(no_category)


def test_a_validation_check_states_tool_command_and_expected_result():
    refused(course_of_action(validation_check={"tool": "curl", "query_or_command": "curl gw"}))


# ---------------------------------------------------------------------------
# indicator
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-46")
def test_an_indicator_without_an_expiry_is_refused():
    refused(indicator(lifetime=None), ObjectPolicyError)
    validate_stix_object(indicator())


@pytest.mark.requirement("SF-46")
def test_an_address_indicator_expires_within_ninety_days():
    address = "[ipv4-addr:value = '198.51.100.7']"
    validate_stix_object(indicator(pattern=address, lifetime=NETWORK_INDICATOR_LIFETIME))
    refused(
        indicator(pattern=address, lifetime=NETWORK_INDICATOR_LIFETIME + dt.timedelta(days=1)),
        ObjectPolicyError,
    )


@pytest.mark.requirement("SF-46")
def test_a_hash_or_rule_indicator_expires_within_two_years():
    validate_stix_object(indicator(lifetime=MAX_INDICATOR_LIFETIME))
    refused(indicator(lifetime=MAX_INDICATOR_LIFETIME + dt.timedelta(days=1)), ObjectPolicyError)
    sigma = "title: x\ndetection:\n  sel: {Image: x}\n  condition: sel"
    validate_stix_object(
        indicator(pattern=sigma, pattern_type="sigma", lifetime=MAX_INDICATOR_LIFETIME)
    )


def test_an_expiry_before_the_start_is_refused():
    refused(indicator(lifetime=dt.timedelta(0)), ObjectPolicyError)


@pytest.mark.parametrize("pattern_type", sorted(INDICATOR_PATTERN_TYPES))
def test_every_pattern_type_in_the_vocabulary_is_accepted(pattern_type):
    validate_stix_object(indicator(pattern_type=pattern_type))


def test_a_pattern_type_no_member_can_run_is_refused():
    refused(indicator(pattern_type="cybox"), ObjectPolicyError)


def test_an_indicator_extension_carries_its_telemetry_needs():
    body = {
        "extension_type": "property-extension",
        "aivs_schema_version": "2.0",
        "telemetry_sources": ["windows-sysmon", "edr-process"],
        "false_positive_notes": "Backup agents read the same path.",
    }
    validate_stix_object(indicator(extensions={AIVS_INTEL_EXTENSION_ID: body}))
    refused(indicator(extensions={AIVS_INTEL_EXTENSION_ID: {**body, "category": "workaround"}}))


# ---------------------------------------------------------------------------
# attack-pattern, and types the 2.0 extension does not cover
# ---------------------------------------------------------------------------
def test_attack_pattern_references_follow_mitres_formats():
    obj = {
        "type": "attack-pattern",
        "id": "attack-pattern--0f9c0000-0000-4000-8000-000000000004",
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1190"},
            {"source_name": "capec", "external_id": "CAPEC-66"},
        ],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
    }
    validate_stix_object(obj)
    validate_stix_object(
        {
            **obj,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
        }
    )
    refused(
        {**obj, "external_references": [{"source_name": "mitre-attack", "external_id": "1190"}]},
        ObjectPolicyError,
    )
    refused({**obj, "kill_chain_phases": [{"phase_name": "initial-access"}]}, ObjectPolicyError)


# ---------------------------------------------------------------------------
# cyber observables, and file content
# ---------------------------------------------------------------------------
def observable(stix_type: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": stix_type,
        "spec_version": "2.1",
        "id": f"{stix_type}--0f9c0000-0000-4000-8000-000000000009",
        **extra,
    }


@pytest.mark.parametrize("stix_type", sorted(STIX_CYBER_OBSERVABLE_TYPES))
def test_a_cyber_observable_is_refused_naming_the_cause(stix_type):
    """Ingest refused every one for lacking ``created``, which names the wrong cause."""
    with pytest.raises(ObjectPolicyError, match="cyber observables are not accepted"):
        validate_stix_object(observable(stix_type))


@pytest.mark.parametrize(
    "content",
    [
        {"payload_bin": "aGVsbG8="},
        {"url": "https://example.org/a.bin", "hashes": {"MD5": "0" * 32}},
    ],
)
def test_an_artifact_is_refused_whether_it_carries_its_bytes_or_points_at_them(content):
    refused(observable("artifact", mime_type="text/plain", **content), ObjectPolicyError)


def test_observed_data_may_not_embed_an_artifact():
    """The other way an artifact's bytes reach every member's tooling."""
    observed = {
        "type": "observed-data",
        "id": "observed-data--0f9c0000-0000-4000-8000-00000000000a",
        "objects": {"0": {"type": "file", "name": "a.bin"}},
    }
    validate_stix_object(observed)
    refused(
        {**observed, "objects": {"1": {"type": "artifact", "payload_bin": "aGVsbG8="}}},
        ObjectPolicyError,
    )


def test_the_2_0_extension_is_refused_on_a_type_it_does_not_define():
    obj = {
        "type": "attack-pattern",
        "id": "attack-pattern--0f9c0000-0000-4000-8000-000000000005",
        "extensions": {
            AIVS_INTEL_EXTENSION_ID: {
                "extension_type": "property-extension",
                "aivs_schema_version": "2.0",
            }
        },
    }
    refused(obj)


# ---------------------------------------------------------------------------
# provenance
# ---------------------------------------------------------------------------
def with_provenance(**body: Any) -> dict[str, Any]:
    obj = course_of_action()
    obj["extensions"][AIVS_PROVENANCE_EXTENSION_ID] = {
        "extension_type": "property-extension",
        **body,
    }
    return obj


@pytest.mark.requirement("SF-6")
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("human_reviewed_by_ref", "identity--0f9c0000-0000-4000-8000-00000000000a"),
        ("reviewed_at", "2026-08-01T00:00:00.000Z"),
    ],
)
def test_a_submitter_may_not_claim_a_review(field, value):
    refused(with_provenance(**{field: value}), ObjectPolicyError)


@pytest.mark.requirement("SF-6")
def test_a_submitter_may_say_what_produced_the_object():
    validate_stix_object(with_provenance(generated_by="sigma-cli 1.0", factors=["vendor advisory"]))


def test_every_server_written_field_is_one_the_schema_defines():
    """The refusal list and the schema are two descriptions; neither may name a ghost."""
    assert set(provenance_json_schema()["properties"]) >= SERVER_WRITTEN_PROVENANCE


# ---------------------------------------------------------------------------
# The ISAC's assessment relative to the public record (Appendix D: ours)
# ---------------------------------------------------------------------------
DELTA = [
    {
        "property": "cvss_v3_vector",
        "public_value": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "isac_value": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "public_source": "nvd",
    }
]


@pytest.mark.requirement("NFR-I2")
@pytest.mark.parametrize("assessment", ["adds", "contradicts"])
def test_an_assessment_that_differs_from_the_public_record_says_where(assessment):
    validate_stix_object(vulnerability(isac_assessment=assessment, isac_assessment_delta=DELTA))
    refused(vulnerability(isac_assessment=assessment))


@pytest.mark.requirement("NFR-I2")
@pytest.mark.parametrize("assessment", ["confirms", "no_position"])
def test_an_assessment_that_agrees_or_abstains_lists_no_difference(assessment):
    validate_stix_object(vulnerability(isac_assessment=assessment))
    refused(vulnerability(isac_assessment=assessment, isac_assessment_delta=DELTA))


def test_an_assessment_outside_the_four_positions_is_refused():
    refused(vulnerability(isac_assessment="disputes"))


def test_a_difference_names_the_property_and_the_isacs_value():
    refused(
        vulnerability(isac_assessment="adds", isac_assessment_delta=[{"property": "ssvc_decision"}])
    )


def test_a_course_of_action_review_date_is_a_date():
    validate_stix_object(course_of_action(review_by="2027-01-31"))
    refused(course_of_action(review_by="next quarter"))


# ---------------------------------------------------------------------------
# The two descriptions of each extension agree (NFR-M2)
# ---------------------------------------------------------------------------
def _type_definitions() -> list[dict[str, Any]]:
    defs = intel_json_schema()["$defs"]
    return [defs[object_type] for object_type in sorted(INTEL_EXTENSION_TYPES)]


@pytest.mark.requirement("NFR-M2")
def test_2_0_registration_and_schema_describe_the_same_properties():
    schema_props = set().union(*(set(d["properties"]) for d in _type_definitions()))
    stix2_props = set(AivsIntelExtension._properties)
    assert schema_props - {"extension_type"} == stix2_props - {"extension_type"}


@pytest.mark.requirement("NFR-M2")
def test_2_0_registration_requires_exactly_what_every_type_requires():
    common = set.intersection(*(set(d["required"]) for d in _type_definitions()))
    stix2_required = {
        name for name, prop in AivsIntelExtension._properties.items() if prop.required
    }
    assert common - {"extension_type"} == stix2_required - {"extension_type"}


@pytest.mark.requirement("NFR-M2")
def test_2_0_registration_and_schema_enumerate_the_same_values():
    schema_props: dict[str, Any] = {}
    for definition in _type_definitions():
        schema_props.update(definition["properties"])
    for name, prop in AivsIntelExtension._properties.items():
        allowed = getattr(prop, "allowed", None)
        if allowed is None or name == "extension_type":
            continue
        assert set(allowed) == set(schema_props[name]["enum"]), name


@pytest.mark.requirement("NFR-M2")
def test_2_0_admits_exactly_the_accepted_scopes():
    scopes = intel_json_schema()["$defs"]["vulnerability"]["properties"]["discovery_scope"]["enum"]
    assert set(scopes) == {scope.value for scope in ACCEPTED_DISCOVERY_SCOPES}


@pytest.mark.requirement("NFR-M2")
def test_every_property_2_0_carries_from_1_0_is_described_identically():
    """Carried properties are a second description of the same thing; pin them together.

    ``affected_products`` is excluded on purpose: 2.0 changes it (vers ranges,
    fixed versions), which is the one difference the version exists for.
    """
    v1 = extension_json_schema()["properties"]
    v2 = intel_json_schema()["$defs"]["vulnerability"]["properties"]
    carried = (set(v1) & set(v2)) - {"extension_type", "aivs_schema_version", "affected_products"}
    assert carried, "nothing carried: the comparison would be vacuous"
    for name in sorted(carried):
        assert v1[name] == v2[name], name


@pytest.mark.requirement("NFR-M2")
def test_provenance_registration_and_schema_describe_the_same_properties():
    schema_props = set(provenance_json_schema()["properties"]) - {"extension_type"}
    assert schema_props == set(AivsProvenanceExtension._properties) - {"extension_type"}


def test_the_definitions_name_the_identifiers_the_code_uses():
    assert intel_extension_definition_sdo()["id"] == AIVS_INTEL_EXTENSION_ID
    assert provenance_extension_definition_sdo()["id"] == AIVS_PROVENANCE_EXTENSION_ID
    for sdo in (intel_extension_definition_sdo(), provenance_extension_definition_sdo()):
        assert sdo["extension_types"] == ["property-extension"]
