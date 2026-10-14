"""Validation of inbound STIX content.

This is the boundary that decides what AIVS accepts from a submitter and then
redistributes to every member of a sharing circle. The tests are written around
that consequence: a property that is not validated here is a property that
reaches every member unexamined.
"""

from __future__ import annotations

import datetime as dt

import pytest

from aivs_schemas.enums import (
    ACCEPTED_DISCOVERY_SCOPES,
    AIDiscoveryMethod,
    CVEStatus,
    DiscoveryScope,
)
from aivs_schemas.extension.builders import (
    AIVS_EXTENSION_ID,
    AIVS_INTEL_EXTENSION_ID,
    AIVS_PROVENANCE_EXTENSION_ID,
    ALLOWED_EXTENSION_IDS,
    MAX_BUNDLE_OBJECTS,
    AivsPreCveExtension,
    ExtensionValidationError,
    UnknownExtensionError,
    build_extension_body,
    extension_definition_sdo,
    extension_json_schema,
    validate_bundle,
    validate_stix_object,
)
from aivs_schemas.tlp import (
    LEGACY_TLP10_MARKING_IDS,
    TLP,
    TLP20_EXTENSION_DEFINITION_ID,
    TLP_MARKING_IDS,
    is_tlp_marking_id,
    marking_definition_for,
    tlp_for_marking_id,
)

VALID_BODY = {
    "extension_type": "property-extension",
    "aivs_schema_version": "1.0",
    "ai_discovery_method": "fuzzing",
    "discovery_scope": "own_product",
    "cve_status": "pre-cve",
    "affected_products": [{"vendor": "Acme", "product": "Gateway"}],
}


def wrap(body: dict, stix_id: str = "vulnerability--0f9c0000-0000-4000-8000-000000000001") -> dict:
    return {"id": stix_id, "type": "vulnerability", "extensions": {AIVS_EXTENSION_ID: body}}


def sealed(**overrides: object) -> dict:
    payload = {
        "protected": "eyJhbGciOiJkaXIifQ",
        "recipients": [{"header": {"kid": "org:meridian:1"}, "encrypted_key": "AAAA"}],
        "iv": "AAAA",
        "ciphertext": "BBBB",
        "tag": "CCCC",
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# The extension allowlist
# ---------------------------------------------------------------------------
def test_unknown_extension_definition_is_rejected():
    """The gap stix2 leaves open must be closed here.

    stix2.parse(allow_custom=False) does NOT reject an unregistered
    ``extension-definition--`` property extension; it passes the body through as
    an opaque dict. Without this check AIVS would store and redistribute content
    it never validated.
    """
    obj = {
        "id": "vulnerability--x",
        "extensions": {
            "extension-definition--00000000-0000-4000-8000-000000000000": {
                "extension_type": "property-extension"
            }
        },
    }
    with pytest.raises(UnknownExtensionError):
        validate_stix_object(obj)


def test_allowlist_contains_only_the_intended_extensions():
    """AIVS's own three extensions and TLP 2.0, by identity rather than by count.

    Asserting a length holds for any set of distinct constants, so swapping
    TLP 2.0 for an arbitrary third-party extension would have passed -- in the
    only test of the contents of the gate that decides what AIVS redistributes.
    """
    assert (
        frozenset(
            {
                AIVS_EXTENSION_ID,
                AIVS_INTEL_EXTENSION_ID,
                AIVS_PROVENANCE_EXTENSION_ID,
                TLP20_EXTENSION_DEFINITION_ID,
            }
        )
        == ALLOWED_EXTENSION_IDS
    )


def test_a_tlp20_marked_object_is_accepted():
    """The second allowlist entry, exercised positively.

    Without this the TLP 2.0 entry is only ever asserted to be present, never
    shown to work.
    """
    validate_stix_object(
        {
            "id": "vulnerability--0f9c0000-0000-4000-8000-000000000009",
            "type": "vulnerability",
            "extensions": {
                TLP20_EXTENSION_DEFINITION_ID: {
                    "extension_type": "property-extension",
                    "tlp_2_0": "amber+strict",
                }
            },
        }
    )


def test_extensions_must_be_an_object():
    """A list-valued `extensions` must not slip past the membership check."""
    with pytest.raises(UnknownExtensionError):
        validate_stix_object({"id": "vulnerability--x", "extensions": ["not-an-object"]})


def test_object_without_extensions_is_accepted():
    """Most STIX objects carry no extension at all; that is normal."""
    validate_stix_object({"id": "identity--x", "type": "identity", "name": "Acme"})


# ---------------------------------------------------------------------------
# Schema strictness -- nothing unvalidated may ride along
# ---------------------------------------------------------------------------
def test_root_rejects_unknown_properties():
    body = {**VALID_BODY, "unexpected_property": "rides along"}
    with pytest.raises(ExtensionValidationError):
        validate_stix_object(wrap(body))


def test_affected_products_rejects_unknown_properties():
    body = {**VALID_BODY, "affected_products": [{"vendor": "a", "product": "b", "extra": "x"}]}
    with pytest.raises(ExtensionValidationError):
        validate_stix_object(wrap(body))


def test_sealed_payload_rejects_unknown_properties():
    """Regression: the sealed payload sub-objects were initially unconstrained.

    `additionalProperties: false` was set at the root and on affected_products
    but not on sealed_payload, so arbitrary properties could ride along one level
    down -- reintroducing, inside the envelope, exactly the hole the extension
    allowlist exists to close.
    """
    body = {
        **VALID_BODY,
        "sealed_payload": sealed(extra_unvalidated_field="rides along"),
        "sealed_payload_recipients": ["org:meridian:1"],
    }
    with pytest.raises(ExtensionValidationError):
        validate_stix_object(wrap(body))


def test_sealed_payload_recipient_header_rejects_unknown_properties():
    body = {
        **VALID_BODY,
        "sealed_payload": sealed(
            recipients=[{"header": {"kid": "k", "smuggled": "d"}, "encrypted_key": "e"}]
        ),
        "sealed_payload_recipients": ["k"],
    }
    with pytest.raises(ExtensionValidationError):
        validate_stix_object(wrap(body))


def test_a_well_formed_sealed_payload_still_validates():
    """The constraint must not be so tight that a real JWE is rejected."""
    body = {
        **VALID_BODY,
        "sealed_payload": sealed(
            recipients=[
                {
                    "header": {
                        "kid": "org:meridian:1",
                        "alg": "ECDH-ES+A256KW",
                        "epk": {"kty": "EC", "crv": "P-384"},
                        "apu": "QWxpY2U",
                    },
                    "encrypted_key": "AAAA",
                }
            ]
        ),
        "sealed_payload_recipients": ["org:meridian:1"],
        "sealed_payload_content_type": "application/json",
    }
    validate_stix_object(wrap(body))


def test_sealed_payload_requires_a_declared_recipient_set():
    """The transparency property is enforced by the schema, not by convention.

    A submitter must be able to audit who can decrypt without decrypting, so the
    recipient list is declared outside the envelope and is mandatory whenever a
    sealed payload is present.
    """
    body = {**VALID_BODY, "sealed_payload": sealed()}
    with pytest.raises(ExtensionValidationError):
        validate_stix_object(wrap(body))


# ---------------------------------------------------------------------------
# Conditional rules
# ---------------------------------------------------------------------------
def test_cve_id_is_forbidden_before_assignment():
    """A placeholder identifier must not be readable as authoritative."""
    body = {**VALID_BODY, "cve_status": "pre-cve", "cve_id": "CVE-2026-1111"}
    with pytest.raises(ExtensionValidationError):
        validate_stix_object(wrap(body))


def test_cve_id_is_required_once_assigned():
    body = {**VALID_BODY, "cve_status": "assigned"}
    with pytest.raises(ExtensionValidationError):
        validate_stix_object(wrap(body))


def test_timer_embargo_requires_a_release_time():
    body = {**VALID_BODY, "embargo_policy": "timer"}
    with pytest.raises(ExtensionValidationError):
        validate_stix_object(wrap(body))


def test_cvss_score_requires_its_vector():
    """A score without its vector cannot be audited or recomputed."""
    body = {**VALID_BODY, "cvss_v4_base_score": 9.1}
    with pytest.raises(ExtensionValidationError):
        validate_stix_object(wrap(body))


@pytest.mark.parametrize("missing", ["discovery_scope", "cve_status"])
def test_required_properties_are_enforced(missing):
    body = {key: value for key, value in VALID_BODY.items() if key != missing}
    with pytest.raises(ExtensionValidationError):
        validate_stix_object(wrap(body))


def test_a_finding_without_an_ai_discovery_method_is_accepted():
    """Optional: a contribution about a vulnerability no AI system found has no
    method to state, and a required value would force the submitter to invent one."""
    body = {key: value for key, value in VALID_BODY.items() if key != "ai_discovery_method"}

    validate_stix_object(wrap(body))


def test_an_ai_discovery_method_that_is_present_must_still_be_a_known_one():
    with pytest.raises(ExtensionValidationError):
        validate_stix_object(wrap({**VALID_BODY, "ai_discovery_method": "intuition"}))


def test_discovery_scope_is_constrained_to_the_v1_content_policy():
    """v1 accepts own-product, own-estate, and AI-system findings only.

    This is the structural half of the control that keeps AIVS clear of the
    coordinated-disclosure consent problem.
    """
    schema = extension_json_schema()
    assert set(schema["properties"]["discovery_scope"]["enum"]) == {
        "own_product",
        "own_estate",
        "ai_system",
    }


@pytest.mark.parametrize("scope", sorted(ACCEPTED_DISCOVERY_SCOPES))
def test_a_bundle_declaring_an_accepted_scope_is_accepted(scope):
    validate_stix_object(wrap({**VALID_BODY, "discovery_scope": scope.value}))


@pytest.mark.parametrize(
    "reserved", sorted(set(DiscoveryScope) - ACCEPTED_DISCOVERY_SCOPES), ids=str
)
def test_a_bundle_declaring_a_reserved_scope_is_refused_as_an_unknown_one_is(reserved):
    """The reserved scopes are storage values only until Phase E admits them.

    Refused with the message an unheard-of value gets, the value itself aside, so
    the refusal does not advertise which values the server already knows.
    """
    with pytest.raises(ExtensionValidationError) as refused:
        validate_stix_object(wrap({**VALID_BODY, "discovery_scope": reserved.value}))
    with pytest.raises(ExtensionValidationError) as unknown:
        validate_stix_object(wrap({**VALID_BODY, "discovery_scope": "never_heard_of_it"}))

    assert str(refused.value).replace(reserved.value, "<value>") == str(unknown.value).replace(
        "never_heard_of_it", "<value>"
    )


# ---------------------------------------------------------------------------
# The two descriptions of the extension must agree
# ---------------------------------------------------------------------------
@pytest.mark.requirement("NFR-M2")
def test_stix2_registration_and_json_schema_describe_the_same_properties():
    """Regression: the reserved sealed_payload fields were in one and not the other.

    The stix2 CustomExtension registration and the JSON Schema are independent
    descriptions of one extension. Where they disagree, content valid under one
    fails under the other -- here, a sealed object would have passed schema
    validation and then failed stix2 parsing with a custom-content error.
    """
    schema_props = set(extension_json_schema()["properties"]) - {"extension_type"}
    stix2_props = set(AivsPreCveExtension._properties) - {"extension_type"}
    assert schema_props == stix2_props, (
        "JSON Schema and stix2 registration have diverged; "
        f"schema-only={sorted(schema_props - stix2_props)}, "
        f"stix2-only={sorted(stix2_props - schema_props)}"
    )


@pytest.mark.requirement("NFR-M2")
def test_stix2_registration_and_json_schema_require_the_same_properties():
    """``ai_discovery_method`` became optional in both; one alone would accept in
    one validator what the other refuses."""
    schema_required = set(extension_json_schema()["required"]) - {"extension_type"}
    stix2_required = {
        name
        for name, prop in AivsPreCveExtension._properties.items()
        if prop.required and name != "extension_type"
    }
    assert schema_required == stix2_required


@pytest.mark.requirement("NFR-M2")
def test_stix2_registration_and_json_schema_enumerate_the_same_values():
    schema_props = extension_json_schema()["properties"]
    for name, prop in AivsPreCveExtension._properties.items():
        allowed = getattr(prop, "allowed", None)
        if allowed is None or name == "extension_type":
            continue
        assert set(allowed) == set(schema_props[name]["enum"]), name


@pytest.mark.requirement("NFR-M2")
def test_the_extension_admits_exactly_the_accepted_scopes():
    """The second description of the accepted set: the schema file is static JSON,
    so it is pinned to the Python set that every other surface reads."""
    schema_scopes = set(extension_json_schema()["properties"]["discovery_scope"]["enum"])
    assert schema_scopes == {scope.value for scope in ACCEPTED_DISCOVERY_SCOPES}


def test_extension_definition_id_matches_the_code_constant():
    """`extension_definition_sdo` raises on divergence, so this asserts the
    loader succeeds at all -- the identity check itself lives in the loader."""
    assert extension_definition_sdo()["id"] == AIVS_EXTENSION_ID


def test_extension_definition_is_a_property_extension():
    assert extension_definition_sdo()["extension_types"] == ["property-extension"]


# ---------------------------------------------------------------------------
# Bundle validation
# ---------------------------------------------------------------------------
@pytest.mark.requirement("NFR-I1")
def test_every_object_in_a_bundle_is_validated():
    """An object nobody looked at still reaches every member of the circle."""
    bundle = {
        "type": "bundle",
        "objects": [
            {"id": "identity--a", "type": "identity", "name": "Acme"},
            {
                "id": "vulnerability--b",
                "type": "vulnerability",
                "extensions": {"extension-definition--00000000-0000-4000-8000-000000000000": {}},
            },
        ],
    }
    with pytest.raises(UnknownExtensionError):
        validate_bundle(bundle)


def test_valid_bundle_returns_its_object_count():
    bundle = {
        "type": "bundle",
        "objects": [
            {"id": "identity--a", "type": "identity"},
            wrap(dict(VALID_BODY)),
        ],
    }
    assert validate_bundle(bundle) == 2


def test_non_bundle_is_rejected():
    with pytest.raises(ValueError, match="expected a STIX bundle"):
        validate_bundle({"type": "vulnerability"})


def test_oversized_bundle_is_rejected():
    bundle = {
        "type": "bundle",
        "objects": [
            {"id": f"identity--{i}", "type": "identity"} for i in range(MAX_BUNDLE_OBJECTS + 1)
        ],
    }
    with pytest.raises(ValueError, match="limit is"):
        validate_bundle(bundle)


def test_empty_bundle_is_legal():
    assert validate_bundle({"type": "bundle"}) == 0


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
def test_builder_output_validates():
    body = build_extension_body(
        ai_discovery_method=AIDiscoveryMethod.EXPLOIT_CHAIN_SEARCH,
        discovery_scope=DiscoveryScope.AI_SYSTEM,
        cve_status=CVEStatus.PRE_CVE,
        affected_products=[{"vendor": "Acme", "product": "AgentRuntime"}],
        embargo_policy="timer",
        embargo_release_at=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
    )
    validate_stix_object(wrap(body))
    assert body["embargo_release_at"] == "2026-09-01T00:00:00.000Z"


def test_builder_refuses_a_naive_embargo_timestamp():
    """Guessing a timezone on an embargo release time publishes content early."""
    with pytest.raises(ValueError, match="naive datetime"):
        build_extension_body(
            ai_discovery_method=AIDiscoveryMethod.FUZZING,
            discovery_scope=DiscoveryScope.OWN_PRODUCT,
            cve_status=CVEStatus.PRE_CVE,
            affected_products=[{"vendor": "a", "product": "b"}],
            embargo_release_at=dt.datetime(2026, 9, 1),  # noqa: DTZ001 - the point
        )


# ---------------------------------------------------------------------------
# TLP 2.0
# ---------------------------------------------------------------------------
def test_tlp20_marking_ids_are_the_oasis_values():
    """These identifiers are the entire basis of interoperable handling."""
    assert TLP_MARKING_IDS[TLP.CLEAR] == (
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    )
    assert TLP_MARKING_IDS[TLP.AMBER_STRICT] == (
        "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003"
    )
    assert TLP_MARKING_IDS[TLP.RED] == ("marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1")


def test_tlp20_ids_are_distinct_from_the_tlp10_namesakes():
    """TLP 2.0 GREEN/AMBER/RED are different objects from TLP 1.0's."""
    assert set(TLP_MARKING_IDS.values()).isdisjoint(set(LEGACY_TLP10_MARKING_IDS.values()))


def test_legacy_tlp10_markings_are_not_silently_upgraded():
    """TLP 1.0 AMBER and TLP 2.0 AMBER carry different handling obligations."""
    for legacy_id in LEGACY_TLP10_MARKING_IDS.values():
        assert tlp_for_marking_id(legacy_id) is None


def test_a_legacy_tlp10_marking_is_still_a_tlp_marking():
    """Not translated, but not mistaken for a statement marking either: a TLP 1.0
    marking beside the submission's TLP 2.0 one is a conflict, and the KEV
    script must not carry it into a version as if it were the record's own."""
    for marking_id in [*TLP_MARKING_IDS.values(), *LEGACY_TLP10_MARKING_IDS.values()]:
        assert is_tlp_marking_id(marking_id)
    assert not is_tlp_marking_id("marking-definition--0b3e1c6e-7f4a-4a8e-9a39-5d6f2c4b8e11")


def test_marking_definition_returns_a_mutable_copy():
    """Callers place these into bundles they then mutate."""
    first = marking_definition_for(TLP.AMBER)
    first["name"] = "mutated"
    assert marking_definition_for(TLP.AMBER)["name"] == "TLP:AMBER"


def test_marking_definitions_carry_no_modified_property():
    """Marking definitions are not versionable; a `modified` makes them invalid."""
    for tlp in TLP:
        assert "modified" not in marking_definition_for(tlp)
