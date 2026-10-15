"""Exploitability conditions on a ``note`` (plan, Phase N).

What makes a vulnerability exploitable, as data a member's tooling can
evaluate: every condition must hold, each satisfied by any one of its
alternatives. A condition tells most members they are *not* affected, so a
malformed one is refused at ingest, naming the object and the term (Phase N,
property 5), never stored as prose a tool would misread.

Each test is a pair where the property allows one: the refused case beside the
accepted one.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from aivs_schemas.extension.builders import (
    AIVS_INTEL_EXTENSION_ID,
    ExtensionValidationError,
    ObjectPolicyError,
    validate_stix_object,
)

VULNERABILITY_ID = "vulnerability--0f9c0000-0000-4000-8000-000000000001"


def condition(kind: str, *any_of: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"id": f"{kind}-1", "kind": kind, "any_of": list(any_of), **extra}


FUNCTION = condition(
    "function",
    {"ecosystem": "Go", "package": "pkg:golang/example.com/xml", "symbol": "ParseStrict"},
    how_to_check={
        "tool": "govulncheck",
        "query_or_command": "govulncheck ./...",
        "expected_result": "no call path to example.com/xml.ParseStrict",
    },
    if_absent="vulnerable_code_not_in_execute_path",
)
SETTING = condition(
    "configuration",
    {
        "product": "example xml",
        "setting": "AllowExternalEntities",
        "predicate": "equals",
        "value": "true",
        "default_state": "not_exploitable",
    },
    if_absent="vulnerable_code_cannot_be_controlled_by_adversary",
)
PLATFORM = condition("platform", {"os": "linux"}, {"os": "darwin", "arch": "arm64"})


def note(*conditions: dict[str, Any], **body: Any) -> dict[str, Any]:
    extension = {
        "extension_type": "property-extension",
        "aivs_schema_version": "2.1",
        "summary": "Exploitable only through strict parsing with external entities on.",
        "conditions": list(conditions) if conditions else [FUNCTION, SETTING, PLATFORM],
        **body,
    }
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--0f9c0000-0000-4000-8000-000000000101",
        "created": "2026-10-15T00:00:00.000Z",
        "modified": "2026-10-15T00:00:00.000Z",
        "content": "Exploitability conditions.",
        "object_refs": [VULNERABILITY_ID],
        "extensions": {AIVS_INTEL_EXTENSION_ID: extension},
    }


def refused(obj: dict[str, Any], *fragments: str) -> None:
    with pytest.raises((ExtensionValidationError, ObjectPolicyError)) as caught:
        validate_stix_object(obj)
    for fragment in fragments:
        assert fragment in str(caught.value)


@pytest.mark.requirement("SF-83")
def test_a_note_stating_all_three_kinds_of_condition_is_accepted():
    validate_stix_object(
        note(unknowns=["whether Windows is affected is untested"], reproduced=True)
    )


@pytest.mark.requirement("SF-83")
def test_a_note_with_no_conditions_is_refused():
    """An empty list is what a tool reads as "no requirements": exploitable everywhere
    would be the safe reading, and nobody should be asked to rely on that."""
    obj = note()
    obj["extensions"][AIVS_INTEL_EXTENSION_ID]["conditions"] = []
    refused(obj, obj["id"])


@pytest.mark.requirement("SF-83")
def test_a_condition_with_no_alternatives_is_refused():
    refused(note(condition("platform")), "any_of")


@pytest.mark.parametrize("symbol", ["Parse Strict", "ParseStrict()\n", "", "x" * 201], ids=repr)
def test_a_function_symbol_must_be_an_identifier(symbol):
    bad = copy.deepcopy(FUNCTION)
    bad["any_of"][0]["symbol"] = symbol
    refused(note(bad), "symbol")


@pytest.mark.requirement("SF-83")
def test_a_function_names_its_package_as_a_purl():
    bad = copy.deepcopy(FUNCTION)
    bad["any_of"][0]["package"] = "example.com/xml"
    refused(note(bad), "package")


@pytest.mark.requirement("SF-83")
def test_a_configuration_without_a_setting_is_refused():
    bad = copy.deepcopy(SETTING)
    del bad["any_of"][0]["setting"]
    refused(note(bad), "setting")


@pytest.mark.requirement("SF-83")
def test_a_configuration_says_whether_a_fresh_install_is_exploitable():
    bad = copy.deepcopy(SETTING)
    del bad["any_of"][0]["default_state"]
    refused(note(bad), "default_state")


@pytest.mark.requirement("SF-83")
def test_a_platform_outside_the_vocabulary_is_refused():
    refused(note(condition("platform", {"os": "Linux 6"})), "os")


@pytest.mark.requirement("SF-83")
def test_a_platform_may_be_a_cpe_instead():
    validate_stix_object(
        note(condition("platform", {"cpe": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}))
    )


@pytest.mark.requirement("SF-83")
def test_a_term_of_another_kind_is_refused():
    """A file path offered as a function alternative is not a function."""
    refused(note(condition("function", {"path": "xml/strict.go"})), "any_of")


@pytest.mark.requirement("SF-83")
def test_a_version_is_a_vers_range():
    validate_stix_object(note(condition("version", {"vers": "vers:golang/>=1.2.0|<1.4.1"})))
    refused(note(condition("version", {"vers": "1.2 to 1.4"})), "vers")


@pytest.mark.requirement("SF-83")
def test_exposure_uses_cvss_v4_values():
    validate_stix_object(note(condition("exposure", {"AV": "N", "PR": "N", "UI": "N"})))
    refused(note(condition("exposure", {"AV": "network"})), "AV")


@pytest.mark.requirement("SF-83")
def test_if_absent_is_a_vex_justification():
    bad = copy.deepcopy(FUNCTION)
    bad["if_absent"] = "we checked"
    refused(note(bad), "if_absent")


@pytest.mark.requirement("SF-83")
def test_condition_ids_are_unique_within_a_note():
    """Posture pre-fill cites a condition by id; two with one id cite either."""
    twin = copy.deepcopy(SETTING)
    twin["id"] = FUNCTION["id"]
    refused(note(FUNCTION, twin), FUNCTION["id"])


@pytest.mark.requirement("SF-83")
def test_conditions_are_about_a_vulnerability():
    obj = note()
    obj["object_refs"] = ["indicator--0f9c0000-0000-4000-8000-000000000009"]
    refused(obj, obj["id"], "vulnerability")
