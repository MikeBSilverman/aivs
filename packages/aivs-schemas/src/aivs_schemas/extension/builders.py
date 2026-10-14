"""The AIVS STIX 2.1 pre-CVE property-extension: registration, construction, validation.

This module is the only place in AIVS that talks to the ``stix2`` library
directly. Everything else works with plain dictionaries or the typed builders
here, which keeps an untyped third-party surface contained to one reviewable
file.

Security note -- why this module validates extensions itself
------------------------------------------------------------
``stix2.parse(..., allow_custom=False)`` does **not** reject unknown
property-extensions keyed by an ``extension-definition--<uuid>`` identifier. It
validates only that the identifier is well-formed and then passes the extension
body through as an opaque dictionary. Verified against ``stix2`` 3.0.2:

* unknown ``x-foo-ext`` key            -> raises ``InvalidValueError``
* unknown ``extension-definition--...`` -> **parses silently**

So ``allow_custom=False`` alone would let a submitter smuggle arbitrary
unvalidated content into objects that AIVS then stores and redistributes to
every member of a circle. :func:`assert_extensions_allowed` closes that gap with
an explicit allowlist, and :func:`validate_stix_object` additionally validates
our own extension body against its JSON Schema. Both run on every inbound
object; neither is optional.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
from collections.abc import Callable, Iterator, Mapping, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

import jsonschema
from stix2 import CustomExtension
from stix2.properties import (
    BooleanProperty,
    DictionaryProperty,
    EnumProperty,
    FloatProperty,
    IntegerProperty,
    ListProperty,
    ReferenceProperty,
    StringProperty,
)

from aivs_schemas.enums import (
    ACCEPTED_DISCOVERY_SCOPES,
    AIDiscoveryMethod,
    CVEStatus,
    DiscoveryScope,
)
from aivs_schemas.extension.errors import (
    BundleValidationError,
    ExtensionValidationError,
    ObjectPolicyError,
    UnknownExtensionError,
)
from aivs_schemas.extension.policy import apply_type_policy
from aivs_schemas.tlp import (
    LEGACY_TLP10_MARKING_IDS,
    TLP20_EXTENSION_DEFINITION_ID,
    TLP_MARKING_IDS,
)

__all__ = [
    "AIVS_EXTENSION_ID",
    "AIVS_INTEL_EXTENSION_ID",
    "AIVS_PROJECT_IDENTITY_ID",
    "AIVS_PROVENANCE_EXTENSION_ID",
    "ALLOWED_EXTENSION_IDS",
    "EXPLOIT_CHAIN_GROUPING_CONTEXT",
    "INTEL_EXTENSION_TYPES",
    "MAX_BUNDLE_OBJECTS",
    "RELATIONSHIP_CHAINS_TO",
    "SERVER_WRITTEN_PROVENANCE",
    "AivsIntelExtension",
    "AivsPreCveExtension",
    "AivsProvenanceExtension",
    "BundleValidationError",
    "ExtensionValidationError",
    "ObjectPolicyError",
    "UnknownExtensionError",
    "assert_extensions_allowed",
    "build_extension_body",
    "extension_definition_sdo",
    "extension_json_schema",
    "intel_extension_definition_sdo",
    "intel_json_schema",
    "provenance_extension_definition_sdo",
    "provenance_json_schema",
    "validate_bundle",
    "validate_stix_object",
]

#: Fixed identifier for the AIVS property-extension. Minted once; never changes.
#: A new identifier would be a new, unrecognised extension to every member's TIP.
AIVS_EXTENSION_ID: Final[str] = "extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6"

#: The intelligence extension, 2.0. A new identifier rather than a new version
#: of the 1.0 one: 1.0 stays registered and accepted, and a consumer that only
#: understands 1.0 must not mistake a 2.0 body for one it can read.
AIVS_INTEL_EXTENSION_ID: Final[str] = "extension-definition--a61c713d-42f5-4e19-bffc-6870dc66d209"

#: The provenance extension: who at the ISAC reviewed an object, and what the
#: submitter says produced it.
AIVS_PROVENANCE_EXTENSION_ID: Final[str] = (
    "extension-definition--b9ebb26e-6564-439d-af75-ebc68cf19bc0"
)

#: The object types the 2.0 extension has a definition for. On any other type
#: it is refused: a body nobody defined for that type means nothing to anyone.
INTEL_EXTENSION_TYPES: Final[frozenset[str]] = frozenset(
    {"vulnerability", "course-of-action", "indicator"}
)

#: Provenance fields the server writes when the ISAC validates. A submitter
#: that sets one is claiming a review that did not happen (SF-6).
SERVER_WRITTEN_PROVENANCE: Final[frozenset[str]] = frozenset(
    {"human_reviewed_by_ref", "reviewed_at"}
)

#: The AIVS project's own STIX identity, which authors the extension definition.
#: Distinct from any hosting ISAC's identity -- the extension is shared across
#: deployments, the ISAC identity is per-instance.
AIVS_PROJECT_IDENTITY_ID: Final[str] = "identity--e50b8964-5a9a-4d4b-a016-16ea043c2c56"

#: Extensions AIVS will accept on inbound content. Anything else is rejected
#: rather than stored: we redistribute what we accept, so accepting content we
#: cannot validate would make AIVS a delivery mechanism for it.
ALLOWED_EXTENSION_IDS: Final[frozenset[str]] = frozenset(
    {
        AIVS_EXTENSION_ID,
        AIVS_INTEL_EXTENSION_ID,
        AIVS_PROVENANCE_EXTENSION_ID,
        TLP20_EXTENSION_DEFINITION_ID,
    }
)

#: Relationship type linking one vulnerability to the next step of a chain.
#: STIX permits producer-defined relationship types; this one is documented in
#: docs/stix-extension.md so consumers can traverse chains deterministically.
RELATIONSHIP_CHAINS_TO: Final[str] = "chains-to"

#: ``grouping.context`` value collecting the members of one exploit chain.
EXPLOIT_CHAIN_GROUPING_CONTEXT: Final[str] = "exploit-chain"

_SCHEMA_DIR: Final[Path] = Path(__file__).parent
_CURRENT_SCHEMA_VERSION: Final[str] = "1.0"

#: Upper bound on objects in one inbound bundle. A submission is a finding and
#: its supporting objects -- a chain of a few dozen at most. The bound exists so
#: that validation cost stays proportional to something a reviewer can reason
#: about, rather than to whatever a client chose to send.
MAX_BUNDLE_OBJECTS: Final[int] = 5000

#: How deep the extension allowlist walks into nested objects before refusing.
#: STIX nests a handful of levels at most; anything deeper is not a real document.
_MAX_NESTING_DEPTH: Final[int] = 12

#: Marking-definition identifiers fixed by specification. Both TLP 2.0 and the
#: legacy TLP 1.0 set are included: a consumer that still recognises a 1.0
#: identifier would be misled by a redefinition of it just as readily.
_RESERVED_MARKING_IDS: Final[frozenset[str]] = frozenset(
    set(TLP_MARKING_IDS.values()) | set(LEGACY_TLP10_MARKING_IDS.values())
)


# ---------------------------------------------------------------------------
# stix2 registration
#
# The decorator's first argument is the extension identifier; the extension
# *kind* is declared by the ``extension_type`` class attribute, which stix2
# turns into a fixed enumerated property on the generated class.
# ---------------------------------------------------------------------------
@CustomExtension(
    AIVS_EXTENSION_ID,
    [
        ("aivs_schema_version", StringProperty(required=True)),
        # Optional: a contribution about a vulnerability that no AI system
        # found has no method to state, and a required value would force one.
        ("ai_discovery_method", EnumProperty(allowed=[m.value for m in AIDiscoveryMethod])),
        ("ai_model_name", StringProperty()),
        ("ai_harness_name", StringProperty()),
        ("ai_harness_version", StringProperty()),
        ("ai_confidence", IntegerProperty(min=0, max=100)),
        ("ai_reproduction_available", BooleanProperty()),
        (
            "discovery_scope",
            # The accepted scopes, not every member of the enum: the reserved
            # values are storage only, and a bundle declaring one is refused
            # exactly as an unknown value is.
            EnumProperty(
                allowed=[s.value for s in DiscoveryScope if s in ACCEPTED_DISCOVERY_SCOPES],
                required=True,
            ),
        ),
        ("affected_products", ListProperty(DictionaryProperty(spec_version="2.1"), required=True)),
        ("cvss_v4_vector", StringProperty()),
        ("cvss_v4_base_score", FloatProperty(min=0, max=10)),
        ("cvss_v4_severity", StringProperty()),
        ("embargo_policy", StringProperty()),
        ("embargo_release_at", StringProperty()),
        ("remediation_summary", StringProperty()),
        ("workaround_available", BooleanProperty()),
        ("cve_status", EnumProperty(allowed=[s.value for s in CVEStatus], required=True)),
        ("cve_id", StringProperty()),
        ("exploit_chain_position", IntegerProperty(min=1, max=100)),
        # Reserved for end-to-end encrypted payloads; see docs/encryption-design.md.
        # Declared here as well as in the JSON Schema because these are two
        # independent descriptions of the same extension, and content valid under
        # one but not the other round-trips inconsistently: an object carrying a
        # sealed payload would pass schema validation and then fail stix2 parsing
        # with a custom-content error. The shapes are enforced by the JSON Schema;
        # these declarations exist so stix2 recognises the properties at all.
        ("sealed_payload", DictionaryProperty(spec_version="2.1")),
        ("sealed_payload_recipients", ListProperty(StringProperty)),
        ("sealed_payload_content_type", StringProperty()),
    ],
)
class AivsPreCveExtension:
    """Pre-CVE AI vulnerability properties attached to a STIX ``vulnerability``."""

    extension_type = "property-extension"


#: Vocabularies of the 2.0 extension, verbatim from the standard each names
#: (schema-2.0.json says which), plus the values marked *ours* there. Declared
#: once here for stix2; the parity tests pin them to the JSON Schema.
_SSVC_EXPLOITATION: Final[tuple[str, ...]] = ("none", "poc", "active")
_SSVC_AUTOMATABLE: Final[tuple[str, ...]] = ("yes", "no")
_SSVC_TECHNICAL_IMPACT: Final[tuple[str, ...]] = ("partial", "total")
_SSVC_DECISION: Final[tuple[str, ...]] = ("Track", "Track*", "Attend", "Act")
_KEV_RANSOMWARE_USE: Final[tuple[str, ...]] = ("Known", "Unknown")
_REMEDIATION_CATEGORY: Final[tuple[str, ...]] = (
    "vendor_fix",
    "mitigation",
    "workaround",
    "no_fix_planned",
    "none_available",
    "validation",
    "rollback",
)
_RESTART_REQUIRED: Final[tuple[str, ...]] = (
    "none",
    "vulnerable_component",
    "service",
    "parent",
    "dependencies",
    "connected",
    "machine",
    "zone",
    "system",
)
_ACTION_TYPE: Final[tuple[str, ...]] = (
    "config_change",
    "credential_rotation",
    "dependency_upgrade",
    "compromise_assessment",
)


# One registration for every type the 2.0 extension applies to, because stix2
# registers an extension per identifier, not per object type. Required here is
# only what every type's definition requires; per-type requirements are the
# JSON Schema's, which validate_stix_object applies by the object's type.
@CustomExtension(
    AIVS_INTEL_EXTENSION_ID,
    [
        ("aivs_schema_version", StringProperty(required=True)),
        # vulnerability -- carried from 1.0
        ("ai_discovery_method", EnumProperty(allowed=[m.value for m in AIDiscoveryMethod])),
        ("ai_model_name", StringProperty()),
        ("ai_harness_name", StringProperty()),
        ("ai_harness_version", StringProperty()),
        ("ai_confidence", IntegerProperty(min=0, max=100)),
        ("ai_reproduction_available", BooleanProperty()),
        (
            "discovery_scope",
            EnumProperty(
                allowed=[s.value for s in DiscoveryScope if s in ACCEPTED_DISCOVERY_SCOPES]
            ),
        ),
        ("affected_products", ListProperty(DictionaryProperty(spec_version="2.1"))),
        ("cvss_v4_vector", StringProperty()),
        ("cvss_v4_base_score", FloatProperty(min=0, max=10)),
        ("cvss_v4_severity", StringProperty()),
        ("embargo_policy", StringProperty()),
        ("embargo_release_at", StringProperty()),
        ("remediation_summary", StringProperty()),
        ("workaround_available", BooleanProperty()),
        ("cve_status", EnumProperty(allowed=[s.value for s in CVEStatus])),
        ("cve_id", StringProperty()),
        ("exploit_chain_position", IntegerProperty(min=1, max=100)),
        # vulnerability -- new in 2.0
        ("cvss_v3_vector", StringProperty()),
        ("ssvc_exploitation", EnumProperty(allowed=list(_SSVC_EXPLOITATION))),
        ("ssvc_automatable", EnumProperty(allowed=list(_SSVC_AUTOMATABLE))),
        ("ssvc_technical_impact", EnumProperty(allowed=list(_SSVC_TECHNICAL_IMPACT))),
        ("ssvc_decision", EnumProperty(allowed=list(_SSVC_DECISION))),
        ("epss_score", FloatProperty(min=0, max=1)),
        ("epss_percentile", FloatProperty(min=0, max=1)),
        ("epss_date", StringProperty()),
        ("kev_listed", BooleanProperty()),
        ("kev_date_added", StringProperty()),
        ("kev_due_date", StringProperty()),
        ("kev_ransomware_use", EnumProperty(allowed=list(_KEV_RANSOMWARE_USE))),
        ("novel_attack_vector", BooleanProperty()),
        # course-of-action
        ("category", EnumProperty(allowed=list(_REMEDIATION_CATEGORY))),
        ("restart_required", EnumProperty(allowed=list(_RESTART_REQUIRED))),
        ("action_type", EnumProperty(allowed=list(_ACTION_TYPE))),
        ("residual_risk", StringProperty()),
        ("validation_check", DictionaryProperty(spec_version="2.1")),
        # indicator
        ("telemetry_sources", ListProperty(StringProperty)),
        ("false_positive_notes", StringProperty()),
    ],
)
class AivsIntelExtension:
    """The 2.0 intelligence properties on vulnerability, course-of-action and indicator."""

    extension_type = "property-extension"


@CustomExtension(
    AIVS_PROVENANCE_EXTENSION_ID,
    [
        ("human_reviewed_by_ref", ReferenceProperty(valid_types="identity", spec_version="2.1")),
        ("reviewed_at", StringProperty()),
        ("generated_by", StringProperty()),
        ("factors", ListProperty(StringProperty)),
    ],
)
class AivsProvenanceExtension:
    """Who reviewed an object at the ISAC, and what the submitter says produced it."""

    extension_type = "property-extension"


def _load_definition(filename: str, expected_id: str) -> Mapping[str, Any]:
    raw: dict[str, Any] = json.loads((_SCHEMA_DIR / filename).read_text(encoding="utf-8"))
    if raw["id"] != expected_id:
        msg = (
            f"{filename} declares id {raw['id']!r} but the code expects "
            f"{expected_id!r}; these must never diverge"
        )
        raise RuntimeError(msg)
    return raw


def _load_schema(filename: str) -> Mapping[str, Any]:
    schema: dict[str, Any] = json.loads((_SCHEMA_DIR / filename).read_text(encoding="utf-8"))
    return schema


@lru_cache(maxsize=1)
def extension_definition_sdo() -> Mapping[str, Any]:
    """Return the ``extension-definition`` SDO that declares the 1.0 extension.

    Published in every distributed bundle so that a consumer encountering the
    extension for the first time can resolve what it means without an
    out-of-band lookup.
    """
    return _load_definition("definition.json", AIVS_EXTENSION_ID)


@lru_cache(maxsize=1)
def intel_extension_definition_sdo() -> Mapping[str, Any]:
    """Return the ``extension-definition`` SDO for the 2.0 intelligence extension."""
    return _load_definition("definition-2.0.json", AIVS_INTEL_EXTENSION_ID)


@lru_cache(maxsize=1)
def provenance_extension_definition_sdo() -> Mapping[str, Any]:
    """Return the ``extension-definition`` SDO for the provenance extension."""
    return _load_definition("definition-provenance-1.0.json", AIVS_PROVENANCE_EXTENSION_ID)


@lru_cache(maxsize=1)
def extension_json_schema() -> Mapping[str, Any]:
    """Return the JSON Schema for the 1.0 extension body."""
    return _load_schema("schema-1.0.json")


@lru_cache(maxsize=1)
def intel_json_schema() -> Mapping[str, Any]:
    """Return the JSON Schema for the 2.0 extension: one definition per object type."""
    return _load_schema("schema-2.0.json")


@lru_cache(maxsize=1)
def provenance_json_schema() -> Mapping[str, Any]:
    """Return the JSON Schema for the provenance extension body."""
    return _load_schema("schema-provenance-1.0.json")


def _compile(schema: Mapping[str, Any]) -> jsonschema.protocols.Validator:
    """Compile a validator, refusing a malformed schema.

    Compiled once per schema (callers cache) because compilation is the
    expensive part and every inbound object pays it otherwise.
    """
    # Deep copy, not dict(). A shallow copy shares `properties`, `allOf` and
    # every subschema with the lru_cached mapping, so anything that reached into
    # the loaded schema and mutated a nested value would silently change the
    # compiled validator for every subsequent inbound object.
    copied = copy.deepcopy(dict(schema))
    validator_cls = jsonschema.validators.validator_for(copied)
    # Fail at first use on a malformed schema rather than on an inbound object,
    # when the failure would look like a member's fault.
    validator_cls.check_schema(copied)
    return validator_cls(copied)


@lru_cache(maxsize=1)
def _schema_validator() -> jsonschema.protocols.Validator:
    return _compile(extension_json_schema())


@lru_cache(maxsize=len(INTEL_EXTENSION_TYPES))
def _intel_validator(object_type: str) -> jsonschema.protocols.Validator:
    """The 2.0 definition for one object type, with the shared ``$defs`` in reach."""
    return _compile({**intel_json_schema(), "$ref": f"#/$defs/{object_type}"})


@lru_cache(maxsize=1)
def _provenance_validator() -> jsonschema.protocols.Validator:
    return _compile(provenance_json_schema())


def assert_extensions_allowed(obj: Mapping[str, Any]) -> None:
    """Raise :class:`UnknownExtensionError` if ``obj`` carries an unknown extension.

    This is the check ``stix2`` does not perform for ``extension-definition--``
    keys. See the module docstring.
    """
    extensions = obj.get("extensions")
    if extensions:
        if not isinstance(extensions, Mapping):
            msg = f"'extensions' must be an object, got {type(extensions).__name__}"
            raise UnknownExtensionError(msg)
        _refuse_unknown_extensions(extensions, f"object {obj.get('id', '<no id>')}")

    # Nested objects carry their own extensions, and the allowlist has to reach
    # them. An observed-data SDO's deprecated-but-valid `objects` property holds
    # embedded SCOs, each of which may declare `extensions` of its own. Checking
    # only the top level meant a bundle whose top-level `extensions` was absent
    # passed untouched and was then stored and served verbatim -- which is the
    # delivery mechanism this allowlist exists to prevent, reached one level down.
    for child in _child_objects(obj):
        _assert_nested_extensions_allowed(child)


def _assert_nested_extensions_allowed(obj: Mapping[str, Any], depth: int = 0) -> None:
    """Apply the extension allowlist to a nested object.

    Depth-bounded: the recursion walks attacker-supplied JSON, and a deeply
    nested document should be refused rather than exhaust the stack.
    """
    if depth > _MAX_NESTING_DEPTH:
        msg = f"object nesting exceeds {_MAX_NESTING_DEPTH} levels"
        raise UnknownExtensionError(msg)

    extensions = obj.get("extensions")
    if isinstance(extensions, Mapping):
        _refuse_unknown_extensions(extensions, f"nested object {obj.get('id', '<no id>')}")

    for child in _child_objects(obj):
        _assert_nested_extensions_allowed(child, depth + 1)


def _refuse_unknown_extensions(extensions: Mapping[str, Any], described: str) -> None:
    """Raise if ``extensions`` names anything outside the allowlist."""
    unknown = sorted(set(extensions) - ALLOWED_EXTENSION_IDS)
    if unknown:
        msg = f"{described} carries unsupported extension(s): {', '.join(unknown)}"
        raise UnknownExtensionError(msg)


def _child_objects(obj: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    """Yield the objects one level inside ``obj``: mapping values, and mappings in lists."""
    for value in obj.values():
        if isinstance(value, Mapping):
            yield value
        elif isinstance(value, list):
            yield from (item for item in value if isinstance(item, Mapping))


def _reject_authoritative_object_forgery(obj: Mapping[str, Any]) -> None:
    """Refuse inbound objects that would redefine what other objects *mean*.

    Two STIX object types are not ordinary content: they are the definitions
    consumers use to interpret everything else. AIVS publishes both itself, so a
    submitter has no legitimate reason to send either, and both are redistributed
    verbatim to every member of the target circles.

    * ``extension-definition`` -- a submitter re-declaring
      :data:`AIVS_EXTENSION_ID` with a ``schema`` URL of their choosing puts a
      definition of the AIVS extension pointing at an address they control into
      every consuming platform in the circle.
    * ``marking-definition`` bearing a spec-fixed TLP identifier -- the whole
      basis of TLP interoperability is that those identifiers mean one thing
      everywhere. An object claiming the TLP:RED id with a TLP:CLEAR body turns
      the most restrictive handling instruction into the least restrictive one,
      on content already distributed under it.
    """
    obj_type = obj.get("type")

    if obj_type == "extension-definition":
        msg = (
            f"bundles may not carry extension-definition objects "
            f"({obj.get('id', '<no id>')}). AIVS publishes its own definition; "
            "a submitted one would redefine how members interpret every object."
        )
        raise UnknownExtensionError(msg)

    if obj_type == "marking-definition" and obj.get("id") in _RESERVED_MARKING_IDS:
        msg = (
            f"marking-definition {obj.get('id')} uses a specification-fixed TLP "
            "identifier. Reference it with object_marking_refs; do not redefine it."
        )
        raise UnknownExtensionError(msg)


def validate_stix_object(obj: Mapping[str, Any]) -> None:
    """Validate one inbound STIX object's extensions.

    Performs two checks in order:

    1. every extension present is one AIVS recognises, and
    2. an AIVS extension body, if present, satisfies the JSON Schema.

    Raises :class:`UnknownExtensionError` or :class:`ExtensionValidationError`.
    Callers must apply this to every object in a bundle, not only the ones they
    intend to read.
    """
    assert_extensions_allowed(obj)
    _reject_authoritative_object_forgery(obj)
    apply_type_policy(obj)

    extensions = obj.get("extensions") or {}
    _refuse_both_intel_versions(obj, extensions)
    _validate_body(obj, extensions.get(AIVS_EXTENSION_ID), _schema_validator, "AIVS extension")
    _validate_intel_body(obj, extensions.get(AIVS_INTEL_EXTENSION_ID))
    provenance = extensions.get(AIVS_PROVENANCE_EXTENSION_ID)
    _validate_body(obj, provenance, _provenance_validator, "provenance extension")
    _refuse_server_written_provenance(obj, provenance)


def _validate_body(
    obj: Mapping[str, Any],
    body: Any,
    validator: Callable[[], jsonschema.protocols.Validator],
    described: str,
) -> None:
    """Validate one extension body against its schema; absent is fine."""
    if body is None:
        return
    if not isinstance(body, Mapping):
        msg = f"{described} body on {obj.get('id', '<no id>')} must be an object"
        raise ExtensionValidationError(msg)

    errors = sorted(validator().iter_errors(dict(body)), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(p) for p in err.path) or '<root>'}: {err.message}" for err in errors[:5]
        )
        msg = f"{described} on {obj.get('id', '<no id>')} failed validation: {detail}"
        raise ExtensionValidationError(msg)


def _validate_intel_body(obj: Mapping[str, Any], body: Any) -> None:
    """Validate a 2.0 body against the definition for the object's own type."""
    if body is None:
        return
    object_type = obj.get("type")
    if object_type not in INTEL_EXTENSION_TYPES:
        msg = (
            f"the AIVS 2.0 extension has no definition for {object_type!r} "
            f"(object {obj.get('id', '<no id>')}); it applies to "
            f"{', '.join(sorted(INTEL_EXTENSION_TYPES))}"
        )
        raise ExtensionValidationError(msg)
    _validate_body(obj, body, lambda: _intel_validator(object_type), "AIVS 2.0 extension")


def _refuse_both_intel_versions(obj: Mapping[str, Any], extensions: Mapping[str, Any]) -> None:
    """One description of a vulnerability, not two that can disagree.

    The 2.0 vulnerability definition carries every 1.0 property; an object with
    both could state two CVE ids or two scopes, and a consumer would read
    whichever it understood.
    """
    if AIVS_EXTENSION_ID in extensions and AIVS_INTEL_EXTENSION_ID in extensions:
        msg = (
            f"object {obj.get('id', '<no id>')} carries both the 1.0 and the 2.0 AIVS "
            "extension; use one"
        )
        raise ObjectPolicyError(msg)


def _refuse_server_written_provenance(obj: Mapping[str, Any], provenance: Any) -> None:
    """A review is recorded by the ISAC that did it, never asserted by a submitter (SF-6)."""
    if not isinstance(provenance, Mapping):
        return
    claimed = sorted(SERVER_WRITTEN_PROVENANCE & set(provenance))
    if claimed:
        msg = (
            f"object {obj.get('id', '<no id>')} sets {', '.join(claimed)}: the ISAC "
            "records who reviewed an object when it validates it, and a submission "
            "may not claim a review"
        )
        raise ObjectPolicyError(msg)


def validate_bundle(bundle: Mapping[str, Any]) -> int:
    """Validate every object in an inbound STIX bundle. Returns the object count.

    Exists so that no caller has to remember to loop. :func:`validate_stix_object`
    is per-object, and the instruction to apply it to *every* object -- not only
    the ones the caller intends to read -- is exactly the kind of requirement that
    survives in a docstring and dies in a code path. AIVS redistributes whole
    bundles, so an object nobody looked at is still an object every member of the
    circle receives.

    Raises :class:`UnknownExtensionError` or :class:`ExtensionValidationError` on
    the first object that fails, and :class:`BundleValidationError` if the bundle
    itself is malformed. All three derive from ``ValueError``, so a caller
    translating validation failure into HTTP 400 can catch that one family.
    """
    if bundle.get("type") != "bundle":
        msg = f"expected a STIX bundle, got type={bundle.get('type')!r}"
        raise BundleValidationError(msg)

    objects = bundle.get("objects")
    if objects is None:
        # A bundle with no objects is legal in STIX 2.1 and simply carries
        # nothing; it is not an error, but there is nothing to validate.
        return 0
    if not isinstance(objects, list):
        msg = f"bundle 'objects' must be a list, got {type(objects).__name__}"
        raise BundleValidationError(msg)
    if len(objects) > MAX_BUNDLE_OBJECTS:
        msg = f"bundle carries {len(objects)} objects, limit is {MAX_BUNDLE_OBJECTS}"
        raise BundleValidationError(msg)

    for index, obj in enumerate(objects):
        if not isinstance(obj, Mapping):
            msg = f"bundle object at index {index} is not an object"
            raise BundleValidationError(msg)
        validate_stix_object(obj)

    return len(objects)


def build_extension_body(
    *,
    discovery_scope: DiscoveryScope,
    cve_status: CVEStatus,
    affected_products: Sequence[Mapping[str, str]],
    ai_discovery_method: AIDiscoveryMethod | None = None,
    ai_model_name: str | None = None,
    ai_harness_name: str | None = None,
    ai_harness_version: str | None = None,
    ai_confidence: int | None = None,
    ai_reproduction_available: bool | None = None,
    cvss_v4_vector: str | None = None,
    cvss_v4_base_score: float | None = None,
    cvss_v4_severity: str | None = None,
    embargo_policy: str | None = None,
    embargo_release_at: dt.datetime | None = None,
    remediation_summary: str | None = None,
    workaround_available: bool | None = None,
    cve_id: str | None = None,
    exploit_chain_position: int | None = None,
) -> dict[str, Any]:
    """Build a validated AIVS extension body.

    Keyword-only throughout: these are eighteen mostly-optional fields of
    similar types, and positional calls would be unreadable and easy to
    transpose. The result is validated before it is returned, so a caller cannot
    construct an invalid body and discover it later at distribution time.
    """
    body: dict[str, Any] = {
        "extension_type": "property-extension",
        "aivs_schema_version": _CURRENT_SCHEMA_VERSION,
        "discovery_scope": discovery_scope.value,
        "cve_status": cve_status.value,
        "affected_products": [dict(product) for product in affected_products],
    }

    optional: dict[str, Any] = {
        "ai_discovery_method": ai_discovery_method.value if ai_discovery_method else None,
        "ai_model_name": ai_model_name,
        "ai_harness_name": ai_harness_name,
        "ai_harness_version": ai_harness_version,
        "ai_confidence": ai_confidence,
        "ai_reproduction_available": ai_reproduction_available,
        "cvss_v4_vector": cvss_v4_vector,
        "cvss_v4_base_score": cvss_v4_base_score,
        "cvss_v4_severity": cvss_v4_severity,
        "embargo_policy": embargo_policy,
        "remediation_summary": remediation_summary,
        "workaround_available": workaround_available,
        "cve_id": cve_id,
        "exploit_chain_position": exploit_chain_position,
    }
    body.update({key: value for key, value in optional.items() if value is not None})

    if embargo_release_at is not None:
        body["embargo_release_at"] = format_stix_timestamp(embargo_release_at)

    validate_stix_object({"id": "<building>", "extensions": {AIVS_EXTENSION_ID: body}})
    return body


def format_stix_timestamp(value: dt.datetime) -> str:
    """Render an aware datetime as a STIX 2.1 timestamp.

    STIX requires UTC with a literal ``Z`` and millisecond precision. A naive
    datetime is rejected rather than assumed to be UTC: guessing a timezone on
    an embargo release time is exactly the kind of assumption that publishes
    content hours early.
    """
    if value.tzinfo is None:
        msg = "refusing to format a naive datetime as a STIX timestamp"
        raise ValueError(msg)
    milliseconds = value.microsecond // 1000
    return value.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{milliseconds:03d}Z"
