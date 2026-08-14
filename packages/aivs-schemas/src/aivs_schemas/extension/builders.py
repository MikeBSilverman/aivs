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

import datetime as dt
import json
from collections.abc import Mapping, Sequence
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
    StringProperty,
)

from aivs_schemas.enums import AIDiscoveryMethod, CVEStatus, DiscoveryScope
from aivs_schemas.tlp import TLP20_EXTENSION_DEFINITION_ID

__all__ = [
    "AIVS_EXTENSION_ID",
    "AIVS_PROJECT_IDENTITY_ID",
    "ALLOWED_EXTENSION_IDS",
    "EXPLOIT_CHAIN_GROUPING_CONTEXT",
    "RELATIONSHIP_CHAINS_TO",
    "AivsPreCveExtension",
    "ExtensionValidationError",
    "UnknownExtensionError",
    "assert_extensions_allowed",
    "build_extension_body",
    "extension_definition_sdo",
    "extension_json_schema",
    "validate_stix_object",
]

#: Fixed identifier for the AIVS property-extension. Minted once; never changes.
#: A new identifier would be a new, unrecognised extension to every member's TIP.
AIVS_EXTENSION_ID: Final[str] = "extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6"

#: The AIVS project's own STIX identity, which authors the extension definition.
#: Distinct from any hosting ISAC's identity -- the extension is shared across
#: deployments, the ISAC identity is per-instance.
AIVS_PROJECT_IDENTITY_ID: Final[str] = "identity--e50b8964-5a9a-4d4b-a016-16ea043c2c56"

#: Extensions AIVS will accept on inbound content. Anything else is rejected
#: rather than stored: we redistribute what we accept, so accepting content we
#: cannot validate would make AIVS a delivery mechanism for it.
ALLOWED_EXTENSION_IDS: Final[frozenset[str]] = frozenset(
    {AIVS_EXTENSION_ID, TLP20_EXTENSION_DEFINITION_ID}
)

#: Relationship type linking one vulnerability to the next step of a chain.
#: STIX permits producer-defined relationship types; this one is documented in
#: docs/stix-extension.md so consumers can traverse chains deterministically.
RELATIONSHIP_CHAINS_TO: Final[str] = "chains-to"

#: ``grouping.context`` value collecting the members of one exploit chain.
EXPLOIT_CHAIN_GROUPING_CONTEXT: Final[str] = "exploit-chain"

_SCHEMA_DIR: Final[Path] = Path(__file__).parent
_CURRENT_SCHEMA_VERSION: Final[str] = "1.0"


class ExtensionValidationError(ValueError):
    """An object's AIVS extension body failed schema validation."""


class UnknownExtensionError(ValueError):
    """An object carried an extension AIVS does not recognise.

    Raised rather than ignored: silently dropping an unrecognised extension
    would change the meaning of content that a member may have relied on, and
    silently keeping it would redistribute unvalidated data.
    """


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
        (
            "ai_discovery_method",
            EnumProperty(allowed=[m.value for m in AIDiscoveryMethod], required=True),
        ),
        ("ai_model_name", StringProperty()),
        ("ai_harness_name", StringProperty()),
        ("ai_harness_version", StringProperty()),
        ("ai_confidence", IntegerProperty(min=0, max=100)),
        ("ai_reproduction_available", BooleanProperty()),
        (
            "discovery_scope",
            EnumProperty(allowed=[s.value for s in DiscoveryScope], required=True),
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
    ],
)
class AivsPreCveExtension:
    """Pre-CVE AI vulnerability properties attached to a STIX ``vulnerability``."""

    extension_type = "property-extension"


@lru_cache(maxsize=1)
def extension_definition_sdo() -> Mapping[str, Any]:
    """Return the ``extension-definition`` SDO that declares this extension.

    Published in every distributed bundle so that a consumer encountering the
    extension for the first time can resolve what it means without an
    out-of-band lookup.
    """
    raw: dict[str, Any] = json.loads((_SCHEMA_DIR / "definition.json").read_text(encoding="utf-8"))
    if raw["id"] != AIVS_EXTENSION_ID:
        msg = (
            f"definition.json declares id {raw['id']!r} but the code expects "
            f"{AIVS_EXTENSION_ID!r}; these must never diverge"
        )
        raise RuntimeError(msg)
    return raw


@lru_cache(maxsize=1)
def extension_json_schema() -> Mapping[str, Any]:
    """Return the JSON Schema for the extension body."""
    schema: dict[str, Any] = json.loads(
        (_SCHEMA_DIR / "schema-1.0.json").read_text(encoding="utf-8")
    )
    return schema


@lru_cache(maxsize=1)
def _schema_validator() -> jsonschema.protocols.Validator:
    """Return a compiled validator.

    Compiled once because schema compilation is the expensive part and every
    inbound object pays it otherwise.
    """
    schema = dict(extension_json_schema())
    validator_cls = jsonschema.validators.validator_for(schema)
    # Fail at import time on a malformed schema rather than on the first
    # inbound object, when the failure would look like a member's fault.
    validator_cls.check_schema(schema)
    return validator_cls(schema)


def assert_extensions_allowed(obj: Mapping[str, Any]) -> None:
    """Raise :class:`UnknownExtensionError` if ``obj`` carries an unknown extension.

    This is the check ``stix2`` does not perform for ``extension-definition--``
    keys. See the module docstring.
    """
    extensions = obj.get("extensions")
    if not extensions:
        return
    if not isinstance(extensions, Mapping):
        msg = f"'extensions' must be an object, got {type(extensions).__name__}"
        raise UnknownExtensionError(msg)
    unknown = sorted(set(extensions) - ALLOWED_EXTENSION_IDS)
    if unknown:
        msg = (
            f"object {obj.get('id', '<no id>')} carries unsupported extension(s): "
            f"{', '.join(unknown)}"
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

    extensions = obj.get("extensions") or {}
    body = extensions.get(AIVS_EXTENSION_ID)
    if body is None:
        return
    if not isinstance(body, Mapping):
        msg = f"AIVS extension body on {obj.get('id', '<no id>')} must be an object"
        raise ExtensionValidationError(msg)

    errors = sorted(_schema_validator().iter_errors(dict(body)), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(p) for p in err.path) or '<root>'}: {err.message}" for err in errors[:5]
        )
        msg = f"AIVS extension on {obj.get('id', '<no id>')} failed validation: {detail}"
        raise ExtensionValidationError(msg)


def build_extension_body(
    *,
    ai_discovery_method: AIDiscoveryMethod,
    discovery_scope: DiscoveryScope,
    cve_status: CVEStatus,
    affected_products: Sequence[Mapping[str, str]],
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
        "ai_discovery_method": ai_discovery_method.value,
        "discovery_scope": discovery_scope.value,
        "cve_status": cve_status.value,
        "affected_products": [dict(product) for product in affected_products],
    }

    optional: dict[str, Any] = {
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
