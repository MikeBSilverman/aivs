"""Traffic Light Protocol 2.0 marking definitions.

These identifiers are fixed by the OASIS CTI Technical Committee and are the
whole basis of interoperability for handling instructions: a member's TIP
recognises ``marking-definition--55d920b0-...`` as TLP:AMBER because everyone
uses that exact string. Never regenerate them.

Two facts about TLP 2.0 that routinely cause defects, recorded here so they are
not rediscovered the hard way:

1. **TLP 2.0 markings are not in the STIX 2.1 specification.** The STIX 2.1
   OASIS Standard (June 2021) predates TLP 2.0 (August 2022) and defines only
   the four TLP 1.0 markings in section 7.2.1.4. TLP 2.0 is defined in the OASIS
   ``cti-stix-common-objects`` repository, which is the source of truth for the
   identifiers below.

2. **TLP 2.0 GREEN, AMBER, and RED have different UUIDs from their TLP 1.0
   namesakes,** and TLP 2.0 uses the ``extensions`` property-extension form
   rather than TLP 1.0's ``definition_type``/``definition`` pair. Mixing the two
   generations produces markings that look right and mean nothing.

The ``stix2`` library ships TLP 1.0 constants only and actively rejects
attempts to construct a TLP:CLEAR via its ``TLPMarking`` type, so these are
declared as literal mappings. They parse and round-trip cleanly through
``stix2.parse``.

Reference: https://github.com/oasis-open/cti-stix-common-objects
           /tree/main/extension-definition-specifications/tlp-2.0
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Final, Mapping

from aivs_schemas.enums import TLP

__all__ = [
    "TLP20_EXTENSION_DEFINITION_ID",
    "TLP_MARKING_IDS",
    "TLP_MARKING_OBJECTS",
    "TLP_NAMES",
    "LEGACY_TLP10_MARKING_IDS",
    "marking_definition_for",
    "marking_id_for",
    "tlp_for_marking_id",
]

#: The extension-definition that TLP 2.0 marking objects reference.
TLP20_EXTENSION_DEFINITION_ID: Final[str] = (
    "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"
)

#: Creation timestamp carried by every published TLP 2.0 marking object.
_TLP20_CREATED: Final[str] = "2022-10-01T00:00:00.000Z"

#: Human-readable label. Per FIRST, labels are capitalised and contain no
#: spaces -- "TLP:AMBER+STRICT", never "TLP: Amber+Strict".
TLP_NAMES: Final[Mapping[TLP, str]] = MappingProxyType(
    {
        TLP.CLEAR: "TLP:CLEAR",
        TLP.GREEN: "TLP:GREEN",
        TLP.AMBER: "TLP:AMBER",
        TLP.AMBER_STRICT: "TLP:AMBER+STRICT",
        TLP.RED: "TLP:RED",
    }
)

#: Value carried in the extension body's ``tlp_2_0`` property.
_TLP_EXTENSION_VALUES: Final[Mapping[TLP, str]] = MappingProxyType(
    {
        TLP.CLEAR: "clear",
        TLP.GREEN: "green",
        TLP.AMBER: "amber",
        TLP.AMBER_STRICT: "amber+strict",
        TLP.RED: "red",
    }
)

TLP_MARKING_IDS: Final[Mapping[TLP, str]] = MappingProxyType(
    {
        TLP.CLEAR: "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        TLP.GREEN: "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
        TLP.AMBER: "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
        TLP.AMBER_STRICT: "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
        TLP.RED: "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
    }
)

#: Reverse lookup, for interpreting ``object_marking_refs`` on inbound content.
_ID_TO_TLP: Final[Mapping[str, TLP]] = MappingProxyType(
    {marking_id: tlp for tlp, marking_id in TLP_MARKING_IDS.items()}
)


def _build_marking(tlp: TLP) -> Mapping[str, Any]:
    """Construct one TLP 2.0 marking-definition object.

    Marking definitions are not versionable, so there is deliberately no
    ``modified`` property -- adding one would make the object invalid.
    """
    return MappingProxyType(
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": TLP_MARKING_IDS[tlp],
            "created": _TLP20_CREATED,
            "name": TLP_NAMES[tlp],
            "extensions": {
                TLP20_EXTENSION_DEFINITION_ID: {
                    "extension_type": "property-extension",
                    "tlp_2_0": _TLP_EXTENSION_VALUES[tlp],
                }
            },
        }
    )


TLP_MARKING_OBJECTS: Final[Mapping[TLP, Mapping[str, Any]]] = MappingProxyType(
    {tlp: _build_marking(tlp) for tlp in TLP}
)

#: TLP 1.0 identifiers, retained solely to *recognise* legacy content arriving
#: from older feeds. AIVS never emits these. Note the absence of any TLP 2.0
#: equivalent for TLP:WHITE, which TLP 2.0 replaced with TLP:CLEAR.
LEGACY_TLP10_MARKING_IDS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    }
)


def marking_id_for(tlp: TLP) -> str:
    """Return the STIX marking-definition id for ``tlp``."""
    return TLP_MARKING_IDS[tlp]


def marking_definition_for(tlp: TLP) -> dict[str, Any]:
    """Return a mutable copy of the marking-definition object for ``tlp``.

    A copy, because callers place these into bundles that they then mutate;
    handing out the shared mapping would let one caller corrupt every other's.
    """
    marking = TLP_MARKING_OBJECTS[tlp]
    extension_body = dict(marking["extensions"][TLP20_EXTENSION_DEFINITION_ID])
    return {
        **{k: v for k, v in marking.items() if k != "extensions"},
        "extensions": {TLP20_EXTENSION_DEFINITION_ID: extension_body},
    }


def tlp_for_marking_id(marking_id: str) -> TLP | None:
    """Return the TLP designation for a marking id, or ``None`` if unrecognised.

    Legacy TLP 1.0 identifiers deliberately return ``None`` rather than being
    silently upgraded: TLP 1.0 AMBER and TLP 2.0 AMBER carry materially
    different handling obligations, and guessing on a member's behalf is not
    ours to do.
    """
    return _ID_TO_TLP.get(marking_id)
