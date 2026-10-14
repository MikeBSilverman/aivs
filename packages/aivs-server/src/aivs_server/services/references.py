"""What a bundle points at outside itself.

A contribution is an object plus references to objects somebody else already
shared: a workaround's ``relationship`` to the ISAC's vulnerability, an
``opinion``'s ``object_refs``, a ``sighting``'s ``sighting_of_ref``. Several
rules are about those referents -- whose they are, how they are marked, whether
they are public -- so they are found once, here.

Pure functions over raw STIX, so the rules that use them can be checked without
a database.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from typing import Any, Final

__all__ = ["external_references_by_type", "referenced_ids"]

#: Reference properties that are not "this content is about that object".
#: ``created_by_ref`` is rewritten at distribution; markings are handled by
#: the marking rule; ``where_sighted_refs`` names who saw it, and SF-50 lets
#: it name only the filer itself (and nothing at all when anonymous).
#: ``observed_data_refs`` is not here: a sighting's evidence is content it is
#: about, and left out, a post-moderated sighting cited hidden or stricter
#: observed-data with no visibility or TLP check.
_NOT_SUBJECT_REFERENCES: Final[frozenset[str]] = frozenset(
    {
        "created_by_ref",
        "object_marking_refs",
        "marking_ref",
        "where_sighted_refs",
    }
)


def _reference_values(value: Any) -> Iterator[str]:
    """Every identifier held in ``*_ref`` and ``*_refs`` properties, at any depth."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in _NOT_SUBJECT_REFERENCES:
                continue
            if key.endswith("_ref") and isinstance(item, str):
                yield item
            elif key.endswith("_refs") and isinstance(item, list):
                yield from (ref for ref in item if isinstance(ref, str))
            else:
                yield from _reference_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _reference_values(item)


def referenced_ids(objects: Iterable[Mapping[str, Any]]) -> set[str]:
    """Identifiers the objects are about that the bundle does not itself define."""
    listed = list(objects)
    defined = {obj.get("id") for obj in listed}
    return {ref for obj in listed for ref in _reference_values(obj)} - defined


def external_references_by_type(objects: Iterable[Mapping[str, Any]], stix_type: str) -> set[str]:
    """The referenced identifiers outside the bundle that are of ``stix_type``."""
    return {ref for ref in referenced_ids(objects) if ref.startswith(f"{stix_type}--")}
