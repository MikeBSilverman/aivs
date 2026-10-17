"""Rules AIVS holds for an object because of its type, whether or not it carries an extension.

The extension schemas describe what an extension body may say. These rules are
about the object itself, and they apply to every inbound object of the type: a
rule that only applied when the extension was present could be avoided by
leaving the extension off.

Pure functions over the raw object, with no clock and no I/O, so each can be
checked in isolation and a client can run the same checks before it submits.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from aivs_schemas.extension.errors import ObjectPolicyError

__all__ = [
    "INDICATOR_PATTERN_TYPES",
    "MAX_INDICATOR_LIFETIME",
    "NETWORK_INDICATOR_LIFETIME",
    "STIX_CYBER_OBSERVABLE_TYPES",
    "apply_type_policy",
]

#: STIX 2.1's pattern-type vocabulary verbatim, plus two of ours: KQL and SPL,
#: the query languages most members' SIEMs run. An unknown pattern type is a
#: pattern no member can execute, so it is refused rather than passed on.
INDICATOR_PATTERN_TYPES: Final[frozenset[str]] = frozenset(
    {"stix", "pcre", "sigma", "snort", "suricata", "yara", "kql", "spl"}
)

#: The longest an indicator naming a network address may be valid for. An
#: address is reassigned, a domain re-registered; a member that blocks one for
#: years blocks whoever holds it next (SF-46). Ninety days is long enough for a
#: campaign and short enough that a stale block is reviewed within a quarter.
NETWORK_INDICATOR_LIFETIME: Final[dt.timedelta] = dt.timedelta(days=90)

#: The longest any other indicator may be valid for: file hashes and detection
#: rules. A hash names the same bytes for ever, but the threat it marks moves
#: on, and a rule's false-positive profile drifts as estates change. Two years
#: keeps them in a review cycle without forcing reissue for every campaign.
MAX_INDICATOR_LIFETIME: Final[dt.timedelta] = dt.timedelta(days=730)

#: STIX observable types that name a network address in a STIX pattern.
_NETWORK_OBSERVABLE: Final[re.Pattern[str]] = re.compile(
    r"\[\s*(ipv4-addr|ipv6-addr|domain-name|url)\s*:"
)

#: STIX 2.1's cyber-observable types (section 6). Refused as top-level objects:
#: they carry no ``created`` or ``modified``, and a stored object is versioned by
#: ``modified`` (TAXII ``match[version]``, owner-only versioning). Until SCOs
#: are given a version key of their own, an observable is stated where STIX
#: puts it in a sharing context: an indicator's pattern, or observed-data.
STIX_CYBER_OBSERVABLE_TYPES: Final[frozenset[str]] = frozenset(
    {
        "artifact",
        "autonomous-system",
        "directory",
        "domain-name",
        "email-addr",
        "email-message",
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "mac-addr",
        "mutex",
        "network-traffic",
        "process",
        "software",
        "url",
        "user-account",
        "windows-registry-key",
        "x509-certificate",
    }
)

_STIX_TIMESTAMP: Final[re.Pattern[str]] = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$"
)

#: External-reference identifiers whose format AIVS indexes or links on. A
#: malformed one would be stored, indexed and served as if it named something.
_REFERENCE_FORMATS: Final[Mapping[str, Mapping[str, re.Pattern[str]]]] = {
    "vulnerability": {
        "cve": re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$"),
        "cwe": re.compile(r"^CWE-[0-9]{1,6}$"),
    },
    "attack-pattern": {
        "mitre-attack": re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$"),
        "capec": re.compile(r"^CAPEC-[0-9]{1,6}$"),
    },
}


def apply_type_policy(obj: Mapping[str, Any]) -> None:
    """Raise :class:`ObjectPolicyError` if ``obj`` breaks a rule for its type."""
    obj_type = obj.get("type")
    if obj_type in STIX_CYBER_OBSERVABLE_TYPES:
        msg = (
            f"{_described(obj)}: STIX cyber observables are not accepted as objects of "
            "their own; state the observable in an indicator's pattern or in observed-data"
        )
        raise ObjectPolicyError(msg)
    if isinstance(obj_type, str):
        check = _POLICIES.get(obj_type)
        if check is not None:
            check(obj)


def _vulnerability(obj: Mapping[str, Any]) -> None:
    _check_reference_formats(obj, _REFERENCE_FORMATS["vulnerability"])


def _attack_pattern(obj: Mapping[str, Any]) -> None:
    _check_reference_formats(obj, _REFERENCE_FORMATS["attack-pattern"])
    _check_kill_chain_phases(obj)


def _indicator(obj: Mapping[str, Any]) -> None:
    """An indicator says what to run, and until when (SF-46).

    ``valid_until`` is required, not optional as STIX has it: an indicator with
    no end is blocked by members for years after the address changes hands.
    """
    described = _described(obj)
    pattern_type = obj.get("pattern_type")
    if pattern_type not in INDICATOR_PATTERN_TYPES:
        allowed = ", ".join(sorted(INDICATOR_PATTERN_TYPES))
        msg = f"{described} has pattern_type {pattern_type!r}; expected one of {allowed}"
        raise ObjectPolicyError(msg)

    valid_from = _timestamp(obj, "valid_from")
    valid_until = _timestamp(obj, "valid_until")
    if valid_until <= valid_from:
        msg = f"{described}: valid_until must be later than valid_from"
        raise ObjectPolicyError(msg)

    limit, kind = _lifetime_limit(obj)
    if valid_until - valid_from > limit:
        msg = (
            f"{described} is valid for {(valid_until - valid_from).days} days; "
            f"{kind} indicators may be valid for at most {limit.days}"
        )
        raise ObjectPolicyError(msg)


def _lifetime_limit(obj: Mapping[str, Any]) -> tuple[dt.timedelta, str]:
    pattern = obj.get("pattern")
    names_an_address = (
        obj.get("pattern_type") == "stix"
        and isinstance(pattern, str)
        and _NETWORK_OBSERVABLE.search(pattern) is not None
    )
    if names_an_address:
        return NETWORK_INDICATOR_LIFETIME, "network-address"
    return MAX_INDICATOR_LIFETIME, "hash and rule"


def _timestamp(obj: Mapping[str, Any], field: str) -> dt.datetime:
    value = obj.get(field)
    if not isinstance(value, str) or _STIX_TIMESTAMP.match(value) is None:
        msg = f"{_described(obj)} needs '{field}' as a STIX timestamp, got {value!r}"
        raise ObjectPolicyError(msg)
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _check_reference_formats(
    obj: Mapping[str, Any], formats: Mapping[str, re.Pattern[str]]
) -> None:
    """An identifier stated in one of these schemes is in that scheme's format.

    Only a *stated* identifier is checked: a reference that is not an object,
    or names the scheme without an id, is tolerated at ingest and skipped by
    indexing, as it was before these rules (``test_inbound_validation``). What
    must not happen is a malformed id that indexing would store as if it named
    something.
    """
    for reference in _external_references(obj):
        pattern = formats.get(reference.get("source_name", ""))
        external_id = reference.get("external_id")
        if pattern is None or not isinstance(external_id, str):
            continue
        if pattern.match(external_id) is None:
            msg = (
                f"{_described(obj)} has a '{reference['source_name']}' reference "
                f"with external_id {external_id!r}, which is not that scheme's format"
            )
            raise ObjectPolicyError(msg)


def _external_references(obj: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    references = obj.get("external_references")
    if not isinstance(references, list):
        return ()
    return [reference for reference in references if isinstance(reference, Mapping)]


def _check_kill_chain_phases(obj: Mapping[str, Any]) -> None:
    phases = obj.get("kill_chain_phases")
    if phases is None:
        return
    well_formed = isinstance(phases, list) and all(
        isinstance(phase, Mapping)
        and isinstance(phase.get("kill_chain_name"), str)
        and isinstance(phase.get("phase_name"), str)
        and phase["kill_chain_name"]
        and phase["phase_name"]
        for phase in phases
    )
    if not well_formed:
        msg = f"{_described(obj)}: each kill_chain_phase needs kill_chain_name and phase_name"
        raise ObjectPolicyError(msg)


def _observed_data(obj: Mapping[str, Any]) -> None:
    """No file content, embedded or not: AIVS carries no member's bytes to the sector.

    An ``artifact`` holds bytes (``payload_bin``) or points at them (``url``),
    and either way every circle member's tooling would fetch or unpack them. A
    finished document is linked from its report, on this instance's own route.
    """
    embedded = obj.get("objects")
    if not isinstance(embedded, Mapping):
        return
    for key, value in embedded.items():
        if isinstance(value, Mapping) and value.get("type") == "artifact":
            msg = f"{_described(obj)} embeds an artifact (object {key!r}); file content is refused"
            raise ObjectPolicyError(msg)


def _described(obj: Mapping[str, Any]) -> str:
    return f"{obj.get('type', 'object')} {obj.get('id', '<no id>')}"


_POLICIES: Final[Mapping[str, Callable[[Mapping[str, Any]], None]]] = {
    "vulnerability": _vulnerability,
    "attack-pattern": _attack_pattern,
    "indicator": _indicator,
    "observed-data": _observed_data,
}
