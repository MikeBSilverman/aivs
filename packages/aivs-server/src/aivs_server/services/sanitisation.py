"""The sanitisation assist: free text that may say more than the submitter meant.

The server cannot sanitise free text (CLAUDE.md section 5: anonymity is a
promise it can only partly keep), but it can point at what usually gives a
submitter or a victim away, before the text leaves them: their own name, an
internal hostname, a private address range, an email address, and SAR
language, which is confidential by law in a way a technical finding is not.

An assist, never a refusal (plan, Phase E): each hit carries its span so the
portal can offer one-click redaction, and the submitter decides.

What it deliberately does *not* check: the names of other enrolled
organisations. Answering "your text mentions Acme Bank" would tell any caller
whether Acme is a member -- an oracle over the membership graph, which is a
protected asset. It checks the caller's own name and slug, the anonymity risk
that matters, and patterns that need no list.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal

__all__ = ["Hit", "free_text_of", "lint", "redact"]

Kind = Literal[
    "own_organisation", "private_address", "internal_hostname", "email_address", "sar_language"
]

#: STIX properties that hold prose a person wrote. Identifiers, references and
#: timestamps are structure, checked elsewhere.
_PROSE_KEYS: Final[frozenset[str]] = frozenset(
    {"name", "description", "content", "explanation", "abstract", "summary", "title"}
)

#: Prose inside our extension bodies. Read one level down, because a person
#: wrote it as surely as a description: a note's exploitability summary and
#: unknowns, an indicator's false-positive notes, a fix's residual risk.
_EXTENSION_PROSE_KEYS: Final[frozenset[str]] = frozenset(
    {"summary", "unknowns", "false_positive_notes", "residual_risk"}
)

#: Shorter names match inside ordinary words too often to be worth a warning.
_SHORTEST_NAME: Final[int] = 3

_IPV4: Final[re.Pattern[str]] = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_IPV6: Final[re.Pattern[str]] = re.compile(
    r"\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}(?:/\d{1,3})?\b"
)
_EMAIL: Final[re.Pattern[str]] = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_INTERNAL_HOST: Final[re.Pattern[str]] = re.compile(
    r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:local|internal|intranet|corp|lan|localdomain|home\.arpa)\b",
    re.IGNORECASE,
)
_SAR_PHRASE: Final[re.Pattern[str]] = re.compile(
    r"\bsuspicious activity reports?\b|\bFinCEN\b|\b314\(b\)", re.IGNORECASE
)
#: Case-sensitive: "SAR" is an acronym, and ignoring case flagged "SARS".
_SAR_ACRONYM: Final[re.Pattern[str]] = re.compile(r"\bSARs?\b")

#: Ranges that only exist inside an organisation. Named, not ``not is_global``:
#: the documentation ranges are not global either, and an advisory quoting
#: 203.0.113.9 as the attacker's address names no one.
_INTERNAL_V4: Final[tuple[ipaddress.IPv4Network, ...]] = tuple(
    ipaddress.IPv4Network(block)
    for block in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "127.0.0.0/8",
    )
)
_INTERNAL_V6: Final[tuple[ipaddress.IPv6Network, ...]] = (
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
)


def _is_internal(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if isinstance(network, ipaddress.IPv4Network):
        return any(network.subnet_of(internal) for internal in _INTERNAL_V4)
    return any(network.subnet_of(internal) for internal in _INTERNAL_V6)


_PATTERNS: Final[tuple[tuple[re.Pattern[str], Kind], ...]] = (
    (_INTERNAL_HOST, "internal_hostname"),
    (_EMAIL, "email_address"),
    (_SAR_PHRASE, "sar_language"),
    (_SAR_ACRONYM, "sar_language"),
)


@dataclass(frozen=True, slots=True)
class Hit:
    """One span worth a second look. ``field`` names where it is."""

    field: str
    kind: Kind
    start: int
    end: int
    text: str


def _private_addresses(text: str) -> Iterator[tuple[int, int]]:
    for pattern in (_IPV4, _IPV6):
        for match in pattern.finditer(text):
            try:
                network = ipaddress.ip_network(match.group(0), strict=False)
            except ValueError:
                continue
            if _is_internal(network):
                yield match.span()


def _own_names(text: str, names: Iterable[str]) -> Iterator[tuple[int, int]]:
    for name in names:
        if len(name) < _SHORTEST_NAME:
            continue
        for match in re.finditer(rf"\b{re.escape(name)}\b", text, re.IGNORECASE):
            yield match.span()


def _spans(text: str, own_names: Iterable[str]) -> Iterator[tuple[Kind, int, int]]:
    for start, end in _own_names(text, own_names):
        yield "own_organisation", start, end
    for start, end in _private_addresses(text):
        yield "private_address", start, end
    for pattern, kind in _PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()
            yield kind, start, end


def lint(fields: Mapping[str, str], *, own_names: Iterable[str]) -> list[Hit]:
    """Every hit in every field, in field order then position."""
    names = list(own_names)
    hits = [
        Hit(field, kind, start, end, text[start:end])
        for field, text in fields.items()
        for kind, start, end in _spans(text, names)
    ]
    return sorted(hits, key=lambda hit: (hit.field, hit.start))


def free_text_of(bundle: Mapping[str, Any]) -> dict[str, str]:
    """The prose in a bundle, keyed by a path a person can find it by."""
    found: dict[str, str] = {}
    for index, obj in enumerate(bundle.get("objects") or []):
        if not isinstance(obj, Mapping):
            continue
        label = obj.get("id") or f"objects[{index}]"
        for key, value in obj.items():
            if key in _PROSE_KEYS and isinstance(value, str):
                found[f"{label}.{key}"] = value
        found.update(_extension_prose(obj.get("extensions"), f"{label}.extensions"))
    return found


def _extension_prose(extensions: Any, label: str) -> dict[str, str]:
    if not isinstance(extensions, Mapping):
        return {}
    found: dict[str, str] = {}
    for body in extensions.values():
        if not isinstance(body, Mapping):
            continue
        for key in _EXTENSION_PROSE_KEYS & body.keys():
            value = body[key]
            if isinstance(value, str):
                found[f"{label}.{key}"] = value
            elif isinstance(value, list):
                found.update(
                    {
                        f"{label}.{key}[{i}]": item
                        for i, item in enumerate(value)
                        if isinstance(item, str)
                    }
                )
    return found


def redact(text: str, hits: Iterable[Hit], *, mark: str = "[redacted]") -> str:
    """Replace each hit's span with ``mark``.

    Overlapping hits are merged first: an address at an internal domain is both
    an email and an internal hostname, and replacing the two spans one after the
    other would cut the text at offsets the first replacement had moved.
    """
    merged: list[list[int]] = []
    for start, end in sorted((hit.start, hit.end) for hit in hits):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    for start, end in reversed(merged):
        text = text[:start] + mark + text[end:]
    return text
