#!/usr/bin/env python3
"""File exploitability conditions from CVE and OSV records onto the ISAC's vulnerabilities.

Run by the operator, as the ISAC's automation organisation, with that
organisation's mTLS certificate:

    uv run python scripts/import-conditions.py \\
        --cve-dir cvelistV5/cves --osv-dir osv [--dry-run]

Both directories hold records the operator downloaded beforehand: CVE 5.x JSON
(the CNA's container and any ADP's) and OSV JSON (Go vulndb, RustSec). The
script makes no request to anyone but the AIVS instance, as the KEV script
does not.

For each ISAC vulnerability record that names a CVE, and each upstream record
about that CVE, it builds one condition note (Phase N, SF-95): the vulnerable
functions, files, modules and platforms the record states, as typed terms.
The note is filed as the automation's draft, which an editor sends; a machine's
conditions must be named at validate (the AI gate, SF-6).

**Never drop an alternative.** A note's conditions all hold together (AND),
and each is met by any one of its alternatives (OR). Leaving out a condition
makes the note claim more members are affected, which is safe. Leaving out an
alternative makes it claim fewer: a member whose platform or function was the
one left out is told it is not affected, a false negative at sector scale. So
a condition is built only when every affected entry in the record states it
and every alternative it lists maps to a typed term. Otherwise the whole
condition is left out and ``unknowns`` says so. If nothing is left, nothing is
filed.

Prose is never turned into a term. A CVE record's ``configurations`` is written
into the submission's summary, which only the ISAC reads, for the editor to
structure by hand; the note's own text is a fixed sentence, so nothing an
upstream author wrote is distributed.

Each note carries the import's reference (``CONDITION_IMPORT_REFERENCE``) with
the upstream record as its id, and the script reads the ISAC's notes that carry
it before filing: it versions its own when the record has changed, leaves one
an editor has since corrected, and files nothing while an earlier draft or
review of it waits.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import itertools
import json
import sys
import uuid
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, TextIO
from urllib.parse import quote

import jsonschema

from aivs_client.config import load_config
from aivs_client.transport import AivsError, NativeClient, build_http_client
from aivs_schemas.extension.builders import (
    AIVS_INTEL_EXTENSION_ID,
    CONDITION_IMPORT_REFERENCE,
    format_stix_timestamp,
    intel_json_schema,
)
from aivs_schemas.tlp import tlp_for_marking_id

#: One alternative more than the schema allows and the condition cannot be
#: carried whole; truncating it would drop alternatives.
MAX_ALTERNATIVES: Final[int] = 50
#: The submission summary's limit, less room for the closing pointer.
SUMMARY_ROOM: Final[int] = 4800

#: Package URL types, as the CVE record's ``packageURL`` writes them, to the
#: ecosystems a function term names.
PURL_ECOSYSTEMS: Final[Mapping[str, str]] = {
    "golang": "Go",
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
}

#: Package collections a CVE record may name instead of a ``packageURL``, to
#: the package URL type their ``packageName`` is written in. Exact URLs only:
#: a collection not listed here leaves the function condition out.
COLLECTIONS: Final[Mapping[str, str]] = {
    "https://pkg.go.dev": "golang",
    "https://www.npmjs.com": "npm",
    "https://pypi.org": "pypi",
    "https://crates.io": "cargo",
    "https://repo.maven.apache.org/maven2": "maven",
    "https://www.nuget.org": "nuget",
    "https://rubygems.org": "gem",
    "https://packagist.org": "composer",
}

#: Operating systems as CVE records and RustSec write them, to the Go/OSV
#: vocabulary a platform term uses. A name not here leaves the condition out.
OPERATING_SYSTEMS: Final[Mapping[str, str]] = {
    "linux": "linux",
    "windows": "windows",
    "macos": "darwin",
    "mac os x": "darwin",
    "os x": "darwin",
    "darwin": "darwin",
    "android": "android",
    "ios": "ios",
    "freebsd": "freebsd",
    "openbsd": "openbsd",
    "netbsd": "netbsd",
    "solaris": "solaris",
    "aix": "aix",
    "illumos": "illumos",
    "dragonfly": "dragonfly",
}

#: Architectures as RustSec writes them, to the Go/OSV vocabulary.
ARCHITECTURES: Final[Mapping[str, str]] = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "x86": "386",
    "386": "386",
    "aarch64": "arm64",
    "arm64": "arm64",
    "arm": "arm",
    "riscv64": "riscv64",
    "powerpc64": "ppc64",
    "s390x": "s390x",
    "wasm32": "wasm",
    "wasm": "wasm",
}

#: Words a CVE record's ``platforms`` uses for an architecture rather than an
#: operating system. An architecture alone restricts nothing a term can say
#: here, so it is set aside, which only widens the condition.
ARCHITECTURE_WORDS: Final[frozenset[str]] = frozenset(
    {"x86", "x64", "x86_64", "x86-64", "amd64", "arm", "arm64", "aarch64", "32-bit", "64-bit"}
)

KINDS: Final[tuple[str, ...]] = ("function", "file", "module", "platform")

#: What ``unknowns`` says when a condition is left out, by kind.
LEFT_OUT: Final[Mapping[str, str]] = {
    "function": (
        "Vulnerable functions: not every affected entry in the record names them in a form "
        "that can be checked, so no function condition is given."
    ),
    "file": "Vulnerable files: not stated for every affected entry, so none are given.",
    "module": "Vulnerable modules: not stated for every affected entry, so none are given.",
    "platform": (
        "Platforms: not stated for every affected entry, or named in a way that cannot be "
        "mapped, so every platform should be assumed affected."
    ),
}


# ---------------------------------------------------------------------------
# Terms: one alternative, typed, or nothing
# ---------------------------------------------------------------------------
def _term_validator(kind: str) -> jsonschema.Draft202012Validator:
    schema = intel_json_schema()
    return jsonschema.Draft202012Validator(
        {"$ref": f"#/$defs/exploit_term_{kind}", "$defs": schema["$defs"]}
    )


VALIDATORS: Final[Mapping[str, jsonschema.Draft202012Validator]] = {
    kind: _term_validator(kind) for kind in KINDS
}


def typed(kind: str, term: Mapping[str, Any]) -> dict[str, Any] | None:
    """``term`` if the extension's schema takes it as a ``kind`` term, else ``None``."""
    return dict(term) if VALIDATORS[kind].is_valid(term) else None


def all_typed(kind: str, terms: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]] | None:
    """Every term typed, or ``None``: one that does not map spoils the set, never shrinks it."""
    checked = [typed(kind, term) for term in terms]
    if not checked or any(term is None for term in checked):
        return None
    return [term for term in checked if term is not None]


# ---------------------------------------------------------------------------
# Conditions: every entry states it, or it is left out
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Statement:
    """What one upstream record says, as conditions, and what it left out."""

    conditions: tuple[dict[str, Any], ...]
    unknowns: tuple[str, ...]
    #: Prose the editor reads and structures; never distributed.
    configuration_prose: str


def condition(kind: str, per_entry: Sequence[list[dict[str, Any]] | None]) -> dict[str, Any] | None:
    """The ``kind`` condition over every affected entry, or ``None`` to leave it out.

    One entry that does not state it, or states it in a form that does not
    map, leaves the whole condition out: that entry's product may be affected
    through anything, and a condition naming only the others would tell its
    users they are not.
    """
    if not per_entry or any(terms is None for terms in per_entry):
        return None
    alternatives: list[dict[str, Any]] = []
    for terms in per_entry:
        alternatives.extend(term for term in terms or () if term not in alternatives)
    if len(alternatives) > MAX_ALTERNATIVES:
        return None
    return {"id": kind, "kind": kind, "any_of": alternatives}


def statement(
    per_kind: Mapping[str, Sequence[list[dict[str, Any]] | None]], configuration_prose: str = ""
) -> Statement:
    """The conditions a record supports, each kind built or left out with its reason."""
    conditions = []
    unknowns = []
    for kind in KINDS:
        built = condition(kind, per_kind.get(kind, ()))
        if built is None:
            unknowns.append(LEFT_OUT[kind])
        else:
            conditions.append(built)
    return Statement(tuple(conditions), tuple(unknowns), configuration_prose)


# ---------------------------------------------------------------------------
# CVE 5.x
# ---------------------------------------------------------------------------
def cve_entries(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Every ``affected`` entry, the CNA's and each ADP's.

    All of them, whatever their status: an entry counted that is not affected
    can only widen a condition, and one skipped that is can narrow it.
    """
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    adps = containers.get("adp") or []
    return [entry for container in [cna, *adps] for entry in container.get("affected") or []]


def entry_package(entry: Mapping[str, Any]) -> tuple[str, str] | None:
    """The entry's (ecosystem, package URL), from ``packageURL`` or a known collection."""
    purl = entry.get("packageURL")
    if not isinstance(purl, str):
        purl = _collection_purl(entry)
    if purl is None or not purl.startswith("pkg:"):
        return None
    purl_type = purl[4:].split("/", 1)[0]
    ecosystem = PURL_ECOSYSTEMS.get(purl_type)
    return (ecosystem, purl.split("@", 1)[0]) if ecosystem else None


def _collection_purl(entry: Mapping[str, Any]) -> str | None:
    purl_type = COLLECTIONS.get(str(entry.get("collectionURL", "")).rstrip("/"))
    name = entry.get("packageName")
    if purl_type is None or not isinstance(name, str) or not name:
        return None
    if purl_type == "maven":
        name = name.replace(":", "/", 1)
    return f"pkg:{purl_type}/{quote(name, safe='/')}"


def cve_functions(entry: Mapping[str, Any]) -> list[dict[str, Any]] | None:
    package = entry_package(entry)
    routines = entry.get("programRoutines") or []
    if package is None:
        return None
    ecosystem, purl = package
    return all_typed(
        "function",
        ({"ecosystem": ecosystem, "package": purl, "symbol": r.get("name")} for r in routines),
    )


def cve_paths(entry: Mapping[str, Any], field: str, kind: str) -> list[dict[str, Any]] | None:
    return all_typed(kind, ({"path": path} for path in entry.get(field) or []))


def cve_platforms(entry: Mapping[str, Any]) -> list[dict[str, Any]] | None:
    """The entry's operating systems; architecture words set aside, anything else spoils it."""
    named = [str(name).strip().lower() for name in entry.get("platforms") or []]
    systems = [name for name in named if name not in ARCHITECTURE_WORDS]
    if not systems or any(name not in OPERATING_SYSTEMS for name in systems):
        return None
    return all_typed(
        "platform", ({"os": OPERATING_SYSTEMS[name]} for name in dict.fromkeys(systems))
    )


def configuration_prose(record: Mapping[str, Any]) -> str:
    """The CNA's ``configurations``, English first, as the editor will read them."""
    cna = (record.get("containers") or {}).get("cna") or {}
    texts = [
        str(item.get("value", "")).strip()
        for item in cna.get("configurations") or []
        if str(item.get("lang", "en")).lower().startswith("en")
    ]
    return "\n\n".join(text for text in texts if text)


def from_cve(record: Mapping[str, Any]) -> Statement:
    entries = cve_entries(record)
    return statement(
        {
            "function": [cve_functions(entry) for entry in entries],
            "file": [cve_paths(entry, "programFiles", "file") for entry in entries],
            "module": [cve_paths(entry, "modules", "module") for entry in entries],
            "platform": [cve_platforms(entry) for entry in entries],
        },
        configuration_prose(record),
    )


# ---------------------------------------------------------------------------
# OSV: Go vulndb and RustSec
# ---------------------------------------------------------------------------
def platform_terms(
    systems: Iterable[str], architectures: Iterable[str]
) -> list[dict[str, Any]] | None:
    """Every (os, arch) the record names, mapped; ``None`` when it names none, or one we cannot map.

    No operating system named means every one: no condition, not an empty one.
    """
    os_names = [OPERATING_SYSTEMS.get(str(name).lower()) for name in systems]
    arch_names = [ARCHITECTURES.get(str(name).lower()) for name in architectures]
    if not os_names or None in os_names or None in arch_names:
        return None
    if not arch_names:
        return all_typed("platform", ({"os": name} for name in dict.fromkeys(os_names)))
    pairs = dict.fromkeys(itertools.product(os_names, arch_names))
    return all_typed("platform", ({"os": os, "arch": arch} for os, arch in pairs))


def _go_import(
    item: Mapping[str, Any],
) -> tuple[list[dict[str, Any]] | None, list[dict[str, Any]] | None]:
    path = item.get("path")
    symbols = item.get("symbols") or []
    functions = None
    if isinstance(path, str) and symbols:
        purl = f"pkg:golang/{path}"
        functions = all_typed(
            "function", ({"ecosystem": "Go", "package": purl, "symbol": s} for s in symbols)
        )
    return functions, platform_terms(item.get("goos") or [], item.get("goarch") or [])


def _rust_affects(
    affected: Mapping[str, Any], affects: Mapping[str, Any]
) -> tuple[list[dict[str, Any]] | None, list[dict[str, Any]] | None]:
    name = (affected.get("package") or {}).get("name")
    paths = affects.get("functions") or []
    functions = None
    if isinstance(name, str) and paths:
        purl = f"pkg:cargo/{name}"
        functions = all_typed(
            "function", ({"ecosystem": "crates.io", "package": purl, "symbol": p} for p in paths)
        )
    return functions, platform_terms(affects.get("os") or [], affects.get("arch") or [])


def osv_entries(record: Mapping[str, Any]) -> Iterator[tuple[Any, Any]]:
    """(functions, platforms) per affected unit: each Go import, each RustSec package.

    An ``affected`` entry with neither shape is one unit that states nothing,
    so it leaves both conditions out.
    """
    for affected in record.get("affected") or []:
        ecosystem = (affected.get("package") or {}).get("ecosystem")
        specific = affected.get("ecosystem_specific") or {}
        if ecosystem == "Go" and specific.get("imports"):
            yield from (_go_import(item) for item in specific["imports"])
        elif ecosystem == "crates.io" and isinstance(specific.get("affects"), Mapping):
            yield _rust_affects(affected, specific["affects"])
        else:
            yield None, None


def from_osv(record: Mapping[str, Any]) -> Statement:
    units = list(osv_entries(record))
    return statement(
        {
            "function": [functions for functions, _ in units],
            "platform": [platforms for _, platforms in units],
        }
    )


def osv_names(record: Mapping[str, Any], cve: str) -> bool:
    """Whether the OSV record is about ``cve``: its id, or one of its aliases."""
    names = {
        str(record.get("id", "")).upper(),
        *(str(a).upper() for a in record.get("aliases") or []),
    }
    return cve.upper() in names


# ---------------------------------------------------------------------------
# The note
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Upstream:
    """One record about one CVE: where it came from, and what it says."""

    source: str
    reference: dict[str, str]
    said: Statement


def cve_upstream(cve: str, record: Mapping[str, Any]) -> Upstream:
    return Upstream(
        source="cve.org",
        reference={
            "source_name": "cve",
            "external_id": cve,
            "url": f"https://www.cve.org/CVERecord?id={cve}",
        },
        said=from_cve(record),
    )


def osv_upstream(record: Mapping[str, Any]) -> Upstream:
    osv_id = str(record["id"])
    return Upstream(
        source=f"osv:{osv_id}",
        reference={
            "source_name": "osv",
            "external_id": osv_id,
            "url": f"https://osv.dev/vulnerability/{osv_id}",
        },
        said=from_osv(record),
    )


def note_for(
    vulnerability_id: str,
    upstream: Upstream,
    *,
    now: dt.datetime,
    previous: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """The note saying what ``upstream`` says, or ``None`` when there is nothing to file.

    Nothing when the record supports no condition, when it says what the
    previous version already says, or when the previous version is not older
    than now (a later ``modified`` is what makes a version newer).
    """
    said = upstream.said
    if not said.conditions:
        return None
    body = {
        "extension_type": "property-extension",
        "aivs_schema_version": "2.1",
        "summary": "Conditions as the upstream vulnerability record states them.",
        "conditions": list(said.conditions),
        **({"unknowns": list(said.unknowns)} if said.unknowns else {}),
    }
    stamp = format_stix_timestamp(now)
    if previous is not None and (
        _intel(previous) == body or stamp <= str(previous.get("modified", ""))
    ):
        return None
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": str(previous["id"]) if previous else f"note--{uuid.uuid4()}",
        "created": str(previous["created"]) if previous else stamp,
        "modified": stamp,
        "content": "Exploitability conditions imported from an upstream vulnerability record.",
        "object_refs": [vulnerability_id],
        "external_references": [
            {"source_name": CONDITION_IMPORT_REFERENCE, "external_id": upstream.source},
            upstream.reference,
        ],
        "extensions": {AIVS_INTEL_EXTENSION_ID: body},
    }


def _intel(note: Mapping[str, Any]) -> Any:
    return (note.get("extensions") or {}).get(AIVS_INTEL_EXTENSION_ID)


def submission_summary(upstream: Upstream) -> str:
    """What the editor reads beside the note: never distributed."""
    lines = [f"Imported by the condition import from {upstream.reference['url']}."]
    prose = upstream.said.configuration_prose
    if prose:
        if len(prose) > SUMMARY_ROOM:
            prose = prose[:SUMMARY_ROOM] + " [... continued in the record]"
        lines += [
            "",
            "The record states configuration in prose, which is not imported as a condition. "
            "Structure it as a configuration condition if it holds:",
            "",
            prose,
        ]
    return "\n".join(lines)


def tlp_of(record: Mapping[str, Any]) -> str:
    """The vulnerability record's TLP: a note about it is never looser (SF-49)."""
    marked = [tlp_for_marking_id(ref) for ref in record.get("object_marking_refs") or []]
    known = [tlp for tlp in marked if tlp is not None]
    if len(known) != 1:
        msg = f"{record.get('id')} does not carry exactly one TLP marking"
        raise ValueError(msg)
    return known[0].value


# ---------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------
FILED: Final[str] = "filed as a draft, waiting for an ISAC editor to send it"
WOULD_FILE: Final[str] = "would be filed (dry run)"
UNCHANGED: Final[str] = "already current"
NOTHING: Final[str] = "nothing filed: the record states no condition that can be carried whole"
HELD_BACK: Final[str] = (
    "skipped: an earlier version waits for an editor or in review, or is not readable here"
)
CORRECTED: Final[str] = "skipped: an editor has corrected the imported note, which is theirs now"
REFUSED: Final[str] = "refused by the server"
_OUTCOMES: Final[tuple[str, ...]] = (
    FILED,
    WOULD_FILE,
    UNCHANGED,
    NOTHING,
    HELD_BACK,
    CORRECTED,
    REFUSED,
)


def summary(counts: Mapping[str, int]) -> list[str]:
    """The closing lines: how many upstream records were read, and what became of each."""
    lines = [f"{sum(counts.values())} upstream records read"]
    lines += [f"  {counts[outcome]} {outcome}" for outcome in _OUTCOMES if counts.get(outcome)]
    return lines


def _say(line: str, stream: TextIO | None = None) -> None:
    # Looked up at the call, not bound as a default: a default is evaluated once,
    # at import, and output redirected after that went to the old stream.
    (stream or sys.stdout).write(line + "\n")


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Known:
    """The import's notes as the server reports them, by (vulnerability, source)."""

    notes: Mapping[tuple[str, str], Mapping[str, Any]]
    held_back: frozenset[tuple[str, str]]


def known_from(read: Mapping[str, Any]) -> Known:
    notes: dict[tuple[str, str], Mapping[str, Any]] = {}
    for served in read.get("notes") or []:
        note = served["note"]
        for key in _keys(note.get("object_refs") or [], _source_of(note)):
            notes[key] = {**note, "_machine_filed": served["machine_filed"]}
    held = {
        key
        for item in read.get("held_back") or []
        for key in _keys(item.get("about") or [], item.get("source"))
    }
    return Known(notes=notes, held_back=frozenset(held))


def _keys(about: Iterable[str], source: str | None) -> list[tuple[str, str]]:
    return [(str(ref), source) for ref in about] if source else []


def _source_of(note: Mapping[str, Any]) -> str | None:
    return next(
        (
            str(ref.get("external_id"))
            for ref in note.get("external_references") or []
            if ref.get("source_name") == CONDITION_IMPORT_REFERENCE
        ),
        None,
    )


def upstreams_for(
    cve: str, cve_dir: Path | None, osv_records: Sequence[Mapping[str, Any]]
) -> list[Upstream]:
    found = []
    if cve_dir is not None:
        path = cve_dir / f"{cve.upper()}.json"
        if path.is_file():
            found.append(cve_upstream(cve.upper(), json.loads(path.read_text(encoding="utf-8"))))
    found += [osv_upstream(record) for record in osv_records if osv_names(record, cve)]
    return found


def _decide(
    vulnerability: Mapping[str, Any], upstream: Upstream, known: Known, *, now: dt.datetime
) -> tuple[str, dict[str, Any] | None]:
    key = (str(vulnerability["id"]), upstream.source)
    if key in known.held_back:
        return HELD_BACK, None
    previous = known.notes.get(key)
    if previous is not None and not previous["_machine_filed"]:
        return CORRECTED, None
    if not upstream.said.conditions:
        return NOTHING, None
    clean = {k: v for k, v in previous.items() if k != "_machine_filed"} if previous else None
    note = note_for(str(vulnerability["id"]), upstream, now=now, previous=clean)
    return (UNCHANGED, None) if note is None else (FILED, note)


def _file(
    native: NativeClient, vulnerability: Mapping[str, Any], upstream: Upstream, note: dict[str, Any]
) -> str:
    extension = vulnerability["extensions"][AIVS_INTEL_EXTENSION_ID]
    created = native.create_submission(
        title=f"Exploitability conditions for {extension['cve_id']} ({upstream.source})",
        summary=submission_summary(upstream),
        discovery_scope=extension["discovery_scope"],
        tlp=tlp_of(vulnerability),
        bundle={"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [note]},
        # The ISAC's own note: it is the ISAC's whichever way this points.
        credit=False,
    )
    return str(created["id"])


def _handle(
    native: NativeClient,
    vulnerability: Mapping[str, Any],
    upstream: Upstream,
    known: Known,
    *,
    now: dt.datetime,
    dry_run: bool,
) -> str:
    outcome, note = _decide(vulnerability, upstream, known, now=now)
    if note is None:
        return outcome
    if dry_run:
        _say(f"would file {note['id']} for {vulnerability['id']} from {upstream.source}")
        return WOULD_FILE
    try:
        draft = _file(native, vulnerability, upstream, note)
    except (AivsError, ValueError) as exc:
        _say(f"refused {vulnerability['id']} from {upstream.source}: {exc}", sys.stderr)
        return REFUSED
    _say(f"filed {note['id']} for {vulnerability['id']} from {upstream.source} as draft {draft}")
    return FILED


def _osv_records(osv_dir: Path | None) -> list[dict[str, Any]]:
    if osv_dir is None:
        return []
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(osv_dir.glob("*.json"))]


def _cve_of(record: Mapping[str, Any]) -> str | None:
    cve = (record.get("extensions") or {}).get(AIVS_INTEL_EXTENSION_ID, {}).get("cve_id")
    return cve if isinstance(cve, str) else None


def run(args: argparse.Namespace) -> int:
    cve_dir = Path(args.cve_dir) if args.cve_dir else None
    osv_records = _osv_records(Path(args.osv_dir) if args.osv_dir else None)
    config = load_config(
        base_url=args.url, certificate=args.cert, private_key=args.key, ca_bundle=args.ca
    )
    counts: collections.Counter[str] = collections.Counter()
    with build_http_client(config) as http:
        native = NativeClient(http)
        now = dt.datetime.now(dt.UTC)
        known = known_from(native.isac_condition_notes())
        for vulnerability in native.isac_vulnerabilities()["objects"]:
            cve = _cve_of(vulnerability)
            for upstream in upstreams_for(cve, cve_dir, osv_records) if cve else ():
                counts[
                    _handle(native, vulnerability, upstream, known, now=now, dry_run=args.dry_run)
                ] += 1
    for line in summary(counts):
        _say(line)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cve-dir", default=None, help="CVE 5.x records, one CVE-*.json each")
    parser.add_argument("--osv-dir", default=None, help="OSV records, one *.json each")
    parser.add_argument("--dry-run", action="store_true", help="say what would be filed")
    for name in ("url", "cert", "key", "ca"):
        parser.add_argument(f"--{name}", default=None)
    args = parser.parse_args(argv)
    if not args.cve_dir and not args.osv_dir:
        parser.error("give --cve-dir, --osv-dir or both")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
