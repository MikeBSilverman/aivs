"""One vulnerability as an OSV record, for the reachability tools that read OSV (Phase N).

A serialiser over the vulnerability the caller can see and its exploitability
view (``services.exploitability``). Nothing new is decided here; what this
module adds is the refusal.

An OSV record is read by a scanner, not a person, and a scanner reads absence
as "not affected": a record with no ``affected`` entries, or one listing the
symbols but not the versions, clears every member that runs the package. That
is the sector-scale false negative the view exists to prevent (plan, Phase N,
property 1). So the record is built only when every part of it is stated:

- the view is ``agreed``: a contested or unestablished view has no conditions
  to give, and symbols from one source would narrow another's;
- an agreed condition names a function, which is what OSV's symbols carry;
- every affected product names its package as a purl in an ecosystem OSV
  knows, and states a ``vers:`` range this module converts to OSV events
  without changing what it covers.

Anything else is refused with the reason, never answered with a smaller
record. One product the record cannot carry refuses the whole record: a
record that left it out would tell the scanner that product is safe.

What the record leaves out only widens it. Conditions of the other kinds
(a platform, a configuration, an exposure) have no OSV field and are dropped,
so a scanner reports more members affected than the view does, never fewer.
Several function conditions, which the view requires together, become one
list of symbols, any of which a scanner treats as reachable: wider again.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import unquote

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.extension.builders import AIVS_EXTENSION_ID, AIVS_INTEL_EXTENSION_ID
from aivs_server.auth.context import AuthContext
from aivs_server.services.exploitability import (
    ExploitabilityStatus,
    ExploitabilityView,
    exploitability_in,
)
from aivs_server.services.visible import visible_objects
from aivs_server.services.vulnerability_objects import gather_vulnerability

__all__ = ["OSV_SCHEMA_VERSION", "OsvRefusedError", "osv_for", "osv_record"]

#: The OSV schema release the record follows and the tests validate against.
OSV_SCHEMA_VERSION: Final[str] = "1.9.1"

#: OSV reserves ``x_`` for databases it does not list; the ISAC is one.
_ID_PREFIX: Final[str] = "x_AIVS-"


class OsvRefusedError(Exception):
    """The record would say less than the caller's view does; ``reason`` says what is missing."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class _Ecosystem:
    #: OSV's name for the ecosystem.
    name: str
    #: OSV's range type for its versions.
    range_type: str
    #: The ``vers:`` schemes whose versions this ecosystem's range type orders.
    vers_schemes: frozenset[str]
    #: How a purl's namespace and name join into OSV's package name.
    separator: str = "/"


#: By purl type. An ecosystem missing here is refused rather than guessed at.
_ECOSYSTEMS: Final[Mapping[str, _Ecosystem]] = {
    "golang": _Ecosystem("Go", "SEMVER", frozenset({"golang", "semver"})),
    "npm": _Ecosystem("npm", "SEMVER", frozenset({"npm", "semver"})),
    "cargo": _Ecosystem("crates.io", "SEMVER", frozenset({"cargo", "semver"})),
    "pypi": _Ecosystem("PyPI", "ECOSYSTEM", frozenset({"pypi"})),
    "maven": _Ecosystem("Maven", "ECOSYSTEM", frozenset({"maven"}), separator=":"),
    "nuget": _Ecosystem("NuGet", "ECOSYSTEM", frozenset({"nuget"})),
    "gem": _Ecosystem("RubyGems", "ECOSYSTEM", frozenset({"gem"})),
    "composer": _Ecosystem("Packagist", "ECOSYSTEM", frozenset({"composer"})),
}

_NOT_AGREED: Final[Mapping[ExploitabilityStatus, str]] = {
    ExploitabilityStatus.NOT_ESTABLISHED: (
        "nobody has stated what makes this exploitable, so there are no symbols to export"
    ),
    ExploitabilityStatus.CONTESTED: (
        "the sources disagree about what makes this exploitable, and any one "
        "source's symbols would narrow another's"
    ),
}


async def osv_for(
    session: AsyncSession, ctx: AuthContext, vulnerability_stix_id: str, *, now: dt.datetime
) -> dict[str, Any]:
    """The OSV record for one vulnerability, from what ``ctx`` can see.

    Raises ``VulnerabilityHiddenError`` unless ``ctx`` can see the
    vulnerability, and :class:`OsvRefusedError` when the record cannot be
    complete.
    """
    found = await gather_vulnerability(session, ctx, vulnerability_stix_id, now=now)
    view = await exploitability_in(session, visible_objects(ctx, now), vulnerability_stix_id)
    return osv_record(found.vulnerability.raw, view)


def osv_record(vulnerability: Mapping[str, Any], view: ExploitabilityView) -> dict[str, Any]:
    """``vulnerability`` and its view as an OSV record, or :class:`OsvRefusedError`."""
    if view.status is not ExploitabilityStatus.AGREED:
        raise OsvRefusedError(_NOT_AGREED[view.status])
    functions = [c for c in view.conditions if c["kind"] == "function"]
    if not functions:
        reason = "no agreed condition names a function, which is what OSV carries"
        raise OsvRefusedError(reason)
    intel = _intel(vulnerability)
    products = [p for p in intel.get("affected_products") or () if isinstance(p, Mapping)]
    if not products:
        reason = "the vulnerability names no affected product"
        raise OsvRefusedError(reason)
    symbols = _symbols(functions)
    record: dict[str, Any] = {
        "schema_version": OSV_SCHEMA_VERSION,
        "id": _ID_PREFIX + str(vulnerability["id"]).removeprefix("vulnerability--"),
        "modified": _stamp(_modified(vulnerability, view)),
        "published": _stamp(_parse(vulnerability["created"])),
        "summary": str(vulnerability.get("name", "")),
        "affected": [_affected(product, symbols) for product in products],
    }
    if isinstance(vulnerability.get("description"), str):
        record["details"] = vulnerability["description"]
    aliases = _aliases(vulnerability, intel)
    if aliases:
        record["aliases"] = aliases
    return record


def _aliases(vulnerability: Mapping[str, Any], intel: Mapping[str, Any]) -> list[str]:
    """The CVE, wherever the record states it."""
    cited = [
        reference.get("external_id")
        for reference in vulnerability.get("external_references") or ()
        if isinstance(reference, Mapping) and reference.get("source_name") == "cve"
    ]
    return [cve for cve in dict.fromkeys([intel.get("cve_id"), *cited]) if isinstance(cve, str)]


def _intel(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    extensions = obj.get("extensions") or {}
    body = extensions.get(AIVS_INTEL_EXTENSION_ID) or extensions.get(AIVS_EXTENSION_ID)
    return body if isinstance(body, Mapping) else {}


def _modified(vulnerability: Mapping[str, Any], view: ExploitabilityView) -> dt.datetime:
    """The latest change to anything the record says: the vulnerability or a source."""
    return max([_parse(vulnerability["modified"]), *(source.modified for source in view.sources)])


def _parse(stamp: str) -> dt.datetime:
    return dt.datetime.fromisoformat(stamp)


def _stamp(moment: dt.datetime) -> str:
    return moment.astimezone(dt.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _Package:
    ecosystem: _Ecosystem
    name: str
    purl: str


def _package(purl: Any) -> _Package:
    """The OSV package a purl names, or a refusal naming the purl."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        reason = f"an affected product has no package URL ({purl!r})"
        raise OsvRefusedError(reason)
    path = purl[4:].split("#", 1)[0].split("?", 1)[0]
    purl_type, _, rest = path.partition("/")
    ecosystem = _ECOSYSTEMS.get(purl_type.lower())
    if ecosystem is None or not rest:
        reason = f"{purl} is not in an ecosystem OSV records"
        raise OsvRefusedError(reason)
    *namespace, last = rest.split("/")
    name, _, version = last.partition("@")
    segments = [unquote(segment) for segment in (*namespace, name)]
    joined = ecosystem.separator.join(
        [*(["/".join(segments[:-1])] if namespace else []), segments[-1]]
    )
    unversioned = f"pkg:{purl_type}/{'/'.join((*namespace, name))}"
    return _Package(ecosystem, joined, unversioned if version else purl.split("?", 1)[0])


def _symbols(functions: Sequence[Mapping[str, Any]]) -> dict[tuple[str, str], list[str]]:
    """Every agreed function, by the (ecosystem, package) it is in."""
    found: dict[tuple[str, str], list[str]] = {}
    for condition in functions:
        for term in condition["any_of"]:
            package = _package(term["package"])
            listed = found.setdefault((package.ecosystem.name, package.name), [])
            if term["symbol"] not in listed:
                listed.append(term["symbol"])
    return found


def _affected(
    product: Mapping[str, Any], symbols: Mapping[tuple[str, str], list[str]]
) -> dict[str, Any]:
    package = _package(product.get("purl"))
    entry: dict[str, Any] = {
        "package": {
            "ecosystem": package.ecosystem.name,
            "name": package.name,
            "purl": package.purl,
        },
        "ranges": [
            {"type": package.ecosystem.range_type, "events": events}
            for events in _intervals(product.get("version_range"), package)
        ],
    }
    listed = symbols.get((package.ecosystem.name, package.name))
    if listed:
        # The shape Go's tooling reads; other ecosystems' tools ignore the
        # block and treat the whole package as affected, which is wider.
        entry["ecosystem_specific"] = {"imports": [{"path": package.name, "symbols": listed}]}
    return entry


# ---------------------------------------------------------------------------
# Versions: vers to OSV events, interval by interval
# ---------------------------------------------------------------------------
def _intervals(version_range: Any, package: _Package) -> list[list[dict[str, str]]]:
    """``version_range`` as OSV ranges' events, one range per interval.

    One range per interval because OSV forbids ``fixed`` and ``last_affected``
    in one range, and ``<`` and ``<=`` bounds can both appear in one vers.
    """
    if not isinstance(version_range, str) or "/" not in version_range:
        reason = f"{package.purl} states no version range"
        raise OsvRefusedError(reason)
    scheme, _, constraints = version_range.removeprefix("vers:").partition("/")
    if scheme not in package.ecosystem.vers_schemes:
        reason = f"{version_range} is not in a scheme {package.ecosystem.name} orders"
        raise OsvRefusedError(reason)
    try:
        return list(_events(constraints.split("|"), package.ecosystem))
    except _UnconvertibleError as unconvertible:
        reason = f"{version_range}: {unconvertible}"
        raise OsvRefusedError(reason) from None


class _UnconvertibleError(Exception):
    pass


def _events(constraints: Sequence[str], ecosystem: _Ecosystem) -> Iterator[list[dict[str, str]]]:
    """Walk the sorted constraints, pairing each lower bound with the upper one after it."""
    if list(constraints) == ["*"]:
        yield [{"introduced": "0"}]
        return
    lower: str | None = None
    for position, constraint in enumerate(constraints):
        operator, version = _split(constraint, ecosystem)
        if operator == ">=" and lower is None:
            lower = version
        elif operator in {"<", "<="} and (lower is not None or position == 0):
            bound = "fixed" if operator == "<" else "last_affected"
            yield [{"introduced": lower or "0"}, {bound: version}]
            lower = None
        elif operator == "=" and lower is None:
            yield [{"introduced": version}, {"last_affected": version}]
        else:
            reason = f"{constraint!r} cannot be said in OSV events here"
            raise _UnconvertibleError(reason)
    if lower is not None:
        yield [{"introduced": lower}]


def _split(constraint: str, ecosystem: _Ecosystem) -> tuple[str, str]:
    for operator in (">=", "<=", "!=", ">", "<", "="):
        if constraint.startswith(operator):
            return operator, _version(constraint[len(operator) :], ecosystem)
    return "=", _version(constraint, ecosystem)


def _version(version: str, ecosystem: _Ecosystem) -> str:
    """OSV writes Go's versions without the ``v`` its modules carry."""
    if not version or version == "*":
        reason = f"{version!r} is not one version"
        raise _UnconvertibleError(reason)
    return version.removeprefix("v") if ecosystem.name == "Go" else version
