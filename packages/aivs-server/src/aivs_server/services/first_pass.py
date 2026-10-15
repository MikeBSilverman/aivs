"""The first pass over a submission: what an analyst would otherwise spot by hand (plan, Phase O).

Deterministic checks only, over the submission's own objects: no model, no
other member's content, so nothing here can tell anyone what else exists.
Each finding has a fixed code, the object and field it is about, and a
sentence for the analyst. Slice 1 shows them to the ISAC's reviewers alone:
the checks are tuned against real submissions before a member is told
anything, and nothing here changes a submission's state.

Computed when asked, never stored, like readiness. Storing begins when a
finding drives a disposition that has to be audited (Phase O, slice 2).

Duplicates are not repeated here: they need a caller's view, and the
reviewers already have them (``services.duplicates``).
"""

from __future__ import annotations

import datetime as dt
import enum
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID
from aivs_server.services.sanitisation import free_text_of, lint

__all__ = ["Finding", "FindingCode", "first_pass"]

#: How far ahead of the server's clock a stamp may be before it is worth a
#: question: clocks drift, and a minute's skew is not a member's mistake.
_FUTURE_TOLERANCE: Final[dt.timedelta] = dt.timedelta(minutes=5)
_STAMPED_FIELDS: Final[tuple[str, ...]] = ("created", "modified", "valid_from")
_MITIGATING: Final[frozenset[str]] = frozenset({"mitigation", "workaround"})


class FindingCode(enum.StrEnum):
    #: A mitigation or workaround that does not say how to confirm it took.
    MITIGATION_WITHOUT_CHECK = "mitigation_without_check"
    #: A vendor fix filed with a vulnerability that names no fixed version.
    FIX_WITHOUT_FIXED_VERSIONS = "fix_without_fixed_versions"
    #: An affected product with neither a purl nor a CPE: no tool can match it.
    PRODUCT_NOT_MACHINE_READABLE = "product_not_machine_readable"
    #: A vulnerability with no CVSS vector of either version.
    NO_SEVERITY = "no_severity"
    #: A timestamp later than now.
    DATED_IN_FUTURE = "dated_in_future"
    #: An exploitability condition that does not say how to check it.
    CONDITION_WITHOUT_CHECK = "condition_without_check"
    #: A function condition in a package the vulnerability does not list as affected.
    FUNCTION_OUTSIDE_PRODUCTS = "function_outside_products"
    #: Free text that may say more than the submitter meant (the sanitisation assist).
    SANITISATION = "sanitisation"


@dataclass(frozen=True, slots=True)
class Finding:
    code: FindingCode
    #: The object's id and the field: where the analyst looks.
    path: str
    detail: str


def first_pass(
    objects: Sequence[Mapping[str, Any]], *, own_names: Iterable[str], now: dt.datetime
) -> list[Finding]:
    """Every finding for ``objects``, the submission's own, in a stable order."""
    findings = [
        *_completeness(objects),
        *_dated_in_future(objects, now),
        *_sanitisation(objects, own_names),
    ]
    return sorted(findings, key=lambda finding: (finding.path, finding.code))


def _intel(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    body = (obj.get("extensions") or {}).get(AIVS_INTEL_EXTENSION_ID)
    return body if isinstance(body, Mapping) else {}


def _completeness(objects: Sequence[Mapping[str, Any]]) -> Iterator[Finding]:
    vulnerabilities = [obj for obj in objects if obj.get("type") == "vulnerability"]
    names_a_fixed_version = any(
        product.get("fixed_versions")
        for vulnerability in vulnerabilities
        for product in _intel(vulnerability).get("affected_products") or ()
    )
    for obj in objects:
        checks = _CHECKS.get(str(obj.get("type")))
        if checks is not None:
            yield from checks(obj, vulnerabilities, names_a_fixed_version)


def _course_of_action(
    obj: Mapping[str, Any], vulnerabilities: Sequence[Any], names_a_fixed_version: bool
) -> Iterator[Finding]:
    body = _intel(obj)
    category = body.get("category")
    if category in _MITIGATING and not body.get("validation_check"):
        yield Finding(
            FindingCode.MITIGATION_WITHOUT_CHECK,
            f"{obj.get('id')}.validation_check",
            f"a {category} with no way to confirm it took effect",
        )
    if category == "vendor_fix" and vulnerabilities and not names_a_fixed_version:
        yield Finding(
            FindingCode.FIX_WITHOUT_FIXED_VERSIONS,
            f"{obj.get('id')}.category",
            "a vendor fix, while the vulnerability filed with it names no fixed version",
        )


def _vulnerability(obj: Mapping[str, Any], *_: object) -> Iterator[Finding]:
    body = _intel(obj)
    if not (body.get("cvss_v4_vector") or body.get("cvss_v3_vector")):
        yield Finding(FindingCode.NO_SEVERITY, f"{obj.get('id')}.cvss", "no CVSS vector")
    for index, product in enumerate(body.get("affected_products") or ()):
        if not (product.get("purl") or product.get("cpe")):
            yield Finding(
                FindingCode.PRODUCT_NOT_MACHINE_READABLE,
                f"{obj.get('id')}.affected_products[{index}]",
                f"{product.get('vendor')} {product.get('product')} has neither a purl nor a CPE",
            )


def _note(
    obj: Mapping[str, Any], vulnerabilities: Sequence[Mapping[str, Any]], *_: object
) -> Iterator[Finding]:
    for condition in _intel(obj).get("conditions") or ():
        if not condition.get("how_to_check"):
            yield Finding(
                FindingCode.CONDITION_WITHOUT_CHECK,
                f"{obj.get('id')}.conditions.{condition.get('id')}",
                "a condition a member cannot check for itself",
            )
    yield from _functions_outside_products(obj, vulnerabilities)


def _functions_outside_products(
    note: Mapping[str, Any], vulnerabilities: Sequence[Mapping[str, Any]]
) -> Iterator[Finding]:
    """A function in a package its vulnerability does not list: a question, never a refusal.

    It may be right -- the flaw can sit in a dependency the advisory does not
    name -- but a member matching on the listed products will never look
    there. Only vulnerabilities filed in the same submission are compared;
    one already shared is the ISAC's view, which this first pass does not read.
    """
    refs = set(note.get("object_refs") or ())
    listed = {
        _package_of(product.get("purl"))
        for vulnerability in vulnerabilities
        if vulnerability.get("id") in refs
        for product in _intel(vulnerability).get("affected_products") or ()
    } - {None}
    if not listed:
        return
    for condition in _intel(note).get("conditions") or ():
        outside = [
            term["package"]
            for term in condition.get("any_of") or ()
            if condition.get("kind") == "function"
            and _package_of(term.get("package")) not in listed
        ]
        for package in outside:
            yield Finding(
                FindingCode.FUNCTION_OUTSIDE_PRODUCTS,
                f"{note.get('id')}.conditions.{condition.get('id')}",
                f"{package} is not among the vulnerability's affected products",
            )


def _package_of(purl: Any) -> str | None:
    """A purl without its version, qualifiers or subpath: the package it names."""
    if not isinstance(purl, str):
        return None
    base = purl.split("#", 1)[0].split("?", 1)[0]
    head, separator, last = base.rpartition("/")
    return f"{head}/{last.split('@', 1)[0]}" if separator else base


_CHECKS: Final[Mapping[str, Callable[..., Iterator[Finding]]]] = {
    "course-of-action": _course_of_action,
    "vulnerability": _vulnerability,
    "note": _note,
}


def _dated_in_future(objects: Sequence[Mapping[str, Any]], now: dt.datetime) -> Iterator[Finding]:
    latest_allowed = now + _FUTURE_TOLERANCE
    for obj in objects:
        for field in _STAMPED_FIELDS:
            stamp = _parse(obj.get(field))
            if stamp is not None and stamp > latest_allowed:
                yield Finding(
                    FindingCode.DATED_IN_FUTURE,
                    f"{obj.get('id')}.{field}",
                    f"{field} is {obj[field]}, later than now",
                )


def _parse(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return dt.datetime.fromisoformat(value)
    except ValueError:
        return None


def _sanitisation(
    objects: Sequence[Mapping[str, Any]], own_names: Iterable[str]
) -> Iterator[Finding]:
    for hit in lint(free_text_of({"objects": list(objects)}), own_names=own_names):
        yield Finding(FindingCode.SANITISATION, hit.field, f"{hit.kind.replace('_', ' ')}")
