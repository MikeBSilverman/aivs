"""Guided depth: one vulnerability, explained from its objects alone.

A bank's reviewer reads a vulnerability as four questions: what is this, am I
affected, what do I do, and how do I know I am done. The objects already hold
every answer -- the vulnerability's extension names the products, the
courses of action say what to do and in what kind of change, their validation
checks say how to confirm it -- so the guided view is a function over them and
nothing else (NFR-U6). It has no stored text of its own, no editor writing a
second, plain-language copy that would drift from the record it explains
(CLAUDE.md section 5, "two descriptions of one thing will drift").

The view never shows a STIX type name or identifier (NFR-U5). "Indicator" and
"course-of-action" are the format's words, not the reader's; the reader's are
"watch for" and "do this".

The caller passes only objects it may see -- the latest visible version of
each, as the vulnerability page gathers them -- so this module makes no
visibility decision and needs no session. Everything it
renders is member-supplied text, which the template escapes (SF-29).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from aivs_schemas.enums import ReadingDepth
from aivs_schemas.extension.builders import (
    AIVS_EXTENSION_ID,
    AIVS_INTEL_EXTENSION_ID,
    AIVS_PROVENANCE_EXTENSION_ID,
)
from aivs_server.services.exploitability import ExploitabilityStatus, ExploitabilityView

__all__ = [
    "AffectedProduct",
    "AffectedWhen",
    "Assessment",
    "Condition",
    "Guidance",
    "Step",
    "WatchFor",
    "affected_product_names",
    "affected_when",
    "guide",
    "is_current_indicator",
    "is_due_for_review",
    "provenance",
    "resolve_depth",
    "review_lapsed",
    "stated_review_by",
]

type StixObject = Mapping[str, Any]


def resolve_depth(requested: str | None, preference: ReadingDepth | None) -> ReadingDepth:
    """The depth to render: the link's, else the operator's preference, else standard.

    The preference (``operators.default_depth``) is the one thing stored about
    how a person reads, and it is safe to store because it confers nothing: it
    picks a rendering of objects the caller may already see. The authorization
    matrix runs with it set to prove that.

    An unrecognised ``?depth=`` is ignored rather than refused. A depth is a
    reading preference carried in links people paste into tickets; a typo in
    one should still show the page, and no value can show more than the caller
    may read.
    """
    known = {depth.value: depth for depth in ReadingDepth}
    if requested in known:
        return known[requested]
    return preference or ReadingDepth.STANDARD


@dataclass(frozen=True)
class AffectedProduct:
    name: str
    versions: str | None
    fixed_in: str | None


@dataclass(frozen=True)
class Step:
    title: str
    detail: str | None
    kind: str
    restart: str | None
    provenance: str
    #: Became visible to the reader since they last read this vulnerability.
    is_new: bool
    #: The step's ``review_by`` has passed: still shown, flagged, because a
    #: stale workaround is information but not an instruction.
    review_overdue: bool


@dataclass(frozen=True)
class WatchFor:
    title: str
    detail: str | None
    valid_until: str
    provenance: str
    is_new: bool


@dataclass(frozen=True)
class DeltaLine:
    what: str
    public_says: str
    isac_says: str


@dataclass(frozen=True)
class Assessment:
    statement: str
    differences: tuple[DeltaLine, ...]


@dataclass(frozen=True)
class Condition:
    #: What must be true, alternatives joined by "or".
    requirement: str
    #: How to find out, when the source says.
    check: str | None


@dataclass(frozen=True)
class AffectedWhen:
    """What exploitation needs beyond running the product (Phase N)."""

    statement: str
    #: Every one must hold; given only when the sources agree.
    conditions: tuple[Condition, ...]
    unknowns: tuple[str, ...]


@dataclass(frozen=True)
class Guidance:
    title: str
    summary: str | None
    severity: str | None
    urgency: str | None
    exploited: str | None
    affected: tuple[AffectedProduct, ...]
    affected_when: AffectedWhen
    steps: tuple[Step, ...]
    no_fix: str | None
    done_when: tuple[str, ...]
    watch_for: tuple[WatchFor, ...]
    if_it_goes_wrong: tuple[Step, ...]
    assessment: Assessment | None


# ---------------------------------------------------------------------------
# Vocabulary: the format's values in the reader's words
# ---------------------------------------------------------------------------
#: Order of the steps: fix first, then reduce exposure, then work around.
_STEP_ORDER: Final[Mapping[str, int]] = {"vendor_fix": 0, "mitigation": 1, "workaround": 2}

_STEP_KIND: Final[Mapping[str, str]] = {
    "vendor_fix": "Apply the fix",
    "mitigation": "Reduce your exposure",
    "workaround": "Work around it",
    "rollback": "Undo the change",
}

_NO_FIX: Final[Mapping[str, str]] = {
    "none_available": "No fix is available yet.",
    "no_fix_planned": "The vendor does not plan to fix this.",
}
_STALE_NO_FIX: Final[str] = (
    "The last word was that there is no fix, but nobody has confirmed that since "
    "the date its author set. Ask the ISAC before relying on it."
)

_RESTART: Final[Mapping[str, str]] = {
    "none": "No restart needed.",
    "vulnerable_component": "Restart the affected component.",
    "service": "Restart the affected service.",
    "parent": "Restart the program that hosts the affected component.",
    "dependencies": "Restart the services that depend on it.",
    "connected": "Restart the systems connected to it.",
    "machine": "Reboot the machine.",
    "zone": "Restart every system in the affected zone.",
    "system": "Restart the whole system.",
}

_URGENCY: Final[Mapping[str, str]] = {
    "Act": "Act now: this needs attention ahead of your normal patch cycle.",
    "Attend": "Attend to this soon, ahead of your normal patch cycle.",
    "Track*": "Track this closely; handle it in your normal patch cycle.",
    "Track": "Handle this in your normal patch cycle.",
}

_ASSESSMENT: Final[Mapping[str, str]] = {
    "confirms": "The ISAC's analysis agrees with the public record.",
    "adds": "The ISAC's analysis adds to the public record.",
    "contradicts": "The ISAC's analysis disagrees with the public record.",
    "no_position": "The ISAC takes no position on the public record.",
}

_DELTA_PROPERTY: Final[Mapping[str, str]] = {
    "cvss_v4_base_score": "Severity score (CVSS 4)",
    "cvss_v3_vector": "Severity (CVSS 3)",
    "cvss_v4_vector": "Severity (CVSS 4)",
    "affected_products": "Affected products",
    "kev_listed": "Known to be exploited",
    "ssvc_exploitation": "Exploitation",
    "ssvc_automatable": "Can be automated",
    "ssvc_technical_impact": "Impact",
    "ssvc_decision": "Recommended urgency",
    "workaround_available": "Workaround available",
}


# ---------------------------------------------------------------------------
# The generator
# ---------------------------------------------------------------------------
def guide(
    vulnerability: StixObject,
    related: Sequence[StixObject],
    *,
    now: dt.datetime,
    exploitability: ExploitabilityView,
    new_ids: frozenset[str] = frozenset(),
) -> Guidance:
    """The guided view of ``vulnerability``, from it and the objects related to it.

    ``related`` are the latest visible versions of the objects a visible
    relationship connects to the vulnerability. Revoked ones are ignored.
    ``new_ids`` are the ids the reader has not seen since they last read it
    (:func:`~aivs_server.services.vulnerability_objects.new_since`); their
    steps and signs are marked new. ``exploitability`` is the view over the
    condition notes the caller can see (:mod:`~aivs_server.services.exploitability`).
    """
    intel = _intel(vulnerability)
    actions = [obj for obj in _live(related) if obj.get("type") == "course-of-action"]
    indicators = [obj for obj in _live(related) if obj.get("type") == "indicator"]
    return Guidance(
        title=_title(vulnerability, intel),
        summary=_text(vulnerability.get("description")),
        severity=_severity(intel),
        urgency=_URGENCY.get(str(intel.get("ssvc_decision"))),
        exploited=_exploited(intel),
        affected=tuple(_affected(product) for product in _products(intel)),
        affected_when=affected_when(exploitability),
        steps=_steps(actions, now, new_ids),
        no_fix=_no_fix(actions, now),
        done_when=_done_when(actions),
        watch_for=tuple(
            _watch_for(obj, new_ids) for obj in indicators if is_current_indicator(obj, now)
        ),
        if_it_goes_wrong=tuple(
            _step(obj, now, new_ids) for obj in actions if _category(obj) == "rollback"
        ),
        assessment=_assessment(intel),
    )


def is_current_indicator(indicator: StixObject, now: dt.datetime) -> bool:
    """Whether an indicator may still be acted on: it states an end, and that end is ahead.

    One with no ``valid_until`` (stored before SF-46 required it) is not
    current: nobody can say it still holds, and a member blocking an address
    for years on its strength is the harm SF-46 exists to stop.
    """
    valid_until = _timestamp(indicator.get("valid_until"))
    return valid_until is not None and valid_until > now


def is_due_for_review(course_of_action: StixObject, now: dt.datetime) -> bool:
    """Whether a course of action's ``review_by`` date has passed (:func:`review_lapsed`)."""
    return review_lapsed(stated_review_by(course_of_action), now)


def stated_review_by(course_of_action: StixObject) -> str | None:
    """The ``review_by`` a course of action states, as written; None when it states none."""
    review_by = _intel(course_of_action).get("review_by")
    return review_by if isinstance(review_by, str) else None


def review_lapsed(review_by: str | None, now: dt.datetime) -> bool:
    """Whether a ``review_by`` date has passed: the one rule, for this view and readiness.

    Past it, the action's claim -- a fix exists, or none does -- is stale:
    nobody has re-checked it since a date its author set, so neither view may
    go on stating it (``readiness.Availability.LAPSED``). No ``review_by``
    never lapses. The date is a whole day in UTC, so a claim lapses from the
    start of the day after it; one that is not a date has lapsed, because
    nobody can say when it was meant to be re-checked.
    """
    if review_by is None:
        return False
    try:
        last_day = dt.date.fromisoformat(review_by)
    except ValueError:
        return True
    return now.date() > last_day


def _live(objects: Iterable[StixObject]) -> list[StixObject]:
    return [obj for obj in objects if not obj.get("revoked")]


def _intel(obj: StixObject) -> Mapping[str, Any]:
    """The AIVS extension body: 2.0 if present, else 1.0, else nothing."""
    extensions = obj.get("extensions") or {}
    body = extensions.get(AIVS_INTEL_EXTENSION_ID) or extensions.get(AIVS_EXTENSION_ID)
    return body if isinstance(body, Mapping) else {}


def _text(value: Any) -> str | None:
    return value.strip() or None if isinstance(value, str) else None


def _title(vulnerability: StixObject, intel: Mapping[str, Any]) -> str:
    name = _text(vulnerability.get("name"))
    cve_id = _text(intel.get("cve_id"))
    if name and cve_id and cve_id not in name:
        return f"{name} ({cve_id})"
    return name or cve_id or "Untitled"


def _severity(intel: Mapping[str, Any]) -> str | None:
    score = intel.get("cvss_v4_base_score")
    label = _text(intel.get("cvss_v4_severity"))
    if score is None:
        return label.capitalize() if label else None
    return f"{label.capitalize() if label else 'Severity'}: {score} out of 10"


def _exploited(intel: Mapping[str, Any]) -> str | None:
    if intel.get("kev_listed") is not True:
        return None
    since = _text(intel.get("kev_date_added"))
    statement = "Attackers are known to be exploiting this"
    if intel.get("kev_ransomware_use") == "Known":
        statement += ", including in ransomware campaigns"
    return f"{statement} (listed by CISA since {since})." if since else f"{statement}."


# ---------------------------------------------------------------------------
# Am I affected
# ---------------------------------------------------------------------------
def _products(intel: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    products = intel.get("affected_products")
    if not isinstance(products, list):
        return []
    return [product for product in products if isinstance(product, Mapping)]


def affected_product_names(vulnerability: StixObject) -> list[str]:
    """The names of the products a vulnerability affects, as the guided view writes them.

    For routing: a member's ticketing system assigns on the product. Shared by
    the guided view and the notification, so the two name a product the same way.
    """
    return [_product_name(product) for product in _products(_intel(vulnerability))]


def _affected(product: Mapping[str, Any]) -> AffectedProduct:
    fixed = product.get("fixed_versions")
    return AffectedProduct(
        name=_product_name(product),
        versions=_versions(product.get("version_range")),
        fixed_in=", ".join(str(v) for v in fixed) if isinstance(fixed, list) and fixed else None,
    )


def _product_name(product: Mapping[str, Any]) -> str:
    """The product's name: as given, else read from its CPE, else from its package URL."""
    vendor = _text(product.get("vendor"))
    name = _text(product.get("product"))
    if name:
        return f"{vendor} {name}" if vendor and not name.startswith(vendor) else name
    return _name_from_cpe(product.get("cpe")) or _name_from_purl(product.get("purl")) or "Unnamed"


def _name_from_cpe(cpe: Any) -> str | None:
    """``cpe:2.3:a:apache:http_server:2.4.1:...`` reads as "Apache Http Server"."""
    if not isinstance(cpe, str):
        return None
    parts = cpe.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":  # noqa: PLR2004 - CPE 2.3 layout
        return None
    words = [part.replace("_", " ").title() for part in parts[3:5] if part not in {"*", "-", ""}]
    return " ".join(words) or None


def _name_from_purl(purl: Any) -> str | None:
    """``pkg:pypi/requests@2.31.0`` reads as "requests (pypi)"."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    package_type, _, rest = purl[4:].partition("/")
    name = rest.split("@", 1)[0].split("?", 1)[0].rsplit("/", 1)[-1]
    return f"{name} ({package_type})" if name else None


def _versions(version_range: Any) -> str | None:
    """A ``vers:`` range in words.

    ``vers:semver/>=2.0.0|<2.4.1`` reads as "2.0.0 or later, before 2.4.1".
    """
    if not isinstance(version_range, str) or "/" not in version_range:
        return None
    constraints = version_range.split("/", 1)[1]
    words = [_constraint_words(item.strip()) for item in constraints.split("|") if item.strip()]
    return ", ".join(words) or None


def _constraint_words(constraint: str) -> str:
    for operator, words in ((">=", "{} or later"), ("<=", "up to {}"), (">", "after {}")):
        if constraint.startswith(operator):
            return words.format(constraint[len(operator) :])
    if constraint.startswith("<"):
        return f"before {constraint[1:]}"
    if constraint == "*":
        return "every version"
    return constraint.removeprefix("=")


# ---------------------------------------------------------------------------
# What exploitation needs (Phase N), from the exploitability view
# ---------------------------------------------------------------------------
_AFFECTED_WHEN: Final[Mapping[ExploitabilityStatus, str]] = {
    ExploitabilityStatus.NOT_ESTABLISHED: (
        "Nobody has said yet what else an attacker needs, so if you run one of "
        "these, treat yourself as affected."
    ),
    ExploitabilityStatus.AGREED: (
        "Running it is not enough on its own: you are affected only if every one of "
        "these is true. If you cannot tell whether one is, treat it as true."
    ),
    ExploitabilityStatus.CONTESTED: (
        "The ISAC's sources disagree about what else an attacker needs, so if you run "
        "one of these, treat yourself as affected. The standard view shows each "
        "source's account."
    ),
}

_OS_NAMES: Final[Mapping[str, str]] = {
    "darwin": "macOS",
    "ios": "iOS",
    "linux": "Linux",
    "windows": "Windows",
    "android": "Android",
    "freebsd": "FreeBSD",
    "openbsd": "OpenBSD",
    "netbsd": "NetBSD",
}
_ARCH_NAMES: Final[Mapping[str, str]] = {"amd64": "64-bit Intel or AMD", "arm64": "64-bit Arm"}

#: CVSS v4's exposure metrics in the reader's words, in the order a sentence wants them.
_EXPOSURE_WORDS: Final[Mapping[str, Mapping[str, str]]] = {
    "AV": {
        "N": "can reach it over the network",
        "A": "can reach it from the same local network",
        "L": "can already run something on the machine",
        "P": "can touch the machine",
    },
    "PR": {
        "N": "without signing in",
        "L": "with an ordinary account",
        "H": "with an administrator's account",
    },
    "UI": {
        "N": "with nobody's help",
        "P": "once someone opens or views something",
        "A": "once someone is talked into doing something",
    },
}


def affected_when(view: ExploitabilityView) -> AffectedWhen:
    """What exploitation needs, in the reader's words.

    Conditions are spelled out only when the sources agree. A contested view
    gives none, as the view itself does: the guided reader acts on one list, and
    any one source's list would narrow another's.
    """
    agreed = view.status is ExploitabilityStatus.AGREED
    unknowns = dict.fromkeys(unknown for source in view.sources for unknown in source.unknowns)
    return AffectedWhen(
        statement=_AFFECTED_WHEN[view.status],
        conditions=tuple(_condition(c) for c in view.conditions) if agreed else (),
        unknowns=tuple(unknowns),
    )


def _condition(condition: Mapping[str, Any]) -> Condition:
    kind = str(condition["kind"])
    alternatives = " or ".join(_alternative(kind, term) for term in condition["any_of"])
    check = condition.get("how_to_check")
    return Condition(
        requirement=_REQUIREMENT[kind].format(alternatives),
        check=(
            f"To find out, use {check['tool']}: “{check['query_or_command']}”. "
            f"Its source expects: {check['expected_result']}"
            if isinstance(check, Mapping)
            else None
        ),
    )


_REQUIREMENT: Final[Mapping[str, str]] = {
    "function": "Your software calls {}.",
    "file": "What you run includes {}.",
    "module": "You use {}.",
    "platform": "It runs on {}.",
    "configuration": "{}.",
    "version": "The version you run is {}.",
    "exposure": "An attacker {}.",
}


def _alternative(kind: str, term: Mapping[str, Any]) -> str:
    if kind == "function":
        return f"{term['symbol']} from {_name_from_purl(term['package']) or term['package']}"
    if kind == "platform":
        return _platform(term)
    if kind == "configuration":
        return _setting(term)
    if kind == "version":
        return _versions(term["vers"]) or str(term["vers"])
    if kind == "exposure":
        return ", ".join(
            words[term[metric]] for metric, words in _EXPOSURE_WORDS.items() if metric in term
        )
    return str(term["path"])


def _platform(term: Mapping[str, Any]) -> str:
    if "cpe" in term:
        return _name_from_cpe(term["cpe"]) or str(term["cpe"])
    os_name = _OS_NAMES.get(str(term["os"]), str(term["os"]))
    arch = term.get("arch")
    return f"{os_name} on {_ARCH_NAMES.get(str(arch), str(arch))}" if arch else os_name


_PREDICATE: Final[Mapping[str, str]] = {
    "equals": "{setting} is set to {value} in {product}",
    "not_equals": "{setting} is not set to {value} in {product}",
    "present": "{setting} is set in {product}",
    "absent": "{setting} is not set in {product}",
}
_FRESH_INSTALL: Final[Mapping[str, str]] = {
    "exploitable": " (as it is on a fresh install)",
    "not_exploitable": " (it is not, on a fresh install)",
}


def _setting(term: Mapping[str, Any]) -> str:
    sentence = _PREDICATE[str(term["predicate"])].format(
        setting=term["setting"], value=term.get("value", ""), product=term["product"]
    )
    return sentence + _FRESH_INSTALL.get(str(term["default_state"]), "")


# ---------------------------------------------------------------------------
# What to do, in order, and how to know you are done
# ---------------------------------------------------------------------------
def _category(action: StixObject) -> str | None:
    category = _intel(action).get("category")
    return category if isinstance(category, str) else None


def _steps(
    actions: Sequence[StixObject], now: dt.datetime, new_ids: frozenset[str]
) -> tuple[Step, ...]:
    ordered = sorted(
        (obj for obj in actions if _category(obj) in _STEP_ORDER),
        key=lambda obj: (_STEP_ORDER[_category(obj) or ""], str(obj.get("name", ""))),
    )
    return tuple(_step(obj, now, new_ids) for obj in ordered)


def _step(action: StixObject, now: dt.datetime, new_ids: frozenset[str]) -> Step:
    intel = _intel(action)
    return Step(
        title=_text(action.get("name")) or _STEP_KIND.get(_category(action) or "", "Step"),
        detail=_text(action.get("description")),
        kind=_STEP_KIND.get(_category(action) or "", "Step"),
        restart=_RESTART.get(str(intel.get("restart_required"))),
        provenance=provenance(action),
        is_new=action.get("id") in new_ids,
        review_overdue=is_due_for_review(action, now),
    )


def _no_fix(actions: Sequence[StixObject], now: dt.datetime) -> str | None:
    """What the reader is told when no step is shared: the statement that there is no fix.

    A statement past its ``review_by`` is told as stale, the way readiness
    reports it (``LAPSED``): repeating "no fix" as current would be a claim
    nobody has re-checked.
    """
    if any(_category(obj) in {"vendor_fix", "mitigation", "workaround"} for obj in actions):
        return None
    statements = [obj for obj in actions if _category(obj) in _NO_FIX]
    current = [obj for obj in statements if not is_due_for_review(obj, now)]
    if current:
        return _NO_FIX[_category(current[0]) or ""]
    if statements:
        return _STALE_NO_FIX
    return None


def _done_when(actions: Sequence[StixObject]) -> tuple[str, ...]:
    """Each validation action, then each step's own check, in step order."""
    checks = [
        _text(obj.get("description")) or _text(obj.get("name")) or ""
        for obj in actions
        if _category(obj) == "validation"
    ]
    for obj in sorted(actions, key=lambda o: _STEP_ORDER.get(_category(o) or "", 99)):
        checks.extend(_check_words(_intel(obj).get("validation_check")))
    return tuple(check for check in checks if check)


def _check_words(check: Any) -> list[str]:
    if not isinstance(check, Mapping):
        return []
    expected = _text(check.get("expected_result"))
    command = _text(check.get("query_or_command"))
    tool = _text(check.get("tool"))
    if expected and command:
        using = f" using {tool}" if tool else ""
        return [f"Running “{command}”{using} shows: {expected}"]
    return [expected] if expected else []


def _watch_for(indicator: StixObject, new_ids: frozenset[str]) -> WatchFor:
    return WatchFor(
        title=_text(indicator.get("name")) or "Signs of this being exploited",
        detail=_text(indicator.get("description")),
        valid_until=str(indicator.get("valid_until", ""))[:10],
        provenance=provenance(indicator),
        is_new=indicator.get("id") in new_ids,
    )


def provenance(obj: StixObject) -> str:
    """Who stands behind an object, in a sentence (SF-29: provenance inline).

    The reviewer fields are server-written at validation and never taken from
    a submitter, so "reviewed by the ISAC" is the server's claim. What produced
    the object is the submitter's own statement and is labelled as theirs.
    """
    extensions = obj.get("extensions") or {}
    body = extensions.get(AIVS_PROVENANCE_EXTENSION_ID)
    body = body if isinstance(body, Mapping) else {}
    reviewed_at = _text(body.get("reviewed_at"))
    reviewed = (
        f"Reviewed by the ISAC on {reviewed_at[:10]}."
        if reviewed_at
        else "Not reviewed by the ISAC; shared by a member."
    )
    generated_by = _text(body.get("generated_by"))
    return (
        f"{reviewed} The sender says it was produced by {generated_by}."
        if generated_by
        else reviewed
    )


# ---------------------------------------------------------------------------
# The ISAC's position on the public record
# ---------------------------------------------------------------------------
def _assessment(intel: Mapping[str, Any]) -> Assessment | None:
    statement = _ASSESSMENT.get(str(intel.get("isac_assessment")))
    if statement is None:
        return None
    delta = intel.get("isac_assessment_delta")
    lines = (
        tuple(_delta_line(entry) for entry in delta if isinstance(entry, Mapping))
        if isinstance(delta, list)
        else ()
    )
    return Assessment(statement=statement, differences=lines)


def _delta_line(entry: Mapping[str, Any]) -> DeltaLine:
    prop = str(entry.get("property", ""))
    public_value = entry.get("public_value")
    source = _text(entry.get("public_source"))
    public_says = "nothing" if public_value is None else str(public_value)
    return DeltaLine(
        what=_DELTA_PROPERTY.get(prop, prop.replace("_", " ").capitalize()),
        public_says=f"{public_says} ({source.upper() if source == 'nvd' else source})"
        if source
        else public_says,
        isac_says=str(entry.get("isac_value")),
    )


def _timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)
