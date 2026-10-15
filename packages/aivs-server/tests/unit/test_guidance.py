"""Guided depth is a function over the objects alone, in the reader's words.

NFR-U6: every answer the guided view gives comes from the objects it is handed
-- no stored text, no session. NFR-U5: what it renders names no STIX type and
no STIX identifier. SF-29: what it renders is escaped, and says inline who
stands behind each step.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

import pytest

from aivs_schemas.enums import ReadingDepth
from aivs_schemas.extension.builders import AIVS_PROVENANCE_EXTENSION_ID
from aivs_server.portal.shared import TEMPLATES
from aivs_server.services.exploitability import ConditionSource, combine
from aivs_server.services.guidance import (
    Guidance,
    affected_when,
    guide,
    is_current_indicator,
    is_due_for_review,
    provenance,
    resolve_depth,
)
from tests.unit.sharing import indicator, intel, sdo, stamp

NOW = dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.UTC)
TOMORROW = NOW + dt.timedelta(days=1)
YESTERDAY = NOW - dt.timedelta(days=1)

#: STIX's own nouns, which a member's reviewer should never have to read. The
#: plain-English type names (vulnerability, malware, tool, report, note,
#: campaign, incident, location) are the reader's words too and are allowed.
STIX_JARGON = re.compile(
    r"\b(?:attack-pattern|course-of-action|course of action|indicator|relationship|"
    r"identity|intrusion-set|threat-actor|observed-data|sighting|grouping|opinion|"
    r"infrastructure|marking-definition|extension-definition|language-content|"
    r"x_aivs|x-aivs|stix)\b",
    re.IGNORECASE,
)
STIX_ID = re.compile(r"\b[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-")

#: No condition note visible: the view most pages are rendered with.
UNSTATED = combine([])


def action(
    category: str, name: str, *, description: str | None = None, **body: Any
) -> dict[str, Any]:
    described = {} if description is None else {"description": description}
    return sdo(
        "course-of-action", name=name, extensions=intel(category=category, **body), **described
    )


def vulnerability(**body: Any) -> dict[str, Any]:
    return sdo(
        "vulnerability",
        name="Gateway auth bypass",
        description="An unauthenticated request reaches the admin console.",
        extensions=intel(
            cve_id="CVE-2026-1234",
            cvss_v4_base_score=9.3,
            cvss_v4_severity="critical",
            ssvc_decision="Act",
            kev_listed=True,
            kev_date_added="2026-10-01",
            affected_products=[
                {
                    "vendor": "Acme",
                    "product": "Gateway",
                    "version_range": "vers:semver/>=4.0.0|<4.2.1",
                },
                {"cpe": "cpe:2.3:a:acme:edge_proxy:*:*:*:*:*:*:*:*"},
                {"purl": "pkg:pypi/acme-sdk@1.2.0"},
            ],
            **body,
        ),
    )


def everything() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """A vulnerability with one of each kind of related object, out of order."""
    related = [
        action("workaround", "Block /admin at the edge"),
        action(
            "vendor_fix",
            "Upgrade to 4.2.1",
            restart_required="service",
            validation_check={
                "tool": "curl",
                "query_or_command": "curl -I https://gw/admin",
                "expected_result": "401 Unauthorized",
            },
        ),
        action("mitigation", "Restrict the console to the management VLAN"),
        action("validation", "Confirm the version", description="The banner reads 4.2.1."),
        action("rollback", "Reinstall 4.2.0"),
        indicator("Admin console probe", valid_until=TOMORROW),
        indicator("Old scanner address", valid_until=YESTERDAY),
    ]
    return vulnerability(), related


def render(guidance: Guidance) -> str:
    return TEMPLATES.get_template("_guided.html").render(guidance=guidance)


# ---------------------------------------------------------------------------
# The four questions, from the objects alone (NFR-U6)
# ---------------------------------------------------------------------------
@pytest.mark.requirement("NFR-U6")
def test_guided_depth_answers_from_the_objects_alone():
    vuln, related = everything()
    guidance = guide(vuln, related, now=NOW, exploitability=UNSTATED)

    assert guidance.title == "Gateway auth bypass (CVE-2026-1234)"
    assert guidance.severity == "Critical: 9.3 out of 10"
    assert guidance.urgency is not None
    assert guidance.urgency.startswith("Act now")
    assert (
        guidance.exploited
        == "Attackers are known to be exploiting this (listed by CISA since 2026-10-01)."
    )
    assert [p.name for p in guidance.affected] == [
        "Acme Gateway",
        "Acme Edge Proxy",
        "acme-sdk (pypi)",
    ]
    assert guidance.affected[0].versions == "4.0.0 or later, before 4.2.1"
    assert [s.title for s in guidance.steps] == [
        "Upgrade to 4.2.1",
        "Restrict the console to the management VLAN",
        "Block /admin at the edge",
    ]
    assert guidance.steps[0].restart == "Restart the affected service."
    assert guidance.done_when == (
        "The banner reads 4.2.1.",
        "Running “curl -I https://gw/admin” using curl shows: 401 Unauthorized",
    )
    assert [s.title for s in guidance.if_it_goes_wrong] == ["Reinstall 4.2.0"]


@pytest.mark.requirement("NFR-U6")
def test_the_same_objects_give_the_same_guidance():
    vuln, related = everything()
    assert guide(vuln, related, now=NOW, exploitability=UNSTATED) == guide(
        vuln, list(reversed(related)), now=NOW, exploitability=UNSTATED
    )


def test_a_revoked_action_is_not_a_step():
    vuln, _ = everything()
    revoked = action("vendor_fix", "Upgrade to 4.2.1") | {"revoked": True}
    live = action("mitigation", "Restrict the console")
    assert [
        s.title for s in guide(vuln, [revoked, live], now=NOW, exploitability=UNSTATED).steps
    ] == ["Restrict the console"]


def test_a_statement_that_there_is_no_fix_is_shown_only_when_nothing_can_be_done():
    vuln, _ = everything()
    no_fix = action("no_fix_planned", "No fix planned")
    assert (
        guide(vuln, [no_fix], now=NOW, exploitability=UNSTATED).no_fix
        == "The vendor does not plan to fix this."
    )
    workaround = action("workaround", "Block /admin")
    assert guide(vuln, [no_fix, workaround], now=NOW, exploitability=UNSTATED).no_fix is None


@pytest.mark.requirement("SF-8")
def test_a_no_fix_statement_past_its_review_date_is_told_as_stale_not_repeated():
    """The guided view and readiness give one answer: a lapsed "no fix" is
    neither repeated as current nor turned into its opposite."""
    vuln, _ = everything()
    stale = action("none_available", "No fix yet", review_by="2026-09-01")
    told = guide(vuln, [stale], now=NOW, exploitability=UNSTATED).no_fix
    assert told is not None
    assert "No fix is available yet." not in told
    assert "Ask the ISAC" in told
    current = action("no_fix_planned", "No fix planned", review_by="2026-12-01")
    assert (
        guide(vuln, [stale, current], now=NOW, exploitability=UNSTATED).no_fix
        == "The vendor does not plan to fix this."
    )


# ---------------------------------------------------------------------------
# Freshness (SF-46; review_by)
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-46")
def test_an_expired_sign_is_not_shown_and_a_current_one_is():
    vuln, related = everything()
    shown = [
        sign.title for sign in guide(vuln, related, now=NOW, exploitability=UNSTATED).watch_for
    ]
    assert shown == ["Admin console probe"]


@pytest.mark.parametrize(
    ("valid_until", "current"),
    [(stamp(TOMORROW), True), (stamp(NOW), False), (stamp(YESTERDAY), False), (None, False)],
)
def test_an_indicator_is_current_only_while_it_states_an_end_ahead(valid_until, current):
    assert is_current_indicator({"valid_until": valid_until}, NOW) is current


@pytest.mark.parametrize(
    ("review_by", "due"),
    [
        (None, False),
        ("2026-10-14", False),
        ("2026-10-13", True),
        ("2026-12-01", False),
        ("garbled", True),
    ],
)
def test_a_course_of_action_falls_due_the_day_after_its_review_by(review_by, due):
    body = {} if review_by is None else {"review_by": review_by}
    assert is_due_for_review(action("workaround", "Block", **body), NOW) is due


def test_a_step_past_its_review_date_is_flagged_and_one_before_it_is_not():
    vuln, _ = everything()
    stale = action("workaround", "Stale", review_by="2026-09-01")
    fresh = action("mitigation", "Fresh", review_by="2026-12-01")
    flags = {
        s.title: s.review_overdue
        for s in guide(vuln, [stale, fresh], now=NOW, exploitability=UNSTATED).steps
    }
    assert flags == {"Fresh": False, "Stale": True}


# ---------------------------------------------------------------------------
# New since you last read; the ISAC's assessment; provenance
# ---------------------------------------------------------------------------
def test_only_steps_the_reader_has_not_seen_are_marked_new():
    vuln, _ = everything()
    seen = action("vendor_fix", "Upgrade")
    unseen = action("mitigation", "Restrict")
    steps = guide(
        vuln, [seen, unseen], now=NOW, exploitability=UNSTATED, new_ids=frozenset({unseen["id"]})
    ).steps
    assert {s.title: s.is_new for s in steps} == {"Upgrade": False, "Restrict": True}


def test_the_assessment_lists_where_the_isac_differs():
    vuln = vulnerability(
        isac_assessment="contradicts",
        isac_assessment_delta=[
            {
                "property": "cvss_v4_base_score",
                "public_value": 5.3,
                "isac_value": 9.3,
                "public_source": "nvd",
            }
        ],
    )
    assessment = guide(vuln, [], now=NOW, exploitability=UNSTATED).assessment
    assert assessment is not None
    assert assessment.statement == "The ISAC's analysis disagrees with the public record."
    (line,) = assessment.differences
    assert (line.what, line.public_says, line.isac_says) == (
        "Severity score (CVSS 4)",
        "5.3 (NVD)",
        "9.3",
    )


def test_no_assessment_means_none_is_shown():
    assert guide(vulnerability(), [], now=NOW, exploitability=UNSTATED).assessment is None


@pytest.mark.requirement("SF-29")
def test_provenance_says_whether_the_isac_reviewed_it():
    reviewed = action("vendor_fix", "Upgrade") | {
        "extensions": {
            AIVS_PROVENANCE_EXTENSION_ID: {
                "extension_type": "property-extension",
                "reviewed_at": "2026-10-02T09:00:00.000Z",
                "generated_by": "the vendor's PSIRT",
            }
        }
    }
    assert provenance(reviewed) == (
        "Reviewed by the ISAC on 2026-10-02. The sender says it was produced by the vendor's PSIRT."
    )
    assert (
        provenance(action("vendor_fix", "Upgrade"))
        == "Not reviewed by the ISAC; shared by a member."
    )


# ---------------------------------------------------------------------------
# Depth
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("requested", "preference", "expected"),
    [
        ("guided", None, ReadingDepth.GUIDED),
        ("technical", ReadingDepth.GUIDED, ReadingDepth.TECHNICAL),
        (None, ReadingDepth.GUIDED, ReadingDepth.GUIDED),
        (None, None, ReadingDepth.STANDARD),
        ("nonsense", ReadingDepth.TECHNICAL, ReadingDepth.TECHNICAL),
        ("GUIDED", None, ReadingDepth.STANDARD),
    ],
)
def test_the_link_wins_then_the_preference_then_standard(requested, preference, expected):
    assert resolve_depth(requested, preference) is expected


# ---------------------------------------------------------------------------
# What is rendered: no STIX nouns, and escaped
# ---------------------------------------------------------------------------
@pytest.mark.requirement("NFR-U5")
def test_the_guided_page_names_no_stix_type_and_no_stix_id():
    vuln, related = everything()
    vuln["extensions"].update(
        intel(
            cve_id="CVE-2026-1234",
            affected_products=[{"vendor": "Acme", "product": "Gateway"}],
            isac_assessment="adds",
            isac_assessment_delta=[{"property": "kev_listed", "isac_value": True}],
        )
    )
    html = render(
        guide(
            vuln,
            related,
            now=NOW,
            exploitability=UNSTATED,
            new_ids=frozenset(o["id"] for o in related),
        )
    )
    assert "Upgrade to 4.2.1" in html  # the page rendered its content
    assert STIX_JARGON.findall(html) == []
    assert STIX_ID.findall(html) == []


@pytest.mark.requirement("NFR-U5")
def test_the_jargon_check_would_see_a_type_name_if_one_were_rendered():
    vuln = vulnerability()
    vuln["name"] = "See the course-of-action for indicator--0b5c2a1e-0000-4000-8000-000000000000"
    html = render(guide(vuln, [], now=NOW, exploitability=UNSTATED))
    assert STIX_JARGON.findall(html)
    assert STIX_ID.findall(html)


@pytest.mark.requirement("SF-29")
def test_member_text_is_escaped_on_the_guided_page():
    hostile = action(
        "vendor_fix", '<script>alert("x")</script>', description="<img src=x onerror=1>"
    )
    html = render(guide(vulnerability(), [hostile], now=NOW, exploitability=UNSTATED))
    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# What exploitation needs (Phase N): the view, in the reader's words
# ---------------------------------------------------------------------------
CALLS_PARSER = {
    "id": "fn",
    "kind": "function",
    "any_of": [
        {"ecosystem": "Go", "package": "pkg:golang/example.com/xml", "symbol": "ParseStrict"}
    ],
    "how_to_check": {
        "tool": "govulncheck",
        "query_or_command": "govulncheck ./...",
        "expected_result": "no call path to ParseStrict",
    },
}
ENTITIES_ON = {
    "id": "entities",
    "kind": "configuration",
    "any_of": [
        {
            "product": "example xml",
            "setting": "AllowExternalEntities",
            "predicate": "equals",
            "value": "true",
            "default_state": "not_exploitable",
        }
    ],
}
ON_LINUX_OR_ARM_MAC = {
    "id": "os",
    "kind": "platform",
    "any_of": [{"os": "linux"}, {"os": "darwin", "arch": "arm64"}],
}
UNAUTHENTICATED = {"id": "net", "kind": "exposure", "any_of": [{"AV": "N", "PR": "N", "UI": "N"}]}
NOTE_A = "note--0f9c0000-0000-4000-8000-00000000000a"
NOTE_B = "note--0f9c0000-0000-4000-8000-00000000000b"


def stated(note_id: str, *conditions: dict[str, Any], unknowns: tuple[str, ...] = ()):
    return ConditionSource(
        note_id=note_id,
        modified=NOW,
        summary="s",
        conditions=conditions,
        unknowns=unknowns,
        reproduced=None,
    )


@pytest.mark.requirement("SF-84")
def test_with_no_conditions_the_reader_is_told_to_treat_themselves_as_affected():
    told = affected_when(UNSTATED)

    assert "treat yourself as affected" in told.statement
    assert told.conditions == ()


@pytest.mark.requirement("NFR-U6")
def test_agreed_conditions_read_as_sentences_an_engineer_can_act_on():
    view = combine(
        [stated(NOTE_A, CALLS_PARSER, ENTITIES_ON, ON_LINUX_OR_ARM_MAC, UNAUTHENTICATED)]
    )

    told = affected_when(view)

    assert "only if every one of these is true" in told.statement
    assert [c.requirement for c in told.conditions] == [
        "Your software calls ParseStrict from xml (golang).",
        "AllowExternalEntities is set to true in example xml (it is not, on a fresh install).",
        "It runs on Linux or macOS on 64-bit Arm.",
        "An attacker can reach it over the network, without signing in, with nobody's help.",
    ]
    assert told.conditions[0].check == (
        "To find out, use govulncheck: “govulncheck ./...”. "
        "Its source expects: no call path to ParseStrict"
    )
    assert told.conditions[1].check is None


@pytest.mark.requirement("SF-84")
def test_contested_sources_give_the_guided_reader_no_conditions_to_rule_themselves_out_with():
    """Either source's list alone would narrow the other's: the guided reader
    acts on one list, so a disagreement gives them none, and "affected"."""
    view = combine(
        [
            stated(NOTE_A, ENTITIES_ON),
            stated(NOTE_B, ENTITIES_ON, ON_LINUX_OR_ARM_MAC, unknowns=("Windows is untested",)),
        ]
    )

    told = affected_when(view)

    assert "disagree" in told.statement
    assert "treat yourself as affected" in told.statement
    assert told.conditions == ()
    assert told.unknowns == ("Windows is untested",)


@pytest.mark.requirement("NFR-U5")
def test_the_guided_conditions_name_no_stix_type_and_no_note_id():
    vuln, related = everything()
    view = combine([stated(NOTE_A, CALLS_PARSER, ENTITIES_ON, unknowns=("Windows untested",))])

    html = render(guide(vuln, related, now=NOW, exploitability=view))

    assert "Your software calls ParseStrict" in html  # the conditions rendered
    assert "Windows untested" in html
    assert STIX_JARGON.findall(html) == []
    assert STIX_ID.findall(html) == []


@pytest.mark.requirement("SF-29")
def test_condition_text_is_escaped_on_the_guided_page():
    hostile = {
        "id": "cfg",
        "kind": "configuration",
        "any_of": [
            {
                "product": "<img src=x onerror=1>",
                "setting": "<script>x</script>",
                "predicate": "present",
                "default_state": "unknown",
            }
        ],
    }
    view = combine([stated(NOTE_A, hostile)])

    html = render(guide(vulnerability(), [], now=NOW, exploitability=view))

    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;x&lt;/script&gt; is set in &lt;img" in html
