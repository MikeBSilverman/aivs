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
from aivs_server.services.guidance import (
    Guidance,
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
    guidance = guide(vuln, related, now=NOW)

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
    assert guide(vuln, related, now=NOW) == guide(vuln, list(reversed(related)), now=NOW)


def test_a_revoked_action_is_not_a_step():
    vuln, _ = everything()
    revoked = action("vendor_fix", "Upgrade to 4.2.1") | {"revoked": True}
    live = action("mitigation", "Restrict the console")
    assert [s.title for s in guide(vuln, [revoked, live], now=NOW).steps] == [
        "Restrict the console"
    ]


def test_a_statement_that_there_is_no_fix_is_shown_only_when_nothing_can_be_done():
    vuln, _ = everything()
    no_fix = action("no_fix_planned", "No fix planned")
    assert guide(vuln, [no_fix], now=NOW).no_fix == "The vendor does not plan to fix this."
    workaround = action("workaround", "Block /admin")
    assert guide(vuln, [no_fix, workaround], now=NOW).no_fix is None


# ---------------------------------------------------------------------------
# Freshness (SF-46; review_by)
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-46")
def test_an_expired_sign_is_not_shown_and_a_current_one_is():
    vuln, related = everything()
    shown = [sign.title for sign in guide(vuln, related, now=NOW).watch_for]
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
    flags = {s.title: s.review_overdue for s in guide(vuln, [stale, fresh], now=NOW).steps}
    assert flags == {"Fresh": False, "Stale": True}


# ---------------------------------------------------------------------------
# New since you last read; the ISAC's assessment; provenance
# ---------------------------------------------------------------------------
def test_only_steps_the_reader_has_not_seen_are_marked_new():
    vuln, _ = everything()
    seen = action("vendor_fix", "Upgrade")
    unseen = action("mitigation", "Restrict")
    steps = guide(vuln, [seen, unseen], now=NOW, new_ids=frozenset({unseen["id"]})).steps
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
    assessment = guide(vuln, [], now=NOW).assessment
    assert assessment is not None
    assert assessment.statement == "The ISAC's analysis disagrees with the public record."
    (line,) = assessment.differences
    assert (line.what, line.public_says, line.isac_says) == (
        "Severity score (CVSS 4)",
        "5.3 (NVD)",
        "9.3",
    )


def test_no_assessment_means_none_is_shown():
    assert guide(vulnerability(), [], now=NOW).assessment is None


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
    html = render(guide(vuln, related, now=NOW, new_ids=frozenset(o["id"] for o in related)))
    assert "Upgrade to 4.2.1" in html  # the page rendered its content
    assert STIX_JARGON.findall(html) == []
    assert STIX_ID.findall(html) == []


@pytest.mark.requirement("NFR-U5")
def test_the_jargon_check_would_see_a_type_name_if_one_were_rendered():
    vuln = vulnerability()
    vuln["name"] = "See the course-of-action for indicator--0b5c2a1e-0000-4000-8000-000000000000"
    html = render(guide(vuln, [], now=NOW))
    assert STIX_JARGON.findall(html)
    assert STIX_ID.findall(html)


@pytest.mark.requirement("SF-29")
def test_member_text_is_escaped_on_the_guided_page():
    hostile = action(
        "vendor_fix", '<script>alert("x")</script>', description="<img src=x onerror=1>"
    )
    html = render(guide(vulnerability(), [hostile], now=NOW))
    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html
