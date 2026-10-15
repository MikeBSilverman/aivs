"""Every audit action, and every detection rule, is classified for the ISAC's auditor (SF-94).

The auditor's stream serves a content row without who did it, and a finding
without the filer it names. Both decisions are tables; an action or a rule
added without a decision would be served by whatever the default happens to
be, so these hold each table equal to what it classifies.
"""

from __future__ import annotations

import pytest

from aivs_server.audit.log import AuditAction
from aivs_server.services.audit_stream import _PROJECTIONS
from aivs_server.services.detections import ATTRIBUTION_RULES, RULE_NAMES, detection_rules
from tests.conftest import TEST_ATTRIBUTION_KEY

pytestmark = pytest.mark.requirement("SF-94")


def _every_action() -> set[str]:
    return {value for name, value in vars(AuditAction).items() if name.isupper()}


def test_every_audit_action_is_classified_for_the_isacs_auditor():
    assert set(_PROJECTIONS) == _every_action()


def test_every_detection_rule_is_known_to_the_auditors_stream():
    assert {rule.name for rule in detection_rules(TEST_ATTRIBUTION_KEY)} == RULE_NAMES


def test_the_rules_that_name_a_filer_are_detection_rules():
    assert ATTRIBUTION_RULES <= RULE_NAMES
