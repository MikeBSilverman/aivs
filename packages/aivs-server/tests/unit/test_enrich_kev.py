"""The KEV enrichment script: what it builds, and that the server takes it.

The script runs outside the server, as the ISAC's automation organisation. Its
pure parts are tested here directly. Its output is then filed through the real
API as that organisation, so the version it builds is proven against the rules
the server applies (ownership, the AI gate, an editor's validation) rather than
against a hand-built expectation of them.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import uuid
from types import ModuleType
from typing import Any

import pytest

from aivs_schemas.enums import TLP, OrgType, SubmissionSource
from aivs_schemas.extension.builders import AIVS_EXTENSION_ID, AIVS_INTEL_EXTENSION_ID
from aivs_schemas.tlp import marking_id_for
from aivs_server.db.models import Submission
from tests.unit.contribution_world import STAMP, file, seed, submit_and_validate

CVE = "CVE-2026-31337"
NOW = dt.datetime(2026, 10, 13, 12, 0, tzinfo=dt.UTC)
KEV_CATALOGUE = {
    "vulnerabilities": [
        {
            "cveID": CVE,
            "dateAdded": "2026-10-01",
            "dueDate": "2026-10-22",
            "knownRansomwareCampaignUse": "Known",
        },
        {"cveID": "CVE-2026-00001", "dateAdded": "2026-09-01", "dueDate": "2026-09-22"},
    ]
}


@pytest.fixture(scope="module")
def script(repo_root) -> ModuleType:
    path = repo_root / "scripts" / "enrich-kev.py"
    spec = importlib.util.spec_from_file_location("enrich_kev", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def isac_record(identity: str, **extension: Any) -> dict[str, Any]:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "name": "Agent gateway prompt injection",
        "created_by_ref": identity,
        "object_marking_refs": [marking_id_for(TLP.AMBER)],
        "extensions": {
            AIVS_INTEL_EXTENSION_ID: {
                "extension_type": "property-extension",
                "aivs_schema_version": "2.0",
                "discovery_scope": "ai_system",
                "cve_status": "published",
                "cve_id": CVE,
                "affected_products": [{"vendor": "Acme", "product": "Gateway"}],
                **extension,
            }
        },
    }


# ---------------------------------------------------------------------------
# What the script builds
# ---------------------------------------------------------------------------
def test_a_listed_record_gets_a_newer_version_saying_what_kev_says(script):
    record = isac_record("identity--isac")

    version = script.enriched_version(record, script.kev_by_cve(KEV_CATALOGUE), now=NOW)

    body = version["extensions"][AIVS_INTEL_EXTENSION_ID]
    assert version["id"] == record["id"]
    assert version["modified"] > record["modified"]
    assert body["kev_listed"] is True
    assert body["kev_date_added"] == "2026-10-01"
    assert body["kev_due_date"] == "2026-10-22"
    assert body["kev_ransomware_use"] == "Known"
    assert body["cve_id"] == CVE, "everything else is carried over"
    assert "object_marking_refs" not in version, "the server stamps the marking (SF-49)"


def test_a_record_that_already_says_it_gets_nothing(script):
    kev = script.kev_by_cve(KEV_CATALOGUE)
    current = script.enriched_version(isac_record("identity--isac"), kev, now=NOW)

    assert script.enriched_version(current, kev, now=NOW + dt.timedelta(days=1)) is None


def test_a_record_kev_does_not_list_gets_nothing(script):
    record = isac_record("identity--isac", cve_id="CVE-2026-99999")

    assert script.enriched_version(record, script.kev_by_cve(KEV_CATALOGUE), now=NOW) is None


def test_a_record_on_the_1_0_extension_is_left_alone(script):
    record = isac_record("identity--isac")
    record["extensions"] = {AIVS_EXTENSION_ID: record["extensions"][AIVS_INTEL_EXTENSION_ID]}

    assert script.enriched_version(record, script.kev_by_cve(KEV_CATALOGUE), now=NOW) is None


def test_a_ransomware_value_kev_did_not_define_is_not_carried(script):
    catalogue = {
        "vulnerabilities": [
            {
                "cveID": CVE,
                "dateAdded": "2026-10-01",
                "dueDate": "2026-10-22",
                "knownRansomwareCampaignUse": "Probably",
            }
        ]
    }

    assert "kev_ransomware_use" not in script.kev_by_cve(catalogue)[CVE]


def test_only_the_isacs_newest_version_of_each_record_is_considered(script):
    old = isac_record("identity--isac")
    new = {**old, "modified": "2026-09-01T00:00:00.000Z"}
    members = isac_record("identity--member")

    latest = script.latest_isac_records([old, new, members], "identity--isac")

    assert latest == {old["id"]: new}


def test_the_version_is_filed_at_the_records_tlp(script):
    record = isac_record("identity--isac")
    record["object_marking_refs"] = [marking_id_for(TLP.AMBER_STRICT)]

    assert script.tlp_of(record) is TLP.AMBER_STRICT


# ---------------------------------------------------------------------------
# The server takes it
# ---------------------------------------------------------------------------
@pytest.mark.db
@pytest.mark.requirement("SF-48", "SF-6")
async def test_the_version_the_script_builds_is_validated_by_an_editor(
    client, session, script, isac, isac_org, make_org, make_cert, make_circle, join_circle
):
    circle = await make_circle("kev")
    record = isac_record(isac_org.stix_identity_id)
    await seed(session, isac_org, record, circle=circle)
    automation = await make_org("isac-automation", org_type=OrgType.AUTOMATION)
    pem, _ = await make_cert(automation)
    _org, editor = isac

    version = script.enriched_version(record, script.kev_by_cve(KEV_CATALOGUE), now=NOW)
    filed = await file(
        client,
        pem,
        [version],
        scope=version["extensions"][AIVS_INTEL_EXTENSION_ID]["discovery_scope"],
        tlp=script.tlp_of(record).value,
    )
    assert filed.status_code == 201, filed.text
    validated = await submit_and_validate(client, pem, filed.json()["id"], editor)

    assert validated.status_code == 200, validated.text
    submission = await session.get(Submission, uuid.UUID(filed.json()["id"]))
    await session.refresh(submission)
    assert submission.source is SubmissionSource.SYSTEM, "so the AI gate applied"
