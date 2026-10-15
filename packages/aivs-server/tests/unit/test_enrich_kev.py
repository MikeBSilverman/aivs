"""The KEV enrichment script: what it builds, and that the server takes it.

The script runs outside the server, as the ISAC's automation organisation. Its
pure parts are tested here directly. Its output is then filed through the real
API as that organisation, so the version it builds is proven against the rules
the server applies (ownership, the AI gate, an editor's validation) rather than
against a hand-built expectation of them.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as dt
import importlib.util
import json
import uuid
from collections.abc import Iterator
from types import ModuleType
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import TLP, OrgType, SubmissionSource, SubmissionState
from aivs_schemas.extension.builders import (
    AIVS_EXTENSION_ID,
    AIVS_INTEL_EXTENSION_ID,
    AIVS_PROVENANCE_EXTENSION_ID,
)
from aivs_schemas.tlp import marking_id_for
from aivs_server.db.models import InstanceControl, StixObject, Submission
from aivs_server.services.provenance import reviewer_identity_id, stamp_review
from tests.conftest import proxy_headers
from tests.unit.contribution_world import STAMP, distribute, file, seed, submit_and_validate

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


STATEMENT_MARKING = "marking-definition--0b3e1c6e-7f4a-4a8e-9a39-5d6f2c4b8e11"


def test_a_records_other_markings_are_carried_and_only_its_tlp_is_left_to_the_server(script):
    """The server keeps a statement marking beside the TLP it stamps; so does the script."""
    record = isac_record("identity--isac")
    record["object_marking_refs"] = [marking_id_for(TLP.AMBER), STATEMENT_MARKING]

    version = script.enriched_version(record, script.kev_by_cve(KEV_CATALOGUE), now=NOW)

    assert version["object_marking_refs"] == [STATEMENT_MARKING]


def test_the_previous_versions_review_is_not_carried(script):
    """The server refuses a submission claiming a review; it writes this version's own."""
    record = validated(isac_record("identity--isac"))

    version = script.enriched_version(record, script.kev_by_cve(KEV_CATALOGUE), now=NOW)

    assert AIVS_PROVENANCE_EXTENSION_ID not in version["extensions"]


def validated(record: dict[str, Any]) -> dict[str, Any]:
    """``record`` as an editor's validation leaves it: with the server's review stamped."""
    return stamp_review(record, reviewer=reviewer_identity_id(uuid.uuid4()), now=NOW)


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
    """Built on a record as validation leaves it, review stamped, as every real one is."""
    circle = await make_circle("kev")
    record = validated(isac_record(isac_org.stix_identity_id))
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
    review = await _sent_and_validated(client, filed.json()["id"], editor)

    assert review.status_code == 200, review.text
    submission = await session.get(Submission, uuid.UUID(filed.json()["id"]))
    await session.refresh(submission)
    assert submission.source is SubmissionSource.SYSTEM, "so the AI gate applied"


@pytest.mark.db
@pytest.mark.requirement("SF-48")
async def test_the_kev_version_is_distributed_under_the_isacs_name_not_the_machines(
    client, session, script, isac, isac_org, make_org, make_cert, make_circle
):
    """The ISAC is one owner for versioning, so it is one name on the result: a
    member's TIP must see the ISAC's record updated by the ISAC, not re-attributed
    to a machine identity it has never heard of."""
    circle = await make_circle("kev-name")
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
    submission_id = filed.json()["id"]
    assert (await _sent_and_validated(client, submission_id, editor)).status_code == 200

    distributed = await distribute(client, submission_id, editor, circle)

    assert distributed.status_code == 200, distributed.text
    stored = await session.scalar(
        select(StixObject).where(StixObject.submission_id == uuid.UUID(submission_id))
    )
    await session.refresh(stored)
    assert stored.raw["created_by_ref"] == isac_org.stix_identity_id
    assert stored.raw["created_by_ref"] != automation.stix_identity_id


# ---------------------------------------------------------------------------
# What the script reads: the ISAC's own records, chosen by owner
# ---------------------------------------------------------------------------
RECORDS = "/api/v1/isac-records/vulnerabilities"


@pytest.fixture
async def automation_pem(make_org, make_cert) -> str:
    automation = await make_org("isac-automation", org_type=OrgType.AUTOMATION)
    pem, _ = await make_cert(automation)
    return pem


async def _read_records(client, headers) -> list[dict[str, Any]]:
    response = await client.get(RECORDS, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["objects"]


async def _anonymous_member_record(client, isac, make_org, make_cert, join_circle, circle) -> str:
    """A member's vulnerability, distributed anonymously: its ``created_by_ref`` is the ISAC's."""
    member = await make_org("meridian-global")
    pem, _ = await make_cert(member)
    await join_circle(member, circle)
    _org, editor = isac
    record = isac_record("identity--placeholder")
    del record["created_by_ref"]
    filed = await file(client, pem, [record], scope="ai_system", anonymous=True)
    assert filed.status_code == 201, filed.text
    assert (await submit_and_validate(client, pem, filed.json()["id"], editor)).status_code == 200
    assert (await distribute(client, filed.json()["id"], editor, circle)).status_code == 200
    return str(record["id"])


@pytest.mark.db
async def test_the_automation_reads_the_isacs_records_and_not_a_members_anonymous_one(
    client, session, isac, isac_org, make_org, make_cert, make_circle, join_circle, automation_pem
):
    """Chosen by owner. ``created_by_ref`` would have matched both, and did."""
    circle = await make_circle("kev")
    ours = isac_record(isac_org.stix_identity_id)
    await seed(session, isac_org, ours, circle=circle)
    theirs = await _anonymous_member_record(client, isac, make_org, make_cert, join_circle, circle)
    stored = await session.scalar(select(StixObject).where(StixObject.stix_id == theirs))
    assert stored.raw["created_by_ref"] == isac_org.stix_identity_id, "the trap is real"

    records = await _read_records(client, proxy_headers(automation_pem))

    assert [record["id"] for record in records] == [ours["id"]]


@pytest.mark.db
async def test_only_the_newest_version_is_read(
    client, session, isac_org, make_circle, automation_pem
):
    circle = await make_circle("kev")
    old = isac_record(isac_org.stix_identity_id)
    new = {**old, "modified": "2026-09-01T00:00:00.000Z", "name": "Revised"}
    await seed(session, isac_org, old, circle=circle)
    await seed(session, isac_org, new, circle=circle)

    records = await _read_records(client, proxy_headers(automation_pem))

    assert [(record["id"], record["name"]) for record in records] == [(old["id"], "Revised")]


@pytest.mark.db
async def test_a_record_whose_newest_version_is_embargoed_is_left_out(
    client, session, isac_org, make_circle, automation_pem
):
    """Not answered with the version before: a KEV version built on it would replace the new one."""
    circle = await make_circle("kev")
    released = isac_record(isac_org.stix_identity_id)
    await seed(session, isac_org, released, circle=circle)
    embargoed = await seed(
        session, isac_org, {**released, "modified": "2026-09-01T00:00:00.000Z"}, circle=circle
    )
    await _embargo(session, embargoed)

    assert await _read_records(client, proxy_headers(automation_pem)) == []


async def _file_newer_version(
    client, automation_pem: str, record: dict[str, Any], *, editor: dict[str, str]
) -> str:
    """A newer version of ``record``, filed by the automation and sent for
    review by an editor, whose verb that is on the automation's filing (Q35)."""
    newer = {**record, "modified": "2026-09-01T00:00:00.000Z", "name": "Revised"}
    del newer["extensions"][AIVS_PROVENANCE_EXTENSION_ID]
    filed = await file(client, automation_pem, [newer], scope="ai_system")
    assert filed.status_code == 201, filed.text
    submission_id = str(filed.json()["id"])
    submitted = await client.post(
        f"/api/v1/submissions/{submission_id}/submit", json={}, headers=editor
    )
    assert submitted.status_code == 200, submitted.text
    return submission_id


async def _sent_and_validated(client, submission_id: str, editor: dict[str, str]):
    """An editor sends the automation's draft for review and validates it."""
    submitted = await client.post(
        f"/api/v1/submissions/{submission_id}/submit", json={}, headers=editor
    )
    assert submitted.status_code == 200, submitted.text
    return await client.post(
        f"/api/v1/submissions/{submission_id}/validate", json={}, headers=editor
    )


@pytest.mark.db
async def test_a_record_with_a_newer_version_in_review_is_left_out(
    client, session, isac, isac_org, make_circle, automation_pem
):
    """Same reason as an embargoed one: a KEV version of the older would outrank the newer."""
    circle = await make_circle("kev")
    record = validated(isac_record(isac_org.stix_identity_id))
    await seed(session, isac_org, record, circle=circle)
    _org, editor = isac
    submission_id = await _file_newer_version(client, automation_pem, record, editor=editor)
    headers = proxy_headers(automation_pem)

    assert await _read_records(client, headers) == [], "submitted"
    validate = await client.post(
        f"/api/v1/submissions/{submission_id}/validate", json={}, headers=editor
    )
    assert validate.status_code == 200, validate.text
    assert await _read_records(client, headers) == [], "validated"


@pytest.mark.db
async def test_a_withdrawn_newer_version_does_not_hold_the_record_back(
    client, session, isac, isac_org, make_circle, automation_pem
):
    circle = await make_circle("kev")
    record = validated(isac_record(isac_org.stix_identity_id))
    await seed(session, isac_org, record, circle=circle)
    _org, editor = isac
    submission_id = await _file_newer_version(client, automation_pem, record, editor=editor)
    headers = proxy_headers(automation_pem)

    withdrawn = await client.post(
        f"/api/v1/submissions/{submission_id}/withdraw", json={}, headers=editor
    )

    assert withdrawn.status_code == 200, withdrawn.text
    assert [found["id"] for found in await _read_records(client, headers)] == [record["id"]]


@pytest.mark.db
async def test_a_red_record_is_not_read(client, session, isac_org, make_circle, automation_pem):
    circle = await make_circle("kev")
    await seed(
        session, isac_org, isac_record(isac_org.stix_identity_id), circle=circle, tlp=TLP.RED
    )
    amber = isac_record(isac_org.stix_identity_id)
    await seed(session, isac_org, amber, circle=circle)

    records = await _read_records(client, proxy_headers(automation_pem))

    assert [record["id"] for record in records] == [amber["id"]]


@pytest.mark.db
async def test_nobody_but_the_automation_reads_them(
    client, session, isac, isac_org, make_org, make_cert, make_circle, join_circle
):
    circle = await make_circle("kev")
    await seed(session, isac_org, isac_record(isac_org.stix_identity_id), circle=circle)
    member = await make_org("meridian-global")
    pem, _ = await make_cert(member)
    await join_circle(member, circle)
    isac_pem, _ = await make_cert(isac_org)
    _org, editor = isac

    for headers in (proxy_headers(pem), editor, proxy_headers(isac_pem)):
        assert (await client.get(RECORDS, headers=headers)).status_code == 404


@pytest.mark.db
async def test_nothing_is_read_while_distribution_is_paused(
    client, session, isac_org, make_circle, automation_pem
):
    """The script runs unattended, and a stop button stops it too."""
    circle = await make_circle("kev")
    await seed(session, isac_org, isac_record(isac_org.stix_identity_id), circle=circle)
    control = await session.get(InstanceControl, 1) or InstanceControl(id=1)
    control.distribution_paused = True
    session.add(control)
    await session.commit()

    assert await _read_records(client, proxy_headers(automation_pem)) == []


@pytest.mark.db
async def test_a_withdrawn_record_is_not_read(
    client, session, isac_org, make_circle, automation_pem
):
    circle = await make_circle("kev")
    await seed(
        session,
        isac_org,
        isac_record(isac_org.stix_identity_id),
        circle=circle,
        state=SubmissionState.WITHDRAWN,
    )

    assert await _read_records(client, proxy_headers(automation_pem)) == []


@pytest.mark.db
async def test_a_person_at_the_automation_organisation_reads_nothing(
    client, session, isac_org, make_circle, make_org, make_cert, make_operator, human_headers
):
    """The read is the automation's machine identity, not a door for a session."""
    circle = await make_circle("kev")
    await seed(session, isac_org, isac_record(isac_org.stix_identity_id), circle=circle)
    automation = await make_org("isac-automation", org_type=OrgType.AUTOMATION)
    pem, _ = await make_cert(automation)
    operator, _seed = await make_operator(automation)

    response = await client.get(RECORDS, headers=await human_headers(operator, pem))

    assert response.status_code == 404
    assert (await client.get(RECORDS, headers=proxy_headers(pem))).status_code == 200


async def _embargo(session, submission: Submission) -> None:
    from aivs_server.db.models import Distribution  # noqa: PLC0415 - one test's helper

    rows = await session.execute(
        select(Distribution).where(Distribution.submission_id == submission.id)
    )
    for row in rows.scalars():
        row.date_added = dt.datetime.now(dt.UTC) + dt.timedelta(days=3)
    await session.commit()


# ---------------------------------------------------------------------------
# run(), end to end against the API
# ---------------------------------------------------------------------------
class _ToTheApp(httpx.BaseTransport):
    """Carries the script's synchronous requests to the app, on the test's event loop.

    The script runs in a thread, as it would at a terminal; each request is
    handed to the loop the app and its database connections live on.
    """

    def __init__(self, client: httpx.AsyncClient, loop, headers: dict[str, str]) -> None:
        self._client = client
        self._loop = loop
        self._headers = headers

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        sent = asyncio.run_coroutine_threadsafe(self._send(request), self._loop)
        return sent.result(timeout=60)

    async def _send(self, request: httpx.Request) -> httpx.Response:
        response = await self._client.request(
            request.method,
            request.url.raw_path.decode(),
            content=request.read(),
            headers={**dict(request.headers), **self._headers},
        )
        return httpx.Response(
            response.status_code, headers=response.headers, content=response.content
        )


@pytest.mark.db
@pytest.mark.requirement("SF-48", "SF-6")
async def test_run_files_a_kev_version_of_the_isacs_record_and_of_nothing_else(
    client,
    session,
    script,
    isac,
    isac_org,
    make_org,
    make_cert,
    make_circle,
    join_circle,
    automation_pem,
    monkeypatch,
    tmp_path,
    capsys,
):
    circle = await make_circle("kev")
    ours = validated(isac_record(isac_org.stix_identity_id))
    await seed(session, isac_org, ours, circle=circle)
    theirs = await _anonymous_member_record(client, isac, make_org, make_cert, join_circle, circle)
    transport = _ToTheApp(client, asyncio.get_running_loop(), proxy_headers(automation_pem))

    @contextlib.contextmanager
    def _client(_config: object) -> Iterator[httpx.Client]:
        with httpx.Client(transport=transport, base_url="https://aivs.test") as http:
            yield http

    monkeypatch.setattr(script, "load_config", lambda **_kwargs: None)
    monkeypatch.setattr(script, "build_http_client", _client)
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(json.dumps(KEV_CATALOGUE), encoding="utf-8")
    args = argparse.Namespace(
        kev_file=str(kev_file), dry_run=False, url=None, cert=None, key=None, ca=None
    )

    assert await asyncio.to_thread(script.run, args) == 0

    filed = (
        (
            await session.execute(
                select(StixObject)
                .join(Submission, Submission.id == StixObject.submission_id)
                .where(Submission.state == SubmissionState.DRAFT)
            )
        )
        .scalars()
        .all()
    )
    assert [obj.stix_id for obj in filed] == [ours["id"]], "a draft, waiting for an editor"
    assert filed[0].raw["extensions"][AIVS_INTEL_EXTENSION_ID]["kev_listed"] is True
    assert theirs not in {obj.stix_id for obj in filed}

    # Its own waiting draft holds the record back, so a second run files
    # nothing twice (Q35: the script no longer sends what it files), and says
    # so: the record's KEV updates stall until an editor sends the draft.
    capsys.readouterr()
    assert await asyncio.to_thread(script.run, args) == 0
    assert f"  1 {script.WAITING}" in capsys.readouterr().out
    response = await client.get(RECORDS, headers=proxy_headers(automation_pem))
    assert response.json()["waiting_drafts"] == 1
    drafts = await session.scalar(
        select(func.count())
        .select_from(Submission)
        .where(Submission.state == SubmissionState.DRAFT)
    )
    assert drafts == 1


# ---------------------------------------------------------------------------
# What the run says it did
# ---------------------------------------------------------------------------
def test_the_summary_counts_each_outcome_and_says_why_records_were_skipped(script):
    lines = script.summary({script.FILED: 2, script.SKIPPED_1_0: 3, script.REFUSED: 0})
    assert lines[0] == "5 records read"
    assert "  2 filed as a draft, waiting for an ISAC editor to send it" in lines
    assert any(line.startswith("  3 skipped: still on extension 1.0") for line in lines)
    assert not any("refused" in line for line in lines), "an outcome nobody had is not listed"


@pytest.mark.db
async def test_run_reports_how_many_records_it_skipped_on_the_1_0_extension(
    client, session, script, isac_org, make_circle, automation_pem, monkeypatch, tmp_path, capsys
):
    circle = await make_circle("kev-1-0")
    old = validated(isac_record(isac_org.stix_identity_id))
    old["extensions"] = {
        AIVS_EXTENSION_ID: old["extensions"].pop(AIVS_INTEL_EXTENSION_ID),
        **old["extensions"],
    }
    await seed(session, isac_org, old, circle=circle)
    current = validated(isac_record(isac_org.stix_identity_id))
    await seed(session, isac_org, current, circle=circle)
    transport = _ToTheApp(client, asyncio.get_running_loop(), proxy_headers(automation_pem))

    @contextlib.contextmanager
    def _client(_config: object) -> Iterator[httpx.Client]:
        with httpx.Client(transport=transport, base_url="https://aivs.test") as http:
            yield http

    monkeypatch.setattr(script, "load_config", lambda **_kwargs: None)
    monkeypatch.setattr(script, "build_http_client", _client)
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(json.dumps(KEV_CATALOGUE), encoding="utf-8")
    args = argparse.Namespace(
        kev_file=str(kev_file), dry_run=True, url=None, cert=None, key=None, ca=None
    )

    assert await asyncio.to_thread(script.run, args) == 0

    out = capsys.readouterr().out
    assert "2 records read" in out
    assert f"  1 {script.SKIPPED_1_0}" in out
    assert f"  1 {script.WOULD_FILE}" in out
