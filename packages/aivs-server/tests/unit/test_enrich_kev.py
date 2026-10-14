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
from sqlalchemy import select

from aivs_schemas.enums import TLP, OrgType, SubmissionSource, SubmissionState
from aivs_schemas.extension.builders import AIVS_EXTENSION_ID, AIVS_INTEL_EXTENSION_ID
from aivs_schemas.tlp import marking_id_for
from aivs_server.db.models import StixObject, Submission
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
):
    circle = await make_circle("kev")
    ours = isac_record(isac_org.stix_identity_id)
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
                .where(Submission.state == SubmissionState.SUBMITTED)
            )
        )
        .scalars()
        .all()
    )
    assert [obj.stix_id for obj in filed] == [ours["id"]]
    assert filed[0].raw["extensions"][AIVS_INTEL_EXTENSION_ID]["kev_listed"] is True
    assert theirs not in {obj.stix_id for obj in filed}
