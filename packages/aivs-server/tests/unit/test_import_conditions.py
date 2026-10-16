"""The condition import: what it builds from CVE and OSV records, and that the server takes it.

The fixtures in ``conditions_import/`` are written to the published formats: the
CVE record to CVE JSON 5.2.0 (CVEProject/cve-schema, the ``product`` object's
``packageURL``, ``collectionURL``/``packageName``, ``programRoutines``,
``programFiles``, ``modules`` and ``platforms``), and the OSV records to OSV 1.9.1
(``osv/schema-1.9.1.json``, which they are validated against below), with
``ecosystem_specific`` as the Go vulnerability database documents its
``imports`` and as RustSec's ``OsvEcosystemSpecificAffected`` serialises
``affects``.

The rule every table below tests: **never drop an alternative**. A condition is
built only when every affected entry states it and every alternative maps; one
that does not leaves the whole condition out (SF-95).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import copy
import dataclasses
import datetime as dt
import importlib.util
import json
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import jsonschema
import pytest
from sqlalchemy import select

from aivs_schemas.enums import SubmissionSource, SubmissionState
from aivs_schemas.extension.builders import AIVS_INTEL_EXTENSION_ID, CONDITION_IMPORT_REFERENCE
from aivs_server.db.models import StixObject, Submission
from tests.conftest import proxy_headers
from tests.unit.contribution_world import distribute, seed
from tests.unit.test_enrich_kev import CVE, _ToTheApp, isac_record, validated

FIXTURES = Path(__file__).parent / "conditions_import"
OSV_SCHEMA = json.loads((Path(__file__).parent / "osv" / "schema-1.9.1.json").read_text())
NOW = dt.datetime(2026, 10, 15, 12, 0, tzinfo=dt.UTC)

pytestmark = pytest.mark.requirement("SF-95")


@pytest.fixture(scope="module")
def script(repo_root) -> ModuleType:
    path = repo_root / "scripts" / "import-conditions.py"
    spec = importlib.util.spec_from_file_location("import_conditions", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before it runs: a dataclass looks its module up by name.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def kinds(said) -> dict[str, list[dict[str, Any]]]:
    return {c["kind"]: c["any_of"] for c in said.conditions}


def fn(package: str, symbol: str, ecosystem: str = "Go") -> dict[str, str]:
    return {"ecosystem": ecosystem, "package": package, "symbol": symbol}


# ---------------------------------------------------------------------------
# The fixtures are what they claim to be
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["GO-2026-0001.json", "RUSTSEC-2026-0001.json"])
def test_the_osv_fixtures_are_valid_osv(name):
    jsonschema.Draft202012Validator(OSV_SCHEMA).validate(fixture(name))


# ---------------------------------------------------------------------------
# CVE 5.x
# ---------------------------------------------------------------------------
def test_a_cve_record_gives_every_condition_its_entries_all_state(script):
    """The CNA's entry and the ADP's: functions from a package URL and from a known
    collection, files, modules, and the operating systems with the architecture set aside."""
    said = script.from_cve(fixture("CVE-2026-31337.json"))

    assert kinds(said) == {
        "function": [
            fn("pkg:golang/example.com/xml", "ParseStrict"),
            fn("pkg:golang/example.com/xml", "Decoder.Token"),
            fn("pkg:golang/example.com/xml/v2", "ParseStrict"),
        ],
        "file": [{"path": "parse.go"}, {"path": "v2/parse.go"}],
        "module": [{"path": "example.com/xml"}, {"path": "example.com/xml/v2"}],
        "platform": [{"os": "linux"}, {"os": "darwin"}],
    }
    assert said.unknowns == ()


@pytest.mark.parametrize(
    ("field", "kind"),
    [
        ("programRoutines", "function"),
        ("programFiles", "file"),
        ("modules", "module"),
        ("platforms", "platform"),
    ],
)
def test_one_entry_that_does_not_state_a_condition_leaves_it_out(script, field, kind):
    """The ADP's product says nothing of it, so it may be affected through anything:
    a condition naming only the CNA's would tell its users they are not."""
    record = fixture("CVE-2026-31337.json")
    del record["containers"]["adp"][0]["affected"][0][field]

    said = script.from_cve(record)

    assert kind not in kinds(said)
    assert script.LEFT_OUT[kind] in said.unknowns


@pytest.mark.parametrize(
    ("field", "value", "kind"),
    [
        ("platforms", ["Linux", "HP-UX"], "platform"),
        ("programRoutines", [{"name": "ParseStrict"}, {"name": "parses the doc type"}], "function"),
        ("packageURL", "https://example.com/not-a-purl", "function"),
    ],
    ids=["an-unknown-os", "a-routine-that-is-prose", "no-package"],
)
def test_an_alternative_that_does_not_map_leaves_its_whole_condition_out(
    script, field, value, kind
):
    """Never narrowed to the alternatives that did map: HP-UX's users are not told
    they are safe because Linux was the one we could read."""
    record = fixture("CVE-2026-31337.json")
    record["containers"]["cna"]["affected"][0][field] = value

    said = script.from_cve(record)

    assert kind not in kinds(said)
    assert script.LEFT_OUT[kind] in said.unknowns


def test_a_condition_with_more_alternatives_than_a_note_carries_is_left_out(script):
    record = fixture("CVE-2026-31337.json")
    record["containers"]["cna"]["affected"][0]["programRoutines"] = [
        {"name": f"Parse{n}"} for n in range(script.MAX_ALTERNATIVES + 1)
    ]

    assert "function" not in kinds(script.from_cve(record))


def test_an_unknown_collection_gives_no_package(script):
    entry = {"collectionURL": "https://registry.example", "packageName": "xml"}
    assert script.entry_package(entry) is None


def test_a_record_with_no_affected_entries_states_no_condition(script):
    record = fixture("CVE-2026-31337.json")
    record["containers"] = {"cna": {"affected": []}}

    assert script.from_cve(record).conditions == ()


def test_configuration_prose_reaches_the_editor_and_not_the_note(script):
    """Prose is never a term: the editor reads it in the submission's summary,
    which members never see, and structures it by hand."""
    upstream = script.cve_upstream(CVE, fixture("CVE-2026-31337.json"))

    note = script.note_for("vulnerability--1", upstream, now=NOW, previous=None)

    prose = "AllowExternalEntities is set to true"
    assert prose in script.submission_summary(upstream)
    assert prose not in json.dumps(note)


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------
def test_a_go_record_gives_each_imports_symbols_and_platforms(script):
    said = script.from_osv(fixture("GO-2026-0001.json"))

    assert kinds(said) == {
        "function": [
            fn("pkg:golang/example.com/xml", "ParseStrict"),
            fn("pkg:golang/example.com/xml", "Decoder.Token"),
            fn("pkg:golang/example.com/xml/internal/dtd", "Resolve"),
        ],
        "platform": [{"os": "linux"}, {"os": "darwin"}],
    }


@pytest.mark.parametrize("field", ["symbols", "goos"])
def test_a_go_import_that_names_none_leaves_the_condition_out(script, field):
    """No symbols: the whole package is affected. No goos: every system is."""
    record = fixture("GO-2026-0001.json")
    del record["affected"][0]["ecosystem_specific"]["imports"][1][field]

    said = script.from_osv(record)

    kind = "function" if field == "symbols" else "platform"
    assert kind not in kinds(said)


def test_a_rustsec_record_gives_its_functions_and_each_platform_pair(script):
    said = script.from_osv(fixture("RUSTSEC-2026-0001.json"))

    assert kinds(said) == {
        "function": [fn("pkg:cargo/xml-strict", "xml_strict::parse", "crates.io")],
        "platform": [{"os": "darwin", "arch": "amd64"}, {"os": "linux", "arch": "amd64"}],
    }


def test_an_osv_entry_of_another_shape_leaves_every_condition_out(script):
    """A GHSA-shaped entry beside a Go one: what it affects is not stated in a form
    read here, so neither condition may stand on the Go entry alone."""
    record = fixture("GO-2026-0001.json")
    record["affected"].append({"package": {"ecosystem": "npm", "name": "xml"}})

    assert script.from_osv(record).conditions == ()


def test_an_osv_record_is_about_a_cve_by_its_aliases(script):
    assert script.osv_names(fixture("GO-2026-0001.json"), CVE)
    assert not script.osv_names(fixture("GO-2026-0001.json"), "CVE-2026-00001")


# ---------------------------------------------------------------------------
# The note
# ---------------------------------------------------------------------------
def test_the_note_names_the_import_and_the_record_and_states_no_upstream_prose(script):
    upstream = script.osv_upstream(fixture("GO-2026-0001.json"))

    note = script.note_for("vulnerability--1", upstream, now=NOW, previous=None)

    assert note["object_refs"] == ["vulnerability--1"]
    assert note["external_references"][0] == {
        "source_name": CONDITION_IMPORT_REFERENCE,
        "external_id": "osv:GO-2026-0001",
    }
    assert note["external_references"][1]["url"] == "https://osv.dev/vulnerability/GO-2026-0001"
    assert note["modified"] == note["created"]


def test_nothing_is_filed_when_the_record_states_nothing_that_can_be_carried(script):
    record = fixture("GO-2026-0001.json")
    record["affected"] = [{"package": {"ecosystem": "npm", "name": "xml"}}]

    upstream = script.osv_upstream(record)

    assert script.note_for("vulnerability--1", upstream, now=NOW, previous=None) is None


def test_an_unchanged_record_files_nothing_and_a_changed_one_versions_the_note(script):
    upstream = script.osv_upstream(fixture("GO-2026-0001.json"))
    first = script.note_for("vulnerability--1", upstream, now=NOW, previous=None)
    later = NOW + dt.timedelta(days=1)

    assert script.note_for("vulnerability--1", upstream, now=later, previous=first) is None
    changed = copy.deepcopy(fixture("GO-2026-0001.json"))
    changed["affected"][0]["ecosystem_specific"]["imports"].pop()
    version = script.note_for(
        "vulnerability--1", script.osv_upstream(changed), now=later, previous=first
    )
    assert (version["id"], version["created"]) == (first["id"], first["created"])
    assert version["modified"] > first["modified"]


def test_the_summary_counts_each_outcome(script):
    lines = script.summary({script.FILED: 1, script.HELD_BACK: 2, script.REFUSED: 0})
    assert lines[0] == "3 upstream records read"
    assert f"  2 {script.HELD_BACK}" in lines
    assert not any("refused" in line for line in lines)


# ---------------------------------------------------------------------------
# run(), end to end against the API
# ---------------------------------------------------------------------------
@pytest.fixture
def automation_pem_for(make_org, make_cert):
    from aivs_schemas.enums import OrgType  # noqa: PLC0415 - one fixture's import

    async def _make() -> str:
        automation = await make_org("isac-automation", org_type=OrgType.AUTOMATION)
        pem, _ = await make_cert(automation)
        return pem

    return _make


def _runner(script, client, pem, monkeypatch):
    transport = _ToTheApp(client, asyncio.get_running_loop(), proxy_headers(pem))

    @contextlib.contextmanager
    def _client(_config: object) -> Iterator[httpx.Client]:
        with httpx.Client(transport=transport, base_url="https://aivs.test") as http:
            yield http

    monkeypatch.setattr(script, "load_config", lambda **_kwargs: None)
    monkeypatch.setattr(script, "build_http_client", _client)

    async def _run(cve_dir: Path | None, osv_dir: Path | None) -> int:
        args = argparse.Namespace(
            cve_dir=str(cve_dir) if cve_dir else None,
            osv_dir=str(osv_dir) if osv_dir else None,
            dry_run=False,
            url=None,
            cert=None,
            key=None,
            ca=None,
        )
        return await asyncio.to_thread(script.run, args)

    return _run


@dataclasses.dataclass(frozen=True)
class Filed:
    """One imported note's version, as plain values: nothing to load later."""

    stix_id: str
    raw: dict[str, Any]
    submission_id: str
    state: SubmissionState
    source: SubmissionSource


async def _imported(session) -> list[Filed]:
    # Columns, not entities: read fresh every time, and nothing expired to reload.
    rows = await session.execute(
        select(
            StixObject.stix_id, StixObject.raw, Submission.id, Submission.state, Submission.source
        )
        .join(Submission, Submission.id == StixObject.submission_id)
        .where(StixObject.type == "note")
        .order_by(StixObject.modified)
    )
    return [
        Filed(stix_id, dict(raw), str(submission_id), state, source)
        for stix_id, raw, submission_id, state, source in rows
    ]


async def _send_validate_distribute(client, editor, circle, filed: Filed):
    path = f"/api/v1/submissions/{filed.submission_id}"
    sent = await client.post(f"{path}/submit", json={}, headers=editor)
    assert sent.status_code == 200, sent.text
    checked = await client.post(
        f"{path}/validate", json={"acknowledge": [f"{filed.stix_id}:conditions"]}, headers=editor
    )
    assert checked.status_code == 200, checked.text
    shared = await distribute(client, filed.submission_id, editor, circle)
    assert shared.status_code == 200, shared.text


@pytest.mark.db
async def test_run_files_one_note_an_editor_validates_and_never_files_it_twice(
    client,
    session,
    script,
    isac,
    isac_org,
    make_circle,
    automation_pem_for,
    monkeypatch,
    tmp_path,
    capsys,
):
    """Filed as the automation's draft, held back while it waits, validated by an
    editor who names the conditions, then left alone until the record changes."""
    circle = await make_circle("conditions")
    record = validated(isac_record(isac_org.stix_identity_id))
    await seed(session, isac_org, record, circle=circle)
    _org, editor = isac
    run = _runner(script, client, await automation_pem_for(), monkeypatch)
    osv_dir = tmp_path / "osv"
    osv_dir.mkdir()
    (osv_dir / "GO-2026-0001.json").write_text(json.dumps(fixture("GO-2026-0001.json")))

    assert await run(None, osv_dir) == 0
    [note] = await _imported(session)
    assert note.state is SubmissionState.DRAFT
    assert note.source is SubmissionSource.SYSTEM
    assert note.raw["object_refs"] == [record["id"]]
    assert note.raw["extensions"][AIVS_INTEL_EXTENSION_ID]["conditions"]

    capsys.readouterr()
    assert await run(None, osv_dir) == 0
    assert f"  1 {script.HELD_BACK}" in capsys.readouterr().out
    assert len(await _imported(session)) == 1, "the waiting draft is not filed again"

    await _send_validate_distribute(client, editor, circle, note)
    assert await run(None, osv_dir) == 0
    assert f"  1 {script.UNCHANGED}" in capsys.readouterr().out

    changed = fixture("GO-2026-0001.json")
    changed["affected"][0]["ecosystem_specific"]["imports"].pop()
    (osv_dir / "GO-2026-0001.json").write_text(json.dumps(changed))
    assert await run(None, osv_dir) == 0
    versions = await _imported(session)
    assert [v.stix_id for v in versions] == [note.stix_id, note.stix_id]
    assert versions[1].state is SubmissionState.DRAFT


@pytest.mark.db
async def test_run_leaves_a_note_an_editor_corrected(
    client,
    session,
    script,
    isac,
    isac_org,
    make_circle,
    automation_pem_for,
    monkeypatch,
    tmp_path,
    capsys,
):
    circle = await make_circle("conditions")
    record = validated(isac_record(isac_org.stix_identity_id))
    await seed(session, isac_org, record, circle=circle)
    _org, editor = isac
    run = _runner(script, client, await automation_pem_for(), monkeypatch)
    cve_dir = tmp_path / "cves"
    cve_dir.mkdir()
    (cve_dir / f"{CVE}.json").write_text(json.dumps(fixture("CVE-2026-31337.json")))
    assert await run(cve_dir, None) == 0
    [note] = await _imported(session)
    await _send_validate_distribute(client, editor, circle, note)
    # As an editor re-files it: without what the server stamps (review, TLP, attribution).
    stamped = {"object_marking_refs", "created_by_ref"}
    corrected = {k: v for k, v in note.raw.items() if k not in stamped}
    later = dt.datetime.fromisoformat(note.raw["modified"]) + dt.timedelta(hours=1)
    corrected.update(modified=script.format_stix_timestamp(later), content="Checked.")
    corrected["extensions"] = {
        AIVS_INTEL_EXTENSION_ID: corrected["extensions"][AIVS_INTEL_EXTENSION_ID]
    }
    filed = await client.post(
        "/api/v1/submissions",
        json={
            "title": "Correction",
            "discovery_scope": "ai_system",
            "tlp": "amber",
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [corrected]},
        },
        headers=editor,
    )
    assert filed.status_code == 201, filed.text
    [*_, correction] = await _imported(session)
    await _send_validate_distribute(client, editor, circle, correction)

    changed = fixture("CVE-2026-31337.json")
    del changed["containers"]["adp"]
    (cve_dir / f"{CVE}.json").write_text(json.dumps(changed))
    capsys.readouterr()
    assert await run(cve_dir, None) == 0

    assert f"  1 {script.CORRECTED}" in capsys.readouterr().out
    assert len(await _imported(session)) == 2, "nothing filed over the editor's version"
