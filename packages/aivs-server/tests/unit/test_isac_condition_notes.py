"""The condition import's read of its own notes (Phase N intake, SF-95).

The import files one note per vulnerability and upstream record. Before it
files, it must know which of its notes exist: one it may version, or one it
must leave be (in review, a draft waiting, or not readable to it). Anything
else it would file again. The notes are driven through the real API, as the
automation files them and an editor sends, validates and distributes them,
so the read is tested against the rows its writer produces.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy import select

from aivs_schemas.enums import TLP, OrgType
from aivs_schemas.extension.builders import CONDITION_IMPORT_REFERENCE
from aivs_server.db.models import Distribution, InstanceControl
from tests.conftest import proxy_headers
from tests.unit.contribution_world import distribute, file, seed
from tests.unit.test_enrich_kev import isac_record
from tests.unit.test_exploitability import conditions_note

pytestmark = [pytest.mark.db, pytest.mark.requirement("SF-95")]

NOTES = "/api/v1/isac-records/condition-notes"
PARSE = {"ecosystem": "Go", "package": "pkg:golang/example.com/xml", "symbol": "Parse"}


def imported(vulnerability_id: str, *, source: str = "cve.org", **raw: Any) -> dict[str, Any]:
    """A note as the import files it: conditions, and the import's reference."""
    note = conditions_note(
        vulnerability_id, {"id": "fn", "kind": "function", "any_of": [PARSE]}, **raw
    )
    note["external_references"] = [
        {"source_name": CONDITION_IMPORT_REFERENCE, "external_id": source},
    ]
    return note


@pytest.fixture
async def seeded(session, isac, isac_org, make_org, make_cert, make_circle):
    """The ISAC's record the notes are about, and the automation that files them."""
    circle = await make_circle("conditions")
    record = isac_record(isac_org.stix_identity_id)
    await seed(session, isac_org, record, circle=circle)
    automation = await make_org("isac-automation", org_type=OrgType.AUTOMATION)
    pem, _ = await make_cert(automation)
    _org, editor = isac
    return {"circle": circle, "record": record, "pem": pem, "editor": editor}


async def _filed(client, world, note: dict[str, Any], *, pem: str | None = None) -> str:
    filed = await file(client, pem or world["pem"], [note], scope="ai_system")
    assert filed.status_code == 201, filed.text
    return str(filed.json()["id"])


async def _filed_by_the_editor(client, world, note: dict[str, Any]) -> str:
    filed = await client.post(
        "/api/v1/submissions",
        json={
            "title": "Correction",
            "discovery_scope": "ai_system",
            "tlp": "amber",
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [note]},
        },
        headers=world["editor"],
    )
    assert filed.status_code == 201, filed.text
    return str(filed.json()["id"])


async def _sent(client, world, submission_id: str) -> None:
    sent = await client.post(
        f"/api/v1/submissions/{submission_id}/submit", json={}, headers=world["editor"]
    )
    assert sent.status_code == 200, sent.text


async def _validated(client, world, submission_id: str, note: dict[str, Any]) -> None:
    validated = await client.post(
        f"/api/v1/submissions/{submission_id}/validate",
        json={"acknowledge": [f"{note['id']}:conditions"]},
        headers=world["editor"],
    )
    assert validated.status_code == 200, validated.text


async def _distributed(client, world, note: dict[str, Any]) -> str:
    """Filed by the automation, sent, validated and distributed by an editor."""
    submission_id = await _filed(client, world, note)
    await _sent(client, world, submission_id)
    await _validated(client, world, submission_id, note)
    shared = await distribute(client, submission_id, world["editor"], world["circle"])
    assert shared.status_code == 200, shared.text
    return submission_id


async def _read(client, world) -> dict[str, Any]:
    response = await client.get(NOTES, headers=proxy_headers(world["pem"]))
    assert response.status_code == 200, response.text
    return response.json()


def _held(read: dict[str, Any]) -> list[str]:
    return [held["note_id"] for held in read["held_back"]]


# ---------------------------------------------------------------------------
# What is served
# ---------------------------------------------------------------------------
async def test_a_distributed_imported_note_is_served_as_the_machines(client, seeded):
    note = imported(seeded["record"]["id"])
    await _distributed(client, seeded, note)

    read = await _read(client, seeded)

    assert [(n["note"]["id"], n["machine_filed"]) for n in read["notes"]] == [(note["id"], True)]
    assert read["held_back"] == []


async def test_only_the_newest_version_is_served(client, seeded):
    note = imported(seeded["record"]["id"])
    await _distributed(client, seeded, note)
    newer = {
        **imported(seeded["record"]["id"]),
        "id": note["id"],
        "modified": "2026-09-02T00:00:00.000Z",
    }
    await _distributed(client, seeded, newer)

    read = await _read(client, seeded)

    assert [n["note"]["modified"] for n in read["notes"]] == ["2026-09-02T00:00:00.000Z"]


async def test_an_editors_version_is_served_as_not_the_machines(client, seeded):
    """The analyst corrected the import's note; the import must leave it alone."""
    note = imported(seeded["record"]["id"])
    await _distributed(client, seeded, note)
    corrected = {**note, "modified": "2026-09-02T00:00:00.000Z", "content": "Corrected."}
    submission_id = await _filed_by_the_editor(client, seeded, corrected)
    await _sent(client, seeded, submission_id)
    await _validated(client, seeded, submission_id, corrected)
    shared = await distribute(client, submission_id, seeded["editor"], seeded["circle"])
    assert shared.status_code == 200, shared.text

    read = await _read(client, seeded)

    assert [(n["note"]["content"], n["machine_filed"]) for n in read["notes"]] == [
        ("Corrected.", False)
    ]


# ---------------------------------------------------------------------------
# What is held back, and what is in neither list
# ---------------------------------------------------------------------------
async def test_the_automations_waiting_draft_is_held_back(client, seeded):
    """A first note's draft: the read must name it, or the next run files it again."""
    note = imported(seeded["record"]["id"], source="osv")
    await _filed(client, seeded, note)

    read = await _read(client, seeded)

    assert read["notes"] == []
    assert read["held_back"] == [
        {"note_id": note["id"], "about": [seeded["record"]["id"]], "source": "osv"}
    ]


async def test_a_note_in_review_is_held_back(client, seeded):
    note = imported(seeded["record"]["id"])
    await _distributed(client, seeded, note)
    newer = {**note, "modified": "2026-09-02T00:00:00.000Z"}
    submission_id = await _filed(client, seeded, newer)
    await _sent(client, seeded, submission_id)

    read = await _read(client, seeded)

    assert (read["notes"], _held(read)) == ([], [note["id"]]), "submitted"
    await _validated(client, seeded, submission_id, newer)
    read = await _read(client, seeded)
    assert (read["notes"], _held(read)) == ([], [note["id"]]), "validated"


async def test_a_note_whose_newest_version_is_embargoed_is_held_back(client, session, seeded):
    """Not readable to the import, and not absent either: absent, it would be filed again."""
    note = imported(seeded["record"]["id"])
    submission_id = await _distributed(client, seeded, note)
    rows = await session.scalars(
        select(Distribution).where(Distribution.submission_id == uuid.UUID(submission_id))
    )
    for row in rows:
        row.date_added = dt.datetime.now(dt.UTC) + dt.timedelta(days=3)
    await session.commit()

    read = await _read(client, seeded)

    assert (read["notes"], _held(read)) == ([], [note["id"]])


async def test_a_withdrawn_draft_holds_nothing_back(client, seeded):
    """As for KEV: an editor who withdrew the import's draft sees it filed again."""
    note = imported(seeded["record"]["id"])
    submission_id = await _filed(client, seeded, note)
    assert _held(await _read(client, seeded)) == [note["id"]], "held while it waits"
    withdrawn = await client.post(
        f"/api/v1/submissions/{submission_id}/withdraw", json={}, headers=seeded["editor"]
    )
    assert withdrawn.status_code == 200, withdrawn.text

    assert await _read(client, seeded) == {"notes": [], "held_back": []}


async def test_a_members_marked_note_in_review_is_in_neither_list(
    client, seeded, make_org, make_cert, join_circle
):
    """The read answers what the refile check needs, and a member's note is not that,
    whatever reference it carries."""
    member = await make_org("meridian-global")
    pem, _ = await make_cert(member)
    await join_circle(member, seeded["circle"])
    note = imported(seeded["record"]["id"])
    submission_id = await _filed(client, seeded, note, pem=pem)
    sent = await client.post(
        f"/api/v1/submissions/{submission_id}/submit", json={}, headers=proxy_headers(pem)
    )
    assert sent.status_code == 200, sent.text
    ours = imported(seeded["record"]["id"])
    our_submission = await _filed(client, seeded, ours)
    await _sent(client, seeded, our_submission)

    assert _held(await _read(client, seeded)) == [ours["id"]], "the ISAC's own, in review"


async def test_an_analysts_own_note_citing_the_cve_is_in_neither_list(
    client, session, seeded, isac_org
):
    """Only the import's reference makes a note the import's."""
    note = conditions_note(
        seeded["record"]["id"], {"id": "fn", "kind": "function", "any_of": [PARSE]}
    )
    note["external_references"] = [{"source_name": "cve", "external_id": "CVE-2026-31337"}]
    await seed(session, isac_org, note, circle=seeded["circle"])
    ours = imported(seeded["record"]["id"])
    await _distributed(client, seeded, ours)

    read = await _read(client, seeded)

    assert ([n["note"]["id"] for n in read["notes"]], read["held_back"]) == ([ours["id"]], [])


async def test_a_red_note_is_held_back_not_served(client, session, seeded, isac_org):
    await seed(
        session, isac_org, imported(seeded["record"]["id"]), circle=seeded["circle"], tlp=TLP.RED
    )

    read = await _read(client, seeded)

    assert read["notes"] == []
    assert len(read["held_back"]) == 1


async def test_nothing_is_served_while_distribution_is_paused(client, session, seeded):
    note = imported(seeded["record"]["id"])
    await _distributed(client, seeded, note)
    control = await session.get(InstanceControl, 1) or InstanceControl(id=1)
    control.distribution_paused = True
    session.add(control)
    await session.commit()

    read = await _read(client, seeded)

    assert (read["notes"], _held(read)) == ([], [note["id"]])


async def test_nobody_but_the_automation_reads_them(client, seeded, isac_org, make_org, make_cert):
    member = await make_org("meridian-global")
    pem, _ = await make_cert(member)
    isac_pem, _ = await make_cert(isac_org)

    for headers in (proxy_headers(pem), seeded["editor"], proxy_headers(isac_pem)):
        assert (await client.get(NOTES, headers=headers)).status_code == 404
