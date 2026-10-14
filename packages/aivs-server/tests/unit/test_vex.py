"""A posture is a VEX statement, and a member exports its own as OpenVEX (SF-70).

VEX's rules are what make an export usable by a regulator or a scanner: a
``not_affected`` statement says why, an ``affected`` one says what is being
done, and a justification explains ``not_affected`` only. The API refuses a
statement that breaks one, naming the rule, and the database refuses it
whatever writes the row. The export carries the caller's own postures and
nothing else, names a vulnerability only as far as the caller can still see
it, and leaves out what VEX has no field for.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from aivs_schemas.enums import PostureStatus, VexJustification
from aivs_server.audit.log import AuditAction
from aivs_server.db.models import AuditLog, OrgPosture, StixObject
from aivs_server.services.detections import RULES
from aivs_server.services.posture import VexStatement, vex_problem
from aivs_server.services.submissions import _extract_indexed_fields
from aivs_server.services.telemetry import counted_organisations
from aivs_server.services.vex_export import OPENVEX_CONTEXT
from tests.unit.contribution_world import seed, vulnerability_raw
from tests.unit.sharing_world import API, SharingWorld, build_sharing_world

pytestmark = pytest.mark.db

CVE = "CVE-2026-40404"


@pytest.fixture
async def world(
    session,
    isac,
    isac_org,
    make_org,
    make_cert,
    make_operator,
    make_circle,
    make_collection,
    join_circle,
    human_headers,
) -> SharingWorld:
    return await build_sharing_world(
        session,
        isac,
        isac_org,
        make_org=make_org,
        make_cert=make_cert,
        make_operator=make_operator,
        make_circle=make_circle,
        make_collection=make_collection,
        join_circle=join_circle,
        human_headers=human_headers,
    )


async def put(client, headers, vulnerability: str, **body: Any):
    return await client.put(
        f"{API}/postures", json={"vulnerability": vulnerability, **body}, headers=headers
    )


async def export(client, headers) -> dict[str, Any]:
    response = await client.get(f"{API}/postures/openvex", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


async def a_named_vulnerability(session, world) -> str:
    """A vulnerability in the member's circle that carries a CVE id."""
    stix_id = f"vulnerability--{uuid.uuid4()}"
    raw = vulnerability_raw(
        stix_id,
        cve_status="published",
        external_references=[{"source_name": "cve", "external_id": CVE}],
    )
    submission = await seed(session, world.isac_org, raw, circle=world.circle)
    # seed() stores the row without the ingest extraction; index it as ingest does.
    await session.execute(
        update(StixObject)
        .where(StixObject.submission_id == submission.id)
        .values(**_extract_indexed_fields(raw))
    )
    await session.commit()
    return stix_id


# ---------------------------------------------------------------------------
# VEX's rules
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-70")
@pytest.mark.parametrize(
    ("body", "rule"),
    [
        ({"status": "not_affected"}, "not_affected needs a justification"),
        ({"status": "affected"}, "affected needs an action statement"),
        (
            {"status": "fixed", "justification": "component_not_present"},
            "a justification explains not_affected only",
        ),
    ],
    ids=["not-affected-without-why", "affected-without-action", "justification-on-fixed"],
)
async def test_a_statement_vex_would_reject_is_refused_by_name(client, session, world, body, rule):
    response = await put(client, world.member.person, world.published, **body)

    assert response.status_code == 400
    assert rule in response.json()["title"]
    assert await session.scalar(select(OrgPosture.id)) is None


@pytest.mark.requirement("SF-70")
@pytest.mark.parametrize(
    "body",
    [
        {"status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"},
        {"status": "not_affected", "impact_statement": "The plugin is disabled estate-wide."},
        {"status": "affected", "action_statement": "Isolating the gateways until the patch."},
        {"status": "fixed"},
        {"status": "under_investigation"},
    ],
    ids=["justified", "explained", "affected-with-action", "fixed", "investigating"],
)
async def test_a_statement_that_says_what_vex_asks_is_recorded(client, world, body):
    response = await put(client, world.member.person, world.published, **body)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == body["status"]


@pytest.mark.parametrize(
    "values",
    [
        {"status": "affected", "action_statement": None},
        {"status": "not_affected", "justification": None, "impact_statement": None},
        {"status": "fixed", "justification": "component_not_present"},
    ],
    ids=["affected-without-action", "not-affected-without-why", "justification-on-fixed"],
)
async def test_the_database_refuses_a_row_vex_would_reject(session, world, client, values):
    """Whatever writes the row: the export is valid VEX by construction."""
    recorded = await put(client, world.member.person, world.published, status="fixed")
    row_id = uuid.UUID(recorded.json()["id"])

    with pytest.raises(IntegrityError, match="ck_org_postures_"):
        await session.execute(update(OrgPosture).where(OrgPosture.id == row_id).values(**values))
    await session.rollback()


def test_the_rules_hold_as_pure_functions():
    """The rule the API names is the rule the database holds, case by case."""
    assert vex_problem(VexStatement(PostureStatus.FIXED)) is None
    assert (
        vex_problem(
            VexStatement(
                PostureStatus.NOT_AFFECTED, justification=VexJustification.COMPONENT_NOT_PRESENT
            )
        )
        is None
    )
    assert vex_problem(VexStatement(PostureStatus.AFFECTED)) is not None
    assert vex_problem(VexStatement(PostureStatus.NOT_AFFECTED)) is not None


@pytest.mark.parametrize(
    "body",
    [
        {"status": "affected", "action_statement": "nul \x00 in prose"},
        {"status": "fixed", "products": ["pkg:pypi/agent@1.2"] * 51},
        {"status": "fixed", "products": ["two\nlines"]},
        {"status": "fixed", "evidence_note": "x" * 2001},
        {"status": "affected", "action_statement": "   \n  "},
    ],
    ids=[
        "nul",
        "too-many-products",
        "multi-line-product",
        "note-too-long",
        "blank-action",
    ],
)
async def test_unbounded_or_unstorable_input_is_refused_as_the_members_mistake(
    client, session, world, body
):
    """A NUL reaches PostgreSQL as a server error; it is the member's typo, so 400."""
    response = await put(client, world.member.person, world.published, **body)

    assert response.status_code == 400
    assert await session.scalar(select(OrgPosture.id)) is None


async def test_a_nul_in_the_vulnerability_id_is_the_members_400(client, session, world):
    """It reached PostgreSQL in the lookup as a server error."""
    response = await put(client, world.member.person, "vulnerability--\x00", status="fixed")

    assert response.status_code == 400
    assert await session.scalar(select(OrgPosture.id)) is None


# ---------------------------------------------------------------------------
# Validation is the server's to time
# ---------------------------------------------------------------------------
async def test_the_server_records_when_a_posture_was_validated(client, world):
    response = await put(
        client, world.member.person, world.published, status="fixed", validated=True
    )

    assert response.json()["validated_at"] is not None


async def test_a_new_status_voids_the_validation_of_the_old_one(client, world):
    await put(client, world.member.person, world.published, status="fixed", validated=True)

    changed = await put(
        client,
        world.member.person,
        world.published,
        status="affected",
        action_statement="It came back on the canary hosts.",
    )
    kept = await put(
        client,
        world.member.person,
        world.published,
        status="affected",
        action_statement="Rolled back the canary hosts.",
    )

    assert changed.json()["validated_at"] is None
    assert kept.json()["validated_at"] is None


async def test_a_changed_statement_voids_the_validation_of_the_old_one(client, world):
    """Validated for one product, then widened to two: the second was never validated."""
    await put(
        client,
        world.member.person,
        world.published,
        status="fixed",
        products=["pkg:pypi/agent-gateway@2.4.1"],
        validated=True,
    )

    widened = await put(
        client,
        world.member.person,
        world.published,
        status="fixed",
        products=["pkg:pypi/agent-gateway@2.4.1", "pkg:pypi/agent-gateway@2.5.0"],
    )

    assert widened.json()["validated_at"] is None


async def test_restating_the_same_status_keeps_its_validation(client, world):
    first = await put(client, world.member.person, world.published, status="fixed", validated=True)

    again = await put(
        client, world.member.person, world.published, status="fixed", evidence_note="Rechecked."
    )

    assert again.json()["validated_at"] == first.json()["validated_at"]


# ---------------------------------------------------------------------------
# The OpenVEX export
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-70")
async def test_the_export_is_openvex_and_carries_the_statements(client, session, world):
    vulnerability = await a_named_vulnerability(session, world)
    await put(
        client,
        world.member.person,
        vulnerability,
        status="not_affected",
        justification="vulnerable_code_not_in_execute_path",
        impact_statement="The plugin loader is disabled.",
        products=[
            "pkg:pypi/agent-gateway@2.4.1",
            "cpe:2.3:a:acme:gateway:2.4:*:*:*:*:*:*:*",
            "Core banking",
        ],
        detection_deployed=True,
        evidence_note="Checked the loader config on every host.",
    )

    document = await export(client, world.member.machine)

    assert document["@context"] == OPENVEX_CONTEXT
    assert document["author"] == world.member.org.name
    [statement] = document["statements"]
    assert statement["vulnerability"] == {"@id": vulnerability, "name": CVE}
    assert statement["status"] == "not_affected"
    assert statement["justification"] == "vulnerable_code_not_in_execute_path"
    assert statement["impact_statement"] == "The plugin loader is disabled."
    assert statement["products"] == [
        {
            "@id": "pkg:pypi/agent-gateway@2.4.1",
            "identifiers": {"purl": "pkg:pypi/agent-gateway@2.4.1"},
        },
        {
            "@id": "cpe:2.3:a:acme:gateway:2.4:*:*:*:*:*:*:*",
            "identifiers": {"cpe23": "cpe:2.3:a:acme:gateway:2.4:*:*:*:*:*:*:*"},
        },
        {"@id": "urn:aivs:product:Core%20banking"},
    ]


async def test_the_export_leaves_out_what_vex_has_no_field_for(client, world):
    await put(
        client,
        world.member.person,
        world.published,
        status="fixed",
        detection_deployed=True,
        validated=True,
        evidence_note="Our own note.",
    )

    [statement] = (await export(client, world.member.person))["statements"]

    assert not {"detection_deployed", "validated_at", "evidence_note"} & set(statement)
    assert "Our own note." not in str(statement)


async def test_a_statement_with_no_products_is_about_the_estate(client, world):
    await put(client, world.member.person, world.published, status="fixed")

    [statement] = (await export(client, world.member.person))["statements"]

    assert statement["products"] == [{"@id": f"urn:aivs:estate:{world.member.org.slug}"}]


@pytest.mark.requirement("SF-70")
async def test_the_export_is_the_callers_own_and_nobody_elses(client, world):
    await put(client, world.member.person, world.published, status="fixed")
    await put(
        client,
        world.reader.person,
        world.published,
        status="affected",
        action_statement="The reader's own plan.",
    )

    mine = await export(client, world.member.machine)
    by_isac = await export(client, world.editor)

    assert [s["status"] for s in mine["statements"]] == ["fixed"]
    assert "The reader's own plan." not in str(mine)
    assert by_isac["statements"] == []


async def test_a_vulnerability_the_member_can_no_longer_see_is_named_by_its_id_only(
    client, session, world
):
    """The posture is the member's to keep; the record's CVE is not its to read any more."""
    vulnerability = await a_named_vulnerability(session, world)
    await put(client, world.member.person, vulnerability, status="fixed")
    removed = await client.delete(
        f"{API}/circles/{world.circle.id}/members/{world.member.org.id}", headers=world.editor
    )
    assert removed.status_code == 204

    [statement] = (await export(client, world.member.machine))["statements"]

    assert statement["vulnerability"] == {"@id": vulnerability, "name": vulnerability}


@pytest.mark.requirement("SF-70")
async def test_an_export_is_audited_as_an_act_never_its_content_or_size(client, session, world):
    await put(
        client,
        world.member.person,
        world.published,
        status="affected",
        action_statement="Isolating the gateways.",
    )

    await export(client, world.member.machine)

    row = await session.scalar(
        select(AuditLog).where(AuditLog.action == AuditAction.POSTURE_EXPORTED)
    )
    assert row is not None
    assert row.org_id == world.member.org.id
    assert row.details == {}


@pytest.mark.requirement("SF-70")
def test_the_export_burst_rule_is_the_documented_twenty_an_hour():
    """SF-70 and the runbook say 20 an hour; the rule is the third description."""
    rule = next(rule for rule in RULES if rule.name == "posture_export_burst")

    assert (rule.threshold, rule.window) == (20, dt.timedelta(hours=1))


@pytest.mark.requirement("SF-70")
async def test_the_isacs_automation_is_never_a_counted_organisation(session, world, make_org):
    """No path lets the automation hold a posture today; the count still never takes one."""
    counted = set((await session.execute(counted_organisations())).scalars())

    assert world.automation.org.id not in counted
    assert world.isac_org.id not in counted
    assert world.member.org.id in counted
