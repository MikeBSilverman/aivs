"""Validate writes the reviewer; consequential machine changes need naming (SF-6)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import OrgType, SubmissionSource
from aivs_schemas.extension.builders import (
    AIVS_EXTENSION_ID,
    AIVS_INTEL_EXTENSION_ID,
    AIVS_PROVENANCE_EXTENSION_ID,
)
from aivs_server.db.models import Operator, StixObject, Submission
from aivs_server.services.provenance import reviewer_identity_id
from tests.conftest import ISAC_STAFF_ROLES, proxy_headers
from tests.unit.contribution_world import (
    API,
    LATER,
    STAMP,
    distribute,
    file,
    seed,
    submit_and_validate,
)
from tests.unit.test_portal import csrf_of, sign_in
from tests.unit.test_portal import make_operator as portal_make_operator

pytestmark = pytest.mark.db

VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


@pytest.fixture
async def world(make_org, make_cert, make_circle, join_circle, isac, isac_org):
    circle = await make_circle("section9")
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    member_pem, _ = await make_cert(member)
    robot = await make_org("kev-enrichment", org_type=OrgType.AUTOMATION)
    robot_pem, _ = await make_cert(robot)
    await join_circle(member, circle)
    _isac_org, editor = isac
    return {
        "circle": circle,
        "member_pem": member_pem,
        "robot_pem": robot_pem,
        "editor": editor,
        "isac_org": isac_org,
    }


def workaround(*, restart_required: str = "service", generated_by: str | None = None) -> dict:
    extensions: dict = {
        AIVS_INTEL_EXTENSION_ID: {
            "extension_type": "property-extension",
            "aivs_schema_version": "2.0",
            "category": "workaround",
            "restart_required": restart_required,
        }
    }
    if generated_by is not None:
        extensions[AIVS_PROVENANCE_EXTENSION_ID] = {
            "extension_type": "property-extension",
            "generated_by": generated_by,
        }
    return {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": f"course-of-action--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "name": "Restrict the agent's tool access",
        "extensions": extensions,
    }


def scored(stix_id: str, *, score: float, modified: str) -> dict:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id,
        "created": STAMP,
        "modified": modified,
        "name": "Scored finding",
        "extensions": {
            AIVS_EXTENSION_ID: {
                "extension_type": "property-extension",
                "aivs_schema_version": "1.0",
                "discovery_scope": "own_product",
                "cve_status": "pre-cve",
                "affected_products": [{"vendor": "Acme", "product": "Gateway"}],
                "cvss_v4_vector": VECTOR,
                "cvss_v4_base_score": score,
            }
        },
    }


async def validate_filing(client, world, pem, objects, **validate_body: object):
    filed = await file(client, pem, objects)
    assert filed.status_code == 201, filed.text
    return filed.json()["id"], await submit_and_validate(
        client, pem, filed.json()["id"], world["editor"], **validate_body
    )


# ---------------------------------------------------------------------------
# The reviewer is the server's to write
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-6")
async def test_validate_writes_the_reviewer_from_the_signed_in_editor(client, session, world):
    submission_id, validated = await validate_filing(
        client, world, world["member_pem"], [workaround(generated_by="our SOAR playbook")]
    )
    assert validated.status_code == 200, validated.text

    editor = await session.scalar(select(Operator).where(Operator.org_id == world["isac_org"].id))
    raw = await session.scalar(
        select(StixObject.raw).where(StixObject.submission_id == uuid.UUID(submission_id))
    )
    provenance = raw["extensions"][AIVS_PROVENANCE_EXTENSION_ID]
    assert provenance["human_reviewed_by_ref"] == reviewer_identity_id(editor.id)
    assert provenance["reviewed_at"].endswith("Z")
    assert provenance["generated_by"] == "our SOAR playbook", "the submitter's claim is kept"


@pytest.mark.requirement("SF-6")
async def test_a_draft_carries_no_reviewer_until_it_is_validated(client, session, world):
    filed = await file(client, world["member_pem"], [workaround(generated_by="analyst")])

    raw = await session.scalar(
        select(StixObject.raw).where(StixObject.submission_id == uuid.UUID(filed.json()["id"]))
    )
    assert "human_reviewed_by_ref" not in raw["extensions"][AIVS_PROVENANCE_EXTENSION_ID]


# ---------------------------------------------------------------------------
# The source is the principal's, whatever the content says
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-6")
@pytest.mark.parametrize(
    ("pem_key", "expected"),
    [("robot_pem", SubmissionSource.SYSTEM), ("member_pem", SubmissionSource.MEMBER)],
)
async def test_the_source_is_derived_from_the_filing_organisation(
    client, session, world, pem_key, expected
):
    """The automation organisation says a human analyst made this; it is still a machine."""
    filed = await file(client, world[pem_key], [workaround(generated_by="a human analyst")])

    stored = await session.get(Submission, uuid.UUID(filed.json()["id"]))
    assert stored.source is expected


# ---------------------------------------------------------------------------
# The AI gate
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-6")
async def test_a_machine_filed_disruptive_restart_needs_an_editor_to_name_it(client, world):
    coa = workaround(restart_required="system")

    _id, refused = await validate_filing(client, world, world["robot_pem"], [coa])

    assert refused.status_code == 409
    assert f"{coa['id']}:restart_required" in refused.json()["title"]


@pytest.mark.requirement("SF-6")
async def test_naming_the_change_lets_the_editor_validate_it(client, world):
    coa = workaround(restart_required="system")

    _id, validated = await validate_filing(
        client, world, world["robot_pem"], [coa], acknowledge=[f"{coa['id']}:restart_required"]
    )

    assert validated.status_code == 200, validated.text


@pytest.mark.requirement("SF-6")
async def test_the_same_change_from_a_member_needs_no_acknowledgement(client, world):
    _id, validated = await validate_filing(
        client, world, world["member_pem"], [workaround(restart_required="system")]
    )

    assert validated.status_code == 200, validated.text


@pytest.mark.requirement("SF-6")
async def test_a_machine_lowering_a_score_members_already_hold_needs_naming(client, world):
    shared = f"vulnerability--{uuid.uuid4()}"
    first, validated = await validate_filing(
        client, world, world["robot_pem"], [scored(shared, score=9.1, modified=STAMP)]
    )
    assert validated.status_code == 200, validated.text
    assert (await distribute(client, first, world["editor"], world["circle"])).status_code == 200

    _second, refused = await validate_filing(
        client, world, world["robot_pem"], [scored(shared, score=5.0, modified=LATER)]
    )

    assert refused.status_code == 409
    assert f"{shared}:cvss_v4_base_score" in refused.json()["title"]


@pytest.mark.requirement("SF-6", "SF-48")
async def test_the_isacs_automation_lowering_the_isacs_score_needs_naming(client, session, world):
    """The previous version is the owner's, and the ISAC and its automation are one owner.

    Looked for within the automation organisation's own filings, the gate found
    no previous version of the ISAC's record, so a machine lowering the ISAC's
    score passed with nothing to acknowledge -- on exactly the path SF-48 opens.
    """
    shared = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session,
        world["isac_org"],
        scored(shared, score=9.1, modified=STAMP),
        circle=world["circle"],
    )

    _second, refused = await validate_filing(
        client, world, world["robot_pem"], [scored(shared, score=5.0, modified=LATER)]
    )

    assert refused.status_code == 409
    assert f"{shared}:cvss_v4_base_score" in refused.json()["title"]


@pytest.mark.requirement("SF-6")
async def test_a_machine_raising_a_score_is_not_consequential(client, world):
    shared = f"vulnerability--{uuid.uuid4()}"
    first, _validated = await validate_filing(
        client, world, world["robot_pem"], [scored(shared, score=5.0, modified=STAMP)]
    )
    await distribute(client, first, world["editor"], world["circle"])

    _second, validated = await validate_filing(
        client, world, world["robot_pem"], [scored(shared, score=9.1, modified=LATER)]
    )

    assert validated.status_code == 200, validated.text


def assessed(stix_id: str, *, modified: str, **properties: object) -> dict:
    """A vulnerability with 2.0 extension properties: SSVC values, a novel vector."""
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id,
        "created": STAMP,
        "modified": modified,
        "name": "Assessed finding",
        "extensions": {
            AIVS_INTEL_EXTENSION_ID: {
                "extension_type": "property-extension",
                "aivs_schema_version": "2.0",
                "discovery_scope": "own_product",
                "cve_status": "pre-cve",
                "affected_products": [{"vendor": "Acme", "product": "Gateway"}],
                **properties,
            }
        },
    }


async def revise_distributed(client, world, before: dict, after: dict):
    """The machine files ``before``, an editor distributes it, then it files ``after``."""
    first, validated = await validate_filing(client, world, world["robot_pem"], [before])
    assert validated.status_code == 200, validated.text
    assert (await distribute(client, first, world["editor"], world["circle"])).status_code == 200
    _second, response = await validate_filing(client, world, world["robot_pem"], [after])
    return response


@pytest.mark.requirement("SF-6")
async def test_a_machine_asserting_a_novel_attack_vector_needs_an_editor_to_name_it(client, world):
    """An assertion on its own, with no earlier version: a new class of attack is news."""
    finding = assessed(f"vulnerability--{uuid.uuid4()}", modified=STAMP, novel_attack_vector=True)

    _id, refused = await validate_filing(client, world, world["robot_pem"], [finding])

    assert refused.status_code == 409
    assert f"{finding['id']}:novel_attack_vector" in refused.json()["title"]


@pytest.mark.requirement("SF-6")
async def test_a_machine_saying_the_vector_is_not_novel_needs_no_acknowledgement(client, world):
    """The pair: the property present and false asserts nothing."""
    finding = assessed(f"vulnerability--{uuid.uuid4()}", modified=STAMP, novel_attack_vector=False)

    _id, validated = await validate_filing(client, world, world["robot_pem"], [finding])

    assert validated.status_code == 200, validated.text


@pytest.mark.requirement("SF-6")
async def test_a_machine_lowering_the_ssvc_decision_members_hold_needs_naming(client, world):
    shared = f"vulnerability--{uuid.uuid4()}"

    refused = await revise_distributed(
        client,
        world,
        assessed(shared, modified=STAMP, ssvc_decision="Act"),
        assessed(shared, modified=LATER, ssvc_decision="Attend"),
    )

    assert refused.status_code == 409
    assert f"{shared}:ssvc_decision" in refused.json()["title"]


@pytest.mark.requirement("SF-6")
async def test_a_machine_lowering_ssvc_exploitation_members_hold_needs_naming(client, world):
    shared = f"vulnerability--{uuid.uuid4()}"

    refused = await revise_distributed(
        client,
        world,
        assessed(shared, modified=STAMP, ssvc_exploitation="active"),
        assessed(shared, modified=LATER, ssvc_exploitation="poc"),
    )

    assert refused.status_code == 409
    assert f"{shared}:ssvc_exploitation" in refused.json()["title"]


@pytest.mark.requirement("SF-6")
async def test_a_machine_raising_ssvc_values_is_not_consequential(client, world):
    """SSVC values compare by CISA's urgency order, not as any change: the pair of the two above."""
    shared = f"vulnerability--{uuid.uuid4()}"

    validated = await revise_distributed(
        client,
        world,
        assessed(shared, modified=STAMP, ssvc_decision="Track", ssvc_exploitation="none"),
        assessed(shared, modified=LATER, ssvc_decision="Act", ssvc_exploitation="active"),
    )

    assert validated.status_code == 200, validated.text


# ---------------------------------------------------------------------------
# The portal: each change is a checkbox the editor ticks by name
# ---------------------------------------------------------------------------
@pytest.fixture
async def portal_editor(client, session, secret_box, make_cert, isac_org):
    pem, _ = await make_cert(isac_org)
    operator, secret = await portal_make_operator(
        session, secret_box, isac_org, roles=ISAC_STAFF_ROLES, email="editor@isac.test"
    )
    await sign_in(client, operator, secret, pem)
    return pem


async def portal_validate(client, pem, submission_id, acknowledge):
    return await client.post(
        f"/portal/submissions/{submission_id}/validate",
        data={"csrf_token": csrf_of(client), "acknowledge": acknowledge},
        headers=proxy_headers(pem),
    )


@pytest.mark.requirement("SF-6")
async def test_the_portal_refuses_validation_until_the_change_is_ticked(
    client, session, world, portal_editor
):
    coa = workaround(restart_required="system")
    filed = await file(client, world["robot_pem"], [coa])
    submission_id = filed.json()["id"]
    await client.post(
        f"{API}/{submission_id}/submit", json={}, headers=proxy_headers(world["robot_pem"])
    )

    detail = await client.get(
        f"/portal/submissions/{submission_id}", headers=proxy_headers(portal_editor)
    )
    assert f'value="{coa["id"]}:restart_required"' in detail.text

    await portal_validate(client, portal_editor, submission_id, [])
    unticked = await session.get(Submission, uuid.UUID(submission_id))
    await session.refresh(unticked)
    assert unticked.state.value == "submitted"

    await portal_validate(client, portal_editor, submission_id, [f"{coa['id']}:restart_required"])
    await session.refresh(unticked)
    assert unticked.state.value == "validated"
