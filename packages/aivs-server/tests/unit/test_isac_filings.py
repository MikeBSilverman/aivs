"""Every verb on the ISAC's own filing needs a human ``isac_editor`` (Mike, Q15).

The submitter's rights used to apply to the ISAC's submissions as to any
member's, so an ISAC analyst's session, or the admin organisation's
certificate alone, could amend an ISAC draft or withdraw a validated
advisory. Each principal is driven at each verb through the API, and each
refusal is checked for the rule that made it (CLAUDE.md section 2).
"""

from __future__ import annotations

import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select

from aivs_schemas.enums import TLP, DiscoveryScope, OperatorRole, OrgType, SubmissionState
from aivs_server.audit.log import AuditAction
from aivs_server.auth.policy import holds_submitter_rights
from aivs_server.auth.sessions import establish_session
from aivs_server.db.models import AuditLog, Submission
from aivs_server.services.attribution import is_submitted_by
from aivs_server.services.submissions import is_isac_filing
from tests.conftest import TEST_ATTRIBUTION_KEY, proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1/submissions"
REFUSAL = "isac_filing_requires_isac_editor"


def _bundle() -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{uuid.uuid4()}",
                "created": "2026-08-01T00:00:00.000Z",
                "modified": "2026-08-01T00:00:00.000Z",
                "name": "An ISAC advisory",
            }
        ],
    }


@pytest.fixture
async def people(isac_org, make_org, make_cert, make_operator, human_headers):
    isac_pem, _ = await make_cert(isac_org)
    editor, _ = await make_operator(isac_org, roles=(OperatorRole.ISAC_EDITOR,))
    analyst, _ = await make_operator(isac_org, roles=(OperatorRole.ISAC_ANALYST,))
    automation = await make_org("isac-automation", org_type=OrgType.AUTOMATION)
    automation_pem, _ = await make_cert(automation)
    return {
        "isac_pem": isac_pem,
        "editor": await human_headers(editor, isac_pem),
        "analyst": await human_headers(analyst, isac_pem),
        "admin certificate": proxy_headers(isac_pem),
        "automation": proxy_headers(automation_pem),
    }


async def _isac_filing(client, people, *, validated: bool) -> str:
    filed = await client.post(
        API,
        json={
            "title": "An ISAC advisory",
            "discovery_scope": "own_estate",
            "tlp": "amber",
            "bundle": _bundle(),
        },
        headers=people["editor"],
    )
    assert filed.status_code == 201, filed.text
    submission_id = filed.json()["id"]
    if validated:
        for verb in ("submit", "validate"):
            moved = await client.post(
                f"{API}/{submission_id}/{verb}", json={}, headers=people["editor"]
            )
            assert moved.status_code == 200, moved.text
    return submission_id


async def _denial_reasons(session) -> list[str]:
    rows = await session.scalars(
        select(AuditLog).where(AuditLog.action == AuditAction.ACCESS_DENIED)
    )
    return [row.details["reason"] for row in rows]


def _verb(client, submission_id: str, verb: str, headers: dict[str, str]):
    if verb == "amend":
        return client.patch(f"{API}/{submission_id}", json={"title": "Amended"}, headers=headers)
    return client.post(f"{API}/{submission_id}/{verb}", json={}, headers=headers)


@pytest.mark.requirement("SF-81")
@pytest.mark.parametrize("principal", ["analyst", "admin certificate"])
@pytest.mark.parametrize(
    ("verb", "validated"), [("amend", False), ("submit", False), ("withdraw", True)]
)
async def test_isac_staff_without_the_editor_role_hold_no_verb_on_an_isac_filing(
    client, session, people, principal, verb, validated
):
    submission_id = await _isac_filing(client, people, validated=validated)

    refused = await _verb(client, submission_id, verb, people[principal])

    assert refused.status_code == 403, refused.text
    assert await _denial_reasons(session) == [REFUSAL]


@pytest.mark.requirement("SF-81")
@pytest.mark.parametrize(
    ("verb", "validated"), [("amend", False), ("submit", False), ("withdraw", True)]
)
async def test_an_isac_editor_holds_every_verb_on_an_isac_filing(client, people, verb, validated):
    submission_id = await _isac_filing(client, people, validated=validated)
    done = await _verb(client, submission_id, verb, people["editor"])
    assert done.status_code == 200, done.text


@pytest.mark.parametrize(
    ("verb", "validated"), [("amend", False), ("submit", False), ("withdraw", True)]
)
async def test_the_automation_identity_cannot_see_an_isac_filing(client, people, verb, validated):
    """Not the ISAC's organisation, so no submitter's right, and the filing is
    not its to see: the 404 any unknown id gets."""
    submission_id = await _isac_filing(client, people, validated=validated)
    refused = await _verb(client, submission_id, verb, people["automation"])
    assert refused.status_code == 404, refused.text


@pytest.mark.requirement("SF-81")
async def test_the_portal_offers_an_isac_analyst_no_verb_on_an_isac_filing(
    client, session, people, isac_org, make_operator, settings
):
    """The portal lists only verbs policy grants, through the same predicate,
    so a button the API would refuse never appears."""
    submission_id = await _isac_filing(client, people, validated=False)
    analyst, _ = await make_operator(isac_org, roles=(OperatorRole.ISAC_ANALYST,))
    certificate = x509.load_pem_x509_certificate(people["isac_pem"].encode("ascii"))
    established = await establish_session(
        session,
        settings,
        operator=analyst,
        cert_fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
    )
    await session.commit()
    client.cookies.set(settings.session_cookie_name, established.token)
    page = await client.get(
        f"/portal/submissions/{submission_id}", headers=proxy_headers(people["isac_pem"])
    )
    assert page.status_code == 200, page.text
    assert "Send for review" not in page.text
    assert "Withdraw" not in page.text


@pytest.mark.requirement("SF-81")
async def test_an_analysts_isac_draft_waits_for_an_editor_and_only_an_editor_moves_it(
    client, people
):
    """Filing a draft is not a verb on a submission, so an analyst may still
    draft for the ISAC. Everything after that is an editor's: the analyst can
    neither send nor withdraw it, and an editor can do both. It is not orphaned
    -- it sits in the editors' hands -- but nothing reaches review until one
    acts."""
    drafted = await client.post(
        API,
        json={
            "title": "An analyst's draft",
            "discovery_scope": "own_estate",
            "tlp": "amber",
            "bundle": _bundle(),
        },
        headers=people["analyst"],
    )
    assert drafted.status_code == 201, drafted.text
    draft_id = drafted.json()["id"]

    analyst_sends = await _verb(client, draft_id, "submit", people["analyst"])
    analyst_withdraws = await _verb(client, draft_id, "withdraw", people["analyst"])
    editor_sends = await _verb(client, draft_id, "submit", people["editor"])

    assert (analyst_sends.status_code, analyst_withdraws.status_code) == (403, 403)
    assert editor_sends.status_code == 200, editor_sends.text


# ---------------------------------------------------------------------------
# The automation's own filings (Mike, Q35)
# ---------------------------------------------------------------------------
async def _automation_draft(client, people) -> str:
    drafted = await client.post(
        API,
        json={
            "title": "A KEV version",
            "discovery_scope": "ai_system",
            "tlp": "amber",
            "bundle": _bundle(),
        },
        headers=people["automation"],
    )
    assert drafted.status_code == 201, drafted.text
    return drafted.json()["id"]


@pytest.mark.requirement("SF-81")
@pytest.mark.parametrize("verb", ["amend", "submit", "withdraw"])
async def test_the_automation_holds_no_verb_on_its_own_draft(client, session, people, verb):
    """It may file, as an analyst may draft; sending, changing or withdrawing
    what it filed is an editor's."""
    draft_id = await _automation_draft(client, people)

    refused = await _verb(client, draft_id, verb, people["automation"])

    assert refused.status_code == 403, refused.text
    assert await _denial_reasons(session) == [REFUSAL]


@pytest.mark.requirement("SF-81")
@pytest.mark.parametrize("verb", ["amend", "submit", "withdraw"])
async def test_an_isac_editor_holds_every_verb_on_the_automations_draft(client, people, verb):
    """The editor is at the admin organisation, not the automation's: before
    Q35 it held none of these, so refusing the automation alone would have
    stranded its drafts."""
    draft_id = await _automation_draft(client, people)
    done = await _verb(client, draft_id, verb, people["editor"])
    assert done.status_code == 200, done.text


async def test_an_isac_analyst_holds_no_verb_on_the_automations_draft(client, session, people):
    draft_id = await _automation_draft(client, people)
    refused = await _verb(client, draft_id, "submit", people["analyst"])
    assert refused.status_code == 403, refused.text
    assert await _denial_reasons(session) == [REFUSAL]


@pytest.mark.requirement("SF-81")
async def test_a_filing_whose_tag_names_no_organisation_gives_no_one_its_verbs(session, isac_ctx):
    """``is_isac_filing`` answers from the tag (Phase P): a tag that matches no
    organisation is not taken for the ISAC's, and no caller's tag matches it
    either, so nobody holds the submitter's verbs on it, an editor included.
    Before the tag it read the owner from ``attribution`` and took an owner it
    could not find for the ISAC's, so an editor held them."""
    orphan_id = uuid.uuid4()
    orphan = Submission(
        id=orphan_id,
        owner_tag=TEST_ATTRIBUTION_KEY.owner_tag(uuid.uuid4(), orphan_id),
        state=SubmissionState.DRAFT,
        tlp=TLP.AMBER,
        discovery_scope=DiscoveryScope.OWN_ESTATE,
        title="no owner",
    )
    owner_is_isac = await is_isac_filing(session, TEST_ATTRIBUTION_KEY, orphan)
    owner_is_caller = is_submitted_by(TEST_ATTRIBUTION_KEY, orphan, isac_ctx.org_id)
    assert (owner_is_isac, owner_is_caller) == (False, False)
    assert not holds_submitter_rights(
        isac_ctx, owner_is_isac=owner_is_isac, owner_is_caller=owner_is_caller
    )
