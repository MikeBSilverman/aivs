"""The drafts waiting for an ISAC editor, and the stale count (Mike, Q36).

Since Q15 and Q35 an analyst may draft for the ISAC and the automation may
file a KEV version, and only an editor may send either. These are the screen
an editor works the queue from, and the line on the status page that says when
one has waited too long.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import update

from aivs_schemas.enums import OperatorRole, OrgType
from aivs_server.db.models import Submission
from aivs_server.services.instance_status import gather_status
from aivs_server.services.isac_drafts import STALE_AFTER, stale_isac_drafts
from tests.conftest import proxy_headers
from tests.unit.test_portal import make_operator as portal_make_operator
from tests.unit.test_portal import sign_in

pytestmark = pytest.mark.db

API = "/api/v1/submissions"
REVIEW = "/portal/review"


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
                "name": "A draft",
            }
        ],
    }


async def _draft(client, headers, title: str, scope: str = "own_estate") -> str:
    drafted = await client.post(
        API,
        json={"title": title, "discovery_scope": scope, "tlp": "amber", "bundle": _bundle()},
        headers=headers,
    )
    assert drafted.status_code == 201, drafted.text
    return str(drafted.json()["id"])


@pytest.fixture
async def world(isac, isac_org, make_org, make_cert):
    _org, editor = isac
    member = await make_org("drafting-member")
    member_pem, _ = await make_cert(member)
    automation = await make_org("isac-automation", org_type=OrgType.AUTOMATION)
    automation_pem, _ = await make_cert(automation)
    isac_pem, _ = await make_cert(isac_org)
    return {
        "editor_api": editor,
        "member": proxy_headers(member_pem),
        "automation": proxy_headers(automation_pem),
        "isac_pem": isac_pem,
    }


async def _review_page_as(client, session, secret_box, isac_org, world, role: OperatorRole):
    client.cookies.clear()
    operator, secret = await portal_make_operator(
        session, secret_box, isac_org, roles=(role,), email=f"{role.value}@isac.test"
    )
    await sign_in(client, operator, secret, world["isac_pem"])
    return await client.get(REVIEW, headers=proxy_headers(world["isac_pem"]))


# ---------------------------------------------------------------------------
# The list
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-81")
async def test_an_editor_sees_the_isacs_and_the_automations_drafts_with_its_verbs(
    client, session, secret_box, isac_org, world
):
    isac_draft = await _draft(client, world["editor_api"], "An ISAC advisory")
    kev_draft = await _draft(client, world["automation"], "A KEV version", scope="ai_system")

    page = await _review_page_as(
        client, session, secret_box, isac_org, world, OperatorRole.ISAC_EDITOR
    )

    assert page.status_code == 200, page.text
    assert f'data-draft="{isac_draft}"' in page.text
    assert f'data-draft="{kev_draft}"' in page.text
    assert "the automation (KEV)" in page.text
    assert f'action="/portal/submissions/{isac_draft}/submit"' in page.text


@pytest.mark.requirement("SF-81")
async def test_an_analyst_sees_the_list_and_no_verb(client, session, secret_box, isac_org, world):
    """The verbs come from the predicate the API asks, so the analyst, who
    holds none of them on the ISAC's filing, is offered none."""
    isac_draft = await _draft(client, world["editor_api"], "An ISAC advisory")

    page = await _review_page_as(
        client, session, secret_box, isac_org, world, OperatorRole.ISAC_ANALYST
    )

    assert f'data-draft="{isac_draft}"' in page.text
    assert f'action="/portal/submissions/{isac_draft}/submit"' not in page.text


@pytest.mark.parametrize("role", [OperatorRole.ISAC_MEMBERSHIP, OperatorRole.SYSTEM_ADMIN])
async def test_staff_who_hold_no_content_right_do_not_see_it(
    client, session, secret_box, isac_org, world, role
):
    await _draft(client, world["editor_api"], "An ISAC advisory")
    page = await _review_page_as(client, session, secret_box, isac_org, world, role)
    assert page.status_code == 404


async def test_a_member_draft_never_appears(client, session, secret_box, isac_org, world):
    """A member's draft is its own business until it sends it."""
    member_draft = await _draft(client, world["member"], "A member's finding")

    page = await _review_page_as(
        client, session, secret_box, isac_org, world, OperatorRole.ISAC_EDITOR
    )

    assert f'data-draft="{member_draft}"' not in page.text


async def test_a_draft_sent_for_review_leaves_the_list(
    client, session, secret_box, isac_org, world
):
    isac_draft = await _draft(client, world["editor_api"], "An ISAC advisory")
    sent = await client.post(f"{API}/{isac_draft}/submit", json={}, headers=world["editor_api"])
    assert sent.status_code == 200, sent.text

    page = await _review_page_as(
        client, session, secret_box, isac_org, world, OperatorRole.ISAC_EDITOR
    )

    assert f'data-draft="{isac_draft}"' not in page.text


# ---------------------------------------------------------------------------
# The stale count
# ---------------------------------------------------------------------------
async def _age(session, submission_id: str, by: dt.timedelta) -> None:
    await session.execute(
        update(Submission)
        .where(Submission.id == uuid.UUID(submission_id))
        .values(created_at=Submission.created_at - by)
    )
    await session.commit()


@pytest.mark.requirement("SF-81")
async def test_drafts_waiting_past_a_week_are_counted_kev_on_its_own_line(
    client, session, secret_box, world
):
    """A forgotten KEV draft stalls its record's KEV updates, so it is counted
    apart from the ISAC's own drafts, and a fresh draft is not counted."""
    old_isac = await _draft(client, world["editor_api"], "An old advisory")
    old_kev = await _draft(client, world["automation"], "An old KEV version", scope="ai_system")
    await _draft(client, world["editor_api"], "A fresh advisory")
    await _draft(client, world["member"], "A member's old finding")
    for submission_id in (old_isac, old_kev):
        await _age(session, submission_id, STALE_AFTER + dt.timedelta(days=1))

    now = dt.datetime.now(dt.UTC)
    stale = await stale_isac_drafts(session, now=now)
    status = await gather_status(session, now=now, box=secret_box, email_max_attempts=5)

    assert (stale.isac, stale.kev) == (1, 1)
    assert status.stale_drafts == stale


async def test_the_status_page_shows_the_kev_line(client, session, secret_box, isac_org, world):
    old_kev = await _draft(client, world["automation"], "An old KEV version", scope="ai_system")
    await _age(session, old_kev, STALE_AFTER + dt.timedelta(days=1))
    client.cookies.clear()
    operator, secret = await portal_make_operator(
        session, secret_box, isac_org, roles=(OperatorRole.SYSTEM_ADMIN,), email="sa@isac.test"
    )
    await sign_in(client, operator, secret, world["isac_pem"])

    page = await client.get("/portal/admin/status", headers=proxy_headers(world["isac_pem"]))

    assert page.status_code == 200, page.text
    assert 'data-stale-drafts="kev"' in page.text
    assert 'data-stale-drafts="isac"' not in page.text
