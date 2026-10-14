"""A sandbox circle counts in no figure; a government body waits for its receipts policy.

Both are rules about what the instance reports or admits, so each is shown on
both sides and, for enrolment, at both doors.
"""

from __future__ import annotations

import datetime as dt

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from aivs_schemas.enums import OrgType
from aivs_server.db.models import Organization, Submission
from aivs_server.main import create_app
from aivs_server.services.enrolment import enrolment_problem
from aivs_server.services.lead_time import Quarter, sector_median
from aivs_server.services.telemetry import K_ANONYMITY, submission_telemetry
from tests.unit.sharing import vulnerability_intel
from tests.unit.test_portal_admin import ADMIN, csrf, signed_in_admin  # noqa: F401 - fixture

pytestmark = pytest.mark.db


# ---------------------------------------------------------------------------
# Sandbox circles
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(("sandbox", "reach"), [(True, None), (False, K_ANONYMITY)])
async def test_what_reaches_a_sandbox_is_no_reach(
    session, make_org, make_circle, make_collection, join_circle, publish, sandbox, reach
):
    circle = await make_circle("exercise" if sandbox else "real")
    circle.is_sandbox = sandbox
    await session.commit()
    await make_collection(circle)
    submitter = await make_org("exercise-submitter", org_type=OrgType.GSIB)
    for number in range(K_ANONYMITY):
        await join_circle(await make_org(f"reader-{number}", org_type=OrgType.GSIB), circle)
    submission, _obj, _row = await publish(submitter, circle, name="Exercise")

    telemetry = await submission_telemetry(session, await session.get(Submission, submission.id))
    assert telemetry.reach.value == reach


@pytest.mark.parametrize(("sandbox", "shown"), [(True, False), (False, True)])
async def test_an_exercise_is_no_part_of_the_isacs_lead_time(
    session, make_org, make_circle, publish, sandbox, shown
):
    circle = await make_circle("lead-exercise" if sandbox else "lead-real")
    circle.is_sandbox = sandbox
    await session.commit()
    org = await make_org("lead-exercise-vendor", org_type=OrgType.GSIB)
    now = dt.datetime.now(dt.UTC)
    for number in range(K_ANONYMITY):
        _submission, stix_object, _row = await publish(org, circle, name=f"Item {number}")
        public = (now + dt.timedelta(days=number + 1)).date().isoformat()
        stix_object.raw = stix_object.raw | {
            "extensions": vulnerability_intel(nvd_published=public)
        }
        await session.commit()
    quarter = Quarter(now.year, (now.month - 1) // 3 + 1)
    median = await sector_median(session, quarter, now=now + dt.timedelta(seconds=1))
    assert (median.median_days_ahead_of_nvd is not None) is shown


async def test_a_sandbox_is_created_as_one_and_says_so(client, isac):
    _isac_org, isac_headers = isac
    created = await client.post(
        "/api/v1/circles",
        json={"slug": "tip-check", "name": "TIP check", "is_sandbox": True},
        headers=isac_headers,
    )
    assert created.status_code == 201, created.text
    assert created.json()["is_sandbox"] is True


# ---------------------------------------------------------------------------
# Government recipients
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("org_type", "agreed", "refused"),
    [
        (OrgType.GOVERNMENT, False, True),
        (OrgType.GOVERNMENT, True, False),
        (OrgType.GSIB, False, False),
    ],
)
def test_a_government_body_waits_for_the_receipts_policy(org_type, agreed, refused):
    problem = enrolment_problem(org_type, government_receipts_policy_agreed=agreed)
    assert (problem is not None) is refused


def _org(slug: str) -> dict:
    return {"slug": slug, "name": slug.title(), "org_type": "government"}


@pytest.mark.requirement("SF-76")
async def test_the_api_refuses_a_government_body_until_the_policy_is_agreed(
    client, isac, settings, engine
):
    _isac_org, isac_headers = isac
    refused = await client.post("/api/v1/orgs", json=_org("agency-one"), headers=isac_headers)
    assert refused.status_code == 409
    assert "section 10" in refused.json()["title"]

    agreed = create_app(settings.model_copy(update={"government_receipts_policy_agreed": True}))
    transport = ASGITransport(app=agreed, client=("127.0.0.1", 0))
    async with AsyncClient(transport=transport, base_url="https://aivs.test") as http:
        accepted = await http.post("/api/v1/orgs", json=_org("agency-two"), headers=isac_headers)
    assert accepted.status_code == 201, accepted.text


@pytest.mark.requirement("SF-76")
async def test_the_portal_refuses_a_government_body_too(client, session, signed_in_admin):  # noqa: F811
    _org_row, pem = signed_in_admin
    from tests.conftest import proxy_headers  # noqa: PLC0415 - beside its one use

    response = await client.post(
        f"{ADMIN}/orgs",
        data={
            "csrf_token": csrf(client),
            "slug": "agency-portal",
            "name": "Agency",
            "org_type": "government",
        },
        headers=proxy_headers(pem),
    )
    assert response.status_code == 303
    found = await session.scalar(
        select(Organization.id).where(Organization.slug == "agency-portal")
    )
    assert found is None
