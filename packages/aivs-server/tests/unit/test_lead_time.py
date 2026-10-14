"""Lead time: a member's own statement, and the ISAC's sector median withheld below k."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from aivs_schemas.enums import PostureStatus
from aivs_server.db.models import OrgPosture
from aivs_server.services.lead_time import ItemLead, Quarter, item_lead, summarise
from aivs_server.services.telemetry import K_ANONYMITY
from tests.conftest import proxy_headers
from tests.unit.sharing import sdo, share, vulnerability_intel

NOW = dt.datetime.now(dt.UTC)
THIS_QUARTER = Quarter(NOW.year, (NOW.month - 1) // 3 + 1)
SEEN = dt.datetime(2026, 7, 10, 12, 0, tzinfo=dt.UTC)


# ---------------------------------------------------------------------------
# Arithmetic
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("text", "start", "end"),
    [
        ("2026Q1", dt.datetime(2026, 1, 1, tzinfo=dt.UTC), dt.datetime(2026, 4, 1, tzinfo=dt.UTC)),
        ("2026q3", dt.datetime(2026, 7, 1, tzinfo=dt.UTC), dt.datetime(2026, 10, 1, tzinfo=dt.UTC)),
        ("2026Q4", dt.datetime(2026, 10, 1, tzinfo=dt.UTC), dt.datetime(2027, 1, 1, tzinfo=dt.UTC)),
    ],
)
def test_a_quarter_is_three_calendar_months_in_utc(text, start, end):
    quarter = Quarter.parse(text)
    assert (quarter.start, quarter.end) == (start, end)


@pytest.mark.parametrize("text", ["2026", "2026Q5", "2026Q0", "Q3", "26Q3x", ""])
def test_anything_else_is_not_a_quarter(text):
    with pytest.raises(ValueError, match="not a quarter"):
        Quarter.parse(text)


def _version(**body: object) -> dict:
    return sdo("vulnerability", name="v", extensions=vulnerability_intel(**body))


def test_a_lead_is_days_from_first_seen_to_the_public_date():
    lead = item_lead(
        "vulnerability--x",
        "x",
        SEEN,
        [_version(nvd_published="2026-07-14", kev_date_added="2026-07-01")],
    )
    assert lead.nvd_lead_days == 3.5  # 12:00 on the 10th to midnight on the 14th
    assert lead.kev_lead_days == -9.5  # KEV listed it before the member saw it


def test_the_earliest_date_any_visible_version_states_is_the_public_date():
    versions = [
        _version(),
        _version(kev_date_added="2026-07-20"),
        _version(kev_date_added="2026-07-15"),
    ]
    lead = item_lead("vulnerability--x", "x", SEEN, versions)
    assert lead.kev_lead_days == 4.5
    assert lead.nvd_lead_days is None  # not on NVD yet


def test_a_statement_counts_leads_and_takes_the_median_of_known_ones():
    def item(nvd: float | None, kev: float | None) -> ItemLead:
        return ItemLead("vulnerability--x", "x", SEEN, nvd, kev)

    statement = summarise(
        Quarter(2026, 3), [item(3.0, None), item(-1.0, 2.0), item(10.0, -4.0), item(None, None)], 2
    )
    assert (statement.relevant, statement.before_nvd, statement.before_kev, statement.actioned) == (
        4,
        2,
        1,
        2,
    )
    assert statement.median_days_ahead_of_nvd == 3.0


# ---------------------------------------------------------------------------
# A member's own statement, through the real path
# ---------------------------------------------------------------------------
@pytest.fixture
async def shared(client, isac, make_org, make_cert, make_circle, join_circle):
    _isac_org, isac_headers = isac
    vendor = await make_org("lead-vendor")
    vendor_pem, _ = await make_cert(vendor)
    reader = await make_org("lead-reader")
    reader_pem, _ = await make_cert(reader)
    circle = await make_circle("lead")
    for org in (vendor, reader):
        await join_circle(org, circle)
    in_three_days = (NOW + dt.timedelta(days=3)).date().isoformat()
    vulnerability = sdo(
        "vulnerability",
        name="Ahead of NVD",
        extensions=vulnerability_intel(nvd_published=in_three_days),
    )
    await share(client, vendor_pem, isac_headers, [vulnerability], [circle.id])
    return {
        "reader": reader,
        "reader_headers": proxy_headers(reader_pem),
        "vendor_headers": proxy_headers(vendor_pem),
        "isac": isac_headers,
        "vulnerability": vulnerability["id"],
    }


def statement_url(org_id: uuid.UUID, quarter: Quarter | str = THIS_QUARTER) -> str:
    return f"/api/v1/organizations/{org_id}/lead-time?quarter={quarter}"


@pytest.mark.db
async def test_a_member_reads_its_own_lead_and_what_it_actioned(client, shared, session):
    session.add(
        OrgPosture(
            org_id=shared["reader"].id,
            vulnerability_stix_id=shared["vulnerability"],
            status=PostureStatus.FIXED,
            detection_deployed=False,
        )
    )
    await session.commit()
    response = await client.get(
        statement_url(shared["reader"].id), headers=shared["reader_headers"]
    )
    assert response.status_code == 200, response.text
    statement = response.json()
    assert (statement["relevant"], statement["before_nvd"], statement["actioned"]) == (1, 1, 1)
    assert 2.0 <= statement["median_days_ahead_of_nvd"] <= 3.0


@pytest.mark.db
async def test_an_open_posture_is_not_counted_as_actioned(client, shared, session):
    session.add(
        OrgPosture(
            org_id=shared["reader"].id,
            vulnerability_stix_id=shared["vulnerability"],
            status=PostureStatus.UNDER_INVESTIGATION,
            detection_deployed=False,
        )
    )
    await session.commit()
    response = await client.get(
        statement_url(shared["reader"].id), headers=shared["reader_headers"]
    )
    assert response.json()["actioned"] == 0


@pytest.mark.db
async def test_another_quarter_holds_nothing_from_this_one(client, shared):
    response = await client.get(
        statement_url(shared["reader"].id, "2020Q1"), headers=shared["reader_headers"]
    )
    assert response.json()["relevant"] == 0


@pytest.mark.db
@pytest.mark.requirement("SF-70")
@pytest.mark.parametrize("asker", ["vendor_headers", "isac"])
async def test_nobody_else_reads_a_members_statement_the_isac_included(client, shared, asker):
    theirs = await client.get(statement_url(shared["reader"].id), headers=shared[asker])
    nobodys = await client.get(statement_url(uuid.uuid4()), headers=shared[asker])
    assert theirs.status_code == nobodys.status_code == 404
    assert theirs.content == nobodys.content


# ---------------------------------------------------------------------------
# The ISAC's sector median
# ---------------------------------------------------------------------------
async def _distribute_with_nvd(
    session, publish, org, circle, count: int, *, date_added: dt.datetime | None = None
) -> None:
    for number in range(count):
        _submission, stix_object, _distribution = await publish(
            org, circle, name=f"Sector {number}", date_added=date_added
        )
        public = (NOW + dt.timedelta(days=number + 1)).date().isoformat()
        stix_object.raw = stix_object.raw | {
            "extensions": vulnerability_intel(nvd_published=public)
        }
        await session.commit()


@pytest.mark.db
@pytest.mark.parametrize(("items", "shown"), [(K_ANONYMITY - 1, False), (K_ANONYMITY, True)])
async def test_the_sector_median_is_withheld_below_k(
    client, isac, session, publish, make_org, make_circle, items, shown
):
    _isac_org, isac_headers = isac
    org = await make_org("sector-vendor")
    circle = await make_circle("sector")
    await _distribute_with_nvd(session, publish, org, circle, items)
    response = await client.get(
        f"/api/v1/lead-time/sector?quarter={THIS_QUARTER}", headers=isac_headers
    )
    assert response.status_code == 200, response.text
    figures = response.json()
    assert (figures["median_days_ahead_of_nvd"] is not None) is shown
    assert (figures["compared_with_nvd"] is not None) is shown


@pytest.mark.db
async def test_content_still_under_embargo_is_not_in_the_sector_median(
    client, isac, session, publish, make_org, make_circle
):
    _isac_org, isac_headers = isac
    org = await make_org("sector-embargoed")
    circle = await make_circle("sector-embargoed")
    release = min(NOW + dt.timedelta(hours=1), THIS_QUARTER.end - dt.timedelta(seconds=1))
    await _distribute_with_nvd(session, publish, org, circle, K_ANONYMITY, date_added=release)
    response = await client.get(
        f"/api/v1/lead-time/sector?quarter={THIS_QUARTER}", headers=isac_headers
    )
    assert response.json()["median_days_ahead_of_nvd"] is None


@pytest.mark.db
async def test_a_member_does_not_read_the_sector_median(client, shared):
    response = await client.get(
        f"/api/v1/lead-time/sector?quarter={THIS_QUARTER}", headers=shared["reader_headers"]
    )
    assert response.status_code == 404
