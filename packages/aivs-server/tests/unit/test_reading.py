"""What a reader is handed for one vulnerability, and what is new to them.

The gatherer is the one place guided depth and the exports decide what the
caller may see; these pin its two rules that a renderer could not notice
being broken -- the latest *visible* version, and a relationship's latest
version deciding what it connects -- plus the reading preference's route.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid

import pytest
from sqlalchemy import select

from aivs_schemas.enums import AckVia, OrgType, ReadingDepth
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.deps import load_circle_grants
from aivs_server.db.models import Operator
from aivs_server.services.receipts import record_retrievals
from aivs_server.services.vulnerability_objects import (
    VisibleObject,
    gather_vulnerability,
    last_read_at,
    new_since,
)
from tests.conftest import proxy_headers
from tests.unit.sharing import relates, sdo, share, stamp
from tests.unit.test_portal import make_operator, sign_in

pytestmark = pytest.mark.db

NOW = dt.datetime.now(dt.UTC)


async def _member(session, org) -> AuthContext:
    """The context a request from ``org``'s certificate resolves to, grants included."""
    return AuthContext(
        org_id=org.id,
        org_slug=org.slug,
        org_type=org.org_type,
        org_status=org.status,
        auth_method=AuthMethod.MTLS,
        circles=await load_circle_grants(session, org.id),
    )


@pytest.fixture
async def circles(client, isac, make_org, make_cert, make_circle, join_circle):
    _isac_org, isac_headers = isac
    owner = await make_org("reading-owner")
    owner_pem, _ = await make_cert(owner)
    reader = await make_org("reading-reader")
    reader_pem, _ = await make_cert(reader)
    wide = await make_circle("reading-wide")
    narrow = await make_circle("reading-narrow")
    for org in (owner, reader):
        await join_circle(org, wide)
    await join_circle(owner, narrow)
    return {
        "isac": isac_headers,
        "owner": owner,
        "owner_pem": owner_pem,
        "reader": reader,
        "reader_pem": reader_pem,
        "wide": wide,
        "narrow": narrow,
    }


def _later(obj: dict, **changes: object) -> dict:
    """The next version of ``obj``: same id, a later ``modified``."""
    return obj | {"modified": stamp(NOW.replace(microsecond=0)), **changes}


async def test_a_reader_gets_the_latest_version_it_can_see(client, circles, session):
    vuln = sdo("vulnerability", name="First wording")
    await share(client, circles["owner_pem"], circles["isac"], [vuln], [circles["wide"].id])
    await share(
        client,
        circles["owner_pem"],
        circles["isac"],
        [_later(vuln, name="Second wording")],
        [circles["narrow"].id],
    )
    now = dt.datetime.now(dt.UTC)
    reader_view = await gather_vulnerability(
        session, await _member(session, circles["reader"]), vuln["id"], now=now
    )
    owner_view = await gather_vulnerability(
        session, await _member(session, circles["owner"]), vuln["id"], now=now
    )
    assert reader_view.vulnerability.raw["name"] == "First wording"
    assert owner_view.vulnerability.raw["name"] == "Second wording"


async def test_a_relationship_repointed_by_its_owner_no_longer_connects(client, circles, session):
    vuln = sdo("vulnerability", name="Repointed")
    other = sdo("vulnerability", name="Elsewhere")
    fix = sdo("course-of-action", name="Patch")
    link = relates(fix, vuln, "mitigates")
    await share(
        client,
        circles["owner_pem"],
        circles["isac"],
        [vuln, other, fix, link],
        [circles["wide"].id],
    )
    ctx = await _member(session, circles["reader"])
    before = await gather_vulnerability(session, ctx, vuln["id"], now=dt.datetime.now(dt.UTC))
    assert [obj.stix_id for obj in before.related] == [fix["id"]]

    await share(
        client,
        circles["owner_pem"],
        circles["isac"],
        [_later(link, target_ref=other["id"])],
        [circles["wide"].id],
    )
    after = await gather_vulnerability(session, ctx, vuln["id"], now=dt.datetime.now(dt.UTC))
    assert after.related == ()


# ---------------------------------------------------------------------------
# New since you last read
# ---------------------------------------------------------------------------
def _visible(stix_id: str, date_added: dt.datetime | None) -> VisibleObject:
    return VisibleObject({"id": stix_id, "type": "indicator"}, uuid.uuid4(), date_added)


def test_what_arrived_after_the_last_read_is_new_and_what_came_before_is_not():
    read_at = NOW
    objects = [
        _visible("indicator--before", NOW - dt.timedelta(hours=1)),
        _visible("indicator--after", NOW + dt.timedelta(hours=1)),
        _visible("indicator--reviewer-only", None),
    ]
    assert new_since(objects, read_at) == {"indicator--after"}
    assert new_since(objects, None) == {"indicator--before", "indicator--after"}


async def test_only_a_portal_read_counts_as_having_read_it(session, make_org, make_validated):
    """The collector's poll is not a person reading. The two are on different days
    so the pair does not depend on the receipt key carrying the channel (SF-51)."""
    org = await make_org("reading-receipts")
    submission_id = await make_validated("Read in the portal")
    polled_at = NOW - dt.timedelta(days=2)
    await record_retrievals(
        session,
        org_id=org.id,
        submission_ids=[submission_id],
        via=AckVia.TAXII,
        actor_ref=None,
        now=polled_at,
    )
    await session.commit()
    assert await last_read_at(session, org.id, [submission_id]) is None

    await record_retrievals(
        session,
        org_id=org.id,
        submission_ids=[submission_id],
        via=AckVia.PORTAL,
        actor_ref=None,
        now=NOW,
    )
    await session.commit()
    assert await last_read_at(session, org.id, [submission_id]) is not None


# ---------------------------------------------------------------------------
# The stored preference
# ---------------------------------------------------------------------------
@pytest.fixture
async def signed_in(client, session, secret_box, make_org, make_cert):
    org = await make_org("reading-pref", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    operator, secret = await make_operator(session, secret_box, org)
    await sign_in(client, operator, secret, pem)
    operator_id = operator.id
    dashboard = await client.get("/portal/", headers=proxy_headers(pem))
    token = re.search(r'name="csrf_token" value="([^"]+)"', dashboard.text).group(1)
    return operator_id, pem, token


async def _stored_depth(session, operator_id) -> ReadingDepth | None:
    session.expire_all()
    return await session.scalar(select(Operator.default_depth).where(Operator.id == operator_id))


async def test_a_person_can_store_and_clear_their_reading_depth(client, session, signed_in):
    operator_id, pem, token = signed_in
    saved = await client.post(
        "/portal/preferences/depth",
        data={"depth": "guided", "csrf_token": token},
        headers=proxy_headers(pem),
    )
    assert saved.status_code == 303
    assert await _stored_depth(session, operator_id) is ReadingDepth.GUIDED
    page = await client.get("/portal/", headers=proxy_headers(pem))
    assert '<option value="guided" selected>' in page.text

    await client.post(
        "/portal/preferences/depth",
        data={"depth": "", "csrf_token": token},
        headers=proxy_headers(pem),
    )
    assert await _stored_depth(session, operator_id) is None


async def test_an_unknown_depth_changes_nothing(client, session, signed_in):
    operator_id, pem, token = signed_in
    refused = await client.post(
        "/portal/preferences/depth",
        data={"depth": "everything", "csrf_token": token},
        headers=proxy_headers(pem),
    )
    assert refused.status_code == 303
    assert await _stored_depth(session, operator_id) is None


async def test_storing_a_depth_needs_the_form_token(client, session, signed_in):
    operator_id, pem, _token = signed_in
    refused = await client.post(
        "/portal/preferences/depth",
        data={"depth": "guided", "csrf_token": "wrong"},
        headers=proxy_headers(pem),
    )
    assert refused.status_code == 403
    assert await _stored_depth(session, operator_id) is None
