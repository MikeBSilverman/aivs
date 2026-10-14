"""The admin status page: every monitorable fact, for a person (NFR-O6).

A component is not monitorable until it appears here, so the first test reads
the component list from ``/readyz`` rather than from a list kept in this file.
Each "needs attention" list is tested as a pair: what belongs on it appears,
its neighbour that does not belong stays off.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from aivs_schemas.enums import AckType, AckVia, OperatorRole, OrgStatus, OrgType
from aivs_server.audit.log import AuditAction
from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db.models import (
    Acknowledgment,
    AuditLog,
    InstanceControl,
    Organization,
    Submission,
    Webhook,
)
from aivs_server.observability import HEARTBEATS
from tests.conftest import proxy_headers
from tests.unit.test_portal_admin import sign_in

pytestmark = pytest.mark.db

STATUS = "/portal/admin/status"


@pytest.fixture(autouse=True)
def _fresh_heartbeats():
    HEARTBEATS.clear()
    yield
    HEARTBEATS.clear()


@pytest.fixture
async def isac_org(make_org):
    return await make_org("hosting-isac", org_type=OrgType.ADMIN)


@pytest.fixture
async def open_status(client, isac_org, make_cert, make_operator):
    """Sign in at the ISAC with ``roles`` and fetch the status page."""

    async def _open(*roles: OperatorRole):
        pem, _ = await make_cert(isac_org)
        operator, seed = await make_operator(isac_org, roles=roles)
        await sign_in(client, operator, seed, pem)
        return await client.get(STATUS, headers=proxy_headers(pem))

    return _open


@pytest.mark.parametrize(
    ("roles", "expected"),
    [
        ((OperatorRole.SYSTEM_ADMIN,), 200),
        ((OperatorRole.ISAC_MEMBERSHIP,), 200),
        ((OperatorRole.ISAC_EDITOR,), 403),
        ((OperatorRole.ISAC_ANALYST,), 403),
    ],
)
async def test_the_people_who_run_the_instance_and_the_membership_see_it(
    open_status, roles, expected
):
    response = await open_status(*roles)
    assert response.status_code == expected


async def test_a_member_org_admin_cannot_see_it(client, make_org, make_cert, make_operator):
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)
    operator, seed = await make_operator(member, roles=(OperatorRole.ORG_ADMIN,))
    await sign_in(client, operator, seed, pem)

    assert (await client.get(STATUS, headers=proxy_headers(pem))).status_code == 403


@pytest.mark.requirement("NFR-O6")
async def test_every_component_readyz_reports_is_on_the_page(
    client, open_status, safe_database_role
):
    now = dt.datetime.now(dt.UTC)
    HEARTBEATS.register("embargo_sweeper", dt.timedelta(seconds=30), now=now)
    HEARTBEATS.success("embargo_sweeper", now=now)
    HEARTBEATS.register(
        "webhook_dispatcher", dt.timedelta(seconds=10), now=now - dt.timedelta(minutes=5)
    )

    readiness = (await client.get("/readyz")).json()
    page = (await open_status(OperatorRole.SYSTEM_ADMIN)).text

    assert set(readiness["components"]) == {"embargo_sweeper", "webhook_dispatcher"}
    for name, component in readiness["components"].items():
        assert f'data-component="{name}"' in page
        row = page.split(f'data-component="{name}"', 1)[1].split("</tr>", 1)[0]
        assert f"state-{component['state']}" in row


async def test_attention_lists_name_what_needs_it_and_leave_out_what_does_not(
    open_status, make_org, make_cert, session, secret_box
):
    now = dt.datetime.now(dt.UTC)
    expiring = await make_org("expiring-soon", org_type=OrgType.GSIB)
    healthy = await make_org("healthy-member", org_type=OrgType.GSIB)
    await make_cert(expiring, not_after=now + dt.timedelta(days=10))
    await make_cert(healthy, not_after=now + dt.timedelta(days=300))
    quarantined = await make_org("cut-off", org_type=OrgType.GSIB)
    quarantined_id = quarantined.id

    # healthy-member retrieved something today; expiring-soon never has.
    submission = Submission(
        submitter_org_id=healthy.id,
        state="submitted",
        tlp="amber",
        discovery_scope="ai_system",
        title="t",
    )
    session.add(submission)
    await session.flush()
    session.add(
        Acknowledgment(
            org_id=healthy.id,
            submission_id=submission.id,
            ack_type=AckType.RETRIEVED,
            via=AckVia.TAXII,
        )
    )
    hook_id, quiet_id = uuid.uuid4(), uuid.uuid4()
    for webhook_id, org, failures in ((hook_id, expiring, 4), (quiet_id, healthy, 0)):
        session.add(
            Webhook(
                id=webhook_id,
                org_id=org.id,
                url=f"https://{org.slug}.example/hooks/routing-token-{org.slug}",
                hmac_secret_encrypted=secret_box.seal(
                    "s" * 32, purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook_id
                ),
                events=[],
                consecutive_failures=failures,
            )
        )
    session.add(
        AuditLog(
            actor_type="system",
            action=AuditAction.DETECTION_RAISED,
            outcome="success",
            details={"rule": "bulk_retrieval", "severity": "high", "summary": "s"},
        )
    )
    session.add(
        AuditLog(
            actor_type="system",
            action=AuditAction.DETECTION_RAISED,
            outcome="success",
            at=now - dt.timedelta(days=2),
            details={"rule": "stale_rule", "severity": "high", "summary": "s"},
        )
    )
    await session.commit()
    org = await session.get(Organization, quarantined_id)
    org.status, org.quarantined_at = OrgStatus.QUARANTINED, now
    await session.commit()

    page = (await open_status(OperatorRole.ISAC_MEMBERSHIP)).text

    assert 'data-expiring="expiring-soon"' in page
    assert 'data-expiring="healthy-member"' not in page
    assert 'data-silent="expiring-soon"' in page
    assert 'data-silent="healthy-member"' not in page
    assert 'data-failing="expiring-soon"' in page
    assert 'data-failing="healthy-member"' not in page
    assert "routing-token" not in page, "a webhook's host only; its path can carry a token"
    assert 'data-quarantined="cut-off"' in page
    assert 'data-quarantined="healthy-member"' not in page
    assert 'data-detection="bulk_retrieval"' in page
    assert 'data-detection="stale_rule"' not in page, "only the last 24 hours"


async def test_a_pause_and_an_unrotated_secret_are_shown(open_status, session, isac_org):
    unrotated = uuid.uuid4()
    session.add(
        Webhook(
            id=unrotated,
            org_id=isac_org.id,
            url="https://isac.example/hook",
            hmac_secret_encrypted=b"sealed under a format this key never wrote",
            events=[],
        )
    )
    control = await session.get(InstanceControl, 1)
    if control is None:
        control = InstanceControl(id=1)
        session.add(control)
    control.distribution_paused = True
    await session.commit()

    page = (await open_status(OperatorRole.SYSTEM_ADMIN)).text

    assert "Distribution is paused" in page
    assert 'data-fact="secrets_needing_rewrap">1<' in page


async def test_a_running_instance_shows_no_pause_and_nothing_to_rewrap(open_status):
    page = (await open_status(OperatorRole.SYSTEM_ADMIN)).text

    assert "Distribution is paused" not in page
    assert 'data-fact="secrets_needing_rewrap">0<' in page
