"""One-click contributions and the lane rule (SF-66).

A click builds the STIX on the server and is published at once only when it
carries no prose, is about public content, comes from a person, goes into a
circle the member contributes to, and is not a vendor's opinion. Every other
click is filed for review. Each property is a pair: the click that takes the
fast lane, and the one changed in exactly that respect that does not.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid

import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import (
    CIRCLE_ELIGIBLE_ORG_TYPES,
    TLP,
    CircleRole,
    DiscoveryScope,
    OperatorRole,
    OrgStatus,
    OrgType,
    SubmissionLane,
    SubmissionState,
)
from aivs_server.audit.log import AuditAction
from aivs_server.auth.context import AuthContext, AuthMethod, CircleGrant, MembershipInterval
from aivs_server.db.models import (
    AuditLog,
    Distribution,
    StixObject,
    Submission,
    SubmissionTransition,
)
from aivs_server.services.contributions import NEEDS_AN_EDITOR, Target, fast_lane_problem
from tests.authz_matrix.test_authz_matrix import walk_routes
from tests.unit.contribution_world import LATER, STAMP, seed, vulnerability_raw
from tests.unit.sharing_world import SharingWorld, build_sharing_world, one_click

pytestmark = pytest.mark.db


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


#: The lane rule's own refusal of content the member does not see as public.
NOT_PUBLIC = "review: about content that is not public"


async def _filed(session, response) -> Submission:
    assert response.status_code == 201, response.text
    submission = await session.get(Submission, uuid.UUID(response.json()["submission_id"]))
    await session.refresh(submission)
    return submission


async def _distributed_to(session, submission: Submission) -> set[uuid.UUID]:
    rows = await session.execute(
        select(Distribution.circle_id)
        .join(StixObject, StixObject.id == Distribution.stix_object_id)
        .where(StixObject.submission_id == submission.id)
    )
    return set(rows.scalars().all())


# ---------------------------------------------------------------------------
# The fast lane
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-66")
async def test_a_person_seeing_a_public_vulnerability_is_published_at_once(client, session, world):
    submission = await _filed(
        session, await one_click(client, world.member.person, world.published)
    )

    assert submission.state is SubmissionState.DISTRIBUTED
    assert submission.lane is SubmissionLane.FAST
    assert await _distributed_to(session, submission) == {world.circle.id}


@pytest.mark.requirement("SF-66")
async def test_the_same_click_from_a_machine_certificate_waits_for_review(client, session, world):
    submission = await _filed(
        session, await one_click(client, world.member.machine, world.published)
    )

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW
    assert await _distributed_to(session, submission) == set()


@pytest.mark.requirement("SF-66")
async def test_a_click_on_a_vulnerability_not_yet_public_waits_for_review(client, session, world):
    """Refused by the lane rule, from what the member sees, not by the ISAC-view check behind it.

    Both refuse a pre-CVE record; asserting the reason is what shows the
    lane rule's own term still works when the later check would cover for it.
    """
    submission = await _filed(session, await one_click(client, world.member.person, world.pre_cve))

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW
    assert (await _transition_reasons(session, submission))[-1] == NOT_PUBLIC


@pytest.mark.requirement("SF-66", "SF-49")
async def test_a_click_on_red_content_waits_for_review_and_is_red_itself(client, session, world):
    submission = await _filed(
        session, await one_click(client, world.member.person, world.published_red)
    )

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.tlp is TLP.RED


@pytest.mark.requirement("SF-66")
async def test_a_vendors_opinion_waits_for_review_though_its_sighting_does_not(
    client, session, world
):
    """A vendor arguing about a product -- possibly its own -- is what an editor is for."""
    assert world.vendor.org.org_type is OrgType.VENDOR
    opinion = await _filed(
        session, await one_click(client, world.vendor.person, world.published, "fails")
    )
    sighting = await _filed(
        session, await one_click(client, world.vendor.person, world.published, "seen")
    )

    assert opinion.state is SubmissionState.SUBMITTED
    assert sighting.state is SubmissionState.DISTRIBUTED


@pytest.mark.requirement("SF-66")
@pytest.mark.parametrize(
    "role",
    [
        OperatorRole.ISAC_ANALYST,
        OperatorRole.ISAC_MEMBERSHIP,
        OperatorRole.SYSTEM_ADMIN,
        OperatorRole.ISAC_EDITOR,
    ],
)
async def test_the_isacs_own_staff_wait_for_review_in_a_circle_the_isac_contributes_to(
    client, session, isac_org, join_circle, make_cert, make_operator, human_headers, world, role
):
    """The ISAC files through review, whoever at it clicks.

    The ISAC's organisation may hold a contributor membership like anyone
    (``CIRCLE_ELIGIBLE_ORG_TYPES`` admits it, and the runbook suggests it).
    Its person's click was published at once, in the ISAC's name with no
    editor -- by an analyst, membership officer or system admin, none of whom
    may distribute. The pair is the member's identical click, published
    (first test in this module).
    """
    assert OrgType.ADMIN in CIRCLE_ELIGIBLE_ORG_TYPES
    await join_circle(isac_org, world.circle, role=CircleRole.CONTRIBUTOR)
    pem, _ = await make_cert(isac_org)
    operator, _seed = await make_operator(isac_org, roles=(role,))
    headers = await human_headers(operator, pem)

    submission = await _filed(session, await one_click(client, headers, world.published))

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW
    assert await _distributed_to(session, submission) == set()


#: Every organisation type that is not the ISAC's own. Written out rather than
#: derived, so a new type is a decision this test makes someone take.
MEMBER_TYPES = frozenset(
    {
        OrgType.GSIB,
        OrgType.SECTION9,
        OrgType.CRIT_INFRA,
        OrgType.VENDOR,
        OrgType.RESEARCHER,
        OrgType.GOVERNMENT,
    }
)


@pytest.mark.requirement("SF-66")
@pytest.mark.parametrize("org_type", list(OrgType))
def test_only_a_person_at_a_member_organisation_takes_a_shortcut_lane(org_type):
    """The lane rule's filer check is an allow-list of member organisation types.

    Everything else about the click is what the fast lane takes; only the
    filer's organisation type varies. The ISAC and its automation are refused
    by the same term, which is what "the ISAC files through review" means.
    """
    circle_id = uuid.uuid4()
    ctx = AuthContext(
        org_id=uuid.uuid4(),
        org_slug="filer",
        org_type=org_type,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.PORTAL_SESSION,
        circles={
            circle_id: CircleGrant(
                role=CircleRole.CONTRIBUTOR,
                intervals=(MembershipInterval(joined_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC)),),
            )
        },
        operator_id=uuid.uuid4(),
    )
    target = Target(
        stix_id=f"vulnerability--{uuid.uuid4()}",
        tlp=TLP.AMBER,
        circle_ids=frozenset({circle_id}),
        is_public=True,
    )

    problem = fast_lane_problem(ctx, target, object_type="sighting")

    assert (problem is None) is (org_type in MEMBER_TYPES)


@pytest.mark.requirement("SF-66")
async def test_the_isacs_automation_reads_no_circle_so_its_click_finds_nothing(client, world):
    """No path makes the automation organisation a circle member, so it sees no target.

    Its click answers exactly as a click on an absent object does. Should that
    ever change, the allow-list above still sends its click to review.
    """
    assert OrgType.AUTOMATION not in CIRCLE_ELIGIBLE_ORG_TYPES

    clicked = await one_click(client, world.automation.person, world.published)
    absent = await one_click(client, world.automation.person, f"vulnerability--{uuid.uuid4()}")

    assert clicked.status_code == absent.status_code == 404
    assert clicked.text == absent.text


@pytest.mark.requirement("SF-66")
async def test_a_reader_only_member_waits_for_review(client, session, world):
    """The circle's contributor role is not bypassed by the fast lane."""
    submission = await _filed(
        session, await one_click(client, world.reader.person, world.published)
    )

    assert submission.state is SubmissionState.SUBMITTED
    assert await _distributed_to(session, submission) == set()


@pytest.mark.requirement("SF-66")
async def test_the_fast_lane_publishes_only_into_the_circles_the_member_contributes_to(
    client, session, make_circle, join_circle, world
):
    """The record reached two of the member's circles; it contributes to one, reads the other.

    A click is published at once -- the member contributes somewhere the record
    is -- but only there. Asking "may it contribute anywhere the record went?"
    and then publishing everywhere the record went put an unreviewed click in
    front of a circle whose editor never let the member write to it.
    """
    read_only = await make_circle("government-liaison")
    await join_circle(world.member.org, read_only, role=CircleRole.MEMBER)
    target = f"vulnerability--{uuid.uuid4()}"
    record = await seed(
        session,
        world.isac_org,
        vulnerability_raw(target, cve_status="published"),
        circle=world.circle,
    )
    await _also_distribute(session, record, read_only)

    submission = await _filed(session, await one_click(client, world.member.person, target))

    assert submission.state is SubmissionState.DISTRIBUTED
    assert await _distributed_to(session, submission) == {world.circle.id}


async def _also_distribute(session, record: Submission, circle) -> None:
    stored = await session.scalar(select(StixObject).where(StixObject.submission_id == record.id))
    first = await session.scalar(
        select(Distribution).where(Distribution.stix_object_id == stored.id)
    )
    session.add(
        Distribution(
            stix_object_id=stored.id,
            circle_id=circle.id,
            submission_id=record.id,
            date_added=first.date_added,
        )
    )
    await session.commit()


# ---------------------------------------------------------------------------
# A contribution on public content is public content
# ---------------------------------------------------------------------------
def _note_on(target: str) -> dict:
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": f"note--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "content": "Seen against our gateway since Tuesday.",
        "object_refs": [target],
    }


async def _seed_note(session, world, scope: DiscoveryScope) -> str:
    """Another firm's note on the ISAC's published record, filed under ``scope``."""
    note = _note_on(world.published)
    await seed(session, world.vendor.org, note, circle=world.circle, discovery_scope=scope)
    return note["id"]


@pytest.mark.requirement("SF-66")
async def test_a_click_on_a_disclosed_third_party_contribution_is_published_at_once(
    client, session, world
):
    """``disclosed_third_party`` reached distribution only because its target was public."""
    note = await _seed_note(session, world, DiscoveryScope.DISCLOSED_THIRD_PARTY)

    submission = await _filed(session, await one_click(client, world.member.person, note))

    assert submission.state is SubmissionState.DISTRIBUTED
    assert submission.lane is SubmissionLane.FAST


@pytest.mark.requirement("SF-66")
async def test_a_click_on_a_contribution_from_a_members_own_estate_waits_for_review(
    client, session, world
):
    """The same note filed as the firm's own experience says nothing about being public.

    Only a vulnerability's own record can say "published"; anything else is
    public because of the scope it was filed under, and ``own_estate`` may be
    about content nobody has disclosed. The pair is the test above.
    """
    note = await _seed_note(session, world, DiscoveryScope.OWN_ESTATE)

    submission = await _filed(session, await one_click(client, world.member.person, note))

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW


# ---------------------------------------------------------------------------
# The click's TLP
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-66", "SF-49")
async def test_a_click_takes_the_strictest_tlp_among_the_versions_the_member_sees(
    client, session, world
):
    """An older AMBER+STRICT version and a newer AMBER one, both in the member's circle.

    The click repeats that the record exists, so it is at least as strict as
    every version of it the member holds -- not the latest one's TLP, which
    would make it looser than the older version and refused from the ISAC's
    view.
    """
    target = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session,
        world.isac_org,
        vulnerability_raw(target, cve_status="published"),
        circle=world.circle,
        tlp=TLP.AMBER_STRICT,
    )
    await seed(
        session,
        world.isac_org,
        vulnerability_raw(target, cve_status="published", modified=LATER),
        circle=world.circle,
        tlp=TLP.AMBER,
    )

    submission = await _filed(session, await one_click(client, world.member.person, target))

    assert submission.tlp is TLP.AMBER_STRICT
    assert submission.state is SubmissionState.DISTRIBUTED


@pytest.mark.requirement("SF-66", "SF-49")
async def test_a_stricter_version_the_member_cannot_see_does_not_set_the_clicks_tlp(
    client, session, isac_org, make_circle, world
):
    """The member's own submission would otherwise carry a TLP it never saw.

    A newer AMBER+STRICT version sits in a circle the member is not in. Taking
    the strictest TLP across every version made the click AMBER+STRICT, which
    the member reads back on its own submission -- the hidden version's
    existence and marking, delivered to the one firm not cleared for it.
    """
    staff_only = await make_circle("staff-only")
    await seed(
        session,
        isac_org,
        vulnerability_raw(world.published, cve_status="published", modified=LATER),
        circle=staff_only,
        tlp=TLP.AMBER_STRICT,
    )

    submission = await _filed(
        session, await one_click(client, world.member.person, world.published)
    )
    shown = await client.get(f"/api/v1/submissions/{submission.id}", headers=world.member.person)

    assert submission.tlp is TLP.AMBER
    assert shown.status_code == 200, shown.text
    assert shown.json()["tlp"] == TLP.AMBER.value


# ---------------------------------------------------------------------------
# What the click builds
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-50")
async def test_a_click_is_anonymous_and_its_sighting_says_nowhere(client, session, world):
    submission = await _filed(
        session, await one_click(client, world.member.person, world.published)
    )
    raw = await session.scalar(
        select(StixObject.raw).where(StixObject.submission_id == submission.id)
    )

    assert submission.distribute_anonymously is True
    assert raw["type"] == "sighting"
    assert raw["sighting_of_ref"] == world.published
    assert "where_sighted_refs" not in raw


async def test_works_and_fails_are_agreeing_and_disagreeing_opinions(client, session, world):
    works = await _filed(
        session, await one_click(client, world.member.person, world.published, "works")
    )
    fails = await _filed(
        session, await one_click(client, world.member.person, world.published, "fails")
    )
    opinions = [
        await session.scalar(select(StixObject.raw).where(StixObject.submission_id == s.id))
        for s in (works, fails)
    ]

    assert [raw["opinion"] for raw in opinions] == ["agree", "disagree"]
    assert all(raw["object_refs"] == [world.published] for raw in opinions)


# ---------------------------------------------------------------------------
# An object the caller cannot see
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-47")
async def test_a_click_on_an_object_outside_the_callers_circles_reads_as_absent(
    client, world, make_org, make_cert, make_operator, human_headers
):
    outsider = await make_org("harbour-trust", org_type=OrgType.GSIB)
    pem, _ = await make_cert(outsider)
    operator, _seed = await make_operator(outsider)
    headers = await human_headers(operator, pem)

    hidden = await one_click(client, headers, world.published)
    absent = await one_click(client, headers, f"vulnerability--{uuid.uuid4()}")

    assert hidden.status_code == absent.status_code == 404
    assert hidden.text == absent.text


# ---------------------------------------------------------------------------
# What the ISAC sees and the member does not
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-66", "SF-49")
async def test_a_stricter_version_the_member_cannot_see_sends_the_click_to_review_unexplained(
    client, session, isac_org, make_circle, world
):
    """The ISAC's view refuses; the member is told only that an editor will look.

    A newer AMBER+STRICT version of the record sits in a circle the member is
    not in. The click, AMBER from what the member sees, is looser than it, so
    it may not be published unread -- and answering with that reason told the
    member the version existed, and its TLP. The pair is the first test in
    this module: without the hidden version the same click is published.
    """
    staff_only = await make_circle("staff-only")
    await seed(
        session,
        isac_org,
        vulnerability_raw(world.published, cve_status="published", modified=LATER),
        circle=staff_only,
        tlp=TLP.AMBER_STRICT,
    )

    response = await one_click(client, world.member.person, world.published)
    submission = await _filed(session, response)

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW
    assert "strict" not in response.text.lower()
    history = await session.execute(
        select(SubmissionTransition.to_state, SubmissionTransition.reason)
        .where(SubmissionTransition.submission_id == submission.id)
        .order_by(SubmissionTransition.id)
    )
    assert [(row.to_state, row.reason) for row in history] == [
        (SubmissionState.DRAFT, "created"),
        (SubmissionState.SUBMITTED, NEEDS_AN_EDITOR),
    ]


@pytest.mark.requirement("SF-66")
async def test_a_members_own_record_saying_published_does_not_open_the_fast_lane(
    client, session, world
):
    """Public means the ISAC's record says so, as the disclosure split reads it.

    Read from whoever's version was latest, a member's own vulnerability,
    distributed with ``cve_status: published``, opened the fast lane on itself.
    The pair is the ISAC's published record, which does (first test above).
    """
    own = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session,
        world.member.org,
        vulnerability_raw(own, cve_status="published"),
        circle=world.circle,
    )

    submission = await _filed(session, await one_click(client, world.member.person, own))

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW
    assert (await _transition_reasons(session, submission))[-1] == NOT_PUBLIC


async def _transition_reasons(session, submission: Submission) -> list[str | None]:
    return list(
        (
            await session.execute(
                select(SubmissionTransition.reason).where(
                    SubmissionTransition.submission_id == submission.id
                )
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.requirement("SF-66")
@pytest.mark.parametrize("hidden_as", ["validated", "distributed-elsewhere"])
async def test_a_newer_isac_version_no_longer_published_sends_the_click_to_review_unexplained(
    client, session, isac_org, make_circle, world, hidden_as
):
    """Public is the ISAC's current record, as the ISAC sees it, not as the member does.

    The member sees the ISAC's version saying ``published``. A newer one says
    the disclosure is back to ``reserved`` -- validated and not yet out, or out
    only to a circle the member is not in. A click is ``own_estate``, so the
    disclosure split never re-reads the record from the ISAC's view, and the
    click was published on the strength of a state the ISAC had moved on from.
    The pair is the first test in this module, with no newer version.
    """
    newer = vulnerability_raw(world.published, cve_status="reserved", modified=LATER)
    if hidden_as == "validated":
        await seed(session, isac_org, newer, circle=None, state=SubmissionState.VALIDATED)
    else:
        await seed(session, isac_org, newer, circle=await make_circle("staff-only"))

    response = await one_click(client, world.member.person, world.published)
    submission = await _filed(session, response)

    assert submission.state is SubmissionState.SUBMITTED
    assert submission.lane is SubmissionLane.REVIEW
    assert "reserved" not in response.text
    reasons = await _transition_reasons(session, submission)
    assert reasons[-1] == NEEDS_AN_EDITOR


@pytest.mark.requirement("SF-66")
async def test_the_rule_that_sent_a_click_to_review_is_kept_for_the_isac_and_logged_without_it(
    client, session, isac_org, make_circle, world, caplog
):
    """The member is told one constant reason; the ISAC keeps the real one.

    ``publish_without_review`` swallowed the refusal, so an editor looking at
    a click filed for review had nothing to say why, and no log line recorded
    the decision. The reason goes in the audit row, which only the ISAC
    reads; the log line names the submission and the kind of rule, never the
    reason, which names objects. The member's own transition history keeps
    only ``NEEDS_AN_EDITOR``.
    """
    staff_only = await make_circle("staff-only")
    await seed(
        session,
        isac_org,
        vulnerability_raw(world.published, cve_status="published", modified=LATER),
        circle=staff_only,
        tlp=TLP.AMBER_STRICT,
    )

    with caplog.at_level(logging.INFO, logger="aivs_server.services.contributions"):
        response = await one_click(client, world.member.person, world.published)
    submission = await _filed(session, response)

    kept = (
        await session.execute(
            select(AuditLog.details).where(
                AuditLog.action == AuditAction.CONTRIBUTION_SENT_TO_REVIEW,
                AuditLog.resource_id == str(submission.id),
            )
        )
    ).scalar_one()
    assert kept["lane"] == SubmissionLane.FAST.value
    assert "looser than" in kept["reason"]
    decisions = [
        record
        for record in caplog.records
        if record.name == "aivs_server.services.contributions"
        and str(submission.id) in str(vars(record))
    ]
    assert len(decisions) == 1
    assert "SubmissionError" in str(vars(decisions[0]))
    assert "strict" not in str(vars(decisions[0])).lower()
    assert world.published not in str(vars(decisions[0]))
    assert await _transition_reasons(session, submission) == [
        "created",
        NEEDS_AN_EDITOR,
    ]


@pytest.mark.requirement("SF-66", "SF-70")
def test_no_member_contribution_or_posture_route_carries_an_object_id_in_its_path(app):
    """Request lines are logged with the caller's identity and leave the platform.

    ``POST /objects/{id}/contributions`` put "firm X sighted, or tried, V at t"
    in nginx's log and the app's access log, both forwarded to the ISAC's
    collector; postures were moved off the same shape first. Only the ISAC's
    posture summary may name an object in its path: the ISAC is the caller,
    and the request says nothing of a member.
    """
    paths = {
        path
        for path, _method in walk_routes(app.routes)
        if path.startswith("/api/v1/") and ("contribution" in path or "posture" in path)
    }

    member_paths = paths - {"/api/v1/vulnerabilities/{stix_id}/posture-summary"}
    assert member_paths == {
        "/api/v1/contributions",
        "/api/v1/postures",
        "/api/v1/postures/openvex",
        "/api/v1/postures/{posture_id}",
    }


@pytest.mark.requirement("SF-66")
@pytest.mark.parametrize(
    "app_clock_offset", [dt.timedelta(0), -dt.timedelta(hours=1)], ids=["honest", "behind"]
)
async def test_a_click_published_at_once_tells_the_circle_whatever_the_app_clock_says(
    client, session, secret_box, world, monkeypatch, app_clock_offset
):
    """A fast-lane publication notifies the circle, like any distribution.

    The notifier compared a database-clock instant with its own app-clock
    "now"; on a replica running behind, the content read as not yet visible
    and nobody was told. The pair is the honest clock.
    """
    from aivs_server.auth.secretbox import SecretPurpose  # noqa: PLC0415 - this test only
    from aivs_server.db.models import Webhook, WebhookDelivery  # noqa: PLC0415 - as above
    from aivs_server.notify import events as notify_events  # noqa: PLC0415 - patched here
    from tests.unit.test_one_clock import skew_clock  # noqa: PLC0415 - shared helper

    hook_id = uuid.uuid4()
    session.add(
        Webhook(
            id=hook_id,
            org_id=world.reader.org.id,
            url="https://reader.example/aivs",
            hmac_secret_encrypted=secret_box.seal(
                "reader-secret", purpose=SecretPurpose.WEBHOOK_HMAC, subject=hook_id
            ),
            events=[],
        )
    )
    await session.commit()
    skew_clock(monkeypatch, notify_events, app_clock_offset)

    response = await one_click(client, world.member.person, world.published)

    assert response.json()["lane"] == "fast"
    queued = await session.scalar(
        select(func.count())
        .select_from(WebhookDelivery)
        .where(WebhookDelivery.webhook_id == hook_id)
    )
    assert queued == 1


async def test_a_nul_in_the_target_is_the_members_400(client, world):
    """It reached PostgreSQL in the lookup as a server error."""
    response = await client.post(
        "/api/v1/contributions",
        json={"target": "vulnerability--\u0000", "kind": "seen"},
        headers=world.member.person,
    )

    assert response.status_code == 400
