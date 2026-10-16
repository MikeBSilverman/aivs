"""Members sign in with the ISAC's identity provider over ordinary TLS (Phase M, SF-65).

Each control is a pair against a local fake IdP: the sign-in that must work
beside the one that must not. What the session may then read is pinned by the
TLP ceiling pair: up to AMBER+STRICT, never RED, never embargoed content.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from pydantic import ValidationError
from sqlalchemy import delete, func, select

from aivs_schemas.enums import (
    TLP,
    EmbargoPolicy,
    EmbargoStatus,
    OperatorRole,
    OrgStatus,
    OrgType,
    SubmissionState,
)
from aivs_server.audit.log import AuditAction
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.memberships import load_circle_grants
from aivs_server.auth.policy import (
    distribution_visibility_clause,
    tlp_ceiling,
    tlp_ceiling_clause,
    within_tlp_ceiling,
)
from aivs_server.auth.sessions import (
    SessionRejectedError,
    establish_sso_session,
    resolve_sso_session,
)
from aivs_server.config import Settings
from aivs_server.db.models import (
    AuditLog,
    Distribution,
    Embargo,
    Operator,
    OrgMailDomain,
    PortalSession,
    StixObject,
    Submission,
)
from aivs_server.main import create_app
from aivs_server.services.attribution import submissions_filed_by
from aivs_server.taxii.filters import TaxiiFilters
from aivs_server.taxii.queries import build_object_listing_query
from tests.conftest import (
    TEST_ATTRIBUTION_KEY_FILE,
    TEST_CA_CERT_FILE,
    TEST_DATABASE_URL,
    TEST_MEMBER_DATABASE_URL,
    TEST_PROXY_SECRET,
    TEST_SECRET_KEY_FILE,
    TEST_SESSION_SECRET,
    proxy_headers,
    seed_filing,
    seeded_owner_token,
)
from tests.sso_support import (
    CLIENT_ID,
    CLIENT_SECRET,
    ISSUER,
    REDIRECT_URI,
    FakeIdp,
    browser,
    sso_settings,
)

pytestmark = pytest.mark.db

MEMBER_GROUP = "grp-meridian-analysts"
STAFF_GROUP = "grp-isac-staff"


@pytest.fixture
async def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture
async def sso_app(app, settings, idp):
    """The application with member SSO configured against the fake IdP."""
    application = create_app(sso_settings(settings))
    application.state.oidc_http = idp.client()
    return application


@pytest.fixture
async def member(session, make_org, isac_org, record_mail_domain):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    org.directory_object_id = MEMBER_GROUP
    isac_org.directory_object_id = STAFF_GROUP
    await session.commit()
    await record_mail_domain(org, "meridian.test")
    return org


async def sign_in(
    sso_app, idp, *, groups=(MEMBER_GROUP,), email="analyst@meridian.test", **claims: Any
) -> Any:
    """Run the whole flow in one browser. Returns (browser, callback response, subject)."""
    subject = claims.pop("sub", f"subject-{uuid.uuid4()}")
    client = browser(sso_app)
    started = await client.get("/portal/sso/login")
    assert started.status_code == 303, started.text
    code, state = idp.authorize(
        started.headers["location"], sub=subject, groups=list(groups), email=email, **claims
    )
    finished = await client.get("/portal/sso/callback", params={"code": code, "state": state})
    return client, finished, subject


async def refused_reason(session) -> str:
    row = (
        await session.execute(
            select(AuditLog)
            .where(AuditLog.action == AuditAction.SSO_LOGIN_REFUSED)
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
    ).scalar_one()
    return row.details["reason"]


# ---------------------------------------------------------------------------
# The flow
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-65")
async def test_a_member_signs_in_and_reaches_the_portal(sso_app, idp, member, session):
    client, finished, subject = await sign_in(sso_app, idp, amr=["pwd", "otp"])
    assert finished.status_code == 200, finished.text
    dashboard = await client.get("/portal/")
    assert dashboard.status_code == 200

    stored = (await session.execute(select(PortalSession))).scalar_one()
    assert stored.cert_fingerprint is None
    assert stored.idp_subject == subject
    assert stored.amr == ["pwd", "otp"]


@pytest.mark.requirement("SF-65")
async def test_an_authorization_endpoint_off_the_issuers_origin_is_never_redirected_to(
    sso_app, idp, member, session
):
    idp.discovery_tamper = {"authorization_endpoint": "https://elsewhere.test/authorize"}
    started = await browser(sso_app).get("/portal/sso/login")
    assert started.status_code == 403
    assert "location" not in started.headers
    assert await refused_reason(session) == "authorization_endpoint_off_origin"


@pytest.mark.requirement("SF-65")
async def test_a_callback_without_the_pending_cookie_or_with_another_state_is_refused(
    sso_app, idp, member, session
):
    client = browser(sso_app)
    started = await client.get("/portal/sso/login")
    code, state = idp.authorize(
        started.headers["location"], sub="s", groups=[MEMBER_GROUP], email="a@meridian.test"
    )

    stranger = browser(sso_app)  # the code replayed into a browser that never started a login
    replayed = await stranger.get("/portal/sso/callback", params={"code": code, "state": state})
    assert replayed.status_code == 403
    assert await refused_reason(session) == "no_pending_login"

    wrong_state = await client.get("/portal/sso/callback", params={"code": code, "state": "forged"})
    assert wrong_state.status_code == 403
    assert await refused_reason(session) == "state_mismatch"


@pytest.mark.requirement("SF-65")
async def test_a_token_minted_for_another_login_is_refused_by_its_nonce(
    sso_app, idp, member, session
):
    idp.tamper = {"nonce": "a-nonce-from-another-login"}
    _client, finished, _subject = await sign_in(sso_app, idp)
    assert finished.status_code == 403
    assert await refused_reason(session) == "nonce_mismatch"


@pytest.mark.requirement("SF-65")
async def test_a_token_for_another_audience_is_refused(sso_app, idp, member, session):
    idp.tamper = {"aud": "some-other-client"}
    _client, finished, _subject = await sign_in(sso_app, idp)
    assert finished.status_code == 403
    assert await refused_reason(session) == "id_token_invalid"


@pytest.mark.requirement("SF-65")
@pytest.mark.parametrize("amr", [["pwd", "mfa"], ["pwd", "otp"], ["hwk", "pin"]])
async def test_a_sign_in_the_idp_says_used_two_factors_is_accepted(sso_app, idp, member, amr):
    _client, finished, _ = await sign_in(sso_app, idp, amr=amr)
    assert finished.status_code == 200, finished.text


@pytest.mark.requirement("SF-65")
@pytest.mark.parametrize("amr", [["pwd"], ["otp", "otp"], [], None])
async def test_a_sign_in_without_an_asserted_second_factor_is_refused(
    sso_app, idp, member, session, amr
):
    """The pair: a sign-on policy edited to password-only, or a token that
    does not say, is refused rather than trusted."""
    _client, finished, _ = await sign_in(sso_app, idp, amr=amr)
    assert finished.status_code == 403
    assert await refused_reason(session) == "second_factor_not_asserted"
    assert (await session.scalar(select(func.count()).select_from(PortalSession))) == 0


@pytest.mark.requirement("SF-65")
async def test_signing_in_rotates_the_session(sso_app, idp, member):
    client = browser(sso_app, aivs_session="planted-by-someone-else")
    started = await client.get("/portal/sso/login")
    code, state = idp.authorize(
        started.headers["location"], sub="s1", groups=[MEMBER_GROUP], email="a@meridian.test"
    )
    finished = await client.get("/portal/sso/callback", params={"code": code, "state": state})
    assert finished.status_code == 200
    assert finished.cookies.get("aivs_session") not in (None, "planted-by-someone-else")


@pytest.mark.requirement("SF-65")
async def test_signing_out_ends_the_session_on_a_page_the_public_listener_serves(
    sso_app, idp, member
):
    """Not ``/portal/login``, which nginx refuses on this listener, nor the IdP,
    which would sign the person straight back in."""
    client, _finished, _ = await sign_in(sso_app, idp)
    out = await client.post(
        "/portal/logout", data={"csrf_token": client.cookies.get("aivs_csrf", "")}
    )
    assert out.status_code == 200, out.text
    assert 'href="/portal/sso/login"' in out.text

    after = await client.get("/portal/")
    assert after.status_code == 303
    assert after.headers["location"] == "/portal/sso/login"


# ---------------------------------------------------------------------------
# The issuer decides authority
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-65")
async def test_a_member_tenant_token_carrying_a_staff_group_is_refused(
    sso_app, idp, member, session
):
    _client, refused, _subject = await sign_in(sso_app, idp, groups=(STAFF_GROUP,))
    assert refused.status_code == 403
    assert await refused_reason(session) == "staff_group_on_member_issuer"
    _client, allowed, _subject = await sign_in(
        sso_app, idp, groups=(MEMBER_GROUP,), email="b@meridian.test"
    )
    assert allowed.status_code == 200


@pytest.mark.requirement("SF-65")
async def test_a_token_naming_an_unmapped_group_grants_nothing(sso_app, idp, member, session):
    before = await session.scalar(select(func.count()).select_from(Operator))
    _client, refused, _subject = await sign_in(sso_app, idp, groups=("grp-nobody-mapped",))
    assert refused.status_code == 403
    assert await refused_reason(session) == "no_mapped_organisation"
    assert await session.scalar(select(func.count()).select_from(Operator)) == before


async def test_first_sign_in_creates_an_analyst_linked_by_issuer_and_subject(
    sso_app, idp, member, session
):
    _client, finished, subject = await sign_in(sso_app, idp, email="New.Analyst@Meridian.test")
    assert finished.status_code == 200
    created = (
        await session.execute(select(Operator).where(Operator.federated_subject == subject))
    ).scalar_one()
    assert created.org_id == member.id
    assert created.roles == [OperatorRole.ANALYST]
    assert created.password_hash is None
    assert created.email == "new.analyst@meridian.test"


async def test_with_provisioning_off_an_unknown_person_is_refused(
    app, settings, idp, member, session
):
    closed = create_app(
        sso_settings(settings).model_copy(update={"oidc_member_jit_provisioning": False})
    )
    closed.state.oidc_http = idp.client()
    _client, refused, _subject = await sign_in(closed, idp)
    assert refused.status_code == 403
    assert await refused_reason(session) == "not_provisioned"


async def test_a_person_moved_to_another_firm_does_not_carry_the_old_operator(
    sso_app, idp, member, make_org, session
):
    _client, first, subject = await sign_in(sso_app, idp)
    assert first.status_code == 200
    other = await make_org("other-member", org_type=OrgType.GSIB)
    other.directory_object_id = "grp-other"
    await session.commit()
    _client, moved, _ = await sign_in(sso_app, idp, groups=("grp-other",), sub=subject)
    assert moved.status_code == 403
    assert await refused_reason(session) == "organisation_changed"


# ---------------------------------------------------------------------------
# Whose addresses a member's IdP may link (Q41, R30)
# ---------------------------------------------------------------------------
async def operators_at(session, email: str) -> list[Operator]:
    return list((await session.scalars(select(Operator).where(Operator.email == email))).all())


@pytest.mark.requirement("SF-104")
async def test_a_member_idp_cannot_create_a_person_in_another_firms_domain(
    sso_app, idp, member, make_org, record_mail_domain, session
):
    """Before Q41 this created ``analyst@bank.test`` at Meridian, which then
    owned the address: Bank could not register its own person, and with the
    intake on, that person's mail became Meridian's drafts."""
    bank = await make_org("bank", org_type=OrgType.GSIB)
    await record_mail_domain(bank, "bank.test")

    _client, refused, _subject = await sign_in(sso_app, idp, email="analyst@bank.test")

    assert refused.status_code == 403
    assert await refused_reason(session) == "email_outside_organisation_domains"
    assert await operators_at(session, "analyst@bank.test") == []


@pytest.mark.requirement("SF-104")
async def test_a_member_idp_cannot_link_another_firms_registered_person(
    sso_app, idp, member, make_org, make_operator, record_mail_domain, session
):
    """Refused for the domain, before the existing person is even looked up."""
    bank = await make_org("bank", org_type=OrgType.GSIB)
    await record_mail_domain(bank, "bank.test")
    person, _seed = await make_operator(bank, email="analyst@bank.test")

    _client, refused, _subject = await sign_in(sso_app, idp, email="analyst@bank.test")

    assert refused.status_code == 403
    assert await refused_reason(session) == "email_outside_organisation_domains"
    await session.refresh(person)
    assert person.federated_subject is None


@pytest.mark.requirement("SF-104")
async def test_a_pre_provisioned_person_outside_the_domains_is_not_linked(
    sso_app, idp, member, make_operator, session
):
    """The domain bounds linking as well as creating: a person registered at the
    member under an address outside its domains is not taken over by whoever
    the IdP says holds that address."""
    person, _seed = await make_operator(member, email="analyst@webmail.example")

    _client, refused, _subject = await sign_in(sso_app, idp, email="analyst@webmail.example")

    assert refused.status_code == 403
    assert await refused_reason(session) == "email_outside_organisation_domains"
    await session.refresh(person)
    assert person.federated_subject is None


@pytest.mark.requirement("SF-104")
async def test_a_firm_with_no_recorded_domain_links_nobody_new(
    sso_app, idp, make_org, isac_org, session
):
    org = await make_org("unrecorded", org_type=OrgType.GSIB)
    org.directory_object_id = "grp-unrecorded"
    await session.commit()

    _client, refused, _subject = await sign_in(
        sso_app, idp, groups=("grp-unrecorded",), email="analyst@unrecorded.test"
    )

    assert refused.status_code == 403
    assert await refused_reason(session) == "email_outside_organisation_domains"


async def test_a_linked_person_signs_in_by_subject_after_the_domain_is_removed(
    sso_app, idp, member, session
):
    """The domain decides the link, once; the link is issuer and subject (§4)."""
    _client, first, subject = await sign_in(sso_app, idp)
    assert first.status_code == 200
    await session.execute(delete(OrgMailDomain).where(OrgMailDomain.domain == "meridian.test"))
    await session.commit()

    _client, again, _ = await sign_in(sso_app, idp, sub=subject)

    assert again.status_code == 200


# ---------------------------------------------------------------------------
# What the session is bound to, and where it is worth anything
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-65")
async def test_the_session_cookie_alone_without_its_device_is_refused(sso_app, idp, member):
    client, finished, _ = await sign_in(sso_app, idp)
    assert finished.status_code == 200
    stolen = browser(sso_app, aivs_session=client.cookies["aivs_session"])
    refused = await stolen.get("/portal/")
    assert refused.status_code == 303
    assert refused.headers["location"] == "/portal/sso/login"
    assert (await client.get("/portal/")).status_code == 200


@pytest.mark.requirement("SF-65")
async def test_an_sso_session_for_the_hosting_isac_is_refused_whatever_its_row_says(
    session, settings, isac_org, make_operator
):
    """Sign-in refuses the staff group first; this is the resolver's own check,
    for a row that came about some other way. The pair is the member session
    resolving in every other test here."""
    configured = sso_settings(settings)
    operator, _seed = await make_operator(isac_org, roles=(OperatorRole.ISAC_EDITOR,))
    operator.federated_issuer, operator.federated_subject = ISSUER, "staff-subject"
    now = dt.datetime.now(dt.UTC)
    established = await establish_sso_session(
        session,
        configured,
        operator=operator,
        issuer=ISSUER,
        subject="staff-subject",
        device_cookie="device",
        amr=("pwd", "mfa"),
        source_ip=None,
        user_agent=None,
        now=now,
    )
    await session.commit()

    with pytest.raises(SessionRejectedError, match="sso_staff_refused"):
        await resolve_sso_session(
            session,
            configured,
            token=established.token,
            device_cookie="device",
            request_id="r",
            source_ip=None,
            now=now,
        )


@pytest.mark.requirement("SF-65")
async def test_an_sso_session_is_not_an_api_or_taxii_credential(sso_app, idp, member):
    client, _finished, _ = await sign_in(sso_app, idp)
    bearer = {"authorization": f"Bearer {client.cookies['aivs_session']}"}
    async with browser(sso_app) as api:
        assert (await api.get("/api/v1/whoami", headers=bearer)).status_code == 401
        assert (await api.get("/taxii2/", headers=bearer)).status_code == 401


@pytest.mark.requirement("SF-65")
async def test_an_sso_session_is_worth_nothing_beside_a_certificate(
    sso_app, idp, member, make_cert, session
):
    """The dangerous direction: carried to the certificate-bound listener with
    the firm's own certificate, the session would resolve as certificate-bound
    and so without the ceiling. Each resolver refuses the other kind.

    The audited reason is asserted too: the certificate lookup behind it would
    also refuse, but as "certificate revoked", which sends whoever reads the
    audit log after a certificate that was never involved."""
    pem, _cert = await make_cert(member)
    client, _finished, _ = await sign_in(sso_app, idp)
    with_certificate = proxy_headers(pem)

    portal = await client.get("/portal/", headers=with_certificate)
    assert portal.status_code == 303
    assert portal.headers["location"] == "/portal/login"
    rejected = (
        await session.execute(
            select(AuditLog)
            .where(AuditLog.action == AuditAction.SESSION_REJECTED)
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
    ).scalar_one()
    assert rejected.details["reason"] == "session_unbound"
    bearer = {**with_certificate, "authorization": f"Bearer {client.cookies['aivs_session']}"}
    async with browser(sso_app) as api:
        assert (await api.get("/api/v1/whoami", headers=bearer)).status_code == 401


# ---------------------------------------------------------------------------
# The ceiling (SF-65): AMBER+STRICT, never RED, never embargoed content
# ---------------------------------------------------------------------------
def _ctx(method: AuthMethod) -> AuthContext:
    return AuthContext(
        org_id=uuid.uuid4(),
        org_slug="m",
        org_type=OrgType.GSIB,
        org_status=OrgStatus.ACTIVE,
        auth_method=method,
    )


@pytest.mark.parametrize(
    ("marking", "readable"),
    [
        (TLP.CLEAR, True),
        (TLP.GREEN, True),
        (TLP.AMBER, True),
        (TLP.AMBER_STRICT, True),
        (TLP.RED, False),
    ],
)
@pytest.mark.requirement("SF-65")
def test_an_sso_session_reads_up_to_amber_strict_and_never_red(marking, readable):
    assert tlp_ceiling(_ctx(AuthMethod.SSO_SESSION)) is TLP.AMBER_STRICT
    assert within_tlp_ceiling(_ctx(AuthMethod.SSO_SESSION), marking) is readable
    assert within_tlp_ceiling(_ctx(AuthMethod.PORTAL_SESSION), marking) is True


async def _distributed(
    session, org, circle, marking: TLP, *, embargoed: bool = False
) -> Submission:
    now = dt.datetime.now(dt.UTC)
    submission = Submission(
        state=SubmissionState.DISTRIBUTED,
        tlp=marking,
        discovery_scope="own_product",
        title=f"{marking} content",
        distributed_at=now,
    )
    await seed_filing(session, submission, org)
    await session.flush()
    stix_id = f"vulnerability--{uuid.uuid4()}"
    obj = StixObject(
        stix_id=stix_id,
        modified=now,
        created=now,
        type="vulnerability",
        spec_version="2.1",
        submission_id=submission.id,
        raw={"type": "vulnerability"},
        owner_token=await seeded_owner_token(session, submission, stix_id),
    )
    session.add(obj)
    await session.flush()
    session.add(
        Distribution(
            stix_object_id=obj.id,
            circle_id=circle.id,
            submission_id=submission.id,
            date_added=now - dt.timedelta(minutes=1),
        )
    )
    if embargoed:
        session.add(
            Embargo(
                submission_id=submission.id,
                policy=EmbargoPolicy.TIMER,
                status=EmbargoStatus.RELEASED,
                release_at=now - dt.timedelta(minutes=1),
                released_at=now - dt.timedelta(minutes=1),
            )
        )
    await session.commit()
    return submission


@pytest.mark.requirement("SF-65")
async def test_sso_reads_amber_strict_but_not_red_or_embargoed_content(
    session, member, make_circle, join_circle
):
    circle = await make_circle("sso-circle")
    await join_circle(member, circle)
    strict = await _distributed(session, member, circle, TLP.AMBER_STRICT)
    red = await _distributed(session, member, circle, TLP.RED)
    embargoed = await _distributed(session, member, circle, TLP.AMBER, embargoed=True)
    grants = await load_circle_grants(session, member.id)
    now = dt.datetime.now(dt.UTC)

    def ctx(method: AuthMethod) -> AuthContext:
        return AuthContext(
            org_id=member.id,
            org_slug=member.slug,
            org_type=member.org_type,
            org_status=OrgStatus.ACTIVE,
            auth_method=method,
            circles=grants,
        )

    async def readable(method: AuthMethod) -> set[uuid.UUID]:
        rows = await session.execute(
            select(Submission.id)
            .join(Distribution, Distribution.submission_id == Submission.id)
            .where(distribution_visibility_clause(ctx(method), now))
        )
        return set(rows.scalars())

    assert await readable(AuthMethod.SSO_SESSION) == {strict.id}
    assert await readable(AuthMethod.PORTAL_SESSION) == {strict.id, red.id, embargoed.id}


@pytest.mark.requirement("SF-65")
async def test_the_taxii_listing_applies_the_ceiling_it_is_given(
    session, member, make_circle, join_circle
):
    """No SSO session reaches TAXII today (nginx, and the bearer refusal);
    the listing takes the ceiling anyway, so that stays true the day one can."""
    circle = await make_circle("sso-taxii-circle")
    await join_circle(member, circle)
    strict = await _distributed(session, member, circle, TLP.AMBER_STRICT)
    red = await _distributed(session, member, circle, TLP.RED)
    embargoed = await _distributed(session, member, circle, TLP.AMBER, embargoed=True)
    grants = await load_circle_grants(session, member.id)
    now = dt.datetime.now(dt.UTC)

    async def listed(method: AuthMethod) -> set[uuid.UUID]:
        ctx = AuthContext(
            org_id=member.id,
            org_slug=member.slug,
            org_type=member.org_type,
            org_status=OrgStatus.ACTIVE,
            auth_method=method,
            circles=grants,
        )
        query = build_object_listing_query(
            circle_id=circle.id,
            intervals=grants[circle.id].intervals,
            ceiling=tlp_ceiling_clause(ctx),
            filters=TaxiiFilters(),
            now=now,
            cursor=None,
            limit=100,
        )
        return {row.submission_id for row in (await session.execute(query))}

    assert await listed(AuthMethod.SSO_SESSION) == {strict.id}
    assert await listed(AuthMethod.PORTAL_SESSION) == {strict.id, red.id, embargoed.id}


# ---------------------------------------------------------------------------
# Configuration, and the ceiling on a member's own records
# ---------------------------------------------------------------------------
def _staging(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": "staging",
        "public_base_url": "https://aivs.test",
        "database_url": TEST_DATABASE_URL,
        "member_database_url": TEST_MEMBER_DATABASE_URL,
        "proxy_shared_secret": TEST_PROXY_SECRET,
        "session_secret": TEST_SESSION_SECRET,
        "attribution_key_file": TEST_ATTRIBUTION_KEY_FILE,
        "issuing_ca_certificate_file": TEST_CA_CERT_FILE,
        "secret_encryption_key_file": TEST_SECRET_KEY_FILE,
        "oidc_member_issuer": ISSUER,
        "oidc_member_client_id": CLIENT_ID,
        "oidc_member_client_secret": CLIENT_SECRET,
        "oidc_member_redirect_uri": REDIRECT_URI,
    }
    return Settings(**(base | overrides))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "unsafe",
    [
        {"oidc_member_issuer": "http://idp.member-tenant.test"},
        {"oidc_member_client_secret": None},
        {"oidc_member_redirect_uri": "http://members.aivs.test/portal/sso/callback"},
    ],
)
def test_outside_dev_a_half_configured_issuer_refuses_to_start(unsafe):
    _staging()  # the complete configuration starts
    with pytest.raises(ValidationError):
        _staging(**unsafe)


@pytest.mark.requirement("SF-65")
async def test_an_sso_session_cannot_open_its_own_firms_red_filing(sso_app, idp, member, session):
    client, _finished, _ = await sign_in(sso_app, idp)
    filings = {}
    for marking in (TLP.AMBER, TLP.RED):
        filing = Submission(
            state=SubmissionState.DRAFT,
            tlp=marking,
            discovery_scope="own_product",
            title=f"{marking} filing",
        )
        await seed_filing(session, filing, member)
        await session.commit()
        filings[marking] = filing.id
    assert (await client.get(f"/portal/submissions/{filings[TLP.AMBER]}")).status_code == 200
    assert (await client.get(f"/portal/submissions/{filings[TLP.RED]}")).status_code == 404


async def _own_filings(session, member, make_circle, join_circle) -> dict[str, uuid.UUID]:
    """The firm's own distributed filings: one within the ceiling, one RED, one embargoed."""
    circle = await make_circle("own-filings-circle")
    await join_circle(member, circle)
    return {
        "strict": (await _distributed(session, member, circle, TLP.AMBER_STRICT)).id,
        "red": (await _distributed(session, member, circle, TLP.RED)).id,
        "embargoed": (await _distributed(session, member, circle, TLP.AMBER, embargoed=True)).id,
    }


@pytest.mark.requirement("SF-65")
async def test_an_sso_session_lists_only_its_firms_filings_within_the_ceiling(
    sso_app, idp, member, session, make_circle, join_circle
):
    """A RED filing's title is RED content: the list may not show it either."""
    client, _finished, _ = await sign_in(sso_app, idp)
    filings = await _own_filings(session, member, make_circle, join_circle)

    listed = await client.get("/portal/submissions")
    assert listed.status_code == 200
    assert str(filings["strict"]) in listed.text
    assert str(filings["red"]) not in listed.text
    assert str(filings["embargoed"]) not in listed.text
    assert "certificate to see the rest." in listed.text


@pytest.mark.requirement("SF-65")
async def test_an_sso_session_cannot_open_its_own_firms_embargoed_filing(
    sso_app, idp, member, session, make_circle, join_circle
):
    client, _finished, _ = await sign_in(sso_app, idp)
    filings = await _own_filings(session, member, make_circle, join_circle)
    assert (await client.get(f"/portal/submissions/{filings['strict']}")).status_code == 200
    assert (await client.get(f"/portal/submissions/{filings['embargoed']}")).status_code == 404


@pytest.mark.requirement("SF-65")
# A member's own list is read staff side, on the process's staff sessionmaker.
@pytest.mark.usefixtures("app")
async def test_the_certificate_view_of_the_same_filings_lists_them_all(
    member, session, make_circle, join_circle
):
    """The pair: the ceiling is the SSO session's, not the firm's."""
    filings = await _own_filings(session, member, make_circle, join_circle)
    ctx = AuthContext(
        org_id=member.id,
        org_slug=member.slug,
        org_type=member.org_type,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.PORTAL_SESSION,
    )
    visible = set(
        (
            await session.execute(
                select(Submission.id).where(
                    Submission.id.in_(await submissions_filed_by(member.id)),
                    tlp_ceiling_clause(ctx),
                )
            )
        ).scalars()
    )
    assert visible == set(filings.values())


# ---------------------------------------------------------------------------
# The IdP being down or wrong: each refusal says which check refused
# ---------------------------------------------------------------------------
def _status(code: int, body: dict[str, Any] | None = None):
    return lambda _request: httpx.Response(code, json=body or {})


def _unreachable(request: httpx.Request) -> httpx.Response:
    message = "connection refused"
    raise httpx.ConnectError(message, request=request)


def _foreign_jwks(idp: FakeIdp):
    def respond(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"keys": [{**idp.jwk(), "kid": "another-key"}]})

    return respond


def _unsigned_token(idp: FakeIdp):
    def respond(request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        _challenge, claims = idp.codes.pop(form["code"])
        now = dt.datetime.now(dt.UTC)
        payload = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "s",
            "iat": now,
            "exp": now + dt.timedelta(minutes=5),
            "amr": ["pwd", "mfa"],
            **claims,
        }
        return httpx.Response(200, json={"id_token": jwt.encode(payload, None, algorithm="none")})

    return respond


def _discovery_failure(reason: str) -> dict[str, Any]:
    """Failures seen at the start: discovery is read before the browser is sent off."""
    path = "/.well-known/openid-configuration"
    return {
        "discovery_unavailable": {path: _status(503)},
        "discovery_incomplete": {path: _status(200, {"issuer": ISSUER})},
        "idp_unreachable": {path: _unreachable},
    }[reason]


def _callback_failure(reason: str, idp: FakeIdp) -> dict[str, Any]:
    """Failures seen at the callback, after the person signed in at the IdP."""
    return {
        "token_exchange_refused": {"/token": _status(400, {"error": "invalid_grant"})},
        "no_id_token": {"/token": _status(200, {"token_type": "Bearer"})},
        "id_token_malformed": {"/token": _status(200, {"id_token": "not-a-jwt"})},
        "jwks_unavailable": {"/jwks": _status(503)},
        "jwks_invalid": {"/jwks": _status(200, {"keys": [{"kty": "nonsense"}]})},
        "signing_key_unknown": {"/jwks": _foreign_jwks(idp)},
    }[reason]


DISCOVERY_FAILURES = ["discovery_incomplete", "discovery_unavailable", "idp_unreachable"]
CALLBACK_FAILURES = [
    "id_token_malformed",
    "jwks_invalid",
    "jwks_unavailable",
    "no_id_token",
    "signing_key_unknown",
    "token_exchange_refused",
]


@pytest.mark.requirement("SF-65")
@pytest.mark.parametrize("reason", DISCOVERY_FAILURES)
async def test_an_idp_that_cannot_be_discovered_signs_nobody_in(
    sso_app, idp, member, session, reason
):
    idp.overrides = _discovery_failure(reason)
    started = await browser(sso_app).get("/portal/sso/login")
    assert started.status_code == 403
    assert await refused_reason(session) == reason


@pytest.mark.requirement("SF-65")
async def test_a_discovery_document_naming_another_issuer_signs_nobody_in(
    sso_app, idp, member, session
):
    idp.discovery_tamper = {"issuer": "https://idp.elsewhere.test"}
    started = await browser(sso_app).get("/portal/sso/login")
    assert started.status_code == 403
    assert await refused_reason(session) == "discovery_issuer_mismatch"


@pytest.mark.requirement("SF-65")
@pytest.mark.parametrize("reason", CALLBACK_FAILURES)
async def test_a_token_that_cannot_be_redeemed_or_verified_signs_nobody_in(
    sso_app, idp, member, session, reason
):
    client = browser(sso_app)
    started = await client.get("/portal/sso/login")
    code, state = idp.authorize(started.headers["location"], sub="s", groups=[MEMBER_GROUP])
    idp.overrides = _callback_failure(reason, idp)
    finished = await client.get("/portal/sso/callback", params={"code": code, "state": state})
    assert finished.status_code == 403
    assert await refused_reason(session) == reason
    assert (await session.scalar(select(func.count()).select_from(PortalSession))) == 0


@pytest.mark.requirement("SF-65")
async def test_an_unsigned_token_is_refused(sso_app, idp, member, session):
    client = browser(sso_app)
    started = await client.get("/portal/sso/login")
    code, state = idp.authorize(started.headers["location"], sub="s", groups=[MEMBER_GROUP])
    idp.overrides = {"/token": _unsigned_token(idp)}
    finished = await client.get("/portal/sso/callback", params={"code": code, "state": state})
    assert finished.status_code == 403
    assert await refused_reason(session) == "signing_key_unknown"


@pytest.mark.requirement("SF-65")
async def test_a_forged_pending_login_cookie_is_refused(sso_app, idp, member, session):
    client = browser(sso_app)
    started = await client.get("/portal/sso/login")
    code, state = idp.authorize(started.headers["location"], sub="s", groups=[MEMBER_GROUP])
    client.cookies.set("aivs_sso_pending", f"{state}.forged", path="/portal/sso")
    finished = await client.get("/portal/sso/callback", params={"code": code, "state": state})
    assert finished.status_code == 403
    assert await refused_reason(session) == "pending_login_invalid_or_expired"


async def test_a_single_group_given_as_a_string_still_maps(sso_app, idp, member):
    """Some IdPs send a one-element claim as a bare string."""
    client = browser(sso_app)
    started = await client.get("/portal/sso/login")
    code, state = idp.authorize(
        started.headers["location"], sub="s", groups=MEMBER_GROUP, email="a@meridian.test"
    )
    finished = await client.get("/portal/sso/callback", params={"code": code, "state": state})
    assert finished.status_code == 200, finished.text


# ---------------------------------------------------------------------------
# What the resolver re-checks on every request
# ---------------------------------------------------------------------------
@pytest.fixture
async def sso_row(session, settings, member, make_operator):
    """A live SSO session for a linked member operator: (settings, token, row)."""
    configured = sso_settings(settings)
    operator, _seed = await make_operator(member)
    operator.federated_issuer, operator.federated_subject = ISSUER, "member-subject"
    established = await establish_sso_session(
        session,
        configured,
        operator=operator,
        issuer=ISSUER,
        subject="member-subject",
        device_cookie="device",
        amr=("pwd", "mfa"),
        source_ip=None,
        user_agent=None,
        now=dt.datetime.now(dt.UTC),
    )
    await session.commit()
    row = (await session.execute(select(PortalSession))).scalar_one()
    return configured, established.token, row, operator


async def _resolve(session, configured, token, *, now=None):
    return await resolve_sso_session(
        session,
        configured,
        token=token,
        device_cookie="device",
        request_id="r",
        source_ip=None,
        now=now or dt.datetime.now(dt.UTC),
    )


@pytest.mark.requirement("SF-65")
async def test_the_session_resolves_as_established(session, sso_row):
    """The pair for the refusals below."""
    configured, token, _row, _operator = sso_row
    ctx, _csrf = await _resolve(session, configured, token)
    assert ctx.auth_method is AuthMethod.SSO_SESSION


@pytest.mark.requirement("SF-65")
async def test_a_session_from_an_issuer_no_longer_configured_is_refused(session, sso_row, settings):
    _configured, token, _row, _operator = sso_row
    moved = sso_settings(settings).model_copy(
        update={"oidc_member_issuer": "https://idp.new-tenant.test"}
    )
    with pytest.raises(SessionRejectedError, match="sso_issuer_not_trusted"):
        await _resolve(session, moved, token)


@pytest.mark.requirement("SF-65")
async def test_a_session_past_its_maximum_age_is_refused_whatever_its_expiry_says(session, sso_row):
    configured, token, row, _operator = sso_row
    later = row.created_at + dt.timedelta(minutes=configured.sso_session_max_age_minutes)
    row.expires_at = later + dt.timedelta(days=1)
    row.last_seen_at = later
    await session.commit()
    with pytest.raises(SessionRejectedError, match="sso_max_age"):
        await _resolve(session, configured, token, now=later)


@pytest.mark.requirement("SF-65")
async def test_a_session_whose_operator_was_relinked_is_refused(session, sso_row):
    configured, token, _row, operator = sso_row
    operator.federated_subject = "someone-else"
    await session.commit()
    with pytest.raises(SessionRejectedError, match="sso_identity_changed"):
        await _resolve(session, configured, token)


@pytest.mark.requirement("SF-65")
async def test_no_sso_session_is_established_for_an_organisation_that_has_left(
    session, settings, member, make_operator
):
    """Sign-in resolved the organisation as active; offboarding committed before
    the session row. The session refuses under the organisation's lock, as a
    certificate-bound one does (``establish_session``); the pair is
    ``sso_row``, which establishes one for the same, still active, firm."""
    operator, _seed = await make_operator(member)
    operator.federated_issuer, operator.federated_subject = ISSUER, "leaver-subject"
    member.status = OrgStatus.OFFBOARDED
    await session.commit()

    with pytest.raises(SessionRejectedError, match="org_not_active"):
        await establish_sso_session(
            session,
            sso_settings(settings),
            operator=operator,
            issuer=ISSUER,
            subject="leaver-subject",
            device_cookie="device",
            amr=("pwd", "mfa"),
            source_ip=None,
            user_agent=None,
            now=dt.datetime.now(dt.UTC),
        )
    await session.rollback()
    assert (await session.execute(select(PortalSession))).scalars().all() == []
