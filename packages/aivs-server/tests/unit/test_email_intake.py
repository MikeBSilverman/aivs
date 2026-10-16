"""The email door: a registered person's message makes a draft, and nothing else does (SF-93).

Every refusal is asserted by the reason its audit row names, not only by the
draft that did not appear: a message refused for the wrong reason would pass
a test that looked only for the absence (CLAUDE.md section 2).
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import DataError, DBAPIError

from aivs_schemas.enums import (
    TLP,
    OperatorRole,
    OrgStatus,
    OrgType,
    SubmissionSource,
    SubmissionState,
)
from aivs_server.audit.log import AuditAction
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.policy import EMAIL_FILER_ORG_TYPES, tlp_ceiling
from aivs_server.db.models import (
    AuditLog,
    InboundEmail,
    InstanceControl,
    StixObject,
    Submission,
    SubmissionTransition,
)
from aivs_server.services import email_intake
from aivs_server.services.attribution import is_submitted_by
from aivs_server.services.contributions import SHORTCUT_LANE_ORG_TYPES
from aivs_server.services.email_intake import MailIntake, read_mailbox, receive_message
from aivs_server.services.imap_mailbox import MailboxLogin
from tests.unit.test_email_message import OURS, PASS, raw_message

pytestmark = pytest.mark.db

ALICE = "alice@bank.test"


def intake(*, hourly_limit: int = 10, max_message_bytes: int = 1_000_000) -> MailIntake:
    return MailIntake(
        login=MailboxLogin(
            host="imap.isac.test",
            port=993,
            username="intake",
            password="unused",
            mailbox="INBOX",
            timeout_seconds=5,
        ),
        authserv_id=OURS,
        accepted_folder="AIVS/accepted",
        refused_folder="AIVS/refused",
        max_message_bytes=max_message_bytes,
        hourly_limit=hourly_limit,
    )


class FakeMailbox:
    """The intake's mailbox interface over a dict, recording what was done to it."""

    def __init__(self, messages: dict[str, bytes], sizes: dict[str, int] | None = None) -> None:
        self.messages = dict(messages)
        self.sizes = sizes or {}
        self.fetched: list[str] = []
        self.moved: dict[str, str] = {}

    def uids(self) -> list[str]:
        return list(self.messages)

    def size(self, uid: str) -> int:
        return self.sizes.get(uid, len(self.messages[uid]))

    def fetch(self, uid: str) -> bytes:
        self.fetched.append(uid)
        return self.messages[uid]

    def fetch_header(self, uid: str) -> bytes:
        return self.messages[uid].split(b"\n\n", 1)[0]

    def move(self, uid: str, folder: str) -> None:
        self.moved[uid] = folder
        del self.messages[uid]


def sessions_of(session):
    @asynccontextmanager
    async def _sessions():
        yield session

    return _sessions


@pytest.fixture
async def bank(make_org, record_mail_domain):
    org = await make_org("bank", org_type=OrgType.GSIB)
    await record_mail_domain(org, "bank.test")
    return org


@pytest.fixture
async def alice(bank, make_operator):
    operator, _ = await make_operator(bank, email=ALICE)
    return operator


async def receive(session, attribution_key, raw: bytes, *, hourly_limit: int = 10) -> str:
    outcome = await receive_message(
        session,
        raw,
        intake=intake(hourly_limit=hourly_limit),
        key=attribution_key,
        now=dt.datetime.now(dt.UTC),
    )
    await session.commit()
    return outcome


async def audit_rows(session, action: str) -> list[AuditLog]:
    return list((await session.scalars(select(AuditLog).where(AuditLog.action == action))).all())


async def submissions(session) -> list[Submission]:
    return list((await session.scalars(select(Submission))).all())


async def refused_for(session) -> list[str]:
    return [
        row.details["reason"] for row in await audit_rows(session, AuditAction.EMAIL_INTAKE_REFUSED)
    ]


# ---------------------------------------------------------------------------
# The door
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-93")
async def test_a_registered_persons_message_becomes_their_organisations_draft_and_nothing_more(
    session, attribution_key, bank, alice
):
    assert await receive(session, attribution_key, raw_message()) == "accepted"

    [draft] = await submissions(session)
    assert draft.state is SubmissionState.DRAFT
    assert draft.source is SubmissionSource.MEMBER
    assert draft.tlp is TLP.AMBER_STRICT
    assert draft.title == "Prompt injection in the agent gateway"
    assert draft.summary.startswith("We saw it in our estate.")
    assert is_submitted_by(attribution_key, draft, bank.id)
    [created] = (
        await session.scalars(
            select(SubmissionTransition).where(SubmissionTransition.submission_id == draft.id)
        )
    ).all()
    assert created.actor_operator_id == alice.id
    [made] = await audit_rows(session, AuditAction.SUBMISSION_CREATED)
    assert made.details["via"] == "email"
    [accepted] = await audit_rows(session, AuditAction.EMAIL_INTAKE_ACCEPTED)
    assert accepted.actor_id == str(alice.id)
    assert accepted.details["reason"] is None


@pytest.mark.requirement("SF-85")
async def test_an_emailed_draft_is_anonymous_as_every_members_filing_is(
    session, attribution_key, alice
):
    """The email door has no way to ask for credit, so it takes the member's
    default: anonymous, as the API with the field left out does (Phase P exit)."""
    assert await receive(session, attribution_key, raw_message()) == "accepted"

    [draft] = await submissions(session)
    assert draft.distribute_anonymously is True
    [made] = await audit_rows(session, AuditAction.SUBMISSION_CREATED)
    assert made.details["anonymous"] is True


@pytest.mark.requirement("SF-93")
@pytest.mark.parametrize(
    ("stamps", "why"),
    [
        ((f"{OURS}; dmarc=fail header.from=bank.test", PASS), "a forged pass below our fail"),
        ((PASS.replace(OURS, "mx.elsewhere.test"),), "another server's word"),
        ((PASS.replace("header.from=bank.test", "header.from=other.test"),), "misaligned"),
        ((), "no stamp"),
    ],
    ids=["forged-pass-below", "other-server", "misaligned", "no-stamp"],
)
async def test_a_spoofed_sender_files_nothing(session, attribution_key, alice, stamps, why):
    assert await receive(session, attribution_key, raw_message(stamps=stamps)) == "refused", why

    assert await submissions(session) == []
    assert await refused_for(session) == ["unauthenticated"]
    [refusal] = await audit_rows(session, AuditAction.EMAIL_INTAKE_REFUSED)
    # The From of a refused message is the impersonated person: never recorded.
    assert ALICE not in str(vars(refusal))
    assert refusal.org_id is None


@pytest.mark.requirement("SF-93")
@pytest.mark.parametrize("status", [OrgStatus.SUSPENDED, OrgStatus.QUARANTINED, OrgStatus.PENDING])
async def test_a_registered_person_at_an_organisation_that_may_not_transact_files_nothing(
    session, attribution_key, bank, alice, status
):
    bank.status = status
    await session.commit()

    assert await receive(session, attribution_key, raw_message()) == "refused"

    assert await submissions(session) == []
    assert await refused_for(session) == ["organisation_inactive"]


@pytest.mark.requirement("SF-93")
async def test_an_unregistered_address_files_nothing(session, attribution_key, alice):
    raw = raw_message(sender="carol@bank.test")

    assert await receive(session, attribution_key, raw) == "refused"

    assert await submissions(session) == []
    assert await refused_for(session) == ["unknown_sender"]


@pytest.mark.requirement("SF-93")
@pytest.mark.parametrize(
    "who",
    ["auditor", "isac_staff", "isac_role_only", "deactivated", "access_ended", "automation"],
)
async def test_a_person_who_may_not_draft_files_nothing(
    session, attribution_key, make_org, make_operator, who
):
    org_type = {"isac_staff": OrgType.ADMIN, "automation": OrgType.AUTOMATION}.get(
        who, OrgType.GSIB
    )
    org = await make_org("bank", org_type=org_type)
    roles = {
        "auditor": (OperatorRole.AUDITOR,),
        "isac_staff": (OperatorRole.ANALYST,),
        # A member organisation's account holding only an ISAC role: no
        # member role to draft with.
        "isac_role_only": (OperatorRole.ISAC_ANALYST,),
    }.get(who, (OperatorRole.ANALYST,))
    now = dt.datetime.now(dt.UTC)
    # An auditor's role always has an end date (the operators check); a past
    # one is an engagement that is over.
    ended = {"access_ended": now - dt.timedelta(days=1), "auditor": now + dt.timedelta(days=30)}
    expires = ended.get(who)
    operator, _ = await make_operator(org, email=ALICE, roles=roles, role_expires_at=expires)
    if who == "deactivated":
        operator.is_active = False
        await session.commit()

    assert await receive(session, attribution_key, raw_message()) == "refused"

    assert await submissions(session) == []
    assert await refused_for(session) == ["not_permitted"]


# ---------------------------------------------------------------------------
# Whose domain (Q41, R30)
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-104")
async def test_a_person_registered_in_another_firms_domain_files_nothing(
    session, attribution_key, bank, make_org, make_operator, record_mail_domain
):
    """A firm that registers another firm's person files nothing in that person's name.

    Bank holds ``bank.test``; Meridian has registered ``alice@bank.test`` as its
    own analyst (an operator's mistake, or a member IdP's claim). Alice's mail
    carries an aligned pass for ``bank.test``, so before Q41 it became
    Meridian's draft, which Meridian can read.
    """
    meridian = await make_org("meridian", org_type=OrgType.GSIB)
    await record_mail_domain(meridian, "meridian.test")
    await make_operator(meridian, email=ALICE)

    assert await receive(session, attribution_key, raw_message()) == "refused"

    assert await submissions(session) == []
    assert await refused_for(session) == ["outside_organisation_domains"]
    [refusal] = await audit_rows(session, AuditAction.EMAIL_INTAKE_REFUSED)
    assert refusal.org_id == meridian.id


@pytest.mark.requirement("SF-104")
async def test_an_organisation_with_no_recorded_domain_takes_no_mail(
    session, attribution_key, make_org, make_operator
):
    """Fail closed: nobody having said which domains are a firm's is not "all of them"."""
    org = await make_org("bank", org_type=OrgType.GSIB)
    await make_operator(org, email=ALICE)

    assert await receive(session, attribution_key, raw_message()) == "refused"

    assert await submissions(session) == []
    assert await refused_for(session) == ["outside_organisation_domains"]


@pytest.mark.requirement("SF-104")
async def test_a_subdomain_is_not_its_parents(session, attribution_key, bank, make_operator):
    """Exact match: each domain the intake accepts is one the ISAC wrote down."""
    await make_operator(bank, email="alice@mail.bank.test")
    stamp = PASS.replace("header.from=bank.test", "header.from=mail.bank.test")
    raw = raw_message(sender="Alice <alice@mail.bank.test>", stamps=(stamp,))

    assert await receive(session, attribution_key, raw) == "refused"

    assert await refused_for(session) == ["outside_organisation_domains"]


@pytest.mark.requirement("SF-104")
async def test_an_address_in_the_domain_matches_whatever_its_case(
    session, attribution_key, bank, alice
):
    raw = raw_message(sender="Alice <Alice@BANK.Test>").replace(
        b"header.from=bank.test", b"header.from=BANK.Test"
    )

    assert await receive(session, attribution_key, raw) == "accepted"


@pytest.mark.requirement("SF-93")
async def test_an_organisations_email_drafts_stop_at_its_hourly_allowance(
    session, attribution_key, alice
):
    outcomes = [
        await receive(session, attribution_key, raw_message(), hourly_limit=2) for _ in range(3)
    ]

    assert outcomes == ["accepted", "accepted", "refused"]
    assert len(await submissions(session)) == 2
    assert await refused_for(session) == ["rate_limited"]


@pytest.mark.requirement("SF-93")
async def test_a_message_read_twice_is_filed_once(session, attribution_key, alice):
    raw = raw_message()

    assert await receive(session, attribution_key, raw) == "accepted"
    assert await receive(session, attribution_key, raw) == "accepted"

    assert len(await submissions(session)) == 1
    assert len(await audit_rows(session, AuditAction.EMAIL_INTAKE_ACCEPTED)) == 1
    assert await session.scalar(select(func.count()).select_from(InboundEmail)) == 1


@pytest.mark.requirement("SF-93")
async def test_a_second_reader_that_missed_the_first_ones_record_files_nothing(
    session, attribution_key, alice, monkeypatch
):
    """Two processes polling one mailbox: both check before either commits.

    The early check is only a fast path; the claim on the message's digest is
    what stops the second draft, so the second reader's check is made to miss.
    """
    raw = raw_message()
    assert await receive(session, attribution_key, raw) == "accepted"
    real = email_intake._recorded_outcome
    checks = 0

    async def first_check_misses(session, digest):
        nonlocal checks
        checks += 1
        return None if checks == 1 else await real(session, digest)

    monkeypatch.setattr(email_intake, "_recorded_outcome", first_check_misses)

    assert await receive(session, attribution_key, raw) == "accepted"

    assert len(await submissions(session)) == 1
    assert len(await audit_rows(session, AuditAction.EMAIL_INTAKE_ACCEPTED)) == 1


# ---------------------------------------------------------------------------
# The draft's content
# ---------------------------------------------------------------------------
def a_vulnerability() -> dict:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": "2026-08-01T00:00:00.000Z",
        "modified": "2026-08-01T00:00:00.000Z",
        "name": "Prompt injection in the agent gateway",
    }


async def test_an_attached_bundle_is_filed_with_the_draft(session, attribution_key, alice):
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [a_vulnerability()]}
    raw = raw_message(attachments=(("findings.json", json.dumps(bundle).encode()),))

    assert await receive(session, attribution_key, raw) == "accepted"

    [draft] = await submissions(session)
    stored = await session.scalar(
        select(func.count()).select_from(StixObject).where(StixObject.submission_id == draft.id)
    )
    assert stored == 1


async def test_a_refused_bundle_leaves_a_draft_of_the_text_saying_why(
    session, attribution_key, alice
):
    broken = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [{"type": "vulnerability"}],
    }
    raw = raw_message(attachments=(("findings.json", json.dumps(broken).encode()),))

    assert await receive(session, attribution_key, raw) == "accepted"

    [draft] = await submissions(session)
    assert "We saw it in our estate." in draft.summary
    assert "The attached bundle was not filed" in draft.summary
    stored = await session.scalar(
        select(func.count()).select_from(StixObject).where(StixObject.submission_id == draft.id)
    )
    assert stored == 0


@pytest.mark.requirement("SF-93")
def test_the_email_way_in_reads_below_red():
    ctx = AuthContext(
        org_id=uuid.uuid4(),
        org_slug="bank",
        org_type=OrgType.GSIB,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.EMAIL,
        operator_id=uuid.uuid4(),
        operator_roles=frozenset({OperatorRole.ANALYST}),
    )
    assert tlp_ceiling(ctx) is TLP.AMBER_STRICT


def test_the_organisations_that_may_email_a_draft_are_the_members():
    assert EMAIL_FILER_ORG_TYPES == SHORTCUT_LANE_ORG_TYPES


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-93")
async def test_each_message_is_moved_to_the_folder_for_its_outcome(session, attribution_key, alice):
    mailbox = FakeMailbox(
        {
            "1": raw_message(),
            "2": raw_message(stamps=()),
            "3": raw_message(),
        },
        sizes={"3": 5_000_000},
    )

    read = await read_mailbox(
        mailbox,
        intake=intake(max_message_bytes=1_000_000),
        key=attribution_key,
        sessions=sessions_of(session),
    )

    assert read == 3
    assert mailbox.moved == {"1": "AIVS/accepted", "2": "AIVS/refused", "3": "AIVS/refused"}
    assert "3" not in mailbox.fetched
    assert sorted(await refused_for(session)) == ["too_large", "unauthenticated"]
    assert len(await submissions(session)) == 1


@pytest.mark.requirement("SF-93")
async def test_nothing_is_read_while_distribution_is_paused(session, attribution_key, alice):
    await session.merge(InstanceControl(id=1, distribution_paused=True))
    await session.commit()
    mailbox = FakeMailbox({"1": raw_message()})

    read = await read_mailbox(
        mailbox, intake=intake(), key=attribution_key, sessions=sessions_of(session)
    )

    assert read == 0
    assert mailbox.moved == {}
    assert await submissions(session) == []


# ---------------------------------------------------------------------------
# Messages that must not stop the intake (T1's review)
# ---------------------------------------------------------------------------
def hostile(header_lines: bytes) -> bytes:
    stamp = PASS.encode()
    unique = uuid.uuid4().hex.encode()
    return (
        b"Authentication-Results: "
        + stamp
        + b"\r\n"
        + header_lines
        + b"Subject: s\r\nMessage-ID: <"
        + unique
        + b"@x>\r\n\r\nbody\r\n"
    )


@pytest.mark.requirement("SF-93")
@pytest.mark.parametrize(
    "header_lines",
    [
        b"From: x:;y\r\n",
        b"From: alice@bank.test\r\nContent-Type: text/plain; charset=x-nope\r\n",
    ],
    ids=["group-from", "unknown-charset"],
)
async def test_a_message_the_parser_cannot_read_is_refused_and_moved_not_left_first(
    session, attribution_key, alice, header_lines
):
    mailbox = FakeMailbox({"1": hostile(header_lines), "2": raw_message()})

    read = await read_mailbox(
        mailbox, intake=intake(), key=attribution_key, sessions=sessions_of(session)
    )

    assert read == 2
    assert mailbox.moved == {"1": "AIVS/refused", "2": "AIVS/accepted"}
    assert await refused_for(session) == ["unreadable"]


@pytest.mark.requirement("SF-93")
async def test_a_message_left_in_place_does_not_use_up_the_runs_batch(
    session, attribution_key, alice, monkeypatch
):
    stuck = raw_message(subject="stuck")
    real = email_intake.receive_message

    async def storing_fails_for_one(session, raw, **kwargs: Any):
        if raw == stuck:
            statement = "INSERT ..."
            raise DBAPIError(statement, {}, Exception("connection lost"))
        return await real(session, raw, **kwargs)

    monkeypatch.setattr(email_intake, "receive_message", storing_fails_for_one)
    monkeypatch.setattr(email_intake, "_BATCH", 1)
    mailbox = FakeMailbox({"1": stuck, "2": raw_message()})

    read = await read_mailbox(
        mailbox, intake=intake(), key=attribution_key, sessions=sessions_of(session)
    )

    assert read == 1
    assert mailbox.moved == {"2": "AIVS/accepted"}
    assert "1" in mailbox.messages


async def test_a_storage_error_is_not_shown_to_the_member(
    session, attribution_key, alice, monkeypatch
):
    real = email_intake.create_submission
    calls = 0

    async def first_store_fails(*args: Any, **kwargs: Any):
        nonlocal calls
        calls += 1
        if calls == 1:
            statement = "INSERT INTO stix_objects (owner_token) VALUES (...)"
            raise DataError(statement, {}, Exception())
        return await real(*args, **kwargs)

    monkeypatch.setattr(email_intake, "create_submission", first_store_fails)

    assert await receive(session, attribution_key, raw_message()) == "accepted"

    [draft] = await submissions(session)
    assert "The attached bundle was not filed: it could not be stored" in draft.summary
    assert "INSERT" not in draft.summary
