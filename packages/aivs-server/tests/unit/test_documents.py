"""Text documents and their document-only grants (Phase I, slice I1; SF-98).

Driven through ``services.documents`` -- the one door -- with the caller's
context built as the request layer builds it, so every read is tested on rows
its own writers made. "Not found" is one answer for an absent document, one the
caller holds no grant on, and a principal the owner may not name, so each test
of a refusal also shows the same caller succeeding where it should.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest
from sqlalchemy import func, select

from aivs_schemas.enums import (
    TLP,
    CircleRole,
    DocumentPermission,
    DocumentState,
    GrantPrincipal,
    OperatorRole,
    OrgStatus,
    OrgType,
)
from aivs_server.audit.log import AuditAction
from aivs_server.auth.context import AuthContext, AuthMethod
from aivs_server.auth.policy import PolicyDeniedError
from aivs_server.auth.secretbox import SecretBox
from aivs_server.db.models import (
    AuditLog,
    Document,
    DocumentGrant,
    DocumentRead,
    DocumentVersion,
    Operator,
    OrgSharingCode,
)
from aivs_server.rewrap_secrets import rewrap
from aivs_server.services import documents
from aivs_server.services.documents import (
    DocumentNotFoundError,
    DocumentRefusedError,
    DocumentStaleError,
    DocumentUnreadableError,
)

pytestmark = [pytest.mark.db, pytest.mark.requirement("SF-98")]

NOW = dt.datetime(2026, 10, 16, 12, 0, tzinfo=dt.UTC)
BODY = "BLUF: patch the gateway before Friday.\n\nDetails follow."


def person(org, operator: Operator | None, *, method: AuthMethod = AuthMethod.PORTAL_SESSION):
    return AuthContext(
        org_id=org.id,
        org_slug=org.slug,
        org_type=org.org_type,
        org_status=OrgStatus.ACTIVE,
        auth_method=method,
        operator_id=operator.id if operator is not None else None,
        operator_roles=frozenset({OperatorRole.ANALYST}),
    )


@pytest.fixture
async def world(app, session, make_org, make_operator, make_circle, join_circle):
    """An owner, a peer it shares an active circle with, and an outsider it does not."""
    owner = await make_org("owner-bank", org_type=OrgType.GSIB)
    peer = await make_org("peer-bank", org_type=OrgType.GSIB)
    outsider = await make_org("outsider-bank", org_type=OrgType.GSIB)
    circle = await make_circle("documents")
    for org in (owner, peer):
        await join_circle(org, circle, role=CircleRole.MEMBER)
    people = {}
    for name, org in (
        ("author", owner),
        ("colleague", owner),
        ("colleague2", owner),
        ("peer_one", peer),
        ("peer_two", peer),
        ("outsider_one", outsider),
    ):
        operator, _seed = await make_operator(org)
        people[name] = operator
    world = {"owner": owner, "peer": peer, "outsider": outsider, "circle": circle, **people}
    # Each other firm's sharing code, made by its own org admin: how the owner names it.
    codes = {}
    for org in (owner, peer, outsider):
        admin, _seed = await make_operator(org, roles=(OperatorRole.ORG_ADMIN,))
        codes[org.id] = await documents.rotate_sharing_code(session, admin_of(org, admin), now=NOW)
    world["codes"] = codes
    return world


def admin_of(org, admin: Operator) -> AuthContext:
    return AuthContext(
        org_id=org.id,
        org_slug=org.slug,
        org_type=org.org_type,
        org_status=OrgStatus.ACTIVE,
        auth_method=AuthMethod.PORTAL_SESSION,
        operator_id=admin.id,
        operator_roles=frozenset({OperatorRole.ORG_ADMIN}),
    )


def ctx_of(world, name: str, **kwargs: Any) -> AuthContext:
    org = {
        "author": "owner",
        "colleague": "owner",
        "colleague2": "owner",
        "peer_one": "peer",
        "peer_two": "peer",
        "outsider_one": "outsider",
    }[name]
    return person(world[org], world[name], **kwargs)


async def create(session, secret_box: SecretBox, world, *, tlp: TLP = TLP.AMBER) -> uuid.UUID:
    return await documents.create_document(
        session,
        ctx_of(world, "author"),
        box=secret_box,
        title="Gateway advisory",
        abstract="Patch it.",
        tlp=tlp,
        body=BODY,
        now=NOW,
    )


async def read(session, secret_box, ctx, document_id, *, now=NOW, version_number=None):
    return await documents.read_document(
        session, ctx, document_id, box=secret_box, now=now, version_number=version_number
    )


async def share(session, world, document_id, principal, principal_id, **kwargs: Any):
    """Share as the author: another firm by its sharing code, the owner's own by id."""
    is_other_firm = principal is GrantPrincipal.ORGANIZATION and principal_id != world["owner"].id
    code = world["codes"].get(principal_id) if is_other_firm else None
    return await documents.grant_access(
        session,
        ctx_of(world, "author"),
        document_id,
        principal=principal,
        principal_id=None if code is not None else principal_id,
        sharing_code=code,
        permission=kwargs.pop("permission", DocumentPermission.VIEW),
        expires_at=kwargs.pop("expires_at", None),
        now=kwargs.pop("now", NOW),
    )


# ---------------------------------------------------------------------------
# The owner, the body and its keys
# ---------------------------------------------------------------------------
async def test_the_author_reads_what_it_wrote_and_the_read_is_receipted(session, secret_box, world):
    document_id = await create(session, secret_box, world)

    view = await read(session, secret_box, ctx_of(world, "author"), document_id)

    assert (view.body, view.version_number, view.state) == (BODY, 1, DocumentState.DRAFT)
    assert view.permission is DocumentPermission.EDIT
    assert view.owner_name == world["owner"].name
    [receipt] = (await session.scalars(select(DocumentRead))).all()
    assert (receipt.org_id, receipt.operator_id) == (world["owner"].id, world["author"].id)


async def test_the_body_is_sealed_at_rest_under_the_documents_own_key(session, secret_box, world):
    document_id = await create(session, secret_box, world)

    version = await session.scalar(select(DocumentVersion))
    document = await session.get(Document, document_id)
    assert BODY.encode() not in version.body_sealed
    assert b"BLUF" not in version.body_sealed
    assert document.dek_sealed.startswith(b"AIVS")


async def test_a_sealed_body_moved_to_another_version_does_not_open(session, secret_box, world):
    """Bound to its row: a version's ciphertext copied into a new version is refused."""
    document_id = await create(session, secret_box, world)
    first = await session.scalar(select(DocumentVersion))
    session.add(
        DocumentVersion(
            document_id=document_id,
            number=2,
            content_sha256=first.content_sha256,
            body_sealed=first.body_sealed,
            author_operator_id=first.author_operator_id,
        )
    )
    await session.commit()

    assert (
        await read(session, secret_box, ctx_of(world, "author"), document_id, version_number=1)
    ).body == BODY
    with pytest.raises(DocumentUnreadableError):
        await read(session, secret_box, ctx_of(world, "author"), document_id, version_number=2)


async def test_a_stale_save_is_refused_and_a_current_one_makes_the_next_version(
    session, secret_box, world
):
    document_id = await create(session, secret_box, world)
    ctx = ctx_of(world, "author")

    with pytest.raises(DocumentStaleError):
        await documents.save_version(
            session, ctx, document_id, box=secret_box, body="v2", expected_version=7, now=NOW
        )
    number = await documents.save_version(
        session, ctx, document_id, box=secret_box, body="v2", expected_version=1, now=NOW
    )

    view = await read(session, secret_box, ctx, document_id)
    assert (number, view.body, view.version) == (2, "v2", 2)


# ---------------------------------------------------------------------------
# Who may read: one not-found for everyone else
# ---------------------------------------------------------------------------
async def test_a_draft_is_its_authors_until_shared_inside_its_firm_as_outside(
    session, secret_box, world
):
    document_id = await create(session, secret_box, world)
    await read(session, secret_box, ctx_of(world, "author"), document_id)

    for name in ("colleague", "peer_one", "outsider_one"):
        with pytest.raises(DocumentNotFoundError) as unshared:
            await read(session, secret_box, ctx_of(world, name), document_id)
        with pytest.raises(DocumentNotFoundError) as absent:
            await read(session, secret_box, ctx_of(world, name), uuid.uuid4())
        assert str(unshared.value) == str(absent.value) == ""


async def test_an_organisation_grant_lets_its_people_read(session, secret_box, world):
    document_id = await create(session, secret_box, world)
    with pytest.raises(DocumentNotFoundError):
        await read(session, secret_box, ctx_of(world, "peer_one"), document_id)

    await share(session, world, document_id, GrantPrincipal.ORGANIZATION, world["peer"].id)

    for name in ("peer_one", "peer_two"):
        view = await read(session, secret_box, ctx_of(world, name), document_id)
        assert view.permission is DocumentPermission.VIEW


async def test_a_grant_reads_until_it_expires_judged_at_the_read(session, secret_box, world):
    document_id = await create(session, secret_box, world)
    await share(
        session,
        world,
        document_id,
        GrantPrincipal.ORGANIZATION,
        world["peer"].id,
        expires_at=NOW + dt.timedelta(days=1),
    )

    await read(
        session,
        secret_box,
        ctx_of(world, "peer_one"),
        document_id,
        now=NOW + dt.timedelta(hours=23),
    )
    with pytest.raises(DocumentNotFoundError):
        await read(
            session,
            secret_box,
            ctx_of(world, "peer_one"),
            document_id,
            now=NOW + dt.timedelta(days=1),
        )


async def test_a_revoked_grant_reads_nothing(session, secret_box, world):
    document_id = await create(session, secret_box, world)
    grant_id = await share(
        session, world, document_id, GrantPrincipal.ORGANIZATION, world["peer"].id
    )
    await read(session, secret_box, ctx_of(world, "peer_one"), document_id)

    await documents.revoke_grant(session, ctx_of(world, "author"), document_id, grant_id, now=NOW)

    with pytest.raises(DocumentNotFoundError):
        await read(session, secret_box, ctx_of(world, "peer_one"), document_id)


async def test_a_persons_grant_ends_when_they_leave_while_their_organisations_remains(
    session, secret_box, world
):
    """Main's case, both halves: the person's EDIT ends with them; the firm's VIEW does not."""
    document_id = await create(session, secret_box, world)
    await share(session, world, document_id, GrantPrincipal.ORGANIZATION, world["owner"].id)
    await share(
        session,
        world,
        document_id,
        GrantPrincipal.OPERATOR,
        world["colleague"].id,
        permission=DocumentPermission.EDIT,
    )
    held = await read(session, secret_box, ctx_of(world, "colleague"), document_id)
    assert held.permission is DocumentPermission.EDIT

    world["colleague"].is_active = False
    await session.commit()

    left = await read(session, secret_box, ctx_of(world, "colleague"), document_id)
    assert left.permission is DocumentPermission.VIEW, "only the firm's grant is left"
    other = await read(session, secret_box, ctx_of(world, "colleague2"), document_id)
    assert other.permission is DocumentPermission.VIEW, "the firm's grant still holds"


async def test_a_person_grant_without_the_firms_ends_entirely_when_they_leave(
    session, secret_box, world
):
    document_id = await create(session, secret_box, world)
    await share(session, world, document_id, GrantPrincipal.OPERATOR, world["colleague"].id)
    await read(session, secret_box, ctx_of(world, "colleague"), document_id)

    world["colleague"].is_active = False
    await session.commit()

    with pytest.raises(DocumentNotFoundError):
        await read(session, secret_box, ctx_of(world, "colleague"), document_id)


# ---------------------------------------------------------------------------
# The TLP ceiling: a session held below RED reads no RED document
# ---------------------------------------------------------------------------
async def test_a_red_document_is_not_found_over_sso_and_read_with_a_certificate(
    session, secret_box, world
):
    document_id = await create(session, secret_box, world, tlp=TLP.RED)
    await share(session, world, document_id, GrantPrincipal.ORGANIZATION, world["peer"].id)

    view = await read(session, secret_box, ctx_of(world, "peer_one"), document_id)
    assert view.tlp is TLP.RED
    with pytest.raises(DocumentNotFoundError) as over_sso:
        await read(
            session,
            secret_box,
            ctx_of(world, "peer_one", method=AuthMethod.SSO_SESSION),
            document_id,
        )
    with pytest.raises(DocumentNotFoundError) as absent:
        await read(
            session,
            secret_box,
            ctx_of(world, "peer_one", method=AuthMethod.SSO_SESSION),
            uuid.uuid4(),
        )
    assert str(over_sso.value) == str(absent.value)


async def test_a_red_document_cannot_be_written_from_a_session_below_red(
    session, secret_box, world
):
    with pytest.raises(DocumentRefusedError):
        await documents.create_document(
            session,
            ctx_of(world, "author", method=AuthMethod.SSO_SESSION),
            box=secret_box,
            title="t",
            abstract=None,
            tlp=TLP.RED,
            body="b",
            now=NOW,
        )
    assert await session.scalar(select(func.count()).select_from(Document)) == 0


# ---------------------------------------------------------------------------
# Who may be named (SF-2): everything else is the same not-found
# ---------------------------------------------------------------------------
async def test_the_owner_names_its_firm_its_people_and_firms_sharing_an_open_circle(
    session, secret_box, world
):
    document_id = await create(session, secret_box, world)

    for principal, principal_id in (
        (GrantPrincipal.ORGANIZATION, world["owner"].id),
        (GrantPrincipal.OPERATOR, world["colleague"].id),
        (GrantPrincipal.ORGANIZATION, world["peer"].id),
    ):
        await share(session, world, document_id, principal, principal_id)

    assert await session.scalar(select(func.count()).select_from(DocumentGrant)) == 3


async def _refused_as_absent(session, world, document_id, principal, principal_id) -> None:
    with pytest.raises(DocumentNotFoundError) as beyond:
        await share(session, world, document_id, principal, principal_id)
    with pytest.raises(DocumentNotFoundError) as absent:
        await share(session, world, uuid.uuid4(), principal, principal_id)
    assert str(beyond.value) == str(absent.value)


async def test_a_firm_sharing_no_circle_cannot_be_named(session, secret_box, world):
    document_id = await create(session, secret_box, world)
    await share(session, world, document_id, GrantPrincipal.ORGANIZATION, world["peer"].id)

    await _refused_as_absent(
        session, world, document_id, GrantPrincipal.ORGANIZATION, world["outsider"].id
    )


async def test_another_firms_person_cannot_be_named(session, secret_box, world):
    document_id = await create(session, secret_box, world)

    await _refused_as_absent(
        session, world, document_id, GrantPrincipal.OPERATOR, world["peer_one"].id
    )


async def test_a_firm_whose_circle_membership_has_ended_cannot_be_named(session, secret_box, world):
    document_id = await create(session, secret_box, world)
    membership = await session.scalar(
        select(documents.CircleMembership).where(
            documents.CircleMembership.org_id == world["peer"].id
        )
    )
    membership.left_at = NOW - dt.timedelta(days=1)
    membership.ended_by = "operator"
    await session.commit()

    await _refused_as_absent(
        session, world, document_id, GrantPrincipal.ORGANIZATION, world["peer"].id
    )


async def test_a_firm_sharing_only_an_inactive_circle_cannot_be_named(session, secret_box, world):
    document_id = await create(session, secret_box, world)
    world["circle"].is_active = False
    await session.commit()

    await _refused_as_absent(
        session, world, document_id, GrantPrincipal.ORGANIZATION, world["peer"].id
    )


async def test_a_firm_of_a_type_not_on_the_allow_list_cannot_be_named(
    session, secret_box, world, make_org, make_operator, join_circle
):
    """The allow-list, not the circle, decides: the ISAC's own organisation shares the
    circle here and holds a code, and is still refused, as a service provider will
    be until K. The same firm as a bank is named, so the type is what refused."""
    # Its code is made while it is a bank: an ISAC-type org has no org admins.
    isac = await make_org("hosting-isac-doc", org_type=OrgType.GSIB)
    await join_circle(isac, world["circle"])
    admin, _seed = await make_operator(isac, roles=(OperatorRole.ORG_ADMIN,))
    world["codes"][isac.id] = await documents.rotate_sharing_code(
        session, admin_of(isac, admin), now=NOW
    )
    # Committed: the service reads through its own staff connection.
    isac.org_type = OrgType.ADMIN
    await session.commit()
    document_id = await create(session, secret_box, world)

    await _refused_as_absent(session, world, document_id, GrantPrincipal.ORGANIZATION, isac.id)
    assert OrgType.ADMIN not in documents.DOCUMENT_GRANTEE_ORG_TYPES
    isac.org_type = OrgType.GSIB
    await session.commit()
    await share(session, world, document_id, GrantPrincipal.ORGANIZATION, isac.id)


async def test_a_grantee_cannot_pass_the_document_on(session, secret_box, world):
    document_id = await create(session, secret_box, world)
    await share(
        session,
        world,
        document_id,
        GrantPrincipal.ORGANIZATION,
        world["peer"].id,
        permission=DocumentPermission.EDIT,
    )

    # A valid code for a firm in the owner's bound: only "the owner's firm alone
    # grants" stands between the grantee and a new grant.
    with pytest.raises(DocumentNotFoundError):
        await documents.grant_access(
            session,
            ctx_of(world, "peer_one"),
            document_id,
            principal=GrantPrincipal.ORGANIZATION,
            principal_id=None,
            sharing_code=world["codes"][world["peer"].id],
            permission=DocumentPermission.EDIT,
            expires_at=None,
            now=NOW,
        )


# ---------------------------------------------------------------------------
# Editing, comments and the machine
# ---------------------------------------------------------------------------
async def test_a_viewer_cannot_save_and_an_editor_can(session, secret_box, world):
    document_id = await create(session, secret_box, world)
    await share(session, world, document_id, GrantPrincipal.ORGANIZATION, world["peer"].id)
    await share(
        session,
        world,
        document_id,
        GrantPrincipal.OPERATOR,
        world["colleague"].id,
        permission=DocumentPermission.EDIT,
    )

    with pytest.raises(DocumentNotFoundError):
        await documents.save_version(
            session,
            ctx_of(world, "peer_one"),
            document_id,
            box=secret_box,
            body="x",
            expected_version=1,
            now=NOW,
        )
    assert (
        await documents.save_version(
            session,
            ctx_of(world, "colleague"),
            document_id,
            box=secret_box,
            body="x",
            expected_version=1,
            now=NOW,
        )
        == 2
    )


async def test_a_viewer_comments_and_the_comment_reads_back(session, secret_box, world):
    document_id = await create(session, secret_box, world)
    await share(session, world, document_id, GrantPrincipal.ORGANIZATION, world["peer"].id)

    await documents.add_comment(
        session,
        ctx_of(world, "peer_one"),
        document_id,
        box=secret_box,
        version_number=1,
        body="Does this cover 4.1?",
        now=NOW,
    )

    [comment] = (await read(session, secret_box, ctx_of(world, "author"), document_id)).comments
    assert (comment.body, comment.author_operator_id) == (
        "Does this cover 4.1?",
        world["peer_one"].id,
    )
    with pytest.raises(DocumentNotFoundError):
        await documents.add_comment(
            session,
            ctx_of(world, "outsider_one"),
            document_id,
            box=secret_box,
            version_number=1,
            body="x",
            now=NOW,
        )


async def test_comments_are_bounded_in_size_and_rate(session, secret_box, world, monkeypatch):
    document_id = await create(session, secret_box, world)
    ctx = ctx_of(world, "author")
    with pytest.raises(DocumentRefusedError, match="longer than"):
        await documents.add_comment(
            session,
            ctx,
            document_id,
            box=secret_box,
            version_number=1,
            body="x" * (documents.MAX_COMMENT_CHARS + 1),
            now=NOW,
        )
    monkeypatch.setattr(documents, "COMMENTS_PER_HOUR", 2)
    for _ in range(2):
        await documents.add_comment(
            session, ctx, document_id, box=secret_box, version_number=1, body="ok", now=NOW
        )

    with pytest.raises(DocumentRefusedError, match="too many comments"):
        await documents.add_comment(
            session, ctx, document_id, box=secret_box, version_number=1, body="ok", now=NOW
        )


async def test_an_archived_document_reads_but_changes_no_more(session, secret_box, world):
    document_id = await create(session, secret_box, world)
    ctx = ctx_of(world, "author")

    await documents.transition_document(
        session, ctx, document_id, to=DocumentState.ARCHIVED, now=NOW
    )

    assert (await read(session, secret_box, ctx, document_id)).state is DocumentState.ARCHIVED
    with pytest.raises(DocumentRefusedError, match="no longer changes"):
        await documents.save_version(
            session, ctx, document_id, box=secret_box, body="x", expected_version=2, now=NOW
        )
    with pytest.raises(DocumentRefusedError, match="no longer changes"):
        await share(session, world, document_id, GrantPrincipal.ORGANIZATION, world["peer"].id)


async def test_finishing_is_not_offered_until_it_publishes(session, secret_box, world):
    document_id = await create(session, secret_box, world)
    ctx = ctx_of(world, "author")
    await documents.transition_document(
        session, ctx, document_id, to=DocumentState.IN_REVIEW, now=NOW
    )

    with pytest.raises(DocumentRefusedError, match="not built yet"):
        await documents.transition_document(
            session, ctx, document_id, to=DocumentState.FINISHED, now=NOW
        )


# ---------------------------------------------------------------------------
# Offboarding and key rotation
# ---------------------------------------------------------------------------
async def test_offboarding_archives_the_firms_documents_and_ends_every_grant_touching_it(
    session, secret_box, world
):
    theirs = await create(session, secret_box, world)
    await share(session, world, theirs, GrantPrincipal.ORGANIZATION, world["peer"].id)
    await share(session, world, theirs, GrantPrincipal.OPERATOR, world["colleague"].id)
    peers = await documents.create_document(
        session,
        ctx_of(world, "peer_one"),
        box=secret_box,
        title="Peer note",
        abstract=None,
        tlp=TLP.AMBER,
        body="b",
        now=NOW,
    )
    await documents.grant_access(
        session,
        ctx_of(world, "peer_one"),
        peers,
        principal=GrantPrincipal.ORGANIZATION,
        principal_id=None,
        sharing_code=world["codes"][world["owner"].id],
        permission=DocumentPermission.VIEW,
        expires_at=None,
        now=NOW,
    )
    open_grants = (
        select(func.count()).select_from(DocumentGrant).where(DocumentGrant.revoked_at.is_(None))
    )
    assert await session.scalar(open_grants) == 3, "there before gone"

    closed = await documents.close_for_offboarded(session, world["owner"].id, now=NOW)
    await session.commit()

    assert closed == 3
    assert await session.scalar(open_grants) == 0
    owned = await session.get(Document, theirs)
    await session.refresh(owned)
    assert owned.state is DocumentState.ARCHIVED
    peer_document = await session.get(Document, peers)
    await session.refresh(peer_document)
    assert peer_document.state is DocumentState.DRAFT, "another firm's document stays its own"


async def test_rotating_the_instance_key_rewraps_each_documents_key(session, settings, world):
    old_key, new_key = bytes(range(32)), bytes(range(1, 33))
    old_box = SecretBox(active=old_key)
    document_id = await create(session, old_box, world)

    rotated = SecretBox(active=new_key, previous=old_key)
    counts = await rewrap(session, rotated, apply=True)
    await session.commit()

    assert counts.rewrapped >= 1
    view = await read(session, SecretBox(active=new_key), ctx_of(world, "author"), document_id)
    assert view.body == BODY


async def test_a_document_key_that_does_not_open_is_reported_as_lost(session, world):
    document_id = await create(session, SecretBox(active=bytes(range(32))), world)

    counts = await rewrap(session, SecretBox(active=bytes(range(2, 34))), apply=True)

    assert counts.unopenable >= 1
    with pytest.raises(DocumentUnreadableError):
        await read(
            session, SecretBox(active=bytes(range(2, 34))), ctx_of(world, "author"), document_id
        )


async def test_offboarding_a_firm_through_the_isac_closes_its_document_grants(
    client, session, secret_box, world, isac
):
    """The real offboarding, not the helper: dropping the call would leave grants open."""
    document_id = await create(session, secret_box, world)
    await share(session, world, document_id, GrantPrincipal.ORGANIZATION, world["peer"].id)
    await read(session, secret_box, ctx_of(world, "peer_one"), document_id)
    _org, membership_staff = isac

    response = await client.post(
        f"/api/v1/orgs/{world['owner'].id}/offboard",
        json={"reason": "left the ISAC", "confirm_slug": world["owner"].slug},
        headers=membership_staff,
    )

    assert response.status_code == 200, response.text
    with pytest.raises(DocumentNotFoundError):
        await read(session, secret_box, ctx_of(world, "peer_one"), document_id)
    grant = await session.scalar(select(DocumentGrant))
    await session.refresh(grant)
    assert grant.revoked_by == "offboarded"


# ---------------------------------------------------------------------------
# Sharing codes: another firm is named only by the code it handed over
# ---------------------------------------------------------------------------
async def test_another_firm_is_not_named_by_its_id(session, secret_box, world):
    """By id, a firm sharing a circle is refused; by its code, it is named."""
    document_id = await create(session, secret_box, world)

    with pytest.raises(DocumentNotFoundError):
        await documents.grant_access(
            session,
            ctx_of(world, "author"),
            document_id,
            principal=GrantPrincipal.ORGANIZATION,
            principal_id=world["peer"].id,
            sharing_code=None,
            permission=DocumentPermission.VIEW,
            expires_at=None,
            now=NOW,
        )
    await share(session, world, document_id, GrantPrincipal.ORGANIZATION, world["peer"].id)


async def _by_code(session, world, document_id, code: str):
    return await documents.grant_access(
        session,
        ctx_of(world, "author"),
        document_id,
        principal=GrantPrincipal.ORGANIZATION,
        principal_id=None,
        sharing_code=code,
        permission=DocumentPermission.VIEW,
        expires_at=None,
        now=NOW,
    )


async def test_a_rotated_code_stops_naming_its_firm_and_grants_made_stand(
    session, secret_box, world, make_operator
):
    document_id = await create(session, secret_box, world)
    old = world["codes"][world["peer"].id]
    await _by_code(session, world, document_id, old)
    admin, _seed = await make_operator(world["peer"], roles=(OperatorRole.ORG_ADMIN,))

    new = await documents.rotate_sharing_code(session, admin_of(world["peer"], admin), now=NOW)

    assert new != old
    with pytest.raises(DocumentNotFoundError):
        await _by_code(session, world, document_id, old)
    await read(session, secret_box, ctx_of(world, "peer_one"), document_id)
    await _by_code(session, world, document_id, new.lower())


async def test_only_the_firms_own_org_admin_rotates_its_code(session, world):
    with pytest.raises(PolicyDeniedError):
        await documents.rotate_sharing_code(session, ctx_of(world, "peer_one"), now=NOW)


async def test_the_code_is_stored_only_as_its_hash_and_its_rotation_audited(session, world):
    code = world["codes"][world["peer"].id]

    rows = (await session.scalars(select(OrgSharingCode))).all()
    assert code not in str([vars(row) for row in rows])
    [audited] = (
        await session.scalars(
            select(AuditLog).where(
                AuditLog.action == AuditAction.ORG_SHARING_CODE_ROTATED,
                AuditLog.org_id == world["peer"].id,
            )
        )
    ).all()
    assert code not in str(audited.details)
