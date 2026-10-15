"""The attribution key keeps who filed what out of reach of SQL (Phase P, SF-90).

The member path asks "is this mine?" of a tag, and ingest computes the token a
version is stored with, both under a key the database never holds. These are
the properties that depend on: a value is bound to what it says, names the key
it was made under, cannot be made without the key, and an instance refuses to
serve values under a key it was not given.
"""

from __future__ import annotations

import base64
import uuid

import pytest
from pydantic import SecretStr, ValidationError
from sqlalchemy import select, text

from aivs_schemas.enums import TLP, DiscoveryScope
from aivs_server.auth.attribution_key import AttributionKey, ForeignAttributionKeyError
from aivs_server.config import Settings
from aivs_server.db import models
from aivs_server.main import lifespan
from aivs_server.services.attribution import is_submitted_by, rekey, values_under_other_keys
from tests.conftest import (
    TEST_ATTRIBUTION_KEY,
    TEST_ATTRIBUTION_KEY_BYTES,
    TEST_SECRET_KEY,
    seed_filing,
    seeded_owner_token,
)
from tests.unit.test_security_regressions import _settings

ORG = uuid.UUID("00000000-0000-4000-8000-0000000000e1")
PEER = uuid.UUID("00000000-0000-4000-8000-0000000000e2")
SUBMISSION = uuid.UUID("00000000-0000-4000-8000-0000000000f1")
OTHER_SUBMISSION = uuid.UUID("00000000-0000-4000-8000-0000000000f2")
OTHER_KEY = AttributionKey(b"another-attribution-key-32-bytes")


def _encoded(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# What a tag and a token are bound to
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-90")
def test_a_tag_says_its_format_and_its_key_and_fits_its_column():
    tag = TEST_ATTRIBUTION_KEY.owner_tag(ORG, SUBMISSION)

    assert tag.startswith(f"1.{TEST_ATTRIBUTION_KEY.key_id}.")
    assert len(tag) <= 36
    assert TEST_ATTRIBUTION_KEY.owner_token(ORG, "vulnerability--x").startswith(
        TEST_ATTRIBUTION_KEY.prefix
    )


@pytest.mark.requirement("SF-90")
def test_one_firms_tags_cannot_be_matched_across_its_submissions():
    """A tag per submission: equal tags on two filings would gather a firm's work."""
    first = TEST_ATTRIBUTION_KEY.owner_tag(ORG, SUBMISSION)
    second = TEST_ATTRIBUTION_KEY.owner_tag(ORG, OTHER_SUBMISSION)

    assert first != second
    assert not TEST_ATTRIBUTION_KEY.is_owner_tag(first, ORG, OTHER_SUBMISSION)


@pytest.mark.requirement("SF-90")
def test_a_tag_answers_yes_for_its_filer_and_no_for_anyone_else():
    tag = TEST_ATTRIBUTION_KEY.owner_tag(ORG, SUBMISSION)

    assert TEST_ATTRIBUTION_KEY.is_owner_tag(tag, ORG, SUBMISSION)
    assert not TEST_ATTRIBUTION_KEY.is_owner_tag(tag, PEER, SUBMISSION)


def test_one_owners_tokens_on_two_ids_say_nothing_about_each_other():
    assert TEST_ATTRIBUTION_KEY.owner_token(ORG, "vulnerability--x") != (
        TEST_ATTRIBUTION_KEY.owner_token(ORG, "vulnerability--y")
    )
    assert TEST_ATTRIBUTION_KEY.owner_token(ORG, "vulnerability--x") != (
        TEST_ATTRIBUTION_KEY.owner_token(PEER, "vulnerability--x")
    )


def test_a_tag_and_a_token_are_made_with_different_subkeys():
    """The same input bytes to each: equal MACs would mean one key, so a tag
    could be presented as a token."""
    readable = "sixteen-ascii-id"
    submission = uuid.UUID(bytes=readable.encode("ascii"))

    tag = TEST_ATTRIBUTION_KEY.owner_tag(ORG, submission)
    token = TEST_ATTRIBUTION_KEY.owner_token(ORG, readable)

    assert tag.rsplit(".", 1)[1] != token.rsplit(".", 1)[1]


@pytest.mark.requirement("SF-90")
def test_a_tag_under_another_key_is_a_fault_not_a_no():
    """Answered "not yours", a half-finished rotation would hide every member's
    submissions from it with no fault anywhere."""
    submission = models.Submission(id=SUBMISSION, owner_tag=OTHER_KEY.owner_tag(ORG, SUBMISSION))

    with pytest.raises(ForeignAttributionKeyError):
        is_submitted_by(TEST_ATTRIBUTION_KEY, submission, ORG)


def test_the_key_never_appears_in_its_own_description():
    assert TEST_ATTRIBUTION_KEY_BYTES.hex() not in repr(TEST_ATTRIBUTION_KEY)
    assert repr(TEST_ATTRIBUTION_KEY) == f"AttributionKey(key_id={TEST_ATTRIBUTION_KEY.key_id!r})"


# ---------------------------------------------------------------------------
# What configuration is refused
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-90")
@pytest.mark.parametrize(
    ("value", "refusal"),
    [
        ("REPLACE_ME", "REPLACE_ME"),
        (_encoded(b"sixteen-byte-key"), "must decode to 32 bytes"),
        ("not base64!", "must be base64"),
    ],
    ids=["placeholder", "short", "malformed"],
)
def test_an_unusable_attribution_key_is_refused_everywhere(value, refusal):
    with pytest.raises(ValidationError, match=refusal) as caught:
        Settings(**_settings(environment="dev", attribution_key=value, attribution_key_file=None))
    if value != refusal:  # the placeholder's refusal names the marker, which is public
        assert value not in str(caught.value), "the refusal does not print the key"


@pytest.mark.requirement("SF-90")
def test_outside_dev_the_key_comes_from_a_file():
    with pytest.raises(ValidationError, match="attribution_key_file"):
        Settings(
            **_settings(
                attribution_key=_encoded(TEST_ATTRIBUTION_KEY_BYTES), attribution_key_file=None
            )
        )


@pytest.mark.requirement("SF-90")
def test_outside_dev_the_key_must_differ_from_the_key_encryption_key(tmp_path):
    same = tmp_path / "attribution-key"
    same.write_text(TEST_SECRET_KEY, encoding="utf-8")
    same.chmod(0o600)

    with pytest.raises(ValidationError, match="must differ from secret_encryption_key"):
        Settings(**_settings(attribution_key_file=same))


# ---------------------------------------------------------------------------
# Startup and rekey
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-90")
async def test_the_instance_refuses_to_start_on_values_under_another_key(
    app, session, make_org, settings
):
    member = await make_org("tagged-member")
    await seed_filing(
        session,
        models.Submission(tlp=TLP.AMBER, discovery_scope=DiscoveryScope.AI_SYSTEM, title="tagged"),
        member,
    )
    await session.commit()
    app.state.settings = settings.model_copy(
        update={"attribution_key": SecretStr(_encoded(b"another-attribution-key-32-bytes"))}
    )
    try:
        with pytest.raises(ForeignAttributionKeyError, match=r"submissions\.owner_tag"):
            async with lifespan(app):
                pytest.fail("served with values under another key")
    finally:
        app.state.settings = settings

    assert await values_under_other_keys(session, TEST_ATTRIBUTION_KEY) == []


@pytest.mark.requirement("SF-90")
async def test_a_rekey_needs_only_the_new_key_and_the_mapping(session, make_org):
    member = await make_org("rekeyed-member")
    submission = await seed_filing(
        session,
        models.Submission(tlp=TLP.AMBER, discovery_scope=DiscoveryScope.AI_SYSTEM, title="rekeyed"),
        member,
    )
    session.add(
        models.StixObject(
            stix_id="vulnerability--rekeyed",
            modified=submission.created_at,
            created=submission.created_at,
            type="vulnerability",
            spec_version="2.1",
            submission_id=submission.id,
            raw={},
            owner_token=await seeded_owner_token(session, submission, "vulnerability--rekeyed"),
        )
    )
    await session.commit()

    counts = await rekey(session, OTHER_KEY)
    await session.commit()

    assert (counts.tags, counts.tokens) == (1, 1)
    assert await values_under_other_keys(session, OTHER_KEY) == []
    await session.refresh(submission)
    assert is_submitted_by(OTHER_KEY, submission, member.id)
    token = await session.scalar(
        select(models.StixObject.owner_token).where(
            models.StixObject.submission_id == submission.id
        )
    )
    assert token == OTHER_KEY.owner_token(member.id, "vulnerability--rekeyed")


# ---------------------------------------------------------------------------
# The key is not in the database
# ---------------------------------------------------------------------------
@pytest.mark.requirement("SF-90")
async def test_no_row_anywhere_holds_the_key_or_anything_derived_from_it(
    client, session, make_org, make_cert
):
    """SQL alone can neither compute nor reverse a tag only if nothing in the
    database holds the key. Every row of every table, after a real filing."""
    from tests.conftest import proxy_headers  # noqa: PLC0415 - one use

    member = await make_org("keyless-member")
    pem, _ = await make_cert(member)
    filed = await client.post(
        "/api/v1/submissions",
        json={
            "title": "keyless",
            "tlp": "amber",
            "discovery_scope": "ai_system",
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": []},
        },
        headers=proxy_headers(pem),
    )
    assert filed.status_code == 201, filed.text

    key_forms = {
        TEST_ATTRIBUTION_KEY_BYTES.hex(),
        _encoded(TEST_ATTRIBUTION_KEY_BYTES),
        TEST_ATTRIBUTION_KEY_BYTES.decode("ascii"),
        TEST_ATTRIBUTION_KEY._tag_key.hex(),
        TEST_ATTRIBUTION_KEY._token_key.hex(),
    }
    tables = (
        await session.execute(
            text(
                "SELECT quote_ident(schemaname) || '.' || quote_ident(tablename) "
                "FROM pg_tables WHERE schemaname IN ('public', 'attribution')"
            )
        )
    ).scalars()
    found = []
    for table in tables:
        rows = (
            await session.execute(text(f"SELECT row_to_json(t)::text FROM {table} t"))  # noqa: S608 - names from pg_tables
        ).scalars()
        found += [table for row in rows for form in key_forms if form in row]
    assert found == []
