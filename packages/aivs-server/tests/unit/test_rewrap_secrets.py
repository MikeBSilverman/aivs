"""Key rotation, against a real database.

A rotation tool is only ever run in the situation where getting it wrong is
expensive, so it does not get to be the module nobody exercises. These cover the
three outcomes an operator actually has to distinguish: nothing to do, work to
do, and a value no configured key can open -- which is the one where doing
nothing is the correct behaviour.
"""

from __future__ import annotations

import os
import uuid

import pytest

from aivs_schemas.enums import OperatorRole, OrgType
from aivs_server.auth.passwords import hash_password
from aivs_server.auth.secretbox import (
    DEFAULT_ALGORITHM_NAME,
    SecretBox,
    SecretPurpose,
    algorithm_by_name,
)
from aivs_server.db.models import Operator, Webhook
from aivs_server.rewrap_secrets import rewrap

pytestmark = pytest.mark.db

_KEY_BYTES = algorithm_by_name(DEFAULT_ALGORITHM_NAME).key_bytes
OLD_KEY = os.urandom(_KEY_BYTES)
NEW_KEY = os.urandom(_KEY_BYTES)

TOTP_SEED = "JBSWY3DPEHPK3PXP"
SIGNING_KEY = "webhook-signing-secret"


@pytest.fixture
async def sealed_under_old(session, make_org):
    """One operator and one webhook, sealed under the key being rotated away."""
    old = SecretBox(active=OLD_KEY)
    org = await make_org(f"firm-{uuid.uuid4().hex[:8]}", org_type=OrgType.GSIB)

    operator_id = uuid.uuid4()
    operator = Operator(
        id=operator_id,
        org_id=org.id,
        email=f"analyst-{uuid.uuid4().hex[:8]}@example.test",
        display_name="Analyst",
        roles=[OperatorRole.ANALYST],
        password_hash=hash_password("correct-horse-battery-staple"),
        totp_secret_encrypted=old.seal(TOTP_SEED, purpose=SecretPurpose.TOTP, subject=operator_id),
        is_active=True,
    )
    webhook_id = uuid.uuid4()
    webhook = Webhook(
        id=webhook_id,
        org_id=org.id,
        url="https://example.com/hook",
        hmac_secret_encrypted=old.seal(
            SIGNING_KEY, purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook_id
        ),
        events=[],
    )
    session.add_all([operator, webhook])
    await session.commit()
    return operator, webhook


async def test_a_report_run_counts_without_writing(session, sealed_under_old):
    """The check an operator runs before committing to anything."""
    operator, _webhook = sealed_under_old
    before = operator.totp_secret_encrypted
    rotating = SecretBox(active=NEW_KEY, previous=OLD_KEY)

    counts = await rewrap(session, rotating, apply=False)

    assert counts.stale == 2
    assert counts.rewrapped == 0
    assert counts.unopenable == 0
    await session.refresh(operator)
    assert operator.totp_secret_encrypted == before, "reporting must not write"


async def test_applying_moves_both_secrets_onto_the_new_key(session, sealed_under_old):
    operator, webhook = sealed_under_old
    rotating = SecretBox(active=NEW_KEY, previous=OLD_KEY)

    counts = await rewrap(session, rotating, apply=True)
    await session.commit()

    assert counts.rewrapped == 2
    assert counts.unopenable == 0

    # The point of the exercise: the old key can now be dropped.
    new_only = SecretBox(active=NEW_KEY)
    await session.refresh(operator)
    await session.refresh(webhook)
    assert (
        new_only.unseal(
            operator.totp_secret_encrypted, purpose=SecretPurpose.TOTP, subject=operator.id
        )
        == TOTP_SEED
    )
    assert (
        new_only.unseal(
            webhook.hmac_secret_encrypted,
            purpose=SecretPurpose.WEBHOOK_HMAC,
            subject=webhook.id,
        )
        == SIGNING_KEY
    )


async def test_a_second_run_finds_nothing_stale(session, sealed_under_old):
    """Idempotent, and this is the run that says the rotation is finished."""
    rotating = SecretBox(active=NEW_KEY, previous=OLD_KEY)
    await rewrap(session, rotating, apply=True)
    await session.commit()

    counts = await rewrap(session, rotating, apply=False)

    assert counts.stale == 0
    assert counts.current == 2


async def test_an_unopenable_value_is_reported_and_left_alone(session, sealed_under_old):
    """Never overwrite what you cannot read.

    The realistic cause is the previous key having been dropped too early. The
    secret is still recoverable if that key is found; a tool that "fixed" the
    row by sealing something else would make the loss permanent.
    """
    operator, _webhook = sealed_under_old
    stranded = SecretBox(active=NEW_KEY)  # the old key was not kept
    before = operator.totp_secret_encrypted

    counts = await rewrap(session, stranded, apply=True)
    await session.commit()

    assert counts.unopenable == 2
    assert counts.rewrapped == 0
    await session.refresh(operator)
    assert operator.totp_secret_encrypted == before, "left recoverable"


async def test_an_algorithm_change_is_the_same_operation(session, sealed_under_old):
    """Migrating cipher and migrating key use one tool, because they are one shape.

    The old values were written with AES-256-GCM under the old key; the box now
    seals with ChaCha20-Poly1305 under a new one. Nothing is stranded, and the
    report is what tells the operator the move is complete.
    """
    operator, webhook = sealed_under_old
    switched = SecretBox(
        active=NEW_KEY, previous=OLD_KEY, algorithm=algorithm_by_name("chacha20-poly1305")
    )

    counts = await rewrap(session, switched, apply=True)
    await session.commit()

    assert counts.rewrapped == 2
    assert counts.unopenable == 0

    await session.refresh(operator)
    await session.refresh(webhook)
    for blob in (operator.totp_secret_encrypted, webhook.hmac_secret_encrypted):
        assert blob[5] == algorithm_by_name("chacha20-poly1305").id

    # And the old key can now go.
    new_only = SecretBox(active=NEW_KEY, algorithm=algorithm_by_name("chacha20-poly1305"))
    assert (
        new_only.unseal(
            operator.totp_secret_encrypted, purpose=SecretPurpose.TOTP, subject=operator.id
        )
        == TOTP_SEED
    )
    assert (await rewrap(session, switched, apply=False)).stale == 0


async def test_a_value_on_the_right_key_but_the_wrong_algorithm_is_stale(session, sealed_under_old):
    """`needs_rewrap` has to consider both, or an algorithm move silently stops."""
    same_key_new_algorithm = SecretBox(
        active=OLD_KEY, algorithm=algorithm_by_name("chacha20-poly1305")
    )

    counts = await rewrap(session, same_key_new_algorithm, apply=False)

    assert counts.stale == 2
    assert counts.current == 0
