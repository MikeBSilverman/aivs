"""The webhooks a notification is queued for are key-share locked, so readers never wait.

``with_for_update(key_share=True)`` reads as a share lock and renders FOR NO KEY
UPDATE, which conflicts with itself: every distribution to a member waited on
any other distribution, or one-click, notifying the same member, while the
module said "readers do not block each other". The lock exists to make
offboarding wait for a distribution in flight (review L2-P3); it must not make
distributions wait for each other.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import async_sessionmaker

from aivs_server.auth.secretbox import SecretPurpose
from aivs_server.db.models import Webhook
from aivs_server.db.webhook_lock import deliverable_webhooks

pytestmark = pytest.mark.db


def test_the_lock_is_a_key_share_lock():
    rendered = str(deliverable_webhooks().compile(dialect=postgresql.dialect()))
    assert rendered.endswith("FOR KEY SHARE OF webhooks")


async def test_two_readers_of_one_members_webhooks_do_not_wait_for_each_other(
    engine, session, make_org, secret_box
):
    org = await make_org("locked-webhooks")
    webhook_id = uuid.uuid4()
    session.add(
        Webhook(
            id=webhook_id,
            org_id=org.id,
            url="https://hooks.locked.example/hook",
            hmac_secret_encrypted=secret_box.seal(
                "webhook-signing-secret", purpose=SecretPurpose.WEBHOOK_HMAC, subject=webhook_id
            ),
            events=[],
        )
    )
    await session.commit()

    sessions = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with sessions() as first, sessions() as second:
        held = (await first.execute(deliverable_webhooks())).scalars().all()
        # Refused at once rather than queued: a wait here is the defect.
        await second.execute(text("SET LOCAL lock_timeout = '200ms'"))
        also = (await second.execute(deliverable_webhooks())).scalars().all()
        assert [hook.id for hook in held] == [hook.id for hook in also] == [webhook_id]
        await first.rollback()
        await second.rollback()
