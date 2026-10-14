"""Reading the webhooks a notification is about to be queued for.

A notification is a ``WebhookDelivery`` row inserted in the transaction that
made something visible. Offboarding deletes the member's webhooks. If it
commits between a distribution reading a webhook and inserting its delivery,
the insert's foreign-key check fails, and the distribution fails with it as a
500: one member leaving stopped content reaching everyone else (review L2-P3).

So every reader of webhooks-to-notify takes ``FOR KEY SHARE`` on the rows it
reads. A deletion already committed leaves nothing to read; one in progress
is waited for and then skipped; and a deletion that starts after the read
waits for the distribution to commit, then removes the delivery with its
webhook (the foreign key cascades). Readers do not block each other.
"""

from __future__ import annotations

from sqlalchemy import Select, select

from aivs_server.db.models import Webhook

__all__ = ["deliverable_webhooks"]


def deliverable_webhooks() -> Select[tuple[Webhook]]:
    """Active webhooks, key-share locked; callers add which organisation's."""
    return (
        select(Webhook)
        .where(Webhook.is_active.is_(True))
        .with_for_update(key_share=True, of=Webhook)
    )
