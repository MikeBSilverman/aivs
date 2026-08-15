"""Regressions for defects found by adversarial security review.

Each test here corresponds to a specific finding. They are kept together, and
named after the property rather than the bug, so that a future refactor that
reintroduces one fails with a message that explains what was lost rather than
just which assertion tripped.
"""

from __future__ import annotations

import datetime as dt

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from aivs_server.config import Settings
from aivs_server.db.models import Distribution, TaxiiCollection
from tests.conftest import (
    TEST_CA_ISSUER_DN,
    TEST_PROXY_SECRET,
    TEST_SESSION_SECRET,
    proxy_headers,
)


# ---------------------------------------------------------------------------
# The production-posture interlock must not be scoped to one environment name
# ---------------------------------------------------------------------------
def _settings(**overrides: object) -> dict[str, object]:
    base = {
        "environment": "staging",
        "public_base_url": "https://aivs.test",
        "database_url": "postgresql+psycopg://aivs@127.0.0.1:55432/aivs_test",
        "proxy_shared_secret": TEST_PROXY_SECRET,
        "session_secret": TEST_SESSION_SECRET,
        "expected_certificate_issuer_dn": TEST_CA_ISSUER_DN,
    }
    return {**base, **overrides}


@pytest.mark.parametrize("environment", ["production", "staging"])
@pytest.mark.parametrize(
    "unsafe",
    [
        {"dev_trust_unauthenticated_proxy": True},
        {"dev_expose_error_detail": True},
        {"dev_allow_private_webhook_targets": True},
        {"trusted_proxy_cidrs": []},
        {"public_base_url": "http://aivs.test"},
        {"log_level": "DEBUG"},
    ],
)
def test_hardened_environments_refuse_dev_bypasses(environment, unsafe):
    """Every non-development environment refuses to start with a bypass enabled.

    The interlock previously exempted anything that was not literally
    ``"production"``, so a staging deployment -- which for an ISAC routinely
    mirrors production and holds real embargoed intelligence -- could run with
    ``dev_trust_unauthenticated_proxy`` and silently lose the entire
    proxy-authentication control. Staging is included here deliberately: it is
    the case the original check missed.
    """
    with pytest.raises(ValidationError):
        Settings(**_settings(environment=environment, **unsafe))


def test_development_may_still_use_bypasses():
    """The exemption is allow-listed to `dev`, and dev must remain usable."""
    settings = Settings(
        **_settings(
            environment="dev",
            dev_trust_unauthenticated_proxy=True,
            dev_expose_error_detail=True,
            public_base_url="http://localhost",
        )
    )
    assert settings.dev_trust_unauthenticated_proxy is True


def test_hardened_environment_starts_when_configured_safely():
    """The interlock must not be so broad that a correct deployment cannot start."""
    settings = Settings(**_settings(environment="staging"))
    assert settings.is_production is False
    assert settings.dev_trust_unauthenticated_proxy is False


# ---------------------------------------------------------------------------
# Pagination must tiebreak on a monotonic key, not a random one
# ---------------------------------------------------------------------------
@pytest.mark.db
async def test_distribution_seq_follows_insertion_order(session, make_org, make_circle, publish):
    """Rows sharing one `date_added` still order by insertion.

    This is the property that makes keyset pagination unable to skip a row. The
    tiebreaker was previously the random UUID primary key, under which rows in a
    single millisecond -- exactly what an embargo release of a batch produces --
    ordered randomly, so a row committed after a member paged past that
    millisecond could sort below the cursor and never be delivered.
    """
    org = await make_org("meridian-global")
    circle = await make_circle("section9")

    # One shared timestamp, several separately committed rows: the embargo
    # release shape.
    shared = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5)
    for index in range(6):
        await publish(org, circle, name=f"batch-{index}", date_added=shared)

    rows = (
        await session.execute(
            select(Distribution.seq, Distribution.date_added).order_by(Distribution.seq)
        )
    ).all()

    assert len(rows) == 6
    assert len({row.date_added for row in rows}) == 1, "test setup: all share one timestamp"
    sequences = [row.seq for row in rows]
    assert sequences == sorted(sequences)
    assert len(set(sequences)) == 6, "seq must be unique so the sort key is total"


@pytest.mark.db
async def test_paging_a_same_millisecond_batch_skips_nothing(
    client, make_org, make_cert, make_circle, join_circle, make_collection, publish
):
    """Paging through a batch that shares one timestamp delivers every object.

    The end-to-end version of the property above, driven through the real TAXII
    endpoint one page at a time.
    """
    org = await make_org("meridian-global")
    pem, _ = await make_cert(org)
    circle = await make_circle("section9")
    await join_circle(org, circle)
    collection = await make_collection(circle)

    shared = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5)
    expected = {f"batch-{index}" for index in range(7)}
    for name in sorted(expected):
        await publish(org, circle, name=name, date_added=shared)

    collected: list[str] = []
    params: dict[str, str | int] = {"limit": 2}
    for _ in range(10):  # bounded, so a paging bug fails rather than hangs
        response = await client.get(
            f"/taxii2/aivs/collections/{collection.id}/objects/",
            params=params,
            headers=proxy_headers(pem),
        )
        assert response.status_code == 200
        body = response.json()
        collected.extend(obj["name"] for obj in body.get("objects", []))
        if not body.get("more"):
            break
        params = {"limit": 2, "next": body["next"]}

    assert sorted(collected) == sorted(expected), "paging skipped or duplicated an object"
    assert len(collected) == len(set(collected)), "paging returned a duplicate"


# ---------------------------------------------------------------------------
# One active collection per circle
# ---------------------------------------------------------------------------
@pytest.mark.db
async def test_second_active_collection_on_a_circle_is_rejected(
    session, make_circle, make_collection
):
    """A circle may not have two active collections.

    Two would serve the same objects under different ids and split retrieval
    receipts between them, corrupting the record of who collected what.
    """
    circle = await make_circle("section9")
    await make_collection(circle)

    session.add(TaxiiCollection(circle_id=circle.id, title="Duplicate feed", can_read=True))
    with pytest.raises(IntegrityError):
        await session.commit()
    await session.rollback()


@pytest.mark.db
async def test_a_retired_collection_may_be_replaced(session, make_circle, make_collection):
    """The constraint is partial, so retiring and replacing still works."""
    circle = await make_circle("section9")
    await make_collection(circle, is_active=False)

    replacement = TaxiiCollection(circle_id=circle.id, title="Replacement feed", can_read=True)
    session.add(replacement)
    await session.commit()

    assert replacement.id is not None
