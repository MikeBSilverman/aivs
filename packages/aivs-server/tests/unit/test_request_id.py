"""The request id an audit row carries is the proxy's, never one a caller chose.

nginx overwrites ``X-Request-Id`` on every request it forwards, because a
caller-chosen id lets someone plant entries that correlate with an audit trail.
A request that reaches the app without the proxy's credential -- from inside
the container network, say -- could still choose it, so the app takes the
header only from a request the proxy vouches for.
"""

from __future__ import annotations

import pytest

from tests.conftest import proxy_headers

pytestmark = pytest.mark.db

CHOSEN = "chosenbythecaller0123456789"


async def test_a_request_the_proxy_did_not_send_gets_its_own_request_id(client):
    response = await client.get("/api/v1/whoami", headers={"x-request-id": CHOSEN})

    assert response.status_code == 401
    assert response.headers["x-request-id"] != CHOSEN


async def test_the_proxys_request_id_is_kept_for_correlation(client, make_org, make_cert):
    """The pair: behind the proxy the id spans nginx's log and the app's."""
    org = await make_org("meridian-global")
    pem, _ = await make_cert(org)

    response = await client.get(
        "/api/v1/whoami", headers={**proxy_headers(pem), "x-request-id": CHOSEN}
    )

    assert response.headers["x-request-id"] == CHOSEN
