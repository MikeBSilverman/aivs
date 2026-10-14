"""Every request is logged once, without its query string.

``main.py`` turned uvicorn's access log off on the ground that this middleware
"emits structured access logs" -- and it emitted none, so per-request coverage
rested entirely on nginx. A request the application refuses is the one an
operator most needs to find, so the refused case is half of the pair.
"""

from __future__ import annotations

import logging

import pytest

from aivs_schemas.enums import OrgType
from tests.conftest import proxy_headers

pytestmark = pytest.mark.db


@pytest.mark.requirement("NFR-S5")
async def test_each_request_is_logged_once_with_status_and_without_its_query(
    client, make_org, make_cert, caplog
):
    member = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(member)

    with caplog.at_level(logging.INFO, logger="aivs_server.access"):
        served = await client.get(
            "/api/v1/whoami?secret-filter=cve-2026-1234", headers=proxy_headers(pem)
        )
        refused = await client.get("/api/v1/whoami")

    assert served.status_code == 200
    assert refused.status_code == 401
    lines = [record for record in caplog.records if record.name == "aivs_server.access"]
    assert [(line.path, line.status) for line in lines] == [
        ("/api/v1/whoami", 200),
        ("/api/v1/whoami", 401),
    ]
    assert all(line.duration_ms >= 0 for line in lines)
    # Every field of every record, not caplog.text: the text is only the
    # message, so a query string carried as a structured field would pass a
    # check of the text.
    assert all("cve-2026-1234" not in str(vars(line)) for line in lines)
