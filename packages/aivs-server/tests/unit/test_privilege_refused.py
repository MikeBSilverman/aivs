"""A privilege the database refuses is the server's fault, logged by name, never the caller's.

The routes that store a member's content report a storage refusal as the
member's malformed content (``STORAGE_ERRORS``, a 400): a value too long for its
column is the member's to fix. A refused grant is not. With the member login's
grants an allow-list made from what the suite exercises, a member path the
suite never ran meets SQLSTATE 42501 the first time it runs in production;
reported as a 400 it told the member its bundle was bad and logged nothing for
the operator. These drive the real engine, route and handler.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from sqlalchemy import text

from aivs_schemas.enums import OrgType
from aivs_server.db.engine import PrivilegeRefusedError
from tests.conftest import proxy_headers
from tests.unit.test_submission_workflow import API, bundle

pytestmark = pytest.mark.db

#: What the database says when a grant is missing, raised as it would be.
_REFUSE = (
    "DO $$ BEGIN RAISE EXCEPTION 'permission denied for table submissions' "
    "USING ERRCODE = 'insufficient_privilege'; END $$"
)


async def test_the_engine_raises_a_refused_privilege_as_its_own_error(session):
    with pytest.raises(PrivilegeRefusedError) as refused:
        await session.execute(text(_REFUSE))
    assert (refused.value.operation, refused.value.table) == ("DO", "submissions")


async def test_a_member_meeting_a_refused_privilege_gets_a_500_and_the_operator_a_line(
    client, make_org, make_cert, monkeypatch, caplog
):
    async def _refused(session: Any, *_args: Any, **_kwargs: Any) -> None:
        await session.execute(text(_REFUSE))

    monkeypatch.setattr("aivs_server.api.submissions.create_submission", _refused)
    pem, _ = await make_cert(await make_org("refused-member", org_type=OrgType.GSIB))
    caplog.set_level(logging.ERROR, logger="aivs_server.main")

    response = await client.post(
        API,
        json={
            "title": "a title nobody may see in a log",
            "discovery_scope": "ai_system",
            "tlp": "amber",
            "distribute_anonymously": False,
            "bundle": bundle(),
        },
        headers=proxy_headers(pem),
    )

    assert response.status_code == 500, response.text
    assert response.json() == {"title": "Internal server error", "http_status": "500"}
    [line] = [r for r in caplog.records if r.getMessage() == "database refused a privilege"]
    assert (line.db_operation, line.db_table) == ("DO", "submissions")
    assert line.request_id
    assert "a title nobody may see" not in str(vars(line))
