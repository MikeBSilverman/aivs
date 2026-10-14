"""nginx overwrites every identity header a client sends.

The single most important property of the proxy. The application derives the
caller's identity from headers the proxy sets, so a client-supplied
``X-Client-Cert`` that survived to the app would let any certificate holder be
any member. These requests carry forged identity headers through the real
nginx and show the app resolving the certificate actually presented.
"""

from __future__ import annotations

import json
from urllib.parse import quote

import pytest

from tests.e2e.stack import Stack, requires_stack

pytestmark = [pytest.mark.e2e, requires_stack]

FORGED_ADDRESS = "203.0.113.9"


def forged_headers(stack: Stack) -> dict[str, str]:
    """Every identity header the app reads, set by the client to name the ISAC."""
    return {
        "X-Client-Cert": quote(stack.isac.cert.read_text(encoding="ascii")),
        "X-Client-Verify": "SUCCESS",
        "X-Proxy-Auth": "forged-proxy-secret-0123456789abcdef0123456789",
        "X-Real-IP": FORGED_ADDRESS,
        "X-Forwarded-For": FORGED_ADDRESS,
    }


def whoami_slug(stack: Stack, identity, headers=None) -> str:
    with stack.client(identity) as client:
        response = client.get("/api/v1/whoami", headers=headers or {})
    assert response.status_code == 200, response.text
    return str(response.json()["organization"]["slug"])


def test_a_forged_certificate_header_is_replaced_by_the_one_presented(stack):
    assert whoami_slug(stack, stack.member, forged_headers(stack)) == stack.member_slug


def test_the_forged_certificate_would_have_named_another_organisation(stack):
    """The pair: presented for real, the certificate in the forged header is the
    ISAC's, so a forgery that survived would have shown up as a different slug."""
    assert whoami_slug(stack, stack.isac) != stack.member_slug


def test_forged_identity_headers_without_a_certificate_reach_nothing(stack):
    with stack.client(None) as client:
        response = client.get("/api/v1/whoami", headers=forged_headers(stack))

    assert response.status_code == 403
    assert "client certificate is required" in response.text


def _nginx_remote_addr(stack: Stack, request_id: str) -> str:
    logs = stack.compose("logs", "--no-log-prefix", "proxy").stdout.splitlines()
    for line in logs:
        if request_id in line and line.startswith("{"):
            return str(json.loads(line)["remote_addr"])
    msg = f"no access-log line for request {request_id}"
    raise AssertionError(msg)


def test_the_audit_records_the_address_nginx_saw_not_the_one_claimed(stack):
    """A refused request is audited with a source address. It must be the one
    nginx saw on the connection, and never the client's ``X-Real-IP``."""
    with stack.client(stack.root_signed) as client:
        response = client.get("/api/v1/whoami", headers=forged_headers(stack))
    assert response.status_code == 401
    request_id = response.headers["x-request-id"]
    recorded = stack.sql(
        "SELECT source_ip FROM audit_log WHERE request_id = :'request_id'", request_id=request_id
    )

    assert recorded == _nginx_remote_addr(stack, request_id)
    assert recorded != FORGED_ADDRESS
