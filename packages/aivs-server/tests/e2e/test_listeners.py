"""What each listener answers, and what the host can reach at all.

The member listener (8443, published) serves the API, TAXII and the portal and
nothing operational: the probes answer 404 there, so a member cannot read the
instance's health or metrics. The public member listener (8444, published by
docker-compose.public.yml) asks for no certificate and serves the member
portal's own paths only; nginx answers everything else itself (SF-65). The
internal listener (8080) answers the probe and is not published. The
application publishes nothing, which is the first of the three controls that
make header-derived identity safe.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from tests.e2e.stack import requires_stack

pytestmark = [pytest.mark.e2e, requires_stack]


def published_ports(container: str) -> dict[str, object]:
    result = subprocess.run(  # noqa: S603 - fixed argv
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", container],  # noqa: S607 - docker from PATH, as the harness runs it
        capture_output=True,
        text=True,
        check=True,
    )
    ports: dict[str, object] = json.loads(result.stdout)
    return {port: binding for port, binding in ports.items() if binding}


@pytest.mark.parametrize("path", ["/healthz", "/readyz", "/metrics"])
def test_the_probes_answer_404_on_the_member_listener(stack, path):
    with stack.client(stack.member) as client:
        response = client.get(path)

    assert response.status_code == 404


def test_the_member_listener_still_serves_the_api_to_the_same_client(stack):
    with stack.client(stack.member) as client:
        assert client.get("/api/v1/whoami").status_code == 200


def test_the_internal_listener_answers_the_probe(stack):
    result = stack.compose("exec", "-T", "proxy", "wget", "-qO-", "http://127.0.0.1:8080/healthz")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"status": "ok"}


def test_the_internal_listener_serves_nothing_else(stack):
    result = stack.compose(
        "exec", "-T", "proxy", "wget", "-qO-", "http://127.0.0.1:8080/api/v1/whoami"
    )

    assert result.returncode != 0
    assert "404" in result.stderr


def test_the_application_publishes_no_host_port():
    assert published_ports("aivs-app") == {}


def test_the_proxy_publishes_exactly_its_member_listeners():
    """The pair: the inspection does see a published port where there is one."""
    assert set(published_ports("aivs-proxy")) == {"8443/tcp", "8444/tcp"}


#: nginx's own answer on the public listener, which no application response has.
NOT_SERVED = "not served on this listener\n"


@pytest.mark.requirement("SF-65")
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/whoami",
        "/taxii2/",
        "/portal/admin/orgs",
        "/portal/login",
        "/portal/review",
        "/healthz",
        "/metrics",
        # An allowed prefix walked out of: nginx matches the decoded,
        # normalised path, so this is /api/v1/whoami by the time it is routed.
        "/portal/submissions/..%2F..%2Fapi/v1/whoami",
        "/portal/vulnerabilities/..%2F..%2Fapi/v1/whoami",
    ],
)
def test_the_public_listener_answers_everything_but_the_member_portal_itself(stack, path):
    with stack.public_client() as client:
        response = client.get(path)

    assert response.status_code == 404
    assert response.text == NOT_SERVED


@pytest.mark.requirement("SF-65")
@pytest.mark.parametrize("path", ["/portal/", "/portal/vulnerabilities?id=CVE-2026-1234"])
def test_the_public_listener_passes_the_member_portal_to_the_application(stack, path):
    """The pair: an allowed path is answered by the application, which sends
    a person with no session to sign in."""
    with stack.public_client() as client:
        response = client.get(path)

    assert response.status_code == 303
    assert response.text != NOT_SERVED


@pytest.mark.requirement("SF-65")
def test_a_certificate_bound_session_is_worth_nothing_on_the_public_listener(stack, isac_bearer):
    """The ISAC operator's own session, with its certificate offered too: the
    listener never asks for the certificate, so the session has no binding."""
    token = isac_bearer["authorization"].removeprefix("Bearer ")
    with stack.public_client(stack.isac) as client:
        client.cookies.set("aivs_session", token)
        response = client.get("/portal/")

    assert response.status_code == 303
    with stack.client(stack.isac) as client:
        client.cookies.set("aivs_session", token)
        assert client.get("/portal/").status_code == 200


@pytest.mark.requirement("SF-65")
def test_signing_in_on_the_public_listener_is_rate_limited(stack):
    """Ten a minute per address with a burst of five; the sixth-plus in a
    tight loop is refused by nginx before the application sees it."""
    with stack.public_client() as client:
        statuses = [client.get("/portal/sso/login").status_code for _ in range(12)]

    assert 429 in statuses
    assert statuses[0] != 429
