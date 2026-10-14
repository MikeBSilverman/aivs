"""What each listener answers, and what the host can reach at all.

The member listener (8443, published) serves the API, TAXII and the portal and
nothing operational: the probes answer 404 there, so a member cannot read the
instance's health or metrics. The internal listener (8080) answers the probe
and is not published. The application publishes nothing, which is the first of
the three controls that make header-derived identity safe.
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


def test_the_proxy_publishes_exactly_its_member_listener():
    """The pair: the inspection does see a published port where there is one."""
    assert set(published_ports("aivs-proxy")) == {"8443/tcp"}
