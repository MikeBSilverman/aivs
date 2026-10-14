"""The deployment files do what the runbook tells operators they do.

Found by the Phase A review: the rotation procedure could not be followed (the
app refused the environment form it described, and compose had no way to mount
a previous key); nothing probed /readyz; and an unedited database password was
baked into the volume on first start.
"""

from __future__ import annotations

import http.server
import ipaddress
import re
import socket
import threading
from pathlib import Path

import pytest
import yaml

from aivs_server.healthcheck import is_ready

ROOT = Path(__file__).resolve().parents[4]


def _compose(name: str) -> dict:
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def test_the_rotation_override_mounts_the_previous_key_as_a_file():
    app = _compose("docker-compose.rotation.yml")["services"]["app"]
    target = app["environment"]["AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS_FILE"]

    [mount] = app["volumes"]
    assert mount["target"] == target
    assert mount["read_only"] is True
    assert mount["source"].startswith("${AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS_PATH:?")
    base_env = _compose("docker-compose.yml")["services"]["app"]["environment"]
    assert "AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS_FILE" not in base_env, "rotation only"


def test_the_runbook_rotation_never_sets_a_key_in_the_environment():
    runbook = (ROOT / "docs/operator-runbook.md").read_text(encoding="utf-8")
    rotation = runbook.split("### 7.4", 1)[1].split("### 7.5", 1)[0]

    assert "docker-compose.rotation.yml" in rotation
    assert not re.search(r"^\d+\. Set `AIVS_SECRET_ENCRYPTION_KEY", rotation, re.M)


def test_the_app_healthcheck_asks_readiness():
    app = _compose("docker-compose.yml")["services"]["app"]
    assert app["healthcheck"]["test"] == ["CMD", "python", "-m", "aivs_server.healthcheck"]
    dockerfile = (ROOT / "packages/aivs-server/Dockerfile").read_text(encoding="utf-8")
    assert '"aivs_server.healthcheck"' in dockerfile


def test_an_unedited_database_password_fails_before_anything_starts():
    """The database container cannot refuse a placeholder; compose's `:?` can,
    but only for an empty value."""
    example = (ROOT / "deploy/env.example").read_text(encoding="utf-8")
    assert re.search(r"^AIVS_DB_PASSWORD=$", example, re.M)
    db_env = _compose("docker-compose.yml")["services"]["db"]["environment"]
    assert db_env["POSTGRES_PASSWORD"].startswith("${AIVS_DB_PASSWORD:?")


class _Probe(http.server.BaseHTTPRequestHandler):
    status = 200

    def do_GET(self) -> None:
        self.send_response(self.status if self.path == "/readyz" else 404)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def readyz_answering():
    servers = []

    def _serve(status: int) -> int:
        handler = type("Handler", (_Probe,), {"status": status})
        server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server.server_address[1]

    yield _serve
    for server in servers:
        server.shutdown()
        server.server_close()


def test_ready_only_when_readyz_answers_200(readyz_answering):
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        closed_port = unused.getsockname()[1]

    assert is_ready(readyz_answering(200)) is True
    assert is_ready(readyz_answering(503)) is False
    assert is_ready(closed_port) is False


def _static_address_collisions(compose: dict) -> list[str]:
    """Static addresses Docker could also hand to a container dynamically.

    Docker allocates from a network's ``ip_range`` when one is set, otherwise
    from the whole subnet, and does not skip addresses another service merely
    asked for. A static address inside that pool goes to whichever container
    starts first.
    """
    pools = {}
    for name, network in compose.get("networks", {}).items():
        for config in (network.get("ipam") or {}).get("config", []):
            subnet = ipaddress.ip_network(config["subnet"])
            pools[name] = (subnet, ipaddress.ip_network(config.get("ip_range", config["subnet"])))
    problems = []
    for service_name, service in compose["services"].items():
        networks = service.get("networks") or {}
        if not isinstance(networks, dict):
            continue
        for network_name, attachment in networks.items():
            address = (attachment or {}).get("ipv4_address")
            if address is None:
                continue
            subnet, pool = pools[network_name]
            ip = ipaddress.ip_address(address)
            if ip not in subnet or ip in pool:
                problems.append(f"{service_name} {address} on {network_name} (pool {pool})")
    return problems


def test_no_static_address_can_be_handed_out_dynamically():
    """The first `up` on a clean host failed: the app started first, was given the
    proxy's .2, and the proxy then could not start. `docker compose config` passes
    that file; only this check, or starting the stack, sees it."""
    assert _static_address_collisions(_compose("docker-compose.yml")) == []


def test_the_collision_check_sees_the_shape_that_failed():
    compose = _compose("docker-compose.yml")
    del compose["networks"]["backend"]["ipam"]["config"][0]["ip_range"]

    assert _static_address_collisions(compose) == [
        "proxy 172.29.10.2 on backend (pool 172.29.10.0/24)"
    ]


def test_the_published_port_is_configurable_and_defaults_to_443():
    ports = _compose("docker-compose.yml")["services"]["proxy"]["ports"]

    assert ports == ["${AIVS_BIND_ADDRESS:-0.0.0.0}:${AIVS_BIND_PORT:-443}:8443"]
