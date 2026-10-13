"""The deployment files do what the runbook tells operators they do.

Found by the Phase A review: the rotation procedure could not be followed (the
app refused the environment form it described, and compose had no way to mount
a previous key); nothing probed /readyz; and an unedited database password was
baked into the volume on first start.
"""

from __future__ import annotations

import http.server
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
