"""The application's healthcheck follows the database down and back up.

Until abf92a3 the healthcheck validated configuration only, so with the
database stopped every container stayed "healthy" and nothing in the stack
asked ``/readyz``. Stopping the database interrupts every other test, and the
suite runs in random order (pytest-randomly), so this module runs as its own
step after the rest (``.github/workflows/e2e.yml``); it also waits for full
recovery before it returns, so a local run of everything at once still passes.
"""

from __future__ import annotations

import subprocess
import time

import pytest

from tests.e2e.stack import Stack, requires_stack

pytestmark = [pytest.mark.e2e, requires_stack]

#: interval 30s x retries 3, plus the timeout and some slack.
_TRANSITION_SECONDS = 180


def app_health() -> str:
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Health.Status}}", "aivs-app"],  # noqa: S607 - docker from PATH, as the harness runs it
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def wait_for_health(expected: str) -> str:
    deadline = time.monotonic() + _TRANSITION_SECONDS
    status = app_health()
    while status != expected and time.monotonic() < deadline:
        time.sleep(5)
        status = app_health()
    return status


def test_the_app_goes_unhealthy_without_its_database_and_recovers(stack: Stack):
    assert app_health() == "healthy"
    stopped = stack.compose("stop", "db")
    assert stopped.returncode == 0, stopped.stderr
    try:
        assert wait_for_health("unhealthy") == "unhealthy"
    finally:
        started = stack.compose("start", "db")
        assert started.returncode == 0, started.stderr

    assert wait_for_health("healthy") == "healthy"
