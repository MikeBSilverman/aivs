"""Container healthcheck: valid configuration, and ready to serve.

    python -m aivs_server.healthcheck

Exit 0 when the settings validate (every posture check included) and
``/readyz`` on loopback answers 200; 1 otherwise. The previous check validated
configuration only, so with the database down every container stayed healthy
and nothing in the stack ever asked ``/readyz`` -- the probe the docs described
as the orchestrator's. A degraded background component keeps ``/readyz`` at 200
by design; it is reported by name there and on ``/metrics``.
"""

from __future__ import annotations

import http.client
import sys
from typing import Final

from aivs_server.config import ConfigurationError, get_settings

__all__ = ["is_ready"]

_TIMEOUT_SECONDS: Final[float] = 5.0


def is_ready(port: int) -> bool:
    """Whether the application on this host answers ``/readyz`` with 200."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=_TIMEOUT_SECONDS)
    try:
        connection.request("GET", "/readyz")
        return connection.getresponse().status == http.client.OK
    except OSError:
        return False
    finally:
        connection.close()


def main() -> int:  # pragma: no cover - process entry point; is_ready is tested
    try:
        settings = get_settings()
    except ConfigurationError as exc:
        print(f"configuration refused: {exc}", file=sys.stderr)  # noqa: T201 - healthcheck output
        return 1
    return 0 if is_ready(settings.bind_port) else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
