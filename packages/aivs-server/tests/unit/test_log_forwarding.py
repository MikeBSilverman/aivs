"""Logs and alerts reach the ISAC's own monitoring without custom work (NFR-S13).

Two halves: the compose override forwards every container's output over
syslog/TLS, and the line the application writes for a detection still carries
OCSF and CEF once the production formatter has rendered it.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
import yaml

from aivs_server.logging_config import JsonFormatter

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / "docker-compose.yml"
FORWARD = ROOT / "docker-compose.log-forward.yml"


class _Tagged(dict[str, Any]):
    """A mapping that remembers the compose tag (``!override``) it was written with."""

    tag = ""


class _ComposeLoader(yaml.SafeLoader):
    pass


def _tagged_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> _Tagged:
    mapping = _Tagged(loader.construct_mapping(node, deep=True))
    mapping.tag = node.tag
    return mapping


for _tag in ("!override", "!reset"):
    _ComposeLoader.add_constructor(_tag, _tagged_mapping)


def _load(path: Path) -> dict[str, Any]:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_ComposeLoader)  # noqa: S506 - SafeLoader subclass


@pytest.mark.requirement("NFR-S13")
def test_every_service_in_the_stack_is_forwarded():
    """A service added to the base file without forwarding is a blind spot."""
    base_services = set(_load(BASE)["services"])
    forwarded = _load(FORWARD)["services"]

    assert set(forwarded) == base_services
    for name, service in forwarded.items():
        assert service["logging"]["driver"] == "syslog", name


@pytest.mark.requirement("NFR-S13")
def test_forwarding_replaces_the_local_policy_and_insists_on_tls():
    """Merged instead of replaced, json-file's options reach the syslog driver
    and the container refuses to start."""
    forward = _load(FORWARD)["x-forward"]
    options = forward["options"]

    assert forward.tag == "!override"
    assert "max-size" not in options
    assert options["syslog-format"].startswith("rfc5424")
    # The scheme is fixed in the file; only host:port comes from the environment.
    assert options["syslog-address"].startswith("tcp+tls://${AIVS_LOG_FORWARD_COLLECTOR:?")
    assert options["syslog-tls-ca-cert"].startswith("${AIVS_LOG_FORWARD_CA_CERT:?")
    assert options["mode"] == "non-blocking", "a collector outage must not stop the platform"


@pytest.mark.requirement("NFR-S13")
def test_a_detection_line_carries_ocsf_and_cef_through_the_production_formatter():
    record = logging.LogRecord(
        "aivs_server.security", logging.WARNING, __file__, 1, "3 refused authentications", (), None
    )
    record.ocsf = {
        "class_uid": 2004,
        "finding_info": {"uid": "auth_failure_burst:192.0.2.7", "title": "auth_failure_burst"},
        "metadata": {"product": {"name": "AIVS", "vendor_name": "AIVS"}, "version": "1.1.0"},
    }
    record.cef = "CEF:0|AIVS|AIVS|1|auth_failure_burst|3 refused|5|cnt=3 suid=192.0.2.7"

    line = json.loads(JsonFormatter().format(record))

    assert line["ocsf"]["class_uid"] == 2004
    assert line["ocsf"]["metadata"]["product"]["name"] == "AIVS", "nesting survives the depth bound"
    assert line["cef"] == record.cef
