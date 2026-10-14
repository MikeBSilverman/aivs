"""The proxy's TLS configuration, as committed (SF-71).

Static checks of the files a deployment runs. The negotiated group itself is
an end-to-end property; until the e2e tier exists it was verified by hand
against nginx 1.29 with OpenSSL 3.5 clients: hybrid offered -> X25519MLKEM768,
classical only -> X25519. These tests stop the configuration drifting away
from what was verified.
"""

from __future__ import annotations

import re
from pathlib import Path

HYBRID_GROUP = "X25519MLKEM768"


def _directive(conf: str, name: str) -> list[str]:
    match = re.search(rf"^\s*{name}\s+([^;]+);", conf, re.MULTILINE)
    assert match, f"{name} is not set"
    return match.group(1).split(":")


def test_the_hybrid_post_quantum_group_is_offered_first_with_a_classical_fallback(
    repo_root: Path,
):
    """First, because nginx honours the server's order when the client offers
    both; with a classical fallback after it, because a TLS 1.2 or older client
    cannot do ML-KEM and must still connect."""
    groups = _directive((repo_root / "deploy/nginx/nginx.conf").read_text(), "ssl_ecdh_curve")
    assert groups[0] == HYBRID_GROUP
    assert "X25519" in groups[1:], "a classical fallback must remain"


def test_the_default_proxy_image_is_built_with_an_openssl_that_has_ml_kem(repo_root: Path):
    """nginx-unprivileged 1.27-alpine is built with OpenSSL 3.3, which has no
    ML-KEM: the configuration above would silently fall back to classical key
    exchange for every client. 1.29 is built with 3.5."""
    compose = (repo_root / "docker-compose.yml").read_text()
    # The `image:` line itself -- a first version of this test matched the tag
    # in a comment above it and passed with the old image restored.
    match = re.search(
        r"^\s*image: \$\{AIVS_PROXY_IMAGE:-nginxinc/nginx-unprivileged:(\d+)\.(\d+)-alpine\}",
        compose,
        re.MULTILINE,
    )
    assert match, "the proxy image default has moved; update this test with it"
    assert (int(match.group(1)), int(match.group(2))) >= (1, 29)


def test_the_member_listener_answers_no_probe_or_metrics(repo_root: Path):
    """Component health and backlogs are for the ISAC's monitoring; a member
    learns nothing from them that it should."""
    conf = (repo_root / "deploy/nginx/nginx.conf").read_text()
    for path in ("/healthz", "/readyz", "/metrics"):
        assert re.search(rf"location = {re.escape(path)}\s*\{{\s*return 404;", conf), path


def test_neither_access_log_records_the_query_string(repo_root):
    """TAXII filters name what a member was looking for, and both logs are
    forwarded off the host. The app's log omitted it; nginx's did not."""
    conf = (repo_root / "deploy/nginx/nginx.conf").read_text(encoding="utf-8")
    format_block = conf.split("log_format  aivs_json", 1)[1].split(";", 1)[0]
    assert "$args" not in format_block
    assert "$query_string" not in format_block
    assert "$request_uri" not in format_block, "the request URI carries the query too"


def test_the_dev_server_does_not_rewrite_the_peer_from_forwarded_headers(repo_root):
    dev = (repo_root / "docker-compose.dev.yml").read_text(encoding="utf-8")
    assert "--no-proxy-headers" in dev
