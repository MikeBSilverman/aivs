"""The proxy's TLS configuration, as committed (SF-71).

Static checks of the files a deployment runs. The negotiated group itself is
an end-to-end property, checked against the running proxy by
``tests/e2e/test_pqc.py``; these tests stop the committed configuration
drifting away from the shape that run verified.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

HYBRID_GROUP = "X25519MLKEM768"


def _group_tuples(conf: str) -> list[list[str]]:
    """``ssl_ecdh_curve`` as OpenSSL 3.5 reads it: tuples split by ``/``, groups by ``:``."""
    match = re.search(r"^\s*ssl_ecdh_curve\s+([^;]+);", conf, re.MULTILINE)
    assert match, "ssl_ecdh_curve is not set"
    return [group_tuple.split(":") for group_tuple in match.group(1).split("/")]


@pytest.mark.requirement("SF-71")
@pytest.mark.requirement("NFR-S14")
def test_the_hybrid_post_quantum_group_is_preferred_with_a_classical_fallback(
    repo_root: Path,
):
    """Alone in the first tuple, because within a tuple OpenSSL takes whichever
    group the client already sent a key share for: written as one list, a client
    that supports ML-KEM but led with X25519 was given X25519. The fallback stays
    in a later tuple, because a TLS 1.2 or older client cannot do ML-KEM and must
    still connect."""
    tuples = _group_tuples((repo_root / "deploy/nginx/nginx.conf").read_text())
    assert tuples[0] == [HYBRID_GROUP]
    assert any("X25519" in later for later in tuples[1:]), "a classical fallback must remain"


@pytest.mark.requirement("SF-71")
def test_the_default_proxy_image_is_built_with_an_openssl_that_has_ml_kem(repo_root: Path):
    """nginx-unprivileged 1.27-alpine is built with OpenSSL 3.3, which has no
    ML-KEM: the configuration above would silently fall back to classical key
    exchange for every client. 1.29 is built with 3.5."""
    compose = (repo_root / "docker-compose.yml").read_text()
    # The `image:` line itself -- a first version of this test matched the tag
    # in a comment above it and passed with the old image restored.
    match = re.search(
        r"^\s*image: \$\{AIVS_PROXY_IMAGE:-nginxinc/nginx-unprivileged:(\d+)\.(\d+)-alpine"
        r"(?:@sha256:[0-9a-f]{64})?\}",
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
