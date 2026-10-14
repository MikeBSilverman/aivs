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


# ---------------------------------------------------------------------------
# The public member listener (SF-65)
# ---------------------------------------------------------------------------
_SUBMISSION = "/portal/submissions/0b6f3c1e-7a2d-4c55-9e1a-2f4d6b8c0a11"

#: What a member's person signed in through the IdP needs, and nothing else.
_PUBLIC_PATHS = [
    "/portal/",
    "/portal/submissions",
    _SUBMISSION,
    f"{_SUBMISSION}/submit",
    f"{_SUBMISSION}/withdraw",
    "/portal/submit",
    "/portal/logout",
    "/portal/static/theme.css",
    "/portal/sso/login",
    "/portal/sso/callback",
]

#: Everything that must stay on the certificate-bound listener.
_NOT_PUBLIC_PATHS = [
    "/api/v1/whoami",
    "/taxii2/",
    "/healthz",
    "/portal",
    "/portal/login",
    "/portal/review",
    "/portal/admin/orgs",
    f"{_SUBMISSION}/distribute",
    f"{_SUBMISSION}/validate",
    "/portal/sso/anything-else",
    "/portal/static/",
]


def _public_server_block(repo_root: Path) -> str:
    """The ``server { ... }`` that listens on 8444, by brace matching.

    Braces in comments and quoted strings are not structure to nginx -- the
    member-portal regex is quoted precisely because it contains ``{36}`` -- so
    they are blanked before counting.
    """
    conf = (repo_root / "deploy/nginx/nginx.conf").read_text(encoding="utf-8")
    structure = re.sub(r'#[^\n]*|"[^"]*"', lambda m: " " * len(m.group()), conf)
    listen = structure.index("listen       8444 ssl;")
    start = structure.rindex("server {", 0, listen)
    depth = 0
    for index in range(start, len(structure)):
        depth += {"{": 1, "}": -1}.get(structure[index], 0)
        if depth == 0 and structure[index] == "}":
            return conf[start : index + 1]
    unclosed = "the public listener's server block is not closed"
    raise AssertionError(unclosed)


def _proxied_locations(block: str) -> dict[str, str]:
    """Each regex location that proxies to the application, with its body."""
    locations = re.findall(r'location ~ ("[^"]+"|[^\s"]+) \{([^}]*)\}', block)
    return {pattern.strip('"'): body for pattern, body in locations if "proxy_pass" in body}


def _is_proxied(block: str, path: str) -> bool:
    return any(re.search(pattern, path) for pattern in _proxied_locations(block))


@pytest.mark.requirement("SF-65")
@pytest.mark.parametrize("path", _PUBLIC_PATHS)
def test_the_public_listener_proxies_the_member_portal(repo_root: Path, path: str):
    assert _is_proxied(_public_server_block(repo_root), path)


@pytest.mark.requirement("SF-65")
@pytest.mark.parametrize("path", _NOT_PUBLIC_PATHS)
def test_the_public_listener_proxies_nothing_else(repo_root: Path, path: str):
    assert not _is_proxied(_public_server_block(repo_root), path)


@pytest.mark.requirement("SF-65")
def test_everything_else_on_the_public_listener_is_answered_by_nginx(repo_root: Path):
    """No prefix location may proxy: the allow-list is the regexes above, and
    the catch-all answers 404 itself rather than asking the application."""
    block = _public_server_block(repo_root)
    prefix_locations = re.findall(r"location (/\S*) \{([^}]*)\}", block)
    assert [path for path, _ in prefix_locations] == ["/"]
    assert "proxy_pass" not in prefix_locations[0][1]
    assert "return  404" in prefix_locations[0][1]


@pytest.mark.requirement("SF-65")
def test_every_proxied_public_location_sets_the_identity_headers(repo_root: Path):
    for pattern, body in _proxied_locations(_public_server_block(repo_root)).items():
        assert "include     /etc/nginx/snippets/aivs-identity-headers.conf;" in body, pattern


@pytest.mark.requirement("SF-65")
def test_the_public_listener_asks_for_no_certificate_and_limits_sign_in(repo_root: Path):
    """No certificate is what makes the listener public; the sign-in limit is
    what stands in for the certificate against spraying."""
    block = _public_server_block(repo_root)
    assert "ssl_verify_client" not in block
    sign_in = _proxied_locations(block)[r"^/portal/sso/(login|callback)$"]
    assert "limit_req   zone=aivs_public_sign_in" in sign_in
    assert "limit_req   zone=aivs_public_pages" in block
