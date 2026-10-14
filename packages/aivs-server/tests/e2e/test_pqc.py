"""Hybrid post-quantum key exchange, negotiated over a live connection (SF-71).

``tests/unit/test_proxy_config.py`` pins the committed configuration and the
image; this is the other half, which only a running proxy can show: a client
with OpenSSL 3.5 actually negotiates ``X25519MLKEM768``, and a client that
offers only classical groups still connects.

The client runs in a digest-pinned Alpine container with its OpenSSL 3.5
package, because the CI runner's own OpenSSL (3.0 on Ubuntu 24.04) has no
ML-KEM to offer.
"""

from __future__ import annotations

import subprocess

import pytest

from tests.e2e.stack import Stack, requires_stack

pytestmark = [pytest.mark.e2e, requires_stack]

#: Alpine 3.22, whose openssl package is 3.5.x.
CLIENT_IMAGE = "alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"


def negotiate(stack: Stack, *group_args: str) -> str:
    """Handshake as the member; return the client's report of the key exchange."""
    work = stack.raw["work"]
    port = stack.base_url.rsplit(":", 1)[1]
    command = (
        "apk add -q --no-cache openssl >/dev/null && echo | openssl s_client "
        f"-connect 127.0.0.1:{port} -servername localhost -CAfile /ca/ca-chain.pem "
        "-cert /m/e2e-member.crt -key /m/e2e-member.key " + " ".join(group_args) + " 2>&1"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv; the shell string is built here
        [  # noqa: S607 - docker from PATH, as the harness runs it
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "-v",
            f"{work}/ca/out:/ca:ro",
            "-v",
            f"{work}/ca/out/clients/e2e-member:/m:ro",
            CLIENT_IMAGE,
            "sh",
            "-c",
            command,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert "Verify return code: 0 (ok)" in result.stdout, result.stdout[-2000:]
    return "\n".join(
        line
        for line in result.stdout.splitlines()
        if line.startswith(("Negotiated TLS1.3 group:", "Peer Temp Key:"))
    )


def test_an_openssl_35_client_negotiates_the_hybrid_group(stack):
    assert "Negotiated TLS1.3 group: X25519MLKEM768" in negotiate(stack)


def test_a_classical_only_client_still_connects_with_x25519(stack):
    assert "X25519, 253 bits" in negotiate(stack, "-groups", "X25519")


@pytest.mark.xfail(
    strict=True,
    reason=(
        "the server takes the key share the client sent first rather than asking for "
        "the hybrid one: ssl_ecdh_curve orders support, not preference. Strict, so it "
        "fails the day the configuration makes the server prefer the hybrid group."
    ),
)
def test_a_client_that_prefers_classical_but_supports_hybrid_still_gets_hybrid(stack):
    assert "X25519MLKEM768" in negotiate(stack, "-groups", "X25519:X25519MLKEM768")
