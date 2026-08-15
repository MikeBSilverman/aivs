"""Webhook delivery, and the address checks that keep it from being a proxy.

Webhook URLs are the only member-supplied values AIVS connects to, so this is
the one place server-side request forgery is possible. A member who could point
a webhook at cloud metadata or at a service on the ISAC's internal network would
have turned the instance into a proxy for everything it can reach and they
cannot.

Most of these tests resolve real hostnames, which is the point: the guard has to
work against what DNS actually returns, not against a mocked resolver that
returns whatever the test wants.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress

import pytest

from aivs_server.notify.webhooks import (
    SIGNATURE_VERSION,
    WebhookRejectedError,
    _address_is_forbidden,
    resolve_delivery_target,
    sign_payload,
)


# ---------------------------------------------------------------------------
# Which addresses are forbidden
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("address", "why"),
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback v6"),
        ("10.0.0.1", "RFC1918"),
        ("172.16.0.1", "RFC1918"),
        ("192.168.1.1", "RFC1918"),
        ("169.254.169.254", "cloud metadata"),
        ("fe80::1", "link-local v6"),
        ("fd00::1", "unique local v6"),
        ("224.0.0.1", "multicast"),
        ("0.0.0.0", "unspecified"),  # noqa: S104 - asserting this is REFUSED
        ("240.0.0.1", "reserved"),
    ],
)
def test_non_routable_addresses_are_forbidden(address, why):
    """Categories, not a list of specific addresses.

    169.254.169.254 is the one people remember; it is caught here because
    link-local is a category, which is why the check will still hold when the
    next such address is invented.
    """
    assert _address_is_forbidden(ipaddress.ip_address(address)) is True, why


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1"])
def test_public_addresses_are_permitted(address):
    """The check must not be so broad that no real endpoint qualifies."""
    assert _address_is_forbidden(ipaddress.ip_address(address)) is False


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://example.com/hook", "scheme_not_https"),
        ("ftp://example.com/hook", "scheme_not_https"),
        ("https://user:pass@example.com/hook", "credentials_in_url"),
    ],
)
def test_unacceptable_urls_are_refused(url, reason):
    with pytest.raises(WebhookRejectedError) as caught:
        resolve_delivery_target(url)
    assert caught.value.reason == reason


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/hook",
        "https://127.0.0.1/hook",
        "https://[::1]/hook",
        "https://169.254.169.254/latest/meta-data/",
        "https://10.0.0.5/hook",
    ],
)
def test_internal_targets_are_refused(url):
    """Resolved and judged, whether the URL names an address or a hostname."""
    with pytest.raises(WebhookRejectedError) as caught:
        resolve_delivery_target(url)
    assert caught.value.reason.startswith("address_not_routable")


def test_a_hostname_that_does_not_resolve_is_refused():
    with pytest.raises(WebhookRejectedError) as caught:
        resolve_delivery_target("https://this-name-should-not-exist.invalid/hook")
    assert caught.value.reason == "dns_resolution_failed"


def test_the_private_escape_hatch_is_explicit():
    """Tests must point at loopback, so the exemption is a named argument.

    It is gated to non-production in Settings; if it is ever true there, that is
    the hole this whole module exists to prevent.
    """
    target = resolve_delivery_target("https://127.0.0.1:9443/hook", allow_private=True)
    assert target.hostname == "127.0.0.1"
    assert target.port == 9443


def test_a_validated_target_keeps_the_hostname_for_tls():
    """The connection is pinned to the checked address; the name is still presented.

    Without that, TLS would be verified against an IP literal and the
    certificate the member actually holds would not match.
    """
    target = resolve_delivery_target("https://127.0.0.1/hook", allow_private=True)
    assert target.hostname == "127.0.0.1"
    assert target.address == "127.0.0.1"
    assert target.port == 443


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------
def test_the_signature_covers_the_timestamp_and_the_body():
    """Signing the body alone would leave a genuine notification replayable."""
    secret = b"a-shared-secret"
    body = b'{"event":"test"}'
    timestamp = "2026-08-01T00:00:00+00:00"

    signature = sign_payload(secret, body, timestamp)
    expected = hmac.new(secret, timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()

    assert signature == f"{SIGNATURE_VERSION}={expected}"


def test_a_different_timestamp_produces_a_different_signature():
    secret = b"a-shared-secret"
    body = b'{"event":"test"}'
    assert sign_payload(secret, body, "2026-08-01T00:00:00+00:00") != sign_payload(
        secret, body, "2026-08-01T00:00:01+00:00"
    )


def test_a_different_body_produces_a_different_signature():
    secret = b"a-shared-secret"
    timestamp = "2026-08-01T00:00:00+00:00"
    assert sign_payload(secret, b'{"a":1}', timestamp) != sign_payload(
        secret, b'{"a":2}', timestamp
    )


def test_the_signature_is_versioned():
    """So the scheme can change without receivers guessing which one they hold."""
    assert sign_payload(b"s", b"b", "t").startswith(f"{SIGNATURE_VERSION}=")
