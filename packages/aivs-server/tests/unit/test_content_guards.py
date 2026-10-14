"""What the review of Phase A found about content reaching the wrong place.

Each test is a pair. The defects: an anonymous submission naming its submitter
through a reference; an out-of-range timestamp reported as a server fault;
bound values (STIX content) reaching logs that are forwarded off the host; an
uncaught certificate-parsing error answered with a 500; and identity headers
the shipped proxy does not overwrite.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

import pytest
import yaml
from cryptography.exceptions import UnsupportedAlgorithm

from aivs_schemas.enums import OrgType
from aivs_server.auth import mtls
from aivs_server.config import Settings
from aivs_server.db.engine import _build_engine
from tests.conftest import TEST_PROXY_SECRET, proxy_headers

pytestmark = pytest.mark.db

API = "/api/v1/submissions"
ROOT = Path(__file__).resolve().parents[4]
STAMP = "2026-08-01T00:00:00.000Z"


def _filing(objects: list[dict], *, anonymous: bool) -> dict:
    return {
        "title": "Exploitation observed",
        "discovery_scope": "ai_system",
        "distribute_anonymously": anonymous,
        "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects},
    }


def _sighting(where: str) -> dict:
    return {
        "type": "sighting",
        "spec_version": "2.1",
        "id": f"sighting--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "sighting_of_ref": f"indicator--{uuid.uuid4()}",
        "where_sighted_refs": [where],
    }


@pytest.fixture
async def submitter(make_org, make_cert):
    org = await make_org("meridian-global", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)
    return org, pem


@pytest.mark.parametrize("spelling", [str.lower, str.upper])
async def test_an_anonymous_filing_may_not_reference_its_own_identity(client, submitter, spelling):
    """'Sighted at us' is natural to write, and names the firm to everyone."""
    org, pem = submitter
    naming = [_sighting(spelling(org.stix_identity_id))]

    anonymous = await client.post(
        API, json=_filing(naming, anonymous=True), headers=proxy_headers(pem)
    )
    attributed = await client.post(
        API, json=_filing(naming, anonymous=False), headers=proxy_headers(pem)
    )

    assert anonymous.status_code == 400
    assert "own identity" in anonymous.json()["title"]
    assert attributed.status_code == 201


async def test_a_timestamp_with_no_utc_form_is_the_members_error(client, submitter):
    org, pem = submitter
    # Sighted at the submitter itself: an attributed sighting may name only its
    # filer (SF-50), and this test is about the timestamp.
    beyond = {
        **_sighting(org.stix_identity_id),
        "modified": "9999-12-31T23:30:00-01:00",
    }
    ordinary = _sighting(org.stix_identity_id)

    refused = await client.post(
        API, json=_filing([beyond], anonymous=False), headers=proxy_headers(pem)
    )
    accepted = await client.post(
        API, json=_filing([ordinary], anonymous=False), headers=proxy_headers(pem)
    )

    assert refused.status_code == 400
    assert "representable range" in refused.json()["title"]
    assert accepted.status_code == 201


def test_bound_values_never_reach_an_exception_message(settings):
    assert _build_engine(settings).sync_engine.hide_parameters is True


def test_postgres_never_logs_a_statements_bound_values():
    """A slow INSERT of a STIX bundle would otherwise be logged in full."""
    command = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]["db"]["command"]

    assert "log_min_duration_statement=1000" in command, "the control matters only with this on"
    assert "log_parameter_max_length=0" in command
    assert "log_parameter_max_length_on_error=0" in command


class _Unparseable:
    """A genuine certificate whose signature algorithm or extensions the library
    cannot handle -- stood in for, because cryptography will not build one."""

    def __init__(self, real, *, fails_at: str, error: Exception) -> None:
        self.issuer = real.issuer
        self._real, self._fails_at, self._error = real, fails_at, error

    def verify_directly_issued_by(self, issuer) -> None:
        if self._fails_at == "signature":
            raise self._error
        self._real.verify_directly_issued_by(issuer)

    @property
    def extensions(self):
        if self._fails_at == "extensions":
            raise self._error
        return self._real.extensions


@pytest.mark.parametrize(
    ("fails_at", "error"),
    [
        ("signature", UnsupportedAlgorithm("unknown signature algorithm")),
        ("extensions", ValueError("duplicate extension")),
    ],
)
def test_an_unparseable_certificate_is_a_rejection_not_a_server_fault(ca, fails_at, error):
    _pem, _fp, certificate = ca.issue("odd-member")

    mtls.verify_issued_by(certificate, ca.certificate)  # the genuine one passes
    with pytest.raises(mtls.CertificateRejectedError):
        mtls.verify_issued_by(
            _Unparseable(certificate, fails_at=fails_at, error=error), ca.certificate
        )


def test_every_identity_header_the_app_reads_is_overwritten_by_the_proxy():
    """Two descriptions of one thing: the settings' defaults and the snippet."""
    snippet = (ROOT / "deploy/nginx/snippets/aivs-identity-headers.conf").read_text()
    overwritten = {
        line.split()[1].lower()
        for line in snippet.splitlines()
        if line.strip().startswith("proxy_set_header") and '""' not in line
    }
    fields = Settings.model_fields
    read_by_app = {
        fields[name].default
        for name in (
            "header_client_verify",
            "header_client_cert",
            "header_proxy_auth",
            "header_request_id",
            "header_real_ip",
        )
    }

    assert read_by_app <= overwritten, read_by_app - overwritten


async def test_the_access_log_records_the_member_not_the_proxy(client, submitter, caplog):
    _org, pem = submitter
    vouched = {**proxy_headers(pem), "x-real-ip": "203.0.113.7"}
    forged = {
        **proxy_headers(pem, proxy_secret="not-" + TEST_PROXY_SECRET),
        "x-real-ip": "192.0.2.9",
    }

    with caplog.at_level(logging.INFO, logger="aivs_server.access"):
        await client.get("/api/v1/whoami", headers=vouched)
        await client.get("/api/v1/whoami", headers=forged)

    clients = [r.client for r in caplog.records if r.name == "aivs_server.access"]
    assert clients[0] == "203.0.113.7"
    assert clients[1] not in {"192.0.2.9", "203.0.113.7"}
