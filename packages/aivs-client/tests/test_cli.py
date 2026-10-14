"""What the CLI promises in its help text, pinned where a test can do it cheaply.

- ``poll``: stdout is the data channel (one STIX object per line); everything
  meant for a person goes to stderr.
- ``enroll``: the argument is a slug and nothing else; the key is owner-only;
  existing files are never overwritten.
- Listings: text written by other member firms cannot forge or rewrite rows.
- Refusals exit non-zero with a hint the operator can act on.

The network is a stand-in (``httpx.MockTransport``) substituted for ``_connect``.
"""

from __future__ import annotations

import json
import stat
from collections.abc import Callable
from types import SimpleNamespace

import httpx
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from typer.testing import CliRunner

from aivs_client import cli

BASE = "https://aivs.test"
SLUG = "example-member"

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def serve(monkeypatch, tmp_path) -> Callable[[Handler], None]:
    """Replace the network with ``handler`` for the next command."""

    def install(handler: Handler) -> None:
        config = SimpleNamespace(base_url=BASE, state_dir=tmp_path / "state")
        http = httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE)
        monkeypatch.setattr(cli, "_connect", lambda *_args: (config, http))

    return install


# ---------------------------------------------------------------------------
# poll: stdout is data, stderr is for people
# ---------------------------------------------------------------------------
def _one_collection_with_two_objects(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/collections/"):
        return httpx.Response(200, json={"collections": [{"id": "c-advisories"}]})
    objects = [{"type": "vulnerability", "id": f"vulnerability--{n}"} for n in (1, 2)]
    return httpx.Response(200, json={"objects": objects, "more": False})


def test_poll_writes_only_stix_objects_to_stdout(runner, serve):
    serve(_one_collection_with_two_objects)

    result = runner.invoke(cli.app, ["poll"])

    assert result.exit_code == 0, result.output
    emitted = [json.loads(line) for line in result.stdout.splitlines()]
    assert [obj["id"] for obj in emitted] == ["vulnerability--1", "vulnerability--2"]


def test_poll_reports_its_counts_on_stderr(runner, serve):
    serve(_one_collection_with_two_objects)

    result = runner.invoke(cli.app, ["poll"])

    assert "c-advisories: 2 object(s)" in result.stderr
    assert "collected 2 object(s)" in result.stderr


# ---------------------------------------------------------------------------
# Listings: other firms' text cannot forge rows
# ---------------------------------------------------------------------------
def _submissions_titled(title: str) -> Handler:
    row = {"id": "s-1", "state": "draft", "tlp": "amber", "title": title}
    return lambda _request: httpx.Response(200, json=[row])


def test_a_listing_prints_an_ordinary_title_unchanged(runner, serve):
    serve(_submissions_titled("Prompt injection in vendor assistant"))

    result = runner.invoke(cli.app, ["submissions"])

    assert result.stdout.splitlines()[0].endswith("Prompt injection in vendor assistant")


def test_control_characters_in_a_title_cannot_forge_a_row(runner, serve):
    serve(_submissions_titled("real\ns-2  distributed  clear  forged\r\x1b[2Jgone"))

    result = runner.invoke(cli.app, ["submissions"])

    lines = result.stdout.splitlines()
    assert len(lines) == 1
    assert "\x1b" not in result.stdout
    assert "\r" not in result.stdout


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------
def test_a_refused_certificate_exits_non_zero_with_a_hint(runner, serve):
    serve(lambda _request: httpx.Response(401, json={"title": "certificate not accepted"}))

    result = runner.invoke(cli.app, ["whoami"])

    assert result.exit_code == 1
    assert "registered and not revoked" in result.stderr
    assert result.stdout == ""


def test_an_accepted_certificate_prints_the_identity(runner, serve):
    serve(lambda _request: httpx.Response(200, json={"org_slug": SLUG}))

    result = runner.invoke(cli.app, ["whoami"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"org_slug": SLUG}


# ---------------------------------------------------------------------------
# enroll
# ---------------------------------------------------------------------------
def test_enroll_writes_an_owner_only_key_and_a_csr_naming_the_slug(runner, tmp_path):
    result = runner.invoke(cli.app, ["enroll", SLUG, "--out", str(tmp_path)])

    assert result.exit_code == 0, result.output
    key_mode = stat.S_IMODE((tmp_path / f"{SLUG}.key").stat().st_mode)
    csr = x509.load_pem_x509_csr((tmp_path / f"{SLUG}.csr").read_bytes())
    assert key_mode == 0o600
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == SLUG


def test_enroll_refuses_a_name_that_is_not_a_slug(runner, tmp_path):
    out = tmp_path / "out"

    result = runner.invoke(cli.app, ["enroll", "../escaped", "--out", str(out)])

    assert result.exit_code == 2
    assert not out.exists()
    assert not (tmp_path / "escaped.key").exists()


def test_enroll_never_overwrites_an_existing_key(runner, tmp_path):
    key_path = tmp_path / f"{SLUG}.key"
    key_path.write_text("the key already in use", encoding="utf-8")

    result = runner.invoke(cli.app, ["enroll", SLUG, "--out", str(tmp_path)])

    assert result.exit_code == 2
    assert key_path.read_text(encoding="utf-8") == "the key already in use"
