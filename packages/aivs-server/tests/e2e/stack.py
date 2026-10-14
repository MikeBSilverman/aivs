"""The running stack, as the end-to-end tests and the enrolment step see it.

``scripts/e2e.sh up`` writes ``state.json`` describing what it built: where the
certificates are, how to sign the ISAC operator in. Everything here reads that
file and talks to the stack the way a member or an operator would -- through
nginx on the published port, with a client certificate -- or, for the few
facts only the host can see, through ``docker``.

Unless ``AIVS_E2E_STATE`` names a state file that exists, every e2e test is
skipped with a reason that says how to start a stack. The skip is a ``skipif``
marker evaluated at collection, so the requirement census
(``tests/test_requirements_pinned.py``) does not count an e2e test as a pin in
a run where it cannot have run.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import ssl
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pyotp
import pytest

#: Opt-in by variable, never by finding a file: a stack left up locally must
#: not turn an ordinary `uv run pytest` into an e2e run that stops its database.
_STATE_VARIABLE = os.environ.get("AIVS_E2E_STATE", "")
STATE_PATH = Path(_STATE_VARIABLE)

TAXII_ACCEPT = "application/taxii+json;version=2.1"

requires_stack = pytest.mark.skipif(
    not (_STATE_VARIABLE and STATE_PATH.is_file()),
    reason=(
        "no end-to-end stack: run `scripts/e2e.sh up`, then set AIVS_E2E_STATE to the "
        "state.json it prints"
    ),
)


@dataclass(frozen=True)
class Identity:
    cert: Path
    key: Path


@dataclass(frozen=True)
class Stack:
    raw: dict[str, Any]

    @property
    def base_url(self) -> str:
        return str(self.raw["base_url"])

    @property
    def public_base_url(self) -> str:
        """The public member listener, published by docker-compose.public.yml."""
        return str(self.raw["public_base_url"])

    @property
    def ca_chain(self) -> Path:
        return Path(self.raw["ca_chain"])

    @property
    def isac(self) -> Identity:
        return Identity(Path(self.raw["isac"]["cert"]), Path(self.raw["isac"]["key"]))

    @property
    def member(self) -> Identity:
        return Identity(Path(self.raw["member"]["cert"]), Path(self.raw["member"]["key"]))

    @property
    def root_signed(self) -> Identity:
        return Identity(Path(self.raw["root_signed"]["cert"]), Path(self.raw["root_signed"]["key"]))

    @property
    def member_slug(self) -> str:
        return str(self.raw["member"]["slug"])

    def client(self, identity: Identity | None) -> httpx.Client:
        """An HTTPS client that verifies the proxy against the ISAC's chain.

        Built from an explicit SSL context: httpx's ``cert=`` and ``verify=<path>``
        arguments cancel each other out (CLAUDE.md section 5).
        """
        context = ssl.create_default_context(cafile=str(self.ca_chain))
        if identity is not None:
            context.load_cert_chain(str(identity.cert), str(identity.key))
        return httpx.Client(base_url=self.base_url, verify=context, timeout=30.0)

    def public_client(self, identity: Identity | None = None) -> httpx.Client:
        """A browser on the public listener, which asks for no certificate.

        ``identity`` is offered anyway when given, to show that a certificate
        on this listener counts for nothing.
        """
        context = ssl.create_default_context(cafile=str(self.ca_chain))
        if identity is not None:
            context.load_cert_chain(str(identity.cert), str(identity.key))
        return httpx.Client(base_url=self.public_base_url, verify=context, timeout=30.0)

    def compose(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        command = [
            "docker",
            "compose",
            "-p",
            str(self.raw["project"]),
            "--env-file",
            str(self.raw["env_file"]),
            *(arg for path in self.raw["compose_files"] for arg in ("-f", str(path))),
            *args,
        ]
        return subprocess.run(  # noqa: S603 - fixed argv built above
            command, input=stdin, capture_output=True, text=True, check=False, timeout=600
        )

    def sql(self, query: str, **params: str) -> str:
        """Run one read-only query in the database container; return its unaligned output.

        ``params`` are bound as psql variables and referenced as ``:'name'`` in
        the query, which psql quotes as a literal, so no value is ever spliced
        into the SQL text.
        """
        bindings = [arg for name, value in params.items() for arg in ("-v", f"{name}={value}")]
        # The socket requires the password too (scram-sha-256 for local
        # connections), and the container already holds it; reading it there
        # keeps it off the host's command lines.
        result = self.compose(
            "exec",
            "-T",
            "db",
            "sh",
            "-c",
            'PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At "$@"',
            "psql",
            *bindings,
            stdin=query,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    def _unspent_totp_code(self, seed: str) -> str:
        """A code for a time step this harness has not signed in with yet.

        Each code signs in once (RFC 6238 section 5.2), and the enrolment step
        and the tests sign the same operator in within seconds of each other,
        so the step last used is kept beside the state and a repeat waits for
        the next window rather than being refused.
        """
        totp = pyotp.TOTP(seed)
        spent_path = Path(self.raw["work"]) / "secrets" / "isac-last-totp-step"
        spent = int(spent_path.read_text(encoding="utf-8")) if spent_path.is_file() else -1
        if totp.timecode(dt.datetime.now(dt.UTC)) <= spent:
            time.sleep(_seconds_to_next_step(totp))
        now = dt.datetime.now(dt.UTC)
        spent_path.write_text(str(totp.timecode(now)), encoding="utf-8")
        return totp.at(now)

    def isac_bearer(self) -> dict[str, str]:
        """Sign the ISAC operator in through the portal; return API headers for that session.

        The bearer is the portal session's own token, bound to the ISAC
        certificate, so every API call that uses it must present that
        certificate as well.
        """
        password = Path(self.raw["isac"]["password_file"]).read_text(encoding="utf-8")
        uri = Path(self.raw["isac"]["totp_uri_file"]).read_text(encoding="utf-8")
        code = self._unspent_totp_code(parse_qs(urlparse(uri).query)["secret"][0])
        with self.client(self.isac) as browser:
            form = browser.get("/portal/login")
            assert form.status_code == 200, form.text
            token = re.search(r'name="csrf_token" value="([^"]+)"', form.text)
            assert token, "the sign-in form carried no CSRF token"
            signed_in = browser.post(
                "/portal/login",
                data={
                    "email": self.raw["isac"]["email"],
                    "password": password,
                    "totp_code": code,
                    "csrf_token": token.group(1),
                },
            )
            assert signed_in.status_code == 303, signed_in.text
            session_token = signed_in.cookies.get("aivs_session")
        assert session_token, "sign-in set no session cookie"
        return {"authorization": f"Bearer {session_token}"}


def _seconds_to_next_step(totp: pyotp.TOTP) -> float:
    return totp.interval - (time.time() % totp.interval) + 0.5


def load_stack() -> Stack:
    return Stack(json.loads(STATE_PATH.read_text(encoding="utf-8")))
