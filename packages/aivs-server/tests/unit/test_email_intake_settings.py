"""The intake mailbox's settings: complete when named, its password from a file (SF-93).

Each test is a pair: the refused configuration beside the accepted one.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from aivs_server.services.email_intake import MailIntake
from tests.unit.test_smtp_settings import _settings


@pytest.fixture
def password_file(tmp_path: Path) -> Path:
    path = tmp_path / "imap-password"
    path.write_text("mailbox-password-for-tests-only", encoding="utf-8")
    path.chmod(0o600)
    return path


def named(password_file: Path, **overrides: object) -> dict[str, object]:
    return {
        "email_intake_imap_host": "imap.isac.test",
        "email_intake_imap_username": "intake",
        "email_intake_imap_password_file": password_file,
        "email_intake_authserv_id": "mx.isac.test",
    } | overrides


@pytest.mark.requirement("SF-93")
def test_outside_dev_the_mailbox_password_comes_from_a_file(password_file: Path):
    with pytest.raises(ValidationError, match="email_intake_imap_password_file"):
        _settings(email_intake_imap_password="mailbox-password-for-tests-only")
    settings = _settings(**named(password_file))
    intake = MailIntake.from_settings(settings)
    assert intake is not None
    assert intake.login.password == "mailbox-password-for-tests-only"


@pytest.mark.requirement("SF-93")
@pytest.mark.parametrize(
    "missing",
    ["email_intake_imap_username", "email_intake_imap_password_file", "email_intake_authserv_id"],
)
def test_a_named_mailbox_needs_its_login_and_the_servers_authserv_id(password_file, missing):
    expected = missing.removesuffix("_file")
    with pytest.raises(ValidationError, match=expected):
        _settings(**named(password_file, **{missing: ""}))


def test_no_mailbox_named_reads_nothing_and_empty_means_unset():
    settings = _settings(
        email_intake_imap_host="",
        email_intake_imap_username="",
        email_intake_imap_password_file="",
        email_intake_authserv_id="",
    )
    assert settings.email_intake_imap_host is None
    assert MailIntake.from_settings(settings) is None


def test_the_intake_override_mounts_the_mailbox_password_as_a_file_and_the_base_stack_reads_none():
    root = Path(__file__).resolve().parents[4]
    override = yaml.safe_load(
        (root / "docker-compose.email-intake.yml").read_text(encoding="utf-8")
    )
    app = override["services"]["app"]
    [mount] = app["volumes"]
    assert mount["target"] == app["environment"]["AIVS_EMAIL_INTAKE_IMAP_PASSWORD_FILE"]
    assert mount["read_only"] is True
    assert "AIVS_EMAIL_INTAKE_IMAP_PASSWORD" not in app["environment"]
    base = yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8"))
    assert not any(
        name.startswith("AIVS_EMAIL_INTAKE_") for name in base["services"]["app"]["environment"]
    )
