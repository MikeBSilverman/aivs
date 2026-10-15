"""The digest relay's settings: complete when named, and its password from a file.

Each test is a pair: the refused configuration beside the accepted one.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from aivs_server.config import Settings
from tests.conftest import (
    TEST_ATTRIBUTION_KEY_FILE,
    TEST_CA_CERT_FILE,
    TEST_DATABASE_URL,
    TEST_MEMBER_DATABASE_URL,
    TEST_PROXY_SECRET,
    TEST_SECRET_KEY_FILE,
    TEST_SESSION_SECRET,
)


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": "staging",
        "public_base_url": "https://aivs.test",
        "database_url": TEST_DATABASE_URL,
        "member_database_url": TEST_MEMBER_DATABASE_URL,
        "proxy_shared_secret": TEST_PROXY_SECRET,
        "session_secret": TEST_SESSION_SECRET,
        "attribution_key_file": TEST_ATTRIBUTION_KEY_FILE,
        "issuing_ca_certificate_file": TEST_CA_CERT_FILE,
        "secret_encryption_key_file": TEST_SECRET_KEY_FILE,
    }
    return Settings(**(base | overrides))  # type: ignore[arg-type]


@pytest.fixture
def password_file(tmp_path: Path) -> Path:
    path = tmp_path / "smtp-password"
    path.write_text("relay-password-for-tests-only", encoding="utf-8")
    path.chmod(0o600)
    return path


@pytest.mark.requirement("NFR-S7")
def test_outside_dev_the_relay_password_comes_from_a_file(password_file: Path):
    with pytest.raises(ValidationError, match="smtp_password_file"):
        _settings(smtp_password="relay-password-for-tests-only")
    settings = _settings(smtp_password_file=password_file)
    assert settings.smtp_password is not None
    assert settings.smtp_password.get_secret_value() == "relay-password-for-tests-only"


def test_a_named_relay_needs_a_sender_and_a_password_for_its_user(password_file: Path):
    with pytest.raises(ValidationError, match="smtp_from"):
        _settings(smtp_host="relay.isac.example")
    with pytest.raises(ValidationError, match="smtp_password"):
        _settings(smtp_host="relay.isac.example", smtp_from="d@isac.example", smtp_username="u")
    assert _settings(
        smtp_host="relay.isac.example",
        smtp_from="d@isac.example",
        smtp_username="u",
        smtp_password_file=password_file,
    )


def test_an_empty_relay_variable_means_no_relay():
    """Compose spells an unset optional variable as an empty string."""
    settings = _settings(smtp_host="", smtp_from="", smtp_username="", smtp_password_file="")
    assert settings.smtp_host is None
    assert settings.smtp_password is None


def test_the_email_override_mounts_the_relay_password_as_a_file_and_the_base_stack_sends_none():
    root = Path(__file__).resolve().parents[4]
    override = yaml.safe_load(
        (root / "docker-compose.digest-email.yml").read_text(encoding="utf-8")
    )
    app = override["services"]["app"]
    [mount] = app["volumes"]
    assert mount["target"] == app["environment"]["AIVS_SMTP_PASSWORD_FILE"]
    assert mount["read_only"] is True
    assert "AIVS_SMTP_PASSWORD" not in app["environment"]
    base = yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8"))
    assert not any(name.startswith("AIVS_SMTP_") for name in base["services"]["app"]["environment"])
