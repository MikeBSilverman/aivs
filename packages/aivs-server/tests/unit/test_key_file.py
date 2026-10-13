"""Outside dev the key-encryption key comes from a file only its owner can read.

The environment is shown by ``docker inspect``, ``/proc/<pid>/environ``, crash
dumps and orchestration dashboards, and this key opens every sealed TOTP seed
and webhook signing key. Each test is a pair: the refused configuration beside
the accepted one.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from aivs_server.config import Settings
from tests.conftest import (
    TEST_CA_CERT_FILE,
    TEST_DATABASE_URL,
    TEST_PROXY_SECRET,
    TEST_SECRET_KEY,
    TEST_SECRET_KEY_FILE,
    TEST_SESSION_SECRET,
)


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": "staging",
        "public_base_url": "https://aivs.test",
        "database_url": TEST_DATABASE_URL,
        "proxy_shared_secret": TEST_PROXY_SECRET,
        "session_secret": TEST_SESSION_SECRET,
        "issuing_ca_certificate_file": TEST_CA_CERT_FILE,
    }
    return Settings(**(base | overrides))  # type: ignore[arg-type]


def test_outside_dev_the_environment_form_is_refused_and_the_file_accepted():
    with pytest.raises(ValidationError, match="secret_encryption_key_file"):
        _settings(secret_encryption_key=TEST_SECRET_KEY)
    settings = _settings(secret_encryption_key_file=TEST_SECRET_KEY_FILE)
    assert settings.secret_encryption_key.get_secret_value() == TEST_SECRET_KEY


def test_dev_may_still_use_the_environment():
    """The interlock is "permit only dev", like every other posture rule."""
    assert _settings(environment="dev", secret_encryption_key=TEST_SECRET_KEY)


def test_a_key_file_others_can_read_is_refused(tmp_path: Path):
    readable = tmp_path / "readable-key"
    readable.write_text(TEST_SECRET_KEY, encoding="utf-8")
    readable.chmod(0o644)
    private = tmp_path / "private-key"
    private.write_text(TEST_SECRET_KEY, encoding="utf-8")
    private.chmod(0o600)

    with pytest.raises(ValidationError, match="readable by group or others"):
        _settings(secret_encryption_key_file=readable)
    assert _settings(secret_encryption_key_file=private)


def test_setting_both_forms_is_refused_not_resolved():
    """Two sources for one key is the shape that drifts."""
    with pytest.raises(ValidationError, match="not both"):
        _settings(
            secret_encryption_key=TEST_SECRET_KEY,
            secret_encryption_key_file=TEST_SECRET_KEY_FILE,
        )


def test_a_rotations_previous_key_is_held_to_the_same_rule(tmp_path: Path):
    """It still opens every row not yet re-wrapped."""
    previous = tmp_path / "previous-key"
    previous.write_text(TEST_SECRET_KEY, encoding="utf-8")
    previous.chmod(0o600)

    with pytest.raises(ValidationError, match="secret_encryption_key_previous_file"):
        _settings(
            secret_encryption_key_file=TEST_SECRET_KEY_FILE,
            secret_encryption_key_previous=TEST_SECRET_KEY,
        )
    assert _settings(
        secret_encryption_key_file=TEST_SECRET_KEY_FILE,
        secret_encryption_key_previous_file=previous,
    ).secret_encryption_key_previous


def test_an_unreadable_key_path_is_a_configuration_error_not_a_crash(tmp_path: Path):
    """A directory at the path passes stat() and failed at read as a raw
    IsADirectoryError, outside the configuration-error path."""
    directory = tmp_path / "secret-encryption-key"
    directory.mkdir(mode=0o700)
    private = tmp_path / "private-key"
    private.write_text(TEST_SECRET_KEY, encoding="utf-8")
    private.chmod(0o600)

    with pytest.raises(ValidationError, match="cannot be read"):
        _settings(secret_encryption_key_file=directory)
    assert _settings(secret_encryption_key_file=private)
