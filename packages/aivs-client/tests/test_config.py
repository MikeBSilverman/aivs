"""Configuration resolution: what the client refuses to start without.

Each refusal here closes a configuration in which verification quietly widens:
an unset CA pin falls back to the system trust store, and plain http has no
verification at all.
"""

from __future__ import annotations

import pytest

from aivs_client.config import ConfigError, load_config

BASE = "https://aivs.test"
_SETTINGS = ("base_url", "certificate", "private_key", "ca_bundle")


@pytest.fixture
def no_ambient_config(monkeypatch, tmp_path):
    """No AIVS_* variables, and a config file path that does not exist."""
    for name in _SETTINGS:
        monkeypatch.delenv(f"AIVS_{name.upper()}", raising=False)
    return tmp_path / "absent.toml"


def explicit(**overrides: str | None) -> dict[str, str | None]:
    values: dict[str, str | None] = {
        "base_url": BASE,
        "certificate": "member.pem",
        "private_key": "member.key",
        "ca_bundle": "isac-ca.pem",
    }
    values.update(overrides)
    return values


# ---------------------------------------------------------------------------
# The CA pin is required
# ---------------------------------------------------------------------------
def test_an_unset_ca_bundle_is_a_configuration_error(no_ambient_config):
    with pytest.raises(ConfigError, match="ca_bundle"):
        load_config(**explicit(ca_bundle=None), config_path=no_ambient_config)


def test_a_set_ca_bundle_is_the_one_used(no_ambient_config):
    config = load_config(**explicit(), config_path=no_ambient_config)

    assert config.ca_bundle.name == "isac-ca.pem"


# ---------------------------------------------------------------------------
# Only https
# ---------------------------------------------------------------------------
def test_a_plain_http_base_url_is_refused(no_ambient_config):
    with pytest.raises(ConfigError, match="https"):
        load_config(**explicit(base_url="http://aivs.test"), config_path=no_ambient_config)


def test_an_https_base_url_is_accepted_without_its_trailing_slash(no_ambient_config):
    config = load_config(**explicit(base_url=BASE + "/"), config_path=no_ambient_config)

    assert config.base_url == BASE


# ---------------------------------------------------------------------------
# Resolution order: argument, then environment, then file
# ---------------------------------------------------------------------------
def test_an_argument_beats_the_environment(no_ambient_config, monkeypatch):
    monkeypatch.setenv("AIVS_CA_BUNDLE", "from-env.pem")

    config = load_config(**explicit(ca_bundle="from-arg.pem"), config_path=no_ambient_config)

    assert config.ca_bundle.name == "from-arg.pem"


def test_the_environment_beats_the_file(no_ambient_config, monkeypatch):
    no_ambient_config.write_text('[instance]\nca_bundle = "from-file.pem"\n', encoding="utf-8")
    monkeypatch.setenv("AIVS_CA_BUNDLE", "from-env.pem")

    config = load_config(**explicit(ca_bundle=None), config_path=no_ambient_config)

    assert config.ca_bundle.name == "from-env.pem"


def test_the_file_is_used_when_nothing_else_is_set(no_ambient_config):
    no_ambient_config.write_text('[instance]\nca_bundle = "from-file.pem"\n', encoding="utf-8")

    config = load_config(**explicit(ca_bundle=None), config_path=no_ambient_config)

    assert config.ca_bundle.name == "from-file.pem"
