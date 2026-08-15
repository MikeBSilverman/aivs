"""Client configuration.

Resolution order, most specific first: explicit arguments, environment
variables, then the config file at ``~/.config/aivs/config.toml``. A member
firm's collector typically sets environment variables; an analyst on a laptop
typically uses the file.

The private key path is configuration, never content. This package reads the key
from disk to present it to TLS and does nothing else with it -- it is never
logged, never sent anywhere but the TLS handshake, and never copied.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

__all__ = ["DEFAULT_CONFIG_PATH", "ClientConfig", "load_config"]

DEFAULT_CONFIG_PATH = Path(
    os.environ.get("AIVS_CONFIG", Path.home() / ".config" / "aivs" / "config.toml")
)

#: Where cursors and other client state live. Separate from the config file so
#: that configuration can be managed (or version-controlled, minus secrets)
#: without dragging mutable state along with it.
DEFAULT_STATE_DIR = Path(
    os.environ.get("AIVS_STATE_DIR", Path.home() / ".local" / "state" / "aivs")
)


class ConfigError(RuntimeError):
    """Configuration is missing or unusable."""


@dataclass(frozen=True, slots=True)
class ClientConfig:
    """Everything needed to reach an AIVS instance."""

    #: Base URL of the instance, e.g. https://aivs.exampleisac.org
    base_url: str
    #: Client certificate issued by the hosting ISAC's CA.
    certificate: Path
    #: Matching private key. Stays on this machine.
    private_key: Path
    #: CA bundle used to verify the server. Pinning to the ISAC's CA rather than
    #: the system trust store means a publicly-trusted certificate for the same
    #: hostname is not sufficient to impersonate the instance.
    ca_bundle: Path | None = None
    #: Where to keep polling cursors.
    state_dir: Path = DEFAULT_STATE_DIR
    timeout_seconds: float = 30.0

    def require_files(self) -> None:
        """Fail early and clearly if the credential files are not present."""
        missing = [
            str(path) for path in (self.certificate, self.private_key) if not Path(path).is_file()
        ]
        if self.ca_bundle is not None and not Path(self.ca_bundle).is_file():
            missing.append(str(self.ca_bundle))
        if missing:
            msg = "credential file(s) not found: " + ", ".join(missing)
            raise ConfigError(msg)


def _from_file(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    instance = data.get("instance")
    return instance if isinstance(instance, dict) else {}


def load_config(
    *,
    base_url: str | None = None,
    certificate: str | None = None,
    private_key: str | None = None,
    ca_bundle: str | None = None,
    config_path: Path | None = None,
) -> ClientConfig:
    """Resolve configuration from arguments, environment, then file."""
    file_values = _from_file(config_path or DEFAULT_CONFIG_PATH)

    def resolve(name: str, explicit: str | None) -> str | None:
        if explicit:
            return explicit
        env = os.environ.get(f"AIVS_{name.upper()}")
        if env:
            return env
        value = file_values.get(name)
        return str(value) if value is not None else None

    resolved_url = resolve("base_url", base_url)
    resolved_cert = resolve("certificate", certificate)
    resolved_key = resolve("private_key", private_key)
    resolved_ca = resolve("ca_bundle", ca_bundle)

    missing = [
        name
        for name, value in (
            ("base_url", resolved_url),
            ("certificate", resolved_cert),
            ("private_key", resolved_key),
        )
        if not value
    ]
    if missing:
        msg = (
            "missing configuration: "
            + ", ".join(missing)
            + f". Set AIVS_{missing[0].upper()} or add it to {DEFAULT_CONFIG_PATH}."
        )
        raise ConfigError(msg)

    # Narrowed by the `missing` check above; restated for the type checker.
    if not (resolved_url and resolved_cert and resolved_key):  # pragma: no cover
        msg = "configuration incomplete"
        raise ConfigError(msg)

    if not resolved_url.startswith("https://"):
        msg = f"base_url must be https, got {resolved_url!r}"
        raise ConfigError(msg)

    return ClientConfig(
        base_url=resolved_url.rstrip("/"),
        certificate=Path(resolved_cert).expanduser(),
        private_key=Path(resolved_key).expanduser(),
        ca_bundle=Path(resolved_ca).expanduser() if resolved_ca else None,
        state_dir=DEFAULT_STATE_DIR,
    )
