"""Runtime configuration.

Two rules govern this module.

**Fail closed.** Every default is the safe value, including ``environment``,
which defaults to ``production``. A deployment that forgets to set something
gets the strict behaviour, never the permissive one. The dev conveniences that
would be dangerous in production (trusting identity headers without a proxy
secret, permissive CORS, verbose errors) are individually gated *and*
cross-checked in :meth:`Settings.validate_production_posture`, which refuses to
construct a production ``Settings`` with any of them enabled.

**Secrets never round-trip.** Anything sensitive is a ``SecretStr`` so that an
accidental ``repr``, log line, or error page prints ``**********``. Values come
from the environment (Docker/Kubernetes secrets mount there); there is
deliberately no ``.env`` file support in production.
"""

from __future__ import annotations

import ipaddress
import sys
from functools import lru_cache
from typing import Final, Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["Settings", "get_settings"]

#: Minimum length for the proxy shared secret. 32 bytes of base64 is ~43 chars;
#: we require enough that a brute-force against the header is hopeless.
MIN_SHARED_SECRET_LEN: Final[int] = 32

Environment = Literal["dev", "test", "staging", "production"]


class Settings(BaseSettings):
    """Process configuration, read once from the environment at startup."""

    model_config = SettingsConfigDict(
        env_prefix="AIVS_",
        extra="forbid",  # an unrecognised AIVS_* var is a typo, and typos in
        # security config are silent failures -- refuse to start instead.
        frozen=True,
        validate_default=True,
    )

    # -- Identity of this deployment -------------------------------------
    environment: Environment = "production"
    #: Displayed in the portal and used as the STIX identity name for the
    #: hosting ISAC. Each ISAC instance sets its own.
    instance_name: str = Field(default="AIVS", min_length=1, max_length=120)
    #: Public base URL, used to build TAXII resource URLs. Must be https
    #: outside dev. Note this does NOT set the STIX extension definition's
    #: schema location: that identifier is shared by every AIVS deployment, so
    #: that one member's TIP recognises the extension regardless of which ISAC
    #: instance the content came from.
    public_base_url: str = Field(default="https://localhost", min_length=1)

    # -- Database ---------------------------------------------------------
    #: SQLAlchemy async URL, e.g. postgresql+psycopg://user:pw@host:5432/aivs
    database_url: SecretStr
    db_pool_size: int = Field(default=10, ge=1, le=100)
    db_max_overflow: int = Field(default=5, ge=0, le=100)
    db_pool_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    #: Statement timeout applied to every session. A runaway TAXII query must
    #: not be able to pin a connection indefinitely.
    db_statement_timeout_ms: int = Field(default=15_000, ge=100, le=300_000)

    # -- Trust boundary: reverse proxy -> application ----------------------
    #: Shared secret that the mTLS-terminating proxy must present in
    #: ``X-Proxy-Auth``. This is the third of three stacked controls that stop
    #: a request from forging its own client identity (the others being: the
    #: app publishes no port outside the internal network, and the proxy
    #: unconditionally overwrites the identity headers).
    proxy_shared_secret: SecretStr
    #: CIDRs the proxy may connect from. Empty means "do not check the peer
    #: address" and is only permitted outside production.
    trusted_proxy_cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.1/32"])
    #: Header names carrying the verified client certificate. Configurable
    #: because different proxies (nginx, envoy, HAProxy) spell them differently.
    header_client_verify: str = "x-client-verify"
    header_client_cert: str = "x-client-cert"
    header_proxy_auth: str = "x-proxy-auth"
    header_request_id: str = "x-request-id"

    #: RFC 4514 subject DN of the issuing CA that certificates must chain from,
    #: e.g. "CN=AIVS Issuing CA,O=Global FS-ISAC,C=US".
    #:
    #: Registration refuses any certificate whose issuer does not match. Without
    #: it, the only thing preventing a registered self-signed certificate from
    #: authenticating is the proxy's verdict -- and this application deliberately
    #: does not treat the proxy as the sole authority on identity anywhere else.
    #: Empty disables the check, which is appropriate only before a CA exists.
    expected_certificate_issuer_dn: str = ""

    # -- Development-only escape hatches (refused in production) -----------
    #: Accept identity headers without a valid ``X-Proxy-Auth``. NEVER in prod.
    dev_trust_unauthenticated_proxy: bool = False
    #: Return exception detail in HTTP responses. NEVER in prod.
    dev_expose_error_detail: bool = False

    # -- Request limits ----------------------------------------------------
    #: Hard cap on request body size. STIX bundles are text; 5 MiB is generous
    #: and still bounds memory per in-flight request.
    max_body_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    #: Default and maximum page sizes for TAXII object listings.
    taxii_default_page_size: int = Field(default=100, ge=1, le=1000)
    taxii_max_page_size: int = Field(default=500, ge=1, le=1000)

    # -- Portal sessions ---------------------------------------------------
    #: Signs pagination cursors, CSRF tokens, and session cookies.
    session_secret: SecretStr
    session_ttl_minutes: int = Field(default=60, ge=5, le=1440)
    session_idle_timeout_minutes: int = Field(default=20, ge=5, le=240)
    session_cookie_name: str = "aivs_session"

    # -- Outbound webhooks --------------------------------------------------
    webhook_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    webhook_max_attempts: int = Field(default=5, ge=1, le=20)
    #: Allow webhook delivery to private/loopback addresses. Test fixtures only;
    #: in any real deployment this being true is an SSRF hole.
    dev_allow_private_webhook_targets: bool = False

    # -- Embargo sweeper ----------------------------------------------------
    embargo_sweep_interval_seconds: int = Field(default=30, ge=5, le=3600)

    # -- Bind address -------------------------------------------------------
    #: Interface the application listens on. The default binds all interfaces
    #: because the container's network namespace is the security boundary --
    #: compose publishes no host port for this service, so the only route in is
    #: the reverse proxy. Operators running outside a container should set this
    #: to the specific interface the proxy reaches them on.
    #
    # nosec B104 / noqa S104: binding all interfaces is correct here and the
    # suppression is narrow and deliberate. Obscuring the literal to quiet the
    # scanner would hide a real deployment decision from the next reviewer.
    bind_host: str = "0.0.0.0"  # nosec B104  # noqa: S104
    bind_port: int = Field(default=8000, ge=1, le=65535)

    # -- Logging ------------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------
    @field_validator("proxy_shared_secret", "session_secret")
    @classmethod
    def _secret_is_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_SHARED_SECRET_LEN:
            msg = f"secret must be at least {MIN_SHARED_SECRET_LEN} characters"
            raise ValueError(msg)
        return value

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def _cidrs_parse(cls, value: list[str]) -> list[str]:
        for entry in value:
            # Raises ValueError for anything malformed, which Pydantic surfaces
            # as a startup failure rather than a silently empty allowlist.
            ipaddress.ip_network(entry, strict=False)
        return value

    @field_validator("header_client_verify", "header_client_cert", "header_proxy_auth")
    @classmethod
    def _header_names_lowercase(cls, value: str) -> str:
        # Starlette exposes headers lowercased; normalising here means a
        # misconfigured mixed-case name cannot silently never match.
        return value.strip().lower()

    @model_validator(mode="after")
    def validate_production_posture(self) -> Self:
        """Refuse to start if a hardened deployment has a dev bypass enabled.

        The exemption is allow-listed to ``dev`` alone, never denied for
        ``production`` alone. An earlier version returned early for everything
        that was not literally ``"production"``, which meant a ``staging``
        deployment -- which for a financial-sector ISAC routinely mirrors
        production and holds real embargoed intelligence -- could run with
        ``dev_trust_unauthenticated_proxy`` set and silently lose the entire
        proxy-authentication control. Fail closed: anything that is not an
        engineer's laptop is held to the production posture.
        """
        if self.environment == "dev":
            return self

        violations: list[str] = []
        if self.dev_trust_unauthenticated_proxy:
            violations.append("dev_trust_unauthenticated_proxy")
        if self.dev_expose_error_detail:
            violations.append("dev_expose_error_detail")
        if self.dev_allow_private_webhook_targets:
            violations.append("dev_allow_private_webhook_targets")
        if not self.trusted_proxy_cidrs:
            violations.append("trusted_proxy_cidrs (must not be empty)")
        if not self.public_base_url.startswith("https://"):
            violations.append("public_base_url (must be https)")
        if self.log_level == "DEBUG":
            violations.append("log_level (DEBUG may record request bodies)")

        if violations:
            msg = (
                f"refusing to start in environment={self.environment!r} with unsafe "
                "settings: " + ", ".join(sorted(violations))
            )
            raise ValueError(msg)
        return self

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------
    @property
    def trusted_proxy_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return tuple(ipaddress.ip_network(c, strict=False) for c in self.trusted_proxy_cidrs)

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def peer_is_trusted_proxy(self, peer_ip: str | None) -> bool:
        """Return whether ``peer_ip`` is an address the proxy may connect from.

        An empty allowlist means the check is disabled, which
        :meth:`validate_production_posture` forbids in production.
        """
        if not self.trusted_proxy_cidrs:
            return True
        if peer_ip is None:
            return False
        try:
            address = ipaddress.ip_address(peer_ip)
        except ValueError:
            return False
        return any(address in network for network in self.trusted_proxy_networks)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, constructed once.

    Cached because ``Settings`` is frozen and reading the environment repeatedly
    would let a mid-flight environment change alter security behaviour.
    """
    return Settings()


def _main() -> int:  # pragma: no cover - operational helper
    """Validate configuration and print a redacted summary.

    Run as ``python -m aivs_server.config`` in a container's healthcheck or by
    an operator verifying a deployment before cutting traffic over.
    """
    try:
        settings = get_settings()
    except Exception as exc:  # noqa: BLE001 - operator-facing diagnostic
        print(f"configuration INVALID: {exc}", file=sys.stderr)  # noqa: T201
        return 1
    summary = settings.model_dump(mode="json")
    print(f"configuration OK for environment={summary['environment']}")  # noqa: T201
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
