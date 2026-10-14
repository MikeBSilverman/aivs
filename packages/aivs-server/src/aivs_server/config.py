"""Runtime configuration.

Two rules govern this module.

**Fail closed.** Every default is the safe value, including ``environment``,
which defaults to ``production``. A deployment that forgets to set something
gets the strict behaviour, never the permissive one. The dev conveniences that
would be dangerous on a real deployment (trusting identity headers without a
proxy secret, verbose errors, private webhook targets) are individually gated
*and* cross-checked in :meth:`Settings.validate_production_posture`, which
refuses to construct ``Settings`` with any of them enabled in any environment
but ``dev`` -- staging and test included, not production alone.

**Secrets never round-trip.** Anything sensitive is a ``SecretStr`` so that an
accidental ``repr``, log line, or error page prints ``**********``. Most values
come from the environment; the key-encryption key, outside dev, comes from a
file only its owner can read (``AIVS_SECRET_ENCRYPTION_KEY_FILE``), because the
environment is shown by ``docker inspect``, ``/proc/<pid>/environ``, crash dumps
and orchestration dashboards, and that key opens every sealed secret. There is
deliberately no ``.env`` file support in any environment.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Final, Literal, Self

from cryptography import x509
from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from aivs_server.auth.secretbox import (
    DEFAULT_ALGORITHM_NAME,
    algorithm_by_name,
    supported_key_sizes,
)

__all__ = ["ConfigurationError", "Settings", "get_settings"]

#: Minimum length for the proxy shared secret. 32 bytes of base64 is ~43 chars;
#: we require enough that a brute-force against the header is hopeless.
MIN_SHARED_SECRET_LEN: Final[int] = 32

#: Marker embedded in every placeholder secret in ``deploy/env.example``. Its
#: presence in a configured secret means the operator did not replace it, and
#: the value is one published in the repository.
_PLACEHOLDER_MARKER: Final[str] = "REPLACE_ME"

Environment = Literal["dev", "test", "staging", "production"]


def _check_kek(value: SecretStr | None) -> None:
    """Raise unless ``value`` is a usable key-encryption key.

    Takes the ``SecretStr`` rather than the string it wraps, so that no caller
    can hand the raw value to something that formats it. Nothing here puts the
    value into a message. See ``Settings._keys_fit_the_algorithm`` for why this
    must only ever be called from a model validator.
    """
    if value is None:
        return
    raw = value.get_secret_value()
    if _PLACEHOLDER_MARKER in raw:
        msg = (
            f"secret still contains {_PLACEHOLDER_MARKER!r} -- it is the "
            "deploy/env.example placeholder, which is public. Generate a "
            "real one with: openssl rand -base64 32"
        )
        raise ValueError(msg)
    try:
        base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        msg = "must be base64 (generate one with: openssl rand -base64 32)"
        raise ValueError(msg) from exc


def _decode_kek(value: SecretStr) -> bytes:
    """Decode a key-encryption key that :func:`_check_kek` has already accepted."""
    return base64.b64decode(value.get_secret_value())


def read_secret_file(path: Path) -> str:
    """Read a secret from a file only its owner can read, without the trailing newline.

    The ``_FILE`` convention Docker and Kubernetes secrets use. A key that
    group or others can read is refused: the point of moving it out of the
    environment -- where ``docker inspect``, ``/proc/<pid>/environ``, crash
    dumps and orchestration dashboards all show it -- is lost if the file is
    world-readable instead. Errors name the path and the mode, never content.
    """
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        msg = f"secret file {path} cannot be read: {exc.strerror}"
        raise ValueError(msg) from exc
    if mode & 0o077:
        msg = (
            f"secret file {path} is readable by group or others (mode {oct(mode & 0o777)}); "
            "chmod 600 it"
        )
        raise ValueError(msg)
    try:
        contents = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        # A 0600 file owned by another uid, or a directory at the path, passes
        # stat() and fails here. Raised as ValueError so it reaches the operator
        # as the same "configuration refused" every other bad setting gives.
        msg = f"secret file {path} cannot be read: {getattr(exc, 'strerror', None) or 'not text'}"
        raise ValueError(msg) from exc
    return contents.rstrip("\r\n")


@lru_cache(maxsize=4)
def load_ca_certificate(path: Path) -> x509.Certificate:
    """Read and check the issuing CA certificate. Cached: it is read on every request.

    Refuses a certificate that is not a CA, because verifying member
    certificates against a leaf would accept nothing -- or, if someone
    configured a member's own certificate here, would accept its forgeries.
    """
    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError) as exc:
        msg = f"issuing CA certificate at {path} could not be read as PEM: {exc}"
        raise ValueError(msg) from exc

    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        constraints = None
    if constraints is None or not constraints.value.ca:
        msg = f"the certificate at {path} is not a CA (basicConstraints CA:TRUE is required)"
        raise ValueError(msg)
    return certificate


#: Headers the application reads identity from. Pinned to nginx's identity
#: snippet by tests/unit/test_proxy_config.py.
_IDENTITY_HEADER_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "header_client_verify",
        "header_client_cert",
        "header_proxy_auth",
        "header_request_id",
        "header_real_ip",
    }
)


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
    #: address" and is permitted in ``dev`` alone.
    trusted_proxy_cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.1/32"])
    #: Header names carrying the verified client certificate. Configurable
    #: because different proxies (nginx, envoy, HAProxy) spell them differently.
    header_client_verify: str = "x-client-verify"
    header_client_cert: str = "x-client-cert"
    header_proxy_auth: str = "x-proxy-auth"
    header_request_id: str = "x-request-id"
    #: The member's address as the proxy saw it. Read only when the proxy check
    #: passes; see ``auth.mtls.client_address``.
    header_real_ip: str = "x-real-ip"

    #: Path to the PEM certificate of the CA that issues member certificates --
    #: the *issuing* (intermediate) CA, not the root.
    #:
    #: Every presented and every registered certificate must be signed by it,
    #: verified here by signature, not by comparing issuer names. An issuer DN
    #: is attacker-chosen data inside the certificate: a self-signed certificate
    #: carrying the right DN passed the old string comparison exactly as a
    #: genuinely issued one did, which left the proxy as the sole authority on
    #: identity while three comments said it was not. The DN pre-filter is
    #: derived from this certificate's subject, so the two cannot disagree.
    #:
    #: Unset is permitted in ``dev`` alone, where no issuer check runs at all;
    #: that is why the e2e tests go through nginx rather than trusting dev.
    issuing_ca_certificate_file: Path | None = None

    # -- Development-only escape hatches (refused outside dev) -------------
    #: Accept identity headers without a valid ``X-Proxy-Auth``. Dev only.
    dev_trust_unauthenticated_proxy: bool = False
    #: Return exception detail in HTTP responses. Dev only.
    dev_expose_error_detail: bool = False

    # -- Request limits ----------------------------------------------------
    #: Hard cap on request body size. STIX bundles are text; 5 MiB is generous
    #: and still bounds memory per in-flight request.
    max_body_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    #: Default and maximum page sizes for TAXII object listings.
    taxii_default_page_size: int = Field(default=100, ge=1, le=1000)
    taxii_max_page_size: int = Field(default=500, ge=1, le=1000)
    #: Contributions an organisation may publish without review in one hour:
    #: one-click, post-moderated and TAXII inbox filings together (SF-66). A
    #: member clicking is a few an hour; a flood is a script or a stolen
    #: certificate, refused past this and raised as ``contribution_flood``.
    contribution_hourly_limit: int = Field(default=30, ge=1, le=1000)

    # -- Portal sessions ---------------------------------------------------
    #: Signs pagination cursors, CSRF tokens, and session cookies.
    session_secret: SecretStr
    session_ttl_minutes: int = Field(default=60, ge=5, le=1440)
    session_idle_timeout_minutes: int = Field(default=20, ge=5, le=240)
    session_cookie_name: str = "aivs_session"

    # -- Member sign-in through the ISAC's identity provider (OIDC) ---------
    #: The member tenant's issuer. Unset means member SSO is off and the public
    #: listener has nothing to sign anyone in with. Never the staff tenant: a
    #: session from this issuer can only ever be a member's (identity-federation.md §2).
    oidc_member_issuer: str | None = None
    oidc_member_client_id: str | None = None
    oidc_member_client_secret: SecretStr | None = None
    #: Where the IdP sends the browser back: the public listener's
    #: ``/portal/sso/callback``. Explicit rather than derived, because the
    #: public listener is a different origin from ``public_base_url``.
    oidc_member_redirect_uri: str | None = None
    #: The ID-token claim listing the user's directory groups. A group maps to
    #: an organisation through ``organizations.directory_object_id``, set at
    #: enrolment; a group that maps to nothing grants nothing.
    oidc_member_group_claim: str = "groups"
    #: Create the member's operator on first sign-in. The grant already
    #: happened in the ISAC's own tenant; identity-federation.md §5 argues why on.
    oidc_member_jit_provisioning: bool = True
    #: Hard cap on an SSO session's life, whatever the idle timeout allows, so
    #: an IdP-side disable takes effect within a known window.
    sso_session_max_age_minutes: int = Field(default=480, ge=15, le=1440)
    #: Long-lived per-browser cookie an SSO session is bound to, beside its own.
    sso_device_cookie_name: str = "aivs_device"

    # -- Secrets at rest ----------------------------------------------------
    #: Key-encryption key for the two reversible secrets (operator TOTP seeds,
    #: webhook HMAC keys). Base64, of whatever length the configured algorithm
    #: takes -- 32 bytes for both current options:
    #: ``openssl rand -base64 32``. See ``auth.secretbox`` for what it protects
    #: and what it does not.
    #:
    #: Required rather than optional-with-a-default. A key the application
    #: invents for itself would have to be stored somewhere it can read
    #: unattended, which is the database it is meant to be protecting.
    secret_encryption_key: SecretStr
    #: Where the key above was read from, when it came from a file
    #: (``AIVS_SECRET_ENCRYPTION_KEY_FILE``). Outside dev the key must come from
    #: one: see :meth:`validate_production_posture`.
    secret_encryption_key_file: Path | None = None
    #: The key being rotated away from. Set during a rotation so existing rows
    #: still open; drop it once ``python -m aivs_server.rewrap_secrets`` reports
    #: nothing stale.
    secret_encryption_key_previous: SecretStr | None = None
    secret_encryption_key_previous_file: Path | None = None
    #: AEAD used for *new* values. Existing values name their own algorithm in
    #: their header and keep opening regardless, so changing this is a migration
    #: run at leisure rather than a flag day -- see ``auth.secretbox``.
    #:
    #: Left at the default unless a member's cryptography policy or a platform
    #: without AES hardware calls for something else.
    secret_encryption_algorithm: str = DEFAULT_ALGORITHM_NAME

    # -- Outbound webhooks --------------------------------------------------
    webhook_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    webhook_max_attempts: int = Field(default=5, ge=1, le=20)
    #: Allow webhook delivery to private/loopback addresses. Dev only; in any
    #: real deployment this being true is an SSRF hole.
    dev_allow_private_webhook_targets: bool = False
    #: How often the dispatcher drains queued notifications. Short, because the
    #: whole point of pushing is that a member hears sooner than their next poll.
    webhook_dispatch_interval_seconds: int = Field(default=10, ge=1, le=600)

    # -- Government recipients ---------------------------------------------
    #: Set only once the membership agreement answers sharing-agreement §10 for
    #: government recipients: a receipt proves an agency retrieved X at time T,
    #: which is a discoverable record, and every member's counsel will ask about
    #: it. Until then no ``government`` organisation can be enrolled.
    government_receipts_policy_agreed: bool = False

    # -- Digests (notify.digest) --------------------------------------------
    #: How often held notices are checked for a digest that is due.
    digest_interval_seconds: int = Field(default=60, ge=10, le=3600)
    #: The hour, in UTC, at which a daily digest is sent.
    digest_daily_hour_utc: int = Field(default=7, ge=0, le=23)

    # -- Digest email (SMTP, a named subprocessor) ------------------------------
    #: Unset, no email is sent: an organisation that names a digest mailbox gets
    #: its digest by webhook only, and the status page says why. The relay is a
    #: subprocessor the ISAC names to its members; it sees the contentless
    #: digest and nothing else. STARTTLS is always required.
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    #: Outside dev, read from ``smtp_password_file``: a relay credential in the
    #: environment is shown by ``docker inspect``, as the KEK would be.
    smtp_password: SecretStr | None = None
    smtp_password_file: Path | None = None
    smtp_from: str | None = None
    smtp_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    email_dispatch_interval_seconds: int = Field(default=60, ge=10, le=3600)
    email_max_attempts: int = Field(default=5, ge=1, le=20)

    # -- Embargo sweeper ----------------------------------------------------
    embargo_sweep_interval_seconds: int = Field(default=30, ge=5, le=3600)
    #: How often the platform's own detection rules run (services.detections).
    detection_interval_seconds: int = Field(default=60, ge=10, le=3600)
    #: How often reads of the audit trail are summarised into the stream
    #: (services.audit_read_summary): about one summary per reader per run.
    audit_read_summary_interval_seconds: int = Field(default=3600, ge=60, le=86400)
    #: How often published counts are compared with the live state, and replaced
    #: where at least K organisations changed (services.count_snapshots). Each
    #: run examines every distributed submission and vulnerability, so its cost
    #: follows the archive; Mike accepted counts up to a day old.
    count_publish_interval_seconds: int = Field(default=3600, ge=300, le=86400)
    #: What a detection that recommends quarantine does: ``propose`` shows it on
    #: the status page for a human to confirm; ``enforce`` applies it at once.
    detection_quarantine_policy: Literal["propose", "enforce"] = "propose"
    #: SSVC's Mission and Well-Being Impact, the one input to CISA's table that
    #: describes the stakeholder rather than the vulnerability. An ISAC triages
    #: for its whole sector, so this is the instance's answer, not the content's:
    #: ``high`` by default because an ISAC's members run critical financial
    #: infrastructure, and a triage queue that under-ranks is the costlier error.
    #: An ISAC whose membership is different sets it.
    ssvc_mission_impact: Literal["low", "medium", "high"] = "high"

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
    @field_validator(
        "oidc_member_issuer", "oidc_member_client_id", "oidc_member_redirect_uri", mode="before"
    )
    @classmethod
    def _empty_issuer_means_unset(cls, value: object) -> object:
        """Compose and Kubernetes spell "unset" as an empty string. Optional fields only."""
        return None if value == "" else value

    @field_validator("proxy_shared_secret", "session_secret")
    @classmethod
    def _secret_is_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_SHARED_SECRET_LEN:
            msg = f"secret must be at least {MIN_SHARED_SECRET_LEN} characters"
            raise ValueError(msg)
        return value

    @field_validator("secret_encryption_algorithm")
    @classmethod
    def _algorithm_is_registered(cls, value: str) -> str:
        """Refuse an algorithm name this build does not implement.

        A typo here would otherwise be discovered by the first write, and the
        error would come from inside the cipher rather than from the line of
        configuration that caused it.
        """
        algorithm_by_name(value)  # raises, naming the supported set
        return value

    @field_validator("secret_encryption_key_previous")
    @classmethod
    def _previous_kek_empty_means_absent(cls, value: SecretStr | None) -> SecretStr | None:
        """An empty value means "not rotating".

        Compose and Kubernetes both express "not set" as an empty string --
        ``${VAR:-}`` and an absent secret mount respectively -- so a deployment
        that is not mid-rotation must not be refused for a variable it never
        set. This leniency is deliberately *not* shared with the active key:
        pydantic does not re-validate an after-validator's return value, so a
        shared validator that mapped empty to ``None`` would have quietly set
        the required key to ``None`` and moved the failure to first use.

        This validator must never raise. See :meth:`_keys_fit_the_algorithm`.
        """
        if value is None or not value.get_secret_value():
            return None
        return value

    @field_validator("proxy_shared_secret", "session_secret", "database_url")
    @classmethod
    def _secret_is_not_a_placeholder(cls, value: SecretStr) -> SecretStr:
        """Refuse a secret that is still the value shipped in deploy/env.example.

        Length alone did not catch this. The placeholders were long enough to
        clear the minimum, and compose's ``${VAR:?}`` guard only fires when a
        variable is unset or empty -- so an operator who edited the values they
        had to change to make the stack come up, and missed the secrets, got a
        running production instance whose proxy-authentication secret and
        cursor-signing key were published in a public repository, with every
        healthcheck green and nothing anywhere saying so.
        """
        if _PLACEHOLDER_MARKER in value.get_secret_value():
            msg = (
                f"secret still contains {_PLACEHOLDER_MARKER!r} -- it is the "
                "deploy/env.example placeholder, which is public. Generate a "
                "real one with: openssl rand -base64 48"
            )
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

    @field_validator(
        "header_client_verify",
        "header_client_cert",
        "header_proxy_auth",
        "header_request_id",
        "header_real_ip",
    )
    @classmethod
    def _header_names_lowercase(cls, value: str) -> str:
        # Starlette exposes headers lowercased; normalising here means a
        # misconfigured mixed-case name cannot silently never match.
        #
        # header_request_id belongs here for the same reason and was missed: set
        # to the natural "X-Request-Id" spelling, the comparison in
        # RequestContextMiddleware never matched, so every request was given a
        # fresh id and the proxy access log could no longer be joined to the
        # application log -- silently, with nothing logged to say so.
        return value.strip().lower()

    @model_validator(mode="after")
    def _keys_fit_the_algorithm(self) -> Self:
        """Validate the key-encryption keys, in the one place that cannot leak them.

        **Every check on these two values lives here, and none may move to a
        field validator.** Pydantic puts the *pre-coercion* input into
        ``ValidationError.input`` — the raw environment string, before
        ``SecretStr`` exists to mask it — so a field validator that raises on a
        bad key prints that key in the error. The container healthcheck
        (``python -m aivs_server.healthcheck``) constructs these settings every
        30 seconds and prints the refusal, so a single stray character in a *working* previous key,
        during the rotation window when it still opens every operator's second
        factor and every member's signing key, would publish it to the container
        health log and from there to the ISAC's log pipeline, repeatedly. An
        after-validator's input is the model, whose repr masks ``SecretStr``.

        The rest is ordinary cross-field validation: "how long is a key" is a
        property of the algorithm. The active key is held to the active
        algorithm exactly; the previous key only has to be a length *some*
        registered algorithm uses, since it exists to open values that may have
        been written under a different one.
        """
        _check_kek(self.secret_encryption_key)
        _check_kek(self.secret_encryption_key_previous)

        algorithm = algorithm_by_name(self.secret_encryption_algorithm)
        active = len(self.secret_encryption_key_bytes)
        if active != algorithm.key_bytes:
            msg = (
                f"secret_encryption_key must decode to {algorithm.key_bytes} bytes "
                f"for {algorithm.name}, got {active}"
            )
            raise ValueError(msg)

        previous = self.secret_encryption_key_previous_bytes
        if previous is not None and len(previous) not in supported_key_sizes():
            msg = (
                "secret_encryption_key_previous must decode to one of "
                f"{sorted(supported_key_sizes())} bytes, got {len(previous)}"
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="before")
    @classmethod
    def _read_key_files(cls, data: Any) -> Any:
        """Fill each key from its ``_FILE`` path, so the key never sits in the environment.

        Setting both forms is refused rather than resolved: two sources for one
        key is the shape that drifts, and the operator would not know which was
        live.
        """
        if not isinstance(data, dict):
            return data
        resolved = dict(data)
        for field in ("secret_encryption_key", "secret_encryption_key_previous", "smtp_password"):
            path = resolved.get(f"{field}_file")
            if not path:
                # An empty value is how compose and Kubernetes spell "unset".
                # Left in place it became Path("."), which is not None, so the
                # production check that the key comes from a file passed with
                # the key in the environment beside it.
                resolved.pop(f"{field}_file", None)
                continue
            if resolved.get(field):
                msg = f"set {field} or {field}_file, not both"
                raise ValueError(msg)
            resolved[field] = read_secret_file(Path(path))
        return resolved

    @field_validator("smtp_host", "smtp_username", "smtp_from", "smtp_password_file", mode="before")
    @classmethod
    def _unset_smtp_is_empty(cls, value: Any) -> Any:
        """Compose spells an unset optional variable as an empty string.

        These four are optional, so mapping empty to ``None`` widens nothing:
        an empty ``smtp_host`` must read as "no relay", not as a relay named "".
        """
        return None if value == "" else value

    @field_validator("issuing_ca_certificate_file")
    @classmethod
    def _issuing_ca_must_load(cls, path: Path | None) -> Path | None:
        """Load the CA at startup, so a wrong path fails the healthcheck, not a login."""
        if path is not None:
            load_ca_certificate(path)
        return path

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

        violations = [
            *self._dev_bypasses_enabled(),
            *self._proxy_trust_violations(),
            *self._output_violations(),
            *self._key_and_identity_violations(),
            *self._secret_reuse_violations(),
            *self._sso_violations(),
            *self._smtp_violations(),
        ]
        if violations:
            msg = (
                f"refusing to start in environment={self.environment!r} with unsafe "
                "settings: " + ", ".join(sorted(violations))
            )
            raise ValueError(msg)
        return self

    def _dev_bypasses_enabled(self) -> list[str]:
        """Conveniences that are safe on an engineer's laptop and nowhere else."""
        flags = {
            "dev_trust_unauthenticated_proxy": self.dev_trust_unauthenticated_proxy,
            "dev_expose_error_detail": self.dev_expose_error_detail,
            "dev_allow_private_webhook_targets": self.dev_allow_private_webhook_targets,
        }
        return [name for name, enabled in flags.items() if enabled]

    def _identity_header_violations(self) -> list[str]:
        """Identity headers must be the ones the shipped proxy overwrites.

        The names are settings, for other proxies, but nginx's identity snippet
        overwrites only the defaults. Renamed, a header nginx neither sets nor
        blanks is passed through from the client: a member sending another
        member's (public) certificate under it would be resolved as that member,
        since the CA signature proves who issued a certificate, not who holds it.
        """
        return [
            f"{name} (renamed from {field.default!r}; the shipped proxy overwrites "
            "only the default names)"
            for name, field in type(self).model_fields.items()
            if name in _IDENTITY_HEADER_FIELDS and getattr(self, name) != field.default
        ]

    def _proxy_trust_violations(self) -> list[str]:
        """The allow-list of addresses the mTLS proxy may connect from."""
        violations = self._identity_header_violations()
        if not self.trusted_proxy_cidrs:
            return [*violations, "trusted_proxy_cidrs (must not be empty)"]
        if any(network.prefixlen == 0 for network in self.trusted_proxy_networks):
            # A non-empty allowlist that matches every address is not an
            # allowlist. "0.0.0.0/0" passes the emptiness check, and
            # strict=False means a typo'd prefix length such as "10.0.0.1/0"
            # normalises to exactly that rather than erroring.
            return [*violations, "trusted_proxy_cidrs (must not contain a /0 network)"]
        return violations

    def _smtp_violations(self) -> list[str]:
        """A relay named without what it needs to send, or with its password in the environment."""
        violations = []
        if self.smtp_password is not None and self.smtp_password_file is None:
            violations.append(
                "smtp_password (read it from smtp_password_file, not the environment)"
            )
        if self.smtp_host is None:
            return violations
        if not self.smtp_from:
            violations.append("smtp_from (required when smtp_host is set)")
        if self.smtp_username and self.smtp_password is None:
            violations.append("smtp_password (required when smtp_username is set)")
        return violations

    def _output_violations(self) -> list[str]:
        """What the service tells the world: its URL, its logs, its page sizes."""
        violations: list[str] = []
        if not self.public_base_url.startswith("https://"):
            violations.append("public_base_url (must be https)")
        if self.log_level == "DEBUG":
            violations.append("log_level (DEBUG may record request bodies)")
        if self.taxii_default_page_size > self.taxii_max_page_size:
            # Both are bounded independently, so this pair passes field
            # validation while meaning the opposite of what the names say: a
            # client that sends no `limit` gets the larger page and one that
            # asks for a limit gets capped at the smaller.
            violations.append("taxii_default_page_size (must not exceed taxii_max_page_size)")
        return violations

    def _secret_reuse_violations(self) -> list[str]:
        """Two secrets with different holders must not be one value.

        The proxy secret is also held by nginx, rendered into its config; the
        session secret signs every operator's session and every CSRF token.
        One value for both turns a disclosure of the proxy's config into forged
        operator sessions. The env file's comment asked for different values and
        nothing checked.
        """
        if self.session_secret.get_secret_value() == self.proxy_shared_secret.get_secret_value():
            return ["session_secret (must differ from proxy_shared_secret)"]
        return []

    def _key_and_identity_violations(self) -> list[str]:
        """Where the keys come from, and what anchors member identity."""
        violations: list[str] = []
        if self.secret_encryption_key_file is None:
            # Read from the environment, where docker inspect,
            # /proc/<pid>/environ, crash dumps and orchestration dashboards all
            # show it.
            violations.append(
                "secret_encryption_key_file (outside dev the key comes from a 0600 file)"
            )
        if (
            self.secret_encryption_key_previous is not None
            and self.secret_encryption_key_previous_file is None
        ):
            # The key being rotated away from still opens every row not yet
            # re-wrapped; it leaks through the environment exactly as the
            # active one would.
            violations.append(
                "secret_encryption_key_previous_file (a rotation's old key is a file too)"
            )
        if self.issuing_ca_certificate_file is None:
            # Without it the proxy's handshake verdict is the only thing
            # between a self-signed certificate and a member identity.
            violations.append("issuing_ca_certificate_file (must pin the issuing CA)")
        return violations

    def _sso_violations(self) -> list[str]:
        """A configured member issuer is complete and reached over https, or nothing starts.

        A half-configured issuer must not fall back to anything: an issuer over
        plain http hands token exchange to whoever sits on the path, and one
        with no secret is a configuration nobody finished.
        """
        if self.oidc_member_issuer is None:
            return []
        violations: list[str] = []
        if not self.oidc_member_issuer.startswith("https://"):
            violations.append("oidc_member_issuer (must be https)")
        if not self.oidc_member_client_id or self.oidc_member_client_secret is None:
            violations.append("oidc_member_client_id/secret (an issuer needs both)")
        redirect = self.oidc_member_redirect_uri or ""
        if not redirect.startswith("https://"):
            violations.append("oidc_member_redirect_uri (an issuer needs an https callback)")
        return violations

    @property
    def is_member_sso_enabled(self) -> bool:
        return self.oidc_member_issuer is not None

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------
    @property
    def issuing_ca_certificate(self) -> x509.Certificate | None:
        """The issuing CA certificate, or ``None`` in dev when none is configured."""
        if self.issuing_ca_certificate_file is None:
            return None
        return load_ca_certificate(self.issuing_ca_certificate_file)

    @property
    def trusted_proxy_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return tuple(ipaddress.ip_network(c, strict=False) for c in self.trusted_proxy_cidrs)

    @property
    def secret_encryption_key_bytes(self) -> bytes:
        """The active key-encryption key. Validated at construction."""
        return _decode_kek(self.secret_encryption_key)

    @property
    def secret_encryption_key_previous_bytes(self) -> bytes | None:
        """The key being rotated away from, if one is configured."""
        if self.secret_encryption_key_previous is None:
            return None
        return _decode_kek(self.secret_encryption_key_previous)

    def peer_is_trusted_proxy(self, peer_ip: str | None) -> bool:
        """Return whether ``peer_ip`` is an address the proxy may connect from.

        An empty allowlist means the check is disabled, which
        :meth:`validate_production_posture` forbids outside dev.
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


class ConfigurationError(RuntimeError):
    """Configuration was rejected. Names fields and reasons, never values."""


def _redacted(exc: ValidationError) -> str:
    """Render a validation failure without the values that caused it.

    Pydantic attaches the *input* to every error, and for a settings model built
    from the environment that input is the dict of every configured value --
    database URL, session secret, key-encryption keys and all. It is truncated
    in the middle, so what survives into the message is the tail of a secret.

    ``str(ValidationError)`` therefore cannot be printed or logged, and this is
    not hypothetical: the container healthcheck (``python -m
    aivs_server.healthcheck``) constructs settings every 30 seconds and prints
    the refusal, so one malformed value during a key
    rotation -- when the previous key still opens every operator's second factor
    and every member's signing key -- would publish it to the container health
    log and onward to the ISAC's log pipeline, indefinitely.

    ``include_input=False`` is the whole fix; the rest is presentation.
    """
    reasons = [
        f"{'.'.join(str(part) for part in err['loc']) or 'configuration'}: {err['msg']}"
        for err in exc.errors(include_url=False, include_context=False, include_input=False)
    ]
    return "; ".join(reasons)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, constructed once.

    Cached because ``Settings`` is frozen and reading the environment repeatedly
    would let a mid-flight environment change alter security behaviour.

    A rejected configuration is re-raised as :class:`ConfigurationError` with the
    values stripped, ``from None`` so that the original -- which carries them in
    its ``__context__`` and would be printed by any traceback -- does not travel
    with it. Every caller in the application goes through this function, so the
    redaction cannot be bypassed by forgetting it at a call site.
    """
    try:
        return Settings()
    except ValidationError as exc:
        raise ConfigurationError(_redacted(exc)) from None


def _main() -> int:  # pragma: no cover - operational helper
    """Validate configuration and print a redacted summary.

    Run as ``python -m aivs_server.config`` by an operator verifying a
    deployment before cutting traffic over (inside the app container, where the
    configuration is: ``docker compose --env-file deploy/.env exec app python -m
    aivs_server.config``). The container healthcheck is
    ``aivs_server.healthcheck``, which also asks ``/readyz``.
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
