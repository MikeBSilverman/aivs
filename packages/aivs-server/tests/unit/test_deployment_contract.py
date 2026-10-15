"""The deployment files do what the runbook tells operators they do.

Found by the Phase A review: the rotation procedure could not be followed (the
app refused the environment form it described, and compose had no way to mount
a previous key); nothing probed /readyz; and an unedited database password was
baked into the volume on first start.
"""

from __future__ import annotations

import http.server
import importlib.util
import ipaddress
import re
import shlex
import socket
import threading
from pathlib import Path

import pytest
import yaml

from aivs_server.healthcheck import is_ready

ROOT = Path(__file__).resolve().parents[4]


def _compose(name: str) -> dict:
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def test_the_rotation_override_mounts_the_previous_key_as_a_file():
    app = _compose("docker-compose.rotation.yml")["services"]["app"]
    target = app["environment"]["AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS_FILE"]

    [mount] = app["volumes"]
    assert mount["target"] == target
    assert mount["read_only"] is True
    assert mount["source"].startswith("${AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS_PATH:?")
    base_env = _compose("docker-compose.yml")["services"]["app"]["environment"]
    assert "AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS_FILE" not in base_env, "rotation only"


def test_the_runbook_rotation_never_sets_a_key_in_the_environment():
    runbook = (ROOT / "docs/operator-runbook.md").read_text(encoding="utf-8")
    rotation = runbook.split("### 7.4", 1)[1].split("### 7.5", 1)[0]

    assert "docker-compose.rotation.yml" in rotation
    assert not re.search(r"^\d+\. Set `AIVS_SECRET_ENCRYPTION_KEY", rotation, re.M)


def test_the_app_healthcheck_asks_readiness():
    app = _compose("docker-compose.yml")["services"]["app"]
    assert app["healthcheck"]["test"] == ["CMD", "python", "-m", "aivs_server.healthcheck"]
    dockerfile = (ROOT / "packages/aivs-server/Dockerfile").read_text(encoding="utf-8")
    assert '"aivs_server.healthcheck"' in dockerfile


def test_an_unedited_database_password_fails_before_anything_starts():
    """The database container cannot refuse a placeholder; compose's `:?` can,
    but only for an empty value."""
    example = (ROOT / "deploy/env.example").read_text(encoding="utf-8")
    assert re.search(r"^AIVS_DB_PASSWORD=$", example, re.M)
    db_env = _compose("docker-compose.yml")["services"]["db"]["environment"]
    assert db_env["POSTGRES_PASSWORD"].startswith("${AIVS_DB_PASSWORD:?")


class _Probe(http.server.BaseHTTPRequestHandler):
    status = 200

    def do_GET(self) -> None:
        self.send_response(self.status if self.path == "/readyz" else 404)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def readyz_answering():
    servers = []

    def _serve(status: int) -> int:
        handler = type("Handler", (_Probe,), {"status": status})
        server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server.server_address[1]

    yield _serve
    for server in servers:
        server.shutdown()
        server.server_close()


def test_ready_only_when_readyz_answers_200(readyz_answering):
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        closed_port = unused.getsockname()[1]

    assert is_ready(readyz_answering(200)) is True
    assert is_ready(readyz_answering(503)) is False
    assert is_ready(closed_port) is False


def _static_address_collisions(compose: dict) -> list[str]:
    """Static addresses Docker could also hand to a container dynamically.

    Docker allocates from a network's ``ip_range`` when one is set, otherwise
    from the whole subnet, and does not skip addresses another service merely
    asked for. A static address inside that pool goes to whichever container
    starts first.
    """
    pools = {}
    for name, network in compose.get("networks", {}).items():
        for config in (network.get("ipam") or {}).get("config", []):
            subnet = ipaddress.ip_network(config["subnet"])
            pools[name] = (subnet, ipaddress.ip_network(config.get("ip_range", config["subnet"])))
    problems = []
    for service_name, service in compose["services"].items():
        networks = service.get("networks") or {}
        if not isinstance(networks, dict):
            continue
        for network_name, attachment in networks.items():
            address = (attachment or {}).get("ipv4_address")
            if address is None:
                continue
            subnet, pool = pools[network_name]
            ip = ipaddress.ip_address(address)
            if ip not in subnet or ip in pool:
                problems.append(f"{service_name} {address} on {network_name} (pool {pool})")
    return problems


def test_no_static_address_can_be_handed_out_dynamically():
    """The first `up` on a clean host failed: the app started first, was given the
    proxy's .2, and the proxy then could not start. `docker compose config` passes
    that file; only this check, or starting the stack, sees it."""
    assert _static_address_collisions(_compose("docker-compose.yml")) == []


def test_the_collision_check_sees_the_shape_that_failed():
    compose = _compose("docker-compose.yml")
    del compose["networks"]["backend"]["ipam"]["config"][0]["ip_range"]

    assert _static_address_collisions(compose) == [
        "proxy 172.29.10.2 on backend (pool 172.29.10.0/24)"
    ]


def test_the_published_port_is_configurable_and_defaults_to_443():
    [mapping] = _compose("docker-compose.yml")["services"]["proxy"]["ports"]

    assert mapping.endswith(":${AIVS_BIND_PORT:-443}:8443")


def test_the_published_address_must_be_chosen():
    """A default of every interface made the exposure decision for the operator;
    the example env file leaves it empty so an unedited file stops compose."""
    [mapping] = _compose("docker-compose.yml")["services"]["proxy"]["ports"]
    example = (ROOT / "deploy/env.example").read_text(encoding="utf-8")

    assert mapping.startswith("${AIVS_BIND_ADDRESS:?")
    assert mapping.endswith(":${AIVS_BIND_PORT:-443}:8443")
    assert re.search(r"^AIVS_BIND_ADDRESS=$", example, re.M)


def test_the_allowlist_is_the_operators_file_and_must_exist():
    """The example admits every RFC 1918 range, which behind a source-rewriting
    load balancer is everyone; it was mounted by default."""
    volumes = _compose("docker-compose.yml")["services"]["proxy"]["volumes"]
    [allowlist] = [
        v for v in volumes if isinstance(v, dict) and v["target"].endswith("allowlist.conf")
    ]

    assert allowlist["source"].startswith("${AIVS_NGINX_ALLOWLIST:?")
    assert allowlist["bind"]["create_host_path"] is False
    assert not any(isinstance(v, str) and "allowlist.conf.example:" in v for v in volumes)


# ---------------------------------------------------------------------------
# The application's database role (D-C1). The app connected as the image's
# superuser, which owns every table and can drop the append-only triggers.
# ---------------------------------------------------------------------------
_APP_DSN = "postgresql+psycopg://${AIVS_DB_APP_USER:-aivs_app}:${AIVS_DB_APP_PASSWORD:?"


@pytest.mark.requirement("NFR-S6")
def test_the_app_connects_as_the_application_role_never_the_owner():
    app_env = _compose("docker-compose.yml")["services"]["app"]["environment"]

    assert app_env["AIVS_DATABASE_URL"].startswith(_APP_DSN)
    assert not any("AIVS_DB_PASSWORD" in str(value) for value in app_env.values()), (
        "the owner's password has no business in the app container"
    )


def test_migrations_run_as_the_owner_and_grant_the_same_role_the_app_uses():
    """The pair: someone must hold the owner's password, and only for a migration."""
    services = _compose("docker-compose.yml")["services"]
    migrate = services["migrate"]

    assert migrate["profiles"] == ["migrate"], "never started by a plain `up`"
    assert migrate["environment"]["AIVS_MIGRATION_DATABASE_URL"].startswith(
        "postgresql+psycopg://${AIVS_DB_USER:-aivs}:${AIVS_DB_PASSWORD:?"
    )
    assert migrate["environment"]["AIVS_APP_DB_ROLE"] == "${AIVS_DB_APP_USER:-aivs_app}"
    assert migrate["command"] == ["alembic", "upgrade", "head"]


def test_the_database_creates_the_application_role_on_first_start():
    db = _compose("docker-compose.yml")["services"]["db"]
    script = ROOT / "deploy/db/init/10-app-role.sh"

    assert "./deploy/db/init:/docker-entrypoint-initdb.d:ro" in db["volumes"]
    assert db["environment"]["AIVS_DB_APP_PASSWORD"].startswith("${AIVS_DB_APP_PASSWORD:?")
    assert script.stat().st_mode & 0o111, "the entrypoint sources a non-executable script"
    assert re.search(r"^AIVS_DB_APP_PASSWORD=$", (ROOT / "deploy/env.example").read_text(), re.M)


_MEMBER_DSN = "postgresql+psycopg://${AIVS_DB_MEMBER_USER:-aivs_member}:${AIVS_DB_MEMBER_PASSWORD:?"


@pytest.mark.requirement("SF-89")
def test_the_app_has_a_member_login_of_its_own():
    """Phase P: the member path's login, a different role from the staff one,
    created by the database on first start and granted by the migrate step."""
    services = _compose("docker-compose.yml")["services"]
    app_env, db_env = services["app"]["environment"], services["db"]["environment"]
    migrate_env = services["migrate"]["environment"]
    example = (ROOT / "deploy/env.example").read_text(encoding="utf-8")
    script = (ROOT / "deploy/db/init/10-app-role.sh").read_text(encoding="utf-8")

    assert app_env["AIVS_MEMBER_DATABASE_URL"].startswith(_MEMBER_DSN)
    assert migrate_env["AIVS_MEMBER_DB_ROLE"] == "${AIVS_DB_MEMBER_USER:-aivs_member}"
    assert db_env["AIVS_DB_MEMBER_PASSWORD"].startswith("${AIVS_DB_MEMBER_PASSWORD:?")
    assert re.search(r"^AIVS_DB_MEMBER_USER=aivs_member$", example, re.M)
    assert re.search(r"^AIVS_DB_MEMBER_PASSWORD=$", example, re.M), "empty, as the others"
    assert 'create_login "${AIVS_DB_MEMBER_USER}"' in script
    assert "AIVS_DB_MEMBER_USER must differ from AIVS_DB_APP_USER" in script


def test_the_e2e_stack_sets_the_member_login():
    script = (ROOT / "scripts/e2e.sh").read_text(encoding="utf-8")
    assert "AIVS_DB_MEMBER_USER=aivs_member" in script
    assert "AIVS_DB_MEMBER_PASSWORD=$(random_secret)" in script


def test_the_db_healthcheck_signs_in_as_the_application_role():
    """pg_isready never authenticates, under a comment saying it checked the role."""
    kind, command = _compose("docker-compose.yml")["services"]["db"]["healthcheck"]["test"]

    assert kind == "CMD-SHELL"
    assert "pg_isready" not in command
    assert 'psql -h 127.0.0.1 -U "$$AIVS_DB_APP_USER"' in command
    assert 'PGPASSWORD="$$AIVS_DB_APP_PASSWORD"' in command


# ---------------------------------------------------------------------------
# The documented commands run against the shipped stack (D-C2, D-C3). The
# runbook told operators to run psql, alembic and the bootstrap on the host,
# where neither the database (no published port, internal network) nor the
# configuration is, and §7.4 ran `docker compose exec` without the env file,
# which compose refuses before doing anything.
# ---------------------------------------------------------------------------
_COMMAND_DOCS = ("docs/operator-runbook.md", "docs/deployment-topology.md", "deploy/README.md")
_PROJECTLESS_SUBCOMMANDS = {"version"}
_SUBCOMMAND_OPTIONS_WITH_VALUES = {
    "-e",
    "--env",
    "-u",
    "--user",
    "-w",
    "--workdir",
    "--wait-timeout",
}
_HOST_ONLY_TOOLS = {"python", "python3", "psql", "alembic", "uv", "pg_dump"}


def _fenced_shell(text: str) -> list[str]:
    return re.findall(r"```(?:bash|sh)\n(.*?)```", text, re.S)


def _logical_lines(block: str) -> list[str]:
    return [line.strip() for line in re.sub(r"\\\n", " ", block).splitlines() if line.strip()]


def _compose_commands(name: str) -> list[str]:
    """Every `docker compose` command in a doc's shell blocks, and in the
    runbook's inline code too: there an inline command is an instruction, while
    elsewhere `docker compose ps` in prose names a command without giving one."""
    text = (ROOT / name).read_text(encoding="utf-8")
    fenced = [line for block in _fenced_shell(text) for line in _logical_lines(block)]
    inline = (
        [" ".join(span.split()) for span in re.findall(r"`(docker compose [^`]+)`", text)]
        if name == "docs/operator-runbook.md"
        else []
    )
    commands = []
    for line in [*fenced, *inline]:
        start = line.find("docker compose")
        if start != -1:
            commands.append(line[start:])
    return commands


def _parse(command: str) -> tuple[list[str], str, list[str]]:
    """(compose files, subcommand, the subcommand's arguments)."""
    tokens = shlex.split(command.split("|", 1)[0].split("&&", 1)[0], comments=True)[2:]
    files: list[str] = []
    while tokens and tokens[0].startswith("-"):
        option = tokens.pop(0)
        value = tokens.pop(0)
        if option == "-f":
            files.append(value)
    subcommand = tokens.pop(0)
    return files or ["docker-compose.yml"], subcommand, tokens


def _service_and_rest(arguments: list[str]) -> tuple[str, list[str]]:
    remaining = list(arguments)
    while remaining and remaining[0].startswith("-"):
        option = remaining.pop(0)
        if option in _SUBCOMMAND_OPTIONS_WITH_VALUES:
            remaining.pop(0)
    return remaining[0], remaining[1:]


def _declared_flags(module: str) -> set[str]:
    spec = importlib.util.find_spec(module)
    assert spec is not None, f"{module} does not exist"
    assert spec.origin, f"{module} has no source file"
    source = Path(spec.origin).read_text(encoding="utf-8")
    return set(re.findall(r'add_argument\(\s*"(--[a-z-]+)"', source))


def _problems_with(command: str) -> list[str]:
    files, subcommand, arguments = _parse(command)
    if subcommand in _PROJECTLESS_SUBCOMMANDS:
        return []
    problems = []
    if "--env-file deploy/.env" not in command:
        problems.append(f"no --env-file deploy/.env: {command}")
    if subcommand not in {"exec", "run"}:
        return problems
    services = {name for f in files for name in _compose(f)["services"]}
    service, rest = _service_and_rest(arguments)
    if service not in services:
        problems.append(f"no service {service!r} in {files}: {command}")
    if rest[:2] == ["python", "-m"]:
        flags = {token for token in rest[3:] if token.startswith("--")}
        problems.extend(
            f"{rest[2]} has no {flag}: {command}"
            for flag in sorted(flags - _declared_flags(rest[2]))
        )
    return problems


@pytest.mark.parametrize("doc", _COMMAND_DOCS)
def test_every_documented_compose_command_names_the_env_file_and_real_targets(doc: str):
    commands = _compose_commands(doc)
    assert commands, f"found no compose commands in {doc}; has the parser broken?"

    assert [problem for command in commands for problem in _problems_with(command)] == []


def test_the_command_check_sees_the_shapes_that_failed():
    """The defects the review found, fed to the checker one at a time."""
    compose = "docker compose --env-file deploy/.env"
    rewrap = "exec app python -m aivs_server.rewrap_secrets"
    assert _problems_with(f"docker compose {rewrap}") == [
        f"no --env-file deploy/.env: docker compose {rewrap}"
    ]
    assert _problems_with(f"{compose} exec appx python -m aivs_server.config") != []
    assert _problems_with(f"{compose} {rewrap} --apply") == []
    assert _problems_with(f"{compose} {rewrap} --aply") != []


def test_the_runbook_runs_nothing_against_the_stack_from_the_host():
    """psql, alembic and the application's modules run in a container, where the
    database and the configuration are; on the host neither is reachable."""
    runbook = (ROOT / "docs/operator-runbook.md").read_text(encoding="utf-8")
    host_commands = [
        line
        for block in _fenced_shell(runbook)
        for line in _logical_lines(block)
        if line.split()[0] in _HOST_ONLY_TOOLS
    ]

    assert host_commands == []


def _curl_commands(text: str) -> list[str]:
    """Each ``curl`` invocation in a document, with its continuation lines joined."""
    joined = re.sub(r"\\\s*\n\s*", " ", text)
    return [line.strip() for line in joined.splitlines() if re.search(r"(^|\s)curl\s", line)]


@pytest.mark.parametrize("doc", _COMMAND_DOCS)
def test_every_documented_curl_that_sends_a_body_says_it_is_json(doc: str):
    """FastAPI reads a body as JSON only when told: curl -d sends form encoding.

    The incident pause in section 7.5 -- the first step of instance-compromise
    response -- answered 422 as written.
    """
    text = (ROOT / doc).read_text(encoding="utf-8")
    sending = [cmd for cmd in _curl_commands(text) if re.search(r"\s(-d|--data\S*)\s", cmd)]

    missing = [cmd for cmd in sending if "application/json" not in cmd]
    assert missing == []


def test_the_runbook_never_has_an_operator_set_a_status_column_by_hand():
    """A hand edit skips the one writer that knows every state, the sessions it
    should end and the audit row it should write -- and the app role cannot
    make it."""
    runbook = (ROOT / "docs/operator-runbook.md").read_text(encoding="utf-8")

    assert not re.search(r"`(client_certificates|organizations)\.status\s*=", runbook)


_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def _base_images() -> list[str]:
    dockerfile = (ROOT / "packages/aivs-server/Dockerfile").read_text(encoding="utf-8")
    return re.findall(r"^FROM\s+(\S+)", dockerfile, re.M)


def _compose_default_image(service: str) -> str:
    image = _compose("docker-compose.yml")["services"][service]["image"]
    default = re.fullmatch(r"\$\{AIVS_\w+_IMAGE:-(\S+)\}", image)
    assert default, f"{service}: image is not an overridable default: {image}"
    return default.group(1)


def test_every_base_image_is_pinned_by_digest():
    """CI and e2e built from mutable tags while the digest form sat in a comment
    as a build argument nobody passed; Dependabot could not see the bases either."""
    bases = _base_images()
    assert len(bases) == 3
    assert all(_DIGEST.search(image) for image in bases), bases


@pytest.mark.parametrize("service", ["proxy", "db"])
def test_the_compose_default_images_are_pinned_by_digest(service: str):
    assert _DIGEST.search(_compose_default_image(service))


def test_e2e_chowns_with_the_proxy_image_compose_runs():
    script = (ROOT / "scripts/e2e.sh").read_text(encoding="utf-8")
    default = re.search(r'^PROXY_IMAGE="\$\{AIVS_PROXY_IMAGE:-(\S+)\}"$', script, re.M)
    assert default
    assert default.group(1) == _compose_default_image("proxy")
