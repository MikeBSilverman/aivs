#!/usr/bin/env bash
# =============================================================================
# Stand the production stack up from nothing for the end-to-end tests, and
# take it down again.
#
#   scripts/e2e.sh up      CA, certificates, secrets, compose up, bootstrap, enrol
#   scripts/e2e.sh down    compose down with volumes, then delete the work dir
#   scripts/e2e.sh logs    service status and logs, for a failed run
#
#   AIVS_E2E_DIR=/path scripts/e2e.sh up    (default: ${TMPDIR:-/tmp}/aivs-e2e)
#   uv run pytest -m e2e packages/aivs-server/tests/e2e
#
# It follows deploy/README.md section 3 in order, with the operator's choices
# made by script: an ephemeral CA, generated secrets, the proxy bound to
# loopback on AIVS_E2E_PORT (default 18443, through AIVS_BIND_PORT). The
# compose file is used exactly as shipped: no override file. Everything it creates lives under AIVS_E2E_DIR, never in the
# repository: nothing cryptographic is ever written into the checkout
# (CLAUDE.md section 6), not even into a git-ignored path.
#
# THE STACK'S NAMES ARE FIXED, NOT PROJECT-SCOPED. docker-compose.yml sets
# container_name, network names and volume names explicitly (aivs-app,
# aivs_backend, aivs_pgdata, ...), so a compose project name does not isolate
# this stack from another AIVS stack on the same host -- `down -v` here would
# delete that stack's database volume. `up` therefore refuses to start if any
# of those names already exists without this project's label, and `down`
# refuses to touch a volume that carries another project's.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'
umask 077

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
WORK="${AIVS_E2E_DIR:-${TMPDIR:-/tmp}/aivs-e2e}"
PROJECT="aivs-e2e"
PORT="${AIVS_E2E_PORT:-18443}"
# The proxy image, as compose would choose it; used here only to chown files
# to the uids the containers run as, which needs root on the host otherwise.
PROXY_IMAGE="${AIVS_PROXY_IMAGE:-nginxinc/nginx-unprivileged:1.29-alpine}"

FIXED_CONTAINERS=(aivs-proxy aivs-app aivs-db)
FIXED_NETWORKS=(aivs_frontend aivs_backend aivs_data)
FIXED_VOLUMES=(aivs_pgdata aivs_ca_material)

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

compose() {
    docker compose -p "${PROJECT}" --env-file "${WORK}/.env" -f "${REPO}/docker-compose.yml" "$@"
}

# -----------------------------------------------------------------------------
# Guards
# -----------------------------------------------------------------------------
owner_of() {
    # Prints "absent" when no container, network or volume has this name, and
    # otherwise the compose project label it carries -- empty when unlabelled,
    # which is a volume somebody made by hand or a stack started another way.
    local kind
    for kind in container network volume; do
        if docker "${kind}" inspect "$1" >/dev/null 2>&1; then
            docker "${kind}" inspect --format '{{ index .Labels "com.docker.compose.project" }}' "$1" 2>/dev/null \
                || docker "${kind}" inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$1"
            return
        fi
    done
    printf 'absent\n'
}

refuse_foreign_objects() {
    # Permit only objects this project created. Unlabelled is foreign too: it
    # cannot be shown to be ours, and compose would silently adopt it -- an
    # unlabelled aivs_pgdata would be reused by `up` and destroyed by `down`.
    local name owner
    for name in "$@"; do
        owner="$(owner_of "${name}")"
        if [[ "${owner}" != "absent" && "${owner}" != "${PROJECT}" ]]; then
            die "'${name}' exists and is not this harness's (owner: '${owner:-unlabelled}').
       docker-compose.yml fixes these names, so this stack would collide with it,
       and 'down' would delete its data. Remove or rename it first."
        fi
    done
}

# -----------------------------------------------------------------------------
# up
# -----------------------------------------------------------------------------
make_ca() {
    # The CA scripts write relative to their own directory, so they run from a
    # copy under the work dir. The root key is unencrypted: this CA lives for
    # one test run, which is exactly what --plaintext-root-key is for.
    mkdir -p "${WORK}/ca"
    cp "${REPO}"/deploy/ca/{_lib.sh,init-ca.sh,server-cert.sh,issue-client.sh,openssl.cnf} "${WORK}/ca/"
    log "creating an ephemeral CA"
    AIVS_CA_ALLOW_PLAINTEXT_ROOT=1 "${WORK}/ca/init-ca.sh" \
        --org "E2E Test ISAC" --plaintext-root-key >/dev/null
    "${WORK}/ca/server-cert.sh" --hostname localhost --san-ip 127.0.0.1 >/dev/null 2>&1
    "${WORK}/ca/issue-client.sh" --org-slug e2e-isac --org "E2E Test ISAC" >/dev/null 2>&1
    "${WORK}/ca/issue-client.sh" --org-slug e2e-member --org "E2E Member Bank" >/dev/null 2>&1
}

make_root_signed_client() {
    # A client certificate signed by the ROOT, not the issuing CA. nginx accepts
    # it (the root is in its trust store and the chain is within depth 2); the
    # application must refuse it, because it pins the issuing CA's signature.
    local dir="${WORK}/rogue"
    mkdir -p "${dir}"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${dir}/root-signed.key" 2>/dev/null
    openssl req -new -key "${dir}/root-signed.key" -subj "/O=E2E Member Bank/OU=e2e-member/CN=root signed" \
        -out "${dir}/root-signed.csr"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' \
        > "${dir}/ext.cnf"
    openssl x509 -req -in "${dir}/root-signed.csr" -days 2 -sha384 \
        -CA "${WORK}/ca/out/root/root.crt" -CAkey "${WORK}/ca/private/root/root.key" \
        -CAcreateserial -extfile "${dir}/ext.cnf" -out "${dir}/root-signed.crt" 2>/dev/null
}

random_secret() { openssl rand -hex 32; }

make_env() {
    mkdir -p "${WORK}/secrets"
    openssl rand -base64 32 > "${WORK}/secrets/secret-encryption-key"
    chmod 0600 "${WORK}/secrets/secret-encryption-key"
    cat > "${WORK}/.env" <<EOF
AIVS_INSTANCE_NAME=E2E Test ISAC
AIVS_PUBLIC_BASE_URL=https://localhost:${PORT}
AIVS_BIND_ADDRESS=127.0.0.1
AIVS_BIND_PORT=${PORT}
AIVS_LOG_LEVEL=INFO
AIVS_CA_DIR=${WORK}/ca/out
AIVS_PROXY_SHARED_SECRET=$(random_secret)
AIVS_SESSION_SECRET=$(random_secret)
AIVS_SECRET_ENCRYPTION_KEY_PATH=${WORK}/secrets/secret-encryption-key
AIVS_DB_USER=aivs
AIVS_DB_NAME=aivs
AIVS_DB_PASSWORD=$(random_secret)
EOF
    chmod 0600 "${WORK}/.env"
}

hand_files_to_container_users() {
    # deploy/README.md section 3 step 5 does this with sudo. The daemon is root
    # already, so a throwaway container does it without asking for a password.
    docker run --rm --user 0:0 --entrypoint sh -v "${WORK}:/w" "${PROXY_IMAGE}" -c '
        chown 101:101 /w/ca/out/nginx/server.key && chmod 0400 /w/ca/out/nginx/server.key &&
        chown 10001:10001 /w/secrets/secret-encryption-key'
}

start_stack() {
    log "building and starting the stack (project ${PROJECT})"
    compose build app
    compose up -d db
    compose run --rm app alembic upgrade head
    compose up -d --wait --wait-timeout 300
}

bootstrap_isac() {
    local password uri
    password="$(random_secret)"
    log "bootstrapping the ISAC operator"
    compose exec -T app sh -c 'cat > /tmp/isac.crt' < "${WORK}/ca/out/clients/e2e-isac/e2e-isac.crt"
    # The password is read twice from the terminal; without one, getpass falls
    # back to stdin.
    uri="$(printf '%s\n%s\n' "${password}" "${password}" | compose exec -T app \
        python -m aivs_server.bootstrap_operator \
            --org-slug e2e-isac --org-name "E2E Test ISAC" \
            --email ops@e2e-isac.test --name "E2E Ops" \
            --role system_admin --role isac_editor --role isac_membership \
            --certificate /tmp/isac.crt 2>/dev/null | grep '^otpauth://')"
    [[ -n "${uri}" ]] || die "the bootstrap printed no TOTP provisioning URI"
    printf '%s' "${password}" > "${WORK}/secrets/isac-password"
    printf '%s' "${uri}" > "${WORK}/secrets/isac-totp-uri"
}

write_state() {
    cat > "${WORK}/state.json" <<EOF
{
  "work": "${WORK}",
  "project": "${PROJECT}",
  "repo": "${REPO}",
  "env_file": "${WORK}/.env",
  "base_url": "https://localhost:${PORT}",
  "compose_files": ["${REPO}/docker-compose.yml"],
  "ca_chain": "${WORK}/ca/out/ca-chain.pem",
  "isac": {
    "cert": "${WORK}/ca/out/clients/e2e-isac/e2e-isac.crt",
    "key": "${WORK}/ca/out/clients/e2e-isac/e2e-isac.key",
    "email": "ops@e2e-isac.test",
    "password_file": "${WORK}/secrets/isac-password",
    "totp_uri_file": "${WORK}/secrets/isac-totp-uri"
  },
  "member": {
    "slug": "e2e-member",
    "cert": "${WORK}/ca/out/clients/e2e-member/e2e-member.crt",
    "key": "${WORK}/ca/out/clients/e2e-member/e2e-member.key"
  },
  "root_signed": {
    "cert": "${WORK}/rogue/root-signed.crt",
    "key": "${WORK}/rogue/root-signed.key"
  }
}
EOF
}

enrol_member() {
    log "enrolling the member through the API"
    PYTHONPATH="${REPO}/packages/aivs-server" AIVS_E2E_STATE="${WORK}/state.json" \
        uv run --project "${REPO}" python -m tests.e2e.enrol
}

up() {
    command -v docker >/dev/null || die "docker is required"
    command -v openssl >/dev/null || die "openssl is required"
    [[ ! -e "${WORK}" ]] || die "${WORK} exists: a stack is up or a run was interrupted. Run '$0 down' first."
    refuse_foreign_objects "${FIXED_CONTAINERS[@]}" "${FIXED_NETWORKS[@]}" "${FIXED_VOLUMES[@]}"

    mkdir -p "${WORK}"
    chmod 0700 "${WORK}"
    make_ca
    make_root_signed_client
    make_env
    hand_files_to_container_users
    start_stack
    bootstrap_isac
    write_state
    enrol_member
    log "stack is up; state in ${WORK}/state.json"
    printf 'export AIVS_E2E_STATE=%s/state.json\n' "${WORK}"
}

# -----------------------------------------------------------------------------
# down
# -----------------------------------------------------------------------------
down() {
    refuse_foreign_objects "${FIXED_VOLUMES[@]}"
    if [[ -f "${WORK}/.env" ]]; then
        log "removing the stack and its volumes"
        compose down --volumes --remove-orphans --timeout 10
    fi
    if [[ -d "${WORK}" ]]; then
        # Files the containers own (the server key, the KEK) sit in directories
        # this user owns, so they can be removed without root.
        rm -rf -- "${WORK}"
    fi
    log "down"
}

logs() {
    # For a failed CI run: what each service said, and what health it reported.
    [[ -f "${WORK}/.env" ]] || die "no stack in ${WORK}"
    compose ps --all
    compose logs --no-color --timestamps
}

case "${1-}" in
    up)   up ;;
    down) down ;;
    logs) logs ;;
    *)    printf 'usage: %s up|down|logs\n' "$0" >&2; exit 2 ;;
esac
