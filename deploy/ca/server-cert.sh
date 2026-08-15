#!/usr/bin/env bash
# =============================================================================
# Issue the TLS server certificate for the AIVS edge proxy.
#
#   ./server-cert.sh --hostname aivs.example-isac.org
#   ./server-cert.sh --hostname aivs.example-isac.org --san aivs-dr.example-isac.org --san-ip 10.88.0.1
#
# Writes out/nginx/server.crt and out/nginx/server.key, which docker-compose.yml
# mounts read-only into the proxy as /etc/nginx/ca/nginx/.
#
# THE KEY'S FILE MODE MATTERS HERE. nginx runs as an unprivileged uid inside
# the container (101 by default in the nginx-unprivileged image) and reads this
# key through a bind mount, so it cannot be 0600 owned by the operator. It is
# written 0640 and group-owned by that uid instead: readable by nginx, not by
# other users on the host. That is the tightest mode that works; see
# --nginx-gid if your image uses a different uid.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=deploy/ca/_lib.sh
source "${SCRIPT_DIR}/_lib.sh"
cd "${SCRIPT_DIR}"

CONFIG="./openssl.cnf"

HOSTNAME_PRIMARY=""
ORG=""
COUNTRY="US"
KEY_ALG="ec"
# 397 days is the CA/Browser Forum maximum for publicly trusted server
# certificates. This CA is private and could issue for longer, but matching the
# public limit keeps the rotation habit alive and bounds the damage from a
# server key compromise that goes unnoticed.
DAYS="397"
NGINX_GID="101"
declare -a SAN_DNS=()
declare -a SAN_IP=()

usage() {
    cat <<'EOF'
Usage: server-cert.sh --hostname <fqdn> [options]

Required:
  --hostname FQDN      Primary DNS name members will connect to. Becomes the
                       common name and the first subjectAltName.

Options:
  --san FQDN           Additional DNS subjectAltName. Repeatable.
  --san-ip ADDR        Additional IP subjectAltName (for a WireGuard overlay
                       address, where there may be no DNS). Repeatable.
  --org NAME           Organisation name in the subject
                       (default: taken from the issuing CA certificate)
  --country CC         ISO 3166-1 alpha-2 code (default: US)
  --key-alg ec|rsa     Server key algorithm (default: ec = NIST P-384)
  --days N             Validity in days (default: 397)
  --nginx-gid GID      Group that must be able to read the private key
                       (default: 101, the nginx-unprivileged image's uid/gid)
  -h, --help           This message.
EOF
}

while (( $# > 0 )); do
    case "$1" in
        --hostname)  HOSTNAME_PRIMARY="${2-}"; shift 2 ;;
        --san)       SAN_DNS+=( "${2-}" );     shift 2 ;;
        --san-ip)    SAN_IP+=( "${2-}" );      shift 2 ;;
        --org)       ORG="${2-}";              shift 2 ;;
        --country)   COUNTRY="${2-}";          shift 2 ;;
        --key-alg)   KEY_ALG="${2-}";          shift 2 ;;
        --days)      DAYS="${2-}";             shift 2 ;;
        --nginx-gid) NGINX_GID="${2-}";        shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *)           usage >&2; aivs_die "unknown argument: $1" ;;
    esac
done

aivs_require_openssl

[[ -n "${HOSTNAME_PRIMARY}" ]] || { usage >&2; aivs_die "--hostname is required"; }
aivs_validate_hostname "${HOSTNAME_PRIMARY}"
aivs_validate_country "${COUNTRY}"
aivs_validate_key_alg "${KEY_ALG}"
aivs_validate_days "--days" "${DAYS}"

GID_PATTERN='^[0-9]+$'
[[ "${NGINX_GID}" =~ $GID_PATTERN ]] || aivs_die "--nginx-gid must be numeric"

if (( ${#SAN_DNS[@]} > 0 )); then
    for name in "${SAN_DNS[@]}"; do
        aivs_validate_hostname "${name}"
    done
fi
if (( ${#SAN_IP[@]} > 0 )); then
    for addr in "${SAN_IP[@]}"; do
        aivs_validate_ip "${addr}"
    done
fi

[[ -f "./private/intermediate.key" ]] \
    || aivs_die "issuing CA key not found. Run ./init-ca.sh first."

# Inherit the organisation name from the issuing CA unless told otherwise, so
# the server certificate's O matches the CA's by default and nobody has to
# remember what was typed at init time.
if [[ -z "${ORG}" ]]; then
    ORG="$(openssl x509 -in "./out/intermediate/intermediate.crt" -noout -subject -nameopt sep_multiline,utf8 \
           | sed -n 's/^ *O=//p' | head -n1)"
    [[ -n "${ORG}" ]] || aivs_die "could not read the organisation name from the issuing CA; pass --org"
fi
aivs_validate_name_component "--org" "${ORG}"

KEY_OUT="./out/nginx/server.key"
CSR_OUT="./out/nginx/server.csr"
CERT_OUT="./out/nginx/server.crt"

aivs_publish_dir "./out/nginx"
aivs_refuse_overwrite "${KEY_OUT}"
aivs_refuse_overwrite "${CERT_OUT}"
aivs_refuse_overwrite "${CSR_OUT}"

# -----------------------------------------------------------------------------
# subjectAltName
#
# Built into a temporary extension file rather than into openssl.cnf, because
# it is the only per-deployment value in the whole configuration and putting it
# in the committed file would mean either an $ENV:: reference (which OpenSSL
# expands for every command, breaking the ones that do not set it) or an
# operator editing a security-reviewed file by hand on every install.
#
# The common name is repeated as the first SAN: every client stack that matters
# has ignored the CN for name matching since RFC 6125, and a certificate whose
# CN is not also a SAN simply fails to validate.
#
# mktemp -d honours TMPDIR, and the trap removes it on any exit path including
# an error. Nothing secret is written there -- the extension file contains only
# hostnames -- but leaving debris in /tmp is how stale SANs get reused.
# -----------------------------------------------------------------------------
TMPDIR_EXT="$(mktemp -d)"
trap 'rm -rf -- "${TMPDIR_EXT}"' EXIT
EXT_FILE="${TMPDIR_EXT}/server-ext.cnf"

{
    printf '[ v3_server_cert ]\n'
    printf 'basicConstraints        = critical, CA:FALSE\n'
    printf 'keyUsage                = critical, digitalSignature, keyEncipherment\n'
    printf 'extendedKeyUsage        = serverAuth\n'
    printf 'subjectKeyIdentifier    = hash\n'
    printf 'authorityKeyIdentifier  = keyid,issuer\n'
    printf 'subjectAltName          = @alt_names\n'
    printf '\n[ alt_names ]\n'

    n=1
    printf 'DNS.%d = %s\n' "${n}" "${HOSTNAME_PRIMARY}"
    if (( ${#SAN_DNS[@]} > 0 )); then
        for name in "${SAN_DNS[@]}"; do
            n=$(( n + 1 ))
            printf 'DNS.%d = %s\n' "${n}" "${name}"
        done
    fi
    n=0
    if (( ${#SAN_IP[@]} > 0 )); then
        for addr in "${SAN_IP[@]}"; do
            n=$(( n + 1 ))
            printf 'IP.%d = %s\n' "${n}" "${addr}"
        done
    fi
} > "${EXT_FILE}"

# -----------------------------------------------------------------------------
# Key, request, certificate
# -----------------------------------------------------------------------------
aivs_step "Generating server key (${KEY_ALG})"
aivs_generate_key "${KEY_ALG}" "${KEY_OUT}"

aivs_step "Creating server certificate request"
openssl req -new \
    -config "${CONFIG}" \
    -key "${KEY_OUT}" \
    -sha384 \
    -subj "/C=${COUNTRY}/O=${ORG}/OU=AIVS Edge Proxy/CN=${HOSTNAME_PRIMARY}" \
    -out "${CSR_OUT}" \
    || aivs_die "server CSR generation failed"
chmod 0600 "${CSR_OUT}"

aivs_step "Signing server certificate (${DAYS} days)"
openssl ca \
    -config "${CONFIG}" \
    -name CA_intermediate \
    -extfile "${EXT_FILE}" \
    -extensions v3_server_cert \
    -days "${DAYS}" \
    -md sha384 \
    -notext \
    -batch \
    -in "${CSR_OUT}" \
    -out "${CERT_OUT}" \
    || aivs_die "signing the server certificate failed"

aivs_publish "${CERT_OUT}"

openssl verify -CAfile "./out/ca-chain.pem" -purpose sslserver "${CERT_OUT}" >/dev/null \
    || aivs_die "the server certificate does not verify as a server certificate against out/ca-chain.pem"

# -----------------------------------------------------------------------------
# Private key permissions for the container
# -----------------------------------------------------------------------------
# Owned by the container's uid, mode 0400. chgrp alone left the key readable by
# whatever host group happens to hold gid ${NGINX_GID} -- bind mounts share the
# host's numeric id space with no translation, and on Debian and Ubuntu the low
# 100s are already occupied by unrelated system groups. The container only ever
# reads this file as uid ${NGINX_GID}, so group access bought nothing.
chmod 0400 "${KEY_OUT}"
if chown "${NGINX_GID}:${NGINX_GID}" "${KEY_OUT}" 2>/dev/null; then
    KEY_MODE_NOTE="0400, owner ${NGINX_GID}"
    aivs_ok "server.key is 0400, owned by uid/gid ${NGINX_GID} (readable by nginx only)"
else
    KEY_MODE_NOTE="0400, owner NOT SET -- see the warning above"
    aivs_warn "could not chown ${NGINX_GID}:${NGINX_GID} ${KEY_OUT} (needs root).
         nginx runs as uid/gid ${NGINX_GID} and will fail to start with
         'cannot load certificate key ... Permission denied' until this is fixed:

             sudo chown ${NGINX_GID}:${NGINX_GID} ${SCRIPT_DIR}/out/nginx/server.key
             sudo chmod 0400              ${SCRIPT_DIR}/out/nginx/server.key"
fi

SAN_LINE="$(openssl x509 -in "${CERT_OUT}" -noout -ext subjectAltName \
            | tail -n +2 | tr -d ' \n')"
NOT_AFTER="$(openssl x509 -in "${CERT_OUT}" -noout -enddate | sed 's/^notAfter=//')"

cat <<EOF

${_AIVS_BOLD}Edge proxy certificate issued.${_AIVS_RESET}

  Common name  ${HOSTNAME_PRIMARY}
  SANs         ${SAN_LINE}
  Expires      ${NOT_AFTER}

  out/nginx/server.crt   0644
  out/nginx/server.key   ${KEY_MODE_NOTE}

  Members verify this certificate against out/ca-chain.pem, the same trust
  anchor the proxy uses to verify them. Set --hostname to the name members will
  actually dial: a mismatch shows up as a client-side hostname verification
  failure that looks nothing like a certificate problem.

  Renew before ${NOT_AFTER}. There is no automatic renewal; put it in the
  operational calendar.

EOF
