#!/usr/bin/env bash
# =============================================================================
# Revoke a certificate issued by the AIVS issuing CA and regenerate the CRLs.
#
#   ./revoke.sh --org-slug example-bank --reason keyCompromise
#   ./revoke.sh --cert /path/to/some.crt --reason cessationOfOperation
#   ./revoke.sh --gencrl-only              # scheduled CRL refresh, no revocation
#
# ---------------------------------------------------------------------------
# READ THIS BEFORE RELYING ON IT: THE CRL IS NOT WHAT STOPS ACCESS.
#
# AIVS revocation is authoritative in the DATABASE. A member is cut off by
# disabling their certificate/organisation record in AIVS, at which point the
# application refuses every request carrying that fingerprint -- immediately,
# on the next request, with no cache and no distribution delay.
#
# This CRL is belt and braces. It matters for anything OUTSIDE AIVS that
# consumes the same certificates (a partner ISAC federating with this CA, an
# operator running `openssl verify`, a future gateway), and it matters for
# defence in depth if the application's revocation check were ever bypassed.
# It is also the mechanism by which the ROOT can disown a compromised issuing
# CA, which the database cannot do.
#
# It is deliberately NOT wired into nginx by default. deploy/nginx/nginx.conf
# has the ssl_crl line commented with the reasoning: OpenSSL demands a current
# CRL for every CA in the chain once ssl_crl is set, and an expired CRL turns
# every handshake into a failure. Enabling it means committing to regenerating
# these files well inside default_crl_days (30 days for the issuing CA, 180 for
# the root) -- that is what --gencrl-only is for.
#
# ORDER OF OPERATIONS WHEN A KEY IS COMPROMISED:
#   1. Disable the organisation/certificate in AIVS.       <- stops access
#   2. Run this script.                                    <- external record
#   3. Copy out/crl/ to wherever relying parties fetch it.
#   4. Issue a replacement with issue-client.sh and register its new SHA-256.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=deploy/ca/_lib.sh
source "${SCRIPT_DIR}/_lib.sh"
cd "${SCRIPT_DIR}"

CONFIG="./openssl.cnf"

ORG_SLUG=""
CERT_PATH=""
REASON="unspecified"
GENCRL_ONLY="no"
ROOT_PASSPHRASE_FILE=""
REGEN_ROOT_CRL="no"

usage() {
    cat <<'EOF'
Usage: revoke.sh (--org-slug <slug> | --cert <path> | --gencrl-only) [options]

One of:
  --org-slug SLUG      Revoke the certificate issued to this AIVS organisation
                       slug (out/clients/<slug>/<slug>.crt).
  --cert PATH          Revoke the certificate at this path. Use for a
                       certificate signed from a member-supplied CSR that was
                       archived elsewhere, or for the issuing CA itself.
  --gencrl-only        Revoke nothing; just regenerate the CRLs. Run this on a
                       schedule if nginx's ssl_crl is enabled.

Options:
  --reason REASON      CRL reason code. One of:
                         unspecified, keyCompromise, CACompromise,
                         affiliationChanged, superseded, cessationOfOperation,
                         certificateHold, removeFromCRL
                       (default: unspecified)
  --root-crl           Also regenerate the ROOT CRL. Needs the root key, so
                       only possible with the offline media mounted. Required
                       if you revoked the issuing CA, and periodically to keep
                       crl-chain.pem from expiring.
  --root-passphrase-file P
                       Read the root key passphrase from file P instead of
                       prompting (used with --root-crl).
  -h, --help           This message.
EOF
}

while (( $# > 0 )); do
    case "$1" in
        --org-slug)     ORG_SLUG="${2-}";  shift 2 ;;
        --cert)         CERT_PATH="${2-}"; shift 2 ;;
        --reason)       REASON="${2-}";    shift 2 ;;
        --gencrl-only)  GENCRL_ONLY="yes"; shift ;;
        --root-crl)     REGEN_ROOT_CRL="yes"; shift ;;
        --root-passphrase-file) ROOT_PASSPHRASE_FILE="${2-}"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              usage >&2; aivs_die "unknown argument: $1" ;;
    esac
done

aivs_require_openssl

# The reason code is validated against an allowlist rather than passed through,
# because openssl accepts an unknown -crl_reason silently in some versions and
# records `unspecified`. A revocation recorded with the wrong reason is worse
# than useless in an incident review.
VALID_REASONS=(
    unspecified keyCompromise CACompromise affiliationChanged
    superseded cessationOfOperation certificateHold removeFromCRL
)
REASON_OK="no"
for valid in "${VALID_REASONS[@]}"; do
    if [[ "${valid}" == "${REASON}" ]]; then
        REASON_OK="yes"
    fi
done
[[ "${REASON_OK}" == "yes" ]] \
    || aivs_die "invalid --reason '${REASON}'; see --help for the accepted values"

[[ -f "./private/intermediate.key" ]] \
    || aivs_die "issuing CA key not found. Run ./init-ca.sh first."
[[ -f "./index.txt" ]] \
    || aivs_die "issuing CA database not found. Run ./init-ca.sh first."

if [[ "${GENCRL_ONLY}" == "yes" ]]; then
    [[ -z "${ORG_SLUG}" && -z "${CERT_PATH}" ]] \
        || aivs_die "--gencrl-only cannot be combined with --org-slug or --cert"
elif [[ -n "${ORG_SLUG}" && -n "${CERT_PATH}" ]]; then
    aivs_die "--org-slug and --cert are mutually exclusive"
elif [[ -n "${ORG_SLUG}" ]]; then
    aivs_validate_slug "${ORG_SLUG}"
    CERT_PATH="./out/clients/${ORG_SLUG}/${ORG_SLUG}.crt"
    [[ -f "${CERT_PATH}" ]] \
        || aivs_die "no certificate found at ${CERT_PATH}
       If this member's certificate was signed from a CSR and archived
       elsewhere, pass its path with --cert instead."
elif [[ -n "${CERT_PATH}" ]]; then
    [[ -f "${CERT_PATH}" ]] || aivs_die "certificate not found: ${CERT_PATH}"
else
    usage >&2
    aivs_die "one of --org-slug, --cert or --gencrl-only is required"
fi

# -----------------------------------------------------------------------------
# Revoke
# -----------------------------------------------------------------------------
if [[ "${GENCRL_ONLY}" != "yes" ]]; then
    SUBJECT="$(openssl x509 -in "${CERT_PATH}" -noout -subject -nameopt rfc2253 | sed 's/^subject=//')"
    SERIAL="$(openssl x509 -in "${CERT_PATH}" -noout -serial | sed 's/^serial=//')"
    FINGERPRINT="$(aivs_fingerprint_sha256 "${CERT_PATH}")"

    aivs_step "Revoking certificate"
    aivs_log "  subject  ${SUBJECT}"
    aivs_log "  serial   ${SERIAL}"
    aivs_log "  SHA-256  ${FINGERPRINT}"
    aivs_log "  reason   ${REASON}"

    # openssl exits non-zero if this serial is already revoked, which is the
    # behaviour we want: a second revocation attempt should be visible, not
    # silently absorbed.
    openssl ca \
        -config "${CONFIG}" \
        -name CA_intermediate \
        -revoke "${CERT_PATH}" \
        -crl_reason "${REASON}" \
        || aivs_die "revocation failed (already revoked? check index.txt)"

    aivs_ok "recorded in index.txt"
fi

# -----------------------------------------------------------------------------
# Regenerate CRLs
# -----------------------------------------------------------------------------
aivs_publish_dir "./out/crl"

aivs_step "Regenerating the issuing CA CRL"
openssl ca -config "${CONFIG}" -name CA_intermediate -gencrl -md sha384 \
    -out "./out/crl/intermediate.crl.pem" \
    || aivs_die "issuing CA CRL generation failed"
aivs_publish "./out/crl/intermediate.crl.pem"

if [[ "${REGEN_ROOT_CRL}" == "yes" ]]; then
    [[ -f "./private/root/root.key" ]] \
        || aivs_die "root key not present. Mount the offline media at
       ${SCRIPT_DIR}/private/root before using --root-crl, and remove it again
       afterwards."

    declare -a ROOT_PASSIN
    aivs_passphrase_args ROOT_PASSIN "in" "${ROOT_PASSPHRASE_FILE}"

    aivs_step "Regenerating the root CRL"
    openssl ca -config "${CONFIG}" -name CA_root -gencrl -md sha384 \
        -out "./out/crl/root.crl.pem" \
        "${ROOT_PASSIN[@]+"${ROOT_PASSIN[@]}"}" \
        || aivs_die "root CRL generation failed"
    aivs_publish "./out/crl/root.crl.pem"
else
    [[ -f "./out/crl/root.crl.pem" ]] \
        || aivs_die "out/crl/root.crl.pem is missing; regenerate it with --root-crl"
fi

# Both CRLs in one file. OpenSSL applies CRL_CHECK_ALL when nginx is given an
# ssl_crl, meaning it needs a CRL for every CA in the chain -- the issuing CA's
# alone is rejected. This is that file.
cat "./out/crl/intermediate.crl.pem" "./out/crl/root.crl.pem" > "./out/crl/crl-chain.pem"
aivs_publish "./out/crl/crl-chain.pem"

INT_NEXT_UPDATE="$(openssl crl -in "./out/crl/intermediate.crl.pem" -noout -nextupdate | sed 's/^nextUpdate=//')"
ROOT_NEXT_UPDATE="$(openssl crl -in "./out/crl/root.crl.pem" -noout -nextupdate | sed 's/^nextUpdate=//')"
REVOKED_COUNT="$(grep -c '^R' "./index.txt" || true)"

cat <<EOF

${_AIVS_BOLD}CRLs regenerated.${_AIVS_RESET}

  out/crl/intermediate.crl.pem   next update ${INT_NEXT_UPDATE}
  out/crl/root.crl.pem           next update ${ROOT_NEXT_UPDATE}
  out/crl/crl-chain.pem          both, for nginx ssl_crl

  Certificates revoked to date: ${REVOKED_COUNT}

${_AIVS_BOLD}${_AIVS_YELLOW}The CRL is not what stops access.${_AIVS_RESET} Disable the certificate or the
  organisation in AIVS -- that is authoritative, takes effect on the next
  request, and is what the audit trail records. If you have not done that yet,
  do it now; this file changes nothing on its own.

  If nginx's ssl_crl is enabled, reload the proxy to pick up the new file:

      docker compose exec proxy nginx -s reload

  and make sure something regenerates these before the next-update dates above:

      ${SCRIPT_DIR}/revoke.sh --gencrl-only

EOF
