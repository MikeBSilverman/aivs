#!/usr/bin/env bash
# =============================================================================
# Issue an AIVS member (client) certificate.
#
# Two modes:
#
#   PREFERRED -- the member generates its own key and sends you a CSR:
#       ./issue-client.sh --org-slug example-bank --csr /tmp/example-bank.csr
#     The private key never exists outside the member's control, so a breach of
#     this host cannot impersonate them and there is no key to transport.
#
#   FALLBACK -- this script generates the key and CSR too:
#       ./issue-client.sh --org-slug example-bank --org "Example Bank NA"
#     Use only when the member cannot produce a CSR. You must then hand them
#     the private key over an out-of-band encrypted channel and delete your
#     copy. A key that has been emailed is a key that must be re-issued.
#
# The output that matters is the SHA-256 FINGERPRINT. That, not the DN and not
# the serial, is what AIVS stores against an organisation and what every
# authorisation decision starts from. Nothing works until it is registered.
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
ORG=""
COUNTRY="US"
COMMON_NAME=""
CSR_IN=""
KEY_ALG="ec"
# 365 days. Short enough that a certificate whose revocation was somehow missed
# ages out inside an annual access-review cycle; long enough that an ISAC
# member is not re-enrolling every quarter.
DAYS="365"

usage() {
    cat <<'EOF'
Usage: issue-client.sh --org-slug <slug> (--csr <path> | --org <name>) [options]

Required:
  --org-slug SLUG      AIVS organisation slug. Lowercase letters, digits and
                       internal dashes only; must match the slug registered in
                       AIVS. Also used as the output directory name.

One of:
  --csr PATH           Sign a certificate signing request produced by the
                       member. PREFERRED: their private key never leaves them.
  --org NAME           Generate a key and CSR here, with this organisation name
                       in the subject. Fallback only.

Options:
  --country CC         ISO 3166-1 alpha-2 code for a generated CSR (default: US)
  --cn NAME            Common name for a generated CSR
                       (default: "<org> AIVS Client")
  --key-alg ec|rsa     Algorithm for a generated key (default: ec = NIST P-384)
  --days N             Validity in days (default: 365)
  -h, --help           This message.

Output (deploy/ca/out/clients/<slug>/, mode 0700):
  <slug>.crt           the issued certificate
  <slug>.sha256        its SHA-256 fingerprint -- register this in AIVS
  <slug>.csr           the request that was signed
  <slug>.key           the private key, only when generated here
  ca-chain.pem         trust anchor for the member to verify the AIVS server
EOF
}

while (( $# > 0 )); do
    case "$1" in
        --org-slug) ORG_SLUG="${2-}"; shift 2 ;;
        --org)      ORG="${2-}";      shift 2 ;;
        --country)  COUNTRY="${2-}";  shift 2 ;;
        --cn)       COMMON_NAME="${2-}"; shift 2 ;;
        --csr)      CSR_IN="${2-}";   shift 2 ;;
        --key-alg)  KEY_ALG="${2-}";  shift 2 ;;
        --days)     DAYS="${2-}";     shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *)          usage >&2; aivs_die "unknown argument: $1" ;;
    esac
done

aivs_require_openssl

[[ -n "${ORG_SLUG}" ]] || { usage >&2; aivs_die "--org-slug is required"; }
aivs_validate_slug "${ORG_SLUG}"
aivs_validate_days "--days" "${DAYS}"

if [[ -n "${CSR_IN}" && -n "${ORG}" ]]; then
    aivs_die "--csr and --org are mutually exclusive: with --csr the subject comes from the request"
fi
if [[ -z "${CSR_IN}" && -z "${ORG}" ]]; then
    usage >&2
    aivs_die "provide either --csr <path> (preferred) or --org <name>"
fi

# Validate every generated-key argument up front, before anything is written.
# A validation failure half way through leaves an empty client directory and a
# stray key behind, and the next run then trips the overwrite guard for a
# reason that has nothing to do with the actual mistake.
if [[ -z "${CSR_IN}" ]]; then
    aivs_validate_country "${COUNTRY}"
    aivs_validate_name_component "--org" "${ORG}"
    aivs_validate_key_alg "${KEY_ALG}"
    COMMON_NAME="${COMMON_NAME:-${ORG} AIVS Client}"
    aivs_validate_name_component "--cn" "${COMMON_NAME}"
fi

[[ -f "./private/intermediate.key" ]] \
    || aivs_die "issuing CA key not found. Run ./init-ca.sh first."
[[ -f "./out/ca-chain.pem" ]] \
    || aivs_die "out/ca-chain.pem not found. Run ./init-ca.sh first."

OUT_DIR="./out/clients/${ORG_SLUG}"
CERT_OUT="${OUT_DIR}/${ORG_SLUG}.crt"
CSR_OUT="${OUT_DIR}/${ORG_SLUG}.csr"
KEY_OUT="${OUT_DIR}/${ORG_SLUG}.key"
FPR_OUT="${OUT_DIR}/${ORG_SLUG}.sha256"

# A second issuance for the same slug is a legitimate operation (renewal,
# re-key) but it must not silently clobber the previous artefacts -- the old
# certificate is still valid until it is revoked, and its fingerprint is still
# live in AIVS.
aivs_refuse_overwrite "${CERT_OUT}"
aivs_refuse_overwrite "${CSR_OUT}"

# 0700: this directory holds a private key in the generated-key mode, and there
# is no reason for it to be readable by anything but the operator in either.
aivs_private_dir "${OUT_DIR}"

# -----------------------------------------------------------------------------
# Reject weak subscriber keys.
#
# The CA's own strength is irrelevant if a member protects its identity with a
# 1024-bit RSA key. The floor is 2048-bit RSA / 256-bit EC (NIST SP 800-131A
# "acceptable"); anything below 3072-bit RSA earns a warning because it will
# fall out of acceptability during the certificate's own lifetime.
# -----------------------------------------------------------------------------
check_public_key_strength() {
    local csr="$1"
    local pubtext bits

    pubtext="$(openssl req -in "${csr}" -noout -pubkey 2>/dev/null \
               | openssl pkey -pubin -noout -text 2>/dev/null)" \
        || aivs_die "could not read the public key from ${csr}"

    bits="$(printf '%s\n' "${pubtext}" \
            | sed -n 's/.*Public-Key: (\([0-9][0-9]*\) bit).*/\1/p' | head -n1)"

    case "${pubtext}" in
        *ED25519*|*ED448*)
            # Edwards curves have no "bit" line; both are >= 128-bit security.
            return 0
            ;;
        *Modulus:*)
            [[ -n "${bits}" ]] || aivs_die "could not determine RSA key size in ${csr}"
            (( bits >= 2048 )) || aivs_die "RSA key in ${csr} is ${bits} bits; 2048 is the minimum"
            (( bits >= 3072 )) || aivs_warn "RSA key is ${bits} bits; 3072+ is recommended for new issuance"
            ;;
        *)
            # Elliptic curve, or something exotic. Require a sane field size.
            [[ -n "${bits}" ]] || aivs_die "could not determine key size in ${csr}; unsupported key type"
            (( bits >= 256 )) || aivs_die "EC key in ${csr} is ${bits} bits; 256 is the minimum"
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Obtain the CSR
# -----------------------------------------------------------------------------
if [[ -n "${CSR_IN}" ]]; then
    [[ -f "${CSR_IN}" ]] || aivs_die "CSR not found: ${CSR_IN}"

    # -verify checks the request's self-signature, which proves the sender
    # holds the private key for the public key in it. Without this a request
    # could carry someone else's public key and the resulting certificate would
    # name a member who could never use it -- while the party who holds that
    # key could.
    openssl req -in "${CSR_IN}" -noout -verify >/dev/null 2>&1 \
        || aivs_die "the signature on ${CSR_IN} does not verify; do not sign this request"

    check_public_key_strength "${CSR_IN}"

    cp -- "${CSR_IN}" "${CSR_OUT}"
    chmod 0600 "${CSR_OUT}"
    aivs_ok "accepted member CSR (self-signature verified)"
else
    aivs_warn "generating the member's private key here. Hand it over encrypted
         and out of band, then delete ${KEY_OUT}. Prefer --csr next time."

    aivs_step "Generating member key (${KEY_ALG})"
    aivs_generate_key "${KEY_ALG}" "${KEY_OUT}"

    aivs_step "Creating certificate request"
    # OU carries the AIVS slug so that an operator reading an audit log or a
    # revocation list can map a DN back to an organisation without a lookup.
    openssl req -new \
        -config "${CONFIG}" \
        -key "${KEY_OUT}" \
        -sha384 \
        -subj "/C=${COUNTRY}/O=${ORG}/OU=${ORG_SLUG}/CN=${COMMON_NAME}" \
        -out "${CSR_OUT}" \
        || aivs_die "CSR generation failed"
    chmod 0600 "${CSR_OUT}"
fi

# -----------------------------------------------------------------------------
# Sign
#
# -extensions v3_client_cert forces basicConstraints CA:FALSE,
# extendedKeyUsage clientAuth and keyUsage digitalSignature+keyEncipherment
# regardless of what the request asked for. openssl.cnf sets
# copy_extensions = none, so a member cannot smuggle CA:TRUE or serverAuth into
# its own certificate by putting them in the CSR.
# -----------------------------------------------------------------------------
aivs_step "Signing member certificate (${DAYS} days)"
openssl ca \
    -config "${CONFIG}" \
    -name CA_intermediate \
    -extensions v3_client_cert \
    -days "${DAYS}" \
    -md sha384 \
    -notext \
    -batch \
    -in "${CSR_OUT}" \
    -out "${CERT_OUT}" \
    || aivs_die "signing failed"
chmod 0644 "${CERT_OUT}"

# Prove the issued certificate actually chains to the trust anchor the proxy
# will be given, and that it carries clientAuth. If either is wrong the member
# discovers it as an opaque TLS alert; we would rather discover it here.
openssl verify -CAfile "./out/ca-chain.pem" -purpose sslclient "${CERT_OUT}" >/dev/null \
    || aivs_die "the issued certificate does not verify as a client certificate against out/ca-chain.pem"

cp -- "./out/ca-chain.pem" "${OUT_DIR}/ca-chain.pem"
chmod 0644 "${OUT_DIR}/ca-chain.pem"

# -----------------------------------------------------------------------------
# The fingerprint
# -----------------------------------------------------------------------------
FINGERPRINT="$(aivs_fingerprint_sha256 "${CERT_OUT}")"
printf '%s\n' "${FINGERPRINT}" > "${FPR_OUT}"
chmod 0644 "${FPR_OUT}"

SUBJECT="$(openssl x509 -in "${CERT_OUT}" -noout -subject -nameopt rfc2253 | sed 's/^subject=//')"
SERIAL="$(openssl x509 -in "${CERT_OUT}" -noout -serial | sed 's/^serial=//')"
NOT_AFTER="$(openssl x509 -in "${CERT_OUT}" -noout -enddate | sed 's/^notAfter=//')"

cat <<EOF

${_AIVS_BOLD}Certificate issued for '${ORG_SLUG}'.${_AIVS_RESET}

  Subject      ${SUBJECT}
  Serial       ${SERIAL}
  Expires      ${NOT_AFTER}

${_AIVS_BOLD}  SHA-256      ${FINGERPRINT}${_AIVS_RESET}

  ${_AIVS_BOLD}Register that SHA-256 fingerprint against organisation '${ORG_SLUG}' in
  AIVS.${_AIVS_RESET} It is the identity: the application recomputes it from the
  certificate the proxy forwards and refuses any certificate it does not
  recognise, however validly it was issued. Nothing else here -- not the DN,
  not the serial -- is used for authorisation.

  Note that this is NOT the fingerprint 'openssl x509 -fingerprint' prints by
  default (SHA-1), nor the one in the proxy's access log (also SHA-1).

  Send to the member:
    ${OUT_DIR}/${ORG_SLUG}.crt
    ${OUT_DIR}/ca-chain.pem
$(if [[ -f "${KEY_OUT}" ]]; then
    printf '    %s   <- SECRET: encrypted, out-of-band channel only, then\n' "${KEY_OUT}"
    printf '        shred -u %s on this host\n' "${KEY_OUT}"
fi)
  Revoke with:
    ./revoke.sh --org-slug ${ORG_SLUG} --reason <reason>
  and disable the organisation in AIVS, which is what actually stops requests.

EOF
