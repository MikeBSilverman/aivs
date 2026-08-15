#!/usr/bin/env bash
# =============================================================================
# Create the AIVS two-tier private CA.
#
# Run ONCE per AIVS instance, before anything else in deploy/. It produces:
#
#   private/root/root.key         offline root key (encrypted by default)
#   out/root/root.crt             root certificate, 20 years
#   private/intermediate.key      issuing key, used unattended, 0600
#   out/intermediate/intermediate.crt   issuing certificate, 10 years
#   out/ca-chain.pem              intermediate + root: the member trust anchor
#   out/crl/{root,intermediate,crl-chain}.crl.pem
#
# WHY TWO TIERS AT ALL. The issuing key must be readable by an unattended
# process on a host that also runs a public-facing service; assume it can be
# stolen. Recovering from that with a single-tier CA means re-distributing a
# new trust anchor to every member out of band. With a root that lives on
# offline media, recovery is: revoke the intermediate, issue a new one from the
# root, re-issue member certificates. Members' trust anchors do not change.
#
# The root's only jobs are to sign that one intermediate and to sign root CRLs.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# 077 so that anything created before an explicit chmod -- including openssl's
# own temporary files and the CA database -- is owner-only from the instant it
# exists, rather than being briefly world-readable.
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=deploy/ca/_lib.sh
source "${SCRIPT_DIR}/_lib.sh"
# openssl.cnf uses relative paths so that the CA is relocatable and needs no
# $ENV:: substitution; every openssl invocation below therefore runs from here.
cd "${SCRIPT_DIR}"

CONFIG="./openssl.cnf"

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
COUNTRY="US"
ORG=""
ROOT_CN=""
INTERMEDIATE_CN=""
KEY_ALG="ec"
# 20 years. A root is expensive to distribute, so it should outlive several
# generations of issuing key without a membership-wide re-enrolment.
ROOT_DAYS="7300"
# 10 years, leaving a decade of headroom over the 1-year member certificates it
# signs. An intermediate that expires before the certificates under it is a
# classic and entirely avoidable outage.
INTERMEDIATE_DAYS="3650"
ROOT_PASSPHRASE_FILE=""
PLAINTEXT_ROOT_KEY="no"

usage() {
    cat <<'EOF'
Usage: init-ca.sh --org <organisation name> [options]

Required:
  --org NAME                 Organisation name for the CA subject, e.g.
                             "Example Financial ISAC". Letters, digits, spaces
                             and . _ & ( ) ' - only.

Options:
  --country CC               ISO 3166-1 alpha-2 code (default: US)
  --root-cn NAME             Root CA common name
                             (default: "<org> AIVS Root CA")
  --intermediate-cn NAME     Issuing CA common name
                             (default: "<org> AIVS Issuing CA")
  --key-alg ec|rsa           CA key algorithm (default: ec = NIST P-384;
                             rsa = 4096-bit, for HSMs that cannot hold EC keys)
  --root-days N              Root validity in days (default: 7300, ~20 years)
  --intermediate-days N      Issuing CA validity in days (default: 3650)
  --root-passphrase-file P   Read the root key passphrase from file P instead
                             of prompting. For automated bootstrap only; the
                             file must be deleted afterwards.
  --plaintext-root-key       Do NOT encrypt the root key. Only for ephemeral
                             test CAs. Refused unless AIVS_CA_ALLOW_PLAINTEXT_ROOT=1
                             is also set, so it cannot be reached by a typo.
  -h, --help                 This message.

Examples:
  ./init-ca.sh --org "Example Financial ISAC" --country US
  ./init-ca.sh --org "Aequora" --key-alg rsa --root-days 5475
EOF
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
while (( $# > 0 )); do
    case "$1" in
        --org)                   ORG="${2-}";                  shift 2 ;;
        --country)               COUNTRY="${2-}";              shift 2 ;;
        --root-cn)               ROOT_CN="${2-}";              shift 2 ;;
        --intermediate-cn)       INTERMEDIATE_CN="${2-}";      shift 2 ;;
        --key-alg)               KEY_ALG="${2-}";              shift 2 ;;
        --root-days)             ROOT_DAYS="${2-}";            shift 2 ;;
        --intermediate-days)     INTERMEDIATE_DAYS="${2-}";    shift 2 ;;
        --root-passphrase-file)  ROOT_PASSPHRASE_FILE="${2-}"; shift 2 ;;
        --plaintext-root-key)    PLAINTEXT_ROOT_KEY="yes";     shift ;;
        -h|--help)               usage; exit 0 ;;
        *)                       usage >&2; aivs_die "unknown argument: $1" ;;
    esac
done

aivs_require_openssl

[[ -n "${ORG}" ]] || { usage >&2; aivs_die "--org is required"; }

ROOT_CN="${ROOT_CN:-${ORG} AIVS Root CA}"
INTERMEDIATE_CN="${INTERMEDIATE_CN:-${ORG} AIVS Issuing CA}"

aivs_validate_country "${COUNTRY}"
aivs_validate_name_component "--org" "${ORG}"
aivs_validate_name_component "--root-cn" "${ROOT_CN}"
aivs_validate_name_component "--intermediate-cn" "${INTERMEDIATE_CN}"
aivs_validate_key_alg "${KEY_ALG}"
aivs_validate_days "--root-days" "${ROOT_DAYS}"
aivs_validate_days "--intermediate-days" "${INTERMEDIATE_DAYS}"

if [[ "${PLAINTEXT_ROOT_KEY}" == "yes" && "${AIVS_CA_ALLOW_PLAINTEXT_ROOT:-0}" != "1" ]]; then
    aivs_die "--plaintext-root-key also requires AIVS_CA_ALLOW_PLAINTEXT_ROOT=1.
       An unencrypted root key on a networked host removes the entire benefit
       of having a root separate from the issuing CA."
fi

if [[ -n "${ROOT_PASSPHRASE_FILE}" && "${PLAINTEXT_ROOT_KEY}" == "yes" ]]; then
    aivs_die "--root-passphrase-file and --plaintext-root-key are mutually exclusive"
fi

# -----------------------------------------------------------------------------
# Refuse to run twice.
#
# Checked before anything is created, so a second invocation leaves the
# existing CA completely untouched rather than half-rewriting it.
# -----------------------------------------------------------------------------
aivs_refuse_overwrite "./private/root/root.key"
aivs_refuse_overwrite "./private/intermediate.key"
aivs_refuse_overwrite "./out/root/root.crt"
aivs_refuse_overwrite "./out/intermediate/intermediate.crt"

# -----------------------------------------------------------------------------
# Directory skeleton and CA databases
# -----------------------------------------------------------------------------
aivs_step "Creating CA directory skeleton under ${SCRIPT_DIR}"

aivs_private_dir "./private"
aivs_private_dir "./private/root"
aivs_private_dir "./private/root/newcerts"
aivs_private_dir "./newcerts"

aivs_publish_dir "./out"
aivs_publish_dir "./out/root"
aivs_publish_dir "./out/intermediate"
aivs_publish_dir "./out/crl"
aivs_publish_dir "./out/nginx"
aivs_publish_dir "./out/clients"

# `openssl ca` requires the database, serial and CRL-number files to exist
# before it will run; it will not create them.
#
# unique_subject = no permits re-issuing for a subject that already has a
# certificate. Renewals and re-keys are routine here, and with the default
# (yes) the second issuance for a member fails with a message that reads like
# database corruption.
init_ca_database() {
    local db="$1" serial="$2" crlnumber="$3"
    : > "${db}"
    printf 'unique_subject = no\n' > "${db}.attr"
    # A random 128-bit starting point. `rand_serial = yes` in openssl.cnf means
    # this file is not consulted for issuance, but `openssl ca` still insists
    # on its presence.
    openssl rand -hex 16 > "${serial}"
    printf '1000\n' > "${crlnumber}"
    chmod 0600 "${db}" "${db}.attr" "${serial}" "${crlnumber}"
}

init_ca_database "./private/root/index.txt" "./private/root/serial" "./private/root/crlnumber"
init_ca_database "./index.txt"              "./serial"              "./private/crlnumber"

aivs_ok "directories and CA databases created"

# -----------------------------------------------------------------------------
# Root CA
# -----------------------------------------------------------------------------
ROOT_SUBJECT="/C=${COUNTRY}/O=${ORG}/OU=AIVS Certificate Authority/CN=${ROOT_CN}"
INTERMEDIATE_SUBJECT="/C=${COUNTRY}/O=${ORG}/OU=AIVS Certificate Authority/CN=${INTERMEDIATE_CN}"

declare -a ROOT_KEY_PASS ROOT_PASSIN ROOT_ENCRYPTION
# `openssl genpkey` takes -pass (it rejects -passout); everything that reads the
# key back takes -passin.
aivs_passphrase_args ROOT_KEY_PASS ""   "${ROOT_PASSPHRASE_FILE}"
aivs_passphrase_args ROOT_PASSIN   "in" "${ROOT_PASSPHRASE_FILE}"

if [[ "${PLAINTEXT_ROOT_KEY}" == "yes" ]]; then
    ROOT_ENCRYPTION=()
    aivs_warn "root key will be written UNENCRYPTED (--plaintext-root-key)"
else
    # AES-256-CBC is what OpenSSL's PKCS#8 encryption offers here; the KDF is
    # PBKDF2 with a random salt. Use a passphrase with real entropy: this is
    # the only thing standing between a copied file and a root key.
    ROOT_ENCRYPTION=( -aes-256-cbc )
    if (( ${#ROOT_KEY_PASS[@]} == 0 )); then
        aivs_log ""
        aivs_log "You will now be prompted for a passphrase for the ROOT key."
        aivs_log "Store it in your organisation's password vault, separately"
        aivs_log "from the offline media that will hold the key itself."
        aivs_log ""
    fi
fi

aivs_step "Generating root CA key (${KEY_ALG})"
aivs_generate_key "${KEY_ALG}" "./private/root/root.key" \
    "${ROOT_ENCRYPTION[@]+"${ROOT_ENCRYPTION[@]}"}" \
    "${ROOT_KEY_PASS[@]+"${ROOT_KEY_PASS[@]}"}"
aivs_ok "private/root/root.key (mode 0600)"

aivs_step "Self-signing root certificate (${ROOT_DAYS} days)"
openssl req -new -x509 \
    -config "${CONFIG}" \
    -extensions v3_root_ca \
    -key "./private/root/root.key" \
    -sha384 \
    -days "${ROOT_DAYS}" \
    -subj "${ROOT_SUBJECT}" \
    -out "./out/root/root.crt" \
    "${ROOT_PASSIN[@]+"${ROOT_PASSIN[@]}"}" \
    || aivs_die "root certificate generation failed"
aivs_publish "./out/root/root.crt"
aivs_ok "out/root/root.crt"

# -----------------------------------------------------------------------------
# Issuing (intermediate) CA
#
# The issuing key is NOT passphrase-protected. issue-client.sh and the CRL
# refresh must run unattended, and a passphrase that has to be stored on the
# same host in order to be usable protects nothing while adding the illusion
# that it does. The controls that actually apply here are file mode 0600, an
# 0700 parent directory, and the root's ability to revoke this intermediate.
# -----------------------------------------------------------------------------
aivs_step "Generating issuing CA key (${KEY_ALG})"
aivs_generate_key "${KEY_ALG}" "./private/intermediate.key"
aivs_ok "private/intermediate.key (mode 0600, no passphrase -- see comment)"

aivs_step "Creating issuing CA certificate request"
openssl req -new \
    -config "${CONFIG}" \
    -key "./private/intermediate.key" \
    -sha384 \
    -subj "${INTERMEDIATE_SUBJECT}" \
    -out "./private/intermediate.csr" \
    || aivs_die "intermediate CSR generation failed"
chmod 0600 "./private/intermediate.csr"

aivs_step "Signing issuing CA with the root (${INTERMEDIATE_DAYS} days)"
openssl ca \
    -config "${CONFIG}" \
    -name CA_root \
    -extensions v3_intermediate_ca \
    -days "${INTERMEDIATE_DAYS}" \
    -md sha384 \
    -notext \
    -batch \
    -in "./private/intermediate.csr" \
    -out "./out/intermediate/intermediate.crt" \
    "${ROOT_PASSIN[@]+"${ROOT_PASSIN[@]}"}" \
    || aivs_die "signing the issuing CA failed"
aivs_publish "./out/intermediate/intermediate.crt"
aivs_ok "out/intermediate/intermediate.crt"

# -----------------------------------------------------------------------------
# Trust anchor and CRLs
# -----------------------------------------------------------------------------
aivs_step "Assembling the member trust anchor"
# Intermediate first, then root. Order is immaterial to OpenSSL's trust store
# parsing but conventional (leaf-most first), and some client stacks that
# consume this file as a chain rather than a store do care.
cat "./out/intermediate/intermediate.crt" "./out/root/root.crt" > "./out/ca-chain.pem"
aivs_publish "./out/ca-chain.pem"

# Independent verification. If the intermediate does not chain to the root --
# because a policy mismatch or a wrong -extensions silently produced something
# unusable -- fail here, not at 3am during a member's first handshake.
openssl verify -CAfile "./out/root/root.crt" "./out/intermediate/intermediate.crt" >/dev/null \
    || aivs_die "the issuing CA does not verify against the root"
aivs_ok "out/ca-chain.pem verified"

aivs_step "Generating initial (empty) CRLs"
openssl ca -config "${CONFIG}" -name CA_root -gencrl -md sha384 \
    -out "./out/crl/root.crl.pem" \
    "${ROOT_PASSIN[@]+"${ROOT_PASSIN[@]}"}" \
    || aivs_die "root CRL generation failed"
openssl ca -config "${CONFIG}" -name CA_intermediate -gencrl -md sha384 \
    -out "./out/crl/intermediate.crl.pem" \
    || aivs_die "issuing CA CRL generation failed"

# OpenSSL applies CRL_CHECK_ALL when nginx is given an ssl_crl file, so a
# usable CRL file must cover every CA in the chain. Concatenating them here
# means the operator who enables ssl_crl has a file that actually works.
cat "./out/crl/intermediate.crl.pem" "./out/crl/root.crl.pem" > "./out/crl/crl-chain.pem"
aivs_publish "./out/crl/root.crl.pem"
aivs_publish "./out/crl/intermediate.crl.pem"
aivs_publish "./out/crl/crl-chain.pem"
aivs_ok "out/crl/crl-chain.pem"

# -----------------------------------------------------------------------------
# Operator guidance
# -----------------------------------------------------------------------------
ROOT_FINGERPRINT="$(aivs_fingerprint_sha256 "./out/root/root.crt")"
INTERMEDIATE_FINGERPRINT="$(aivs_fingerprint_sha256 "./out/intermediate/intermediate.crt")"

cat <<EOF

${_AIVS_BOLD}AIVS certificate authority created.${_AIVS_RESET}

  Root CA          ${ROOT_CN}
    valid          ${ROOT_DAYS} days
    SHA-256        ${ROOT_FINGERPRINT}

  Issuing CA       ${INTERMEDIATE_CN}
    valid          ${INTERMEDIATE_DAYS} days
    SHA-256        ${INTERMEDIATE_FINGERPRINT}

  Trust anchor     deploy/ca/out/ca-chain.pem
                   (mounted read-only into the proxy as
                    /etc/nginx/ca/ca-chain.pem; also what each member
                    configures as its CA bundle)

${_AIVS_BOLD}${_AIVS_YELLOW}NEXT STEP -- TAKE THE ROOT KEY OFFLINE.${_AIVS_RESET}

  private/root/root.key is currently on a networked host. Until it is moved,
  this is a single-tier CA wearing a two-tier costume: an attacker who reaches
  this host gets the root, and recovery then means re-distributing a new trust
  anchor to every member.

    1. Copy the whole ./private/root directory (key, index.txt, serial,
       crlnumber, newcerts) to two encrypted removable volumes.
       The database files must travel with the key or you will not be able to
       revoke the intermediate later.

         tar -C '${SCRIPT_DIR}' -cf - private/root | \\
           age -p > /media/vault-a/aivs-root-ca.tar.age

    2. Store the volumes in separate locations under dual control, and put the
       root passphrase in the password vault -- not with the media.

    3. Verify a restore from at least one volume BEFORE deleting the original.

    4. Then remove the on-host copy:

         shred -u '${SCRIPT_DIR}/private/root/root.key'
         rm -rf '${SCRIPT_DIR}/private/root'

  Bring the media back only to sign a replacement issuing CA or a root CRL.
  Everything else -- member certificates, the proxy certificate, revocation --
  is done by the issuing CA and needs no root.

${_AIVS_BOLD}Then:${_AIVS_RESET}

    ./server-cert.sh --hostname aivs.your-isac.example
    ./issue-client.sh --org-slug example-bank --org "Example Bank NA"

EOF
