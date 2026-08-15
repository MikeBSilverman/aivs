#!/usr/bin/env bash
# =============================================================================
# Shared helpers for the AIVS CA scripts.
#
# Sourced, never executed. Every function here exists because the same mistake
# would otherwise be made four times in four slightly different ways.
#
# Input validation is the point of most of this file. Every value that reaches
# an openssl -subj argument, a filename or a subjectAltName is checked against
# an allowlist regex first. A '/' in an organisation name would inject an extra
# RDN into a subject; a '..' in an organisation slug would write a private key
# outside the CA directory; a ';' or '$(' anywhere would matter the moment
# somebody adds an eval or a shell pipeline to one of these scripts. Validating
# at the boundary means none of those become live questions later.
#
# Regexes are always held in a variable and matched with an UNQUOTED right-hand
# side. Writing the pattern inline forces backslash escaping that behaves
# differently inside a bracket expression than a reader expects, and quoting
# the variable would turn the pattern into a literal string comparison -- a
# validator that silently accepts everything.
# =============================================================================

# Deliberately no `set -euo pipefail` here: the sourcing script sets it, and
# changing the caller's shell options from an import is how a script ends up
# with behaviour nobody can find the source of.

# bash 4.3 for namerefs (local -n), used by aivs_passphrase_args.
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
    printf 'error: bash 4.3 or newer is required (found %s)\n' "${BASH_VERSION}" >&2
    exit 1
fi

# Colour is suppressed when stdout is not a terminal, so captured logs and CI
# output stay free of escape sequences.
if [[ -t 1 ]]; then
    _AIVS_BOLD=$'\033[1m'; _AIVS_RED=$'\033[31m'; _AIVS_YELLOW=$'\033[33m'
    _AIVS_GREEN=$'\033[32m'; _AIVS_RESET=$'\033[0m'
else
    _AIVS_BOLD=''; _AIVS_RED=''; _AIVS_YELLOW=''; _AIVS_GREEN=''; _AIVS_RESET=''
fi

aivs_log()  { printf '%s\n' "$*"; }
aivs_step() { printf '%s==>%s %s\n' "${_AIVS_BOLD}" "${_AIVS_RESET}" "$*"; }
aivs_ok()   { printf '%s  ok%s %s\n' "${_AIVS_GREEN}" "${_AIVS_RESET}" "$*"; }
aivs_warn() { printf '%swarning:%s %s\n' "${_AIVS_YELLOW}" "${_AIVS_RESET}" "$*" >&2; }

aivs_die() {
    printf '%serror:%s %s\n' "${_AIVS_RED}" "${_AIVS_RESET}" "$*" >&2
    exit 1
}

# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------

# OpenSSL 1.1.1 is the floor: `rand_serial` in the [ca] section arrived there,
# and 1.0.2 has been out of support since 2019. Refusing to run on an older
# release is better than silently issuing certificates with sequential serials.
aivs_require_openssl() {
    command -v openssl >/dev/null 2>&1 || aivs_die "openssl not found on PATH"

    local version
    version="$(openssl version)" || aivs_die "could not run 'openssl version'"

    case "${version}" in
        OpenSSL\ 0.*|OpenSSL\ 1.0.*)
            aivs_die "OpenSSL 1.1.1 or newer is required (found: ${version})"
            ;;
        LibreSSL*)
            # LibreSSL's `openssl ca` diverges from OpenSSL's on rand_serial
            # and on CRL generation. Certificates it produced would not match
            # what this configuration describes.
            aivs_die "LibreSSL is not supported; install OpenSSL (found: ${version})"
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Input validation
# -----------------------------------------------------------------------------

# Organisation slug: the AIVS identifier for a member, and also a path
# component under out/clients/. Lowercase DNS-label syntax, which excludes '.',
# '/', '..' and every shell metacharacter by construction.
aivs_validate_slug() {
    local slug="$1"
    local pattern='^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
    [[ -n "${slug}" ]] || aivs_die "organisation slug must not be empty"
    (( ${#slug} <= 63 )) || aivs_die "organisation slug must be 63 characters or fewer"
    [[ "${slug}" =~ $pattern ]] \
        || aivs_die "invalid organisation slug '${slug}': lowercase letters, digits and internal dashes only"
}

# A DNS hostname (optionally a single leading wildcard label) for a server
# certificate's subjectAltName.
aivs_validate_hostname() {
    local host="$1"
    local label='[a-z0-9]([a-z0-9-]*[a-z0-9])?'
    local pattern="^([*][.])?${label}([.]${label})*$"
    [[ -n "${host}" ]] || aivs_die "hostname must not be empty"
    (( ${#host} <= 253 )) || aivs_die "hostname must be 253 characters or fewer"
    [[ "${host}" =~ $pattern ]] \
        || aivs_die "invalid hostname '${host}': lowercase DNS labels only, e.g. aivs.isac.example"
}

# A literal IPv4 or IPv6 address for an IP subjectAltName. IPv4 octet ranges are
# checked numerically rather than by regex, because '999.1.1.1' matches every
# regex people write for this and openssl would then emit a nonsense SAN.
aivs_validate_ip() {
    local addr="$1"
    local ipv4='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'
    local ipv6='^[0-9A-Fa-f:]+$'

    if [[ "${addr}" =~ $ipv4 ]]; then
        local octet
        for octet in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" \
                     "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
            (( 10#${octet} <= 255 )) || aivs_die "invalid IPv4 address '${addr}'"
        done
        return 0
    fi

    # IPv6: character-set check here, full validation by openssl when it builds
    # the extension -- an ill-formed value makes `openssl ca` fail rather than
    # produce a certificate with a wrong SAN.
    if [[ "${addr}" =~ $ipv6 && "${addr}" == *:* ]]; then
        return 0
    fi

    aivs_die "invalid IP address '${addr}'"
}

# Free-text X.509 name component (O, OU, CN, L, ST).
#
# The banned characters are the ones that change the *structure* of what we hand
# to openssl rather than merely its contents: '/' starts a new RDN in a -subj
# string, '+' introduces a multi-valued RDN, ',' and '=' are RFC 4514
# separators that would make the resulting DN ambiguous when the application
# renders it back, and control characters (newline included) can split or
# truncate an argument.
aivs_validate_name_component() {
    local label="$1" value="$2"
    local apostrophe=$'\x27'
    local pattern="^[A-Za-z0-9][A-Za-z0-9 ._&()${apostrophe}-]*$"
    [[ -n "${value}" ]] || aivs_die "${label} must not be empty"
    (( ${#value} <= 64 )) || aivs_die "${label} must be 64 characters or fewer (X.520 ub-common-name)"
    [[ "${value}" =~ $pattern ]] \
        || aivs_die "invalid ${label} '${value}': letters, digits, spaces and . _ & ( ) ' - only"
}

# ISO 3166-1 alpha-2 country code.
aivs_validate_country() {
    local country="$1"
    local pattern='^[A-Z][A-Z]$'
    [[ "${country}" =~ $pattern ]] \
        || aivs_die "invalid country '${country}': two uppercase letters, e.g. US or GB"
}

aivs_validate_days() {
    local label="$1" days="$2"
    local pattern='^[0-9]+$'
    [[ "${days}" =~ $pattern ]] || aivs_die "${label} must be a positive integer"
    (( 10#${days} >= 1 && 10#${days} <= 7500 )) \
        || aivs_die "${label} must be between 1 and 7500 days"
}

aivs_validate_key_alg() {
    case "$1" in
        ec|rsa) : ;;
        *) aivs_die "unknown key algorithm '$1': use 'ec' (P-384) or 'rsa' (4096-bit)" ;;
    esac
}

# -----------------------------------------------------------------------------
# Key generation
#
# ECDSA P-384 is the default.
#
#   * It is on the NSA CNSA 1.0 suite and NIST SP 800-131A's "acceptable"
#     list well past 2030, at a ~192-bit security level -- a step above the
#     ~128 bits that RSA-3072 or P-256 give, which matters for a root that must
#     stay trustworthy for twenty years.
#   * ECDSA signing and verification are roughly an order of magnitude cheaper
#     than RSA-4096, and a TLS handshake performs several. With every member
#     poller reconnecting on a schedule, that is the difference between the
#     proxy's CPU being noticeable and not.
#   * P-384 with SHA-384 is universally supported by everything in scope:
#     OpenSSL 1.1.1+, Python `cryptography`, Java 11+, Go, .NET, and every
#     network appliance that speaks TLS 1.2 with ECDHE.
#
# RSA-4096 remains selectable with --key-alg rsa for members whose HSM or
# smartcard cannot hold an EC key. Mixing the two is fine: the algorithm of a
# member's key is independent of the CA's.
# -----------------------------------------------------------------------------
aivs_generate_key() {
    # $1: algorithm (ec|rsa); $2: output path; $3+: extra openssl args
    # (for example -aes-256-cbc plus -passout, to encrypt at rest).
    local alg="$1" path="$2"
    shift 2

    aivs_refuse_overwrite "${path}"

    case "${alg}" in
        ec)
            openssl genpkey -algorithm EC \
                -pkeyopt ec_paramgen_curve:P-384 \
                -pkeyopt ec_param_enc:named_curve \
                -out "${path}" "$@" \
                || aivs_die "key generation failed for ${path}"
            ;;
        rsa)
            openssl genpkey -algorithm RSA \
                -pkeyopt rsa_keygen_bits:4096 \
                -out "${path}" "$@" \
                || aivs_die "key generation failed for ${path}"
            ;;
        *)
            aivs_die "unknown key algorithm '${alg}'"
            ;;
    esac

    aivs_protect_key "${path}"
}

# -----------------------------------------------------------------------------
# Filesystem safety
# -----------------------------------------------------------------------------

# Never silently replace key material. Overwriting a private key destroys the
# ability to revoke anything issued under it and, for the intermediate,
# instantly invalidates every member certificate. Recovery is manual and
# deliberate: move the old file aside yourself.
aivs_refuse_overwrite() {
    local path="$1"
    if [[ -e "${path}" ]]; then
        aivs_die "refusing to overwrite existing file: ${path}
       Move it aside yourself if you genuinely intend to replace it. Replacing
       a CA key invalidates everything issued under it and cannot be undone."
    fi
}

# Private material: owner-read-only, inside an owner-only directory.
aivs_protect_key() {
    local path="$1"
    chmod 0600 "${path}" || aivs_die "could not chmod 0600 ${path}"
}

# Public material: world-readable, because the nginx container runs as an
# unprivileged uid that is not the operator's and must be able to read the
# trust anchor and the server certificate through the bind mount.
aivs_publish() {
    local path="$1"
    chmod 0644 "${path}" || aivs_die "could not chmod 0644 ${path}"
}

aivs_publish_dir() {
    local path="$1"
    mkdir -p "${path}" || aivs_die "could not create ${path}"
    chmod 0755 "${path}" || aivs_die "could not chmod 0755 ${path}"
}

aivs_private_dir() {
    local path="$1"
    mkdir -p "${path}" || aivs_die "could not create ${path}"
    chmod 0700 "${path}" || aivs_die "could not chmod 0700 ${path}"
}

# -----------------------------------------------------------------------------
# Passphrase handling
#
# Passphrases reach openssl as `file:<path>`, never as `pass:<value>` and never
# through an environment variable: an argv-borne secret is readable in /proc by
# every user on the host for the lifetime of the process, and an environment
# variable is inherited by every child and captured in crash dumps.
#
# With no file given, openssl prompts on the terminal and the passphrase never
# enters this script's memory at all. That is the default for the root key.
# -----------------------------------------------------------------------------
#
# The direction argument spells the option name: "in" gives -passin (reading an
# existing encrypted key), "out" gives -passout, and "" gives plain -pass,
# which is what `openssl genpkey` wants -- it rejects -passout outright.
aivs_passphrase_args() {
    # $1: name of the array to populate; $2: "in", "out" or ""; $3: file or "".
    local -n _args="$1"
    local direction="$2" file="$3"
    _args=()
    [[ -n "${file}" ]] || return 0
    [[ -f "${file}" ]] || aivs_die "passphrase file not found: ${file}"
    [[ -r "${file}" ]] || aivs_die "passphrase file not readable: ${file}"
    _args=( "-pass${direction}" "file:${file}" )
}

# -----------------------------------------------------------------------------
# Fingerprints
#
# THE SHA-256 FINGERPRINT IS THE IDENTITY. AIVS stores it against an
# organisation and every authorisation decision starts from it. The application
# computes it itself from the certificate the proxy forwards -- in
# aivs_server.auth.mtls, `certificate.fingerprint(hashes.SHA256()).hex()` --
# which yields lowercase hex with no separators. That is exactly the form
# printed here, so an operator can paste it straight into AIVS enrolment.
#
# Note what is NOT used: openssl's default -fingerprint is SHA-1, and nginx's
# $ssl_client_fingerprint is SHA-1. Neither is ever the value to register.
# -----------------------------------------------------------------------------
aivs_fingerprint_sha256() {
    local cert="$1"
    openssl x509 -in "${cert}" -noout -fingerprint -sha256 \
        | sed -e 's/^.*=//' -e 's/://g' \
        | tr '[:upper:]' '[:lower:]'
}
