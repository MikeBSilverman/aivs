# Post-quantum readiness

Where every cryptographic use in AIVS stands against a quantum adversary, what
is already done, and what changes when. Written for the member firm's
third-party-risk reviewer as much as for us: "are you PQC ready?" is a question
that now arrives on every questionnaire, and the honest answer is a table, not
a yes.

---

## 1. Which threat matters, and which does not yet

**Harvest now, decrypt later** is the one that matters. Traffic recorded today
can be decrypted once a cryptographically relevant quantum computer exists, and
what AIVS carries — embargoed pre-CVE findings, sector sightings, which member
is exposed to what — keeps its value for years. Anything that *establishes a
key* for confidential content is therefore urgent now, even though no such
computer exists yet.

**Signatures are less urgent.** A forged signature cannot be applied to the
past: a certificate or a signed artefact is only at risk once a forger exists,
and fleets with short-lived certificates can switch before then. They still
have dates (section 3), and member TPRM will ask about them.

**Symmetric cryptography and hashes are already fine** at the sizes used here.
Grover's algorithm roughly halves the effective strength of a symmetric key, so
AES-256 keeps about 128 bits; SHA-256 used for fingerprints and MACs keeps a
comfortable margin for those uses, which depend on preimage resistance, not
collision resistance.

**The rule that makes every row below a migration and not a rewrite** is
CLAUDE.md §5's: every durable artefact names the algorithm that made it, and an
algorithm id once used is never reused. A ciphertext, an envelope or a
certificate that says what it is can be re-made under a new algorithm at
leisure; one that does not makes its first algorithm permanent.

---

## 2. Inventory

Status as of 2026-10-13. **Built** means in the code or the shipped
configuration; **designed** means a document and nothing more.

| Use | Today | Quantum-safe? | What happens next |
| --- | --- | --- | --- |
| **TLS key exchange at the proxy** (member listener) | **Built.** `ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1:prime256v1` in `deploy/nginx/nginx.conf`: hybrid X25519 + ML-KEM-768 (FIPS 203) offered first, classical curves after it for clients that cannot yet. `tests/unit/test_proxy_config.py` pins the order. Verified by hand against nginx 1.29 with OpenSSL 3.5 clients: a hybrid-capable client negotiates `X25519MLKEM768`, a classical one `X25519`. | **Yes, for TLS 1.3 clients that offer the hybrid group.** A TLS 1.2 client, or one whose stack predates hybrid groups, gets a classical curve and remains exposed to harvest-now. | An end-to-end test that asserts the negotiated group with an OpenSSL 3.5 client, in the e2e tier (planned). Drop TLS 1.2 when members' appliances allow; it stays today for legacy TIPs. Pin the proxy image by digest — the hybrid group depends on the image's OpenSSL being 3.5 or later, and a floating tag can change that. |
| **WireGuard overlay** (member reachability) | **Built** as configuration templates (`deploy/wireguard/`): Curve25519 key exchange plus a per-peer **preshared key**. | **Yes, with the preshared key.** Mixing a symmetric PSK into the handshake is WireGuard's own post-quantum hedge; a recording cannot be decrypted by breaking Curve25519 alone. The PSK must be generated per pair and exchanged out of band. | None beyond keeping the PSK mandatory in the templates. |
| **Secrets at rest** (`auth/secretbox.py`: TOTP seeds, webhook signing keys) | **Built.** AES-256-GCM by default, ChaCha20-Poly1305 selectable, 256-bit key from a `0600` file; every value carries format version, algorithm id and key fingerprint; `rewrap_secrets` moves values between keys or algorithms. | **Yes.** About 128-bit security against Grover. | None. Recorded so the question is answered. |
| **Fingerprints, MACs and token hashes** — SHA-256 certificate fingerprints, HMAC-SHA256 webhook signatures, SHA-256 session-token hashes, the keyed HMAC-SHA256 account reference in audit rows | **Built.** | **Yes, for these uses** (preimage and MAC, not collision-critical). | None. A stronger hash is available through the same named-algorithm design if a profile ever demands it. |
| **Passwords** (Argon2id) and **TOTP** (RFC 6238) | **Built.** | **Yes.** Neither depends on public-key cryptography. | None. |
| **Client certificates and the ISAC CA** (signatures) | **Built.** Two-tier private CA in `deploy/ca/`: EC P-384 with SHA-384 by default, RSA-4096 selectable; client certificates valid for at most 365 days. The CA pin is checked with `cryptography`'s generic `verify_directly_issued_by` (`auth/mtls.py`), not a branch per key type. | **No**, but not a harvest-now risk. | **Crypto-agile, not migrated.** Adding ML-DSA (FIPS 204) or composite certificates is a key-type case in the CA scripts and the pin check, not a rewrite; with a 365-day validity a fleet turns over within a year of switching. The switch waits until the TIPs and TLS stacks members run can verify ML-DSA chains — switching first would cut members off. |
| **Proxy to application** | Plain HTTP on the compose-internal network, guarded by a shared secret; a multi-host deployment must carry it over WireGuard or mutual TLS (`nginx.conf`). | Inherits whichever of those carries it. | None of its own. |
| **Outbound webhooks** (member endpoints) | **Built.** TLS from the application image's OpenSSL (Debian bookworm, `python:3.12-slim-bookworm`), which predates hybrid groups. | **No**, but the payload is contentless by design — a submission id and "poll to collect" — so a recording reveals that something was shared, not what. | Picks up hybrid key exchange when the base image's OpenSSL does; no design change needed. |
| **Log forwarding** (syslog over TLS, `docker-compose.log-forward.yml`) | **Built** as a compose override; TLS is performed by the Docker daemon's syslog driver. | **Depends on the host's TLS stack**, which this repository does not control. Logs carry identifiers and decisions, never content. | Document the collector requirement when the host stacks support hybrid groups. |
| **Content sealed to recipients (BYOK)** | **Designed, unbuilt; optional and deferred.** | **Designed to be.** The design was changed before anything was built from ECDH-ES on P-384 to a hybrid KEM — X25519 + ML-KEM-768, or P-384 + ML-KEM-1024 for a CNSA 2.0 profile — with the algorithm named per recipient in the envelope (`encryption-design.md` §4). Sealed payloads are exactly the harvest-now content; a classical-only wrap would have been obsolete on arrival. | Built only if an ISAC asks for it. |
| **Member sign-in tokens from the ISAC's IdP** (OIDC, RS256/ES256) | **Planned**, with member SSO. | No. | The IdP's to migrate. AIVS will accept any algorithm the IdP's JWKS advertises from an allow-list, so a move to ML-DSA is configuration on our side. |
| **Release and image signing** | Not yet chosen. | — | Prefer a scheme with a post-quantum path when it is chosen. |

### Not yet built, and planned

- **A cryptographic bill of materials (CBOM).** CycloneDX 1.6, which the SBOM
  already uses, can carry a `cryptographic-asset` inventory. The plan is to
  publish this table in that machine-readable form beside the SBOM, so a
  member's TPRM reviewer can read the posture without asking. Today it exists
  only as this document.
- **The negotiated-group end-to-end test** (first row).

---

## 3. Dates the questions will come from

These are the dates member TPRM teams quote. They come from documents that are
still moving — check the current version before relying on one in a
contract or an answer to a regulator.

| Source | What it says |
| --- | --- |
| **NIST IR 8547** (*Transition to Post-Quantum Cryptography Standards*, initial public draft, November 2024) | Quantum-vulnerable public-key algorithms — RSA, ECDSA, EdDSA, ECDH and finite-field DH — are **deprecated after 2030** at the 112-bit security level and **disallowed after 2035** at every level. |
| **FIPS 203, 204, 205** (August 2024) | ML-KEM for key establishment, ML-DSA and SLH-DSA for signatures. The algorithms AIVS uses or designs for come from these. |
| **NSA CNSA 2.0** | Sets the 2030s as the transition period for US national security systems, with web and cloud services expected to prefer CNSA 2.0 algorithms early and use them exclusively by the early 2030s. Relevant here because large US financial institutions align their own roadmaps to it. |
| **DORA** (EU, in force January 2025) | No algorithm dates of its own, but requires financial entities to keep cryptographic controls current against evolving threats, which their supervisors and auditors now read as including a quantum transition plan for their ICT third parties. |

What that means for AIVS: the key-establishment rows that matter for embargoed
content are done or designed hybrid already; the signature rows are agile and
wait for members' stacks; and nothing durable we write is tied to its first
algorithm.
