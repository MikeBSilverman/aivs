# AIVS deployment topology

AIVS is "ISAC-in-a-box": one instance serves one ISAC and its members.
**Single-tenant per instance.** There is no multi-tenant mode, and adding one is
not on the roadmap — the isolation guarantee an ISAC needs is a separate
database, a separate CA, and a separate host, not a tenant column.

**Many ISACs means federation between instances, never a tenant column.** The
product is meant to serve several ISACs, and nothing here may design that out;
but the way it serves them is one instance each, exchanging what their
agreements allow over interfaces both sides control — TAXII between instances,
say, or private set intersection for "is another ISAC seeing this?"
(`open-decisions.md`). A shared database
would make one ISAC's isolation depend on every query being right about every
other ISAC, which is the guarantee an ISAC is buying. Nothing for federation is
built, and there is deliberately no `instance_id` setting until something reads
one.

Two hosting modes exist. They differ in who holds the keys and who carries the
pager, not in the software.

---

## 1. Hosting modes

| | **Self-hosted** | **Aequora-managed** |
| --- | --- | --- |
| Who runs the instance | The ISAC's own infrastructure team | Aequora, as a dedicated single-tenant deployment |
| Where it runs | ISAC's cloud account or data centre | Aequora-operated, in a region the ISAC nominates |
| Who holds the CA root | The ISAC, offline | The ISAC, offline — **root stays with the ISAC in both modes** |
| Who holds the issuing CA key | The ISAC | Aequora, under a delegated issuing CA the ISAC signs |
| Who holds database credentials | The ISAC | Aequora |
| Who can read `stix_objects.raw` | The ISAC's operators | Aequora's operators **and** the ISAC's |
| Who validates and distributes submissions | ISAC staff | **ISAC staff.** Aequora does not exercise editorial control. |
| Upgrades, backups, monitoring | The ISAC | Aequora |
| Source | Apache-2.0, identical | Apache-2.0, identical |

The critical line is the last-but-two. Managed hosting is an operations service.
The `isac_editor` accounts that move submissions from `submitted` → `validated`
→ `distributed` belong to the ISAC, and the move requires a human session -- an
admin-organisation certificate on its own, which the holder of the issuing CA
could mint, confers no editorial power, because that transition is the ISAC's
editorial and legal judgement about whether content should reach members. An
Aequora operator holding database access is a real trust exposure and should be
named as such in the hosting agreement — it is not eliminated by process, only
bounded by it (see [`threat-model.md`](threat-model.md), insider section).

An ISAC that cannot accept a third party holding database access should
self-host. The software is the same either way; that is the point of the
licence.

---

## 2. Network layers

Three independent layers, each of which must pass. None of them is a substitute
for another.

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │  MEMBER FIRM                                                           │
 │                                                                        │
 │   TAXII client / TIP / aivs CLI                                        │
 │     • client cert + private key (never leaves the firm)                │
 │     • WireGuard peer key                                               │
 └──────────────────────────────┬─────────────────────────────────────────┘
                                │
              ══════════════════╪══════════════════   LAYER 1
              WireGuard (UDP 51820)   ── or ──   strict IP allowlist
              Noise handshake; unauthenticated       source-address filter
              packets are silently dropped           at the edge firewall
                                │
 ┌──────────────────────────────▼─────────────────────────────────────────┐
 │  AIVS HOST / VPC                                                       │
 │                                                                        │
 │   ┌─────────────────────────────────────────────────────────────────┐  │
 │   │  nginx    host 443 → container 8443 (unprivileged image, uid 101)│ │
 │   │                                                    LAYER 2      │  │
 │   │   ssl_verify_client on   ← chain must validate to the AIVS CA   │  │
 │   │   ssl_verify_depth 2     ← leaf + intermediate, no deeper       │  │
 │   │   ssl_protocols TLSv1.2 TLSv1.3   (1.2 only for legacy appliances)│ │
 │   │   ssl_session_tickets off; AEAD-only 1.2 suites                 │  │
 │   │   limit_req/limit_conn keyed on $ssl_client_fingerprint → 429   │  │
 │   │   client_max_body_size 5m  (matches AIVS_MAX_BODY_BYTES)        │  │
 │   │                                                                 │  │
 │   │   snippets/aivs-identity-headers.conf — the ONE place identity  │  │
 │   │   headers are set, included by every proxying location:         │  │
 │   │     X-Client-Verify → $ssl_client_verify                        │  │
 │   │     X-Client-Cert   → $ssl_client_escaped_cert                  │  │
 │   │     X-Proxy-Auth    → $proxy_shared_secret (rendered to tmpfs)  │  │
 │   │     X-Request-Id    → $request_id  (nginx's, never the client's)│  │
 │   │   ── all set unconditionally; a client-supplied value dies here │  │
 │   └────────────────────────────┬────────────────────────────────────┘  │
 │                                │  internal `backend` bridge only       │
 │   ┌────────────────────────────▼────────────────────────────────────┐  │
 │   │  aivs-server (uvicorn, :8000)  NO PUBLISHED HOST PORT  LAYER 3  │  │
 │   │                                                                 │  │
 │   │   1. peer IP ∈ AIVS_TRUSTED_PROXY_CIDRS                         │  │
 │   │   2. X-Proxy-Auth == AIVS_PROXY_SHARED_SECRET (constant-time)   │  │
 │   │   3. X-Client-Verify == "SUCCESS"                               │  │
 │   │   4. re-parse the PEM; compute SHA-256 itself                   │  │
 │   │   5. re-check the validity window (±5 min skew)                 │  │
 │   │   6. fingerprint → client_certificates → organization           │  │
 │   │   7. auth.policy — deny by default                              │  │
 │   └────────────────────────────┬────────────────────────────────────┘  │
 │                                │                                       │
 │   ┌────────────────────────────▼────────────────────────────────────┐  │
 │   │  PostgreSQL 16+   internal network only, non-superuser app role │  │
 │   │    pgcrypto (gen_random_uuid), append-only triggers             │  │
 │   └─────────────────────────────────────────────────────────────────┘  │
 │                                                                        │
 │   outbound only ──► member-registered HTTPS webhook endpoints          │
 └────────────────────────────────────────────────────────────────────────┘
```

### Layer 1 — reachability

**WireGuard overlay (recommended).** Each member firm is a peer with its own
static public key. WireGuard does not respond to unauthenticated packets at all,
so the service is invisible to scanning: an attacker who does not hold a peer key
cannot establish that anything is listening. Peer keys are per-member, which also
means removing a member is a config change at the overlay as well as a status
flip in the database.

**Strict IP allowlist (fallback).** For members whose network policy forbids an
additional VPN. The edge firewall — and `deploy/nginx/allowlist.conf`, applied by
`ngx_http_access_module` at the listener — permits TCP 443 only from named member
egress ranges. This resists scanning; it does not resist an attacker with a
foothold at a member's egress, and it does not hide the service from allowlisted
networks. **Prefer WireGuard.** If an ISAC runs allowlist mode, record the
decision and its residual risk explicitly — R9 in the threat model.

`deploy/nginx/allowlist.conf.example` states the point plainly and it is worth
repeating: the allowlist is defence in depth, not the access control. What it
genuinely buys is a smaller attack surface for everything that happens *before*
certificate verification — the TLS stack, nginx's HTTP parsing, the
connection-flood limits — all of which are reachable pre-authentication by
anyone who can open a socket. A fresh checkout ships a permissive example file
so the stack starts; **a production deployment must replace it.**

Mixing modes per member is supported and common in practice.

Layer 1 grants **no application privilege whatsoever**. Reaching nginx is the
beginning of authentication, not the end of it.

### Layer 2 — nginx, mTLS termination

nginx is the only component permitted to reach the application. Its
configuration is `deploy/nginx/nginx.conf`, with the identity injection isolated
into `deploy/nginx/snippets/aivs-identity-headers.conf`. It:

- terminates TLS (1.3, with 1.2 retained only for member security appliances
  that cannot yet do 1.3) and requires a client certificate that chains to the
  AIVS issuing CA (`ssl_verify_client on`, `ssl_verify_depth 2`);
- **unconditionally sets** `X-Client-Verify`, `X-Client-Cert`, `X-Proxy-Auth`,
  and `X-Request-Id` on every proxied request, so a client-supplied header of the
  same name is overwritten and never reaches the application;
- **blanks a long list of alternative spellings** — `X-SSL-Client-Cert`,
  `X-Forwarded-Client-Cert`, `X-Org-Id`, `X-Original-URL`,
  `X-HTTP-Method-Override`, and others — so that if a future middleware, WAF, or
  sidecar ever learns to read one, it cannot be handed a client-supplied value;
- replaces rather than appends `X-Forwarded-For`, because the proxy is the edge
  and the only address that is a fact is the peer it is talking to;
- forwards the full URL-escaped PEM (`$ssl_client_escaped_cert`), not a summary.

The last point is deliberate and worth understanding before someone "optimises"
it. nginx's `$ssl_client_fingerprint` is **SHA-1**. AIVS will not key identity on
SHA-1, so the proxy hands over the certificate and the application computes the
SHA-256 itself. That costs a few hundred microseconds per request and removes the
proxy from the set of components that must be correct for identity to be sound.

Note the one place SHA-1 *is* used: `limit_req_zone` and `limit_conn_zone` are
keyed on `$ssl_client_fingerprint`. That is fine — bucketing is not
authentication, and the worst a collision does is make two members share a
quota. Keying on the source address instead would collapse every member behind
one NAT into a single bucket.

Rate limits: 20 r/s with a burst of 40 per certificate, 64 connections per source
address, answered with **429** rather than nginx's default 503 — a throttled
member should see "slow down", not "the service is broken". A TAXII collection
poller runs at roughly 1 r/s, so this leaves two orders of magnitude of headroom.

**What address nginx records, and therefore the audit log.** Measured with
Docker Engine 29 against the shipped compose file (T5, 2026-10-14). A member
connecting from another host arrives through Docker's NAT with its own source
address preserved: nginx's `remote_addr`, the `X-Real-IP` it sets, and the
audit row's `source_ip` are the member's address. A client on the Docker host
itself -- loopback, or another container dialling the host's address -- is
relayed by `docker-proxy` and appears as a bridge gateway (172.29.10.1). So the
per-address connection limit and the `auth_failure_burst` detection see real
member addresses in production, and only a local client shares one.

The published port is delivered to the proxy's **`backend`** address, not its
`frontend` one: Docker publishes through whichever network it picks as the
container's gateway, and nothing in the compose file chooses. That changes
nothing for an external member's address (above). Docker Engine 28+ with
Compose 2.33+ can choose it explicitly (`gw_priority: 1` on the proxy's
`frontend` attachment, verified to move ingress and the proxy's default route
to `frontend`); it is not set because it would raise the supported floor from
Engine 24 for a change no member-facing property depends on.

`X-Request-Id` is nginx's own `$request_id`, never the client's. Accepting a
caller-chosen correlation id would let a member forge audit-trail entries or
deliberately collide with another member's requests.

Two things nginx deliberately does **not** do:

- **OCSP stapling is off.** The AIVS CA is private and runs no OCSP responder.
  Enabling it would produce start-up warnings and a failing per-request DNS
  lookup.
- **`ssl_crl` is present but commented out.** OpenSSL applies
  `X509_V_FLAG_CRL_CHECK_ALL` once `ssl_crl` is set, which means an expired CRL
  for any CA in the chain rejects every client. Revocation in AIVS is enforced by
  the application against its own database, which is authoritative and cannot
  expire. See §3.5.

### Layer 3 — application authorization

Every step listed in the diagram is implemented in
`aivs_server/auth/mtls.py` and `aivs_server/auth/policy.py`. Two properties
matter operationally:

- **The application publishes no host port.** The compose file declares no port
  mapping for the app service. If you can reach the app directly, the deployment
  is wrong.
- **The application refuses to start in production with a dev bypass enabled.**
  `Settings.validate_production_posture()` rejects
  `dev_trust_unauthenticated_proxy`, `dev_expose_error_detail`,
  `dev_allow_private_webhook_targets`, an empty `trusted_proxy_cidrs`, a
  non-HTTPS `public_base_url`, and `log_level=DEBUG`. `AIVS_ENVIRONMENT` defaults
  to `production`, so forgetting it fails safe.

---

## 3. PKI

AIVS runs its own certificate authority. Public CAs are not usable here: the
question is not "does this host control this domain" but "is this organization
enrolled in this ISAC's sharing programme", and only the ISAC can answer it.

### Hierarchy

Created once per instance by `deploy/ca/init-ca.sh`, before anything else in
`deploy/`.

```
        ┌──────────────────────────────────────────┐
        │  AIVS Root CA        20 years (7300 d)   │
        │    EC by default; RSA available          │
        │    private/root/root.key — encrypted     │
        │    OFFLINE — see §3.2                    │
        └───────────────────┬──────────────────────┘
                            │ signs, once
        ┌───────────────────▼──────────────────────┐
        │  AIVS Issuing CA     10 years (3650 d)   │
        │    private/intermediate.key, 0600        │
        │    used unattended on the AIVS host      │
        └───────────────────┬──────────────────────┘
                            │ signs
      ┌─────────────────────┼─────────────────────┐
      ▼                     ▼                     ▼
 member firm A         member firm B          ISAC operators
 client certs          client certs           client certs
 365 days              365 days               365 days

  out/ca-chain.pem  =  intermediate + root  →  the member trust anchor
```

Two levels, not one, and `init-ca.sh` states the reasoning: the issuing key must
be readable by an unattended process on a host that also runs a public-facing
service, so **assume it can be stolen**. Recovering from that with a single-tier
CA means distributing a new trust anchor to every member out of band — a
multi-week outage of the sharing programme. With two tiers, recovery is: revoke
the intermediate, issue a new one from the offline root, re-issue member
certificates. Members' trust anchors never change.

The root's only jobs are to sign that one intermediate and to sign root CRLs.

Note the validity ladder — 20 / 10 / 1 years. An intermediate that expires before
the certificates under it is a classic and entirely avoidable outage, and the
decade of headroom is there to prevent it.

### CA layout

```
deploy/ca/
  init-ca.sh          create the two-tier CA (run once)
  issue-client.sh     issue a member certificate from a CSR (or generate both)
  server-cert.sh      issue the nginx server certificate
  revoke.sh           revoke, and regenerate CRLs
  openssl.cnf         relative-path config; scripts run from this directory
  _lib.sh             shared helpers
  private/root/root.key           OFFLINE — must not remain here (§3.2)
  private/intermediate.key        0600, used unattended
  out/root/root.crt
  out/intermediate/intermediate.crt
  out/ca-chain.pem                what members install as their trust anchor
  out/crl/{root,intermediate,crl-chain}.crl.pem
```

The scripts run with `umask 077`, so keys and the CA database are owner-only from
the instant they exist rather than briefly world-readable.

### 3.1 Where the CA lives

| Mode | Root CA private key | Issuing CA private key |
| --- | --- | --- |
| Self-hosted | ISAC, offline (§3.2) | ISAC — HSM, cloud KMS, or an encrypted key on the AIVS host with a passphrase not stored beside it |
| Aequora-managed | **ISAC, offline** — Aequora never holds the root | Aequora, in a cloud KMS or HSM, under an issuing CA the ISAC's root signed |

In managed mode the ISAC signs a delegated issuing CA for Aequora and retains the
root. That gives the ISAC an exit: revoke the issuing CA, stand up a new one, and
the trust anchor never moved. Design the arrangement so that leaving the managed
service is a certificate operation, not a migration.

Whatever is in `deploy/ca/` on a running host is, by definition, online. The root
key must not be one of those things: `init-ca.sh` writes
`private/root/root.key` there, and moving it to offline media is a step you
perform, not one the script performs for you.

### 3.2 Offline root guidance

"Offline" means the root private key has never existed on a network-connected
machine. Not "on a server with the firewall closed".

1. Run `init-ca.sh` on an air-gapped machine — a live-USB boot with no
   networking is sufficient and cheap. The root key is encrypted with a
   passphrase by default; leave it that way.
2. Carry only `private/intermediate.key`, `out/`, and the CA database to the
   AIVS host. Leave `private/root/root.key` behind.
3. Store the root private key on encrypted removable media, in a safe, with the
   passphrase held separately. Two copies in two locations; media degrades. Its
   only remaining jobs are re-issuing the intermediate (roughly once a decade),
   revoking it in an emergency, and refreshing the root CRL
   (`revoke.sh --gencrl-only --root-crl`, within `default_crl_days` = 180).
4. Optionally split the passphrase (Shamir, 3-of-5) across named ISAC staff. Do
   this only if the ISAC will actually rehearse reassembly — an unrehearsed
   split is a way to lose the key, not protect it.
5. Record the root fingerprint in the ISAC's own governance documentation, so
   members can verify the trust anchor out of band when they enrol.
6. **Rehearse the recovery annually.** An offline root nobody has touched in
   three years, whose passphrase holder has left, is functionally a lost root.

### 3.3 Certificate profile

Member client certificates, issued by `deploy/ca/issue-client.sh`:

| Field | Value |
| --- | --- |
| Key | EC by default; RSA available |
| Validity | 365 days |
| `CN` | `<org-slug>-<label>`, e.g. `meridian-global-taxii-prod` |
| `O` | The member firm's legal name |
| Extended key usage | `clientAuth` **only** — never `serverAuth` |
| Basic constraints | `CA:FALSE` |

One year is a deliberate forcing function: a certificate lifetime long enough
that nobody builds a rotation process is a certificate lifetime that guarantees
an outage.

`issue-client.sh` has two modes, and the preferred one matters:

```bash
# PREFERRED — the member generated the key and sent a CSR.
./issue-client.sh --org-slug meridian-global --csr /tmp/meridian-global.csr

# FALLBACK — only when the member genuinely cannot produce a CSR.
./issue-client.sh --org-slug meridian-global --org "Meridian Global Bank"
```

In the preferred mode the private key never exists outside the member's control,
so a breach of the AIVS host cannot impersonate them and there is no key to
transport. In the fallback mode you must hand the key over an out-of-band
encrypted channel and delete your copy — **a key that has been emailed is a key
that must be re-issued.**

The script's meaningful output is the **SHA-256 fingerprint**. That, not the DN
and not the serial, is what AIVS stores against an organization and what every
authorization decision starts from. Nothing works until it is registered.

**The subject DN is not the identity.** AIVS keys identity on the SHA-256
fingerprint stored in `client_certificates.fingerprint_sha256` (unique,
lowercase-hex, database-check-constrained). The DN is stored for human
recognition. Two consequences: a member may re-use a DN across rotations without
ambiguity, and changing a DN does not change who a certificate authenticates as.

Multiple concurrent certificates per organization are normal and expected — one
per system (`label` distinguishes them: `taxii-prod`, `submit-batch`,
`soc-analyst-laptop`). This is what makes rotation and per-system revocation
possible without an outage.

### 3.4 Rotation

Rotation overlaps; it does not cut over. Both certificates are valid
simultaneously because both have `status = active` rows.

```
day 0    member generates a new key + CSR locally
day 0    ISAC signs it and registers the fingerprint  → 2 active certs
day 0-14 member moves each client to the new cert at its own pace
day 14   member confirms the old cert is unused (ISAC checks last_seen_at)
day 14   ISAC revokes the old cert                     → 1 active cert
```

`client_certificates.last_seen_at` is what makes step 4 verifiable rather than
hopeful. Do not revoke an old certificate whose `last_seen_at` is within the last
few days without asking the member what is still using it.

Start rotation at **60 days before expiry**. The operator runbook has a monthly
expiry-review task for this reason.

### 3.5 Revocation

**What actually stops access is a database status flip, not the CRL.**

```
client_certificates.status:         active → revoked
client_certificates.revoked_at:     set (enforced by check constraint)
client_certificates.revoked_reason: recorded
```

A check constraint keeps these consistent: `status = 'active'` requires
`revoked_at IS NULL`, and `status = 'revoked'` requires it non-null. The status
is checked **on every request** against an indexed unique constraint, so
revocation is effective on the next request with no propagation delay, no CRL
distribution point to publish, and no OCSP responder to keep available.

`deploy/ca/revoke.sh` additionally records the revocation in the CA database and
regenerates `out/crl/`:

```bash
./revoke.sh --org-slug meridian-global --reason keyCompromise
./revoke.sh --gencrl-only            # scheduled refresh, revoking nothing
```

That CRL is belt and braces, and it matters for anything **outside** AIVS that
consumes these certificates. nginx's `ssl_crl` line ships commented out on
purpose: OpenSSL applies `X509_V_FLAG_CRL_CHECK_ALL` once it is set, so an
expired CRL for any CA in the chain rejects every client. If you do enable it,
you have taken on an availability obligation — run `revoke.sh --gencrl-only` on a
schedule well inside `default_crl_days` (30 days for the issuing CA, 180 for the
root, `--root-crl` for the latter, which needs the offline root key).

Note the division of labour: nginx validates the *chain*, and the application
enforces *revocation*. A revoked certificate still passes nginx and is rejected
by the application — which is correct, because the rejection is then auditable,
whereas a TLS-layer rejection is a connection reset with no application record.

Revoke immediately on: suspected key compromise, decommissioning of the system
holding the key, departure of staff with key access, or termination of the
membership. Revoking a certificate does **not** suspend the organization — for
that, set `organizations.status = suspended`, which `is_active(ctx)` checks first
in every authorization predicate.

---

## 4. What the ISAC must provide

### Infrastructure

| Item | Requirement |
| --- | --- |
| Host | 4 vCPU, 8 GB RAM, 100 GB SSD is comfortable for hundreds of members and years of content. The workload is not compute-bound. |
| PostgreSQL | 16 or later, with `pgcrypto` available (`gen_random_uuid()` is a server default on most tables). |
| TLS certificate | A server certificate for the AIVS hostname. `deploy/ca/server-cert.sh` issues one from the AIVS CA; a public CA certificate is also fine, since this authenticates the server to members. |
| DNS | A hostname resolvable on the overlay. |
| Storage encryption | **Volume or disk encryption is required.** `stix_objects.raw` holds embargoed content in plaintext at the application layer. |
| Backup target | Off-host, encrypted, with tested restores. |
| Outbound HTTPS | For webhook delivery to member endpoints. |
| Time sync | NTP. Embargo timing and certificate validity both depend on it; the mTLS validity re-check tolerates ±5 minutes of skew and nothing more. |

### PKI and secrets

- Root CA generated and stored offline (§3.2).
- Issuing CA in an HSM or KMS.
- `AIVS_PROXY_SHARED_SECRET` — ≥ 32 characters, validated at startup.
- `AIVS_SESSION_SECRET` — ≥ 32 characters, validated at startup.
- The key-encryption key, as a **file** (`AIVS_SECRET_ENCRYPTION_KEY_FILE`; under
  compose, `AIVS_SECRET_ENCRYPTION_KEY_PATH` on the host) — base64, of the length
  the configured algorithm takes (32 bytes for either current option), mode
  `0600` or stricter, validated at startup. Outside dev the environment form is
  refused, because `docker inspect` and `/proc/<pid>/environ` show it. On
  Kubernetes or Swarm, set the secret mount's mode to `0400` (`defaultMode`,
  `mode`): their defaults are group- or world-readable and are refused.
  Encrypts operator TOTP seeds and members' webhook signing keys.
  **Back it up separately from the database.** Held together, they are one
  artefact with no encryption at rest; lost entirely, every operator re-enrols
  their second factor and every member re-registers their webhook.
- Database credentials for a **non-superuser role that does not own
  `audit_log` or `submission_transitions`**. Set `AIVS_APP_DB_ROLE` to that role
  name when running the append-only migration so it receives `INSERT, SELECT`
  and nothing more.

### People and process

- At least two operators holding `isac_editor`. One is a single point of failure;
  more than about five dilutes accountability for a role that can distribute
  embargoed content. `isac_membership` and `system_admin` can be held by the same
  people or kept apart, which is the ISAC's choice (`docs/authz-model.md` §3).
- A named submission reviewer with the standing to reject a submission on scope
  grounds. This is the human checkpoint that keeps AIVS out of third-party
  disclosure brokering, and it only works if the reviewer can say no.
- A membership agreement executed with each firm before enrolment — see
  [`sharing-agreement-outline.md`](sharing-agreement-outline.md).
- A documented incident process, including "we distributed something we should
  not have".

### Configuration

Minimum production environment:

```bash
AIVS_ENVIRONMENT=production            # anything but `dev` gets the strict posture
AIVS_INSTANCE_NAME="Example Financial ISAC"
AIVS_PUBLIC_BASE_URL=https://aivs.example.org
AIVS_DATABASE_URL=postgresql+psycopg://aivs_app:...@db:5432/aivs
AIVS_PROXY_SHARED_SECRET=<32+ chars>
AIVS_SESSION_SECRET=<32+ chars>
AIVS_SECRET_ENCRYPTION_KEY_FILE=/run/aivs/secret-encryption-key   # 0600, never the env form
AIVS_ISSUING_CA_CERTIFICATE_FILE=/etc/aivs/issuing-ca.pem          # required outside dev
# AIVS_SECRET_ENCRYPTION_ALGORITHM=aes-256-gcm   # or chacha20-poly1305
AIVS_TRUSTED_PROXY_CIDRS=["10.20.0.2/32"]   # the nginx container address
AIVS_LOG_LEVEL=INFO
```

`AIVS_TRUSTED_PROXY_CIDRS` must be as narrow as the deployment allows — ideally a
`/32`. It is the peer-address half of the B3 boundary control; a `/16` there
throws away most of its value.

Verify before cutting traffic over:

```bash
python -m aivs_server.config       # "configuration OK for environment=production"
```

`extra="forbid"` means a typo'd `AIVS_*` variable prevents startup rather than
being silently ignored. That is intentional: typos in security configuration are
otherwise silent failures.

---

## 5. Bringing an instance up

```bash
# 0. Create the CA, on an air-gapped machine (§3.2)
deploy/ca/init-ca.sh --org "Example Financial ISAC" \
  --root-cn "Example Financial ISAC AIVS Root CA" \
  --intermediate-cn "Example Financial ISAC AIVS Issuing CA"
# then move private/root/root.key to offline media

# 1. Configuration
cp deploy/env.example deploy/.env && chmod 0600 deploy/.env
$EDITOR deploy/.env
docker compose --env-file deploy/.env config -q   # interpolation and syntax

# 2. Schema, with the app role named so the append-only grants apply
AIVS_APP_DB_ROLE=aivs_app \
  uv run alembic -c packages/aivs-server/alembic.ini upgrade head

# 3. Verify the append-only enforcement actually took
psql -c "\d+ audit_log" | grep -i trigger
psql -U aivs_app -c "DELETE FROM audit_log WHERE id = 1;"
#   expected: ERROR: table audit_log is append-only; DELETE is not permitted

# 4. Start
docker compose --env-file deploy/.env up -d
```

Step 3 is not optional. The append-only guarantee is the evidentiary basis of the
whole product, and it is the kind of thing that silently fails to apply — the
grants only happen when `AIVS_APP_DB_ROLE` was set at migration time. **Verify
it, do not assume it.**

Then follow [`operator-runbook.md`](operator-runbook.md) §1 for first-run:
creating the ISAC's own `admin` organization, the first `system_admin`, and the
initial circles.

---

## 6. Backup

Detail is in the runbook; the topology-level constraint is this:

**The audit log and submission transitions are append-only, so a restore that
loses rows is not merely data loss — it is a break in the evidentiary chain.**
There is no way to reconstruct them, because nothing else records the same facts.
Continuous archiving (WAL shipping / PITR) rather than nightly dumps alone, and a
restore test on a schedule you actually keep.

---

## 7. Monitoring

Three ways in, all reading the same health registry
(`aivs_server/observability.py`), so they cannot disagree:

- **`/readyz`**: 503 only when the database is unreachable; a degraded
  background component is named in `components` while the probe stays 200.
  The app container's healthcheck (`python -m aivs_server.healthcheck`) asks
  it on loopback, so `docker compose ps` shows a database outage; an
  orchestrator outside compose should probe the same.
- **`/metrics`** in Prometheus text format. Neither probe is reachable through
  the proxy (the member listener answers 404, the internal listener serves
  only `/healthz`), so a scraper joins the compose `backend` network and asks
  the app directly at `http://app:8000/metrics`: add it to this project with
  `networks: [backend]`, or attach an existing one with
  `docker network connect aivs_backend <scraper>`. Alert on
  `aivs_component_up == 0`; that alert still works when the application's own
  detection loop has died.
- **`docker-compose.log-forward.yml`** forwards every container's output to
  the ISAC's collector as RFC 5424 syslog over TLS, including detections as
  OCSF and CEF (runbook §9.1–9.2). Set `AIVS_LOG_FORWARD_COLLECTOR` (host:port; TLS is fixed in the file) and
  `AIVS_LOG_FORWARD_CA_CERT` on the host. The Docker daemon sends the stream,
  so the allow-list for it is the host firewall, not the compose networks.

The platform's own detection rules cover several rows below (runbook §9.1).
The table remains what to alert on in the ISAC's monitoring.

| Signal | Why | Threshold |
| --- | --- | --- |
| `failed to write independent audit record` in application logs | `record_independently` swallows its own failures by design, so an audit-write outage is otherwise **silent**. | Any occurrence — page. |
| `authz.denied` audit rows, rate and distribution | A member repeatedly hitting the same denial is either misconfigured or probing. | Sustained rate from one org. |
| `auth.failure` audit rows | Certificate problems, or someone trying certificates. | Spike. |
| Certificates expiring within 60 days | Rotation lead time. | Weekly report. |
| Embargo sweeper liveness | Not a correctness risk — release is gated on `date_added <= now` in SQL — but a dead sweeper means members are not being **notified**. | Alert after 3 missed intervals. |
| Submissions sitting in `submitted` | The ISAC review queue is the human checkpoint; a backlog is a product failure, not just an ops one. | > 48 h. |
| Webhook `consecutive_failures` | A member's ingest is broken and they may not know. | ≥ 3. |
| Distribution query latency | The keyset index `(circle_id, date_added, id)` must match the query's `ORDER BY`; a divergence turns every poll into a sequential scan. | p99 > 500 ms. |

---

## 8. Scale

For calibration, not capacity planning: an ISAC with 200 member firms, 8 circles,
and 50 submissions a month generates roughly 600 STIX objects and 5,000
distribution rows a month. With members polling every 5 minutes, that is ~58,000
requests a day, nearly all of them returning `{}` against a keyset index. This is
a small workload. If it is slow, something is misconfigured — start with §7's
last row.
