# AIVS threat model

Scope: one AIVS instance — the Python application, its PostgreSQL database, its
reverse proxy, and the network path member firms reach it over. Analysis is
STRIDE per trust boundary.

AIVS is the platform an ISAC runs to manage intelligence across the whole life
of a vulnerability, from a pre-CVE finding under embargo to the defence work
that follows. This model covers what is built, which is the pre-CVE lane and
the machinery around it. Each later stage adds its surface and its adversary
rows here in the commit that builds it — not earlier, because a row for a
control that does not exist reads as a control, and not later, because a
surface with no named adversary has not been threat-modelled.

The mitigations listed are those **implemented in this repository** and
verifiable in the code cited. Where a control is deployment guidance rather than
code, it says so. Residual risk sections are deliberately blunt; a threat model
that concludes everything is fine is not a threat model.

---

## 0. What is being protected, and from whom

### Assets, in order of value

| Asset | Why it matters |
| --- | --- |
| **Embargoed pre-CVE vulnerability content** (`stix_objects.raw`) | Exploitable weaknesses in named products and named firms' estates, with no patch available, held in one place. |
| **The circle membership graph** | Reveals which firms are in which trust tiers. |
| **Receipts** (`acknowledgments`) | Reveal which firms are paying attention to which threats — and, by omission, which are not. |
| **The audit trail** (`audit_log`, `submission_transitions`) | The evidentiary basis for "we warned member X on this date". |
| **Submitter attribution** | Which firm found what, including for submissions distributed anonymously. |
| **Member credentials** | Client certificate private keys, operator passwords, TOTP secrets, webhook HMAC secrets, the proxy shared secret. |

### Threat actors

| Actor | Capability | Motivation |
| --- | --- | --- |
| **Internet attacker** | Network scanning, no credentials. | Reach the service at all. |
| **Nation-state / organised crime** | Targeted, patient, will attack members to reach AIVS. | Pre-patch exploit inventory against GSIBs. This is the actor the instance's value attracts. |
| **Malicious member firm** | Valid certificate, valid circle membership, can submit and read. | Read beyond their tier; discover who else is in a circle; inject content; poison the corpus; learn who is paying attention to what. |
| **Compromised member certificate** | Valid credential, attacker-controlled. Indistinguishable from the member until noticed. | Everything the member could do, silently. |
| **Insider at the hosting ISAC** | Portal access, possibly database access, possibly host access. | Read everything, alter or suppress records, distribute prematurely. **The highest-capability actor in the model.** |
| **Curious member operator** | Legitimate analyst credentials. | Privilege drift — seeing more than their role intends. |
| **Vendor organisation** | A member-like organisation that contributes about its own products, and may be a party to a coordination case. | Delay a disclosure; make a workaround for its product stop circulating; learn the reporter or which members are affected. |
| **Contributor of record** | Any organisation that files: member, vendor, researcher, or an automation key. | Make its content stand where another firm's does; repeat stricter content at a looser TLP; file about a vulnerability it may not yet discuss. |

---

## Boundary map

```
   ┌─────────────────────────────────────────────────────────────┐
   │  member firm networks                                       │
   └───────────────┬─────────────────────────────────────────────┘
                   │  B1: internet → WireGuard overlay / IP allowlist
   ┌───────────────▼─────────────────────────────────────────────┐
   │  overlay network                                            │
   └───────────────┬─────────────────────────────────────────────┘
                   │  B2: overlay → nginx (mTLS termination)
   ┌───────────────▼─────────────────────────────────────────────┐
   │  container / host network                                   │
   └───────────────┬─────────────────────────────────────────────┘
                   │  B3: nginx → application (header-borne identity)
   ┌───────────────▼─────────────────────────────────────────────┐
   │  FastAPI application                                        │
   └───────┬───────────────────────────────────┬─────────────────┘
           │  B4: app → PostgreSQL             │  B5: app → outbound webhook
   ┌───────▼─────────────┐        ┌────────────▼─────────────────┐
   │  PostgreSQL         │        │  member-controlled HTTPS     │
   └─────────────────────┘        └──────────────────────────────┘
```

B6, the opt-in public member listener, is a second path from the internet
to nginx beside B1–B2: no overlay and no client certificate, for member
people signing in through the ISAC's identity provider.

---

## B1. Internet → WireGuard overlay / IP allowlist

**What crosses:** raw IP packets from member firm egress addresses.
**Assets exposed:** the existence and reachability of the service.
**Relevant actors:** internet attacker, nation-state.

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S** | Attacker spoofs a member's source address to enter the allowlist. | WireGuard mode: a peer is authenticated by its Noise-protocol static public key, not its address; a spoofed source cannot complete the handshake. Allowlist mode: source-address filtering only. | **Allowlist mode is materially weaker than overlay mode.** It resists scanning, not a determined attacker with a path to spoof or a foothold at a member's egress. Prefer WireGuard. |
| **T** | Packet injection into an established flow. | WireGuard AEAD (ChaCha20-Poly1305) on every packet; TLS 1.3 above it in both modes. | Negligible. |
| **R** | Attacker denies having connected. | WireGuard peer keys are per-member and logged; the app records the client address nginx saw on every audit row (`audit_log.source_ip`, INET), taken from `X-Real-IP` only when the request proves it came from the proxy (`auth.mtls.client_address`), and the TCP peer otherwise. | Shared-NAT egress collapses several member hosts to one address. Certificate fingerprint, not IP, is the identity of record. |
| **I** | Service discovery: an attacker learns an ISAC runs an embargoed vulnerability exchange and at what address. | WireGuard does not respond to unauthenticated packets — the port is silent to scanners. Allowlist mode drops before TLS. | In allowlist mode the TCP port is visible from allowlisted ranges. Nothing hides the deployment from a member's own network. |
| **D** | Volumetric flood. | Non-allowlisted traffic is dropped at the network layer before reaching TLS or the application. | An upstream volumetric attack still consumes the ISAC's transit. Out of scope for the application; a hosting concern. |
| **E** | Not applicable at this layer — reaching the overlay grants no application privilege. | Every subsequent boundary re-authenticates independently. | — |

---

## B2. Overlay → nginx (mTLS termination)

**What crosses:** TLS 1.3 with a client certificate.
**Assets exposed:** everything the presented certificate's organization may read.
**Relevant actors:** malicious member, compromised certificate, nation-state.

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S** | Present a forged or self-signed client certificate. | nginx `ssl_verify_client on` against the AIVS CA bundle; `$ssl_client_verify` must be `SUCCESS`, and the app re-checks that header value (`auth/mtls.py`, `_VERIFY_SUCCESS`). | Compromise of the CA private key forges any member. See §6, offline root guidance. |
| **S** | Present a **stolen but genuine** member certificate. | Revocation is a status flip on `client_certificates.status`, checked on every request against an indexed unique constraint — effective within one request, no CRL propagation delay. `last_seen_at` supports "this cert last appeared from an unusual place" review. | **AIVS cannot distinguish a stolen key from its legitimate holder.** The `bulk_retrieval` detection rule raises when one organisation retrieves far more than members do (runbook §9.1), and quarantine cuts it off, but a thief who reads at a member's normal pace is noticed only when the member notices, or an operator reviewing `last_seen_at` and audit patterns does. This is the most realistic path to member-tier data. |
| **S** | Present an expired certificate that a misconfigured proxy accepted. | The application re-checks `not_valid_before_utc` / `not_valid_after_utc` itself, with a 5-minute skew tolerance (`_check_validity_window`). Explicitly defends against `ssl_verify_client optional` being left in place or a stale trust store. | None material. |
| **T** | Downgrade or strip TLS. | `ssl_protocols TLSv1.2 TLSv1.3` — 1.0 and 1.1 absent. TLS 1.2 retains AEAD-only, forward-secret suites (no CBC, no static RSA, no SHA-1). Session tickets are off, so a stolen ticket key cannot retroactively decrypt resumed sessions. The overlay carries no cleartext path. | TLS 1.2 is retained only for member security appliances that cannot do 1.3, and it is a weaker floor than 1.3-only. Remove it once the member base allows. |
| **R** | Member denies having polled. | Identity is the SHA-256 fingerprint of the presented certificate, computed by the **application** from the forwarded PEM — not nginx's `$ssl_client_fingerprint`, which is SHA-1 and is deliberately not trusted. `acknowledgments` rows record retrieval; `audit_log` records the request. | A member can argue their key was stolen. The agreement should place key-custody obligations on the member (see the sharing agreement outline). |
| **I** | Certificate chain reveals the member set to a passive observer. | Client certificates are sent encrypted in TLS 1.3. | The server certificate and SNI still identify the instance. |
| **D** | Handshake flood; oversized certificate chains to burn ASN.1 parsing CPU; a member polling far harder than needed. | nginx: `limit_req_zone`/`limit_conn_zone` keyed on `$ssl_client_fingerprint` at 20 r/s, burst 40, plus 64 connections per source address, answered **429**; requests carrying a body, 2 per certificate and 16 in all, so spooled bodies cannot fill the proxy's shared tmpfs. `ssl_verify_depth 2`. `client_max_body_size 5m`. Application: `MAX_CERT_HEADER_BYTES = 16 KiB` before any parse; `AIVS_MAX_BODY_BYTES` (default 5 MiB); `AIVS_DB_STATEMENT_TIMEOUT_MS` (default 15 s) so one runaway query cannot pin a connection. | Quotas are per certificate, so a member with several certificates has several buckets. Bucketing on a SHA-1 fingerprint is fine — a collision costs a shared quota, not an identity. The **application** still has no per-organization quota; if nginx is replaced or bypassed, that protection goes with it. |
| **E** | Certificate for org A used to act as org B. | Authorization is resolved from the fingerprint → `client_certificates.org_id` mapping in the database. The certificate's subject DN is stored but is **not** the identity key. | None material. |

---

## B3. nginx → application

**The most security-sensitive boundary in AIVS**, because it converts HTTP
headers — which any client can attempt to set — into an authenticated
organization identity.

**What crosses:** `X-Client-Verify`, `X-Client-Cert` (URL-escaped PEM),
`X-Proxy-Auth`, `X-Request-Id`.
**Relevant actors:** anyone with a foothold inside the container/host network.

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S** | A client sets `X-Client-Cert` itself and reaches the app directly. | Three stacked controls, all documented in `auth/mtls.py` and in `deploy/nginx/nginx.conf`: (1) the app publishes **no host port** — the compose file declares no mapping for the app service; (2) `snippets/aivs-identity-headers.conf` **unconditionally overwrites** every identity header via `proxy_set_header`, with no conditional and no "only if absent", and is included by every proxying location; (3) `X-Proxy-Auth` must match `AIVS_PROXY_SHARED_SECRET`, compared with `hmac.compare_digest`, and the peer address must fall inside `AIVS_TRUSTED_PROXY_CIDRS`. The secret reaches nginx by envsubst into a tmpfs at container start, so it is never in a committed file or an image layer; if it is unset, the rendered value is empty and the app rejects everything — the deployment fails closed. | An attacker with code execution **inside the container network** and possession of the shared secret can forge any organization identity. The secret is the sole cryptographic barrier at this hop. The proxy→app hop is plaintext HTTP over the compose bridge; a multi-host deployment must carry it over the overlay or add `proxy_ssl_*`. |
| **S** | Bypass by disabling the proxy check. | `dev_trust_unauthenticated_proxy` exists but `validate_production_posture()` refuses to construct `Settings` with it enabled in any environment but `dev` — staging included — so the process will not start. Same for `dev_expose_error_detail`, `dev_allow_private_webhook_targets`, an empty or `/0` `trusted_proxy_cidrs`, renamed identity headers, non-HTTPS `public_base_url`, `log_level=DEBUG`, a key-encryption key from the environment or not in a `0600` file, a missing issuing-CA certificate, inverted page sizes, and one value for both the session secret and the proxy secret. | Relies on `AIVS_ENVIRONMENT` not being `dev`. It defaults to `production`, and only the literal `dev` relaxes anything, so the failure mode of forgetting it is the strict one. |
| **T** | Tamper with the forwarded certificate to change the fingerprint. | The app parses the PEM and computes SHA-256 itself; any modification produces a fingerprint with no matching `client_certificates` row. Malformed input raises `CertificateRejection`, never a traceback. | None material. |
| **R** | A member forges audit-trail correlation ids, or deliberately collides with another member's requests. | nginx sets `X-Request-Id` to its own `$request_id` unconditionally, never passing the client's through. The value propagates into every audit row and application log line. | None material, provided the shipped identity-headers snippet is used. Any proxying location that omits it breaks this. |
| **I** | The unauthenticated health and metrics routes leak operational state. | `/readyz` and `/metrics` carry component names, run times, error *types* (never messages) and two queue depths, no identifiers and no content. nginx answers all three probes with 404 on the member listener (pinned by `test_proxy_config.py`). The authorization matrix pins the public set exactly. | Anything on the `backend` network can read how many embargoes are pending, and that number moves when a pre-CVE finding enters embargo. That is accepted: such a reader already holds the proxy's position. |
| **I** | Error responses leak internals. | `CertificateRejection.reason` and `PolicyDenied.reason` are recorded in the audit log and **never returned to the caller**. `dev_expose_error_detail` is production-forbidden. | — |
| **D** | Oversized or malformed header floods. | 16 KiB certificate header cap before any parse is attempted. | — |
| **E** | Timing oracle on the shared secret. | `_require_trusted_proxy` evaluates **both** the peer check and the secret comparison before branching, so running time does not distinguish "wrong source address" from "wrong secret"; the comparison itself is `hmac.compare_digest`. | — |

---

## B4. Application → PostgreSQL

**What crosses:** SQL over the container network.
**Assets exposed:** everything.
**Relevant actors:** ISAC insider, an attacker who has reached the app or the DB
host.

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S** | Connect to the database directly with stolen credentials. | `AIVS_DATABASE_URL` is a `SecretStr`; deployment guidance is to bind PostgreSQL to the internal network only and to run the app as a **non-superuser role that does not own the tables**. | A credential in an environment variable is readable by anything that can read the process environment or the orchestrator's secret store. |
| **T** | Alter or delete audit records to hide an action. | Migration `c185fd428721`: `BEFORE UPDATE / DELETE / TRUNCATE` triggers on `audit_log` and `submission_transitions` raising `insufficient_privilege`; `FOR EACH STATEMENT` so a probe fails identically whether or not the row exists; `REVOKE UPDATE, DELETE, TRUNCATE … FROM PUBLIC`; and where `AIVS_APP_DB_ROLE` is set, `GRANT INSERT, SELECT` only. The trigger function pins `SET search_path = pg_catalog` so a caller-controlled schema cannot shadow what it resolves. | **A superuser — or the table owner — can `DROP TRIGGER` or `ALTER TABLE … DISABLE TRIGGER` and then rewrite history.** This is unavoidable in PostgreSQL and is stated as such in the migration itself. Mitigation: the app must not connect as superuser or table owner, which the shipped stack now enforces (a separate `aivs_app` login; the migrate step grants it `INSERT, SELECT` here and refuses a superuser, owner or member of the owner), and audit content must be shipped off-box (see §7). Whoever holds the owner's password, which of the application's containers only the migrate container receives (the database container holds it as `POSTGRES_PASSWORD`), can still rewrite history. |
| **T** | SQL injection. | SQLAlchemy Core/ORM with bound parameters throughout. The one place DDL identifiers are interpolated (migration `c185fd428721`) validates them with `_quote()`, which refuses anything non-alphanumeric-plus-underscore, even though the values are module constants. Database check constraints independently enforce formats (`^[0-9a-f]{64}$` fingerprints and token hashes, slug patterns, `identity--` prefixes) so a parsing-layer bug cannot store a value that later fails to match. | — |
| **T** | Corrupt a distribution's `date_added` to release content early. | Ordinary table, so an actor with write access can. The check constraints (`distributed_has_timestamp`, `timer_requires_release_at`, `released_has_timestamp`) constrain shape, not intent. | An attacker with database write access owns the system. Accepted; the boundary that matters is B3. |
| **R** | An action leaves no trace. | Denials and auth failures use `record_independently()`, which commits in its own transaction because the request's transaction is about to roll back. Successes use `record()`, which commits with the change it describes. | `record_independently` **swallows** its own write failures (logged via `logger.exception`, not raised) — a deliberate trade so an audit outage does not turn a clean 403 into a 500. It means an audit-write outage is silent to the caller. **Monitor for `failed to write independent audit record` in application logs.** |
| **I** | A database dump discloses everything. | Passwords are Argon2id hashes; TOTP secrets and webhook HMAC secrets are sealed by `auth/secretbox.py` (a configurable AEAD, AES-256-GCM by default, key read from a `0600` file outside dev, bound to the row id, algorithm and key recorded in each value);  portal session tokens are stored only as SHA-256, so a dump yields no live sessions. | **`stix_objects.raw` is plaintext.** That is the crown jewel and it is not encrypted at rest in the application layer. The sealed columns also depend on a key file on the same host as the database, readable by the app's uid and by anyone who can read the container's mount, so they resist a dump, a replica or a stolen backup -- not a full host compromise. Encryption is a storage-layer responsibility (full-disk / volume encryption) and must be in the hosting requirements. |
| **I** | Secrets leak into the audit log, which is immutable and therefore un-redactable. | `audit.log.redact()` strips a fixed key list (`password`, `totp_secret`, `hmac_secret`, `token`, `csrf_token`, `api_key`, `private_key`, `authorization`, `cookie`, `proxy_auth`, …) at every nesting depth, caps strings at 2,000 characters, lists at 100 elements, and recursion at depth 6. | The list is **key-name based**. A secret placed under an unlisted key name, or embedded in a free-text field, is written permanently and cannot be removed afterwards, precisely because the table is immutable. Adding a detail key is a change that deserves review. |
| **I** | SQL alone -- injection on the member path, a dump, a read replica -- maps submissions and objects to the firms that filed them. | Who filed what is held in `attribution.submitters` (SF-88). The member path asks "is this mine?" of `submissions.owner_tag`, and versions are grouped by `stix_objects.owner_token`, both HMACs under an attribution key the database never holds (SF-90): SQL can neither compute a tag for a guessed firm nor reverse one, and tags match across no two submissions. The key is a `0600` file, different from the key-encryption key; startup refuses values under any other key. | **Whoever holds the attribution key and a database dump recovers the whole mapping, anonymous filers included** (R24): with the key, a tag can be tested against each of the few dozen organisation ids. Keep the key apart from backups, as the key-encryption key is; a rekey after a joint disclosure does not undo it (runbook §7.4a). The member login cannot read `attribution`, or any table whose rows name an organisation beside a submission (SF-91); a member's own rows in those are read staff side, keyed on its organisation, and its own organisation's status and notification settings are written there, so SQL on the member path can neither lift a peer's quarantine nor redirect its digest. |
| **T** | Copy one row's owner tag or token onto another, so a firm claims, or is credited with, a peer's filing. | SQL cannot compute a value for a chosen firm, only copy an existing one. `attribution.submitters`, the record of who filed what, is append-only by trigger. The two keyed columns carry no deny trigger, because a rekey recomputes them; the member login holds no UPDATE on either (a column grant, SF-91), which a migration test proves by attempting it as that login. The member login may insert a filer, which it needs to record its own filings, so SQL on the member path could record a filing in another firm's name: `filer_mismatch` raises any filing no audited creation names, and `owner_tag_mismatch` any submission whose tag is not its recorded filer's (SQL cannot compute the right one). | A forged filing whose `created_at` is backdated past the rules' 24-hour window is not raised. The member login may append audit rows, so a forger that also writes the creation's audit row passes `filer_mismatch`; it does not pass `owner_tag_mismatch`, because SQL cannot compute the named firm's tag. Closing R25 moved this protection from slice 2b's append-only `attribution.object_owners` to the grant. |
| **D** | A runaway query exhausts the pool. | `AIVS_DB_STATEMENT_TIMEOUT_MS` (default 15 s) on every session; bounded pool (`db_pool_size`, `db_max_overflow`, `db_pool_timeout_seconds`); TAXII page size capped at `AIVS_TAXII_MAX_PAGE_SIZE` (default 500). | Deep pagination over a very large circle is still expensive. The keyset index `(circle_id, date_added, id)` is what keeps it linear — and it must stay aligned with the query's `ORDER BY`. |
| **E** | Privilege escalation via ORM cascade. | Foreign keys are `RESTRICT` except for genuine ephemera and configuration; nothing of evidentiary value can be cascaded away by deleting a parent. | — |

---

## B5. Application → outbound webhook

**What crosses:** an HMAC-signed HTTPS POST to a member-supplied URL.
**Relevant actors:** malicious member (as the URL's author), internal attacker.

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S** | A third party forges a notification to a member. | Each webhook has an HMAC secret, encrypted at rest, shown to the member exactly once at creation. Receivers verify the signature. | A member who does not verify the signature gains nothing from it. Say so explicitly in onboarding. |
| **T** | Payload modified in transit. | `webhooks.url` is constrained to `https://` by a database check constraint (`url_https_only`) — not merely validated in the application. HMAC over the body detects modification. | — |
| **R** | Member claims non-delivery. | Every attempt writes a `webhook_deliveries` row with `attempts`, `response_code`, `error`, `delivered_at`. | The webhook is a convenience channel. **The receipt of record is the TAXII/API retrieval in `acknowledgments`, not the webhook.** Do not build the "we warned you" argument on webhooks. |
| **I** | **SSRF**: a member registers `https://169.254.169.254/…` or an internal address and turns AIVS into a probe of the ISAC's own network. | Delivery refuses private, loopback, and link-local targets. The bypass `dev_allow_private_webhook_targets` is named "in any real deployment this being true is an SSRF hole" in the config, and `validate_production_posture()` refuses to start with it set in any environment but `dev`. | DNS rebinding (resolve public at validation, private at connect) is the classic residual. Resolve-then-pin at connect time, and consider an egress policy that permits only outbound 443 to non-RFC1918 destinations. |
| **I** | Notification payload discloses embargoed content to an endpoint that should not have it. | Design constraint: notifications carry **metadata and identifiers**, never embargoed object bodies. Members fetch content over authenticated TAXII. | Enforced by the notification payload builder, not by a schema. Worth a conformance test. |
| **D** | A slow or hostile endpoint stalls delivery workers. | `AIVS_WEBHOOK_TIMEOUT_SECONDS` (default 5 s, max 30); `AIVS_WEBHOOK_MAX_ATTEMPTS` (default 5); `consecutive_failures` per webhook supports auto-disable. | A member can generate outbound load by registering a slow endpoint. Bounded, not eliminated. |
| **E** | — | Webhook delivery runs with no authorization context; it cannot read content it was not handed. | — |

---

## B6. Internet → public member listener (member SSO, opt-in)

**What crosses:** ordinary TLS from any browser, with no client certificate:
the OIDC sign-in round trip, then portal requests carrying an SSO session
cookie and a device cookie. Published only by `docker-compose.public.yml`
(`deployment-topology.md`, "The public member listener").
**Assets exposed:** what a member's person may read up to `TLP:AMBER+STRICT`,
never RED or embargoed content, and their own firm's filings within that.
**Relevant actors:** internet attacker, curious member operator, an attacker
holding a member person's IdP credentials or browser.

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S** | Sign in as a member with a password phished or sprayed at the IdP. | The IdP performs the second factor, and AIVS refuses a token whose `amr` asserts fewer than two factors, a missing claim included (`auth/oidc.py`). nginx limits sign-in to 10 per minute per address. Lockout per person is the IdP's. | A real-time phishing proxy that relays the second factor yields a session. Passkeys at the IdP close it; AIVS cannot require them, only record `amr`. |
| **S** | Sign a victim in as the attacker (login CSRF), or redeem a code lifted from a log or referrer. | `state` lives in a signed, ten-minute pending-login cookie that the callback must match. The PKCE verifier and `nonce` are derived from that `state`, so a code is useless without the browser that began the login. | None material. |
| **S** | Replay a stolen session cookie from another browser. | The session is bound to a per-browser device cookie by its hash, and to the IdP issuer and subject; every request re-checks both, the maximum age (8 h by default), and operator and organisation status. | Malware that takes both cookies from one browser holds the session until it expires or the operator is deactivated: **R15**. |
| **T** | Forge or alter the ID token. | Signature verified against the issuer's JWKS with PyJWT, with algorithms pinned to RS256/PS256/ES256/ES384, and `iss`, `aud`, `exp`, `iat`, `sub` and `nonce` all required. The discovery document must name the configured issuer. | Compromise of the ISAC's member IdP tenant forges any member person: the tenant is now part of the trusted base for AMBER content. |
| **R** | A person denies having signed in. | `portal.sso.login.success` records the subject's operator and `amr`; every refusal is audited with its reason. | As for any federated login, the evidence of who typed the credential is the IdP's. |
| **I** | Read RED or embargoed content, or another firm's filing, through the portal. | `policy.tlp_ceiling` caps an SSO session at AMBER+STRICT and excludes any submission with an embargo, on every read path: the visibility clause, the TAXII listings (passed as a required argument), the firm's own filings list and count, and `can_view_submission`. The authorization matrix holds the SSO principal to the member analyst's row. | Content at AMBER+STRICT and below is readable from any device the person signs in on. That is the decision this listener embodies. |
| **I** | Reach the API, TAXII, staff or admin screens, or the probes, through the public listener. | nginx proxies an allow-list of member-portal paths; everything else is a 404 written by nginx. The app also refuses an SSO session as an API or TAXII credential, and it refuses an SSO session presented beside a certificate on the certificate-bound listener (`session_unbound`). | None material while the allow-list and the shipped snippet are used. |
| **D** | Flood sign-in or pages from many addresses. | Per-address limits (sign-in 10 r/min with a burst of 5; pages 10 r/s with a burst of 20), 32 connections per address and 2 requests carrying a body, answered 429; at most 8 bodies in flight on this listener, its own share of the proxy's spool tmpfs. | A distributed flood is not stopped by per-address limits. It reaches only this listener, so the certificate-bound listener and its members keep working: the spool space it can use is capped apart from theirs, which it was not before review D2-P1. |
| **E** | A member-tenant account reaches staff authority, through a staff group in its claim or a mis-set role. | A sign-in naming a group that maps to the hosting ISAC is refused. The session resolver refuses any SSO session whose organisation is the ISAC, and intersects roles with `ANALYST` and `ORG_ADMIN`. JIT creates `ANALYST` only. | None material. The staff issuer is unbuilt; staff sign in on the certificate-bound listener. |

---

## Cross-cutting: the malicious or compromised member

Worth pulling out, because it is the actor most people underestimate.

| What they try | What stops it |
| --- | --- |
| Read a circle they are not in. | `can_read_circle` checks `circle_id in ctx.circles` and nothing else. `distribution_visibility_clause` restricts every read to `readable_circle_ids(ctx)`, which returns the **empty set** for an inactive org — and an empty set produces `or_(False)`, a clause matching no rows, rather than an unconstrained `IN ()`. The safe failure mode is asserted in tests. |
| Read content before its embargo lifts. | `Distribution.date_added <= now`, evaluated in SQL on every read. Not scheduler-dependent. |
| Distribute their own submission without ISAC review. | `can_transition_submission` grants `validated` and `distributed` **only** to a human `isac_editor` session; no machine identity, the ISAC's included, can do either. |
| Submit into a circle they only read. | `can_submit_to_circle` requires `contributor`. |
| Learn who read their submission — or anyone else's. | `can_view_submission_receipts` is restricted to the ISAC's reviewers. The submitter sees counts only, each exact only when at least k organisations did the thing and at least k did not, over a reach of organisations that could actually retrieve it (`services/telemetry.py`, SF-15); it once read the named receipts too, which made that suppression decorative. A milestone fires only for a count shown exactly: a "first retrieval" that never fired once told the submitter the count was zero. The counts and milestones come from a published snapshot replaced only once k organisations differ, so a submitter cannot read a count twice and learn which firm acted in between, even around a suspension (SF-80). |
| Keep access after being suspended. | `is_active(ctx)` is the first check in **every** predicate. Setting `status = suspended` takes effect on their next request; no cache to invalidate, no token to expire. |
| Smuggle unvalidated content into other members' TIPs via a STIX extension. | `assert_extensions_allowed()` allowlists exactly two extension ids (AIVS's own and TLP 2.0). This exists because `stix2.parse(allow_custom=False)` **does not** reject unknown `extension-definition--` property extensions — verified against stix2 3.0.2, it passes the body through as an opaque dict. See [`stix-extension.md`](stix-extension.md). |
| Poison the corpus with plausible false findings. | The ISAC's `validated` checkpoint, and human judgement. **Nothing technical stops this.** |

### The claim AIVS cannot verify

**`discovery_scope` is an unverified assertion by the submitter.** AIVS enforces
that the value is one of `own_product`, `own_estate`, `ai_system`; it has no way
to establish that the submitter actually owns the product, actually operates the
estate, or that the finding is genuinely about an AI system rather than a third
party's web server.

The structural controls around it are:

1. The three scopes a submitter may claim for its *own* finding describe no
   third party, so a submitter must affirmatively mis-state its relationship
   rather than merely omit it. The two third-party scopes are not claims at
   all: they are admitted only by the state of the ISAC's own record of the
   target (next section).
2. The ISAC reviews before distributing (`submitted` → `validated` →
   `distributed`).
3. The membership agreement makes the attestation contractual, so a false claim
   is a breach with named consequences.

That is the whole of it. A member who lies convincingly, about a product an ISAC
reviewer cannot check, will get third-party vulnerability content distributed.
The controls make it a deliberate act with an audit trail and a contractual
consequence — they do not make it impossible. **Treat reviewer training on
scope as a first-class operational control**, not paperwork.

---

## Cross-cutting: the insider at the hosting ISAC

The highest-capability actor in this model, and the one the product's positioning
creates. What the hosting ISAC's staff can legitimately do, between them
(the powers are split across `isac_analyst`, `isac_editor`, `isac_membership`
and `system_admin`, each requiring a human session; see `docs/authz-model.md`):

- Read every submission's workflow record (`can_view_submission`) and every
  submission's receipts (`can_view_submission_receipts`) — including the true
  submitter of an anonymized submission.
- Validate and distribute any submission.
- Enrol, suspend, and manage every organization; register and revoke every
  certificate (`can_manage_org`).
- Administer any circle's membership (`can_administer_circle`).

What they deliberately **cannot** do without it being visible:

- Silently read a circle's TAXII feed. `can_read_circle` has no admin bypass. An
  ISAC that wants a circle's content joins that circle, appearing in the
  membership list like any other organization. This is a design decision with a
  cost — it makes some legitimate oversight less convenient — taken so that
  members can verify who is in their circle by inspection.

What is not prevented:

- A system admin with **database or host access** can drop the append-only
  triggers and rewrite history (§B4). Separating who administers the application
  from who administers the database is the only real control, and it is
  organisational.
- A system admin can distribute a submission earlier than the submitter intended
  by lifting an embargo. `embargo_status = lifted_early` records that it
  happened, and the audit log records who did it — after the fact.

---

## The biggest non-technical risk

**Operational discipline at whoever hosts the instance is a larger risk to this
system than any weakness in its code.**

The instance aggregates embargoed, unpatched vulnerabilities affecting GSIBs and
Section 9 firms into a single database. That concentration is the product's value
and its principal danger: it is a more attractive target than any single member
firm's vulnerability backlog, and considerably more attractive than the ISAC's
existing infrastructure. An ISAC that has historically run mailing lists and a
portal is now running a system whose compromise is a sector-wide event.

Concretely, the failure modes that will actually occur are:

- The CA private key kept on the same host as the service, or on a laptop.
- Certificate revocation not performed when a member's staff leave or a key is
  suspected lost, because there is no process for it.
- The application connected to PostgreSQL as a superuser because it was easier,
  silently voiding the append-only guarantees.
- Backups taken but never restore-tested, so the audit trail's continuity is
  discovered to be broken at the moment it is needed.
- `AIVS_ENVIRONMENT=dev` left on a real host, the one value that relaxes
  `validate_production_posture()`.
- A reviewer approving submissions faster than they can actually assess scope,
  because the queue is long.

None of these are code defects, and none are fixed by code. They are the content
of [`operator-runbook.md`](operator-runbook.md), and they should be audited
against, not assumed.

---

## Cross-cutting: contributions about another party's object

Phase E lets anyone file about a vulnerability somebody else owns: a workaround,
a detection, an opinion, a sighting. Every one is an ordinary submission, so
attribution, anonymity, review, TLP floors and receipts apply unchanged; these
are the attempts that are new, with the rule that refuses each and the test
that drives it (`tests/abuse/test_contribution_abuse.py` for the two sequences).

| What they try | What stops it |
| --- | --- |
| A vendor publishes a newer version of a member's workaround saying it is not needed, so every TIP replaces the workaround. | Only the organisation that first distributed an id may publish a newer version of it (`services.ownership`, SF-48), checked at validate and again at distribution. The vendor's disagreement is an `opinion`, which sits beside the workaround and replaces nothing. |
| A correction is published with a `modified` no later than a version already distributed, so every TIP keeps the older version and the correction is never shown: the warning a member would swear it never received. | Newest-version-only (SF-82) refuses it at validate, at distribution and before an embargo releases, against every distributed version by the same owner, embargoed ones included; a held timer is listed on the status page with its reason. |
| A contributor re-files another firm's finding id with a later `modified`, or races it ahead of the owner's distribution. | The same rule, at both points: a submission validated before the owner distributed is refused at distribution. `match[version]=last` resolves per owner, so the read side does not honour a takeover either. |
| A member refers to an id it cannot see, to learn from the refusal whether a pre-CVE finding exists. | Ingest checks only targets the caller can see, and an invisible target gets the refusal an absent one does, byte for byte (`services.disclosure`, SF-47). A vendor's agreeing opinion counts at ingest only when the caller can read it, so acceptance does not reveal an embargoed one. The global checks run at validate, where the actor is the ISAC. Ownership is never checked at ingest for the same reason. |
| File defence content on a vulnerability that is not public yet, as `disclosed_third_party`. | Legal only once the ISAC's canonical record of the target says `published`, at its *current* version: a disclosure withdrawn between validation and distribution stops the distribution (SF-7). |
| Claim a coordinated case by writing the vendor's agreement into one's own bundle. | `coordinated_disclosure` counts only a vendor an editor placed in a circle the target reached, agreeing in an `opinion` the ISAC validated and distributed, or a VINCE / GOLD EAGLE reference on the ISAC's own record. Nothing in the submitter's bundle counts. |
| Repeat AMBER+STRICT content at CLEAR, as an `opinion` on it. | A contribution's TLP must be at least as restrictive as every object it references: against what the submitter can see at ingest, against everything at validate and distribution (SF-49). The submission's TLP is stamped into every object's `object_marking_refs`, and an object marked otherwise is refused. |
| An automation key quietly lowers a CVSS score, or asserts a system restart, inside a routine validation. | The submission's source is derived from the filing organisation (`system` for automation, whatever the content says), and a consequential change it makes must be named by the validating editor (SF-6). The reviewer is written by validate from the editor's session; a submitter cannot claim one. |
| An anonymous submitter is named by a sighting's location or an opinion's authors. | Refused on anonymous submissions, at ingest, on a change of the anonymity flag, and at distribution; an attributed sighting may name only its filer (SF-50). |

**What this does not stop.** A vendor that is a legitimate party to a case can
still delay by not acknowledging; that is the coordination process, and the
ISAC's lever is the embargo policy, not this code. And a coordinated reporter
cannot file against a target it cannot see: the canonical record of a
pre-disclosure case is distributed to its coordination circle, so a reporter
outside it gets the uniform refusal and files through the ISAC.

## Cross-cutting: contributions published without review

Phase E lets some contributions reach members with no editor in the loop: a
one-click ("we see this too", "works", "doesn't work") on public content, and a
short contribution in a circle an editor has made post-moderated. It also opens
two new ways in that still go through review: the TAXII inbox, and an analyst
filing for a member. What a member, a script, or an insider might try, with the
rule that refuses it (`tests/abuse/test_sharing_abuse.py` drives the sequences):

| What they try | What stops it |
| --- | --- |
| A member's platform posts into a circle the ISAC never decided should take machine contributions. | Every collection is created closed; only an ISAC editor opens a circle's inbox, on the API or the portal through one writer, and the switch is recorded with who and which way (SF-69). Open, a post is still a submission for review. |
| A script, or a stolen certificate behind a person's session, floods a circle with one-clicks. | An hourly allowance per organisation for everything published without review, inbox posts included; past it a one-click is refused, and the refusal is audited and raises `contribution_flood` (SF-66). |
| Publish prose, a pre-CVE finding, or RED content through the fast lane. | The lane rule: only a click with no free text, about a published vulnerability or a contribution on one, never RED, takes it. Prose takes it only in a circle an editor made post-moderated, and only for a note, opinion, sighting or RFI grouping (SF-66). |
| A vendor clicks "doesn't work" on a workaround for its own product. | A vendor's opinion is never published without review, whatever product it concerns (SF-66). |
| A machine identity, the ISAC's automation included, publishes by clicking; or ISAC staff without the editor role publish in the ISAC's name, or replace an editor's record (the ISAC is one owner of all its records). | Both shortcut lanes need a person's session at a member organisation, by an allow-list of member types: a certificate alone, anyone at the ISAC, and the automation organisation are filed for review (SF-66). |
| Read, from the logs forwarded to the ISAC's collector, which firm sighted or tried which vulnerability, and when. | A one-click names its target in the request body (`POST /api/v1/contributions`), as a posture does, so neither nginx's access log nor the app's carries "firm X, object V" for either; a test holds every member contribution and posture route to an id-free path (SF-66, SF-70). |
| A reader-only member (a government or vendor in a circle it reads) publishes into that circle through the fast lane. | The fast lane publishes only into circles the organisation contributes to; with none, the click goes to review (SF-66). |
| Learn, from a shortcut's refusal, what the ISAC holds and the member cannot see: a stricter or embargoed version of the object, a hidden record's disclosure state, who owns an id. | The fast lanes run validation's content rules from the ISAC's view, and a refusal there files the contribution for review with one constant reason (`NEEDS_AN_EDITOR`); the reason itself is for an editor. RED is never published unread, whatever its referents. The allowance is counted under a per-organisation lock, by publication time (SF-66). |
| A member's MISP or OpenCTI pushes content that would publish itself, or names the firm. | Each TAXII POST becomes a `submitted` submission with source `system`. It is never published without review, it is anonymous (so `identity` objects are refused), it is held to the disclosure split, and it spends the same allowance (SF-69). |
| An ISAC analyst's session, a system administrator, or the admin organisation's certificate with no person behind it (which the host can mint in the managed-hosting mode) amends an ISAC draft, or withdraws a validated ISAC advisory members rely on. | Every verb on a filing owned by the ISAC's own organisation needs a human `isac_editor`, on the API and the portal through one predicate (`holds_submitter_rights`); the refusal is recorded by name (SF-81). Until Mike's Q15 the submitter's rights applied to the ISAC as to any member. |
| An analyst files content in a member's name that the member never sent. | A proxy filing needs a stored consent hash. The member is told at once, contentlessly. The filing cannot be distributed until the member confirms or 24 hours pass, and the member withdraws it with its ordinary stop button (SF-68). |
| The ISAC, or an auditor at it, reads which members are affected by a vulnerability. | A posture row is its own organisation's alone, and the ISAC gets the 404 an absent row gets. The counts it sees are exact only when at least k members have that status and at least k do not -- the audit log names who recorded a posture, so a unanimous count or a zero would name each firm's status -- the total is withheld when it would give a count away, and only active members are counted. Its audit row says a posture was set, never which, and no posture request names the vulnerability in its URI, so neither nginx's log nor the app's carries "firm X, vulnerability V" to the log collector (SF-70). This holds against ISAC staff *through the application*: whoever operates the database reads `org_postures` in plaintext, and that is the host's trust. The counts are read from a published snapshot, replaced only once at least k members' statuses differ from it, so a firm's audit row at time t, beside the counts read before and after it, or a suspension an editor makes on purpose, moves nothing (SF-80). What remains: an observer who knows k firms changed (a coordinated patch day) learns the sum of their changes, which is what a k-anonymous count shows. |
| A stolen ISAC membership session offboards a member: its certificates end, its postures are deleted, its people are pseudonymised, and nothing reverses it. | Only membership staff hold offboarding, a member's own admin cannot (403), the slug must be typed out, and every offboarding raises `org_offboarded` at once. A legal hold placed beforehand keeps the postures. What cannot be undone is accepted for the role that holds it, and watched (SF-72). |
| A stolen member certificate, or a session behind one, takes the firm's whole list of where it is affected in one request (`/api/v1/postures/openvex`). | The export is the member's own and cannot be refused to its own credential, so it is watched instead: each export is audited as an act, never its content or size, and `posture_export_burst` raises when one organisation exports 20 times in an hour. The alert names the firm, never a statement (SF-70). |

**What this does not stop.** The prose of a post-moderated note reaches members
before an editor reads it; the circle chose that. An editor revokes it
afterwards (`services/revocation.py`): every object gets a newer version with
`revoked: true`, distributed to every circle it reached, so a poller past the
original still receives the retraction. Revoking is allowed while distribution
is paused, so a note that prompted the pause is retracted before anything is
shown again. What a member's TIP already copied elsewhere stays copied: a
revocation is a statement, not a recall.

## Cross-cutting: reading, exporting and lead time

Phase F gives a member's people more ways to take content away: a guided
page meant to be printed into a change ticket, an IoC pack meant for a block
list, and a quarterly statement of how far ahead of NVD and KEV they were.
None of them decides what a caller may see. Each is handed the objects the
visibility gatherer (`services/vulnerability_objects.py`) returns for the
caller, through the same policy clause as TAXII, and writes them out
(`tests/abuse/test_reading_abuse.py` drives the sequences):

| What they try | What stops it |
| --- | --- |
| A stolen certificate or session pulls the IoC pack for every vulnerability instead of paging TAXII. | An export is a retrieval: it writes the receipt a TAXII page writes (on its own channel) and an `export.retrieved` audit row, so `bulk_retrieval` counts it, names the organisation and proposes quarantine. The pack holds nothing the caller could not already read. |
| Plant a spreadsheet formula, or markup, in an indicator or a course of action, to run on the member's analyst. | The pack writes any cell a spreadsheet would run as a formula as text; the guided page escapes every value; both say who stands behind each item (SF-29). |
| Get a proposed rule, still in review, into a member's hands. | Packs and pages read distributed content only. The ISAC's reviewers see it in the review queue, not in a pack (SF-29). |
| Keep blocking an address long after it changed hands. | An indicator past its `valid_until`, or with none, is left out of the pack and the guided page; TAXII still serves it with the date, for a consumer to decide (SF-46). |
| A member, or the ISAC, reads another firm's lead-time statement, or walks organisation ids to find which are members. | A statement answers its own organisation only; everyone else, the ISAC included, gets the same 404 a made-up id gets (SF-70). |
| The ISAC ranks firms by how fast they act. | What a firm actioned is in its own statement only. The ISAC's sector median is computed from distribution dates, which no member's behaviour enters, and is withheld below k items so a quiet quarter does not become one vulnerability's timing. |
| Use the stored reading preference to see more. | It picks a rendering of what the caller may already read and nothing else; the authorization matrix runs every session principal with it set to the fullest depth. |

**What this does not stop.** A pack or a printout, once taken, is beyond
recall: an indicator revoked or expired after the download stays in the
member's block list until someone there honours the `valid_until` column the
pack carries (R17). Sigma rendering per SIEM dialect is not built: every
pySigma release from 1.0 on depends on `diskcache`, which has an open
advisory (pickle deserialisation, PYSEC-2026-2447) and no fixed version, and
suppressing it is not an option this repository takes. Members receive Sigma
rules as their pattern text, in the pack and over TAXII.


A member can still tell that a click the lane rule should have published went to
review, which says, as one bit, that the ISAC's view refused it. That is
accepted (R14): the alternatives are publishing content the ISAC's rules refuse,
or answering with the reason.

## Cross-cutting: notification cadence and the contentless digest

Phase H lets a member choose to hear hourly or daily instead of per
submission, and to have the digest emailed. That puts a mail relay -- a
subprocessor the ISAC names -- and a mailbox the member chose into the path.
What crosses is still a pointer, with two additions argued here: the affected
product names below RED, and the titles of CLEAR and GREEN items.

**Is a title content?** Yes. It is the submitter's own statement of the
finding in one line, and often the most valuable line: "Pre-auth RCE in Acme
Gateway 4.2" tells a reader what to attack. CLEAR and GREEN may be shared
across the community by their own definition, so their titles may cross the
relay; AMBER and above may not, so their digest line reads "an AMBER item
about Acme Gateway". Content email (SF-36) stays unbuilt, and so do the
controls it would need. Product names are a controlled field, not prose, and
are what a member's ticketing system routes on; RED never carries them,
because RED's audience is named people and a webhook endpoint is not one.

| What they try | What stops it |
| --- | --- |
| Read findings from a member's mail relay, its SOC queue, or a log that captures webhook bodies. | A digest carries markings, counts, links, products below RED, and only CLEAR and GREEN titles (SF-74). |
| Read the relay's traffic in transit, or impersonate the relay. | STARTTLS is required with the certificate verified; there is no setting to send in the clear or skip verification (SF-74). |
| Inject headers (a Bcc to an outsider) through a mailbox address or a subject. | The address is checked when set; `EmailMessage` refuses a header value with a line break, and the refusal is recorded, not sent (SF-74). |
| Learn, as a former member, what was shared after it left, from a digest held before it left. | Entitlement is checked again when the digest is sent; the held notices are spent, not kept (SF-61). |
| Keep announcements flowing during an incident. | Digests and digest email wait while distribution is paused, as notices do. |
| Change where a member is notified. | Only the people who may register its webhooks may change its cadence or mailbox, and each change is audited. |

**What this does not stop.** The relay sees that a member received N items of
each marking at a time, and the products of those below RED: a member's
interests, at the granularity it chose. That is the price of email, and why
email is opt-in per member (R18).

## Cross-cutting: email-to-draft

Mike's answer to Q39 opens a door members asked for: email a finding, and it
appears as a draft. Email is the one channel where the sender writes the
claim of who it is, so the door trusts nothing the message says about its
sender, and it can do only one thing: create a draft a person must submit.

| What they try | What stops it |
| --- | --- |
| Send as a member's analyst, with their address in From. | Only the topmost `Authentication-Results`, added by the ISAC's own receiving server, is read: it must carry the configured authserv-id and an aligned DMARC `pass` (SF-93). |
| Write their own `Authentication-Results: <ours>; dmarc=pass` into the message. | It sits below the receiving server's stamp and is never read; the server should also remove it (RFC 8601 §5). |
| Smuggle `;dmarc=pass header.from=<member>` into the server's own stamp, inside the envelope address an SPF result quotes. | Quoted-strings and comments, nested or not, are set aside before results are read; an unterminated one reads as nothing (T1's review). |
| Stop the intake for every member with one malformed message, or fifty. | A message the parser cannot read is refused and moved; one left by a storage error does not count against the run's batch (T1's review). |
| Have the intake erase other mail in the mailbox. | A message is moved by `UID MOVE`, or copied and expunged by its own UID; a server offering neither is refused (T1's review). |
| Put two addresses in From, aligned to one domain and read as another. | A From with anything but one address is refused before the lookup. |
| Email as a person of a suspended or quarantined member, or after an auditor's engagement ended. | The organisation's status, the person's activity, roles and end date are checked as a session would check them; each refusal is audited with its reason. |
| Get a draft distributed, or read content, by email. | It makes one draft, nothing more; a person submits it in the portal. `AuthMethod.EMAIL` is off the certificate-bound path, so checks made while filing see nothing above AMBER+STRICT or under embargo. |
| Learn which addresses AIVS knows, from replies. | No message gets a reply, accepted or refused. |
| Hide instructions in HTML for whoever reads the draft. | HTML parts are never read; only the plain-text part becomes the summary. |
| Flood a member's drafts, or the mailbox. | An hourly allowance per organisation; a size bound checked before a message is fetched; at most 50 messages a run. |
| Replay a message, or race two readers. | One row per message digest, unique, written before the draft is filed: a second reader waits on it and files nothing. |

**What this does not stop.** The rule is only as good as the receiving
server: a message delivered to the mailbox without its stamp has the
sender's header on top, which is why the runbook has the operator confirm
it before turning the intake on (R29). Nor does it decide who may be
registered at an address: the intake files a message into the organisation
of the operator registered at its From address, and nothing yet ties a
domain to an organisation (R30). A member's mail account, once
compromised, files drafts as that person, as a stolen session would; they
are drafts, and the member sees them.

## Cross-cutting: connection health, sandboxes, and government recipients## Cross-cutting: connection health, sandboxes, and government recipients

| What they try | What stops it |
| --- | --- |
| Learn from the connection page or a TIP snippet which collections exist, or another firm's state. | Both name only the caller's own organisation and the collections it reads; webhooks are shown by host, since a path can carry a routing token (SF-75). |
| Plant a line in a TIP snippet through a collection title. | A title is folded into a comment on one line; it cannot start a new option (SF-75). |
| Make an exercise read as engagement, or quietly re-label a real circle as a sandbox to change its figures. | Sandbox content is left out of telemetry reach and lead time, and the flag is set at creation and never changed after. |
| Learn from the sector-event listing or the dashboard that the ISAC holds a record the member cannot see. | Events are listed through the visibility gatherer: an event on a record the caller cannot read is absent, not refused (SF-77). |
| Pin a member's object, or a record not yet distributed, so that the pin announces it. | Only the ISAC's own record, distributed, can be pinned (SF-77). |
| Use call notes to publish around review. | The template files the notes as an ordinary ISAC draft; they reach members only through validation and distribution (SF-77). |
| Enrol a government body before members have agreed how its receipts are treated. | Both enrolment doors refuse a `government` organisation until the ISAC records that its agreement answers sharing-agreement §10 (SF-76). |

---

## Cross-cutting: reading the record (Phase H)

Phase H adds two reads of records rather than content: an auditor's stream of
the audit trail and receipts, and a member's evidence pack. Neither carries
intelligence, but the receipts stream says which firms attend to which
threats, and a firm's packs are its response history, so both are worth
taking with a stolen credential (`tests/abuse/test_audit_abuse.py` drives the
sequences):

| What they try | What stops it |
| --- | --- |
| A stolen auditor session reads content, or the firm's own records through routes that read by organisation. | An auditor's session is refused with 403 at the door, on the API and the portal, for every route but the audit read; repeated refusals raise `auditor_outside_audit` (SF-78). |
| A stolen auditor session pulls the whole receipts trail. | The read is authorised and audited as an act, with the count served; `auditor_bulk_read` raises past 20,000 events an hour from one auditor (SF-78). |
| An auditor's credential outlives the engagement it was issued for. | `role_expires_at` is required for an auditor, held alone, and refused at every session resolution and again per request (SF-78). |
| The ISAC's auditor, or whoever holds its session or its SIEM export, learns which firm filed which submission. | Content rows, and rows sharing their transaction, are served without organisation, actor, request id or address unless the ISAC acted, with `details` cut to an allow-list; findings that name a filer are cut to their summary; every action is classified and an unclassified one counts as content (SF-94). Residual R31. |
| A member's auditor reads other firms' activity through its own rows' `details`. | A member's auditor sees only rows recorded against its own organisation, and of their `details` only an allow-list of keys that describe its own action (SF-78). |
| A SIEM misses an event because a transaction committed after its cursor passed. | The stream pages on the writing transaction and serves only below the oldest one still running, so a late row is served late rather than skipped (SF-78). |
| A SIEM polling until a page comes back empty never finishes, because each read it makes is recorded and served back on the next poll. | A page that served only reads, or nothing, is recorded as `audit.read.quiet`, never served in either mode; in `full` mode the other reads are served, in `condensed` they are summarised (`audit.read.summary`). Either way the reads a poller can be served are finite, for one poller or two reading each other's (SF-78). Found when the suite hung once nothing else on the cluster held the horizon back. |
| Switching the audit stream's mode rewrites history: an export taken before the switch no longer matches one taken after, and the SIEM's chain breaks. | The mode is an append-only history, and each read is judged by the mode in force at its own transaction, so what was served stays served the same way; the switch itself is served as `audit_stream.mode_changed` (SF-78). |
| The ISAC, or another member, draws a member's evidence pack. | A pack is built for the caller's own organisation only, from what reached it, and the ISAC is refused with the body an unknown vulnerability gets (SF-79). |
| A stolen member credential harvests the firm's evidence packs. | Each draw is audited with the pack's hash; `evidence_pack_burst` raises when one organisation draws 20 in an hour (SF-79). |
| A posture change tells the ISAC the status through a receipt. | "We've acted" is a separate, explicit click; setting a posture writes no receipt (SF-79). |

## Cross-cutting: exploitability conditions (Phase N)

A condition note tells most members they are *not* affected. That makes it
the one kind of content whose error is silent: a wrong fix fails visibly when
applied, while a wrong condition leaves a member unpatched and sure of it. It
is also the most precise content the instance holds, naming the function or
setting an attacker needs before a patch exists.

| What goes wrong | What stops it |
| --- | --- |
| A malformed condition reads to a member's tooling as "no requirements" and clears everyone. | Conditions are typed terms, refused at ingest naming the note and term; an empty list is refused; such a note is always reviewed, never post-moderated (SF-83). |
| Two sources disagree, and a merged set narrows what one of them says is exposed. | A disagreement is `contested` with no merged set; standard depth lists each source's account, guided depth gives no conditions at all and says to treat yourself as affected (SF-84). |
| No source has spoken, and an empty answer reads as "not affected". | `not_established` says "assume affected", never an empty list; readiness's `scoping` is unavailable, never `none_available` (SF-84). |
| A member clicks "this doesn't hold for us" and is recorded not affected without deciding it. | The click fills the posture form and writes nothing; a condition the caller cannot see fills in nothing (SF-84). |
| A scanner reads an OSV record's missing product, range or symbol as "not affected". | The export is complete or refused with 409; one product it cannot carry refuses the whole record; what it drops only widens the record (SF-86). |
| A pre-patch condition, a roadmap to exploitation, reaches a wider circle than its own. | The view and the export read through the one visibility scope, at each note's latest visible version, so an embargoed or narrower circle's condition counts for, and contests, nothing outside it (SF-84, SF-8). |
| A source contests a correct set to push every member back to "assume affected". | It fails wide, not narrow; condition notes are reviewed before distribution, and a contested view names each source's note for the editor to resolve (R23). |

## Consolidated residual risk register

| # | Residual risk | Severity | Owner |
| --- | --- | --- | --- |
| R1 | A PostgreSQL superuser can drop the append-only triggers and rewrite the audit log. | High | Hosting ISAC — role separation, off-box audit shipping |
| R2 | AIVS cannot verify a submitter's `discovery_scope` claim. | High | Contract + reviewer training |
| R3 | A stolen-but-valid client certificate is indistinguishable from its owner. | High | Member key custody; ISAC `last_seen_at` review |
| R4 | The instance is a high-value target because it aggregates embargoed vulnerabilities affecting GSIBs. | High | Hosting posture as a whole |
| R5 | `stix_objects.raw` is not encrypted at rest by the application. | Medium | Volume/disk encryption in hosting requirements |
| R6 | An attacker inside the container network with the proxy shared secret can forge any organization identity. | Medium | Secret rotation; network segmentation |
| R7 | `record_independently` swallows its own failures — audit-write outages are silent. | Medium | Alert on the log line |
| R8 | Audit redaction is key-name based; a secret under an unlisted key is permanent. | Medium | Review of new audit detail keys |
| R9 | IP-allowlist mode is materially weaker than WireGuard mode. | Medium | Prefer overlay; document if not |
| R10 | Rate limiting exists at nginx, per certificate rather than per organization (per source address on the public member listener, B6); the application limits only contributions published without review and TAXII inbox posts (per organisation, SF-66). | Low | Keep the shipped nginx limits; revisit if the proxy is replaced |
| R13 | A post-moderated note's prose reaches members before an editor reads it. Closed for retraction: an editor revokes it with a newer `revoked` version (SF-66); what a member's TIP copied onward is beyond recall. | Low | Editors: post-moderation off by default, per circle; revoke |
| R14 | A contribution that goes to review although nothing the member can see requires it tells the member, as one bit, that the ISAC's view refused it. | Low | Accepted: the reason itself is shown to editors only |
| R15 | A member person's browser taken over — both the SSO session and device cookies — reads that firm's AMBER+STRICT content until the session ages out (8 h by default) or the operator or organisation is deactivated. OIDC back-channel logout is not built, so disabling the person at the IdP does not end a live session. | Medium | ISAC membership team; member endpoint security |
| R16 | The ISAC's member IdP tenant is in the trusted base for AMBER content: a compromised tenant, or a sign-on policy that the IdP misreports in `amr`, signs anyone in as a member person. | Medium | Hosting ISAC — tenant administration, phishing-resistant factors |
| R17 | An export, once downloaded or printed, is beyond recall: an indicator revoked or expired afterwards stays in a member's block list until the member honours the pack's `valid_until` column. | Low | Member firms; packs carry `valid_until` on every row |
| R18 | A member's digest relay learns how many items of each marking it received and when, and the affected products below RED. | Low | Member firms opt in per organisation; the ISAC names the relay as a subprocessor |
| R19 | The audit stream waits behind the oldest running transaction on the whole database cluster: a connection left idle in a transaction stalls the SIEM's feed (it never skips). | Low | Hosting ISAC — runbook §9.6; monitor for idle-in-transaction connections |
| R20 | A posture is kept as its current statement only, so an evidence pack shows the posture now and when it last changed, not its history. | Low | Member — draw and keep packs at the points a regulator will ask about |
| R21 | A member's auditor role is enforced but cannot yet be created: operators are created only from the host for the ISAC. | Low | Lands with member operator management (Phase L) |
| R22 | An agreed condition set that is wrong narrows exposure for every member relying on it: agreement is between sources, not a proof, and a member who checks a condition and finds it absent records itself not affected. | Medium | ISAC editors (review; `reproduced` and `unknowns` shown); members confirm with the stated check |
| R23 | A source can contest a correct condition set and return every member to "assume affected" for that vulnerability. | Low | ISAC editors resolve contested views; fails wide by design |
| R24 | Whoever holds the attribution key and a database dump recovers who filed what, anonymous filers included. | Medium | Hosting ISAC -- key kept apart from backups; rekey on suspected disclosure of the key alone (runbook §7.4a) |
| R25 | Closed in Phase P slice 3c. Between slices 3b and 3c, SQL on the member path could copy one row's owner tag or token onto another (no deny trigger on the keyed columns). | — | Closed: the member login holds no UPDATE on `submissions.owner_tag` or `stix_objects.owner_token` (SF-91), proved as that login |
| R26 | SQL on the member path can read every firm's receipts (`acknowledgments`, which SF-15 reserves to the ISAC's reviewers), postures (`org_postures`), circle memberships and distributions: confidential across members, though none says who filed what. | Medium | Operators left the member login in slice 3e (with every password hash); receipts and postures follow in the same slice |
| R27 | Closed in Phase P slice 3e. SQL on the member path could insert an operator row naming any organisation, the ISAC's included, because the member login inserted operators when a member's people first signed in through their IdP. | — | Closed: SSO provisioning runs on the staff login (`auth.staff_auth`), and the member login holds nothing on `operators` (SF-89, SF-91) |
| R28 | Closed in Phase P slice 3e. SQL on the member path could rewrite a peer operator's sign-in bookkeeping: reset `failed_login_count`, or push `last_totp_step` forward. | — | Closed: sign-in and its bookkeeping run on the staff login, keyed on the operator the certificate and password identified (SF-89, SF-91) |
| R29 | Email-to-draft trusts the ISAC's receiving mail server to stamp every message it delivers to the intake mailbox. A message delivered unstamped (a second delivery path, DMARC checking switched off) carries the sender's own `Authentication-Results` on top, and a forged pass for a registered address would make a draft in that member's name. | Low | The runbook (§9.7) has the operator test with a forged header before turning the intake on; the result is a draft, never a distribution, and the member sees it |
| R30 | Email-to-draft files a message into the organisation of the operator registered at its From address, and nothing ties a mail domain to an organisation. Whoever can register an address to an organisation (an ISAC operator; a member's IdP, where SSO creates operators from the `email` claim with no `email_verified` or domain check) can register another firm's person there, and that person's emails become the first organisation's drafts. The address being unique also keeps the real firm from registering it. | Medium | Q41: an ISAC-held list of each member's mail domains, checked at intake and at SSO linking; until answered, the intake stays off unless the ISAC controls every route by which an operator's email is set |
| R31 | The ISAC's auditor sees rows in commit order with their times. A member's request that writes a row in a transaction of its own (`record_independently`: a refusal, a rate limit) puts it milliseconds from the request's content rows, which are served without who did them; timing can pair the two. A request that files successfully writes no such row today. | Low | SF-94 pairs rows of one transaction; separate transactions are recorded, not closed |
| R11 | Webhook SSRF residual via DNS rebinding. | Low | Resolve-and-pin; egress policy |
| R12 | A member firm can poison the corpus with plausible false findings. | Low–Medium | Reviewer judgement |

---

## Assumptions this model rests on

1. The nginx configuration is deployed as shipped, with `ssl_verify_client on`,
   and every proxying location includes
   `snippets/aivs-identity-headers.conf`. A location added later that forgets it
   is a complete authentication bypass.
2. The application service publishes no host port.
3. `AIVS_ENVIRONMENT` is not `dev` on any host holding real content.
4. The application's database role is not a superuser and does not own
   `audit_log` or `submission_transitions`.
5. Member firms protect their client certificate private keys.
6. The CA root is offline (see [`deployment-topology.md`](deployment-topology.md)).

Break any one of these and the corresponding section above is void.
