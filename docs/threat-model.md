# AIVS threat model

Scope: one AIVS instance — the Python application, its PostgreSQL database, its
reverse proxy, and the network path member firms reach it over. Analysis is
STRIDE per trust boundary.

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

---

## B1. Internet → WireGuard overlay / IP allowlist

**What crosses:** raw IP packets from member firm egress addresses.
**Assets exposed:** the existence and reachability of the service.
**Relevant actors:** internet attacker, nation-state.

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S** | Attacker spoofs a member's source address to enter the allowlist. | WireGuard mode: a peer is authenticated by its Noise-protocol static public key, not its address; a spoofed source cannot complete the handshake. Allowlist mode: source-address filtering only. | **Allowlist mode is materially weaker than overlay mode.** It resists scanning, not a determined attacker with a path to spoof or a foothold at a member's egress. Prefer WireGuard. |
| **T** | Packet injection into an established flow. | WireGuard AEAD (ChaCha20-Poly1305) on every packet; TLS 1.3 above it in both modes. | Negligible. |
| **R** | Attacker denies having connected. | WireGuard peer keys are per-member and logged; the app records `source_ip` on every audit row (`audit_log.source_ip`, INET). | Shared-NAT egress collapses several member hosts to one address. Certificate fingerprint, not IP, is the identity of record. |
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
| **S** | Present a **stolen but genuine** member certificate. | Revocation is a status flip on `client_certificates.status`, checked on every request against an indexed unique constraint — effective within one request, no CRL propagation delay. `last_seen_at` supports "this cert last appeared from an unusual place" review. | **AIVS cannot distinguish a stolen key from its legitimate holder.** Detection depends on the member noticing, or an operator reviewing `last_seen_at` and audit patterns. This is the most realistic path to member-tier data. |
| **S** | Present an expired certificate that a misconfigured proxy accepted. | The application re-checks `not_valid_before_utc` / `not_valid_after_utc` itself, with a 5-minute skew tolerance (`_check_validity_window`). Explicitly defends against `ssl_verify_client optional` being left in place or a stale trust store. | None material. |
| **T** | Downgrade or strip TLS. | `ssl_protocols TLSv1.2 TLSv1.3` — 1.0 and 1.1 absent. TLS 1.2 retains AEAD-only, forward-secret suites (no CBC, no static RSA, no SHA-1). Session tickets are off, so a stolen ticket key cannot retroactively decrypt resumed sessions. The overlay carries no cleartext path. | TLS 1.2 is retained only for member security appliances that cannot do 1.3, and it is a weaker floor than 1.3-only. Remove it once the member base allows. |
| **R** | Member denies having polled. | Identity is the SHA-256 fingerprint of the presented certificate, computed by the **application** from the forwarded PEM — not nginx's `$ssl_client_fingerprint`, which is SHA-1 and is deliberately not trusted. `acknowledgments` rows record retrieval; `audit_log` records the request. | A member can argue their key was stolen. The agreement should place key-custody obligations on the member (see the sharing agreement outline). |
| **I** | Certificate chain reveals the member set to a passive observer. | Client certificates are sent encrypted in TLS 1.3. | The server certificate and SNI still identify the instance. |
| **D** | Handshake flood; oversized certificate chains to burn ASN.1 parsing CPU; a member polling far harder than needed. | nginx: `limit_req_zone`/`limit_conn_zone` keyed on `$ssl_client_fingerprint` at 20 r/s, burst 40, plus 64 connections per source address, answered **429**. `ssl_verify_depth 2`. `client_max_body_size 5m`. Application: `MAX_CERT_HEADER_BYTES = 16 KiB` before any parse; `AIVS_MAX_BODY_BYTES` (default 5 MiB); `AIVS_DB_STATEMENT_TIMEOUT_MS` (default 15 s) so one runaway query cannot pin a connection. | Quotas are per certificate, so a member with several certificates has several buckets. Bucketing on a SHA-1 fingerprint is fine — a collision costs a shared quota, not an identity. The **application** still has no per-organization quota; if nginx is replaced or bypassed, that protection goes with it. |
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
| **S** | Bypass by disabling the proxy check. | `dev_trust_unauthenticated_proxy` exists but `validate_production_posture()` refuses to construct a production `Settings` with it enabled — the process will not start. Same for `dev_expose_error_detail`, `dev_allow_private_webhook_targets`, empty `trusted_proxy_cidrs`, non-HTTPS `public_base_url`, and `log_level=DEBUG`. | Relies on `AIVS_ENVIRONMENT` being correct. It defaults to `production`, so the failure mode of forgetting it is the strict one. |
| **T** | Tamper with the forwarded certificate to change the fingerprint. | The app parses the PEM and computes SHA-256 itself; any modification produces a fingerprint with no matching `client_certificates` row. Malformed input raises `CertificateRejection`, never a traceback. | None material. |
| **R** | A member forges audit-trail correlation ids, or deliberately collides with another member's requests. | nginx sets `X-Request-Id` to its own `$request_id` unconditionally, never passing the client's through. The value propagates into every audit row and application log line. | None material, provided the shipped identity-headers snippet is used. Any proxying location that omits it breaks this. |
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
| **T** | Alter or delete audit records to hide an action. | Migration `c185fd428721`: `BEFORE UPDATE / DELETE / TRUNCATE` triggers on `audit_log` and `submission_transitions` raising `insufficient_privilege`; `FOR EACH STATEMENT` so a probe fails identically whether or not the row exists; `REVOKE UPDATE, DELETE, TRUNCATE … FROM PUBLIC`; and where `AIVS_APP_DB_ROLE` is set, `GRANT INSERT, SELECT` only. The trigger function pins `SET search_path = pg_catalog` so a caller-controlled schema cannot shadow what it resolves. | **A superuser — or the table owner — can `DROP TRIGGER` or `ALTER TABLE … DISABLE TRIGGER` and then rewrite history.** This is unavoidable in PostgreSQL and is stated as such in the migration itself. Mitigation is operational: the app must not connect as superuser or table owner, and audit content must be shipped off-box (see §7). |
| **T** | SQL injection. | SQLAlchemy Core/ORM with bound parameters throughout. The one place DDL identifiers are interpolated (migration `c185fd428721`) validates them with `_quote()`, which refuses anything non-alphanumeric-plus-underscore, even though the values are module constants. Database check constraints independently enforce formats (`^[0-9a-f]{64}$` fingerprints and token hashes, slug patterns, `identity--` prefixes) so a parsing-layer bug cannot store a value that later fails to match. | — |
| **T** | Corrupt a distribution's `date_added` to release content early. | Ordinary table, so an actor with write access can. The check constraints (`distributed_has_timestamp`, `timer_requires_release_at`, `released_has_timestamp`) constrain shape, not intent. | An attacker with database write access owns the system. Accepted; the boundary that matters is B3. |
| **R** | An action leaves no trace. | Denials and auth failures use `record_independently()`, which commits in its own transaction because the request's transaction is about to roll back. Successes use `record()`, which commits with the change it describes. | `record_independently` **swallows** its own write failures (logged via `logger.exception`, not raised) — a deliberate trade so an audit outage does not turn a clean 403 into a 500. It means an audit-write outage is silent to the caller. **Monitor for `failed to write independent audit record` in application logs.** |
| **I** | A database dump discloses everything. | Passwords are Argon2id hashes; TOTP secrets and webhook HMAC secrets are encrypted at rest by the application; portal session tokens are stored only as SHA-256, so a dump yields no live sessions. | **`stix_objects.raw` is plaintext.** That is the crown jewel and it is not encrypted at rest in the application layer. Encryption is a storage-layer responsibility (full-disk / volume encryption) and must be in the hosting requirements. |
| **I** | Secrets leak into the audit log, which is immutable and therefore un-redactable. | `audit.log.redact()` strips a fixed key list (`password`, `totp_secret`, `hmac_secret`, `token`, `csrf_token`, `api_key`, `private_key`, `authorization`, `cookie`, `proxy_auth`, …) at every nesting depth, caps strings at 2,000 characters, lists at 100 elements, and recursion at depth 6. | The list is **key-name based**. A secret placed under an unlisted key name, or embedded in a free-text field, is written permanently and cannot be removed afterwards, precisely because the table is immutable. Adding a detail key is a change that deserves review. |
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
| **I** | **SSRF**: a member registers `https://169.254.169.254/…` or an internal address and turns AIVS into a probe of the ISAC's own network. | Delivery refuses private, loopback, and link-local targets. The bypass `dev_allow_private_webhook_targets` is named "in any real deployment this being true is an SSRF hole" in the config, and `validate_production_posture()` refuses to start production with it set. | DNS rebinding (resolve public at validation, private at connect) is the classic residual. Resolve-then-pin at connect time, and consider an egress policy that permits only outbound 443 to non-RFC1918 destinations. |
| **I** | Notification payload discloses embargoed content to an endpoint that should not have it. | Design constraint: notifications carry **metadata and identifiers**, never embargoed object bodies. Members fetch content over authenticated TAXII. | Enforced by the notification payload builder, not by a schema. Worth a conformance test. |
| **D** | A slow or hostile endpoint stalls delivery workers. | `AIVS_WEBHOOK_TIMEOUT_SECONDS` (default 5 s, max 30); `AIVS_WEBHOOK_MAX_ATTEMPTS` (default 5); `consecutive_failures` per webhook supports auto-disable. | A member can generate outbound load by registering a slow endpoint. Bounded, not eliminated. |
| **E** | — | Webhook delivery runs with no authorization context; it cannot read content it was not handed. | — |

---

## Cross-cutting: the malicious or compromised member

Worth pulling out, because it is the actor most people underestimate.

| What they try | What stops it |
| --- | --- |
| Read a circle they are not in. | `can_read_circle` checks `circle_id in ctx.circles` and nothing else. `distribution_visibility_clause` restricts every read to `readable_circle_ids(ctx)`, which returns the **empty set** for an inactive org — and an empty set produces `or_(False)`, a clause matching no rows, rather than an unconstrained `IN ()`. The safe failure mode is asserted in tests. |
| Read content before its embargo lifts. | `Distribution.date_added <= now`, evaluated in SQL on every read. Not scheduler-dependent. |
| Distribute their own submission without ISAC review. | `can_transition_submission` grants `validated` and `distributed` **only** to a system administrator. |
| Submit into a circle they only read. | `can_submit_to_circle` requires `contributor`. |
| Learn who read their submission — or anyone else's. | `can_view_submission_receipts` is restricted to the submitter and the ISAC. |
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

1. The enum has no value for third-party software, so a submitter must
   affirmatively mis-state their relationship rather than merely omit it.
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
creates. What a `system_admin` can legitimately do:

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
- `AIVS_ENVIRONMENT` left at a non-production value on a production host,
  disabling `validate_production_posture()`.
- A reviewer approving submissions faster than they can actually assess scope,
  because the queue is long.

None of these are code defects, and none are fixed by code. They are the content
of [`operator-runbook.md`](operator-runbook.md), and they should be audited
against, not assumed.

---

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
| R10 | Rate limiting exists only at nginx, per certificate rather than per organization; the application has none of its own. | Low | Keep the shipped nginx limits; revisit if the proxy is replaced |
| R11 | Webhook SSRF residual via DNS rebinding. | Low | Resolve-and-pin; egress policy |
| R12 | A member firm can poison the corpus with plausible false findings. | Low–Medium | Reviewer judgement |

---

## Assumptions this model rests on

1. The nginx configuration is deployed as shipped, with `ssl_verify_client on`,
   and every proxying location includes
   `snippets/aivs-identity-headers.conf`. A location added later that forgets it
   is a complete authentication bypass.
2. The application service publishes no host port.
3. `AIVS_ENVIRONMENT=production` on production hosts.
4. The application's database role is not a superuser and does not own
   `audit_log` or `submission_transitions`.
5. Member firms protect their client certificate private keys.
6. The CA root is offline (see [`deployment-topology.md`](deployment-topology.md)).

Break any one of these and the corresponding section above is void.
