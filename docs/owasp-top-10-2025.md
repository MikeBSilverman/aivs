# AIVS against the OWASP Top 10:2025

The OWASP Top 10:2025 was announced at Global AppSec in November 2025 and
finalised in January 2026. Two categories are new — **A03 Software Supply Chain
Failures** and **A10 Mishandling of Exceptional Conditions** — and SSRF is no
longer its own category, having been folded into **A01 Broken Access Control**.

This document records where AIVS stands against each category, what enforces it,
and what is still open. It is a self-assessment, not a certification. Every
"enforced by" entry names a file so the claim can be checked rather than taken.

The assessment below was produced alongside a sharded review of the whole
codebase; findings from that review are marked **[fixed]** where the control now
described is the result of a repair rather than the original design.

---

## A01:2025 — Broken Access Control (now includes SSRF)

The category AIVS lives or dies on. Every authorization decision routes through
one module.

| Control | Where |
|---|---|
| Single deny-by-default decision point | `auth/policy.py` |
| One shared visibility predicate for content | `visible_content_clause`, used by `taxii/queries.py` and the portal dashboard **[fixed]** |
| Deny-by-default proven by test, not by reading | `tests/authz_matrix/` — every route × every principal |
| Absent and forbidden are indistinguishable | 404 for another org's submission, webhook, collection, certificate **[fixed]** |
| SSRF on the one member-supplied URL | `notify/webhooks.py`: https only, resolve → judge every returned address → pin the connection to the judged address, redirects disabled |

**Fixed in this review.** The portal dashboard restated the visibility predicate
by hand and was missing one of its three conditions; certificate revocation
answered 403 for another organisation's certificate and 404 for an unknown one,
making it an existence oracle; the TAXII `can_read` flag was stored and
advertised but never consulted; and `match[version]=last` resolved across every
submission in a circle rather than within one, so a member who re-submitted a
peer's `stix_id` with a later timestamp took over the default feed and the peer's
warning stopped being delivered.

**Closed since this assessment.** Both halves of the delegated-circle-admin
finding are fixed. Visibility now carries a membership-start term
(`date_added >= joined_at`, per circle), so joining a circle grants participation
rather than its back catalogue; and `can_administer_circle` is the hosting ISAC
alone. Admitting an organisation to a circle holding other members' embargoed
intelligence is a read-in, and it belongs with the party the sharing agreement
runs to.

---

## A02:2025 — Security Misconfiguration

The category the deployment layer answers to.

| Control | Where |
|---|---|
| Startup refuses an unsafe posture | `Settings.validate_production_posture` — allow-listed to `dev`, never "deny only production" |
| Dev bypasses inert everywhere else | `dev_trust_unauthenticated_proxy`, `dev_expose_error_detail`, `dev_allow_private_webhook_targets` |
| Placeholder secrets fail closed **[fixed]** | `_secret_is_not_a_placeholder` refuses any secret still containing `REPLACE_ME` |
| Issuer pin required outside dev, by signature **[fixed]** | `issuing_ca_certificate_file` is a production-posture violation when unset; every presented and registered certificate must be *signed* by that CA, with `CA:FALSE` and `clientAuth` -- an earlier issuer-name comparison accepted a self-signed certificate carrying the right name |
| Proxy allowlist cannot be `/0` **[fixed]** | `trusted_proxy_cidrs` rejects a prefix length of 0 |
| Interactive docs only in dev **[fixed]** | `/docs` and `/openapi.json` mounted only when `environment == "dev"` |
| Security headers on every response **[fixed]** | `middleware.security_headers_for`, reapplied by the 500 handler that does not traverse the middleware stack |
| Container hardening | `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, non-root users, tmpfs with `noexec,nosuid,nodev` |

**Fixed in this review.** The shipped `deploy/env.example` placeholders were long
enough to pass the 32-character minimum, and compose's `${VAR:?}` guard only
fires on unset or empty — so an operator who edited the values needed to bring
the stack up and missed the secrets got a running production instance whose
proxy-authentication secret and cursor-signing key were published in this
repository, with every healthcheck green. The dev compose override also *added*
its port mapping to the base file's rather than replacing it, because `ports` is
a multi-value option that Compose concatenates; `!override` now pins it.

---

## A03:2025 — Software Supply Chain Failures (new)

| Control | Where |
|---|---|
| Single committed lockfile | `uv.lock`, workspace-wide |
| Dependency audit fails the build **[fixed]** | `pip-audit --strict` over the exported lockfile. The gate was `--skip-editable --strict`, which in a uv workspace could only ever fail: the three workspace members install as editable and `--strict` counts every skipped distribution as an error. It had been red without anyone noticing. |
| Reproducible SBOM **[fixed]** | `scripts/generate-sbom.sh` — CycloneDX 1.6 from the frozen lockfile, runtime dependencies only, byte-identical for an unchanged lock so two releases can be diffed |
| Image SBOM including the OS layer **[fixed]** | pinned syft scan in the Package stage; a Python-environment scan cannot see the Debian base, which is most of what a member firm's scanner flags |
| Base images pinned by tag, overridable by digest | `packages/aivs-server/Dockerfile` |
| Build toolchain pinned **[fixed]** | CI installs the same uv version the Dockerfile uses, rather than piping the unversioned installer |
| Two-stage build leaves no compiler or installer in the runtime image | `Dockerfile` |
| No CDN, no external fetch at runtime | portal CSP is `default-src 'none'`; fonts and CSS are served from the package |

**Open.** No signed provenance or attestation for the published image. The two
SBOMs are published as build artifacts but nothing attests that a given image was
built from a given source commit. Sigstore/cosign attestation is the next step,
and matters more once an ISAC is pulling images rather than building them.

---

## A04:2025 — Cryptographic Failures

| Control | Where |
|---|---|
| Argon2id for operator passwords, with rehash on login | `auth/passwords.py` |
| Session and CSRF tokens stored only as SHA-256 | `db/models.py`, `auth/sessions.py` |
| `secrets.token_urlsafe(32)` for every minted token | `auth/sessions.py`, `api/admin.py` |
| Constant-time comparison wherever a token is checked | `hmac.compare_digest` throughout |
| SHA-256 for certificate identity, never the proxy's SHA-1 | `auth/mtls.py` |
| TLS 1.2+1.3, AEAD suites only, no session tickets | `deploy/nginx/nginx.conf` |
| Client pins the ISAC CA **and** presents its certificate **[fixed]** | `aivs_client/transport.build_ssl_context` |

**Fixed in this review.** The reference client passed a CA bundle *path* to
httpx's `verify=`. In httpx 0.28 that branch of `create_ssl_context` returns
before the block that calls `load_cert_chain`, so configuring the CA pin
silently discarded the client certificate: every request went out
unauthenticated and came back 401, and the only configuration that worked was
the one that dropped the pin and fell back to the system trust store. The
context is now built explicitly, and the CA bundle is a required setting.

**Closed.** `totp_secret_encrypted` and `hmac_secret_encrypted` were **base64,
not encryption**, for as long as they existed: a database read yielded every
operator's working second factor and every member's webhook signing key. They
are now sealed by `auth/secretbox.py` — an AEAD under a key held in the process
environment, bound by additional authenticated data to the id of the row they
belong to, so a sealed value cannot be moved between rows or reused for another
purpose. AES-256-GCM by default, ChaCha20-Poly1305 also registered; **every
stored value names the algorithm and key it was written with**, so replacing
either is a re-wrap performed at leisure rather than a migration performed under
whatever pressure made it necessary. Migration `a1c7e2b93d45` re-seals existing rows and requires the
key to be present, so the base64 read path is gone from the codebase rather than
retained as a fallback nobody would ever remove.

Note that `docs/threat-model.md` asserted "encrypted at rest by the application"
for both columns while this was still base64. The claim is true as of this
change; it was not before, and a claim in a threat model is exactly the kind
that gets believed rather than checked.

**Residual, stated rather than implied.** The key lives beside the database
credentials, so a full host compromise defeats it. What it defeats is the
realistic set — a stolen backup, a read replica, a SQL-level disclosure, a
support engineer with `SELECT` and no access to the application's environment —
which is the category that appears in incident reports. Moving the key into an
HSM or cloud KMS is a provider swap behind the same interface, not a redesign.

---

## A05:2025 — Injection

| Vector | Status |
|---|---|
| SQL | No raw SQL anywhere in application source. Every query is SQLAlchemy Core/ORM with bound parameters; the only `text()` is `SELECT 1` in the readiness probe. Verified by grep and by semgrep's `p/python` and `p/owasp-top-ten` rulesets, which now run as a build gate rather than as the one-off local scan this line originally described **[fixed]**. |
| Command | No `subprocess`, `os.system`, `os.popen`, `eval`, `exec`, or `__import__` in any package. |
| Deserialisation | No `pickle`, `marshal`, `shelve`, or `yaml.load`. STIX ingest is `json.loads` plus a JSON Schema validator and an explicit extension allowlist. |
| XXE | No XML parsing. |
| Template | Jinja2 autoescaping active on all five templates; no `\|safe`, no `Markup`, no `{% autoescape false %}`, and no value placed in a script, `href`, `style`, or event-handler position. |
| Terminal control sequences **[fixed]** | Member-supplied titles and names are refused at ingest if they contain control characters, and escaped again on output by the reference CLI. |

**Fixed in this review.** Titles were bounded in length but not in content, and
the CLI printed them raw into a one-record-per-line listing — so an embedded
newline forged a row for a submission that did not exist and a carriage return
overwrote a real one, in an ISAC operator's terminal.

---

## A06:2025 — Insecure Design

The design decisions the threat model rests on, and the ones this review
strengthened.

| Decision | Where |
|---|---|
| Read-time timestamp is the authoritative embargo gate; the scheduler only bookkeeps | `services/embargo.py`, `auth/policy.py` |
| Three stacked controls for proxy-derived identity | no published app port · nginx unconditionally overwrites · shared secret + peer allowlist |
| The app re-parses the certificate rather than trusting the proxy's verdict | `auth/mtls.py` |
| Anonymity checked at ingest **and** at distribution **[fixed]** | `services/submissions.py`, `services/distribution.py` |
| Attribution assigned by the server on both paths **[fixed]** | `services/distribution._apply_attribution` |
| Append-only audit enforced in the database, not only in code | statement-level triggers on `audit_log` and `submission_transitions` |

**Fixed in this review.** `distribute_anonymously` could be turned on by a PATCH
carrying no bundle, which skipped the identity-SDO check entirely — so a draft
that legitimately carried the submitter's own `identity` object while attributed
kept it after being made anonymous, and that name went to every circle member
alongside a finding the submitter had been told was anonymous. Separately,
`created_by_ref` was never bound on the attributed path, so a member could file
content under a peer's STIX identity.

**Open.** There is no supersede verb, so `SUPERSEDED` and `superseded_by_id` are
unreachable and a distributed submission is terminal. The webhook delivery
pipeline has no caller: a member registers a URL, is handed a signing secret, and
never receives anything. Both are features the schema describes and the system
does not keep — either wire them up or remove them.

---

## A07:2025 — Authentication Failures

| Control | Where |
|---|---|
| Organisation authenticates by client certificate, re-derived per request | `auth/mtls.py`, `auth/deps.py` |
| Human authenticates by password + TOTP | `auth/sessions.authenticate_operator` |
| Session bound to the organisation's certificate, re-checked every request | `auth/sessions.resolve_session` |
| Binding is unconditional **[fixed]** | a session with no certificate is refused rather than resolving to a full context |
| Certificate expiry re-checked on the portal path too **[fixed]** | matches the machine path |
| Revocation effective on the next request; live sessions closed at revocation time | `api/admin.revoke_certificate` |
| Unknown operator and wrong password are indistinguishable | dummy-hash verification |
| Lockout after repeated failures | 5 attempts / 15 minutes |

**Fixed in this review.** Portal login resolved the organisation without checking
either the certificate's status or the organisation's, so the holder of a
*revoked* certificate still reached the full credential check — a working
password/TOTP oracle for exactly the compromised-credential case revocation
exists for, which also reset the operator's lockout counter and wrote a
`LOGIN_SUCCESS` audit row for an access policy grants nothing. Three independent
reviewers found this one.

---

## A08:2025 — Software or Data Integrity Failures

| Control | Where |
|---|---|
| Inbound STIX validated against a schema with no remote `$ref` resolution | `extension/builders.py` |
| Extension allowlist, now including nested objects **[fixed]** | `assert_extensions_allowed` |
| Submitted `extension-definition` objects refused **[fixed]** | a submitter cannot redefine how members interpret AIVS content |
| Submitted `marking-definition` objects reusing a TLP identifier refused **[fixed]** | TLP identifiers mean one thing everywhere |
| Webhook payloads signed HMAC-SHA256 over timestamp + body | `notify/webhooks.sign_payload` |
| Audit log immutable at the database level | append-only triggers |

**Fixed in this review.** The extension allowlist read only the top-level
`extensions` key, so an `observed-data` object carrying embedded SCOs with their
own extensions passed untouched and was redistributed verbatim. And because
`validate_bundle` had no notion of object *type*, a submitter could include an
`extension-definition` re-declaring the AIVS extension id with a `schema` URL
they controlled, or a `marking-definition` claiming the spec-fixed TLP:RED
identifier with a TLP:CLEAR body — both delivered to every member's platform.

---

## A09:2025 — Security Logging & Alerting Failures

| Control | Where |
|---|---|
| Append-only audit trail, database-enforced | `audit/log.py` + triggers |
| Every mutation and every denial recorded | `record`, `record_independently` |
| Retrieval receipts — who collected what, and when | `services/receipts.py`; this is the regulatory "we warned you / they retrieved it" artefact |
| Recursive redaction of secrets from logs and audit details | `logging_config._scrub`, `audit.log.redact` |
| SQL echo forced off; statements carry submission titles | `db/engine.py` |
| Request correlation id spans proxy and app **[fixed]** | `header_request_id` is now normalised to lowercase like its three siblings |
| One event, one audit row **[fixed]** | portal submission wrote `SUBMISSION_CREATED` twice |

**Fixed in this review.** `header_request_id` was omitted from the validator that
lowercases the other three header-name settings, so configuring it as the natural
`X-Request-Id` meant it silently never matched: every request got a fresh id and
the proxy access log could no longer be joined to the application log, with
nothing logged to say so.

**Open.** There is no alerting. The audit trail is complete and queryable, and
nothing watches it. For an ISAC deployment, failed-login bursts, denied-access
patterns and webhook delivery failures are the three worth a signal.

---

## A10:2025 — Mishandling of Exceptional Conditions (new)

The new category, and the one this review moved the most.

| Control | Where |
|---|---|
| Production posture fails closed, not open | `validate_production_posture` returns early only for `dev` |
| Embargo holds even when the sweeper is dead | visibility is the timestamp, checked per read |
| Distribution is one transaction: fully committed or fully rolled back | `services/distribution.py` |
| Constraint violations surface as 4xx describing the caller's mistake | `_STORAGE_ERRORS` handling in `api/submissions.py` |
| Unhandled exceptions disclose nothing outside dev | `main._unhandled` |
| 500 responses now carry the full security header set **[fixed]** | `_unwrapped_error_response` |
| Operator form errors are 4xx with a message, not a 500 **[fixed]** | portal distribute form parsing moved inside the handled block |
| A failed workflow verb tells the operator it failed **[fixed]** | signed one-shot notice cookie |

**Fixed in this review.** Three failures of exactly this category. Starlette
routes the `Exception` handler to `ServerErrorMiddleware`, which sits *outside*
the user middleware stack — so the one response a member is most likely to report
carried no CSP, no `Cache-Control: no-store` and no correlation id. The portal
parsed the distribute form outside its `try`, so clicking Distribute without
selecting a circle produced a 500. And every workflow failure redirected to the
same page as a success with no message at all: an operator whose distribution was
refused by a circle's TLP floor was shown the detail page and would reasonably
conclude the members had been warned.

---

## Summary

| Category | Standing |
|---|---|
| A01 Broken Access Control | Strong. The delegated-circle-administration question is settled: the hosting ISAC alone. |
| A02 Security Misconfiguration | Strong after this review. Placeholders and the issuer pin now fail closed. |
| A03 Supply Chain | Strong. Reproducible SBOM for the app and the image; signed provenance is the remaining gap. |
| A04 Cryptographic Failures | Strong in transit and for passwords. Secrets at rest are base64 and honestly labelled; envelope encryption is designed, not built. |
| A05 Injection | No known vector. Verified by inspection and by semgrep, in CI. |
| A06 Insecure Design | Strong. Two features described by the schema and not implemented. |
| A07 Authentication Failures | Strong after this review. |
| A08 Integrity Failures | Strong after this review. |
| A09 Logging Failures | Strong on recording, absent on alerting. |
| A10 Exceptional Conditions | Fixed in four places by this review. |

**Sources.** [OWASP Top 10:2025 Introduction](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
