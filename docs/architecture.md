# AIVS architecture

AIVS is the platform an ISAC runs to manage intelligence across the whole life
of a vulnerability — from a pre-CVE, AI-discovered finding under embargo,
through CVE issuance and enrichment, to the detection, mitigation, control and
verification work defenders do — with the ISAC, its members and vendors
creating, cultivating, reviewing and distributing it together. It is deployed
as "ISAC-in-a-box": one instance, one ISAC, one tenant.

What is built today is the first stage of that life: structured, embargoed
early warning about AI-discovered vulnerabilities, carried between a hosting
ISAC and its member firms in the window *before* a CVE exists. The later
stages reuse its machinery — circles, embargoes, attribution, receipts, the
editorial checkpoint — rather than adding a second one. The README's status
table says which stages are built, designed or planned.

**The name.** "AIVS" is the product's name for now, and no rename is decided.
Whatever it is later called, the internal `aivs` names — packages, modules,
settings, database objects, the ciphertext magic — stay as they are, because
they are on disk and in members' configuration where a rename would break
things and gain nothing.

This document describes the system as it is built — the packages, the request
lifecycle, and the two or three design decisions that are load-bearing enough
that changing them would break correctness rather than merely style.

---

## 1. The three packages

The repository is a `uv` workspace (`pyproject.toml`, `[tool.uv.workspace]`)
containing three distributable packages.

| Package | Installed by | Responsibility |
| --- | --- | --- |
| `aivs-schemas` | server, client, **and member firms** | The shared contract: vocabulary enums, the submission state machine, TLP 2.0 marking constants, and the AIVS STIX 2.1 property-extension with its JSON Schema and typed builders. |
| `aivs-server` | the hosting ISAC only | TAXII 2.1 endpoints, the native REST API, the analyst portal, the authorization decision point, the audit writer, and webhook delivery. |
| `aivs-client` | member firms | Reference Python SDK and the `aivs` CLI: local key/CSR generation, cursor-tracking polling, submission, acknowledgment. |

`aivs-schemas` is deliberately dependency-thin (`pydantic`, `stix2`,
`jsonschema` — nothing else). Its own `pyproject.toml` records why: member firms
import it into their environments, so every dependency added there lands in a
GSIB's software bill of materials.

The state machine, the TLP identifiers, and the extension schema live in
`aivs-schemas` rather than in the server so that the server, the CLI, the
portal, and the tests cannot form different opinions about what a legal
transition or a valid marking is.

### Package boundaries that matter

- **`stix2` is touched in exactly one file.** `aivs_schemas/extension/builders.py`
  is the only module that imports the `stix2` library. Everything else works with
  plain dictionaries or the typed builders. `stix2` ships no type stubs, and
  `mypy` is configured `strict`; confining the untyped surface to one reviewable
  file is the point.
- **`auth/policy.py` is the only place authorization is decided.** Routers call
  its predicates; they never re-implement a rule inline. See
  [`authz-model.md`](authz-model.md).
- **`AuthContext` holds identity, not permission.** It is a frozen dataclass with
  no method answering "may they do this" — that separation is what makes the
  authorization matrix tests meaningful.

---

## 2. Domain model in one paragraph

An **organization** is a member firm, or the hosting ISAC itself
(`org_type = admin`). Organizations join **circles**, which are the unit of trust
tiering — "Section 9", "GSIB", "AI supply chain" — with a role of `member`,
or `contributor`. Each circle is projected outward as one TAXII
**collection**. A member creates a **submission**, attaches STIX objects to it,
and moves it to `submitted`. The hosting ISAC reviews it, moves it to
`validated`, then to `distributed`; distribution writes one **distribution** row
per (STIX object × circle). Reads are gated on those rows. Every retrieval writes
an **acknowledgment**; every security-relevant action writes an **audit log**
row. Neither table can be updated or deleted.

```
Organization ──< CircleMembership >── Circle ──< TaxiiCollection
     │                                   │
     │ submits                           │ visibility scope
     ▼                                   │
 Submission ──< StixObject ──< Distribution ┘
     │              (materialised: object × circle × date_added)
     ├──  Embargo (0..1)
     ├──< SubmissionTransition   (append-only)
     └──< Acknowledgment         (receipts)
```

---

## 3. The submission lifecycle

The state machine is declared once, in
`aivs_schemas.enums.SUBMISSION_TRANSITIONS`. Anything not listed is forbidden;
there is no implicit self-transition.

```
draft ──► submitted ──► validated ──► distributed ──► superseded
  │        ▲  │  │          │
  │        │  ▼  │          │
  │      returned│          │
  │          │   │          │
  └──────────┴───┴──────────┴──────► withdrawn
```

| From | To | Who may perform it |
| --- | --- | --- |
| `draft` | `submitted` | the submitter org |
| `draft` | `withdrawn` | the submitter org, or the hosting ISAC |
| `submitted` | `validated` | **the hosting ISAC only** |
| `submitted` | `returned` | **the first pass only**, never a person (`services.triage`) |
| `submitted` | `withdrawn` | the submitter org, or the hosting ISAC |
| `returned` | `submitted` | the submitter org |
| `returned` | `withdrawn` | the submitter org, or the hosting ISAC |
| `validated` | `distributed` | **the hosting ISAC only** |
| `validated` | `withdrawn` | the submitter org, or the hosting ISAC |
| `distributed` | `superseded` | the submitter org, or the hosting ISAC |
| `superseded`, `withdrawn` | — | terminal |

`returned` is Phase O's: the first pass reads every submit, and sends a
member's own filing back with what to change when the content is wrong or no
tool can use it (SF-87). It is editable like a draft. Resubmitted unchanged,
it goes to review with its notes and is never returned twice for the same
content. No person is offered the move, so a return always means "the rules
found this".

Two properties of this diagram are structural controls, not conveniences:

**`validated` and `distributed` are reserved to the hosting ISAC.**
`auth.policy.can_transition_submission` grants those two targets only to a system
administrator. This is the human checkpoint that keeps AIVS clear of the
coordinated-disclosure consent problem: a member firm can upload content, but it
can never distribute it. Content reaches other members only when the ISAC has
decided it should. Combined with the `discovery_scope` field (see below), this is
how v1 stays out of the business of brokering undisclosed third-party
vulnerabilities.

**Nothing can be un-distributed.** `distributed` transitions only to
`superseded`. Once members hold the content, withdrawal would be a false promise.
`VISIBLE_SUBMISSION_STATES` is therefore `{distributed, superseded}` — superseded
content stays readable, because members who pulled it need its history and
removing it would silently break their `added_after` polling.

### Content scope: `discovery_scope`

Every submission carries a non-nullable `discovery_scope`, one of:

| Value | Meaning |
| --- | --- |
| `own_product` | A vulnerability in a product the submitter builds and ships. |
| `own_estate` | A vulnerability in the submitter's own deployed environment. |
| `ai_system` | An AI-system vulnerability generally — prompt injection, model supply chain, agentic tooling. Disclosure norms here are still unformed; this is the white space ISACs have not covered. |

No accepted value means "someone else's software". AIVS is not
a channel for undisclosed vulnerabilities in uninvolved third parties' products,
because that would create coordinated-disclosure consent and tortious-
interference exposure for both the submitter and the hosting ISAC. The enum
enforces the shape of the claim; the ISAC's `validated` checkpoint enforces its
plausibility. **AIVS cannot verify the claim itself** — see
[`threat-model.md`](threat-model.md).

The line drawn here is by ownership, which fits the pre-CVE lane. The wider
goal needs a line drawn by **disclosure** instead: once a vulnerability is
public, anyone may contribute defence intelligence about it; before disclosure
the three scopes above hold, plus `coordinated_disclosure` (the vendor is a
recorded party to the case, or a GOLD EAGLE/VINCE identifier is attached).
That split is built (`services/disclosure.py`, SF-7). The three scopes in the
table are always accepted (`ACCEPTED_DISCOVERY_SCOPES`); the two third-party
scopes (`THIRD_PARTY_DISCOVERY_SCOPES`) are legal only by the current state of
the ISAC's canonical record of the target: `disclosed_third_party` once its
`cve_status` is `published`, `coordinated_disclosure` while the vendor is a
recorded party to the case or a CERT case id is attached. It is checked at
ingest against what the submitter can see, and again at validation and
distribution against the ISAC's view, and a target the submitter cannot see
gets the refusal a nonexistent one does.

---

## 4. Request lifecycle

Two authenticated call shapes exist, and they share an authorization path.

### 4.1 Machine-to-machine (TAXII and native API)

```
member firm
   │  TLS + client certificate
   ▼
WireGuard overlay (or strict IP allowlist)      ── network reachability
   │
   ▼
nginx                                            ── mTLS termination
   │  strips and re-sets X-Client-Verify, X-Client-Cert
   │  adds X-Proxy-Auth: <shared secret>
   ▼
FastAPI application (no host port published)
   │  1. auth.mtls.extract_client_certificate()
   │  2. certificate fingerprint → ClientCertificate → Organization
   │  3. build AuthContext (org, status, type, circle memberships)
   │  4. auth.policy.<predicate>() — deny by default
   │  5. handler; reads apply distribution_visibility_clause()
   │  6. audit.log.record() in-transaction, or record_independently() on denial
   ▼
PostgreSQL
```

Step 1 is the most security-sensitive code in the system, because it converts
HTTP headers — which any client can *attempt* to set — into an authenticated
organization identity. Three stacked controls make that safe, and
`auth/mtls.py` documents all three:

1. **The application publishes no host port.** Only the reverse proxy can reach
   it; the compose file declares no port mapping for the app service.
2. **The proxy unconditionally overwrites the identity headers** on every
   request, so a client-supplied `X-Client-Cert` never survives to the app.
3. **The proxy proves it is the proxy** with a shared secret in `X-Proxy-Auth`,
   compared in constant time via `hmac.compare_digest`, and its peer address is
   checked against `AIVS_TRUSTED_PROXY_CIDRS`.

The application then **re-parses the certificate itself** rather than trusting
the proxy's summary of it. This is not paranoia for its own sake: nginx's
`$ssl_client_fingerprint` is SHA-1, which AIVS will not key identity on. The
proxy forwards the full URL-escaped PEM; the application computes the SHA-256
fingerprint and independently re-checks the validity window (with a five-minute
clock-skew tolerance). That removes the proxy from the set of components that
must be correct for identity to be sound.

Identity is keyed on the **SHA-256 fingerprint**, not the subject DN. DNs get
reissued and reused; fingerprints do not. Revocation is a status flip on
`client_certificates`, checked on every request, so the enforcement path needs no
CRL fetch and no OCSP responder — the authoritative answer is one indexed
unique-constraint lookup away, and it cannot expire. (`deploy/ca/revoke.sh` does
maintain CRLs, for relying parties outside AIVS; nginx's `ssl_crl` ships
commented out, because enabling it makes an expired CRL reject every client.)

### 4.2 Human (analyst portal)

A portal operator authenticates with password (Argon2id) plus TOTP, **and** the
session is bound to the organization's client certificate: `portal_sessions`
stores a `cert_fingerprint`, re-checked per request. Neither factor alone grants
access — a stolen cookie replayed from outside that org's network path fails.
Only the SHA-256 of the session token is stored, so a database disclosure does
not hand an attacker live sessions.

From step 3 onward the path is identical to the machine path: the same
`AuthContext`, the same `auth.policy` predicates, the same audit writer. The
context records `auth_method` (`mtls` or `portal_session`) and, for humans,
`operator_id` and `operator_role`.

### 4.3 Failure paths

Rejections are deliberately uninformative to the caller and precise in the log.
`CertificateRejection.reason` and `PolicyDenied.reason` are short stable tokens
(`untrusted_proxy_peer`, `certificate_expired`, `circle_read`, …) written to the
audit log and never returned in the HTTP response. Telling an unauthenticated
client exactly which of several checks it failed helps only the attacker.

Denials use `audit.log.record_independently`, which opens its own connection and
commits immediately, because the request's own transaction is about to be rolled
back and would otherwise take the record of the attempt with it. Successes use
`audit.log.record`, which joins the caller's transaction so the audit row and the
change it describes commit or fail together. **Choosing the wrong one loses
records.**

---

## 5. Circles projected into TAXII collections

A circle is the internal concept: a named set of organizations with roles. A
TAXII collection is its external projection — the thing a member puts in their
TAXII client configuration.

```
Circle "section9"                 TaxiiCollection
  minimum_tlp = amber_strict  ──►   id     = 4b1f…  (stable for the deployment's life)
  is_active   = true                title  = "Section 9 Pre-CVE"
       │                            alias  = "section9"
       │                            can_read  = true
       │                            can_write = false
       ▼
  CircleMembership rows            visibility is decided by circle membership,
  (org × role)                     never by the collection resource itself
```

Facts worth stating precisely:

- `taxii_collections.circle_id` is a foreign key with no unique constraint. The
  schema therefore permits several collections over one circle; v1 creates one.
- **`can_write` defaults to `false`.** TAXII `POST /objects/` is not the normal
  intake path. Submission goes through the native API, because the workflow needs
  a `discovery_scope`, a TLP, an anonymization choice, and an embargo — none of
  which TAXII has a place for.
- The collection `id` is a UUID and is stable for the life of the deployment,
  because members hard-code it in their client configuration.
- `circles.minimum_tlp` is a structural floor: a submission may not be
  distributed into a circle under a marking looser than the circle's floor. That
  lets an operator declare "Section 9 content is AMBER+STRICT or tighter" once,
  rather than re-deciding it per submission.
  `aivs_schemas.enums.tlp_at_least_as_restrictive` is the comparison.

The visibility rule has one important consequence for the ISAC itself:
**circle membership governs collection visibility even for system
administrators.** `auth.policy.can_read_circle` checks membership and nothing
else. A hosting ISAC that wants to read a circle's TAXII feed joins that circle
visibly, appearing in the membership list like anyone else. It does not silently
appear inside every member's feed. Oversight runs through the native API and the
portal, which are separately authorized and separately audited.

---

## 6. Why `distributions` is a materialised table

This is the single most consequential storage decision in AIVS, and it is worth
the paragraph.

`distributions` is one row per (STIX object × circle), carrying a `date_added`
timestamp. It could instead have been a view computed at read time from
submission state, circle membership, and embargo status. It is not, and it must
not be.

**TAXII 2.1 paging is a cursor over `date_added`.** A client polls
`GET /collections/{id}/objects/?added_after=<the last date_added it saw>`, and
the server returns objects ordered ascending by `date_added`. For that cursor to
be correct, `date_added` must be **stable** (an object's value never changes
after the client has seen it) and the sequence a client observes must be
**monotonic** (nothing is ever inserted *behind* a cursor the client has already
passed).

A computed view breaks both the moment an embargo lifts:

- If `date_added` were derived as "when the submission was distributed", an
  object under embargo would materialise into the feed at a timestamp *earlier*
  than the client's current cursor the instant the embargo released. Every client
  that had polled since distribution would skip it, permanently, and silently.
  A member never learns they missed a warning.
- If `date_added` were derived as `now()` or from a mutable embargo row, an
  object's position in the ordering could change between two pages of the same
  paginated read, producing duplicates and gaps within a single client sweep.

The materialised table fixes both. `date_added` is stamped when the object
becomes visible **to that circle** — distribution time, or the embargo release
time if that is later — and never rewritten. An embargoed object exists in
`distributions` immediately, with a `date_added` in the future.

That, in turn, is what makes embargo enforcement safe:

```python
# auth/policy.py — distribution_visibility_clause
and_(
    Distribution.circle_id.in_(circle_ids),
    Distribution.date_added <= now,
    Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)),
)
```

The read-time comparison `date_added <= now` **is** the embargo gate. The
sweeper that flips `embargoes.status` is a convenience for operator visibility
and the audit trail, not the enforcement point. If it dies, nothing leaks early
and the backlog self-heals on restart. There is no code path in which a stalled
background job releases content, and none in which a crashed one withholds it
past its time.

The sweeper is a plain `asyncio` task on the application lifespan
(`main._embargo_sweeper`), running every `AIVS_EMBARGO_SWEEP_INTERVAL_SECONDS`.
A scheduling framework was considered and rejected: this is one `await
asyncio.sleep` around one idempotent query, and the dependency would land in
every member firm's software bill of materials for that. It logs and continues
on failure — an instance that stopped serving members because a bookkeeping task
hit a transient database error would be a far worse outcome than a stale status
column.

The supporting index is `ix_distributions_circle_paging` on
`(circle_id, date_added, id)`. Its column order mirrors the `ORDER BY` in the
TAXII objects handler exactly. The model file says so, and it means it: changing
one without the other silently turns every member poll into a sequential scan.

The `(stix_object_id, circle_id)` unique constraint makes re-distribution
idempotent — a retried distribution cannot produce a second row and a second
`date_added` for the same object in the same circle.

---

## 7. Storage conventions

**STIX objects are stored as JSONB, canonical and opaque.** `stix_objects.raw`
holds the object exactly as accepted; `stix_id`, `modified`, `created`, `type`,
`name`, `cve_id`, and `cvss_score` are extracted alongside it purely for indexing
and search. Two consequences: evolving the AIVS STIX extension never requires a
table migration, and a member's object round-trips byte-identical rather than
being lossily reassembled from relational columns. A GIN index on `raw` supports
containment queries.

`(stix_id, modified)` is unique — that pair is a STIX *version*, and it is
exactly what TAXII's `match[version]` filter selects on.

**Nothing of evidentiary value is deletable.** Foreign keys are `RESTRICT`, not
`CASCADE`, except for genuine ephemera (`portal_sessions`, `webhook_deliveries`)
and pure configuration (`webhooks`, `circle_memberships`). The receipts,
transitions, and audit trail are the product's regulatory value; a stray cascade
that quietly erased them would be a defect, not a convenience.

**The audit log has no foreign keys at all.** It records what an actor did at a
point in time, which must remain readable even if the referenced org, operator,
or submission is later altered. Constraining it would couple the record of
history to the current state of the world — precisely what an audit log must not
do.

**Two tables are append-only in the database, not by convention.** Migration
`c185fd428721` puts a `BEFORE UPDATE / DELETE / TRUNCATE` trigger on `audit_log`
and `submission_transitions` that raises `insufficient_privilege`, and revokes
those privileges from `PUBLIC`; where `AIVS_APP_DB_ROLE` is set, the application
role is granted only `INSERT` and `SELECT` (plus `USAGE` on the id sequences).
The triggers are `FOR EACH STATEMENT`, not `FOR EACH ROW`, so a probing
`DELETE FROM audit_log WHERE id = 1` fails identically whether or not that row
exists — the attempt is an error, never a silent no-op.

A superuser can still drop the trigger. That is unavoidable, and it is why the
deployment guidance has the application connect as a non-superuser role that does
not own these tables. See [`threat-model.md`](threat-model.md) for the honest
residual-risk statement.

---

## 8. Receipts

`acknowledgments` is the table a regulator would be shown. It answers "we warned
member X, and here is when they collected it".

- `retrieved` rows are written **by the server** when content is actually
  delivered. They are not a member assertion.
- `acknowledged` and `actioned` are explicit member assertions, made over TAXII,
  the native API, or the portal (`via`).
- `dedupe_day` collapses automatic retrieval receipts to one row per org per
  submission per day. Without it, a member polling every minute would write 1,440
  rows a day per submission and drown the useful signal.

Receipts, firm by firm, are visible to the hosting ISAC's reviewers only
(`can_view_submission_receipts`). They reveal which member firms are paying
attention to which threats — exactly the inference other members must not be able
to draw about each other, and the submitter is another member. What the submitter
gets is telemetry: how many organisations could see, collected, acknowledged and
acted on its submission, each count withheld below k (`services/telemetry.py`).

---

## 9. Anonymized distribution

`submissions.distribute_anonymously` is a boolean chosen by the submitter, and
a member's filing is anonymous unless it asks for credit (Mike, Q16): the API
field left out, the portal's "credit my firm" unticked, the CLI without
`--credit`, and every TAXII inbox write. When true, the distribution pipeline
rewrites `created_by_ref` on outbound objects to the hosting ISAC's own STIX
identity and withholds the submitter from every consumer-facing view. The
ISAC's own filings are the ISAC's either way, so asking for anonymity on one is
refused.

An object keeps the choice of its first distributed version (SF-85,
`services/anonymity.py`). Only the owner versions an object, so an attributed
version followed by an anonymous one would name the anonymous one's submitter,
and the reverse would name it after the fact to every member already holding
it. A member that wants the other choice files a new object. Existing
submissions keep what they were distributed under: changing that afterwards
would re-attribute content members already hold.

Receipts and the audit trail still resolve internally, so the ISAC can answer
questions the members cannot. Anonymity here is *from other members*, not from
the ISAC — and the sharing agreement should say so in those words. See
[`sharing-agreement-outline.md`](sharing-agreement-outline.md).

Each organization has a `stix_identity_id` (a STIX `identity` SDO id, unique and
format-checked). The hosting ISAC's own org row (`org_type = admin`) supplies the
identity used for anonymized content and for the instance's own authored objects.

---

## 10. Configuration posture

`aivs_server.config.Settings` reads from the environment with the `AIVS_` prefix,
is frozen, and is constructed exactly once per process.

- **Every default is the safe value**, including `environment`, which defaults to
  `production`. A deployment that forgets a setting gets the strict behaviour.
- `extra="forbid"`: an unrecognised `AIVS_*` variable is a typo, and typos in
  security config are silent failures — the process refuses to start instead.
- Secrets are `SecretStr`, so an accidental `repr`, log line, or error page
  prints `**********`. There is deliberately no `.env` support in production.
- `validate_production_posture()` refuses to construct `Settings` for any
  environment but `dev` (staging included: it is exempted by allow-list, never
  enforced for `production` alone) with `dev_trust_unauthenticated_proxy`,
  `dev_expose_error_detail`, `dev_allow_private_webhook_targets`, an empty or
  `/0` `trusted_proxy_cidrs`, renamed identity headers, a non-HTTPS
  `public_base_url`, `log_level = DEBUG` (which may record request bodies),
  inverted page sizes, a key-encryption key from the environment or not in a
  `0600` file, no pinned issuing CA, or one value for both the session secret
  and the proxy secret.
- `python -m aivs_server.config` validates configuration and prints a redacted
  summary — usable as a container healthcheck or a pre-cutover check.

---

## 11. What runs in the background

| Component | Purpose | Failure behaviour |
| --- | --- | --- |
| Embargo sweeper (APScheduler, `AIVS_EMBARGO_SWEEP_INTERVAL_SECONDS`, default 30s) | Flips `embargoes.status` to `released` and fires notifications when `release_at` passes; holds a pending embargo whose content no longer passes the distribution-time rules. | Not the enforcement point. Content becomes visible on the `date_added <= now` comparison regardless. A dead sweeper delays *notification*, not *release* -- and cannot hold, so a rule that stops holding while it is down is reported at release (`content_problem`), not prevented. |
| Webhook delivery (`notify/`) | HMAC-signed POSTs to member-registered HTTPS endpoints. | Retried up to `AIVS_WEBHOOK_MAX_ATTEMPTS` (default 5) with a `AIVS_WEBHOOK_TIMEOUT_SECONDS` (default 5s) timeout; `consecutive_failures` tracked per webhook; every attempt recorded in `webhook_deliveries`. |

Webhook URLs are constrained to `https://` by a database check constraint, and
delivery is SSRF-guarded: private and loopback targets are refused unless
`dev_allow_private_webhook_targets` is set, which the application refuses to
start with in any environment but `dev`.

---

## Related documents

- [`threat-model.md`](threat-model.md) — STRIDE per trust boundary, with residual risk
- [`authz-model.md`](authz-model.md) — the full subject × resource × action matrix
- [`stix-extension.md`](stix-extension.md) — the pre-CVE property extension
- [`taxii-mapping.md`](taxii-mapping.md) — TAXII 2.1 conformance details
- [`deployment-topology.md`](deployment-topology.md) — network layers and PKI
