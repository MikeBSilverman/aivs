# Intelligence model

> **Status: design.** Apart from §2, this describes phases E–I of the build
> plan and the Tier 2 designs. None of it exists in the code until the phase
> named beside it lands. §2 says what does exist today, and is the only part
> that should be read as describing the running system.

This is the model the next phases build toward, written down before they
start so that no phase forecloses a later one. Each section names its phase.
When a phase lands, the matching section here is rewritten in the present
tense in the same commit, the way `security-requirements.md` gains its rows.

---

## 1. The principle

**STIX objects stay canonical; standards supply vocabularies; a new table
exists only for a concept STIX lacks.**

Every member's TIP already speaks STIX 2.1 over TAXII 2.1. A concept that we
model as STIX reaches that TIP with no integration work. A concept that we
model as our own table reaches nobody until someone writes a connector. So:

- A thing that is *intelligence* (a vulnerability, a workaround, a detection,
  a sighting, an opinion about any of them) is a STIX object, stored as
  received in `stix_objects.raw` and distributed through the existing
  pipeline.
- Where a standard already names a property or a value (CSAF's remediation
  categories, VEX's statuses, SSVC's decision points, ATT&CK's ids), we adopt
  its name and values verbatim (§4). We add a property only where no standard
  has one, and every addition is marked *ours*.
- A table is added only for something STIX has no object for: a member's
  private posture, a document still being drafted, a grant on that document.
  Each table declares a data class in [`data-inventory.md`](data-inventory.md),
  which a test enforces. That inventory is the one place the classes are
  listed, and this document does not repeat it.

The first draft of this model broke the principle in six places. The
reviews removed each one, and §6 records them so that they do not come back.

---

## 2. What exists today

The model the code holds now, as of phase D:

- **Submissions** are a member's filing: a STIX bundle plus title, summary,
  TLP, discovery scope, anonymity flag, and a workflow state (`draft →
  submitted → validated → distributed`, with `withdrawn` and `superseded`).
  The state machine is declared once, in `aivs-schemas`.
- **STIX objects** are stored as received (`raw`) with a few indexed columns
  (`cve_id` among them). Every object in a bundle is validated, and the
  extension allow-list is applied at every nesting level.
- **The AIVS property-extension 1.0** on `vulnerability` carries AI discovery
  provenance, `discovery_scope`, `cve_status`, affected products, CVSS v4 and
  embargo metadata ([`stix-extension.md`](stix-extension.md)).
- **Extension 2.0** (its own identifier; 1.0 stays accepted, and an object
  carries one or the other) brings the §4 vocabularies onto three types:
  - `vulnerability`: SSVC decision points, EPSS, KEV, CVSS v3, and affected
    versions as `vers:` ranges with `fixed_versions`;
  - `course-of-action`: the CSAF remediation category plus ours, the CSAF
    restart vocabulary, `action_type`, `residual_risk` and
    `validation_check`;
  - `indicator`: `telemetry_sources` and `false_positive_notes`.

  A **provenance** extension records who at the ISAC reviewed an object. Its
  reviewer fields are refused from a submitter. Nothing writes them yet: that
  is validate's job, in a later slice of E.
  ([`stix-extension.md`](stix-extension.md) §9.)
- **Type rules, extension or not.** Every inbound indicator states a runnable
  `pattern_type` and a `valid_until`, at most 90 days after `valid_from` for a
  network address and two years for anything else (SF-46). CVE, CWE, ATT&CK
  and CAPEC references must be in their scheme's format.
- **Index columns** on `stix_objects`, extracted from `raw` and backfilled for
  existing rows, each held equal to its source by a test:
  `remediation_category`, `pattern_type`, `valid_until`,
  `ssvc_exploitation`, `kev_listed`, `cwe_ids`. `services/indexing.py`
  names each column's reader.
- **Readiness** (SF-8). For remediation, mitigation, detection and validation,
  the value is `available`, `none_available`, `lapsed` or `unavailable`.
  `lapsed` is a claim either way whose `review_by` has passed; it is served
  with the date (`not_confirmed_since`) and shown as "not confirmed since",
  never as the opposite claim. It is computed
  per caller from the objects the caller can see, through relationships
  visible at both ends, using each object's latest visible version and
  skipping expired indicators and revoked objects. It is served at
  `GET /api/v1/vulnerabilities/readiness?id=` and never over TAXII.
- **Triage.** Submissions carry an assignee and an editor's priority. With no
  priority set, the default is CISA's SSVC decision, from CISA's own table
  (vendored verbatim) and the vulnerability's decision points. Mission and
  Well-Being Impact comes from the instance, because it describes the sector,
  not the vulnerability. The review queue groups submissions by submitting
  organisation and by member or automation, and orders each group by
  priority, showing the factors. An editor may validate a group in one
  audited action (`POST /api/v1/review/validate`, or the queue's button),
  all or nothing; a consequential machine change stops the whole group,
  because each submission still goes through `apply_transition`.
- **Duplicate candidates** by CVE, purl, CPE and CWE. A member is compared
  only with its own submissions and what reached it; the ISAC's reviewers are
  compared with everything (SF-47).
- **Receipts per channel.** The daily dedupe key includes `via`, so a portal
  read is recorded on a day the collector already polled (SF-51).
- **The vulnerability page** (`/portal/vulnerabilities?id=`). Any id the
  vulnerability has opens it: its STIX id, its CVE, or an advisory id in its
  external references, so a CVE attaching later changes no link a member
  already pasted. It shows what's available, every related object and the
  sightings, opinions and notes on them, and a timeline of when each was
  shared. The ISAC's reviewers also see workflow transitions and receipts.
  Everything comes from `services/visible.py`, the scope readiness uses. A
  member responds from the page ("we see this too", "works here", "doesn't
  work here", its own posture), and is told beforehand whether the click is
  shared at once or reviewed first. A member's read writes an `AckVia.PORTAL`
  receipt (SF-8, SF-51).
- **Discovery scope.** A submission may be filed as `own_product`,
  `own_estate` or `ai_system`. Two further values, `disclosed_third_party` and
  `coordinated_disclosure`, are contributions about another party's
  vulnerability, legal only by the current state of the ISAC's canonical
  record of the target (§3.1; `services/disclosure.py`, SF-7).
  `ai_discovery_method` is optional.
- **Circles** are the unit of publication, with TLP floors and membership
  held as intervals. **Distributions** record which object became visible to
  which circle, and from when. **Embargoes** hold that visibility time in the
  future. **Acknowledgments** are the receipts: retrieved, acknowledged,
  actioned.

Everything below is design.

---

## 3. The model, phase by phase

### 3.1 Phase E: contributions on public CVEs

**One canonical `vulnerability` per vulnerability, owned by the ISAC.** It is
keyed by the ISAC's identity, not by CVE. A vulnerability often has a public
existence before it has a CVE: a vendor advisory id, a sector warning,
observed exploitation. The object exists from that first disclosure. A CVE
attaches as an `external_reference` when it issues, and `cve_status` moves
on the canonical object. A vendor advisory, a KEV entry and an NVD record
each become references on it, never new objects.

**Only the owner versions an object; everyone else references it.** STIX
consumers merge by `stix_id` + `modified`, so a newer version filed by a
third party would silently replace the owner's content in every member's
TIP. Validate and distribute refuse any non-`relationship` object whose
`stix_id` was previously distributed by a different organisation.
`supersession` means same owner, same `stix_id`, later `modified`.

**The contribution unit is the existing submission.** A contributor files a
bundle holding a `course-of-action`, `indicator`, `attack-pattern`,
`sighting` or `opinion`, plus a `relationship` to the canonical
vulnerability. The existing workflow already is the contribution lifecycle:
`validated` is acceptance, `withdrawn` is rejection, a new `modified` is
supersession, and `revoked` is retraction. Attribution, anonymity, TLP floors,
embargoes and receipts apply unchanged, because no new write path is added.

**The disclosure split is enforced here, not earlier.** Whether a third party
may contribute depends on the *target* vulnerability's current state: is it
public, has its vendor acknowledged the case. Before the canonical object
exists there is no record of that state, only the submitter's own bundle, and
checking a rule against the request that asserts it is the error CLAUDE.md §5
names. So phase D reserved the two scope values in storage and phase E admits
them, with the rule:

- `disclosed_third_party`: the target is public. The check runs against the
  latest validated or distributed version of the canonical object owned by
  the ISAC, excluding the submission being checked.
- `coordinated_disclosure`: the vendor is a recorded party to the case. An
  `isac_editor` records the vendor, and the vendor itself files an
  acknowledging `opinion`; alternatively a GOLD EAGLE or VINCE case id is
  attached. A party list written by the submitter does not count.

At ingest the check sees only targets the caller can see. A reference to an
invisible target gets the same refusal as a nonexistent one, because a
distinct refusal would confirm a pre-CVE finding to an outsider.

**The vendor sees a case through a circle**, never through a third
visibility mechanism. An editor creates a one-off coordination circle (the
ISAC and the vendor) and distributes the case to it. The ordinary pipeline
applies, so the reporter's anonymity holds against the vendor as it does
against members.

**Extension 2.0 and the index columns exist (§2).** What remains for this
phase:

- `validate` writes the provenance reviewer fields from the authenticated
  context;
- the readers of the index columns are built;
- two columns wait for a reader:
  - `epss_score`, for EPSS enrichment, which the plan defers until an analyst
    asks for it;
  - `attack_technique_ids`, which no phase-E reader needs.

  Each lands with its first reader, as CLAUDE.md §5 requires of any column.

**Readiness and the vulnerability page exist (§2).** A course of action past
its `review_by` date makes its group `lapsed`, through the same predicate the
guided view uses (`guidance.review_lapsed`).

**The vulnerability page is the case.** There is no `cases` table: assignee
and priority are columns on `submissions`, and priority defaults from the SSVC
coordinator tree.

**One-click contributions.** "We see this too" (a `sighting` with no
`where_sighted_refs`), "works" and "doesn't work" (an `opinion`) are built by
the server from a click, anonymous by default, and published at once when the
lane rule holds: a person filed it from a member's session, the target is a
published vulnerability or a contribution on one, it is not RED, it is not a
vendor's opinion, and it goes only into circles the member contributes to.
Otherwise it is filed for review (`services/contributions.py`, SF-66).

**Post-moderation, per circle.** For `note`, `opinion`, `sighting` and RFI
`grouping`s on already-distributed public-lane objects, a circle may let a
contribution distribute on submit, under the same attribution, TLP and
self-identification checks, with an editor able to `revoke` afterwards.
Everything in the pre-CVE lane, everything RED, and every `vulnerability`,
`course-of-action`, `indicator`, `attack-pattern` and `report` still needs a
human `validate`. Everything published without review, with every TAXII inbox
post, spends one hourly allowance per organisation, and a refusal raises
`contribution_flood`. An editor revokes a post-moderated contribution with
`POST /api/v1/submissions/{id}/revoke`.

**The TAXII inbox, per circle.** A circle's collection takes POSTs only once an
ISAC editor has opened its inbox (`PUT /api/v1/circles/{id}/taxii-inbox`, or the
circle's page); every collection starts closed, and the switch is audited. It
opens a door into review, nothing more: each post is a `submitted` submission
under source `system`, anonymous, under the AI gate, the disclosure split and
the hourly allowance (SF-69). Polling members' own TAXII servers is Phase O.

**Telemetry back to the submitter**, computed from the rows the pipeline
already writes: reach, retrieved, acknowledged and actioned counts (built);
aggregate posture outcomes and opinion counts are designed, and named to the
submitter as coming rather than shown as zero. None is ever a list. A count is
exact only when at least k organisations did the thing and at least k did not:
reach is exact, so a count within k of it names the firms that did not act as
surely as a small count names those that did.

### 3.2 Phase M: members sign in with SSO

Built. There are two listeners and two kinds of session. The mTLS listener
stays for machine collectors, ISAC staff and anything that may show RED. An
opt-in public TLS listener serves the member portal to people who sign in
through the ISAC's identity provider with a second factor. Those sessions
carry their own `auth_method` and are ceilinged at `AMBER+STRICT`, and never
read a submission that was ever under embargo, so RED content and the
embargoed pre-CVE lane stay bound to a certificate. The public listener serves
`/portal` member routes and nothing else. This adds no objects to the model;
it adds a principal to the authorization matrix.

### 3.3 Phase F: depth and exporters

Built, except where a line says otherwise:

- **Depth is a link, not a profile.** `?depth=guided` renders a
  vulnerability from its objects alone, in plain language, with no STIX
  type names (`services/guidance.py`, `templates/_guided.html`); `technical`
  is the raw STIX. The one stored preference is a per-operator
  `default_depth`, read by the vulnerability page (`?depth=` overrides it).
  Each depth is a rendering of the same visible objects; technical shows each
  one's latest *visible* version, and history is the evidence pack's.
- **`isac_assessment`** (`confirms | adds | contradicts | no_position`)
  states the ISAC's position relative to the public record, with the delta.
  Like readiness, it is relative to the caller: the guided view reads it from
  the latest version the caller can see.
- **Exporters are serialisers over visible objects**: a print stylesheet and
  a CSV IoC pack (current indicators only). Each export writes a receipt.
  *pySigma rendering per member SIEM dialect is not built*: every pySigma
  release from 1.0 depends on a package with an open advisory and no fix.
- **Lead time** is a query, first visible to the organisation against
  `nvd_published` and `kev_date_added` per item, shown to each organisation
  about itself; the ISAC sees a sector median over distribution dates,
  withheld below k.
- **"New since you last read"** is computed from the organisation's portal
  receipts, not stored.
- **`review_by` on a course of action** is in the 2.0 extension, and the
  guided view flags a step past it (`is_due_for_review`). Readiness reports
  the action's group `lapsed` through the same predicate (§2).

### 3.4 Phase H: posture and evidence

- **`org_posture` is a VEX statement** per organisation × vulnerability:
  `status`, `justification`, `impact_statement`, `action_statement` in VEX's
  vocabulary, plus ours: `detection_deployed`, `validated_at`,
  `evidence_note`. It is private to the organisation, because an ISAC that
  can see which member is `affected` holds a fact member counsel will not
  let it hold; the ISAC sees k-aggregates. STIX has no object for a private
  per-organisation assertion, which is why this is a table. The table
  (`org_postures`) arrived in phase E with the posture click; phase H made it
  a full VEX statement, with VEX's rules held by the database, and an OpenVEX
  export of the member's own rows (`/api/v1/postures/openvex`, SF-70). What VEX
  has no field for stays out of the export. "We've acted on this" is a click
  of its own on the vulnerability page, writing an `actioned` receipt for what
  reached the firm there; setting a posture writes none, because a receipt
  that followed the status would tell the ISAC the status (SF-79).
- **The member evidence pack** (built, SF-79): for one vulnerability, every
  version of the advisory and its related objects as they reached the firm,
  each with the interval it was in force and the ISAC's review stamp; the
  firm's own receipts; its posture as a VEX statement with when it last
  confirmed it. Content-hashed, the hash recorded in the audit trail; JSON at
  `GET /api/v1/evidence-pack?vulnerability=`, printable from the page. The
  member's alone: the ISAC gets the 404 an unknown vulnerability gets.
- **The `auditor` role** (built, SF-78): held alone and until a required end
  date; reads the audit trail and receipts, the instance's at the ISAC and its
  own organisation's at a member, as a cursor stream a SIEM can poll, in
  commit order and hash-chained across pages; refused at the door everywhere
  else, so never content. What the stream serves of its own reading is the
  instance's mode (`condensed` by default, or `full`), with a summary per
  reader in both; a page of nothing but reads is never served, so a poller
  always drains it.
- **Offboarding** (built, SF-72) deletes every operational row the data
  inventory gives the organisation (postures, webhooks, portal sessions, TAXII
  inbox statuses), keeps evidence and content, ends its credentials, closes
  its memberships as `offboarding`, and pseudonymises its people. A legal hold
  keeps the postures until it is lifted. `test_offboarding` reads the
  inventory, so each later phase that adds an operational table is held to
  it, and extends the test with whatever else it adds that can be revoked.

### 3.5 Phase I: documents

- **`documents`, `document_versions`, `document_comments`, `access_grants`**:
  the second exception to the principle, because STIX has no object for a
  draft being written by several organisations. A finished document becomes
  a `report` SDO with the body as an `artifact`, submitted and validated
  through the ordinary pipeline, so acceptance is still the ISAC's
  `validate`.
- **Grants are on documents only**: an organisation or an operator, `view`
  or `edit`, with `expires_at`, bounded to principals the granter can already
  see. STIX objects keep circles. No resource has two visibility mechanisms.
- **Each document has its own data-encryption key**, sealed by `secretbox`.
  Every ciphertext under it carries a per-row binding, so a row cannot be
  moved, replayed or re-threaded.
- **Structured input arrives as proposals**: an ordinary submission of kind
  `proposal`, targeting an object the proposer can see, limited to an
  allow-list of paths, and visible only to the proposer and the owner's
  editors. The owner accepts by filing a new version of its own object.

---

## 4. Standards mapping

Adopt the standard's vocabulary and identifiers verbatim; add a property only
where no standard has one; never rename a standard's value. *Ours* marks
every addition, so nothing of ours is ever mistaken for a field a standards
body later defines (NVD in particular, §4.1).

| Standard | Where it lives | Adopted | Ours (and why) |
|---|---|---|---|
| **STIX 2.1** | Canonical model; `stix_objects.raw`. SDOs `vulnerability`, `course-of-action`, `indicator`, `attack-pattern`, `grouping`, `opinion`, `sighting`, `report`, `identity`, `note`, `campaign`, `threat-actor`; SCO `artifact`; SRO `relationship`. | Types, `confidence`, `revoked`, `modified`, `external_references`, `object_marking_refs`, `pattern_type`, `identity_class`, `roles`, `kill_chain_phases`, `valid_from/until`. | Property extension 1.0 and 2.0, and the provenance extension (all exist). |
| **TAXII 2.1 / TLP 2.0** | Delivery; markings; circle floors. | Unchanged. | A statement marking "shareable with regulator" (H). |
| **CVE** | `external_references[cve]`; `cve_id`; `cve_status`. | Id format; CVE 5.x `affected[]` shape. | `cve_status`: the pre-CVE phase has no standard. |
| **NVD records** | `external_references[source_name=nvd]` on the matching object; `provenance.source` per property. | Whatever NVD issues. | Our values keep their own names beside NVD's; `isac_assessment` records agreement or contradiction. |
| **CWE** | `external_references[cwe]`; `grouping(context=weakness-class)`; `cwe_ids[]`. | Ids. | The `weakness-class` context value. |
| **CVSS** | v4 (exists) and v3.1 vector strings. | Verbatim. | — |
| **SSVC** | `ssvc` on `vulnerability` (CISA v2 decision points); coordinator tree for priority; deployer tree in Tier 2. | Decision-point names and values. | `decision` recorded with its factors. |
| **EPSS** | `epss_score/percentile/date`. | FIRST's fields. | — |
| **CISA KEV** | `kev_listed/date_added/due_date/ransomware_use`. | KEV's fields. | — |
| **CSAF 2.0** | `course-of-action.category` = `remediation.category`; `restart_required`; `product_ids`; `revision_history` on advisories. Product tree not adopted. | Remediation, restart and tracking vocabularies. | `validation`, `rollback`, `action_type`, `residual_risk`, `validation_check`: CSAF stops before verification. |
| **VEX** (CSAF VEX / OpenVEX) | `org_posture`; export. | `status`, `justification`, `impact_statement`, `action_statement`. | `detection_deployed`, `validated_at`, `evidence_note`. |
| **ATT&CK / CAPEC** | `attack-pattern` with MITRE's own references. | Ids verbatim. | — |
| **CPE / purl / vers** | `affected_products`; `version_range` as `vers:`; `fixed_versions[]`. | Verbatim; free text refused. | `fixed_versions`, as a readable list. |
| **Sigma / YARA / Snort / Suricata** | `indicator.pattern_type`; pySigma rendering. | STIX's vocabulary. | `kql`, `spl`; `telemetry_sources[]`; `false_positive_notes`. |
| **STIX confidence scales** | Portal display. | The Admiralty and estimative mappings in the STIX specification. | — |
| **UK Finance / PSR APP categories; FBI IC3 types** | Fraud `attack-pattern` typology by reference (Tier 2). | Names verbatim. | `fraud-lifecycle` kill chain; `loss_band`; `fraud_typology` for gaps. |
| **STIX SCOs** (`user-account`, `email-addr`, `domain-name`, `url`, `ipv4-addr`) | Fraud entities (Tier 2). | Verbatim. | `x-payment-account`; per-circle HMAC tokenisation. |
| **USA PATRIOT Act §314(b); 31 CFR 1020.320(e)** | Precondition for an entity circle; SAR lint (Tier 2, with counsel). | — | — |
| **OpenTelemetry; Prometheus exposition** | `/metrics`. | Prometheus text format. | — |
| **OCSF, CEF, RFC 5424 syslog** | Platform detection alerts and log forwarding to the ISAC's SIEM. | OCSF Security Finding class; CEF; syslog over TLS. | — |
| **OIDC + SCIM 2.0** | Sign-in and provisioning from the ISAC's directory (M, L). | Standard claims; SCIM Users and Groups. | Group → circle and issuer → role mappings. |
| **Relationship tuples (Zanzibar shape)** | `access_grants` as `(resource, relation, principal)` (I). | The tuple shape. | `expires_at`. |

The last three rows describe operational interfaces rather than
intelligence. They are listed because the same rule applies to them: a
consumer that already speaks the standard must not need anything from us.

### 4.1 Tying back to NVD

NIST's request for information asks NVD to consider commonality categories,
structured remediation records, a readiness framework, chainability, a
weaponisation scale and a novel-attack-vector flag. If any of those ship with
NVD identifiers, the canonical record must carry them without a model change.
So each concept we assert that NVD may later assert lives on the object where
an NVD id would attach as an `external_reference`: the `vulnerability` for
the record, the `grouping` for a commonality bucket, the `course-of-action`
for a remediation record, the `attack-pattern` for a technique. Nothing needs
building until NVD moves. What it needs now is that no field of ours is
*named* as if it were NVD's, which the *Ours* column above enforces.

---

## 5. Tier 2: designed now, built when a member asks

Each design is recorded so that nothing in Tier 1 forecloses it. No column,
setting or event for any of them lands until it is pulled.

| Design | Shape | Pulled by |
|---|---|---|
| **Real-time co-editing** | Yjs on `pycrdt`, per-message authorization, a DEK-encrypted update log, a CSP-constrained editor, a dedicated nginx upgrade location. | The pilot ISAC's analysts asking for it. |
| **Inbound email-to-draft** | A monitored mailbox per circle; a message from a verified member address becomes a *draft* for that organisation, never distributed; DMARC-aligned senders only. | The first week of the pilot. |
| **Weekly pre-fill** | The weekly summary template pre-filled from the week's cases. | The first weekly. |
| **AI assist** | A controlled model only (local, or a private endpoint the ISAC controls). Extraction from a pasted advisory, dedup suggestions, drafting the guided depth, Q&A with the visibility rule applied before retrieval. Output always files as the automation identity. | An analyst's first "I pasted this PDF". |
| **Inbound TAXII / CSAF provider ingest** | A poller running as an automation organisation, reusing `aivs-client`'s cursors; an advisory becomes a `vulnerability` plus `course-of-action`. | The first CSAF-publishing vendor. |
| **Technology registry, exposure matching, personalised SSVC** | Private per-organisation product rows; "affects you: N"; the ISAC sees "reaches N of M", never which; k ≥ 5 on every cell, with complementary suppression. | A mid-size member asking "does this affect us". |
| **Pages per job function** | CISO, vulnerability-management and fusion pages, rendered only from the caller's visible set; no stored job function. | The first CISO sign-in. |
| **More exporters** | CSAF 2.0 advisory, DOCX, MISP feed: serialisers over existing objects. | A member's tooling. |
| **Uploads** | Attachments by value: size cap, magic-byte allow-list, a malware scan gating readability, served as `attachment` with `nosniff` and a sandboxing CSP. | A member asking to upload. |
| **Academic research access** | A `researcher` organisation under a research agreement: delayed, anonymised, aggregated export; never in a cohort, a denominator or the feed. | The first university MoU. |
| **Fraud lane: TTPs** | `attack-pattern`, `campaign`, `threat-actor`, `course-of-action`, `sighting` in ordinary circles at AMBER; a `fraud-lifecycle` kill chain of ours; typology by reference to ATT&CK, CAPEC, UK Finance / PSR and IC3. No new column. | The fraud team's first scheme write-up. |
| **Fraud lane: entities** | SCOs (`user-account`, `email-addr`, `x-payment-account`, …) distributable only to circles flagged for entities; §314(b) registration as a membership precondition; per-circle HMAC tokenisation; excluded from search, logs, exports and email. | Counsel's sign-off and a §314(b)-registered cohort. |
| **BYOK sidecar** | Sealed content as an option, excluded from search, analytics and readiness; key exchange designed post-quantum hybrid from the start ([`pqc-readiness.md`](pqc-readiness.md)). | A named ISAC requiring it. |
| **Federation between instances; PSI correlation; passkeys; image signing; GOLD EAGLE / VINCE** | As designed elsewhere in `docs/`. Many ISACs means federation between single-tenant instances, never a tenant column. | — |

---

## 6. Concepts the reviews removed

Recorded so they are recognised if proposed again. Each one was a second
model of something STIX or an existing table already holds.

| Proposed | Replaced by |
|---|---|
| `intel_items` | `vulnerability` and `grouping` objects |
| `assertions` | Objects inside submissions |
| `assertion_challenges` | `opinion` |
| A `cases` table | Columns on `submissions` and a query over relationships |
| Nineteen facets | CSAF categories and STIX types |
| `job_function` / `maturity_profile` columns | Pages, and a depth link |
| Circles as principals on grants | Circles are publication; grants are documents only |
