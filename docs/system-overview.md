# AIVS: goals, tenets and how it works

Status: summary as of 2026-10-15; the plan and docs/ are authoritative.

---

## 1. What AIVS is and why

**AIVS is the ISAC's vulnerability desk.** An ISAC (Information Sharing and Analysis Center) is a sector body whose member firms share threat information through it. AIVS gives the ISAC one page per vulnerability. The page says what the vulnerability is, whether you are affected, what to do, and how to check the fix worked. It also proves that you were told. The ISAC, its members and vendors write the page together.

The longer statement of the goal: AIVS is the platform an ISAC runs to manage intelligence across the whole life of a vulnerability. That life runs from a pre-CVE finding under embargo, often discovered by AI, through CVE issuance and enrichment, to the detection, mitigation, control and verification work defenders do.

**The first lane is pre-CVE early warning.** AI models have made vulnerability discovery cheap. Between the moment a firm finds a vulnerability and the moment a CVE (the public vulnerability identifier) is published, there is a window of days to months. During that window peers exposed to the same problem have no structured way to be warned. Nobody else covers this lane, so it stays at the front of the lifecycle. The rest of the lifecycle is added behind it.

**The page is the product.** Everything else answers three questions: who may write to the page, who may read it, and what record proves it was delivered.

**Two headline measures** are in the README from the start:
- **lead time versus NVD and CISA KEV**: how much earlier members knew. The plan calls this "the dues number".
- **share of advisories with something to do**: how often the page answers "what do we do".

Supporting measures are analyst minutes per advisory, contributions per member (including breadth and repeat rate), the telemetry-back rate, and evidence packs produced. None of these is collected yet.

**Who it serves**

| Who | What they need from AIVS |
|---|---|
| **The ISAC** (analysts, editors, membership staff, operators) | A review queue, editorial control over what reaches members, embargoes, proof of delivery, and monitoring of the platform itself. |
| **Large member firms** (for example a G-SIB fusion centre) | Confirmation, the delta from the public record, and raw objects delivered to their own threat-intelligence platform (TIP) by machine. |
| **Small and mid-size members** | Plain language: "tell me what to do". They sign in with a browser and SSO, not certificates. |
| **AppSec and product-security engineers** | "Does our code actually reach it?" as machine-readable conditions. This is planned, Phase N. |
| **Vendors** | A way to contribute fixes and workarounds and to take part in coordinated disclosure as a case party. Vendors get no special tier. |
| **Regulators and auditors** | Evidence packs a member can hand over, and a scoped, read-only audit role. |

**ISAC-in-a-box.** The ISAC deploys AIVS for its own members, or Aequora hosts a dedicated single-tenant instance for it. In both modes the ISAC holds the CA (certificate authority) root offline, and ISAC staff alone validate and distribute content. The code is Apache-2.0. Each instance serves one ISAC. Several ISACs would be served by federation between instances, never by a tenant column in a shared database.

---

## 2. Tenets

These principles come from the plan's Decisions table, CLAUDE.md §5–§6 and the design docs. Each one names the failure that produced it, so it survives a refactor.

**Fail closed, by allow-list.** Safety checks say "permit only this", never "deny only that". An early check exempted every environment except "production", so staging, which holds real embargoed intelligence, skipped every check. Only `dev` is relaxed now, and an unset environment defaults to the strict posture.

**Anything addressed by id answers 404, never 403.** If "exists but forbidden" looks different from "does not exist", the endpoint becomes an oracle that confirms which pre-CVE findings exist. Refusals that could confirm existence use one constant string, and tests compare response bodies byte for byte.

**The ISAC's editorial checkpoint is human-only.** Validating and distributing take a person with the `isac_editor` role, signed in with password and TOTP (a one-time code). No machine identity can validate or distribute, including the ISAC's own certificates. Whoever controls the CA can mint a certificate, and in hosted mode that would be the host.

**Attribution is the server's to assign, on every path.** The server rewrites `created_by_ref`, the STIX field naming who made an object. A member cannot file content under a peer's identity. Only an object's owner may publish a new version of it; everyone else references it.

**Members are anonymous to other members; the submitter is ISAC-only.** Ordinary reads hide the submitter of an anonymous submission. Naming one is a separate act ("reveal"), done only by an `isac_editor`, with a reason, and audited. Self-identifying structure, such as a sighting that names the submitter itself, is refused rather than stripped. Making anonymity the default on every path, and holding submitter identity in a separate database schema, is Phase P (planned).

**Counts never name firms.** Any number shown to a member or a submitter is exact only when at least k organisations (k = 5) did the thing and at least k did not. This is two-sided suppression. Counts are published as periodic snapshots rather than read live, so one firm's change cannot be seen by comparing two reads.

**A member's posture is its own.** Whether a firm is affected, not affected or fixed is a VEX statement (VEX is a standard for saying whether a product is affected) visible to that firm alone. The ISAC and submitters see k-suppressed aggregates. Member counsel would not let an ISAC hold a per-firm "affected".

**Joining a group grants participation, not the archive.** Circle membership is an interval: it starts on joining and ends on leaving. A firm sees only what was distributed while it was a member. Suspension and quarantine are checked on each request and do not rewrite membership history.

**A stop button stops everything.** Pausing distribution hides content from readers. It also stops the embargo sweeper and the notification dispatcher, because a contentless "poll for X" still says that X exists.

**Embargoes are enforced on every read, not by a scheduler.** An embargoed object has a future visibility time, and every read compares that time to now. If the sweeper dies, nothing leaks early.

**Notifications carry no content.** Webhooks and digests say "poll to collect". They may also carry product names below RED and the titles of CLEAR and GREEN items in a digest.

**The ISAC reads a circle only by joining it, visibly.** No administrator bypasses circle membership. A membership list therefore means what it says.

**Validation rules live in one place.** Workflow rules sit in one transition function that the API, the portal and the TAXII inbox all go through. A rule placed in one route is a rule the other doors skip.

**A flag that is stored and shown must be enforced, or deleted.** A column, setting or model with no caller is a claim the system does not keep. Features land in the commit that gives them a caller and a test.

**Standards first.** STIX objects stay canonical, standards supply the vocabularies, and a new table exists only for a concept STIX lacks. AIVS never renames a standard's value, and every addition is marked "ours".

**Nothing cryptographic is ever committed.** Test certificates are generated at test time. The application never receives a private key. Stored ciphertext names its algorithm and key, so changing either is a re-wrap job, not a migration.

**Controlled AI models only.** Any AI assistance uses a local model or a private endpoint the ISAC controls. It never uses a public model API, because a prompt carrying embargoed content to a shared service is a disclosure. No AI feature is built yet.

**Give-to-get is decided against.** Access to intelligence is never tiered by how much a member contributes. That would expose competitors to a group-boycott claim and would cut off the smaller members who need the pool most. Participation is encouraged by making it cheap and by showing submitters what their contributions did.

**Telemetry back to the submitter is automatic.** A submitter sees reach, retrievals, acknowledgements and actions on its own submissions, all k-suppressed, with no analyst involved. The plan calls this "the reciprocity signal FS-ISAC never had".

**Nothing fails silently.** Every component reports its health by name on `/readyz`, exposes metrics, logs every decision with a correlation id, and raises an alert when it does not run.

---

## 3. Intel: what the system holds

**The model is STIX 2.1.** STIX is the standard format for threat intelligence. Intelligence is stored as STIX objects exactly as received, with a few columns pulled out for search. The object types in use are:
- `vulnerability`
- `course-of-action` (a fix, mitigation or workaround)
- `indicator` (a detection)
- `attack-pattern`
- `sighting`
- `opinion`
- `note`
- `grouping` (also used for requests for information, RFIs)
- `relationship`

**One canonical vulnerability, owned by the ISAC.** It exists from first disclosure, which may be a vendor advisory id or observed exploitation before any CVE. A CVE, a KEV entry or an NVD record attaches to it as a reference, never as a new object. Its `cve_status` moves through `pre-cve → requested → assigned → published`.

**Lanes.**
- **Pre-CVE lane.** A member's own finding: own product, own estate, or an AI system. Always human-reviewed and embargo-capable.
- **Public lane.** Contributions on public CVEs. Anyone may contribute defence intelligence about a vulnerability that is public. Before disclosure, only the vendor's own case or a coordinated disclosure is allowed. In a coordinated disclosure the vendor is recorded as a party by an ISAC editor and acknowledges the case, or a GOLD EAGLE/VINCE case id is attached. This "disclosure split" is a legal-risk control. It is checked against the state of the ISAC's record of the target, never against what the submitter claims.

**AIVS STIX extensions.**
- **Version 1.0** carries the pre-CVE facts: AI discovery method, scope, CVE status, affected products, CVSS v4 and embargo.
- **Version 2.0** adds the standard vocabularies:
  - SSVC decision points, EPSS and KEV fields on vulnerabilities;
  - CSAF remediation categories, a restart flag, action type, residual risk and a structured `validation_check` on courses of action;
  - runnable pattern types, telemetry sources and false-positive notes on indicators.
- **A provenance extension** records who at the ISAC reviewed an object.

**Indicators must expire.** Every inbound indicator states a `valid_until`: at most 90 days for a network address, two years for anything else. Expired indicators drop out of exports and readiness.

**Readiness ("what's available").** For remediation, mitigation, detection and validation, each vulnerability is `available`, `none_available`, `lapsed` or `unavailable`. `lapsed` means a claim is past its review date and is shown as "not confirmed since". Readiness is computed per caller from the objects that caller can see, and is never stored or sent over TAXII. A global value would reveal content the caller cannot see. Phase N plans a fifth group, `scoping`: can you tell whether you are affected?

**Exploitability conditions (planned, Phase N).** These are typed conditions saying exactly when a vulnerability can be exploited:
- a vulnerable function, file or module;
- an operating system or architecture;
- a configuration setting and its default;
- a version range;
- exposure.

Each condition says how to check it and which VEX justification applies if it does not hold. Conditions combine as all-of / any-of, and the system fails closed: no conditions means "assume affected", and sources that disagree mean the broadest reading wins.

**Postures.** A member's VEX statement per vulnerability has a status (`not_affected`, `affected`, `fixed`, `under_investigation`), a justification, impact and action statements, plus three fields of ours: `detection_deployed`, `validated_at` and an evidence note. It exports as OpenVEX. One-click posture defaults to `under_investigation`, never `affected`.

**Versioning and review.**
- A submission moves `draft → submitted → validated → distributed`, with `withdrawn` and `superseded` as the other states. In contribution terms, validated means accepted, withdrawn means rejected, a newer `modified` is a new version, and `revoked` is a retraction.
- An ISAC editor validates. The review queue groups submissions by source and orders them by SSVC-derived priority.
- An editor may bulk-validate a group, but a consequential change made by a machine (for example a lowered score) stops the whole group for human attention.
- **Fast lane:** a member's one-click, no-free-text response on an already-public object publishes at once.
- **Post-moderation:** a circle can let notes, opinions, sightings and RFIs publish on submit, with an editor able to revoke them afterwards.
- Everything pre-CVE, everything RED, and every vulnerability, course-of-action, indicator and attack-pattern still needs a human `validate`.

**Enrichment is a script.** The KEV enrichment script runs as the ISAC's automation identity and files ordinary submissions for an editor to review. AIVS has no background enrichment service and no new outbound connections from the stack.

**Reading depth.** The vulnerability page renders at three depths: `guided` (plain language, no STIX names), `standard`, and `technical` (raw STIX). The page opens from any id the vulnerability has: STIX id, CVE or vendor advisory id. A link pasted into a ticket keeps working after a CVE attaches.

---

## 4. Sharing

**Circles.** A circle is a named trust group, for example Section 9 or G-SIB. Each circle appears as a TAXII collection and has a TLP 2.0 floor. TLP, the Traffic Light Protocol, has the levels CLEAR, GREEN, AMBER, AMBER+STRICT and RED.
- **Membership.** Membership can be explicit or rule-based (by organisation type). It is held as non-overlapping intervals, and only the ISAC admits an organisation.
- **Vendor and coordination circles.** These are explicit-membership circles.
- **Sandbox circles.** These exist for testing a member's connection and count in no reported figure.

**TLP enforcement.**
- At distribution the server stamps the submission's TLP marking onto each object.
- A contribution must be at least as restrictive as anything it references.
- Member SSO sessions are capped at AMBER+STRICT and never read anything that was ever embargoed.
- The planned MSSP programme (managed security service providers) is capped at AMBER.
- Circle ceilings, as opposed to floors, are a Tier 2 idea.

**Embargoes.**
- An embargo is a future release instant, enforced on every read.
- An editor can extend or release early. Release times may not be backdated, because members' polling never looks backwards.
- Embargo policies are `timer`, `coordinated` and `manual`.

**Distribution.**
- One transaction covers the visibility rows, the state change and the audit record, so a member paging concurrently sees all of it or none.
- A single global lock orders publication. Every timestamp is stamped at the next millisecond, so TAXII `added_after` polling never skips a row.

**TAXII 2.1.**
- Members' existing TIPs connect with a certificate and a collection id. No bespoke client is needed.
- A TAXII inbox accepts STIX posted by a member, once an ISAC editor has opened that circle's inbox. Every inbox starts closed, and the switch is audited. Every post becomes an ordinary submission under a machine identity and goes to review.
- The `aivs` CLI (`enroll`, `poll`, `submit`, `ack`) is a reference client.

**Notifications.**
- Contentless webhooks fire when content becomes visible: at distribution with no embargo, or at embargo release.
- A member chooses a cadence: immediate, hourly or daily. The hourly and daily options coalesce into a contentless digest by email or webhook.
- An editor can pin a canonical vulnerability as a sector event during a major incident.

**Receipts.**
- The server records `retrieved` when content is fetched over TAXII, the API or the portal. Members record `acknowledged` and `actioned` themselves.
- The ISAC cannot acknowledge on a member's behalf, because that would manufacture the member's own evidence.
- Firm-by-firm receipts are visible only to ISAC reviewers.

**Telemetry back to the submitter.** Reach, retrieved, acknowledged and actioned counts are k-suppressed and published as snapshots. A milestone notice fires at the first exact count. Aggregate posture outcomes and opinion counts are designed.

**Making sharing cheap.**
- One-click contributions on a page: "we see this too", "works / doesn't work", and posture.
- Analyst-proxy filing: an ISAC editor files for a member, and the member has 24 hours to confirm or withdraw.
- A sanitisation lint that offers redaction rather than rejection.
- A "what happens to this post" preview before submitting.

**Evidence and lead time.**
- **Member evidence pack:** content-hashed, per vulnerability, showing what reached the firm, when, its receipts, and its posture.
- **Lead-time statement:** each firm sees how early it knew compared with NVD and KEV. The ISAC sees only a sector median, withheld below k.

---

## 5. Standards

Rule: adopt each standard's vocabulary verbatim, add only where nothing exists, and mark additions as "ours".

| Standard | How AIVS uses it | Status |
|---|---|---|
| **STIX 2.1** | The canonical model; every intelligence object, plus AIVS extensions 1.0/2.0 and provenance | Built |
| **TAXII 2.1** | Delivery to members' TIPs; inbox for member contributions | Built (inbox built; polling members' own TAXII servers planned, Phase O) |
| **TLP 2.0** | Circle floors, object markings, session ceilings | Built (MSSP ceiling planned, K) |
| **CVE / CVE 5.x** | Ids as references; `cve_status` for the pre-CVE phase (ours); 5.x `affected[]` details for exploitability | Ids built; 5.x detail intake planned (N) |
| **NVD** | References on the canonical object; our values kept beside NVD's, with `isac_assessment` (confirms, adds, contradicts) | References and assessment built; future NVD record types attach without a model change |
| **CWE** | Ids as references; used in duplicate detection | Built |
| **CVSS** | v4 and v3.1 vector strings | Built |
| **SSVC** | CISA decision points on vulnerabilities; coordinator tree sets default review priority | Built (per-member deployer tree is Tier 2) |
| **EPSS** | FIRST's score, percentile and date fields | Fields built; enrichment deferred until an analyst asks |
| **CISA KEV** | Listing fields; KEV enrichment script; lead-time baseline | Built |
| **CSAF 2.0** | Remediation category and restart vocabulary on courses of action | Vocabularies built; CSAF advisory export and vendor CSAF ingest Tier 2 |
| **VEX / OpenVEX** | Member posture statements; OpenVEX export | Built (CSAF VEX export not yet) |
| **CPE / purl / vers** | Affected products and version ranges; free-text versions refused | Built |
| **ATT&CK / CAPEC** | Ids on attack patterns, format-checked | Built (fraud typology Tier 2) |
| **OSV / GHSA** | Vulnerable symbols for exploitability; OSV JSON export | Planned (N) |
| **Sigma / YARA / Snort / Suricata (+ KQL, SPL)** | Indicator pattern types; CSV IoC pack | Built; Sigma conversion per SIEM dialect blocked (every pySigma release depends on a package with an open, unfixed advisory) |
| **OIDC** | Member sign-in through the ISAC's IdP, with second factor | Built (member tenant, Phase M); staff tenant and passkeys designed |
| **SCIM 2.0** | User and group provisioning and deprovisioning from the ISAC's directory | Planned (L) |
| **OCSF, CEF, RFC 5424 syslog over TLS** | Platform detection alerts and log forwarding to the ISAC's SIEM or MSP | Built |
| **OpenTelemetry / Prometheus** | `/metrics` | Built |
| **CycloneDX 1.6** | Reproducible SBOM; image scan for the OS layer | Built; cryptographic bill of materials (CBOM) planned |
| **ML-KEM hybrid TLS (X25519MLKEM768)** | Post-quantum key exchange offered first by the proxy | Built in config and pinned by test; end-to-end negotiation test planned |
| **Fraud typologies (UK Finance/PSR, IC3), §314(b)** | Fraud TTP and entity lanes | Tier 2, designed only |

---

## 6. Roles

### ISAC staff (human, portal session with password + TOTP over a certificate-bound path)

Roles are held as a set, and none implies another. A small ISAC may give one person several roles; a large one will not.

| Role | May | May not |
|---|---|---|
| `isac_analyst` | Work the review queue; see every submission's record and receipts; assign; recommend; draft an ISAC filing | Validate, distribute, set embargoes, reveal; submit, amend or withdraw the ISAC's own filings, including by one-click |
| `isac_editor` | Every verb on the ISAC's own filings (no certificate alone holds them); validate, distribute (including bulk), set, extend or release embargoes; open a circle's TAXII inbox; create circles and set floors; reveal an anonymous submitter (with reason, audited); pause or resume distribution; quarantine or reconnect; post-moderation; proxy filing; sector events | Read a circle's feed without visibly joining it; acknowledge for a member |
| `isac_membership` | Enrol, activate, suspend, offboard; legal holds; circle rosters; register and revoke any certificate; quarantine or reconnect; status page | **Read any submission** |
| `system_admin` | Run the instance: operators, settings, status page; pause; quarantine | Any editorial verb (it used to hold all of them) |
| `auditor` | Read the audit trail and receipts as a hash-chained cursor stream a SIEM can poll; instance-wide at the ISAC, own-organisation at a member | Anything else; it is held alone and must have an end date |

### Member side

| Role | May | May not |
|---|---|---|
| `analyst` | Draft and submit; read its circles; one-click responses; acknowledge; see its own submissions' telemetry | Administer its organisation |
| `org_admin` | Everything an analyst can; manage its own organisation's people and certificates; self-quarantine ("we are compromised, cut us off") | Reconnect itself; act on another organisation |
| Circle role `member` / `contributor` | Read / read and contribute in a given circle | Admit anyone to the circle |

**Organisation types**

| Type | Role in the system |
|---|---|
| `gsib`, `section9`, `crit_infra` | Sector members; the only types a membership rule admits |
| `admin` | The hosting ISAC; holds no machine authority |
| `vendor` | Ordinary access rules; added to circles by name |
| `government` | Explicit membership only; a receipts policy comes before the first enrolment |
| `researcher` | Contributes under terms of contribution; never reads a circle |
| `automation` | The ISAC's own machine identity, for example KEV enrichment; files for review; never reads a circle |
| `service_provider` | MSSPs; planned for Phase K |

**Machine identities.** Machine collectors authenticate with mutual TLS. Identity is the SHA-256 fingerprint of the client certificate, computed by the application, and the certificate must be issued directly by the ISAC's pinned CA. Revocation takes effect on the next request.
- A member's certificate reads its circles, files submissions and records receipts.
- A member's certificate cannot administer its own organisation, because org administration is a human action.
- The automation identity's submissions are marked `system`. This puts consequential changes in front of a human editor.
- **SSO member sessions** (people at member firms) get the member analyst's routes, capped at AMBER+STRICT. They never get an ISAC staff role.

---

## 7. Security and privacy posture

**Main protections**

**Identity**
- mTLS for machines, ISAC staff and anything RED, with a pinned issuing CA.
- Member people sign in with the ISAC's SSO and a second factor on a separate, opt-in public listener. That listener serves only member portal routes: no API, no TAXII, no admin.
- Sessions store only token hashes.

**Authorization**
- One policy module decides every authorization question, deny by default.
- A test matrix sends 14 kinds of caller to every route class and fails if a role gains or loses a power.

**Audit and proof**
- An append-only audit trail and workflow history, enforced by database triggers and grants, not by convention.
- Receipts as proof of delivery.

**Incident levers**
- Pause distribution: one switch that hides content and stops announcements.
- Quarantine an organisation: an incident pause. Every credential is refused while the membership stays open. Reconnecting requires rotated certificates and an ISAC decision on the missed backlog.
- Offboarding: deletes operational rows, keeps evidence and content, ends credentials, closes memberships and pseudonymises people. A legal hold overrides the deletion.

**Detections on the platform itself**
- The rules cover bulk retrieval, bursts of 404s, authentication and TOTP failures, unusual auditor reads, contribution floods, an editor's first distribution to a circle, and degraded components.
- Alerts go out as contentless webhooks, OCSF and CEF.

**Secrets and cryptography**
- Secrets are sealed at rest with a named, rotatable algorithm and key. The key-encryption key is read from a `0600` file, never from the environment.
- Hybrid post-quantum TLS key exchange is offered first, against "harvest now, decrypt later".
- The certificate tooling is algorithm-agile for a later move to ML-DSA signatures.

**Supply chain**
- Locked and audited dependencies, a reproducible SBOM, actions pinned by SHA and images by digest, and secret scanning before every commit.
- Mutation proofs: each security fix is re-applied as a patch, and its tests must turn red.

**Residual limits the docs admit**
- A PostgreSQL superuser can drop the append-only triggers. Separating database and application administration is an organisational control, not a technical one.
- A submitter's claim of discovery scope cannot be verified. The controls are review, contract and reviewer training.
- A stolen but valid certificate looks like its owner. Detection catches heavy readers only.
- The instance concentrates embargoed vulnerabilities affecting systemically important firms. Operational discipline at the host is a larger risk than the code.
- Content (`stix_objects.raw`) is not encrypted by the application. It relies on volume and backup encryption; BYOK is deferred.
- Anyone inside the container network who holds the proxy shared secret can forge any identity.
- A member browser taken over reads that firm's AMBER+STRICT content until the session ends, because IdP back-channel logout is not built. The ISAC's member IdP tenant is in the trusted base.
- Anonymity cannot sanitise free text, and exports cannot be recalled once downloaded.
- A member can poison the corpus with plausible false findings. Only reviewer judgement stops it.

---

## 8. Where it stands and what's next

**Build order:** A → B → C → D → E → M → F → H → P → N → O → G → I → K → L.

**Built**

| Phase | What it delivered |
|---|---|
| A | Stabilise: open findings closed, quarantine, pause, detections, status page, role split, PQ TLS |
| B | CI on GitHub |
| C | Refactor, then complexity gates |
| D | Restated goal, reserved disclosure scopes, intel model and requirement docs |
| E | Contributions on public CVEs: canonical page, readiness, disclosure split, vendor coordination circles, one-click, fast lane and post-moderation, TAXII inbox, proxy filing, KEV enrichment, telemetry |
| M | Member SSO over ordinary TLS |
| F | Reading depth, print, IoC pack, lead time; Sigma conversion blocked |
| H | VEX posture and OpenVEX export, evidence pack, auditor role, offboarding and legal hold, notification cadence and digest, sector events, connection health, sandbox circles |
| G | The repository is public on GitHub, done ahead of its place in the order |

**Remaining, in order**

| Phase | One line |
|---|---|
| **P** | Who submitted it: anonymous to members by default on every door; the anonymity choice fixed by an object's first version; submitter identity treated as RED and kept in a separate `attribution` schema that member-facing database roles cannot query at all. |
| **N** | Exploitability research for AppSec: typed, machine-readable conditions (function, platform, configuration, version, exposure) carried on `note`s, a computed per-caller view, an API and OSV export, posture pre-fill as a suggestion only. |
| **O** | Automated intake and first-pass triage: deterministic checks first (completeness, consistency, duplicates, scope), optional controlled-model checks in shadow mode, field-level "needs changes" feedback to the member within seconds. Automation routes and annotates; it never validates or deletes. Adds email-to-draft and polling members' own TAXII feeds. |
| **I** | Text documents (advisories, RFI responses) with immutable versions, comments, structured proposals, document-only grants (view or edit, with expiry), and a per-document encryption key; a finished document becomes a STIX `report` through the ordinary pipeline. |
| **K** | Approved-MSSP programme: ISAC-admitted, two-party delegation, one provider certificate per member it acts for, capped at AMBER, never STRICT or RED, no bulk export. |
| **L** | Directory integration: OIDC with group claims and SCIM from the ISAC's AD or Entra ID; directory groups as a membership source for circles (never the admission authority); roles derived by an ISAC-owned mapping, with `system_admin` never granted by a claim alone. |

**Tier 2: designed, built when a member asks**
- Real-time co-editing (Yjs, per-message authorisation, encrypted update log).
- AI assist beyond triage: extraction, deduplication suggestions, drafting the guided depth, Q&A with visibility applied before retrieval.
- Vendor CSAF ingest.
- A technology registry with exposure matching and per-member SSVC.
- Pages per job function (CISO, vulnerability-management lead, fusion lead).
- CSAF, DOCX and MISP exporters.
- Uploads with malware scanning.
- Academic research access.
- Fraud lanes: TTPs, and separately the PII-bearing entities under §314(b).
- BYOK sealed content, with a hybrid post-quantum key wrap.
- Federation between instances, private set intersection for cross-ISAC correlation, passkeys, image signing, and the GOLD EAGLE/VINCE CVE handoff.

**Owned roadmap items outside the tiers**
- A KMS phase before the first production member.
- An external penetration test before the first production member.
- An "instance compromised" tabletop exercise.
- The member TPRM (third-party risk) package, assembled as phases land.

**Phase 0, the pilot, is still Mike's to decide.** Open choices are which ISAC (possibly one Mike creates), ten members across tiers, one vendor, and a counsel gate. Three designed experiments test the levers on contribution: cost, pull and feedback speed. At pilot size, k = 5 suppression leaves counts mostly dormant until about 20 members.

---

### Open points

1. **Anonymity is the default only for one-click contributions today.** The ordinary submission schema still defaults to attributed. Making it the default everywhere, with submitter identity held in a separate schema, is Phase P.
2. **The coordinated embargo release is not built.** The `coordinated` embargo policy is documented as advisory in both extension schemas: the server never releases on a vendor's acknowledgement. Building that release, or refusing the value at ingest, is a plan item.
3. **Phase G is done out of order.** The plan places it after O, but the repository is already public.
4. **A member auditor cannot be created yet.** The role is enforced, but operators are created only from the host for the ISAC (threat model R21, pending Phase L).
5. **Automation's own filings will need an editor too** (Mike, Q35, 2026-10-15), as the ISAC's do since T12. The KEV script then leaves drafts for an editor to send, and editors get a list of drafts waiting for them (Q36). Both are queued.
