# End-to-end encryption and bring-your-own-key

**Status:** design agreed, implementation scheduled after Phase 5.
**Decision owner:** Mike Silverman.

This document specifies how AIVS carries submission content that the hosting
infrastructure cannot read, and how that interacts with embargo, key rotation,
and the Traffic Light Protocol.

---

## 1. Why

AIVS aggregates embargoed, pre-disclosure vulnerability intelligence affecting
GSIBs and Section 9 entities. That makes an instance one of the highest-value
targets its members could collectively construct, and it makes the honest answer
to "what happens if you are breached" the single hardest question in every
prospective member's third-party-risk review.

Encrypting payloads to their recipients changes that answer. A breach of the
host yields ciphertext. A subpoena served on the host yields ciphertext. A rogue
administrator gets ciphertext. The residual risk moves from *content disclosure*
to *metadata disclosure and denial of service*, which is a category change, not
an increment.

It is also the feature that makes the managed-hosting business defensible.
"Aequora operates your instance and cannot read your members' submissions" is a
claim an ISAC can repeat to its own board.

---

## 2. What is sealed and what is not

**Decision: full payload seal, with the hosting ISAC included in the recipient
set.**

The hosting ISAC is a recipient because it has legitimate need to read content
it distributes: validating submissions before release (the checkpoint that keeps
AIVS clear of the coordinated-disclosure consent problem), correlating findings
across submissions, and producing its own analysis for members. Excluding it
would force the ISAC to either approve sealed envelopes unseen or maintain a
separate plaintext copy outside the system — and a shadow copy outside the
audited store is strictly worse than a recipient slot inside it.

So the claim AIVS makes is precise, and must be stated precisely in sales
material: **the infrastructure cannot read submissions; the ISAC that operates
the community can.** That is a materially different and much stronger promise
than encryption at rest, and it is honest.

| Layer | Encrypted? | Rationale |
| --- | --- | --- |
| STIX object envelope (`id`, `type`, `created`, `modified`, `spec_version`) | No | TAXII needs it for versioning, dedup, and paging |
| Routing metadata (circle, TLP marking, embargo state, `date_added`) | No | The server enforces access on it |
| Triage metadata (`name`, affected vendor/product/version, CVSS vector and score, `discovery_scope`, `cve_status`) | No | Members must triage without decrypting everything; the ISAC routes on it |
| **Sensitive payload** (technical detail, reproduction, exploit-chain specifics, remediation detail, attachments) | **Yes** | The part whose disclosure actually hurts |

Metadata is not nothing: knowing that a GSIB submitted a critical finding
affecting a named product is itself sensitive. This design does not claim
otherwise. Members who need to conceal even that use anonymous submission
(`distribute_anonymously`), which withholds the submitter from consumers while
the ISAC retains attribution internally.

---

## 3. Key principals — organisation *and* operator

An encryption key belongs to a **principal**, and a principal is either an
organisation or a named human operator. This is the part worth dwelling on,
because it is what makes TLP mean something.

**Organisation keys** are the default. A member firm's SIEM or TIP ingests on
behalf of the firm, not a person; automated collection cannot depend on an
individual being present. One active organisation key at a time, held wherever
the firm chooses — an HSM, a cloud KMS, or a file on the collector.

**Operator keys** are optional, per named analyst, generated in the portal and
held by that individual.

The reason to support both is that TLP 2.0 already draws exactly this
distinction, and today every ISAC enforces it with a coloured label and a
promise:

| Marking | TLP 2.0 handling rule | AIVS recipient set |
| --- | --- | --- |
| `TLP:CLEAR`, `TLP:GREEN` | Community-wide | Organisation keys of every member of the circle |
| `TLP:AMBER` | Recipient's organisation and its clients | Organisation keys of every member of the circle |
| `TLP:AMBER+STRICT` | Recipient's organisation only | Organisation key of each member org, no onward wrap |
| **`TLP:RED`** | **Named recipients only** | **Only the operator keys explicitly named by the submitter** |

`TLP:RED` is defined by FIRST as "for the eyes and ears of individual recipients
only". Under this design that stops being an honour-system label and becomes a
cryptographic fact: a `TLP:RED` submission is wrapped only to the specific
analysts named on it, and nobody else — not their colleagues, not their firm's
collector, not the ISAC's automation — holds a key that opens it.

That is a genuinely novel capability for an ISAC feed, and it is the strongest
single answer to "why would we share our most sensitive finding with you".

The hosting ISAC's organisation key is included in every recipient set,
including `TLP:RED`, per section 2. A submitter who is unwilling to include the
ISAC on a specific finding should not be sharing that finding through the ISAC.

---

## 4. Cryptographic construction

Deliberately boring. Nothing here is novel; every primitive is standard and every
format is one a bank's cryptography reviewer already recognises.

```
content key  CEK  = 32 random bytes (os.urandom)
ciphertext        = AES-256-GCM(CEK, payload, aad = binding)
per recipient     = ECDH-ES + A256KW wrap of CEK to that principal's public key
serialisation     = JWE General JSON Serialization (RFC 7516), multi-recipient
recipient curve   = P-384, matching the certificate authority in deploy/ca/
```

**Format: JWE General JSON Serialization.** Multi-recipient is native to it, it
is a published standard, and vendors bringing their own key can use existing
JOSE tooling in any language rather than an AIVS-specific library. Use a vetted
implementation; do not hand-roll the JOSE layer.

**Additional authenticated data.** The GCM AAD binds the ciphertext to the STIX
object identity — `id`, `modified`, and the submission's circle set — so a
ciphertext lifted from one object and pasted into another fails to authenticate
rather than decrypting into the wrong context.

**Recipient transparency.** The JWE `recipients` array carries a `kid` per
recipient. Any member who can decrypt can therefore enumerate exactly who else
can. This is the mechanism that turns the promise in section 2 into something
each participant verifies on every object, rather than trusting. Combined with
the key registry below, a host that quietly wrapped an extra copy to itself
could not do so undetectably.

---

## 5. The key registry, and why it is append-only

A new table, `encryption_keys`:

| Column | Notes |
| --- | --- |
| `kid` | Stable key identifier, referenced by every JWE that wraps to it |
| `principal_type` | `organization` or `operator` |
| `principal_id` | The org or operator |
| `public_key` | SPKI DER. **Public material only — private keys never reach AIVS** |
| `algorithm` | `ECDH-ES+A256KW` / P-384 |
| `status` | `active`, `retired`, `revoked` |
| `valid_from`, `retired_at` | Bounds the window in which this key was current |

Two properties matter more than the schema:

**It is append-only**, enforced by the same database triggers that protect the
audit log. A key's history cannot be rewritten.

**It is readable by every member.** The registry is the transparency log. A
member's client verifies, before submitting, that the recipient set it is about
to wrap for matches the circle roster and nothing else.

This is what closes the attack you raised — a participant who publishes key A,
receives content, then rotates to key B and later claims they never held a key
that could read it. Which key was active at time T is a matter of immutable
record, and the receipt for their retrieval names the `kid` used.

---

## 6. Rotation, retention, and loss

The rule that prevents most of the pain, stated once: **encryption keys roll
forward, decryption keys are retained.**

- **A recipient rotating** gets a new active key for future content. Their old
  private keys must be kept to read the archive. The reference client maintains
  an encrypted keyring and does this automatically, because a firm that treats
  these like TLS certificates — rotate and discard — will silently lose access
  to its own history and not discover it for months.
- **A submitter rotating** affects nothing. Their key wraps and signs; it is not
  needed to unwrap.
- **A compromised key** is marked `revoked`. Future content excludes it.
  Content already wrapped to it must be assumed exposed, and the registry makes
  the exposure window exactly computable — which is precisely the incident
  question an ISAC will be asked.
- **Late circle joiners** cannot read content wrapped before they joined. Two
  options, and the default is the second: the submitter's client re-wraps on
  request, or the member simply receives content from their join date forward.
  The latter is how every feed subscription already behaves and needs no
  explanation.
- **Key loss is content loss.** There is no server-side recovery, by
  construction — that is the whole point. Each firm needs its own escrow, under
  its own control. This must be stated in the onboarding documentation in words
  a firm cannot later claim to have missed.

---

## 7. Embargo

Encryption and timed release are in genuine tension: whoever can decrypt at
release must already hold the key material.

**The server gates delivery, not decryption.** Content is wrapped to recipients
at distribution; visibility is withheld until `date_added` arrives, exactly as
today. A malicious operator could release *early* — but cannot read, and early
release is visible in the immutable audit log and to every recipient.

That reduces the operator from "can read everything" to "can mis-time
delivery". Accept that, and keep the ability to release early on purpose, which
this domain needs: when a finding starts being exploited in the wild, an ISAC
must be able to push it immediately.

**Optional future layer: cryptographic timelock.** Encrypting the content key to
a future drand beacon round would make early release mathematically impossible
rather than merely detectable. Real and deployed, but it forecloses emergency
early release and adds an external dependency that critical-infrastructure
firms may not accept. If built, it is per-submission opt-in, never the default,
and explicitly not in scope for v1.

---

## 8. Reserved STIX extension fields

Reserved in `schema-1.0.json` **now**, ahead of implementation, so that adding
sealed payloads later is an additive change within 1.x rather than a breaking
one for members who have already integrated:

| Property | Meaning |
| --- | --- |
| `sealed_payload` | The JWE General JSON Serialization object |
| `sealed_payload_recipients` | Array of `kid` values, duplicated outside the JWE so a consumer can see the recipient set without parsing it |
| `sealed_payload_content_type` | Media type of the plaintext once decrypted |

A TIP that does not understand the extension still sees a valid STIX
`vulnerability` with usable triage metadata, and simply cannot open the sealed
part. Graceful degradation is deliberate: interoperability with a member's
existing tooling is the whole reason AIVS speaks TAXII.

---

## 9. What this does not protect against

Stated plainly, because a threat model that oversells is worse than none:

- **The hosting ISAC**, which is a recipient by design (section 2).
- **Metadata analysis.** Who submitted, when, affecting which product, at what
  severity, and which firms collected it — all visible to the host.
- **A compromised member endpoint.** Encryption protects content in transit and
  at rest in AIVS. It does nothing once a recipient's own machine is owned.
- **Denial of service or content destruction** by whoever controls the
  infrastructure. Confidentiality is protected; availability is not.
- **Traffic analysis.** Retrieval receipts, which are a deliberate product
  feature, reveal which firms are paying attention to which findings.

Whether *metadata* could also be sealed while keeping the server able to route
and filter on it — the encrypted-search question — is assessed in
`docs/open-decisions.md`. The short version is that it is not adopted, and the
reasons are in that entry rather than duplicated here.

---

## 10. How members open sealed content

A sealed payload is worthless to a member who cannot get it into the tool they
already triage in. This section decides how that happens, because the obvious
answer — extend a STIX/TAXII client to understand the extension — is the wrong
one and would be discovered to be wrong only after the work was done.

### The reference client is not the integration path, and must not become it

Almost no member firm collects with an open-source Python TAXII client. They
collect with Anomali, EclecticIQ, ThreatQ, Microsoft Sentinel, Splunk, OpenCTI
or MISP. A fork of `cti-taxii-client` reaches tooling authors, not the firms
whose adoption decides whether AIVS exists — while creating a permanent
maintenance obligation and a diligence question ("you run a fork of the
reference client?") that costs exactly the trust the encryption was bought to
earn.

This is why section 4 chose a published multi-recipient format over anything
bespoke, and section 8 made an unaware consumer degrade to valid, triage-able
STIX. Both were chosen so that *no client anywhere is required to change*. The
integration work is therefore a written format plus a small unwrap helper, not a
client anyone has to adopt.

### `aivs proxy`: a decrypting sidecar on loopback

The member points their existing TAXII connector at the sidecar instead of at
the instance. It holds the mTLS identity and the organisation's private key,
polls upstream, unwraps `sealed_payload`, splices the plaintext back into the
object, and serves ordinary TAXII 2.1. The TIP is unchanged, which is what makes
this work for the commercial products that can never be modified — one
implementation covers all of them.

It shares the poll path with `aivs poll`, so the cursor discipline and the
stdout/stderr separation that already make `aivs poll | ingest` safe are not
reimplemented.

Four constraints, each of which undoes the design if dropped:

- **Loopback bind only.** A network-reachable decrypting proxy is a keyless
  decryption oracle for everyone inside the firm's perimeter, and it collapses
  `TLP:AMBER+STRICT` back into "whoever can reach the box". Not configurable to
  a routable address.
- **No plaintext at rest.** No response cache, no spool file, no debug dump.
- **It verifies the recipient set before submitting**, against the registry in
  section 5. The transparency property is a promise the reference client has to
  actually keep; a `kid` list nobody checks is section 5 written in a response
  body and enforced nowhere.
- **It refuses `TLP:RED`, and says why.** See below — this is correct behaviour,
  and the error message is the documentation most members will read.

### `TLP:RED` is deliberately not a collector path

Section 3 makes `TLP:RED` wrap only to named operator keys. A firm's shared
collector being able to open one would destroy the single property that makes
`TLP:RED` a cryptographic fact rather than a coloured label — so RED decrypts in
the portal via WebCrypto, with the operator's private key never leaving their
browser or OS keystore, or with `aivs open` on that analyst's own workstation.

"Why can't my SIEM see the RED ones" is the first support question this feature
will generate. Answered in advance it is the strongest thing about the design;
answered after the fact it reads as a defect.

### What is offered to other implementers

A vendor-neutral format note and a reference unwrap of roughly fifty lines using
standard JOSE tooling — enough for a connector author to implement without
reading this codebase. OpenCTI and MISP are the two where contributing an actual
connector is worthwhile, and only once a member asks for one: a connector nobody
requested is maintenance acquired without adoption.

### Order of work, and one prerequisite

Secrets at rest first — BYOK does not close that hole and it is the live one.
Then the format note and unwrap in the reference client, then the sidecar, then
portal RED decryption, then connectors on demand.

**`packages/aivs-client` needs its own test suite before the sidecar, not
after.** It has none today, which is how a client that pinned the CA and then
connected anonymously survived review. A component whose entire job is holding a
private key and terminating one TLS connection in order to open another is the
worst possible place to add untested surface.
