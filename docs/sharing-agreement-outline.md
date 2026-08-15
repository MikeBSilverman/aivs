# Membership and sharing agreement — outline for counsel

> **This is not legal advice, and it was not written by a lawyer.**
>
> It is a structural outline: the topics a membership agreement for an AIVS
> instance needs to cover, and the technical facts about how the system actually
> behaves that counsel needs in order to draft accurate obligations. Nothing here
> is drafting language. Every clause must be written, reviewed, and adapted to
> the hosting ISAC's jurisdiction, corporate form, existing member agreements,
> insurance position, and regulatory posture by qualified counsel.
>
> Where this document states how AIVS behaves, that is a factual claim about the
> software, verifiable in the code. Where it suggests what an agreement should
> address, that is a checklist, not a recommendation about substance.

**Parties:** the hosting ISAC and each member firm. Where the instance is hosted
by a third party on the ISAC's behalf, that relationship is a separate hosting
agreement between the ISAC and the host, and the member's counterparty remains
the ISAC.

---

## 0. Draft the protections expressly; do not inherit them

The agreement should stand on its own terms rather than resting on statutory
protection that may or may not apply to a given member, in a given jurisdiction,
at a given time. That is ordinary drafting hygiene, and it is what makes the
same outline usable by an ISAC outside the US.

> **Statutory context, for counsel to verify rather than assume.** In the US, the
> Cybersecurity Information Sharing Act of 2015 supplied the liability
> protections, antitrust safe harbour, and FOIA exemptions much of the sector's
> sharing was built on. Those protections lapsed on 30 September 2025 and
> renewal was pending as of early 2026. Whether they are in force, and whether
> they reach this arrangement, is a question for the hosting ISAC's counsel — not
> an assumption the platform or this outline makes on their behalf.

Practically, that means:

- Do not assume statutory antitrust safe harbour for information exchanged
  between competing financial institutions. Address antitrust expressly (§8).
- Do not assume statutory liability protection for sharing or receiving. Allocate
  liability expressly (§9).
- Do not assume FOIA or state-equivalent exemptions apply to material shared with
  or through a government-adjacent entity. Address regulatory disclosure
  expressly (§10).
- Consider a provision that adjusts the agreement's operation if the statutory
  protections are restored, so the parties do not have to renegotiate to benefit
  from them.

The agreement must carry weight the statute previously carried. That is the
single most important framing point in this outline.

---

## 1. Definitions

Terms that must be defined precisely because the system's behaviour depends on
them:

| Term | Notes for counsel |
| --- | --- |
| **Shared Information** | Content submitted to or received from the instance. Note that content is STIX 2.1 objects, not prose reports. |
| **Circle** | A defined subset of members. Membership determines who receives what. |
| **TLP Designation** | Traffic Light Protocol **2.0** — specifically 2.0, which differs materially from 1.0. See §4. |
| **Embargo** | A period during which received content must not be disclosed. |
| **Distribution** | The ISAC's act of making Shared Information available to a Circle. Note: the **member never distributes**; only the ISAC does. |
| **Discovery Scope** | The submitter's attested relationship to the affected system: `own_product`, `own_estate`, or `ai_system`. See §2. |
| **Receipt** | The system-generated record that a member's client retrieved content. |
| **Anonymised Submission** | Content distributed with the submitter's identity withheld from other members but **known to the ISAC**. See §3. |

---

## 2. Submitter attestation — the core content-scope covenant

**This is the most important substantive section.** It is what keeps the ISAC out
of coordinated-disclosure consent problems and tortious interference exposure.

### The technical fact

AIVS accepts submissions in exactly three scopes, enforced by a non-nullable
database column and a JSON Schema enum. There is deliberately no value for "a
third party's software":

| Scope | Meaning |
| --- | --- |
| `own_product` | A vulnerability in a product the submitter builds, ships, or licences to others. |
| `own_estate` | A vulnerability in the submitter's own deployed environment. |
| `ai_system` | An AI-system vulnerability generally — prompt injection, model supply chain, agentic tooling — where disclosure norms are still unformed. |

**AIVS cannot verify the claim.** It enforces the *shape* of the assertion, not
its truth. The ISAC reviews before distributing, but a reviewer cannot establish
that a firm actually builds a product or operates an estate. The contractual
attestation is therefore not a formality — it is the primary control, with the
review as a secondary one.

### What the agreement should address

- An affirmative representation and warranty, made **per submission**, that the
  content falls within one of the three scopes and that the member has the right
  to disclose it.
- An express covenant **not** to submit undisclosed vulnerabilities in an
  uninvolved third party's product or service, however framed.
- Treatment of the boundary cases counsel should expect:
  - A vulnerability in a third-party component *as deployed in the member's own
    estate*: is that `own_estate`? Where does the member's disclosure right end
    and the component vendor's begin?
  - A vulnerability in a product the member has licensed or white-labelled.
  - An `ai_system` finding that necessarily names a specific model vendor.
  - A finding in a jointly developed or open-source system.
- What happens if the member is already in a coordinated disclosure process with
  a third party for the same finding.
- Indemnification running from the member to the ISAC for claims arising from a
  false or inaccurate scope attestation. This is the clause the exposure actually
  turns on.
- The ISAC's unqualified right to reject, hold, or decline to distribute any
  submission for any reason, without liability and without an obligation to
  explain. Its review is a legal control, and it must not be constrained by a
  service-level obligation.
- The member's obligation to notify the ISAC promptly if it learns that a
  submission's scope attestation was inaccurate.

---

## 3. Anonymisation

### The technical fact

A submitter may elect anonymous distribution. AIVS then rewrites `created_by_ref`
on outbound objects to the ISAC's own identity and withholds the submitter from
every member-facing view.

**The ISAC always knows who submitted.** Receipts and the audit trail resolve
internally. Anonymity is from *other members*, never from the ISAC.

### What the agreement should address

- Anonymity is expressly defined as being from other members, and the ISAC's
  retained knowledge is stated in the agreement rather than discovered later.
- Circumstances under which the ISAC may or must reveal the submitter: legal
  process, regulatory demand, a member's claim of harm, an inaccurate scope
  attestation. **The member should know the list before they rely on anonymity.**
- Whether the ISAC will notify the submitter before revealing them, and whether
  it will resist process on their behalf.
- Acknowledgment that anonymisation is not de-identification: content describing
  a specific product or estate may identify the submitter regardless of the
  metadata. The ISAC does not warrant that anonymisation prevents inference.
- Whether other members are contractually barred from attempting to deanonymise
  a submitter. Consider making the attempt itself a breach.

---

## 4. TLP 2.0 handling obligations

### The technical fact

Every distributed object carries a TLP **2.0** marking. These are *not* TLP 1.0.
GREEN, AMBER, and RED have different UUIDs from their TLP 1.0 namesakes and
different definitions, and TLP 2.0 introduced AMBER+STRICT and replaced WHITE
with CLEAR. AIVS never emits TLP 1.0 identifiers and never silently upgrades one
to its 2.0 namesake, because the handling obligations differ.

Circles carry a `minimum_tlp` floor: content cannot be distributed into a circle
under a marking looser than that circle's floor.

### What the agreement should address

- The agreement must reference **TLP 2.0 specifically**, by version, and
  incorporate the FIRST TLP 2.0 standard definitions by reference.
- Per-designation handling obligations, written out rather than incorporated by
  reference alone:

| Designation | Obligation to state expressly |
| --- | --- |
| `TLP:CLEAR` | Unlimited disclosure, subject to copyright. |
| `TLP:GREEN` | The member's community and sector peers; **not public**. Define "community". |
| `TLP:AMBER` | The member's organisation and its clients, need-to-know. **Define "clients"** — for a bank this is a materially broad set and the definition does real work. |
| `TLP:AMBER+STRICT` | The member's organisation **only**. Not clients, not vendors, not the member's MSSP or outsourced SOC. Address outsourced security operations expressly — it is the most common breach path. |
| `TLP:RED` | Named individual recipients only. No onward sharing at all, including within the organisation. |

- Onward sharing to affiliates, subsidiaries, and parent entities: are these
  "the organisation" for AMBER+STRICT purposes? For a GSIB with hundreds of legal
  entities this needs an explicit answer.
- Whether contractors, outsourced SOC providers, and cloud security vendors count
  as the organisation. Usually they must not, for AMBER+STRICT.
- Whether the member may use Shared Information to protect its own estate without
  restriction (almost certainly yes, and it should be stated so members act).
- Whether the member may share with its regulators, and on what terms (§10).
- Storage, retention, and destruction obligations, and whether these survive
  termination.
- Whether the member may re-mark content more restrictively (yes) or less
  restrictively (no).

---

## 5. Embargo obligations

### The technical fact

AIVS enforces embargoes **server-side**: embargoed content is not visible to a
member until its release instant. A member cannot receive embargoed content
early, and cannot poll harder to get it sooner.

Once a member receives content, the embargo obligation is **entirely
contractual**. AIVS has no technical control over what a member does with content
it holds.

Three embargo policies exist: `timer` (a fixed release time), `coordinated` (tied
to an external process), and `manual`. An embargo may be extended or lifted early
by the ISAC; `lifted_early` is recorded as such.

### What the agreement should address

- The obligation: not to disclose, publish, or act in a way that reveals the
  content before the release instant.
- **Whether the member may act internally on embargoed content before release** —
  patching, compensating controls, monitoring. Almost certainly yes; this is the
  entire point of early warning. Say so, because a member's counsel reading a
  bare non-disclosure obligation may advise them not to act, which defeats the
  system.
- Where "acting internally" shades into disclosure: raising a ticket with a
  vendor, deploying a detection rule with a descriptive name, filing a regulatory
  notification.
- Consequences of breach, stated concretely (§6).
- The ISAC's right to extend an embargo, and any limit on it.
- The ISAC's right to lift an embargo early, and when.
- What happens when a third party publishes the same vulnerability during the
  embargo. Is the member released automatically, or must they wait for the ISAC?
  This will happen; decide it in advance.
- The member's obligation to notify the ISAC immediately on becoming aware of a
  breach, whether their own or another's.

---

## 6. Consequences of breach

Counsel will have views on remedies. The structural points AIVS supplies:

- **The ISAC can prove what a member received and when.** Receipts are
  server-written on delivery, not member-asserted, and live in an append-only
  table with database-level modification triggers.
- **Suspension is immediate and complete.** Setting an organisation's status to
  `suspended` is checked first in every authorisation decision and takes effect
  on the member's next request. There is no notice period built into the
  software; if the agreement requires one, it is a process obligation, not a
  technical one.
- **Certificate revocation is immediate**, effective on the next request, with no
  CRL propagation delay.
- **Removal from a circle stops future access but not past receipt.** A member
  removed from a circle keeps everything they already pulled. This is a permanent
  fact about the system and the agreement should not imply otherwise.

Topics to address: graduated remedies; whether breach of embargo is treated
differently from breach of TLP handling; liquidated damages (probably
unenforceable and probably not worth the negotiation, but counsel should decide);
notification to other members of a suspension and what may be said; whether
reinstatement is possible and on what conditions; survival of obligations after
termination.

**Note the limit:** the receipt proves delivery to a client holding the
organisation's certificate. It does not prove a human read the content, and it
does not prove who at the member firm did what. Remedies should not be drafted as
if it does.

---

## 7. Permitted onward sharing

Distinct from TLP handling, and worth its own section because members will
actually ask:

- May a member share with **another ISAC** they belong to? Almost certainly not
  without consent, but state it.
- May a member share with a **government agency** — CISA, a sector regulator, a
  national CERT — and under what designations? Address whether the member must
  notify the ISAC.
- May a member share with the **affected vendor**, where the content concerns a
  product the member deploys? This is a common and often desirable case; a bare
  prohibition will be ignored.
- May a member use the content in **derived work** — internal advisories,
  detection rules, board reporting, threat models — and what marking travels with
  the derivative?
- May a member share **aggregate or statistical** information ("we received 14
  pre-CVE warnings this quarter")?
- What happens on **compelled disclosure**: notice to the ISAC, cooperation, the
  member's obligation to seek protective treatment.
- **Derived-work marking** is the practically important one. A detection rule
  written from AMBER+STRICT content, deployed to a shared platform, is a
  disclosure. Members will not see it that way unless the agreement says so.

---

## 8. Antitrust

Members are frequently direct competitors. With the CISA 2015 antitrust safe
harbour lapsed (§0), this cannot be left implicit.

Counsel should address: an express statement that the arrangement is for
cybersecurity purposes only; a prohibition on exchanging competitively sensitive
information (pricing, customers, strategy, capacity) through the platform;
whether counsel review is required before circles are formed along competitive
lines; conduct rules for any meetings or coordination the platform occasions; and
whether the ISAC needs its own antitrust compliance programme covering the
platform.

---

## 9. Liability, warranties, and disclaimers

### Technical facts counsel should have

- AIVS distributes **warning, not proof-of-concept**. The extension carries a
  boolean stating whether the submitter *holds* a reproduction; the reproduction
  itself is never distributed.
- Content is a submitter's assessment. `ai_confidence` is the submitter's own
  0–100 estimate, and **its absence means "not asserted", not "low"**.
- CVSS scores are v4.0 and are the submitter's calculation, not an independent
  one.
- The ISAC reviews submissions but does not independently verify vulnerabilities.
- The system has no availability guarantee in the software. Any SLA is a hosting
  commitment, drafted separately.

### Topics to address

- Disclaimer of warranty on shared content: no warranty of accuracy,
  completeness, fitness, or that acting on it will prevent anything.
- **No duty to warn.** Whether the ISAC has any obligation to distribute any
  particular content, or to distribute at all. Consider explicitly disclaiming a
  duty to warn arising from the mere operation of the platform — a system that
  builds a record of who was warned may also build an argument about who was not.
  This deserves counsel's specific attention.
- Limitation of liability, with the usual carve-outs.
- Whether members may rely on content for regulatory compliance purposes.
- Allocation of liability where a member acts on content and suffers harm.
- Allocation where a member's *inaction* on delivered content is later
  scrutinised. Receipts prove delivery; that cuts both ways.
- Insurance requirements, if any.
- The hosting arrangement, disclosed to members: whether the instance is
  self-hosted or operated by a third party on the ISAC's behalf, and what access
  that party's personnel have. **Members are entitled to know that a third party
  can read their content**, and should be told in the agreement rather than in a
  breach notification.

---

## 10. Regulatory and government disclosure

With FOIA and equivalent protections uncertain (§0):

- Whether the ISAC may or must share content with government entities, and under
  what designations.
- Whether a member may share received content with its own regulators, and
  whether it must notify the ISAC.
- Treatment of content that becomes subject to a records request at a
  government-adjacent entity.
- Whether submissions can be structured to preserve privilege, and the limits of
  that.
- Mandatory incident-reporting interaction: if a member's receipt of AIVS content
  triggers a reporting obligation, how is that reconciled with the embargo? This
  is a genuine conflict and should not be discovered during an incident.

---

## 11. Data protection and privacy

Content is technical and should contain little personal data, but:

- An obligation on submitters not to include personal data unless necessary.
- Operator account data (names, emails) is personal data and is processed by the
  ISAC and, in managed hosting, by the host.
- Cross-border transfer, where members or the host are in different
  jurisdictions.
- **The audit log is immutable by design.** A deletion request cannot be honoured
  against it. Counsel must reconcile this with applicable data protection law
  before the instance goes live, not after a request arrives. The technical fact
  is unambiguous: database triggers prevent UPDATE, DELETE, and TRUNCATE on
  `audit_log` and `submission_transitions`.
- Retention periods, and what "deletion" means for append-only records.

---

## 12. Term, termination, and exit

- Term and renewal.
- Termination for convenience, for breach, and for insolvency.
- **What survives:** TLP handling obligations, embargo obligations, and
  confidentiality must survive termination, because the member retains everything
  they pulled.
- Whether the member must destroy received content on termination, and how
  compliance is evidenced. Note that the ISAC cannot verify destruction.
- Whether the ISAC retains the departed member's submissions and receipts. It
  must, technically — foreign keys are `RESTRICT` and evidentiary tables are
  append-only — so the agreement should permit it.
- What the member gets on exit: an export of their own submissions and receipts?
- Effect of an ISAC changing hosting mode or host.

---

## 13. Operational obligations of the member

Small but load-bearing, because several security properties depend on them:

- Protect client certificate private keys; never transmit them; report suspected
  compromise **immediately** (revocation is effective on the next request).
- Notify the ISAC of egress network changes **before** they take effect.
- Keep certificates current; complete rotation before expiry.
- Maintain accurate technical and security contacts.
- Maintain the ability to receive content — the ISAC's warning obligation, if
  any, should not extend to a member whose client has been broken for six months.
- Verify webhook HMAC signatures where webhooks are used.
- Correct TAXII cursor handling. A member whose client mishandles `added_after`
  will silently miss content — including, structurally, embargoed content, whose
  `date_added` falls later than the material distributed around it. **The
  agreement should place responsibility for correct client operation on the
  member**, since the ISAC cannot detect the difference between "polled and
  received nothing" and "polled wrongly and skipped something".
- Whether the member must acknowledge receipt of critical content within a stated
  period, and what follows if they do not.

---

## 14. Governance

- How circles are created, and who decides membership.
- Appeal or review of a rejected submission.
- Amendment process for the agreement.
- Dispute resolution and governing law.
- Whether members have any collective governance role over the instance's
  operation.
- ISAC obligations on transparency: what it will tell members about its own
  access, its hosting arrangements, and incidents affecting the platform.

---

## Checklist of technical facts counsel must have

Consolidated, because each has drafting consequences:

| # | Fact | Where it bears |
| --- | --- | --- |
| 1 | AIVS **cannot verify** a `discovery_scope` attestation. | §2 — the attestation is the primary control |
| 2 | Members **never distribute**; only the ISAC does. | §2, §9 |
| 3 | Anonymity is from other members, **never from the ISAC**. | §3 |
| 4 | Markings are **TLP 2.0**, materially different from 1.0. | §4 |
| 5 | Embargoes are enforced server-side **before** delivery, and contractually **after**. | §5 |
| 6 | Distributed content **cannot be un-distributed**. | §5, §6, §12 |
| 7 | Retrieval receipts are **server-written**, not member-asserted. | §6 |
| 8 | Receipts prove **delivery to an organisation's client**, not that a human read it. | §6, §9 |
| 9 | Suspension and revocation are effective on the **next request**. | §6 |
| 10 | Removing a member from a circle **does not recover** what they already pulled. | §6, §12 |
| 11 | The audit log is **immutable** — no deletion is possible against it. | §11 |
| 12 | Superseded content **remains readable** to members. | §5, §12 |
| 13 | In managed hosting, **the host's personnel can read member content**. | §9 |
| 14 | AIVS distributes **warning, not proof-of-concept**. | §9 |
| 15 | `ai_confidence` absent means **not asserted**, not low. | §9 |
| 16 | A member whose TAXII cursor handling is wrong **silently misses content**. | §13 |

---

## Reminder

This outline is a starting point for a conversation with counsel, not a
substitute for one. The statutory position described in §0 must be verified as at
the date of drafting.
