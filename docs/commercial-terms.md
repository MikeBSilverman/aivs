# Commercial terms an ISAC will ask for

> **Draft for counsel. This is not legal advice, and it was not written by a
> lawyer.** It lists the commitments an ISAC's board, counsel and member firms'
> third-party-risk teams can be expected to ask of whoever supplies, hosts or
> supports AIVS, and why each one is asked. Nothing here is drafting language,
> and nothing here is yet offered to anyone. Each term needs to be written, and
> priced, by counsel and the business together.
>
> Where an entry depends on a fact about the software, the fact is stated and is
> verifiable in this repository. Where the fact is not yet true, the entry says
> so — a term promising something the software or the operation cannot yet
> deliver should not be signed until it can.

**The relationship this is about.** AIVS is the platform an ISAC runs to manage
intelligence across the whole life of a vulnerability, with its members and
vendors. An ISAC can self-host it from the Apache-2.0 source, or have Aequora
host a dedicated single-tenant instance for it (`deployment-topology.md`). These
terms matter most for the managed case and for support contracts, but several
— licence, change of control, the build test — matter to a self-hosting ISAC
too, because it is betting its members' workflow on software it did not write.

---

## 1. Licence: the whole product is Apache-2.0, with no open core

**The term.** Every part of the product the ISAC runs is under Apache-2.0, and
a covenant that no feature it relies on will later be moved into a closed,
paid-only edition.

**Why it is asked.** An ISAC's membership will build process around the
platform. An open-core model lets the supplier hold that process to ransom by
putting the next essential feature behind a licence; the covenant is what makes
"you can always self-host" mean something.

**Fact today.** The repository is Apache-2.0 throughout (`LICENSE`), and there
is no closed edition.

## 2. Change of control: notice, and an assisted path to self-hosting

**The term.** If Aequora, or the product, changes hands, the ISAC gets advance
notice and an assisted migration to self-hosting — its data, its CA, its
configuration and a working instance on its own infrastructure — at no penalty,
on a defined timetable.

**Why it is asked.** An ISAC choosing a small supplier is choosing a supplier
whose future ownership is unknown, and an acquirer's priorities may not be the
ISAC's. The ISAC needs to know it can leave without losing its members'
history or the evidence of what was shared with whom.

**Fact today.** The ISAC holds its CA root in both hosting modes, and the
software is the same in both, so a migration is an operational exercise, not a
re-platforming. A written, tested migration runbook does not exist yet.

## 3. No cross-instance access, analytics or model training

**The term.** No one at Aequora accesses, aggregates or analyses one ISAC's
data together with another's, and no ISAC's data is used to train or tune any
model. Whatever analytics run over an ISAC's data run *in that ISAC's instance,
for that ISAC* — "whose analytics, in whose instance".

**Why it is asked.** The content is members' embargoed intelligence and their
exposure to it. A supplier that pools it across ISACs, even "anonymised", has
built the very aggregation an ISAC exists to control, and has made itself a
party to every ISAC's sharing agreement without signing any of them.

**Fact today.** Each instance is a separate database, host and CA; there is no
cross-instance channel in the software (`deployment-topology.md`). AI
assistance, when it exists, uses only a model the ISAC controls, never a
public model API (`open-decisions.md`).

## 4. No supplier account in the application

**The term.** Aequora holds no portal or API account on a customer instance.
Any access the ISAC grants for support is a named, time-limited account the
ISAC creates and can see in its own audit log.

**Why it is asked.** Editorial control — what reaches members, and when — is
the ISAC's legal judgement. An account the supplier holds by default is a
standing path around it.

**Fact today, and its limit.** Editorial actions require a human session in an
ISAC role, and the issuing-CA holder cannot mint editorial power with a
certificate alone. But in the managed mode Aequora's operators hold
infrastructure and database access, which this term does not remove — it can
only be bounded by the hosting agreement and audited (`deployment-topology.md`
§1). The term must not be drafted as if it closed that exposure. An ISAC that
cannot accept it should self-host.

## 5. Subprocessor list

**The term.** A complete, current list of every third party that processes or
can access the ISAC's data, with advance notice and a right to object before a
new one is added.

**Why it is asked.** Member firms' TPRM teams must assess the ISAC's suppliers'
suppliers; a list they cannot see is a finding against the ISAC.

**Fact today.** No managed instance runs yet, so there is no list to publish.

## 6. Penetration testing, annually, with results shared

**The term.** An independent penetration test at least annually and before the
first production member, with a summary of findings and their remediation
shared with the ISAC, and through it with member TPRM teams under NDA.

**Why it is asked.** It is the first document a member firm's TPRM questionnaire
asks for.

**Fact today.** No external penetration test has been performed. One is on the
roadmap before the first production member.

## 7. A fix SLA for vulnerabilities in the software

**The term.** Committed times to *fix* — not merely to acknowledge — a
vulnerability in AIVS itself, by severity, with the ISAC told before any public
disclosure.

**Why it is asked.** An acknowledgement SLA costs nothing to meet. What an ISAC
needs is to know how long its members' intelligence can sit behind a known
defect.

**Fact today.** `SECURITY.md` commits to acknowledging a private report within
three business days and to an initial assessment within ten. There is no
commitment on time to fix.

## 8. A reproducible build, as the escrow test

**The term.** Instead of a conventional source-code escrow, the ISAC can build
the release it runs from the published source and get the same artefact,
verified by hash. If the supplier disappears, the ISAC already holds everything
it needs.

**Why it is asked.** Escrow agreements are slow to invoke and often hold source
that no longer builds. A build the ISAC can reproduce today is a stronger
guarantee than a deposit it may never open.

**Fact today.** The SBOM is reproducible: an unchanged lockfile produces a
byte-identical CycloneDX document (`scripts/generate-sbom.sh`). The release
bundle and container image are **not** yet reproducible to a published hash,
and signed provenance is not in place. This term cannot be offered until both
are.

## 9. Per-instance pricing

**The term.** Price per instance, not per member, per seat or per object.

**Why it is asked.** Per-member or per-seat pricing taxes exactly the behaviour
the ISAC is trying to encourage — more members, more people at each member
reading and contributing. Per-instance pricing makes the platform's cost
independent of its success.

## 10. A customer council that can pull work forward

**The term.** The ISACs using the product form a council that can pull designed
but unbuilt work — the items the README's status table lists as "later" — onto
the roadmap.

**Why it is asked.** Much of the roadmap is deliberately held as designs to be
built "when a member asks". The council is the mechanism by which that asking
has force, rather than depending on the supplier's goodwill.
