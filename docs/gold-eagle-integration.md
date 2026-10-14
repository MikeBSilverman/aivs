# GOLD EAGLE integration — CVE handoff and return path

**Status:** queued. Not scheduled against a phase yet.
**Depends on:** nothing in AIVS. The data model already anticipates this.
**Downstream:** GOLD EAGLE fronts CERT/CC's VINCE — see §4a, which supersedes
parts of the §3 sketch.

AIVS is the platform an ISAC runs to manage intelligence across the whole life
of a vulnerability, and its first lane — the one built today — is the window
*before* CVE publication. GOLD EAGLE helps firms issue CVEs at scale. Today
those are two tools; this integration makes them one
pipeline, so a finding travels from private early warning to public disclosure
without being re-keyed, and the public identifier finds its way back to the
members who were warned first.

---

## 1. The loop this closes

```
   member firm                AIVS                    GOLD EAGLE         public
        |                       |                          |               |
   submit finding ─────────────>|                          |               |
        |            ISAC validates, distributes           |               |
        |          circles receive it under embargo        |               |
        |                       |                          |               |
        |        ready to disclose ──── export ───────────>|               |
        |                       |                   CNA issues CVE         |
        |                       |<─── CVE-2026-NNNNN ──────|               |
        |                       |                          |──────────────>|
        |<── updated object ────|                          |               |
        |   (cve_status: published, cve_id set)            |               |
```

The step that matters commercially is the last one. A member who acted on an
AIVS warning six weeks early should not have to manually reconcile it against a
CVE feed later; the object they already hold updates in place, and their TIP
correlates the private warning to the public identifier automatically.

---

## 2. What already supports this

Nothing needs to be reserved or migrated, which is why this can sit in the queue
without blocking anything:

| Capability | Where it already exists |
| --- | --- |
| `cve_status` (`pre-cve` → `requested` → `assigned` → `published`) | AIVS extension, `schema-1.0.json` |
| `cve_id`, required once assigned and forbidden before | Extension conditional rules |
| Object versioning by `(stix_id, modified)` | `stix_objects`, and TAXII `match[version]` |
| Members receiving an updated version automatically | `added_after` polling; a new version is new content |
| Superseding a distributed submission | `SubmissionState.SUPERSEDED`, `superseded_by_id` |
| Audited, ISAC-gated release of the update | The existing workflow verbs |

The conditional rule is doing real work here: it is impossible to store a
`cve_id` on an object still marked `pre-cve`, so a placeholder identifier can
never be mistaken for an authoritative one.

---

## 3. Design sketch

### Export

A new workflow verb on a distributed submission — `POST /submissions/{id}/export`
— reserved to the hosting ISAC, same authority as `/distribute`. It:

1. Refuses unless `discovery_scope` is `own_product` or `own_estate`. **A firm may
   only push its own product's vulnerability toward CVE issuance.** Exporting an
   `ai_system` finding about someone else's software is precisely the
   coordinated-disclosure consent problem the v1 content policy avoids, and the
   export path must not reintroduce it.
2. Refuses while an embargo is unreleased, unless the operator explicitly
   overrides — CVE issuance is publication, and publishing before the embargo the
   ISAC promised its members would be a breach of that promise.
3. Maps the submission to the interchange format and hands it off.
4. Records the handoff in the audit trail and moves `cve_status` to `requested`.

### Format

> **Read §4a first.** GOLD EAGLE fronts VINCE, whose unit of exchange is a
> coordination case rather than a filed record, so this section is probably the
> right target for the *record* and the wrong one for the *handoff*.

Target **CVE Record Format 5.1** as the interchange, not an AIVS-specific shape.
It is what a CNA actually files, so the mapping is useful even to a firm that
does not use GOLD EAGLE, and it keeps AIVS from inventing a private protocol
between two of its own tools.

Mapping is mostly mechanical: `affected_products[]` → `affected[]` (vendor,
product, versions), `cvss_v4_vector` → `metrics[].cvssV4_0`, `name` and
description → `descriptions[]`, references → `references[]`.

**Deliberately not exported:** reproduction and exploit-chain detail. Only the
triage metadata maps to a CVE record, because a CVE record is a public document
and reproduction detail does not belong in one.

### Return path

`POST /submissions/{id}/cve` accepts the assigned identifier and creates a
**superseding submission** rather than mutating the distributed one. That keeps
the existing invariant — distributed content is immutable — and produces a
proper audit record of who published what and when. The superseding submission
carries the same STIX objects at a new `modified`, with `cve_status: published`
and `cve_id` set, and is distributed to exactly the circles the original reached.

Members receive it as an ordinary new version through polling they already do.
No client change is required, which is the point.

---

## 4. Security considerations

- **Egress discipline.** The export is an outbound call to an external service
  and needs the same SSRF-safe treatment as webhook delivery: https-only,
  resolve-then-pin, no redirects, bounded timeout.
- **Credentials.** GOLD EAGLE credentials are per-deployment configuration held
  as a secret, never per-member. A member never authenticates to GOLD EAGLE
  through AIVS.
- **Idempotency.** Export must be safe to retry without filing twice. Key on the
  submission id and record the handoff before the call returns, so a timeout
  cannot produce a duplicate CVE request.
- **The returned identifier is attacker-influenced input** if the endpoint is
  ever reachable by anything but the ISAC. Validate the `CVE-YYYY-NNNNN` shape
  (the extension schema already does) and restrict the endpoint to the ISAC.
- **Do not let export widen visibility.** Export publishes to the world; it must
  not, as a side effect, distribute the submission to any circle it was not
  already in.

---

## 4a. GOLD EAGLE is a front end for VINCE

**Settled by Mike, 2026-08-17.** This answers the first open question below and
changes the shape of the integration, so it is recorded before the questions it
resolves rather than inside them.

VINCE — the Vulnerability Information and Coordination Environment — is
CERT/CC's coordinated-disclosure platform, and it is open source. Three
consequences, in order of how much they change:

**The unit of exchange is a coordination case, not a CVE record.** VINCE is case
management for multi-party disclosure: a report opens a case, vendors are
brought in, and a CVE identifier is an *outcome* of that case rather than the
thing you hand over to start it. §3's "Format" section designs the export as
filing a CVE Record Format 5.1 document, which is the right shape for the record
once an identifier exists and probably the wrong shape for the handoff. Expect
the export to be "open a case with this report" and the return path to be "this
case produced VU#… and later CVE-…". The `requested → assigned → published`
progression survives; what changes is that AIVS likely needs to track a case
identifier alongside `cve_id`, because the case is the thing that exists first
and the thing an operator will be asked about.

**Coordination is VINCE's purpose, and §3 is built on avoiding it.** The export
refuses anything that is not `own_product` or `own_estate`, deliberately, so
that AIVS never brokers disclosure of a third party's software without consent.
Handing off to VINCE is handing off to the organisation whose mandate that
brokering *is*. Whether AIVS should therefore relax that restriction is a
product decision, not a technical one, and it is recorded as an open question
below rather than assumed either way.

**We can read the model instead of guessing it.** VINCE being open source means
the data model, the workflow states and the API surface are all inspectable, and
an ISAC could in principle run its own instance — which fits the self-hosting
story the rest of AIVS is built around. Before any of this is built, read the
published source and API documentation and replace the sketch in §3 with what
is actually there. Everything above is what *follows* from "GOLD EAGLE fronts
VINCE"; none of it is verified against VINCE's current interface, and this
paragraph is the reminder not to treat it as though it were.

---

## 5. Open questions

These need answering before this can be built:

1. ~~**What is GOLD EAGLE's actual interface?**~~ **Answered: it fronts VINCE.**
   See §4a. What remains is to verify the case-creation and status-callback
   surface against VINCE's own documentation rather than against this sketch.
2. **Does the `own_product` restriction still make sense downstream of VINCE?**
   §3 refuses to export a finding about someone else's software, because
   brokering that disclosure is a responsibility AIVS deliberately declines.
   VINCE exists to broker exactly that, with a coordinator who does it for a
   living. The choice is whether AIVS stays a pure early-warning layer that only
   forwards a firm's own findings, or becomes a feeder into CERT/CC's
   coordination process for third-party findings too — which is a larger claim
   about what the ISAC is doing on its members' behalf, and needs the sharing
   agreement to say so. **Mike's call.**
3. **Who is the CNA?** CERT/CC being in the path narrows this considerably, since
   a coordinator can assign where a vendor will not. Still needs settling
   whether a member firm files under its own CNA scope where it has one, and
   what AIVS does differently when it does.
4. **What comes back, and when?** A case identifier exists before any CVE does,
   and a CVE ID may be reserved long before the record
   is published. The `requested` → `assigned` → `published` progression already
   models that, but the integration needs to know which events it will actually
   be told about.
5. **Anonymous submissions.** A submission distributed anonymously has a real
   submitter recorded internally. If that firm's own product is the affected one,
   CVE issuance will identify them publicly regardless. The export flow should
   surface that explicitly to the operator rather than letting it surprise a
   member who chose anonymity inside the circle.
