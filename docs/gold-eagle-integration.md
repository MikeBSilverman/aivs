# GOLD EAGLE integration — CVE handoff and return path

**Status:** queued. Not scheduled against a phase yet.
**Depends on:** nothing in AIVS. The data model already anticipates this.

AIVS covers the window *before* CVE publication. GOLD EAGLE helps firms issue
CVEs at scale. Today those are two tools; this integration makes them one
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

Target **CVE Record Format 5.1** as the interchange, not an AIVS-specific shape.
It is what a CNA actually files, so the mapping is useful even to a firm that
does not use GOLD EAGLE, and it keeps AIVS from inventing a private protocol
between two of its own tools.

Mapping is mostly mechanical: `affected_products[]` → `affected[]` (vendor,
product, versions), `cvss_v4_vector` → `metrics[].cvssV4_0`, `name` and
description → `descriptions[]`, references → `references[]`.

**Deliberately not exported:** anything sealed. If end-to-end encryption ships
first, the sealed payload is unreadable to the server and must not be part of an
export; only the cleartext triage metadata maps to a CVE record. That is the
correct outcome anyway — a CVE record is a public document and reproduction
detail does not belong in one.

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

## 5. Open questions

These need answering before this can be built, and most are about GOLD EAGLE
rather than about AIVS:

1. **What is GOLD EAGLE's actual interface?** I have designed against CVE Record
   Format 5.1 as the interchange because that is what a CNA files, but I do not
   know GOLD EAGLE's API, auth model, or whether it accepts records
   synchronously or as a queued job. The adapter is small; the assumption is not
   safe to make silently.
2. **Who is the CNA?** Does the member firm file under its own CNA scope, does
   the ISAC file on their behalf, or does GOLD EAGLE broker it? This determines
   whether export is one call or a per-member credential problem.
3. **What comes back, and when?** A CVE ID may be reserved long before the record
   is published. The `requested` → `assigned` → `published` progression already
   models that, but the integration needs to know which events it will actually
   be told about.
4. **Anonymous submissions.** A submission distributed anonymously has a real
   submitter recorded internally. If that firm's own product is the affected one,
   CVE issuance will identify them publicly regardless. The export flow should
   surface that explicitly to the operator rather than letting it surprise a
   member who chose anonymity inside the circle.
