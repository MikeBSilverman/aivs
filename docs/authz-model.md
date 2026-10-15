# AIVS authorization model

Every "may this caller do that" question in AIVS is answered in one module:
`packages/aivs-server/src/aivs_server/auth/policy.py`. This document describes
what that module decides and why it is shaped the way it is.

---

## 1. Three structures, in order

```
Organization ──< CircleMembership >── Circle ──1..n──> TaxiiCollection
     │                                  ▲
     │ employs                          │ distribution targets
     ▼                                  │
  Operator                        Distribution rows
  (human, portal)                 (object × circle × date_added)
```

**Organization** — a member firm, or the hosting ISAC itself. Carries an
`org_type` and a `status` (`pending`, `active`, `suspended`, `quarantined`).
The `admin` org is the tenant operator, not a sharing participant, and there is
exactly one. Members are `gsib`, `section9` or `crit_infra`, which are the only
types a membership *rule* can admit. `vendor` and `government` may be added to a
circle by name only. `researcher` and `automation` read no circle: no path can
make them a circle member (`CIRCLE_ELIGIBLE_ORG_TYPES`,
`unit/test_contributor_types.py`). They contribute.
The one read either has is the automation organisation's machine certificate
reading the ISAC's own vulnerability records at
`/api/v1/isac-records/vulnerabilities` (`can_read_isac_records`), which the KEV
enrichment script builds its versions from: the newest released version of
each, never RED, nothing while distribution is paused, and no member's content.

**Circle** — the unit of trust tiering. Named, slugged, with an `is_active` flag
and a `minimum_tlp` floor. Membership is a set of `circle_memberships` intervals
`[joined_at, left_at)`, each carrying a role: at most one open interval per
`(circle_id, org_id)`, and no two that overlap. A start can be repaired earlier
only for an organisation that has never left the circle; for one that has, the
gap after its earlier interval is never handed over (SF-43).

**TaxiiCollection** — the outward projection of a circle. Its UUID is what
members put in their TAXII client configuration, so it is stable for the life of
the deployment. `can_read` defaults true, `can_write` defaults **false**.

Note the shape precisely: authorization attaches to the **circle**, and the
collection inherits it. There is no per-collection ACL. A collection is readable
because its circle is readable.

---

## 2. Identity: what a caller is

`AuthContext` (`auth/context.py`) is a frozen dataclass carrying identity and
nothing else — it has no method that answers whether an action is permitted.
That separation is what makes the authorization matrix tests meaningful: there is
exactly one module to enumerate.

| Field | Meaning |
| --- | --- |
| `org_id`, `org_slug`, `org_type`, `org_status` | The organization the caller acts as. |
| `auth_method` | `mtls` (machine) or `portal_session` (human). |
| `circles` | `Mapping[circle_id, CircleRole]` — frozen into a `MappingProxyType` in `__post_init__` so a handler cannot grant itself a circle by mutating what it was handed. Empty is normal: a newly enrolled org belongs to no circle and must therefore see nothing. |
| `cert_fingerprint` | Present for mTLS callers, **and** for portal sessions, which are bound to the certificate that established the network path. |
| `operator_id`, `operator_role` | Present only for portal sessions. |
| `request_id`, `source_ip` | Audit correlation. |

Two derived properties feed the audit log: `actor_type` is `operator` when
`operator_id` is set and `organization` otherwise; `actor_id` is the operator id,
else the certificate fingerprint, else the org id.

---

## 3. Roles

### Operator roles (`OperatorRole`) — humans only, and held as a set

An operator holds a **set** of roles. A small ISAC's staff wear several hats and
a large one's do not; which is the ISAC's decision, made when it assigns roles.
Every role is interpreted in `auth.policy` and nowhere else.

| Role | Held at | Grants |
| --- | --- | --- |
| `analyst` | a member firm | Act within their own organization: create and edit drafts, submit, read the circles the org belongs to, record acknowledgments, view their org's own submissions and their telemetry (counts, never firms). |
| `org_admin` | a member firm | Administer **their own organization only** — its operators, its certificates (`can_manage_org(ctx, target) → target == ctx.org_id`). |
| `isac_analyst` | the hosting ISAC | The review queue and every submission's workflow record and receipts. Never validates, distributes or changes an embargo. |
| `isac_editor` | the hosting ISAC | The editorial verbs: validate, distribute, release or extend an embargo; create circles. Also sees what an `isac_analyst` sees. |
| `isac_membership` | the hosting ISAC | Enrol, activate and suspend organizations; circle rosters; register and revoke any organization's certificates; list organizations. **Never reads a submission.** |
| `system_admin` | the hosting ISAC | Runs the instance: operators and settings. **Holds no editorial verb** — it used to hold all of them. |

No ISAC role implies another.

### Circle-level roles (`CircleRole`) — per organization, per circle

| Role | Grants |
| --- | --- |
| `member` | Read content distributed into the circle. |
| `contributor` | Read, **and** contribute content into the circle. |
| `circle_admin` | Historical. Confers exactly what `contributor` does. |

With no role named, an organisation joins with its type's default
(`default_circle_role`): sector members contribute, vendors, government bodies
and the ISAC's own organisation read.

`circle_admin` **no longer administers anything.** Admitting an organisation to a
circle is the hosting ISAC's alone: the circle carries other members' embargoed
intelligence, and membership is backed by an agreement the ISAC holds. A
classified programme does not let a cleared participant read in the next one; the
programme manager does. The value survives only because removing a PostgreSQL
enum member is disruptive out of proportion to the tidiness, and because it marks
the firms a future delegation model would start from.

These are orthogonal to `OperatorRole`. An `org_admin` at a firm holding only
`member` in a circle cannot contribute to it; a rank-and-file `analyst` at a firm
holding `contributor` can. Organization role governs what you may do *to your own
organization*; circle role governs what you may do *inside a circle*.

### A certificate is not a person

```python
def _isac_human(ctx, role) -> bool:
    return (
        is_active(ctx)
        and ctx.org_type is OrgType.ADMIN
        and ctx.auth_method is AuthMethod.PORTAL_SESSION
        and role in ctx.operator_roles
    )
```

Every ISAC power is a human, signed in with password and TOTP over a
certificate-bound session, holding the specific role. **A machine identity of the
admin organization holds none of them.** It used to be "the instance itself" and
held all of them — and whoever controls the issuing CA can mint one, which in the
managed-hosting mode is the host. That put editorial control and every access
grant (enrolment, rosters, certificates) in the hands of the one party the
topology says must not have them. The admin organization still holds
certificates, because its staff reach the portal over a certificate-bound path;
a certificate now authenticates the network path and nothing more.

ISAC staff use the native API with their session as a bearer token
(`Authorization: Bearer <session token>`). It is the portal session's own token:
bound to the certificate on the request, with the same deadlines and revocation.
A bearer header is never sent by a browser on its own, so this path needs no
CSRF token. A header that is present but not a valid session is **refused**,
never quietly downgraded to the certificate's machine identity.

---

## 4. The three invariants

### Deny by default

Every predicate in `policy.py` returns `False` unless a rule explicitly grants
access. There is no branch that ends in a permissive fallthrough — including the
`match` statement in `can_transition_submission`, whose exhaustive `case _`
returns `False`.

The visibility clause carries the same property into SQL. When a caller has no
readable circles, `distribution_visibility_clause` returns `or_(False)` — a
literal false — rather than emitting `IN ()`, which some dialects treat
inconsistently and which reads ambiguously in a query log:

```python
circle_ids = readable_circle_ids(ctx)
if not circle_ids:
    return or_(False)
```

The failure mode of an empty set is "match no rows", never "match all rows", and
that is asserted in tests.

### Suspended and pending organizations get nothing

`is_active(ctx)` — `ctx.org_status is OrgStatus.ACTIVE` — is the first thing
every other predicate does. A `pending` org has enrolled but not been activated;
a `suspended` org has been switched off. Neither may read or write anything.

Revoking an organization's participation is therefore a single field update that
takes effect on their **next request**. There is no cached grant to invalidate
and no token to wait out. Certificate revocation (`client_certificates.status`)
works the same way, checked per request against an indexed unique constraint,
which is why the enforcement path needs no CRL fetch or OCSP responder.

### Circle membership governs collection visibility, even for the ISAC

```python
def can_read_circle(ctx, circle_id) -> bool:
    return is_active(ctx) and circle_id in ctx.circles
```

There is no system-administrator bypass in this function, and its absence is
deliberate.

An ISAC that wants to read a circle's contents **joins that circle**, visibly, as
an organization with a `circle_memberships` row like everyone else. It does not
silently appear inside every member's TAXII feed. The ISAC's oversight of
submissions runs through the native API and the portal — `can_view_submission`,
`can_view_submission_receipts`, `can_transition_submission` — which are
separately authorized and separately audited.

Why it is worth the inconvenience: a member firm can enumerate a circle's
membership and see exactly who receives what they share. If the ISAC could read
circles invisibly, every membership list would carry an implicit asterisk, and
the "who is in this circle" question — the one that determines whether a firm is
willing to share at all — would have no answer a member could verify. AIVS trades
some operational convenience for a membership list that means what it says.

The distinction is real but narrow, and worth stating so nobody mistakes it for
more than it is: a system administrator **can** see a submission's workflow
record and its receipts through the native API. What they cannot do is receive
its distributed content through a TAXII collection without a membership row
saying so.

---

## 5. Subject × resource × action

Rows are the caller; cells are the outcome. "own" means the caller's own
organization or a submission it submitted.

Legend: **Y** allowed · **N** denied · **circle** allowed only for circles the
caller's org belongs to, at the role shown.

| Resource / action | Suspended or pending org | Analyst (member firm) | Org admin (member firm) | Machine cert (member firm) | ISAC human, by role | ISAC machine cert |
| --- | --- | --- | --- | --- | --- | --- |
| **Circles** |
| Read circle content (TAXII objects, manifest) | N | circle: any role | circle: any role | circle: any role | circle: any role — **no bypass** | circle: any role — **no bypass** |
| Contribute into a circle | N | circle: `contributor`/`circle_admin` | circle: `contributor`/`circle_admin` | circle: `contributor`/`circle_admin` | circle: as any member | circle: as any member |
| Manage circle membership | N | N | N | N | `isac_membership` | N |
| Create a circle (no path deletes one) | N | N | N | N | `isac_editor` | N |
| **Submissions** |
| Create a draft | N | Y (own org) | Y (own org) | Y (own org) | Y | Y |
| View submission workflow record | N | own only | own only | own only | `isac_analyst`, `isac_editor` (all) | own only |
| View submission receipts (firm by firm) | N | N | N | N | `isac_analyst`, `isac_editor` (all) | N |
| View submission telemetry (k-suppressed counts) | N | own only | own only | own only | own only | own only |
| Amend a draft | N | own | own | own | `isac_editor`, the ISAC's own drafts¹ | N¹ |
| `draft` → `submitted` | N | own | own | own | `isac_editor`, the ISAC's own¹ | N¹ |
| `submitted` → `validated` | N | N | N | N | **`isac_editor`** | **N** |
| `submitted` → `returned` | N | N | N | N | N (the first pass only) | N |
| `returned` → `submitted` | N | own | own | own | N | N |
| `validated` → `distributed` | N | N | N | N | **`isac_editor`** | **N** |
| any → `withdrawn` (where legal) | N | own | own | own | `isac_editor` | N¹ |
| `distributed` → `superseded` | N | own | own | own | `isac_editor` | N¹ |
| **Organizations and certificates** |
| Enrol a new organization | N | N | N | N | `isac_membership` | N |
| Change an org's `status` | N | N | N | N | `isac_membership` | N |
| Quarantine an org | N | N | own org | N | `isac_membership`, `isac_editor`, `system_admin` | N |
| Reconnect a quarantined org | N | N | N | N | `isac_membership`, `isac_editor` | N |
| Offboard an org; set or lift a legal hold | N | N | N | N | `isac_membership` | N |
| Register / revoke a certificate | N | N | own org | N² | `isac_membership` (any org) | N |
| Create operators | N | N | N | N | N (the host's `bootstrap_operator` command only) | N |
| **Embargoes** |
| Set an embargo (a release time, at distribution) | N | N | N | N | `isac_editor` | N |
| Lift or extend an embargo | N | N | N | N | `isac_editor` | N |
| **Acknowledgments** |
| Record `acknowledged` / `actioned` [^ack] | N | own org | own org | own org | N | N |
| **Audit log** |
| Read the audit log and receipts | N | N | N | N | `auditor` only³ | N |
| Choose what the audit stream serves of its own reading (`full` / `condensed`) | N | N | N | N | `system_admin` | N |
| Modify the audit log | N | N | N | N | **N — database-enforced** | **N — database-enforced** |

¹ The submitter's verbs (amend, submit, withdraw, supersede) go through
`policy.holds_submitter_rights`. A member firm holds them for what it filed. On a
filing whose owner is the ISAC's own organisation or its automation each is a
human `isac_editor`'s and nobody else's, as validating is (Mike, Q15 and Q35;
SF-81): an ISAC analyst, a system administrator, the admin organisation's
certificate alone and the automation's certificate hold none of them, and an
editor holds them on what the automation filed,
and the refusal is recorded as `isac_filing_requires_isac_editor`. A one-click
files and submits in one step, so it refuses them before filing anything, with a
sentence saying an editor has to file it (Q36: refused, not queued). An analyst
may still create a draft for the ISAC; only an editor then sends, amends or
withdraws it. A system administrator does not submit on a member's behalf.

³ `policy.can_read_audit`: an operator holding `auditor` alone, before its
`role_expires_at`; the whole instance at the ISAC, its own organisation's rows
at a member (`audit_scope`). No other role reads the trail, and an auditor
reads nothing else. Its reads are recorded (`audit.read`) and, by design,
not served back by the stream; `auditor_bulk_read` watches them. This table
once said `Y` here for a route that did not exist.

² `can_manage_org` requires `is_isac_membership(ctx)` or `is_org_admin(ctx)`, and
`is_org_admin` tests `ORG_ADMIN in ctx.operator_roles`. A machine identity has
no roles, so **a member firm's mTLS certificate cannot
administer its own organization.** Org administration is a human, portal-session
action. This is worth knowing before someone tries to automate certificate
rotation against the native API with the outgoing certificate.

---


[^ack]: The hosting ISAC is deliberately **not** able to acknowledge a member's
    submission, despite being able to do most things a member can. An
    acknowledgment is one organisation asserting what *it* did about a warning —
    "we received this, we acted on it" — and it is the member's own evidence,
    used to demonstrate their response to their own regulator. An ISAC recording
    an acknowledgment on a member's behalf would be manufacturing that evidence,
    which is the one property this record has to have. The gate in
    `api/acknowledgments.py` enforces it structurally: a caller must hold a
    server-written retrieval receipt for the submission, and the ISAC has none
    unless it visibly joined the circle and collected the content itself.

## 6. The predicates, one line each

| Predicate | Question | Rule |
| --- | --- | --- |
| `is_active(ctx)` | May this caller transact at all? | `org_status is ACTIVE`. First check in every other predicate. |
| `is_system_admin(ctx)` | Does this caller run the instance? | A human ISAC session holding `SYSTEM_ADMIN`. No editorial power. |
| `is_isac_editor(ctx)` | May they validate, distribute, change embargoes, create circles? | A human ISAC session holding `ISAC_EDITOR`. |
| `is_isac_membership(ctx)` | May they enrol, suspend, keep rosters and certificates? | A human ISAC session holding `ISAC_MEMBERSHIP`. |
| `can_review_submissions(ctx)` | May they see every submission's record? | `ISAC_ANALYST` or `ISAC_EDITOR`, human ISAC session. |
| `is_org_admin(ctx)` | May this caller administer their own org? | Active **and** `ORG_ADMIN in operator_roles`. |
| `can_read_circle(ctx, cid)` | May they read this circle? | Active **and** `cid in ctx.circles`. No admin bypass. |
| `can_submit_to_circle(ctx, cid)` | May they contribute here? | Active **and** role in `{CONTRIBUTOR, CIRCLE_ADMIN}`. |
| `can_administer_circle(ctx, cid)` | May they change membership? | `is_isac_membership(ctx)`. |
| `readable_circle_ids(ctx)` | Which circles may they read? | `ctx.circle_ids`, or the empty set if inactive. |
| `writable_circle_ids(ctx)` | Which may they contribute to? | Circles where the role is contributor or circle admin. |
| `can_view_submission(ctx, s)` | May they see the workflow record? | Active **and** (`can_review_submissions`, or `s.submitter_org_id == ctx.org_id`). For an anonymous submission the record omits the submitter for everyone but the submitter. |
| `can_reveal_submitter(ctx)` | May they name an anonymous submitter? | `is_isac_editor(ctx)`. Requires a reason; audited as `anonymity.reveal` with the reason and without the identity. |
| `can_view_submission_receipts(ctx)` | May they see, firm by firm, who retrieved it? | Active **and** `can_review_submissions`. Not the submitter: each receipt is the receiving member's record, which one member never produces to another (sharing agreement §9). The submitter reads k-suppressed telemetry instead; with the named rows as well, that suppression was decorative. |
| `can_transition_submission(ctx, s, target)` | May they make this move? | The move must be legal in `SUBMISSION_TRANSITIONS` **and** the caller must hold the right to that specific target. |
| `can_manage_org(ctx, target)` | May they administer this org? | Active **and** (`isac_membership`, or a member firm's org admin over its own org; an org admin at the ISAC holds nothing). |
| `can_register_certificate(ctx, org)` | May they bind a certificate to this org? | Decided on the org's row read under its lock: never an offboarded org; `isac_membership` whatever the status (enrolment and reconnection need it); a member's org admin only while its org is active. |
| `can_quarantine_org(ctx, target)` | May they cut this org off? | `isac_membership`, `isac_editor` or `system_admin`; or the org's own org admin, for itself. |
| `can_reconnect_org(ctx)` | May they return a quarantined org? | `isac_membership` or `isac_editor`; never the member itself. |
| `can_offboard_org(ctx)`, `can_set_legal_hold(ctx)` | May they end a membership, or hold its data? | `isac_membership` only. |
| `can_confirm_proxy_filing(ctx, s)` | May they confirm a filing made in their name? | A person at the submitting org, never its machine certificate. |
| `can_read_isac_records(ctx)` | May they read the ISAC's own records outside any circle? | The automation organisation's machine certificate only. |
| `distribution_visibility_clause(ctx, now)` | Which rows may they read? | The SQL predicate below. |

`require(allowed, reason)` raises `PolicyDenied(reason)` — letting a router read
as `require(can_read_circle(ctx, cid), "circle_read")` rather than growing its
own if/raise ladder. `PolicyDenied.reason` is a short stable token written to the
audit log and **never returned to the caller**: an under-privileged client learns
only that it was denied, never which rule it tripped.

---

## 7. The read path

`distribution_visibility_clause` is the read-side enforcement point for TAXII and
the authoritative embargo gate. Three conditions, all required:

```python
and_(
    Distribution.circle_id.in_(circle_ids),  # 1. a circle the caller belongs to
    Distribution.date_added <= now,  # 2. its visibility instant has arrived
    Submission.state.in_(tuple(VISIBLE_SUBMISSION_STATES)),  # 3. distributed or superseded
)
```

Callers **must join `Submission`** for condition 3 to resolve.

Condition 2 is what makes embargo enforcement safe without a running scheduler:
an unreleased object simply has a future `date_added`. The APScheduler sweeper
that flips `embargoes.status` is a convenience for notification and operator
visibility, not the gate. See [`architecture.md`](architecture.md) §6 for why
`distributions` is materialised rather than computed.

`VISIBLE_SUBMISSION_STATES` is `{distributed, superseded}`. Superseded content
stays readable: members who pulled it need its history, and removing it would
silently break their `added_after` polling.

---

## 8. Two-factor identity for humans

A portal operator is authenticated by password (Argon2id) **and** TOTP, **and**
the session is bound to the organization's transport client certificate.
`portal_sessions.cert_fingerprint` is re-checked per request, so a cookie stolen
and replayed from outside that org's network path fails. Only the SHA-256 of the
session token is stored, so a database disclosure yields no live sessions;
`csrf_token_hash` is stored the same way.

Online password guessing is throttled by `operators.failed_login_count` and
`locked_until`.

Note the layering: the certificate establishes *which organization*, the password
and TOTP establish *which human*. Neither alone grants access, and the
`AuthContext` carries both (`cert_fingerprint` is populated for portal sessions
too).

**Member people may instead sign in through the ISAC's identity provider**, on
the public listener with no certificate (`identity-federation.md` §11). The IdP
establishes the human and must assert a second factor. The organisation comes
from the person's directory group, and the session is bound to the IdP subject
and a device cookie instead of a certificate. Such a session (`AuthMethod.SSO_SESSION`)
holds at most the analyst and org-admin roles, never a staff role, and reads
under a ceiling: `policy.tlp_ceiling` caps it at `TLP:AMBER+STRICT` and
excludes anything ever under embargo. Each kind of session is refused by the
other's resolver.

---

## 9. Testing the model

`policy.py` exists as a single module for one reason: `tests/authz_matrix`
proves the rules from outside, and that proof is only worth something if there
is one place where the rules live. The `authz` pytest marker tags those tests.

There are two proofs, and they answer different questions.

**The door** (`test_authz_matrix.py`). Every route is called with no
credentials, a forged proxy secret, and a suspended organisation's certificate,
using placeholder identifiers that resolve to nothing. Each must be refused.
Because nothing resolves, this also shows that refusal comes before any lookup:
a 404 there would mean the lookup happened first. The set of routes that answer
anonymously is pinned exactly, in both directions.

**The matrix** (`test_principal_matrix.py`). Fourteen kinds of caller
(`principals.py`) are sent to every route (`routes.py`), against a seeded
instance whose targets exist (`world.py`). Every answer is compared with one
expected outcome per (principal, route class, surface). The targets are real,
so an allowed caller succeeds. The matrix therefore fails when a role **loses**
a power it should have, as well as when it gains one. Guards fail the build
when a walked route has no class, a class is empty, or a surface drops below
its floor.

Two rules apply before the table:

- **Refused at the door.** Anonymous, forged proxy secret, and pending,
  suspended or quarantined organisations get 401 on the machine surface and a
  redirect to sign in on the portal, on every class except health and sign-in.
- **The portal needs a person.** A certificate with no signed-in human is
  redirected to sign in on every portal route.

Health (`/healthz`, `/readyz`, `/metrics`) answers everyone. Sign-in is the
same for every caller: the form renders, a wrong password is refused with 403,
and signing out lands on the sign-in page.

For every other caller, by route class (✓ allowed). "member" filed the
submissions the routes address and contributes to the circle; "peer" is another
member of the same circle, which it only reads; ISAC staff are not members of
that circle. A "content response" is a one-click or a posture on the circle's
content; an "own record" is the member's posture, TAXII status or lead-time
statement; a "posture summary" is a sector figure withheld below k (posture
counts, the lead-time median). The
"automation cert" is the ISAC's one automation organisation, presenting its
certificate; "isac records" is its read of the ISAC's own canonical records,
which it versions (KEV status) and cannot reach through a circle.

| Class | member cert | member analyst | member org_admin | peer cert | admin-org cert | automation cert | ISAC analyst | ISAC editor | ISAC membership | system_admin |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| listing | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| filing | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| own settings | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| health | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| circle content | ✓ | ✓ | ✓ | ✓ | 404 | 404 | 404 | 404 | 404 | 404 |
| vulnerability export | ✓ | ✓ | ✓ | ✓ | 404 | 404 | ✓ | ✓ | 404 | 404 |
| submission record | ✓ | ✓ | ✓ | 404 | 404 | 404 | ✓ | ✓ | 404 | 404 |
| readiness | ✓ | ✓ | ✓ | ✓ | 404 | 404 | ✓ | ✓ | 404 | 404 |
| vulnerability page | sign in | ✓ | ✓ | sign in | sign in | sign in | ✓ | ✓ | 404 | 404 |
| evidence pack | ✓ | ✓ | ✓ | ✓ | 404 | 404 | 404 | 404 | 404 | 404 |
| audit read | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 |
| telemetry | ✓ | ✓ | ✓ | 404 | 404 | 404 | 404 | 404 | 404 | 404 |
| receipt record | 404 | 404 | 404 | 404 | 404 | 404 | ✓ | ✓ | 404 | 404 |
| first pass | 404 | 404 | 404 | 404 | 404 | 404 | ✓ | ✓ | 404 | 404 |
| priority | 403 | 403 | 403 | 404 | 404 | 404 | 403 | ✓ | 404 | 404 |
| assign | 403 | 403 | 403 | 404 | 404 | 404 | ✓ | ✓ | 404 | 404 |
| bulk validate | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ | 403 | 403 |
| draft edit | ✓ | ✓ | ✓ | 404 | 404 | 404 | 403 | 403 | 404 | 404 |
| withdraw | ✓ | ✓ | ✓ | 404 | 404 | 404 | 403 | ✓ | 404 | 404 |
| receipt | 403 | 403 | 403 | ✓ | 404 | 404 | 404 | 404 | 404 | 404 |
| editorial verb | 403 | 403 | 403 | 404 | 404 | 404 | 403 | ✓ | 404 | 404 |
| review queue (portal) | sign in | 404 | 404 | sign in | sign in | sign in | ✓ | ✓ | 404 | 404 |
| membership verb | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ | 403 |
| quarantine | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ | ✓ | ✓ |
| reconnect | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ | ✓ | 403 |
| certificate revoke | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 | ✓ | 404 |
| circle create | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ | 403 | 403 |
| sector event | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ | 403 | 403 |
| circle screens (portal) | sign in | 403 | 403 | sign in | sign in | sign in | 403 | ✓ | ✓ | 403 |
| pause | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ | 403 | ✓ |
| resume | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ | 403 | 403 |
| audit stream mode | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ |
| status page (portal) | sign in | 403 | 403 | sign in | sign in | sign in | 403 | 403 | ✓ | ✓ |
| content response | ✓ | ✓ | ✓ | ✓ | 404 | 404 | 404 | 404 | 404 | 404 |
| own record | ✓ | ✓ | ✓ | 404 | 404 | 404 | 404 | 404 | 404 | 404 |
| posture summary | 404 | 404 | 404 | 404 | 404 | 404 | ✓ | ✓ | 404 | 404 |
| taxii inbox | ✓ | ✓ | ✓ | 403 | 404 | 404 | 404 | 404 | 404 | 404 |
| isac records | 404 | 404 | 404 | 404 | 404 | ✓ | 404 | 404 | 404 | 404 |
| post moderation | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ | 403 | 403 |
| inbox switch | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ | 403 | 403 |
| proxy filing | 403 | 403 | 403 | 403 | 403 | 403 | 403 | ✓ | 403 | 403 |
| proxy confirm | 403 | ✓ | ✓ | 404 | 404 | 404 | 403 | 403 | 404 | 404 |
| webhook register | ✓ | 403 | ✓ | ✓ | 403 | ✓ | 403 | 403 | 403 | ✓ |
| webhook delete | ✓ | 403 | ✓ | 404 | 403 | 404 | 403 | 403 | 403 | 404 |

How to read the deny cells:

- **404 vs 403 is deliberate.** An identifier the caller cannot see answers 404,
  so an endpoint is never an existence oracle (CLAUDE.md §5). 403 means the
  caller can see the thing and may not act on it. For example, an ISAC analyst
  can read a draft and may not edit it.
- **Each class is one policy.** Where two routes under one heading answer
  differently, such as `withdraw` (which admits an editor) and `submit` (which
  does not), they are separate classes rather than one class with exceptions.

The matrix does not claim:

- what a listing *contains*. It proves the listing answers; filtering is a
  clause test.
- visibility within content a caller may read.
- audit content.
- any principal that does not exist yet. The researcher and government
  organisations, and delegated providers, are listed in `principals.py` with the phase that adds them, and are not faked.

**The auditors** (`ISAC auditor session`, `member auditor session`) are not
columns either: their row is a rule (`_auditor` in the matrix). On `audit read`
they are allowed, within their scope (the instance at the ISAC, their own
organisation at a member). Everywhere else, API and portal alike, they get 403
at the door (`auth.deps` and the portal's session refuse an auditor before any
route runs), so no handler that reads a firm's records by organisation is ever
reached. Signing out is the one portal action an auditor takes. The first run
of that row, before the door refused it, found an auditor reading its firm's
submissions, postures and OpenVEX export through routes that ask no policy.

**The member SSO session** is not a column of the table, because its row is
derived from one (`_sso_member` in the matrix). On every portal route it gets
exactly the member analyst's cell; on the API and TAXII it gets 401, because
its token is not a machine credential. Its sign-in routes are their own map:
`/portal/sso/login` is allowed and a callback this browser did not start is
403; for every other principal, and on an instance without member SSO, both
are 404. Signing out lands on a page rather than a redirect. What it may
*read* on those routes is narrower than the analyst's, by the TLP ceiling
(§8), which is a clause test, as filtering always is.

If you add a route, `test_every_walked_route_is_in_exactly_one_class` fails
until you give it a class. If it fits no class, that is a new policy: add the
class and its row. If you need a rule the module does not express, add the
predicate here rather than inline in the router. An authorization rule that
lives in a handler is a rule nothing tests.
