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
`org_type` (`gsib`, `section9`, `crit_infra`, `admin`) and a `status`
(`pending`, `active`, `suspended`). The `admin` org is the tenant operator, not a
sharing participant.

**Circle** — the unit of trust tiering. Named, slugged, with an `is_active` flag
and a `minimum_tlp` floor. Membership is an explicit `circle_memberships` row
carrying a role, unique on `(circle_id, org_id)`.

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

### Organization-level roles (`OperatorRole`) — humans only

Strictly ordered in privilege, and the ordering is enforced in `auth.policy` and
nowhere else.

| Role | Grants |
| --- | --- |
| `analyst` | Act within their own organization: create and edit drafts, submit, read the circles the org belongs to, record acknowledgments, view their org's own submissions and receipts. |
| `org_admin` | Everything an analyst can, plus administer **their own organization only** — its operators, its certificates, its settings (`can_manage_org(ctx, target) → target == ctx.org_id`). |
| `system_admin` | Everything an org admin can, plus operate the instance. Only meaningful at the hosting ISAC. |

### Circle-level roles (`CircleRole`) — per organization, per circle

| Role | Grants |
| --- | --- |
| `member` | Read content distributed into the circle. |
| `contributor` | Read, **and** contribute content into the circle. |
| `circle_admin` | Read, contribute, **and** manage the circle's membership. |

These are orthogonal to `OperatorRole`. An `org_admin` at a firm holding only
`member` in a circle cannot contribute to it; a rank-and-file `analyst` at a firm
holding `contributor` can. Organization role governs what you may do *to your own
organization*; circle role governs what you may do *inside a circle*.

### What makes a caller a system administrator

```python
def is_system_admin(ctx) -> bool:
    if not is_active(ctx) or ctx.org_type is not OrgType.ADMIN:
        return False
    if ctx.operator_id is not None:
        return ctx.operator_role is OperatorRole.SYSTEM_ADMIN
    return ctx.auth_method is AuthMethod.MTLS
```

Two conditions, both required. The organization must be the `admin` org **and**,
for a human, that human must hold `system_admin`. An analyst who happens to work
at the hosting ISAC is an analyst — employment is not authority. A machine
identity belonging to the admin organization is the instance itself.

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

| Resource / action | Suspended or pending org | Analyst (member firm) | Org admin (member firm) | Machine cert (member firm) | System admin (hosting ISAC) | ISAC machine cert |
| --- | --- | --- | --- | --- | --- | --- |
| **Circles** |
| Read circle content (TAXII objects, manifest) | N | circle: any role | circle: any role | circle: any role | circle: any role — **no bypass** | circle: any role — **no bypass** |
| Contribute into a circle | N | circle: `contributor`/`circle_admin` | circle: `contributor`/`circle_admin` | circle: `contributor`/`circle_admin` | Y | Y |
| Manage circle membership | N | circle: `circle_admin` | circle: `circle_admin` | circle: `circle_admin` | Y | Y |
| Create or delete a circle | N | N | N | N | Y | Y |
| **Submissions** |
| Create a draft | N | Y (own org) | Y (own org) | Y (own org) | Y | Y |
| View submission workflow record | N | own only | own only | own only | Y (all) | Y (all) |
| View submission receipts | N | own only | own only | own only | Y (all) | Y (all) |
| `draft` → `submitted` | N | own | own | own | N¹ | N¹ |
| `submitted` → `validated` | N | N | N | N | **Y** | **Y** |
| `validated` → `distributed` | N | N | N | N | **Y** | **Y** |
| any → `withdrawn` (where legal) | N | own | own | own | Y | Y |
| `distributed` → `superseded` | N | own | own | own | Y | Y |
| **Organizations and certificates** |
| Enrol a new organization | N | N | N | N | Y | Y |
| Change an org's `status` | N | N | N | N | Y | Y |
| Register / revoke a certificate | N | N | own org | N² | Y (any org) | Y (any org) |
| Manage operators | N | N | own org | N² | Y (any org) | Y (any org) |
| **Embargoes** |
| Set an embargo on own submission | N | own | own | own | Y | Y |
| Lift or extend an embargo | N | N | N | N | Y | Y |
| **Acknowledgments** |
| Record `acknowledged` / `actioned` | N | own org | own org | own org | Y | Y |
| **Audit log** |
| Read the audit log | N | N | N | N | Y | Y |
| Modify the audit log | N | N | N | N | **N — database-enforced** | **N — database-enforced** |

¹ `can_transition_submission` grants `submitted` to `is_submitter` only. A system
administrator does not submit on a member's behalf; if the ISAC itself is the
submitter (its own org submitted the content) it qualifies as `is_submitter` on
that submission like any other org.

² `can_manage_org` requires `is_system_admin(ctx)` or `is_org_admin(ctx)`, and
`is_org_admin` tests `ctx.operator_role in (ORG_ADMIN, SYSTEM_ADMIN)`. A machine
identity has no `operator_role`, so **a member firm's mTLS certificate cannot
administer its own organization.** Org administration is a human, portal-session
action. This is worth knowing before someone tries to automate certificate
rotation against the native API with the outgoing certificate.

---

## 6. The predicates, one line each

| Predicate | Question | Rule |
| --- | --- | --- |
| `is_active(ctx)` | May this caller transact at all? | `org_status is ACTIVE`. First check in every other predicate. |
| `is_system_admin(ctx)` | Does this caller operate the instance? | Active **and** `org_type is ADMIN` **and** (`SYSTEM_ADMIN` operator, or an mTLS machine identity). |
| `is_org_admin(ctx)` | May this caller administer their own org? | Active **and** (system admin, or `operator_role` in `{ORG_ADMIN, SYSTEM_ADMIN}`). |
| `can_read_circle(ctx, cid)` | May they read this circle? | Active **and** `cid in ctx.circles`. No admin bypass. |
| `can_submit_to_circle(ctx, cid)` | May they contribute here? | Active **and** role in `{CONTRIBUTOR, CIRCLE_ADMIN}`. |
| `can_administer_circle(ctx, cid)` | May they change membership? | Active **and** (system admin, or `CIRCLE_ADMIN` in that circle). |
| `readable_circle_ids(ctx)` | Which circles may they read? | `ctx.circle_ids`, or the empty set if inactive. |
| `writable_circle_ids(ctx)` | Which may they contribute to? | Circles where the role is contributor or circle admin. |
| `can_view_submission(ctx, s)` | May they see the workflow record? | Active **and** (system admin, or `s.submitter_org_id == ctx.org_id`). |
| `can_view_submission_receipts(ctx, s)` | May they see who retrieved it? | Same rule. Restricted because receipts reveal which firms attend to which threats. |
| `can_transition_submission(ctx, s, target)` | May they make this move? | The move must be legal in `SUBMISSION_TRANSITIONS` **and** the caller must hold the right to that specific target. |
| `can_manage_org(ctx, target)` | May they administer this org? | Active **and** (system admin, or org admin over their own org). |
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

---

## 9. Testing the model

`policy.py` exists as a single module for one reason: `tests/authz_matrix`
enumerates every route against every caller shape and asserts the exact outcome,
and that proof is only worth something if there is one place where the rules
live. The `authz` pytest marker (declared in the workspace `pyproject.toml`) tags
those tests as "the deny-by-default proof".

If you add a route, add its row to the matrix. If you need a rule the module does
not express, add the predicate here rather than inline in the router — an
authorization rule that lives in a handler is a rule nothing tests.
