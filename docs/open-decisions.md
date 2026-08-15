# Open decisions

Design notes for choices that are **not yet made**. Each states the current
behaviour, the options with their real costs, and a recommendation. When one is
settled, move the reasoning into the code or into `docs/architecture.md` and
delete the entry — a decision note that outlives its decision reads as though the
question is still open.

Two of these came out of the sharded security review; the third is a product
question that turned out to depend on the same underlying gap.

---

## 1. Who may change a sharing circle's membership?

**Current behaviour.** `auth/policy.can_administer_circle` permits the hosting
ISAC (`is_system_admin`) **or** any member organisation holding
`CircleRole.CIRCLE_ADMIN` in that circle. Circle roles attach to the
organisation's certificate, not to a named human.

**The amplifier.** `visible_content_clause` bounds visibility by circle and by
`date_added <= now`. There is no membership-start term. So adding an
organisation to a circle grants it **every object ever distributed into that
circle**, back to the beginning — including other firms' embargoed content at
that circle's TLP floor. A delegated circle admin can therefore hand a peer the
entire history without the ISAC being involved or, beyond one audit row,
informed.

### Option A — restrict to the hosting ISAC

| | |
|---|---|
| **For** | Membership of a sharing circle *is* the trust boundary. In an ISAC it is a governance act, usually backed by a membership agreement, sector eligibility, and an NDA — not an operational one. Delegating it delegates the ISAC's own admission control, which is the thing members are paying for. One party grants access, which makes "who could see this, and when?" answerable from one place. |
| **Against** | Every membership change becomes an ISAC ticket. For a large circle with real churn that is a standing operational load on exactly the party whose time is scarcest — and adoption friction is a first-order concern for this product. A sector-led working group that wants to self-manage cannot. |

### Option B — keep delegation, bound the blast radius

Add `Distribution.date_added >= <membership start>` to the visibility clause, so
a newly added organisation receives content distributed **from the moment it
joined**, not before.

| | |
|---|---|
| **For** | Restores what "adding someone to a group" intuitively means: they participate from now on, they do not inherit the archive. Costs no migration — `circle_memberships.created_at` already exists. Fixes a real correctness problem *independently of the governance question*: today **any** membership addition, by the ISAC or by anyone else, retroactively exposes the back catalogue. |
| **Against** | A legitimately re-added organisation — certificate rotation handled clumsily, an admin error reversed, a re-enrolment — silently loses its history, because deleting and re-adding a membership resets the clock. Needs an explicit "restore with original join date" path for operators. Adds a term to the hot read path (cheap: the join is already there and indexed). Does not answer the governance question at all — a member firm can still admit another firm. |

### Option C — member proposes, ISAC approves

| | |
|---|---|
| **For** | Keeps governance with the ISAC and the operational load with the people who want the change. |
| **Against** | A workflow, a notification path, and a queue to build and secure, for a problem neither A nor B leaves unsolved. Not MVP-shaped. |

### Recommendation

**Do B regardless, then adopt A.**

B is not really a policy choice — retroactive exposure of the archive on every
membership change is a defect whichever party performs the change, and it is
cheap to fix. Do it first.

Then default to A for v1. For an ISAC-in-a-box, the ISAC's control over
admission *is* the trust story being sold; delegation is a capability to
re-introduce when a deploying ISAC asks for it, with B already in place to bound
it. Note that the operational load A creates is much smaller once §3 below
lands — most membership changes stop being manual at all.

---

## 2. Webhooks: wire them up, or remove them?

**Current behaviour.** A member can register an https endpoint and is handed a
signing secret "shown exactly once". `notify/webhooks.deliver_event` and
`active_webhooks_for` have **no caller anywhere**. `webhook_deliveries` stays
empty, `consecutive_failures` stays zero, and the member has no signal that they
are not subscribed to anything. This is the failure mode `CLAUDE.md` §5 names:
a schema describing a feature nobody implemented reads as done.

### Option A — wire it up

| | |
|---|---|
| **For** | Latency *is* the product. Pre-CVE early warning where the member finds out on their next 15-minute poll is a materially weaker proposition than one that pushes. The hard parts are already built and have now been reviewed: the SSRF guard resolves once, judges every returned address, pins the connection to the judged address and keeps SNI, with redirects disabled; payloads are HMAC-signed over timestamp and body; delivery attempts are recorded. It is also a genuine differentiator against a plain TAXII feed. |
| **Against** | Needs a durable worker with retry and backoff. A background task in the app process — which is what the embargo sweeper is — loses in-flight attempts when the process restarts. Delivery must run **after** the distribution transaction commits and must never run inside it, or a slow member endpoint holds a database transaction open. Egress from the ISAC's network to arbitrary member endpoints is a security-review conversation at *every* deployment, and the instance is deliberately behind network gating. And the notification itself carries metadata: "a new TLP:RED item landed in the Section 9 circle" is informative to anyone who learns it. |

### Option B — remove the endpoint and the models

| | |
|---|---|
| **For** | An honest surface. Less to secure, less to run, nothing to explain. TAXII polling with `added_after` is the ISAC-native pattern and every member firm already runs a client for it. |
| **Against** | Discards the latency advantage that is arguably the point of pre-CVE sharing, and throws away working, reviewed SSRF-safe code that would have to be written again. |

### Recommendation

**A, scoped to contentless notifications** — and make the surface honest in the
meantime.

Fire on the transition that makes content *visible* (distribution, and embargo
release — not distribution alone, or members are notified about content they
cannot yet read), from the post-commit path, carrying only "submission `{id}`
became visible to you in circle `{slug}` — poll to collect". Contentless
sidesteps the metadata-leak and TLP-handling questions completely, keeps the
regulatory story clean because the retrieval receipt still comes from a real
TAXII collect, and reduces the worker's job to "deliver a pointer, eventually".

Until that ships, do not leave the registration endpoint issuing signing secrets
for notifications that never arrive. Either disable the route or have it respond
with a clear "not yet available on this instance".

---

## 3. Selecting a known group instead of enumerating members

**The question.** It is easier for an ISAC to pick a known group than to
enumerate participants every time. Is that possible?

**Short answer: yes, and most of it already exists — but the ergonomics are
missing in a specific place, and one level of it depends on §1B.**

**What is already true.** *Distribution* is already group-based:
`POST /submissions/{id}/distribute` takes `circle_ids`, and a circle is a named
group of organisations. An operator releasing to "Section 9" selects one circle,
not thirty firms.

**Where the friction actually is.** Two places:

1. **Building and maintaining a circle.** `POST /circles/{id}/members` takes a
   single `org_id`. Onboarding thirty GSIBs is thirty calls.
2. **There is no admin UI at all.** The portal ships five templates — login,
   dashboard, submissions, submission detail, submit. Every organisation,
   circle, membership and certificate operation is `curl`. For an ISAC-in-a-box
   this is probably the largest real-world adoption obstacle in the product, and
   it is larger than the API-shape question.

**The unused asset.** Every organisation already carries an `org_type`
(`gsib`, `section9`, `crit_infra`, `admin`), curated at enrolment. Nothing uses
it for targeting — its only consumers are the `ADMIN` checks in `policy.py` and
`distribution.py`. It is a "known group" that already exists and is already
maintained.

### Level 1 — bulk membership

Accept a list of `org_id`s, and accept slugs as well as UUIDs so an operator can
paste a roster rather than look up thirty identifiers.

| | |
|---|---|
| **For** | Pure ergonomics. No model change, no authorization change, one membership row and one audit row per organisation exactly as today. An hour's work. |
| **Against** | Does not remove the maintenance burden — it makes the same manual act faster. A firm enrolled next month still has to be remembered. |

### Level 2 — standing groups defined by a rule

Let a circle declare a membership rule over organisation attributes — "every
active organisation of type `section9`" — and materialise it into real
`circle_memberships` rows whenever it is evaluated (at enrolment, and on demand).

| | |
|---|---|
| **For** | This is the actual answer to the question. Enrolling a new Section 9 firm puts them in the Section 9 circle automatically: no second step, no forgotten member, no firm that quietly receives nothing for a month because someone missed a checkbox. For an ISAC that is the difference between a member being covered on day one and being covered whenever someone remembers. Materialising rather than computing at read time keeps the audit trail exactly as strong as it is today — one row per organisation, with a join time — so "who could see this on 3 March?" stays a query against stored rows rather than a reconstruction of historical attributes. |
| **Against** | **Organisation creation becomes an access grant.** Setting `org_type: section9` at enrolment silently admits that firm to every `section9` circle — and, without §1B, to the entire back catalogue of each. That is a much sharper edge than today's explicit membership call, and it means the enrolment endpoint inherits the sensitivity of the membership endpoint. It also makes `org_type` load-bearing: changing a firm's classification becomes an access change and needs the same audit and the same care as a membership change. Rules that overlap need defined precedence, and a rule-managed membership must not be silently removable by hand. |

### Level 3 — composite circles (a circle containing circles)

| | |
|---|---|
| **For** | Expresses "all critical infrastructure" as the union of several sector circles without duplicating rosters. |
| **Against** | Every additional layer of indirection is another way for an operator to be wrong about who is actually in scope when they release embargoed intelligence. The blast radius of a mistake here is the product's core promise. Not worth it for v1. |

### Recommendation

**Level 1 now. Level 2 as materialised rules, gated on §1B. Skip Level 3.**

Level 1 is trivial and helps immediately. Level 2 is the real answer and is
worth building — but it must not land before the membership-start term from §1B,
because dynamic membership without it means enrolling an organisation
retroactively hands it years of other firms' embargoed content.

Two things worth adding alongside:

- **Roster import.** ISACs maintain these lists somewhere already — a regulator's
  Section 9 list, an existing community-of-interest roster. Accepting a pasted
  list of slugs is a cheap "Level 1.5" that matches how the work is really done.
- **Show the operator who is in scope, by name, before they release.** Whatever
  the targeting mechanism, the distribute screen should resolve the selection to
  the actual list of organisations that will receive the content. A group is
  easier to select and correspondingly easier to be wrong about; the moment
  before releasing embargoed intelligence is the moment to make the membership
  concrete.
