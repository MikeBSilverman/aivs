# AIVS operator runbook

For ISAC staff running an AIVS instance — the platform the ISAC uses to manage
vulnerability intelligence with its members and vendors, from pre-CVE early
warning onward. Today that means the pre-CVE lane: submissions, review,
distribution under embargo, and the record of who received what. Assumes you
have read [`deployment-topology.md`](deployment-topology.md) and the instance is
stood up.

The ISAC's powers are split across four roles and you may hold several:
`isac_editor` validates and distributes embargoed content and changes embargoes;
`isac_analyst` works the review queue; `isac_membership` enrols and suspends
organizations and manages certificates and rosters; `system_admin` runs the
instance. Every one of them requires you to be signed in -- the admin
organisation's certificate on its own confers none of them. To script against the
API, present your session token as `Authorization: Bearer <token>`. Everything you do is written to an append-only
audit log.

---

## 1. First run

Do these in order. Steps 1–3 are one-time and cannot be sensibly reordered.

### 1.1 Verify configuration and the append-only enforcement

Every command here runs inside the stack's containers, from the directory that
holds `docker-compose.yml`. The database has no published port and sits on an
internal network, so nothing on the host can reach it directly, and the app's
configuration lives in its container, not your shell. `--env-file deploy/.env`
goes on every compose command (deploy/README.md §3 says why).

```bash
docker compose --env-file deploy/.env exec app python -m aivs_server.config
# → configuration OK for environment=production
```

Then verify that the append-only enforcement holds, and holds against the role
the application actually uses. This is not ceremonial: a superuser or the
tables' owner can drop the triggers, so the guarantee rests on the application
being neither, and the shipped stack once ran as both without anything saying
so.

As the owner, in the database container:

```bash
docker compose --env-file deploy/.env exec -T db sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At' <<'SQL'
SELECT tgname FROM pg_trigger
 WHERE tgrelid IN ('audit_log'::regclass, 'submission_transitions'::regclass)
   AND NOT tgisinternal ORDER BY 1;
SELECT DISTINCT tableowner FROM pg_tables
 WHERE tablename IN ('audit_log', 'submission_transitions');
SELECT DISTINCT a.usename || ' superuser=' || r.rolsuper
  FROM pg_stat_activity a JOIN pg_roles r ON r.rolname = a.usename
 WHERE a.datname = current_database() AND a.backend_type = 'client backend'
   AND a.application_name <> 'psql';
SELECT 'member can act as staff=' || pg_has_role('aivs_member', 'aivs_app', 'MEMBER');
SQL
# → the six *_deny_update / *_deny_delete / *_deny_truncate triggers
# → aivs                      the owner owns the tables, never the app's roles
# → aivs_app superuser=false     the staff login (your AIVS_DB_APP_USER): the
#                                ISAC's staff and every background job
# → aivs_member superuser=false  the member login (your AIVS_DB_MEMBER_USER):
#                                every member organisation's request
# → member can act as staff=false
#                             (use your own names in the last query if you
#                             changed the defaults)
```

The member login exists so that SQL on a member's request runs as a role that
cannot become the staff one (Phase P). `member can act as staff=true` means
someone granted the staff role to it: revoke that, then re-run the migrate
service, which refuses it.

As the application role, the same check the application would meet:

```bash
docker compose --env-file deploy/.env exec -T db sh -c \
  'PGPASSWORD="$AIVS_DB_APP_PASSWORD" psql -h 127.0.0.1 -U "$AIVS_DB_APP_USER" -d "$POSTGRES_DB" -At' <<'SQL'
DELETE FROM audit_log WHERE id = 1;
DELETE FROM submission_transitions WHERE id = 1;
SQL
# → ERROR:  permission denied for table audit_log
# → ERROR:  permission denied for table submission_transitions
```

"Permission denied" is the grant refusing, before the trigger is reached. If you
see `table audit_log is append-only` instead, the trigger caught it but the role
holds the privilege: re-run the migrate service (`docker compose --env-file
deploy/.env run --rm migrate`), which grants the application role and refuses
one that is a superuser or owns the tables. A database initialised before the
application role, or before the member login, existed needs it created first
(the script creates both, and is safe to run again):

```bash
docker compose --env-file deploy/.env exec -T db /docker-entrypoint-initdb.d/10-app-role.sh
docker compose --env-file deploy/.env run --rm migrate
docker compose --env-file deploy/.env up -d
```

If any of this fails, stop and fix it. Everything downstream assumes it.

### 1.2 Create the ISAC's own organization

The hosting ISAC is itself an `Organization`, with `org_type = admin`. It is the
tenant operator, not a sharing participant.

| Field | Value |
| --- | --- |
| `name` | The ISAC's legal name |
| `slug` | e.g. `meridian-isac` (lowercase, `^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`) |
| `org_type` | `admin` |
| `status` | `active` |
| `stix_identity_id` | A generated `identity--<uuid>` — this becomes `created_by_ref` on anonymised content and on objects the instance authors |

The `stix_identity_id` is unique and format-checked in the database. Generate it
once; it is baked into every object you distribute anonymously and appears in
members' TIPs forever.

### 1.3 Create the first system administrator

An operator in the admin org holding `system_admin`, TOTP enrolled, and operators
holding `isac_editor` -- at least two, because a single editor is a single point
of failure for distributing time-sensitive warnings.

On a fresh instance nobody can enrol an organisation or create an operator --
those are ISAC powers, and they need a signed-in human. The first of each comes
from the bootstrap command, run in the app container, where the application's
configuration is. Issue the ISAC its own client certificate first
(`deploy/ca/issue-client.sh --org-slug example-isac --org "Example ISAC"`,
which writes `deploy/ca/out/clients/example-isac/example-isac.crt`). The app
container does not mount `deploy/ca/out` -- it holds private keys -- so the
certificate goes in on stdin, then the bootstrap reads it from there:

```bash
docker compose --env-file deploy/.env exec -T app sh -c 'cat > /tmp/isac.crt' \
    < deploy/ca/out/clients/example-isac/example-isac.crt
docker compose --env-file deploy/.env exec app python -m aivs_server.bootstrap_operator \
    --org-slug example-isac --org-name "Example ISAC" \
    --email ops@example-isac.org --name "Ops Lead" \
    --role system_admin --role isac_editor --role isac_membership \
    --certificate /tmp/isac.crt
```

`exec` without `-T` gives the command a terminal, which the password prompt
needs. `/tmp` in the app container is a private tmpfs that goes with the
container.

It creates the ISAC's organisation if none exists, registers the certificate
(which must be signed by the issuing CA), and creates the operator. The password
is prompted for, never passed on the command line. The TOTP provisioning URI is
printed **once** -- scan it, then clear the terminal. For each further ISAC
operator, until operator management exists in the portal, run it again without
`--org-name` and with `--additional`, and without `--certificate` once the ISAC's
certificate is registered (the same certificate cannot be registered twice). Once a system admin exists it refuses to
run without that flag, and every run raises the `operator_bootstrapped`
detection (§9.1): whoever holds the host can mint an editor this way, so the ISAC
is told each time it happens. It refuses a member organisation and a second ISAC
organisation.

Do not create more than about five. This role can distribute embargoed content to
GSIBs; the accountability should stay legible.

Issue that operator a client certificate too. Portal sessions are bound to the
organization's transport certificate (`portal_sessions.cert_fingerprint`), so a
password and TOTP alone will not get anyone in.

### 1.4 Create the initial circles

Start with fewer circles than you think you need. Circles are cheap to add and
socially expensive to remove — a member removed from a circle notices.

A common starting set:

| Slug | `minimum_tlp` | Who |
| --- | --- | --- |
| `all-members` | `amber` | Everyone. Broad awareness. |
| `gsib` | `amber_strict` | `org_type = gsib` firms. |
| `section9` | `amber_strict` | Section 9 designated firms. |
| `ai-supply-chain` | `green` | Anyone; `discovery_scope = ai_system` findings that are widely useful. |

`minimum_tlp` is a structural floor. A submission cannot be distributed into a
circle under a marking looser than that circle's floor. Setting it once here is
better than re-deciding it per submission, and it is the kind of decision that
should be made deliberately with the sharing agreement open, not at 4pm on a
Friday with a submission in the queue.

Each circle gets a TAXII collection. Its UUID goes into members' client
configuration, so it is stable for the life of the deployment. Give it a `title`
and an `alias` (`section9`) that members can recognise.

### 1.5 Decide who reviews submissions

Name a reviewer, and name a backup. The reviewer's job is described in §4, and
the essential property is that they have the standing to reject a submission on
scope grounds. A reviewer who cannot say no to a large member firm is not
performing the control.

---

## 2. Enrolling an organization

```
agreement signed → create org (pending) → sign CSR → register fingerprint
                 → activate → add to circles → confirm the member can poll
```

### 2.1 Create

`name`, `slug`, `org_type`, `contact_email`, and a generated `stix_identity_id`.
Status starts `pending`, and a `pending` org can do nothing — `is_active()` is
the first check in every authorization predicate.

Do not create the organization before the membership agreement is executed. The
agreement is what makes the TLP and embargo obligations enforceable, and the gap
between "enrolled" and "contractually bound" is the gap where an incident lives.

A `government` organisation is refused, at both the API and the portal, until
`AIVS_GOVERNMENT_RECEIPTS_POLICY_AGREED=true`. Its retrieval receipts and audit
rows are kept like any member's, and they prove that an agency collected a
named warning at a known time: a discoverable record. Set it only once the
membership agreement answers that (sharing agreement outline, §10).

### 2.2 Sign the CSR

The member sends a CSR. Sign it against the AIVS issuing CA:

```bash
deploy/ca/issue-client.sh --org-slug meridian-global --csr /tmp/meridian-global.csr
```

365 days, `clientAuth` only, `CA:FALSE` — profile in
[`deployment-topology.md`](deployment-topology.md) §3.3. The script's meaningful
output is the SHA-256 fingerprint.

Prefer the CSR mode. The fallback mode (`--org "…"` with no `--csr`) generates
the key here, which means you must transport it to the member over an
out-of-band encrypted channel and delete your copy. A key that has been emailed
is a key that must be re-issued.

Register in `client_certificates`:

| Column | Source |
| --- | --- |
| `fingerprint_sha256` | Computed from the signed certificate, lowercase hex, database-check-constrained to `^[0-9a-f]{64}$` |
| `subject_dn`, `issuer_dn`, `serial_hex` | From the certificate |
| `not_before`, `not_after` | From the certificate |
| `label` | What it is for: `taxii-prod`, `submit-batch`, `soc-analyst` |
| `status` | `active` |

**Read the fingerprint back to the member over a different channel than the one
the certificate travelled on.** It takes ten seconds and it is the only
verification either party gets that the identity on file is the identity they
hold.

### 2.3 Activate

Set `status = active`. Effective on their next request; nothing to restart.

### 2.4 Add to circles

Choose the role deliberately:

| Role | Grants |
| --- | --- |
| `member` | Read only |
| `contributor` | Read and submit |
| `circle_admin` | Historical — same as `contributor` |

Leave the role unset unless you mean something else. Unset, each organisation
gets its type's default: a G-SIB, Section 9 or critical-infrastructure member
joins as `contributor`, because a firm that reads a circle but cannot post to
it is the commonest reason nothing is shared. A vendor or government body joins
as `member`, because what it posts reaches the firms it supplies or supervises;
name `contributor` for one only when that is the point of the circle. Name
`member` for a sector firm that should only read (one still onboarding, say).
Memberships open before this default existed were moved to it once, by
migration `3efc1e04d297`, which left an audit row per circle naming them.

Do not reach for `circle_admin`: it grants nothing beyond `contributor`. Deciding
who is in a circle is yours and cannot be delegated — a circle holds other
members' embargoed intelligence, and you are the party their sharing agreement
runs to.

### 2.5 Confirm

Ask the member to hit `GET /taxii2/` and `GET /{api-root}/collections/`. If they
get `{}` from the collections endpoint, they are in no circles — that is a
correct, spec-conformant response and usually means step 2.4 was missed.

---

## 3. Managing circles

| Task | Notes |
| --- | --- |
| Add an organization | Takes effect on their next request. They will see content distributed **from that point on**; the `distributions` rows that already exist are not retro-visible to a new member unless you explicitly distribute to them. |
| Change a role | Effective immediately. |
| Remove an organization | They stop being able to read. **They keep what they already pulled** — you cannot unring that bell, which is why removal is a contractual conversation, not just a config change. |
| Deactivate a circle (`is_active = false`) | Prefer this to deleting. Deleting a circle cascades its memberships, and `distributions` has a `RESTRICT` foreign key to `circles`, so a circle with distributed content cannot be deleted at all. That restriction is deliberate. |
| Change `minimum_tlp` | Affects future distributions only. It does not re-mark or withdraw content already distributed. |
| Open a circle's TAXII inbox | Closed on every circle until an editor opens it: the **TAXII inbox** card on the circle's page, or `PUT /api/v1/circles/{id}/taxii-inbox` with `{"enabled": true}`. Opening it lets the circle's *contributors'* TAXII clients post to its collection; each post is a submission for review under source `system`, anonymous, under the AI gate, the disclosure split and the hourly allowance, and publishes nothing by itself. Recorded as `circle.taxii_inbox_set` with who switched it and which way. Close it the same way; posts are then refused with TAXII's 403. A replacement collection starts closed. |
| Create a sandbox | Tick "sandbox" when you create it (or `"is_sandbox": true` over the API). Use one for a member's day-one TIP check and for exercises: its content travels the real TAXII path and counts in no figure the ISAC reports (telemetry reach, lead time). It cannot be changed afterwards, so no circle's figures change meaning halfway through. |

### On the ISAC reading a circle

`can_read_circle` has **no system-administrator bypass**. If you want to receive
a circle's TAXII feed, add your admin organization to that circle, where members
will see you in the membership list.

This is deliberate and it will occasionally be inconvenient. The reason is that a
member firm can enumerate a circle's membership and see exactly who receives what
they share — and that answer is only worth something if it is complete. You can
still see every submission's workflow record and receipts through the portal and
native API, which is what oversight actually requires.

---

## 4. Reviewing and distributing submissions

This is the core operational duty and the system's principal legal control.

```
draft ──► submitted ──► validated ──► distributed ──► superseded
             ▲              ▲              ▲
          member         YOU            YOU
```

A member firm can never distribute its own content. The `validated` and
`distributed` transitions are restricted to `isac_editor`, in a human session, in
`can_transition_submission`, and that restriction is what keeps AIVS out of the
business of brokering third-party disclosures.

### 4.1 The review

Work the `submitted` queue. For each submission:

**Scope — the one that matters legally.**

| `discovery_scope` | Ask |
| --- | --- |
| `own_product` | Does this firm actually build and ship this product? Is `affected_products[].vendor` the submitter, or someone else? |
| `own_estate` | Is the affected system plausibly theirs to disclose about? |
| `ai_system` | Is this a genuine AI-system class finding — prompt injection, model supply chain, agentic tooling — or a conventional vulnerability in a third party's software wearing an AI label? |

**The last row is where the real risk sits.** `ai_system` is the broadest
category and the easiest to stretch. A finding in "vendor X's chatbot product"
submitted by a firm that neither builds nor operates it is a third-party
disclosure regardless of the AI framing, and today AIVS is not the channel for
it — the planned split by disclosure (`coordinated_disclosure`, with the vendor
recorded by an `isac_editor` as a party to the case) is not built.

If scope is wrong or unclear, **reject and ask**. AIVS cannot verify a
`discovery_scope` claim, and your review plus the contractual attestation are the
entire control. Rejecting is cheap; distributing someone else's unpatched
vulnerability without consent is not.

**Content.**

- Does it contain a working exploit or weaponised proof-of-concept? It should
  not. `ai_reproduction_available` is a boolean stating the submitter *holds* one.
  AIVS distributes warning, not proof-of-concept.
- Is there enough for a recipient to act — affected products, versions, a
  remediation or workaround?
- Are third parties named unnecessarily? A named vendor in a finding that is not
  about them is a defamation-shaped problem.
- Does `cve_status` match reality? `pre-cve` forbids a `cve_id`; `assigned` and
  `published` require one. The schema enforces this, but check that the claim is
  true, not merely well-formed.

**Distribution.**

- Is the TLP appropriate, and at least as restrictive as the target circle's
  `minimum_tlp`?
- Is the target circle right? Wider is not better. Content distributed to
  `all-members` cannot be narrowed afterwards.
- Is `distribute_anonymously` what the submitter intended? Confirm it if the
  content would obviously identify them anyway — anonymity that does not work is
  worse than none, because the submitter believes they have it.

**Embargo.**

- Is one set? For `own_product` findings, an embargo aligned to the submitter's
  patch schedule is normal.
- `timer` requires a `release_at` — enforced by a check constraint.
- Is the window realistic? Members need lead time to act; a 4-hour embargo on a
  critical finding is theatre.

### 4.2 Validate

`submitted → validated` records that review is complete. Distribution is a
separate step, so you can validate now and hold distribution for a coordination
window.

Give a reason on the transition. `submission_transitions.reason` is append-only
and is what makes the record legible to someone reading it in two years.

### 4.3 Distribute

`validated → distributed` writes one `distributions` row per (STIX object ×
target circle), stamping `date_added` with the visibility instant — now, or the
embargo release time if that is later. Embargoed content gets rows immediately
with a future `date_added`; it is simply not yet visible.

**This is irreversible.** `distributed` transitions only to `superseded`. You
cannot un-distribute, because members already hold the content and withdrawal
would be a false promise.

Check the target circles once more before you confirm.

### 4.4 Superseding

When a finding is updated — a CVE gets assigned, a workaround is found, severity
is revised — the submitter creates a new submission and the old one moves to
`superseded`, with `superseded_by_id` pointing at the replacement.

The old content **stays readable**. `VISIBLE_SUBMISSION_STATES` is
`{distributed, superseded}`. Members who pulled it need its history, and removing
it would silently break their `added_after` polling by shortening the sequence
behind their cursor.

### 4.4a Returned submissions

The first pass (the `triage` component on the status page) reads each
submission when its member submits it. When a member's own filing has
something the member can fix (a timestamp in the future, an affected product
with neither a purl nor a CPE, a vendor fix with no fixed version), it is
returned to the member with the notes, and never reaches your queue in that
form. Everything else arrives in the `submitted` queue with any notes
attached. Nothing urgent (KEV-listed, or an SSVC "Act") is returned, and the
same content is never returned twice. Nothing is returned while distribution
is paused. You cannot return a submission yourself; write to the member.

### 4.5 Withdrawing

`withdrawn` is reachable from `draft`, `submitted`, `returned` and `validated` —
never from `distributed`. Use it when a submission should not have been made or was
duplicated. Record the reason.

---

## 5. Embargo console

An embargo is per-submission (`embargoes`, unique on `submission_id`).

| `policy` | Meaning |
| --- | --- |
| `timer` | Releases at `release_at`. A `release_at` is required — check constraint. |
| `coordinated` | Released when a coordination process concludes. Use `coordination_notes`. |
| `manual` | Released when an operator says so. |

| `status` | Meaning |
| --- | --- |
| `pending` | Not yet released. |
| `released` | Released normally. `released_at` set — check constraint. |
| `extended` | The window was lengthened. |
| `lifted_early` | Released before its scheduled time. `released_at` set. |

### What actually enforces the embargo

**Not the scheduler.** Visibility is gated at read time on
`Distribution.date_added <= now`, evaluated in SQL on every member request. The
APScheduler sweeper (`AIVS_EMBARGO_SWEEP_INTERVAL_SECONDS`, default 30s) flips
`embargoes.status` and fires notifications — it is a convenience, not the gate.

Operationally this means:

- **If the sweeper dies, nothing leaks early** and nothing is withheld past its
  time. Content becomes visible exactly when `date_added` passes. The backlog of
  status flips and notifications self-heals on restart.
- A sweeper outage means members are not **notified**. Alert on it, but do not
  treat it as a disclosure incident.
- The sweeper also re-checks every embargo still on its timer against the
  content rules distribution checked (ownership, newest-version-only, the
  disclosure split, TLP inheritance, others' registered identifiers). One that
  no longer passes -- the target moved back out of disclosure, a referent
  re-marked stricter, a newer version of the same object distributed by its
  owner in the meantime -- is **held**: an `embargo.held` audit row and a
  warning name the rule, the embargo's policy becomes `manual` with no release
  time, its content waits, and it is listed under **Held embargoes** on the
  status page with its reason. Decide: fix the cause and release it early
  (which checks again and says why if it still refuses), or extend it to put it
  back on a timer. A version overtaken by a newer one cannot be fixed in place:
  withdraw it, and refile the change with a later `modified` if it is still
  needed.
- A rule that stops holding within one sweep interval of the release time, or
  while the sweeper is down, cannot be caught before the clock releases the
  content. The release's `embargo.released` row then carries
  `content_problem`; treat that as a handling incident for the content named.

### Extending

Extending pushes the release later. It requires updating the `distributions`
rows' `date_added` for the affected objects, because that column — not the
embargo row — is the gate.

Extend only with the submitter's agreement, and only before members have been
told to expect the original date. An extension after members have planned around
a date is a coordination failure with a technical fix, and members will remember
which it was.

### Lifting early

Set `status = lifted_early` and bring the `distributions.date_added` values
forward. Legitimate when the vulnerability is exploited in the wild, the
submitter patches early, or a third party publishes first.

The audit log records who did it and when. If a submitter's content is released
before they intended, they will ask; have the answer ready before they do.

---

## 6. Backup and restore

**The audit log is append-only, which changes what backup means here.**

`audit_log` and `submission_transitions` cannot be updated or deleted, by trigger
and by grant. They are the evidentiary basis for "we warned member X on this
date". A restore that loses rows is not ordinary data loss — it is a break in the
evidentiary chain, and there is nothing else that records the same facts, because
nothing else is allowed to.

### Strategy

| Layer | Method | Cadence |
| --- | --- | --- |
| Database — continuous | WAL archiving / PITR | Continuous |
| Database — full | `pg_dump -Fc` or a base backup | Nightly, retained per the ISAC's policy |
| Audit stream | **Ship `audit_log` rows off-box, append-only, to a system the AIVS operators cannot alter** | Continuous |
| CA material | Offline, encrypted media, two locations | On change |
| Configuration and secrets | Secret manager, versioned | On change |
| The key-encryption key file (`AIVS_SECRET_ENCRYPTION_KEY_PATH`) | Secret manager or offline media, **not beside the database backup** | On rotation |

**The key-encryption key is not part of the database backup, and must not be
stored with it.** A backup that contains both the sealed columns and the key
that opens them is a backup with no encryption at rest -- which is precisely the
threat the key exists to answer, since the realistic disclosure is a stolen
backup rather than a live host. Lose it entirely and every operator re-enrols
their second factor and every member re-registers their webhook; neither failure
announces itself, because both columns keep working right up until someone tries
to sign in.

**WAL archiving is not optional.** Nightly dumps alone mean a failure at 23:00
loses a day of audit rows, and you cannot regenerate them. PITR bounds the loss
to seconds.

The audit-stream row is the one people skip and the one that matters most. A
PostgreSQL superuser — including someone who has compromised the host — can drop
the append-only triggers and rewrite history. The trigger stops the application
and anyone with an ordinary session; it does not stop root. Shipping audit rows
to a system under different administrative control is the only mitigation, and it
is organisational, not technical.

### Restore

1. Restore the database to a point in time.
2. **Verify audit continuity**: `SELECT max(id), count(*) FROM audit_log;` and
   compare against the off-box stream. If they disagree, you have a gap — record
   it, in writing, with its bounds. A silently reconstructed audit log is worse
   than an acknowledged gap, because it is a document that asserts completeness
   it does not have.
3. Verify the append-only triggers survived the restore (§1.1). A dump/restore
   cycle does not necessarily carry triggers and grants — check, do not assume.
4. Verify the sealed secrets open under the configured key:
   `docker compose --env-file deploy/.env exec app python -m aivs_server.rewrap_secrets`
   reports `unopenable=0`. A database
   restored beside the wrong environment's key looks entirely healthy until the
   first sign-in, and then fails as if the operator's code were wrong.
5. Verify `distributions.date_added` values for pending embargoes are intact.
   These are the enforcement gate; a restore that loses a future `date_added`
   could make embargoed content visible.
6. Reconcile with members: has anything become visible that should not have, or
   stayed hidden that should have released?

**Test restores on a schedule you actually keep.** A backup regime discovered to
be broken at the moment it is needed is the single most common operational
failure in systems of this kind.

---

## 7. Incident response

### 7.1 Content distributed that should not have been

The worst case, and the one to have thought about in advance.

1. **You cannot un-distribute.** Do not spend the first ten minutes looking for
   a way. `distributed` transitions only to `superseded`.
2. **Establish who has it.** `acknowledgments` rows of type `retrieved` tell you
   exactly which organizations pulled it and when. This is the receipts query in
   §8.
3. **Notify the affected parties** — the submitter, the affected vendor if
   relevant, and every organization that retrieved it.
4. **Notify those who have not yet pulled it**, with handling instructions. They
   will still receive it; the content is in their collection.
5. **Supersede** with corrected content if there is any.
6. **Record everything.** The audit log has the technical facts; the ISAC's own
   incident record needs the decisions.

### 7.2 A member is compromised: quarantine

When a member's credentials may be in someone else's hands -- a compromised
collector, a stolen laptop, an intrusion -- quarantine it:
`POST /api/v1/orgs/{id}/quarantine` with a reason. Its status becomes
`quarantined` (refused on every request), and every certificate and portal
session it holds is revoked. Its circle memberships are untouched: quarantine
protects the member and the community; it does not change what it is entitled
to. A member's own `org_admin` can quarantine their firm without asking you.
The `bulk_retrieval` detection can also propose a quarantine, or apply one
itself, depending on `AIVS_DETECTION_QUARANTINE_POLICY` (§9.1).

Reconnecting is yours alone: `POST /api/v1/orgs/{id}/reconnect`. It refuses
until the member has a freshly registered certificate -- the old ones stay
revoked, and any still active from before the quarantine is revoked then.
Membership staff register the fresh one; the member's own admin cannot while
it is quarantined. Reconnection reconciles circle rules, as activation does. `"backlog": "deliver"` (the default) lets the member receive what was
shared while it was out; `"new_interval"` withholds it, for an incident whose
nature means the gap must not reach them. Earlier content is kept either way.
Tell the member which you chose and why; a self-quarantine is also something
they may have to report to their own regulator.

### 7.2a A member leaves: offboarding

Offboarding is the end of a membership, and **nothing reverses it**. A member
that comes back is enrolled again, as a new organisation. If there is any
legal matter open about the member, place a legal hold **first**: offboarding
deletes the member's postures unless one is set.

1. If needed, place the hold (membership staff):
   `PUT /api/v1/orgs/{org_id}/legal-hold` with `{"reason": "..."}`.
2. Offboard: `POST /api/v1/orgs/{org_id}/offboard` with
   `{"reason": "...", "confirm_slug": "<the organisation's slug>"}`. The slug
   typed out is the check that you meant this organisation.
3. Every offboarding raises `org_offboarded`; expect the alert, and confirm it
   to whoever watches them.
4. When the matter closes, lift the hold:
   `POST /api/v1/orgs/{org_id}/legal-hold/lift` with `{"reason": "..."}`. On an
   offboarded organisation this deletes the postures the hold kept.

What it does: every certificate and portal session ends; every open circle
membership closes as `offboarding`; operators are pseudonymised (their ids stay,
so the audit log still resolves); the contact email is cleared; postures,
webhooks, portal sessions and TAXII inbox statuses are deleted (postures kept
under a hold). Contributions, receipts and the audit log are kept: they are
the record of what the member was sent, and its name stays on them.

### 7.3 Suspected certificate compromise

1. Revoke it through the application, as membership staff:
   `POST /api/v1/certificates/{certificate_id}/revoke` (or the portal's
   organisation page). It takes effect on the holder's **next request** -- no
   CRL propagation delay -- and it also ends every portal session bound to that
   certificate and writes the `cert.revoked` audit row, which a hand edit of
   `client_certificates` does neither of (and the app's database role could
   not make it anyway). Then record it in the CA:
   `deploy/ca/revoke.sh --cert <path to that certificate> --reason keyCompromise`.
   The CRL matters for relying parties outside AIVS; the revocation in the
   application is what matters here. Do it first.
2. Query the audit log for everything that fingerprint did. `actor_id` on an
   mTLS-authenticated row **is** the certificate fingerprint.
3. Determine what was retrieved: `acknowledgments` filtered by that org.
4. If more than one certificate may be in the wrong hands, or you cannot tell,
   quarantine the organisation (§7.2): it revokes every certificate and session
   at once, and reconnection needs fresh credentials. Do not set the status in
   the database: `change_org_status` is the one writer that knows every state.
5. Issue a replacement once the member has generated a fresh key.

### 7.4 Rotating the secret-encryption key, or changing its algorithm

Rotate on suspected disclosure of the key itself, on the departure of anyone who
held it, and otherwise on the ISAC's own schedule. Both keys open during a
rotation; only the active one seals, so there is no flag day and no downtime.

**Changing the algorithm is the same procedure.** Every stored value records the
algorithm and the key it was written with, so setting
`AIVS_SECRET_ENCRYPTION_ALGORITHM` to another supported name (`aes-256-gcm`,
`chacha20-poly1305`) leaves existing values readable and moves new writes across;
the same re-wrap below then migrates the rest. Substitute "the algorithm" for
"the key" in the steps, and there is no previous-key variable to remove at the
end.

Both keys are files. Outside dev the application refuses either key from the
environment, so do not set `AIVS_SECRET_ENCRYPTION_KEY` or
`AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS` during a rotation: it will not start.

1. Write the new key to a **new** file, readable only by the app's uid:

   ```bash
   umask 077
   openssl rand -base64 32 > /srv/aivs/secrets/secret-encryption-key.new
   chown 10001:10001 /srv/aivs/secrets/secret-encryption-key.new
   ```

2. In `deploy/.env`, point `AIVS_SECRET_ENCRYPTION_KEY_PATH` at the new file and
   set `AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS_PATH` to the file it replaces. Start
   with the rotation override, which mounts the previous key:

   ```bash
   docker compose --env-file deploy/.env \
     -f docker-compose.yml -f docker-compose.rotation.yml up -d
   ```

   Everything continues to work at this point: existing rows open under the
   previous key, new writes seal under the new one.
3. Re-seal what is still on the old key, with the same files as step 2 (without
   `--env-file`, compose cannot interpolate the file and refuses to run):

   ```bash
   docker compose --env-file deploy/.env \
     -f docker-compose.yml -f docker-compose.rotation.yml \
     exec app python -m aivs_server.rewrap_secrets            # report
   docker compose --env-file deploy/.env \
     -f docker-compose.yml -f docker-compose.rotation.yml \
     exec app python -m aivs_server.rewrap_secrets --apply    # re-seal
   ```

4. Re-run the report. **Only when it shows `stale=0` and `unopenable=0`**, start
   again without `-f docker-compose.rotation.yml` and unset
   `AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS_PATH`. Keep the old file wherever keys
   are kept until a backup taken after the rotation has been tested.

Dropping the previous key before step 4 is clean is the one way to lose these
secrets, and it does not fail loudly: the rows remain, the application starts,
and the loss surfaces as operators being told their authenticator code is wrong.
A value that cannot be opened is reported and left untouched -- never
overwritten -- so a mistaken run is recoverable as long as the old key still
exists somewhere.

**A rotation is not a remediation for a database disclosure.** If the sealed
columns and the key were disclosed together, treat every TOTP seed and every
webhook signing key as known: re-enrol the operators and have members
re-register their webhooks. Re-sealing already-disclosed plaintext under a new
key protects nothing.

### 7.4a Rekeying the attribution key

The attribution key (`AIVS_ATTRIBUTION_KEY_PATH`) keys the owner tags and owner
tokens: how the member path asks "is this mine?" without the database being able
to answer "whose is this?" (SF-90). Rekey on suspected disclosure of the key, on
the departure of anyone who held it, and otherwise on the ISAC's own schedule.

**The key being replaced is not needed.** Every tag and token is recomputed from
who filed what, which the database holds, so a lost key is recovered by this
same procedure with a new one. That works because tokens never leave the server:
nothing a member holds stops matching.

**It needs the application stopped.** A running instance would go on writing
values under the old key while the rekey writes them under the new one. The
rekey is one transaction, and the application refuses to start while any value
is under a key other than the one it is given, naming the columns -- so an
interrupted rekey cannot be served by mistake.

The key is a file, as the secret-encryption key is; do not set
`AIVS_ATTRIBUTION_KEY` in the environment, or the application will not start.

1. Write the new key to a **new** file, readable only by the app's uid:

   ```bash
   umask 077
   openssl rand -base64 32 > /srv/aivs/secrets/attribution-key.new
   chown 10001:10001 /srv/aivs/secrets/attribution-key.new
   ```

2. Stop the application:

   ```bash
   docker compose --env-file deploy/.env stop app
   ```

3. In `deploy/.env`, point `AIVS_ATTRIBUTION_KEY_PATH` at the new file. Report
   what is not on it, then recompute it:

   ```bash
   docker compose --env-file deploy/.env \
     run --rm --no-deps app python -m aivs_server.rekey_attribution            # report
   docker compose --env-file deploy/.env \
     run --rm --no-deps app python -m aivs_server.rekey_attribution --apply    # recompute
   ```

4. Re-run the report. **When it says `not on this key: nothing`**, start the
   application:

   ```bash
   docker compose --env-file deploy/.env up -d
   ```

   If it refuses to start with "hold values under an attribution key other
   than", step 3 did not finish: run it again.

Destroy the old file once the instance is serving. Unlike the secret-encryption
key, it opens nothing that is not recomputed.

**A rekey is not a remediation for a disclosure of the database together with
the key.** Whoever holds both can already recover who filed everything up to
then. Treat it as a disclosure of every filer's identity, including anonymous
filers', and notify as for content (section 7.5).

### 7.5 Instance compromise

Assume every piece of content is disclosed. That is the honest starting
assumption for a database holding embargoed, unpatched vulnerabilities affecting
GSIBs.

1. **Pause distribution** -- the first step, because it takes seconds and needs
   no infrastructure access:

   ```bash
   curl --cert ... --key ... -H "Authorization: Bearer $SESSION" \
        -H 'Content-Type: application/json' \
        -X POST https://<instance>/api/v1/instance/distribution/pause \
        -d '{"reason": "suspected compromise, INC-<n>"}'
   ```

   Every publication is refused and nothing is served, including embargoes
   whose time arrives during the pause -- those would otherwise become visible
   by the clock. No member is told anything either: the embargo sweeper does
   nothing and members' webhook deliveries are held, then sent on resume. The
   ISAC's own endpoints still receive their alerts, including the one raised by
   the pause itself. Extending an embargo still works while paused, because it
   only moves content later: push out anything at risk **before** you resume,
   or every embargo whose time passed during the pause opens at once. Members' polling cursors do not move on an empty page, so
   nothing is skipped when you resume. An ISAC editor or system admin may
   pause; only an editor may resume.
2. Isolate: stop the overlay or the allowlist. Members will notice; that is fine.
3. Preserve: snapshot the database and the audit log before touching anything.
4. Verify audit integrity against the off-box stream. If the triggers were
   dropped, the on-box log is untrustworthy from that point forward and the
   off-box copy is your only record.
5. Notify every member and every submitter with content in the instance.
6. Assume the issuing CA is compromised if the host held its key. Revoke the
   intermediate from the offline root, stand up a new one, re-issue member
   certificates. This is why the root is offline and why the hierarchy has two
   levels.

### 7.6 Audit write failures

`record_independently` **swallows its own failures** — deliberately, so that an
audit outage does not turn a clean 403 into a 500 and tell a caller their denied
request perturbed the server. It logs `failed to write independent audit record`
via `logger.exception`.

Alert on that string. It means denials and authentication failures are happening
and not being recorded, which is precisely the window an attacker wants.

---

## 8. "Prove we warned member X"

The question a regulator, a member's counsel, or an ISAC board will eventually
ask. AIVS is built to answer it, and the answer is a query, not a narrative.

### The four records

| Record | Table | What it establishes |
| --- | --- | --- |
| The content existed and was reviewed | `submissions`, `submission_transitions` | What was shared, by whom, in what state, and every transition with actor and timestamp — append-only |
| It was made visible to their circle | `distributions` | The exact instant it became visible to that circle (`date_added`), per object |
| They collected it | `acknowledgments` (`ack_type = retrieved`) | Server-written on actual delivery, not a member assertion |
| They engaged with it | `acknowledgments` (`acknowledged`, `actioned`) | Member assertions, with `actor_ref` and `note` |

Underneath all four: `audit_log`, immutable, recording every access and every
administrative action with actor, request id, source IP, and outcome.

### The query

```sql
-- Everything about one submission and one member firm.
SELECT
    s.id                        AS submission_id,
    s.title,
    s.tlp,
    s.discovery_scope,
    s.distributed_at,
    c.slug                      AS circle,
    min(d.date_added)           AS visible_to_circle_from,
    a.ack_type,
    a.via,
    a.actor_ref,
    a.created_at                AS ack_at,
    a.note
FROM submissions s
JOIN distributions  d ON d.submission_id = s.id
JOIN circles        c ON c.id = d.circle_id
JOIN circle_memberships cm ON cm.circle_id = c.id AND cm.org_id = :org_id
LEFT JOIN acknowledgments a
       ON a.submission_id = s.id AND a.org_id = :org_id
WHERE s.id = :submission_id
GROUP BY s.id, c.slug, a.ack_type, a.via, a.actor_ref, a.created_at, a.note
ORDER BY a.created_at;
```

### What the answer sounds like

> Submission `0f9c1e2a` was submitted by [firm] on 2026-03-04 at 09:12 UTC,
> validated by [operator] at 11:40, and distributed to the `section9` circle at
> 14:02. Member X has been a member of that circle since 2025-11-03. The content
> became visible to that circle at 2026-03-11 00:00 UTC, when its embargo
> released. Member X's TAXII client retrieved it at 2026-03-11 00:04 UTC using
> certificate `a31d…f09c`. A named analyst recorded `actioned` on 2026-03-12 with
> the note "patched in change CHG-44821". Every one of those facts is in an
> append-only table with a database-level trigger preventing modification, and
> the retrieval receipt was written by the server on delivery, not asserted by
> the member.

### What you cannot claim

Be precise about the limits, because overclaiming is how an evidentiary argument
collapses under examination:

- **Retrieval is not reading.** A `retrieved` receipt proves the content was
  delivered to a client holding that organization's certificate. It does not
  prove a human read it. `acknowledged` and `actioned` are the member's
  assertions about that, and they are assertions.
- **Automatic receipts are deduplicated daily.** `dedupe_day` collapses `retrieved`
  rows to one per org per submission per day. You can prove they collected it
  that day, not how many times.
- **A certificate identifies an organization, not a person.** Unless it is an
  operator's portal session, in which case `actor_id` is the operator id.
- **The audit log is tamper-*evident* against ordinary access and
  tamper-*resistant* in practice — not tamper-proof against a superuser.** If
  you have shipped audit rows off-box to a system under different administrative
  control, say so, because it is what makes the claim strong. If you have not,
  do not imply otherwise.

---

## 9. Routine tasks

| Task | Cadence | Notes |
| --- | --- | --- |
| Work the `submitted` queue | Daily | The human checkpoint. A backlog is a product failure. |
| Work the drafts waiting for an ISAC editor | Daily, with the queue | The review page's **Drafts waiting for an ISAC editor**: analysts' drafts for the ISAC and the automation's KEV drafts, oldest first, which only an editor may send or withdraw. A KEV draft holds its record's next KEV update back until it is sent. The status page counts drafts waiting more than 7 days, KEV drafts on a line of their own. |
| Run `scripts/enrich-kev.py` against CISA's current KEV catalogue | Daily, or when CISA adds entries | Download the catalogue first; the script talks to nothing but this instance. It runs with the **automation organisation's** certificate (the only identity `/api/v1/isac-records/vulnerabilities` answers), reads the ISAC's own records, and files a KEV version of each listed one **as a draft**: every verb on the automation's own filing is an ISAC editor's (Q35), so the run ends with "N filed as a draft, waiting for an ISAC editor to send it", and an editor sends each for review, validates and distributes it. It skips RED records, records whose newest version is still under embargo, records with a version in review (submitted or validated), and records whose KEV draft from an earlier run is still waiting, so a second run files nothing twice. An editor's or analyst's own draft of a record does not hold it back; if a KEV version overtakes it, the draft is refused when sent (SF-82) and is refiled with a later `modified`. The automation can have webhooks, pushing telemetry on its own filings, only with `AIVS_AUTOMATION_WEBHOOKS_ENABLED=true`. It's off by default, as an option the instance may charge for. Switched off, registration is refused and deliveries already queued are held, not sent (SF-92). |
| Run `scripts/import-conditions.py` against downloaded CVE and OSV records | Weekly, or when a record the ISAC tracks changes | Download first (`--cve-dir`: CVE 5.x JSON named `CVE-*.json`, as in the cvelistV5 repository; `--osv-dir`: OSV JSON, Go vulndb and RustSec); the script talks to nothing but this instance, with the **automation organisation's** certificate. For each ISAC record naming a CVE it files one condition note per upstream record, **as a draft** an editor sends; validating it means naming its conditions (`<note id>:conditions`), because a machine's condition tells members they are not affected. A condition is filed only when every affected entry states it in a form that maps -- otherwise it is left out and the note's `unknowns` says so -- and a record that states nothing that maps is counted, not filed. The record's configuration prose is in the submission's summary for the editor to turn into a configuration condition by hand; it is never distributed. A note the editor has since corrected is left alone, and one still waiting, in review or not readable is not filed again. GHSA vulnerable functions are planned, from a source not yet confirmed. |
| Review `authz.denied` audit rows | Weekly | Repeated denials from one org: misconfiguration or probing. |
| Review certificate expiry | Monthly | Member certificates are valid 365 days. Start rotation at 60 days out. |
| Refresh CRLs (`revoke.sh --gencrl-only`) | Monthly, **only if** nginx's `ssl_crl` is enabled | With `ssl_crl` set, OpenSSL requires a current CRL for every CA in the chain — an expired one rejects every client. The shipped config leaves it commented out precisely to avoid that availability obligation. |
| Review `last_seen_at` on active certificates | Monthly | A certificate unused for months should probably be revoked. One appearing from an unexpected place is worth a phone call. |
| Verify polling health per member | Monthly | A member whose cursor has not advanced in weeks is not receiving warnings and may not know. |
| Test a restore | Quarterly | Including audit continuity verification. |
| Review circle membership against the agreements | Quarterly | Drift is normal; unreviewed drift is not. |
| Review who holds `system_admin` | Quarterly | Departures, role changes. |
| Verify append-only enforcement (§1.1) | Quarterly, and after any restore or major upgrade | It can silently stop being true. |
| Rehearse offline root recovery | Annually | An untested offline root is a lost root. |

### 9.1 What the platform watches for you

**`/portal/admin/status`** puts all of it on one page for `system_admin` and
`isac_membership`: component health, queue depths, detections from the last
24 hours, usage for the past week, quarantined organisations, certificates
expiring within 30 days, members that have retrieved nothing for 14 days,
failing webhook endpoints, digest email the relay has not accepted, and sealed
secrets not yet on the active key. Three
of the monthly reviews in the table above start there. It cannot see backups,
and it says so.

Some of the reviews above are now also rules that run every
`AIVS_DETECTION_INTERVAL_SECONDS` (default 60) in `services/detections.py`.
Each finding is raised **once per rule window** and goes three ways:

- a `detection.raised` audit row (the record);
- one WARNING line on the `aivs_server.security` logger carrying the finding as
  an **OCSF Detection Finding** (class 2004) and a **CEF** string, for a SIEM
  or MSP reading the forwarded logs;
- a contentless `detection.raised` webhook to endpoints registered by the
  ISAC's **own** organisation. Members' webhooks never receive it.

| Rule | Raises when | First thing to do |
| --- | --- | --- |
| `auth_failure_burst` | 20 refused authentications from one address in 10 min | Check whether it is a member's collector with an expired certificate before you assume probing. |
| `login_failure_burst` | 10 failed portal logins against one account in 15 min | The account locks at 5 failures, so 10 means someone kept going through the lockout. Contact the operator out of band. |
| `bulk_retrieval` | One organisation retrieves 200 distinct submissions in 1 h | Treat as a possibly stolen certificate (§7.3). The finding **proposes a quarantine** of that organisation; what happens next depends on `AIVS_DETECTION_QUARANTINE_POLICY` (below the table). |
| `signing_key_unavailable` | Any notification is held because its webhook's signing key cannot be opened (per endpoint; raised again every 6 h while it lasts) | The cause is our configuration, not the member's endpoint: check the key-encryption key file, and during a rotation the previous key too (§7.4). Until it opens, that member hears nothing. |
| `not_found_burst` | One organisation gets 50 "not found" answers in 10 min | Someone is walking identifiers. Ask the member whether a misconfigured client explains it. If not, treat it as §7.3. |
| `contribution_flood` | One organisation goes past its hourly allowance for contributions published without review (TAXII inbox posts included) | A script or a stolen certificate behind a session. Check what it filed in the review queue, then treat as §7.3 if the member didn't do it. |
| `posture_export_burst` | One organisation exports its postures 20 times in 1 h | The export is the firm's whole list of where it is affected. Ask the member whether a collector explains it. If not, treat it as §7.3: the alert names the firm, never a statement. |
| `evidence_pack_burst` | One organisation draws 20 evidence packs in 1 h | Each pack is the firm's record of what reached it and what it did; many together are its response history. Ask the member whether an audit explains it. If not, treat it as §7.3. The alert names the firm, never a vulnerability. |
| `auditor_bulk_read` | One auditor is served 20,000 audit or receipt events in 1 h, counting pages the stream records as quiet | A SIEM catching up after an outage does this once. Otherwise someone is reading which firms attend to which threats: confirm with the auditor's engagement contact, and if nobody explains it, revoke the auditor's sessions and end its access. |
| `auditor_outside_audit` | An auditor's session is refused 5 times in 30 min outside the audit read | An auditor's tooling reads two endpoints. A session trying content routes is someone exploring with an auditor's credential: revoke its sessions and ask the auditor's firm. |
| `first_distribution_to_circle` | An operator distributes to a circle they have never distributed to before | The checker's look: confirm the circle was the intended audience. |
| `anonymity_reveal` | Any reveal of an anonymous submitter | Confirm the reveal was expected and that its recorded reason holds up. |
| `distribution_paused` | Distribution paused instance-wide | Confirm someone on the incident bridge did it. |
| `operator_bootstrapped` | The bootstrap command created an operator | Confirm who ran it on the host and why. An unexplained one is a host compromise (§7.5). |
| `org_offboarded` | Any offboarding | Irreversible: confirm it was the agreed end of membership, not a mistyped quarantine. A stolen membership session offboarding a member is §7.5. |
| `org_quarantined` | Any quarantine, including self-quarantine | Confirm the member knows, and start reconnection planning. |
| `filer_mismatch` | A filing recorded in a firm's name that no audited creation names (checked over 24 h) | Only SQL on the member path can write one. Treat it as §7.5: find the request in the audit log by time, and do not distribute the submission. |
| `owner_tag_mismatch` | A submission whose owner tag is not its recorded filer's, or that has no filer (checked over 24 h) | Nobody can act on it as its submitter, so it is inert, not harmful. Treat it as `filer_mismatch` if one was raised for the same submission; otherwise check for a half-finished rekey (§7.4a) and re-run it. |
| `component_degraded` | A background job (embargo sweeper, webhook dispatcher, detections, published counts) has not succeeded for two of its intervals | Read the app log for that component's exception; `/readyz` names it and the error type. |

**Who acts on a proposed quarantine** is the ISAC's choice, set once in
`AIVS_DETECTION_QUARANTINE_POLICY`:

- `propose` (the default, and the setting that does less): `/portal/admin/status`
  lists the proposal — organisation, rule, time — while the organisation is
  still active, and an operator allowed to quarantine confirms it with one
  click. That runs the same quarantine as §7.2, recorded as that operator's
  decision.
- `enforce`: the organisation is quarantined as soon as the finding is raised,
  through the same checks and certificate revocation as §7.2, but recorded with
  the actor `detection:bulk_retrieval`, so an automatic quarantine never reads
  as a person's decision. The ISAC's own organisation is never quarantined this
  way; the refusal is logged and the finding stays a proposal.

Choose `enforce` only if a wrongly quarantined member — cut off until you
reconnect it — is a smaller cost to your community than a stolen certificate
paging the archive until someone reads the status page.

`component_degraded` cannot report the detection loop's own death. That is
why the same health registry is also exposed on `/readyz` (a JSON
`components` map; the probe stays 200 while only background work is degraded)
and `/metrics` (`aivs_component_up`, `aivs_webhook_deliveries_pending`,
`aivs_embargoes_pending`, Prometheus text format). Scrape `/metrics` from the
`backend` network and alert on `aivs_component_up == 0`. That alert is the
one that still works when this process's own loops do not.

### 9.2 What your SIEM or MSP receives

Run the stack with `docker-compose.log-forward.yml` (deployment topology §7)
and the collector receives, as RFC 5424 syslog over TLS, one stream per
container, tagged with the container name:

- **app**: one JSON object per line. `logger` names the source.
  `aivs_server.access` is the per-request access log (method, path, status,
  duration, request id, never the query string).
  `aivs_server.security` carries detections: parse the `ocsf` field as an
  OCSF Detection Finding (class 2004), or take the `cef` field as-is for a
  CEF consumer. Every line from one request shares its `request_id`.
- **proxy**: nginx's JSON access log, keyed by the same request id.
- **db**: Postgres's own log.

None of it carries intelligence content: identifiers, counts, addresses and
times. An MSP watching the ISAC is not a recipient of its intelligence. The
identifiers in request paths are a submission's own id and, on a TAXII read
by object, that object's id. A member's response to content -- a one-click or
a posture -- carries the object in its body, never its path, so the stream
does not say which firm responded to which object. The portal's vulnerability
page and the readiness API take the vulnerability in the query string, which
neither log records, so the stream does not say which firm read which
vulnerability either.

The forwarder is non-blocking. A collector outage drops lines and never stops
the platform, so alert on the collector's side when the stream goes quiet.

---

### 9.3 Is each member still collecting?

A member that has stopped collecting does not notice: nothing arrives, which
looks like nothing being shared. The status page lists **connections with
content waiting more than 3 days**: per member and collection, the oldest
content visible to it that it has not collected since. A member with nothing
new is not listed. Members see the same for themselves on their **Connection**
page, with their webhooks' delivery state, their certificates' expiry, and a
starting configuration for OpenCTI, MISP or Splunk with this instance's
addresses and their collections filled in.

### 9.4 Sector events

When the whole sector is working one vulnerability, pin the ISAC's record for
it: `POST /api/v1/sector-events` with its `vulnerability_stix_id`. Only the
ISAC's own record, already distributed, can be pinned, one event per
vulnerability. Every member that can see the record finds it at the top of
its dashboard, and every notice and digest line about it is marked as part of
the event; keep versioning the record as usual, and members' cadence coalesces
the versions. After each sector call, file its notes with
`POST /api/v1/sector-events/{id}/call-notes` (a summary and the action items):
they become a draft of `note`s on the record for you to review and distribute
like anything else. Close the event with `POST .../close` when it is over.

### 9.5 Notification cadence and digest email

A member chooses how often it is told content became visible:
`immediate` (the default, one notice per submission), `hourly` or `daily`
(one digest per window, sent at the top of the hour or at
`AIVS_DIGEST_DAILY_HOUR_UTC`, 07:00 UTC unless set). It sets this, and an
optional digest mailbox, with `PUT /api/v1/notification-settings`, using the
certificate or org-admin session that registers its webhooks. A mailbox needs
an hourly or daily cadence.

A digest names how many items of each marking became visible, links each to
its collection, names the affected products below RED, and gives titles only
for CLEAR and GREEN items. Nothing more, and nothing while distribution is
paused.

Email is off until you name a relay. The relay is a subprocessor: tell your
members which one, and that it sees the digest's counts, products and green
titles. To turn it on:

1. Put the relay password in a file only uid 10001 can read:
   `umask 077; printf '%s' "$PASSWORD" > /srv/aivs/secrets/smtp-password;
   chown 10001:10001 /srv/aivs/secrets/smtp-password`.
2. Set `AIVS_SMTP_HOST`, `AIVS_SMTP_FROM`, `AIVS_SMTP_USERNAME` and
   `AIVS_SMTP_PASSWORD_PATH` (that file's absolute path) in `deploy/.env`.
3. Start with the override:

```bash
docker compose --env-file deploy/.env -f docker-compose.yml -f docker-compose.digest-email.yml up -d
```

STARTTLS with the relay's certificate verified is always required; there is
no setting to relax it. A message the relay refuses is retried with backoff,
up to `AIVS_EMAIL_MAX_ATTEMPTS`, and keeps its last error in
`email_deliveries.error`. The status page lists undelivered digests per
member and mailbox domain, split into retrying and given up, but not the error:
a relay's refusal usually repeats the address, and `isac_membership` reads that
page. Read the error in the table. A message given up on is not retried; once
the member has fixed its mailbox, the next digest is a new message.
### 9.6 An auditor, and the audit stream your SIEM polls

An auditor reads the audit trail and receipts and nothing else (SF-78). At the
ISAC it reads the whole instance; a member's auditor would read only its own
organisation's rows, but no path creates one yet. Create the ISAC's auditor
from the host, with the date the engagement ends; the role is held alone, and
the database refuses an auditor without an end date:

```bash
docker compose --env-file deploy/.env exec app python -m aivs_server.bootstrap_operator \
    --org-slug <isac> --additional \
    --email auditor@firm.example --name "External auditor" \
    --role auditor --role-expires-at 2027-03-31T00:00:00+00:00
```

Like every operator created this way, it raises `operator_bootstrapped`.
After the end date its sessions are refused (`operator_access_ended`).

The stream is `GET /api/v1/audit/events` and `GET /api/v1/audit/receipts`,
read with the auditor's session as a bearer token. Each page returns a
`cursor`; pass it back to continue. Polling with the last cursor returns only
what has committed since, in commit order. Each event's `hash` chains to the
one before, across pages, so a gap or an edit between two exports shows. The
stream waits behind the oldest transaction still running anywhere on the
database cluster. A cursor that stops moving while the trail is being written
means a connection is sitting in an open transaction; find it in
`pg_stat_activity` (`state = 'idle in transaction'`).

**What the stream serves of its own reading** is a choice the system
administrator makes for the instance, `condensed` (the default) or `full`:

| Mode | `audit.read` (a page that served other events) | `audit.read.quiet` (a page that served only reads, or nothing) | `audit.read.summary` |
| --- | --- | --- | --- |
| `condensed` | not served | not served | served |
| `full` | served | not served | served |

The summary job writes one `audit.read.summary` per reader each run (hourly by
default, `AIVS_AUDIT_READ_SUMMARY_INTERVAL_SECONDS`): pages, quiet pages,
events served, first and last read, streams. It is the only place a SIEM sees
quiet pages, in either mode, and it skips its run while distribution is paused
(the next run covers the gap). Quiet reads are never served so that a poller
reading until a page comes back empty gets there, even with two pollers
reading each other's reads. Every kind stays in the log: `auditor_bulk_read`
counts all of them, and an export of `audit_log` from the database shows them.

To change the mode, as a system administrator:

```bash
curl --cert ... --key ... -H "Authorization: Bearer $SESSION" \
     -H 'Content-Type: application/json' \
     -X PUT https://<instance>/api/v1/instance/audit-stream \
     -d '{"mode": "full", "reason": "the SIEM team wants every read, CHG-<n>"}'
```

The change is served in the stream as `audit_stream.mode_changed`, and applies
to reads written after it. What was served before it is served the same way to
anyone who reads it again, so a SIEM's cursor and the hash chain it keeps carry
on unchanged. Changing to the mode already in force writes nothing.

**What the ISAC's auditor is not shown (SF-94).** Who filed a submission is
intel staff's alone. On a row about a submission or a contribution, and on any
row written in the same transaction as one, the auditor's stream serves
`org_id`, `actor_type`, `actor_id`, `request_id` and `source_ip` as null and
cuts `details` to states, codes, counts, circles, flags and times -- unless the
row's organisation is the ISAC's own or its automation's, so which editor
validated, distributed or filed on a member's behalf stays visible. A null means
"a member did this", never which member. Who filed what is answered from the
database by intel staff, not from the export.

**The chain is version 2 from slice 3d.** A SIEM that re-exports from genesis
after the upgrade gets different hashes for every content row it exported
before, because those rows are now served redacted. That is expected, not
tampering: the first hash of a fresh export chains from `aivs-audit-chain/v2`,
an old export's from `v1`. A SIEM polling forward with its cursor sees no
break; its chain continues over the new projection.

### 9.7 Email-to-draft: members email the ISAC

Members can email a finding to a mailbox you already run, and it appears as
a **draft** in their organisation's portal. Nothing an email does is
distributed, reviewed or submitted: a person at the member opens the draft,
checks it and submits it, and the first pass reads it then. A secure API for
the same thing, for members who would rather not use email, may follow; it is
planned, not built.

AIVS reads the mailbox over IMAP with TLS (port 993, the server's certificate
verified; there is no setting to relax either). It opens no port of its own.
The server must offer `MOVE` (RFC 6851) or `UIDPLUS` (RFC 4315), so that a
message is moved alone; one offering neither is refused, because a plain
expunge would also erase whatever anyone else had flagged in the mailbox.

**Record each member's mail domains first.** An operator's email is the key
the intake looks the sender up by, and a message is filed only when that
address is in one of the domains recorded as the sender's organisation's
(Organisations screen, or `POST /api/v1/orgs/{id}/mail-domains`; membership
staff only). Record each domain the member really holds, exactly: a
subdomain is its own entry. A domain is one organisation's; a second claim is
refused and names the first, which is a question to settle with both firms.
An organisation with no domain takes no mail (`outside_organisation_domains`
in the audit row) and links no new SSO person
(`email_outside_organisation_domains`). After upgrading to migration
`4c4b33ef59f3` no organisation has a domain, so record them before relying on
the intake or on first SSO sign-ins; people already linked by SSO are
unaffected. Removing a domain leaves its people's accounts in place; the
intake stops filing their mail.

**Who sent it is your mail server's word, not the message's.** A message is
read only if the topmost `Authentication-Results` header carries your
receiving server's authserv-id, a DMARC `pass`, and a `header.from` equal to
the From address's domain, and that address belongs to exactly one active
person (analyst or org admin) at a member organisation that is active. So:

- **Your receiving server must stamp every message it delivers to the
  mailbox**, adding its own `Authentication-Results` above the others, and
  should remove inbound ones that claim its authserv-id (RFC 8601 section 5).
  Only the topmost header is read, so a forged one below yours is ignored;
  but a message that reaches the mailbox unstamped (a second delivery path,
  or DMARC checking switched off) has the sender's own header on top. Before
  turning the intake on, send a test message carrying a forged pass and
  check the stamp above it is your server's.
- **The topmost stamp must carry the DMARC result.** Where several filters
  each add their own header (an SPF policy service, OpenDKIM and OpenDMARC
  in front of Postfix, say), the topmost may be the SPF one, and every
  legitimate message is then refused as `unauthenticated`. Order them so
  the DMARC result is added last, or have the server write one combined
  header, and send a legitimate test message from a member as well as the
  forged one.
- **Members' domains need DMARC published.** A domain with no DMARC policy
  gets `dmarc=none`, which is refused.

**A message that is refused gets no reply.** A reply to a spoofed From would
mail the person being impersonated and tell the spoofer the address is read.
Each message is moved, never deleted: to the accepted folder or the refused
folder. `inbound_emails` and the audit log (`email_intake.accepted` /
`email_intake.refused`) record the outcome and a reason code, never the
subject, the body or a refused message's From:

| Reason | Meaning |
| --- | --- |
| `unauthenticated` | no aligned DMARC pass from your server |
| `unreadable` | the message could not be parsed at all |
| `unreadable_sender` | the From header does not hold exactly one address |
| `unknown_sender` | no single registered person has that address |
| `organisation_inactive` | the person's organisation is suspended, quarantined, pending or offboarded |
| `not_permitted` | the person is deactivated, an auditor, past their end date, or not at a member organisation |
| `rate_limited` | the organisation's hourly allowance (`AIVS_EMAIL_INTAKE_HOURLY_LIMIT`, 10) is used |
| `too_large` | over `AIVS_EMAIL_INTAKE_MAX_MESSAGE_BYTES` (10 MB); not fetched |

What the draft holds: the subject as its title, the plain-text part as its
summary (HTML is never read), and one `.json` attachment as its STIX bundle.
Other attachments are named in the summary and not opened. If the bundle is
refused, the draft keeps the text and says why. A new draft is AMBER+STRICT
and "own estate"; the summary tells the member both are defaults. An email is
not a certificate-bound way in, so the checks made while filing it see what
an SSO session would: nothing above AMBER+STRICT, nothing under embargo.

To turn it on:

1. Create the accepted and refused folders in the mailbox
   (`AIVS/accepted` and `AIVS/refused` unless you set
   `AIVS_EMAIL_INTAKE_ACCEPTED_FOLDER` and `AIVS_EMAIL_INTAKE_REFUSED_FOLDER`).
2. Put the mailbox password in a file only uid 10001 can read:
   `umask 077; printf '%s' "$PASSWORD" > /srv/aivs/secrets/imap-password;
   chown 10001:10001 /srv/aivs/secrets/imap-password`.
3. Set `AIVS_EMAIL_INTAKE_IMAP_HOST`, `AIVS_EMAIL_INTAKE_IMAP_USERNAME`,
   `AIVS_EMAIL_INTAKE_AUTHSERV_ID` (the id your receiving server writes, the
   first word of its `Authentication-Results` headers) and
   `AIVS_EMAIL_INTAKE_IMAP_PASSWORD_PATH` in `deploy/.env`.
4. Start with the override:

```bash
docker compose --env-file deploy/.env -f docker-compose.yml -f docker-compose.email-intake.yml up -d
```

The `email_intake` job reads every `AIVS_EMAIL_INTAKE_INTERVAL_SECONDS` (60)
and shows on the status page like every other job. Nothing is read while
distribution is paused. A message that cannot be parsed is refused as
`unreadable` and moved. One that cannot be stored (a database error) stays
in the inbox, logged by its UID, and is tried again next run without
holding back the others; if one stays there, read it by hand and move it.


### 9.8 Model-assisted checks, in shadow

Off by default (`AIVS_AI_PROVIDER=none`): nothing is sent anywhere and nothing
changes. Set, a model reads each submission the first pass read and its
suggestions appear to ISAC reviewers on the submission's page and API detail,
under "Model check (shadow)". It decides nothing: it never returns,
validates or distributes a submission, and a member never sees it. The
`model_triage` component on the status page shows it running.

**The provider is a subprocessor.** Tell your members which one, as you do
for the mail relay: it sees the content of every submission it reads, up to
its ceiling (threat model R39).

| `AIVS_AI_PROVIDER` | What it is | May receive | Reached |
| --- | --- | --- | --- |
| `private_endpoint` | A model in your own cloud account, behind an OpenAI-compatible gateway (Bedrock through a gateway, for example) | up to AMBER+STRICT | https only |
| `local` | A model on your own hardware (vLLM, llama.cpp, Ollama) | everything, RED included | plain http only at a loopback address; https with the certificate verified anywhere else on your network; never a public address |

Settings: `AIVS_AI_ENDPOINT_URL` (the base URL; `/chat/completions` is
appended), `AIVS_AI_MODEL_ID`, `AIVS_AI_API_KEY_FILE` (a `0600` file, never the
environment outside dev), `AIVS_AI_CA_FILE` for a CA of your own,
`AIVS_AI_TLP_CEILING` to lower the ceiling (it cannot be raised),
`AIVS_AI_TIMEOUT_SECONDS`, and `AIVS_AI_HOURLY_CALLS_PER_ORG` (20): past it, a
member's further submissions that hour are recorded as skipped, not sent.
The URL is checked at startup and every address its name resolves to is
checked again at each connection, so a name re-pointed later is refused then.

What a read can be, in `model_reads` and the `submission.model_read` audit
row (which carries the outcome and a total, never the findings):
`findings`, `no_findings`, `invalid_response` (the reply was not the one
fixed shape; nothing was kept), `error` (no reply), `skipped_above_ceiling`
(the content's most restrictive marking -- a statement or unknown marking
counts as RED -- is above the provider's), and `skipped_rate_limited`. Each
row records the model and prompt template, so if a model release proves bad
you can find every read it made. Nothing is read while distribution is
paused.

**To turn it on in the shipped stack**, write the endpoint's key to a file
(mode `0600`, owned by uid 10001, as the other key files are), set
`AIVS_AI_PROVIDER`, `AIVS_AI_ENDPOINT_URL`, `AIVS_AI_MODEL_ID` and
`AIVS_AI_API_KEY_PATH` (the file's absolute path) in `deploy/.env`, and add
the overlay:

```bash
docker compose --env-file deploy/.env -f docker-compose.yml -f docker-compose.ai.yml up -d
```

Compose refuses to start with any of the four unset, naming it. The overlay
mounts the key read-only and opens nothing: the application's container
already reaches the outside through the `backend` network, as webhook
delivery does.

**A `local` model, from inside a container.** The application's loopback is
its own container, so plain http to loopback reaches nothing here: in the
shipped stack a local model is always reached over https with its
certificate verified. Two ways, both in an override file of your own:

- A model container on the stack's `backend` network, serving https. Use
  its service name in `AIVS_AI_ENDPOINT_URL`.
- A model on the host. Add `extra_hosts: ["model-host:host-gateway"]` to the
  `app` service and use `https://model-host:<port>/v1`. The host-gateway
  address is private, so it is accepted for `local`; a name resolving to a
  public address is refused at each connection.

For a certificate from a CA of your own, mount the CA file read-only into
the `app` service and set `AIVS_AI_CA_FILE` to its path inside the
container. Neither is done by default, because each opens a path the stack
does not otherwise have.

A suggestion is a typed value -- a purl, a `vers:` range, a CWE id or a
remediation category -- pointing at the field it came from, never prose. Use
it as a hint while reviewing; it has not been evaluated against your own
decisions yet, which is why it is shown to you alone.

### 9.9 Sharing documents: codes or a picker

A member shares a document inside its own firm by picking a person or the
whole firm. How it names *another* firm is your choice, set once in
`AIVS_DOCUMENT_RECIPIENT_LOOKUP`:

- `code` (the default): only by that firm's sharing code. Its org admins
  make one on the Documents page, it is shown once, and they hand it
  to whoever they want to be found by. Nobody is shown which firms share a
  circle.
- `picker`: the share form also lists every firm the owner shares an open
  circle membership with, if that firm is active and of a type allowed to
  receive documents. Easier for members, and it shows each member firm's
  document editors who its co-members are (threat model R40). Choose it
  only if your members accept that.

Any other value stops the app at startup. Changing the setting is a restart
and loses nothing: grants already made stand, and codes keep working under
either setting. A firm that has left the circle, or been quarantined,
suspended or offboarded, is neither listed nor accepted, even if someone
posts its id directly.

## 10. Things that will bite you

- **`AIVS_ENVIRONMENT=dev`** is the one value that relaxes
  `validate_production_posture()`, which is what refuses to start with dev
  bypasses enabled. Staging and every other value get the strict posture. It
  defaults to `production`, so this only happens if someone set `dev` on a real
  host and left it.
- **A too-wide `AIVS_TRUSTED_PROXY_CIDRS`** throws away half of the B3 boundary
  control. It should be a `/32`.
- **Migrating without `AIVS_APP_DB_ROLE` and `AIVS_MEMBER_DB_ROLE`** leaves
  the application's logins with no privileges at all, or with whatever an
  older run left. The shipped `migrate` service always sets both; a migration
  run any other way must too. The member role is refused if it is, or can act
  as, the staff role.
- **Pointing `AIVS_MEMBER_DATABASE_URL` at the staff login** (or leaving it
  unset) is refused at startup outside `dev`: the member path would run with
  the staff login's reach.
- **A 500 whose app log line is `database refused a privilege`** means a
  login lacked a grant the request needed, or something wrote to an
  append-only table. The line names the table (`db_table`), the operation
  (`db_operation`) and the request (`request_id`), and never the request's
  content. It is the server's fault, not the caller's: report it with that
  line. Do not grant the privilege by hand; the next migration run puts the
  grants back as `aivs_server.db.grants` lists them.
- **Running the app as a database superuser or as the tables' owner** voids the
  append-only guarantee entirely. The shipped stack connects as
  `AIVS_DB_APP_USER`, the migrate step refuses to grant to a role that is
  either, and outside `dev` `/readyz` answers 503 (`"database": "refused"`, the
  role and reason in the app log) while the app is connected as one, so the
  container reports unhealthy and the proxy does not start. §1.1 checks what is
  actually connected.
- **Distributing to a wider circle than intended** cannot be undone.
- **Deleting a circle** with distributed content will fail on a `RESTRICT`
  foreign key. Deactivate instead. The failure is the schema working correctly.
- **Assuming the embargo sweeper enforces embargoes.** It does not.
  `date_added <= now` does. Knowing this is the difference between a calm
  response and a panicked one when the sweeper stops.
- **Clock skew.** The mTLS validity re-check tolerates ±5 minutes. Beyond that,
  valid certificates start failing and the error the member sees says nothing
  useful. Run NTP. Publication and membership times are read from the
  *database host's* clock, so app replicas that disagree cannot reorder them;
  but a step backwards on the database host itself can stamp new content below
  a cursor a member already holds, and that content is never delivered. Run the
  database host's NTP so that it slews rather than steps (`chronyd` without
  `makestep` after boot).
- **Forgetting that superseded content stays readable.** Superseding does not
  retract; it adds. If content must not be readable, it should never have been
  distributed.
