# AIVS operator runbook

For ISAC staff running an AIVS instance. Assumes you have read
[`deployment-topology.md`](deployment-topology.md) and the instance is stood up.

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

```bash
python -m aivs_server.config
# → configuration OK for environment=production
```

Then verify that the append-only triggers actually applied. This is not
ceremonial: the grants in migration `c185fd428721` only take effect when
`AIVS_APP_DB_ROLE` was set at migration time, and a silent omission voids the
evidentiary guarantee the whole product rests on.

```bash
psql -c "SELECT tgname FROM pg_trigger
         WHERE tgrelid = 'audit_log'::regclass AND NOT tgisinternal;"
# → audit_log_deny_update, audit_log_deny_delete, audit_log_deny_truncate

psql -U aivs_app -c "DELETE FROM audit_log WHERE id = 1;"
# → ERROR: table audit_log is append-only; DELETE is not permitted
```

Repeat for `submission_transitions`. Confirm also that `aivs_app` is not a
superuser and does not own these tables:

```bash
psql -c "SELECT rolsuper FROM pg_roles WHERE rolname = 'aivs_app';"   # → f
psql -c "SELECT tableowner FROM pg_tables WHERE tablename = 'audit_log';"  # ≠ aivs_app
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
of failure for distributing time-sensitive warnings. (The bootstrap command that
creates the first operator is the next change; this section will name it.)

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

Default to `member`. Upgrade to `contributor` when the firm is ready to submit
and understands the `discovery_scope` attestation.

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
disclosure regardless of the AI framing, and AIVS is not the channel for it.

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

### 4.5 Withdrawing

`withdrawn` is reachable from `draft`, `submitted`, and `validated` — never from
`distributed`. Use it when a submission should not have been made or was
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
| `AIVS_SECRET_ENCRYPTION_KEY` | Secret manager or offline media, **not beside the database backup** | On rotation |

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
   `python -m aivs_server.rewrap_secrets` reports `unopenable=0`. A database
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

### 7.2 Suspected certificate compromise

1. Revoke in the **database**: `client_certificates.status = revoked`, with
   `revoked_at` and `revoked_reason` set (a check constraint requires the
   timestamp). This is what stops access, and it is effective on the member's
   **next request** — no CRL propagation delay. Then record it in the CA:
   `deploy/ca/revoke.sh --org-slug meridian-global --reason keyCompromise`.
   The CRL matters for relying parties outside AIVS; the database flip is what
   matters here. Do the database flip first.
2. Query the audit log for everything that fingerprint did. `actor_id` on an
   mTLS-authenticated row **is** the certificate fingerprint.
3. Determine what was retrieved: `acknowledgments` filtered by that org.
4. Consider `organizations.status = suspended` while investigating — it takes
   effect on their next request and stops everything, not just that certificate.
5. Issue a replacement once the member has generated a fresh key.

### 7.3 Rotating the secret-encryption key, or changing its algorithm

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

1. Generate the new key: `openssl rand -base64 32`.
2. Set `AIVS_SECRET_ENCRYPTION_KEY` to it, and
   `AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS` to the value it replaces. Restart.
   Everything continues to work at this point: existing rows open under the
   previous key, new writes seal under the new one.
3. Re-seal what is still on the old key:

   ```bash
   python -m aivs_server.rewrap_secrets            # report
   python -m aivs_server.rewrap_secrets --apply    # re-seal
   ```

4. Re-run the report. **Only when it shows `stale=0` and `unopenable=0`** remove
   `AIVS_SECRET_ENCRYPTION_KEY_PREVIOUS` and restart.

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

### 7.4 Instance compromise

Assume every piece of content is disclosed. That is the honest starting
assumption for a database holding embargoed, unpatched vulnerabilities affecting
GSIBs.

1. Isolate: stop the overlay or the allowlist. Members will notice; that is fine.
2. Preserve: snapshot the database and the audit log before touching anything.
3. Verify audit integrity against the off-box stream. If the triggers were
   dropped, the on-box log is untrustworthy from that point forward and the
   off-box copy is your only record.
4. Notify every member and every submitter with content in the instance.
5. Assume the issuing CA is compromised if the host held its key. Revoke the
   intermediate from the offline root, stand up a new one, re-issue member
   certificates. This is why the root is offline and why the hierarchy has two
   levels.

### 7.5 Audit write failures

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

---

## 10. Things that will bite you

- **`AIVS_ENVIRONMENT` not set to `production`** disables
  `validate_production_posture()`, which is what refuses to start with dev
  bypasses enabled. It defaults to `production`, so this only happens if someone
  set it to something else and left it.
- **A too-wide `AIVS_TRUSTED_PROXY_CIDRS`** throws away half of the B3 boundary
  control. It should be a `/32`.
- **Migrating without `AIVS_APP_DB_ROLE`** silently skips the grant half of the
  append-only enforcement. The triggers still apply; the grants do not.
- **Running the app as a database superuser** voids the append-only guarantee
  entirely, and nothing will tell you.
- **Distributing to a wider circle than intended** cannot be undone.
- **Deleting a circle** with distributed content will fail on a `RESTRICT`
  foreign key. Deactivate instead. The failure is the schema working correctly.
- **Assuming the embargo sweeper enforces embargoes.** It does not.
  `date_added <= now` does. Knowing this is the difference between a calm
  response and a panicked one when the sweeper stops.
- **Clock skew.** The mTLS validity re-check tolerates ±5 minutes. Beyond that,
  valid certificates start failing and the error the member sees says nothing
  useful. Run NTP.
- **Forgetting that superseded content stays readable.** Superseding does not
  retract; it adds. If content must not be readable, it should never have been
  distributed.
