# Open decisions

Design notes for choices that are **not yet made**. Each states the current
behaviour, the options with their real costs, and a recommendation. When one is
settled, the reasoning moves into the code and the entry is replaced by a line
in the record at the bottom — a decision note that outlives its decision reads
as though the question is still open.

---

## Searchable / homomorphic encryption over sealed content

**Status: assessed, not adopted.** Recorded here rather than closed because the
condition that would reopen it is specific and nameable, and because it will be
asked again — the pitch is a good one and the vendors are credible.

**The question.** Commercial data-in-use encryption (Vaultree and comparable
products) can run queries, including wildcard matches, against data that is
never decrypted. Applying it here would mean either querying the sealed payload
server-side, or sealing the triage metadata that section 2 of
`docs/encryption-design.md` deliberately leaves in plaintext.

**Current behaviour.** Content is server-readable, protected at rest by volume
and backup encryption; sealing it to recipients (BYOK) is an option, designed
and deferred (`docs/encryption-design.md`). Under that design the payload would
be sealed to recipients and routing and triage metadata left in plaintext,
which is what the server enforces access on, what members triage on, and what
lets an unaware TIP still consume the object. The arguments below were made
against the sealed design and hold more strongly against the default: a server
that can read content has no need to query what it cannot read.

**Why it is not adopted:**

- **No party in the design needs it.** Encrypted search answers "someone who
  must not read the data still has to query it". The hosting ISAC is a recipient
  and can decrypt; members hold plaintext in their own TIP; the infrastructure
  holds no key and runs no query — under BYOK its *lack* of that capability is
  the point.
- **The corpus is small enough to search locally, and will stay that way.**
  Pre-CVE findings arrive in the hundreds to low thousands per year. Anyone
  entitled to read them can hold all of them. Encrypted search exists because
  decrypt-then-search does not scale; here it does.
- **It trades away the thing that gets the design through review.** Section 4 is
  boring on purpose: every primitive is one a bank's cryptographer already
  recognises. A proprietary scheme moves the burden of defending a novel
  construction — and its leakage profile, against a well-developed
  leakage-abuse literature — onto us, in every member's third-party risk review,
  permanently.
- **It contradicts ISAC-in-a-box.** A licensed dependency in the storage layer
  means an ISAC cannot self-host without buying it, the Apache-2.0 release is
  hollow, and an acquirer inherits a third-party crypto licence in the core. We
  would also be taking a vendor-continuity risk we would never accept from a
  member: if the vendor goes, the ciphertext's only reader goes with it.
- **Sealing the triage metadata breaks more than it protects.** It would end
  graceful degradation for unaware consumers, TAXII `match[]` filtering, and
  keyset paging on `(date_added, seq)`.

**What would reopen it:** a named prospective ISAC stating, in writing, that
they will not proceed unless the host can query content it cannot read. That
makes it a funded feature with a customer attached rather than a speculative
dependency, and it is the only version of this worth building.

**Adjacent problem where the technology class does fit, later:** cross-ISAC
correlation — "is another ISAC seeing this same finding?" — with neither side
disclosing its corpus. The well-matched primitive there is private set
intersection, which has standard constructions and published analysis, not
general encrypted search. Related to the GOLD EAGLE duplicate question in
`docs/gold-eagle-integration.md`. Not v1.

Do not reach for this for secrets at rest. `totp_secret_encrypted` and
`hmac_secret_encrypted` are columns nobody searches; they need envelope
encryption against a KMS or HSM, and putting a searchable-encryption product in
the authentication path would be paying for a capability that goes unused.

---

## Decided

| Decision | Where the reasoning now lives |
|---|---|
| **Circle admission is the hosting ISAC's alone.** `can_administer_circle` returns `is_system_admin(ctx)`. A circle carries other members' embargoed intelligence and membership is backed by an agreement the ISAC holds; a cleared participant does not read in the next one. `CircleRole.CIRCLE_ADMIN` is retained but confers only what `contributor` does. | `auth/policy.can_administer_circle`, `aivs_schemas.enums.CircleRole`, `docs/authz-model.md` |
| **Bound visibility by membership start.** Joining a circle grants participation, never the back catalogue. `joined_at` is its own column and is settable, so a membership restored after an administrative mistake keeps the history it legitimately had. | `auth/policy.visible_content_clause`, `CLAUDE.md` §5, migration `d3f18a7c5b02` |
| **Bulk membership.** `POST /circles/{id}/members` takes identifiers and/or slugs; unknown names fail the whole batch, already-members are skipped so re-applying a roster is idempotent. | `services/circles.py` |
| **Rule-based groups.** `Circle.auto_member_org_types` materialises into ordinary membership rows, marked `managed_by_rule` so reconciliation only ever touches what it owns. Reconciled on circle creation, activation and suspension. | `services/circles.py`, migration `e5a92c11f7d4` |
| **Webhooks: contentless, and wired up.** The payload names the submission and collection and says "poll to collect". Fires when content becomes *visible* — distribution without an embargo, and embargo release — never at distribution under embargo. Queued inside the transaction that made the content visible, drained by a separate dispatcher with bounded retries. | `notify/events.py`, `notify/dispatcher.py`, migration `f7b3d40e9a15` |
| **Admin UI.** Organisations and circles are administered from the portal, through the same policy predicates and service functions as the API. | `portal/admin_routes.py` |
| **SBOM.** Reproducible CycloneDX 1.6 from the locked runtime environment, plus a syft scan of the image for the OS layer. | `scripts/generate-sbom.sh`, `CLAUDE.md` §2 |
| **Two IdP tenants, both operated by the ISAC — one for member users, one for staff — with the issuer deciding what authority a session can reach.** Federating outward to each member firm's own IdP was rejected: a lapsed member must lose access on the ISAC's decision, not on that member's own offboarding. OIDC first, SAML when a member requires it; passkeys replace password+TOTP for local accounts and back break-glass staff access. Design only — unbuilt. **Superseded in part for member users** (below): members will sign in over ordinary TLS, not through a certificate-bound session. | `docs/identity-federation.md` |
| **Members open sealed content through a loopback decrypting sidecar, not a forked TAXII client.** No client anywhere has to change; the firm's existing TIP points at `aivs proxy`. `TLP:RED` is deliberately not a collector path. Design only — unbuilt, and deferred with BYOK itself (below). | `docs/encryption-design.md` §10 |
| **The server reads content; BYOK is optional and deferred.** Deduplication, enrichment, "what's available", telemetry back to submitters and sector analytics all need the server to read what it holds, and they are worth more to an ISAC than a host that cannot. Content at rest is protected by the volume and backup encryption the deployment requires. Sealing content to its recipients stays designed — with a hybrid post-quantum key wrap — for an ISAC that wants it for some content; it is not scheduled. | `docs/encryption-design.md` (status), `docs/data-inventory.md` |
| **One ISAC per instance now; several ISACs later by federation between instances, never a tenant column.** An ISAC's isolation is a separate database, CA and host; a shared database would make it depend on every query being right about every other tenant. No `instance_id` setting exists until something reads one. | `docs/deployment-topology.md` |
| **AI assistance uses a controlled model only.** A model running locally, or a private endpoint the ISAC controls (for example Amazon Bedrock in the ISAC's own account), optionally reached through a gateway such as SurePath that the ISAC operates or contracts. **Never a public model API**: a prompt carrying embargoed content to a third party's shared service is a disclosure, whatever that service's retention terms say. Nothing is built: the setting that selects a provider (`ai_provider`: none, local or private endpoint) lands in the commit that adds the first assist, with its test, not before (CLAUDE.md §5: a setting with no caller is a claim the system does not keep). | This record, until the first assist exists |
| **Give-to-get is decided against.** Tiering access to intelligence on how much a member contributes would be an exclusion among competitors — a group-boycott exposure an ISAC's counsel will not accept — it would cut off the smaller members who need the pool most, and it breaks the equal treatment the membership agreement promises. Contribution may unlock things that are not intelligence: working-group seats, call slots, a seat on RFI triage. Participation is encouraged by lowering its cost and showing submitters what their contributions did, not by withholding. | This record; `docs/sharing-agreement-outline.md` |
| **Member users sign in with the ISAC's SSO and a second factor over ordinary TLS; certificates stay for machines, ISAC staff and `TLP:RED`.** A client certificate behind an overlay network is within reach of a few dozen member firms with a PKI team, not of the rest. Sessions from that listener are capped below `TLP:RED`, and embargoed pre-CVE content stays on the certificate-bound path. Planned, unbuilt. | `docs/identity-federation.md` (status) |
