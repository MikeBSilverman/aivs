# Data inventory

Every table the application stores, the class of data it holds, and what that
class means for protection and retention. A member's third-party-risk review
asks for this; it is also the input to offboarding. A test
(`tests/unit/test_data_inventory.py`) fails when a mapped table is missing from
the table below, or is listed under a class not defined here. A new table
therefore cannot land unclassified.

## Classes

"Volume and backup encryption" below is a deployment requirement
(`deployment-topology.md`), not something the application does or can verify.
What the application adds is named per class.

| Class | Means | At rest today | When a member leaves |
| --- | --- | --- | --- |
| `content` | Intelligence: what was shared, and the free text around it. | Volume and backup encryption only. The application reads it, because analytics depend on that (BYOK is an option, deferred; `encryption-design.md`). | **Kept.** Other members received it, and the record of what was shared is the evidence. |
| `pii` | Identifies a person. | Volume and backup encryption. Credentials within it are hashed (passwords, Argon2id) or sealed (TOTP seeds, `auth/secretbox.py`). | **Pseudonymised**: identifying fields scrubbed, the row id kept so the audit trail still resolves. When its organisation is offboarded (`services/offboarding.py`, SF-72). A single person who leaves an organisation that stays is only deactivated today. |
| `evidence` | The record of who could see what, when, and what they did. | Volume and backup encryption. `audit_log`, `submission_transitions`, `audit_stream_modes` and the two `attribution` tables are append-only, enforced by trigger. | **Kept.** Deleting it would destroy the "we warned member X" proof (runbook §8). |
| `operational` | Needed to run the service, and worth nothing once the relationship ends. | Volume and backup encryption. Webhook signing keys are sealed. | **Deleted** when the organisation is offboarded (`services/offboarding.py`, SF-72), except postures under a legal hold, which go when the hold is lifted. |

Some evidence rows hold personal data incidentally. `audit_log` records the
source IP address of each request and the operator id behind each human
action. The class names the row's purpose, which is what decides its
retention. The incidental personal data is why pseudonymisation keeps ids
rather than deleting rows.

## Tables

| Table | Class | Holds |
| --- | --- | --- |
| `stix_objects` | content | Every STIX object submitted, as received (`raw`) plus indexed fields. |
| `submissions` | content | A member's filing: title, summary, TLP, scope, workflow state. |
| `embargoes` | content | Release policy and time, and free-text coordination notes. |
| `distributions` | evidence | Which object became visible to which circle, and from when (`date_added`). |
| `submission_transitions` | evidence | Every workflow state change, by whom and when. Append-only. |
| `attribution.submitters` | evidence | Who filed each submission (Phase P): the organisation, the person who filed it in its name, and for a proxy filing the ISAC analyst and the SHA-256 of the member's consent. ISAC-only and treated as TLP:RED; held in its own schema so a database role can be refused all of it, and read only through `services/attribution.py`. Append-only, enforced by trigger: re-attributing a filing after the fact is what must not be possible. Kept under a legal hold like any evidence. |
| `attribution.object_owners` | evidence | The owner token of one organisation's versions of one object id (Phase P): the mapping back from `stix_objects.owner_token`, which names nobody, to the organisation. A random token per organisation and id, so tokens cannot be matched across ids. Append-only, enforced by trigger. |
| `submission_triage` | evidence | What the first pass found each time a submission was handed to the ISAC, and whether it returned it (Phase O): finding codes, field paths and the member-facing wording, never anything from another member. The record of what the ISAC told a member and of every automated return. |
| `acknowledgments` | evidence | Receipts: retrieved, acknowledged, actioned, per organisation. |
| `audit_log` | evidence | Every security-relevant decision. Append-only. |
| `audit_stream_modes` | evidence | Each choice of what the audit stream serves of its own reading, and who made it. Append-only: the stream judges each read by the mode in force when it was written. |
| `circle_memberships` | evidence | Membership *intervals*, which decide what an organisation could ever have seen. |
| `organizations` | evidence | The member record: name, type, status, STIX identity, the ISAC directory group its people sign in through, and any legal hold with its reason. Referenced by every receipt. Its contact email is cleared at offboarding; its name is kept, because evidence names who it is about. It also holds the organisation's notification cadence and digest mailbox (a routing address the member chose); the mailbox is cleared at offboarding, like the contact email. |
| `client_certificates` | evidence | Certificate fingerprint, the identity of record for every machine request; status and validity. No private key, ever. |
| `operators` | pii | People: email, display name, roles, password hash (absent for a person who signs in only through the ISAC's IdP), sealed TOTP seed, lockout state, and the federated identity (IdP issuer and subject) they sign in as, the depth their vulnerability pages open at (a rendering preference, which grants nothing), and, for an auditor, the date its access ends. |
| `portal_sessions` | operational | Signed-in sessions: token hash, source IP, user agent, expiry, and either the bound certificate or, for an SSO session, the IdP issuer and subject, a device-cookie hash and the IdP's `amr` (how the person authenticated). |
| `circles` | operational | Sharing-group definitions and their TLP floors and membership rules, and whether a circle is a sandbox (its content counts in no reported figure). |
| `taxii_collections` | operational | The TAXII view onto each circle. |
| `taxii_status` | operational | TAXII status resources for submissions over TAXII. |
| `webhooks` | operational | A member's notification endpoints and sealed signing keys. |
| `webhook_deliveries` | operational | The outbound notification queue. Contentless payloads, plus affected product names below RED, and in a digest the titles of CLEAR and GREEN items. |
| `sector_events` | operational | Which of the ISAC's canonical vulnerabilities is pinned as a sector event, by whom and when, and when it closed. |
| `pending_notices` | operational | Visibility notices held for an organisation's next hourly or daily digest, one per subject. Deleted when the digest is queued. |
| `email_deliveries` | operational | The digest email queue: the member's digest mailbox, and the contentless digest text. |
| `instance_controls` | operational | The instance-wide pause switch and who pressed it. |
| `submission_milestones` | operational | Which telemetry milestones a submitter has been told about, so each is announced once. |
| `count_snapshots` | operational | The k-anonymous counts last published per vulnerability (members' posture statuses) and per distributed submission (who could retrieve it, and the receipt types each holds), kept as each counted organisation's contribution so the next publication can be compared firm by firm. Never served as such; readers get only suppressed counts. An offboarded organisation is removed from every one. |
| `detection_state` | operational | When each detection finding was last raised, so it raises once per window. Keyed by an id (organisation, operator, webhook, component) or a source address, never content. **Kept** when a member is offboarded, the one operational exception: it is the detector's memory, and deleting it would raise the offboarding's own alert again. Each row is overwritten or outlives its window harmlessly. |
| `org_postures` | operational | A member's own VEX statement per vulnerability: status, justification, impact and action statements, products, detection deployed, when it was validated, and its own evidence note. The statements are the member's prose about its estate. Read and written by that member alone; the ISAC sees counts suppressed below k (SF-70). *Deletion at offboarding is phase H.* |
