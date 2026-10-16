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
| `evidence` | The record of who could see what, when, and what they did. | Volume and backup encryption. `audit_log`, `submission_transitions`, `audit_stream_modes` and `attribution.submitters` are append-only, enforced by trigger. | **Kept.** Deleting it would destroy the "we warned member X" proof (runbook §8). |
| `operational` | Needed to run the service, and worth nothing once the relationship ends. | Volume and backup encryption. Webhook signing keys are sealed. | **Deleted** when the organisation is offboarded (`services/offboarding.py`, SF-72), except postures under a legal hold, which go when the hold is lifted. |

Some evidence rows hold personal data incidentally. `audit_log` records the
source IP address of each request and the operator id behind each human
action. The class names the row's purpose, which is what decides its
retention. The incidental personal data is why pseudonymisation keeps ids
rather than deleting rows.

## Tables

| Table | Class | Holds |
| --- | --- | --- |
| `stix_objects` | content | Every STIX object submitted, as received (`raw`) plus indexed fields, and `owner_token`: which owner the version counts as, `'isac'` or an HMAC of the owner and the object id under the attribution key (SF-90). It names nobody and matches across no two ids. |
| `submissions` | content | A member's filing: title, summary, TLP, scope, workflow state. And `owner_tag`, an HMAC of the filer and the submission id under the attribution key (below; SF-90): how the member path asks "is this mine?" without reading `attribution`. It names nobody, matches across no two submissions, and cannot be computed or reversed without the key. |
| `embargoes` | content | Release policy and time, and free-text coordination notes. |
| `distributions` | evidence | Which object became visible to which circle, and from when (`date_added`). |
| `submission_transitions` | evidence | Every workflow state change, by whom and when. Append-only. |
| `attribution.submitters` | evidence | Who filed each submission (Phase P): the organisation, the person who filed it in its name, and for a proxy filing the ISAC analyst and the SHA-256 of the member's consent. ISAC-only and treated as TLP:RED; held in its own schema so a database role can be refused all of it, and read only through `services/attribution.py`. Append-only, enforced by trigger: re-attributing a filing after the fact is what must not be possible. Kept under a legal hold like any evidence. |
| `submission_triage` | evidence | What the first pass found each time a submission was handed to the ISAC, and whether it returned it (Phase O): finding codes, field paths and the member-facing wording, never anything from another member. The record of what the ISAC told a member and of every automated return. |
| `model_reads` | evidence | What a model said about a submission in shadow (Phase O slice 4, SF-96): the provider, model, prompt template and content marking, the outcome (typed findings, none, a failed reply, an error, or skipped as above the provider's ceiling or over the allowance), and typed suggested values only -- never prose. Shown to ISAC reviewers only; holds no organisation, so it links a submission to a reading, never to its filer. Append-only, enforced by trigger: it is how a bad model release is found and its findings set aside. |
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
| `inbound_emails` | evidence | One row per message read from the email-to-draft mailbox: its SHA-256, when, accepted or refused with a reason code, and (once the sender is known) the organisation and operator. No subject, body or address: the message stays in the ISAC's mailbox, moved to the accepted or refused folder, and an accepted one's text is in the draft it made. Evidence, not operational: it is the record of what arrived and how it was decided, as the mailbox the message stays in is, so it is kept when a member leaves; the operator it names is pseudonymised with the rest of the member's people. |
| `instance_controls` | operational | The instance-wide pause switch and who pressed it. |
| `submission_milestones` | operational | Which telemetry milestones a submitter has been told about, so each is announced once. |
| `count_snapshots` | operational | The k-anonymous counts last published per vulnerability (members' posture statuses) and per distributed submission (who could retrieve it, and the receipt types each holds), kept as each counted organisation's contribution so the next publication can be compared firm by firm. Never served as such; readers get only suppressed counts. An offboarded organisation is removed from every one. |
| `detection_state` | operational | When each detection finding was last raised, so it raises once per window. Keyed by an id (organisation, operator, webhook, component) or a source address, never content. **Kept** when a member is offboarded, the one operational exception: it is the detector's memory, and deleting it would raise the offboarding's own alert again. Each row is overwritten or outlives its window harmlessly. |
| `org_postures` | operational | A member's own VEX statement per vulnerability: status, justification, impact and action statements, products, detection deployed, when it was validated, and its own evidence note. The statements are the member's prose about its estate. Read and written by that member alone; the ISAC sees counts suppressed below k (SF-70). Deleted when the member is offboarded, unless a legal hold keeps it (`services/offboarding.py`). |

## Keys held outside the database

Not stored by the application, and listed because what they protect is.

| Key | Protects | Held | When lost |
| --- | --- | --- | --- |
| Key-encryption key (`AIVS_SECRET_ENCRYPTION_KEY_FILE`) | The sealed TOTP seeds and webhook signing keys. | A `0600` file on the app host, backed up apart from the database. | Every operator re-enrols their second factor; every member re-registers its webhook. |
| Attribution key (`AIVS_ATTRIBUTION_KEY_FILE`) | Who filed what, against a reader with SQL alone: the owner tags and owner tokens are HMACs under it (SF-90). Held together with a database dump, it recovers the whole mapping, anonymous filers included. | A `0600` file on the app host and the migrate step, a different key from the one above, kept apart from database backups. | Nothing: a rekey under a new key recomputes every value from the mapping (runbook §7.4a). |
