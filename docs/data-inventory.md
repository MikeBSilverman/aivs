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
| `pii` | Identifies a person. | Volume and backup encryption. Credentials within it are hashed (passwords, Argon2id) or sealed (TOTP seeds, `auth/secretbox.py`). | **Pseudonymised**: identifying fields scrubbed, the row id kept so the audit trail still resolves. *Planned in phase H; today an operator can only be deactivated.* |
| `evidence` | The record of who could see what, when, and what they did. | Volume and backup encryption. `audit_log` and `submission_transitions` are append-only, enforced by trigger. | **Kept.** Deleting it would destroy the "we warned member X" proof (runbook §8). |
| `operational` | Needed to run the service, and worth nothing once the relationship ends. | Volume and backup encryption. Webhook signing keys are sealed. | **Deleted.** *Planned in phase H.* |

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
| `acknowledgments` | evidence | Receipts: retrieved, acknowledged, actioned, per organisation. |
| `audit_log` | evidence | Every security-relevant decision. Append-only. |
| `circle_memberships` | evidence | Membership *intervals*, which decide what an organisation could ever have seen. |
| `organizations` | evidence | The member record: name, type, status, STIX identity, the ISAC directory group its people sign in through, and any legal hold with its reason. Referenced by every receipt. Its contact email is cleared at offboarding; its name is kept, because evidence names who it is about. |
| `client_certificates` | evidence | Certificate fingerprint, the identity of record for every machine request; status and validity. No private key, ever. |
| `operators` | pii | People: email, display name, roles, password hash (absent for a person who signs in only through the ISAC's IdP), sealed TOTP seed, lockout state, and the federated identity (IdP issuer and subject) they sign in as. |
| `portal_sessions` | operational | Signed-in sessions: token hash, source IP, user agent, expiry, and either the bound certificate or, for an SSO session, the IdP issuer and subject, a device-cookie hash and the IdP's `amr` (how the person authenticated). |
| `circles` | operational | Sharing-group definitions and their TLP floors and membership rules. |
| `taxii_collections` | operational | The TAXII view onto each circle. |
| `taxii_status` | operational | TAXII status resources for submissions over TAXII. |
| `webhooks` | operational | A member's notification endpoints and sealed signing keys. |
| `webhook_deliveries` | operational | The outbound notification queue. Contentless payloads. |
| `instance_controls` | operational | The instance-wide pause switch and who pressed it. |
| `submission_milestones` | operational | Which telemetry milestones a submitter has been told about, so each is announced once. |
| `detection_state` | operational | When each detection finding was last raised, so it raises once per window. |
| `org_postures` | operational | A member's own VEX statement per vulnerability: status, justification, impact and action statements, products, detection deployed, when it was validated, and its own evidence note. The statements are the member's prose about its estate. Read and written by that member alone; the ISAC sees counts suppressed below k (SF-70). *Deletion at offboarding is phase H.* |
