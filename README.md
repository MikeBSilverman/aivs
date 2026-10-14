# AIVS — the ISAC's vulnerability desk

**One page per vulnerability: what it is, whether you are affected, what to do,
how to verify — and proof that you were told.**

AIVS is the platform an ISAC runs to manage intelligence across the whole life
of a vulnerability — from a pre-CVE, AI-discovered finding under embargo,
through CVE issuance and enrichment, to the detection, mitigation, control and
verification work defenders do — with the ISAC, its members and vendors
creating, cultivating, reviewing and distributing it together.

That is the goal. What exists today is the front of it: **pre-CVE early
warning**, with the trust machinery every later stage reuses — circles,
server-enforced embargoes, anonymity, receipts, and a human editorial
checkpoint. The [status table](#status) says what is built, what is designed,
and what is planned. This README describes a feature as present only when it is
in the code.

It is deployed **by an ISAC**, for its own members, over standard TAXII 2.1 and
STIX 2.1. Apache-2.0 licensed.

---

## Why a vulnerability desk

A member firm does not need another feed. For each vulnerability that matters
to its sector it needs one place that answers the questions its own teams ask —
is this real, are we exposed, what do we do, how do we know it worked — and,
afterwards, a record that the warning arrived. Today those answers are spread
across vendor advisories, NVD, KEV, mailing lists and phone calls, and the
record mostly does not exist.

The ISAC is the right author of that page: it holds the trust relationships,
the agreements and the sector's view. Members and vendors are the right
contributors: they hold the detections, workarounds and sightings. The product
is the page; everything else is who may write to it, who may read it, and the
receipt.

---

## The first lane: pre-CVE early warning

Frontier AI models have made vulnerability discovery cheap. Firms running model-
driven analysis over their own code and their own estates are finding more, and
finding it faster — including multi-step exploit chains that no single scanner
would have flagged. A separate effort, GOLD EAGLE, helps firms convert that
output into CVEs at scale.

Between the moment a firm knows about a vulnerability and the moment a CVE is
published, there is a window — days to months — in which the finding is real,
the risk is live, and there is no structured way to warn peers who are exposed
to the same thing. Today that warning travels by phone call and mailing list, if
it travels at all.

Financial-sector ISACs have not addressed AI-driven vulnerability intelligence.
The AI-system category in particular — prompt injection, model supply chain,
agentic tooling — has no disclosure norms at all, and it is precisely where large
firms are now most exposed and least served. No one else covers this lane, which
is why it stays the front of the lifecycle rather than being replaced by it.

---

## Working on AIVS

Read [CLAUDE.md](CLAUDE.md) before contributing. It carries the verification
gates, the test-database isolation rule, and the correctness rules that exist
because the opposite was written first — each one with the failure that
produced it, so the reasoning survives the next refactor.

## What AIVS does today

A single-tenant server an ISAC runs for its members:

- **TAXII 2.1** content delivery, so a member's existing TIP connects with a
  certificate and a collection id. No bespoke client required.
- **STIX 2.1** content with one property extension for the pre-CVE facts STIX has
  no place for: how an AI system found it, what it affects, its CVSS v4.0
  assessment, its embargo, and where it sits relative to CVE issuance.
- **Sharing circles** — trust tiers such as Section 9 or GSIB, each projected as
  a TAXII collection, each with a TLP 2.0 floor.
- **Server-enforced embargoes.** Content under embargo is not visible to members
  until its release instant. Not a flag in the payload — an enforced condition on
  every read.
- **Receipts.** The server records who retrieved what and when. This is the
  evidentiary answer to "prove we warned member X".
- **Mutual TLS** over a WireGuard overlay or a strict IP allowlist, with identity
  keyed on certificate fingerprints and revocation effective on the next request.
- **An append-only audit trail**, enforced by database triggers rather than by
  application convention.

### What AIVS accepts, and what it does not

Today it is **not a channel for undisclosed vulnerabilities in uninvolved third
parties' software.** The server accepts three scopes and refuses every other value:

| Scope | Meaning |
| --- | --- |
| `own_product` | A vulnerability in a product the submitter builds and ships |
| `own_estate` | A vulnerability in the submitter's own deployed environment |
| `ai_system` | An AI-system vulnerability generally — prompt injection, model supply chain, agentic tooling |

This is a legal-risk control, not a scoping preference. Brokering someone else's
unpatched vulnerability without their consent creates coordinated-disclosure and
tortious-interference exposure for the submitter and the ISAC alike. The
restriction is enforced structurally by the `discovery_scope` field **and** by the
workflow: a member firm can upload content but can never distribute it. Only the
hosting ISAC moves a submission `submitted → validated → distributed`. That human
checkpoint is a design feature.

**Planned: the split by disclosure.** The wider goal needs contributions about
other parties' software, and the line that keeps them lawful is disclosure, not
ownership. Once a vulnerability is public, any member or vendor may contribute
defence intelligence about it — a detection, a workaround, a sighting. Before
disclosure the restriction above stays, with one addition,
`coordinated_disclosure`: the vendor is a party to the case, recorded by the
ISAC, or a GOLD EAGLE/VINCE identifier is attached. Until that is built the
server accepts only the three scopes in the table; the two new values exist in
the database type so the rule that admits them can ship without a type change,
and every surface refuses them exactly as it refuses a value it has never
heard of.

---

## ISAC-in-a-box

AIVS is built to be **deployed by an ISAC**, or hosted by Aequora as a dedicated
single-tenant instance on an ISAC's behalf. It is not a competing sharing
community.

That positioning is deliberate. ISACs already have the trust relationships, the
membership agreements, the sector standing, and the legal frameworks. What they
have not had is the software for this particular problem. AIVS gives them the
software and leaves them the agency: their instance, their circles, their
editorial control over what reaches members, their members' data.

| | Self-hosted | Aequora-managed |
| --- | --- | --- |
| Runs where | The ISAC's infrastructure | Aequora, dedicated single-tenant |
| CA root | The ISAC, offline | **The ISAC, offline** |
| Who validates and distributes submissions | ISAC staff | **ISAC staff** |
| Backups, upgrades, monitoring | The ISAC | Aequora |
| Source | Apache-2.0 | Apache-2.0, identical |

The source is Apache-2.0 in both cases. Revenue comes from managed hosting,
support, and integration — not from the licence, and not from access to the data.
An ISAC that wants to run this entirely on its own can, and that option existing
is the point.

---

## Repository layout

```
packages/
  aivs-schemas/     shared contract: enums, state machine, TLP 2.0, STIX extension
  aivs-server/      TAXII 2.1 + native API + analyst portal + authz + audit
  aivs-client/      reference SDK and the `aivs` CLI for member firms
deploy/
  nginx/            mTLS-terminating reverse proxy; identity headers live in
                    snippets/aivs-identity-headers.conf and nowhere else
  ca/               two-tier private CA: init, issue, revoke, server certs
  wireguard/        overlay network configuration
docs/               the documentation set below
scripts/            operational helpers
demo/               sample content and a walkthrough
```

Three packages in one `uv` workspace. `aivs-schemas` is installed by member firms
as well as by the server, which is why it carries almost no dependencies — every
one added there lands in a GSIB's software bill of materials.

| Package | Key modules |
| --- | --- |
| `aivs-schemas` | `enums.py` (vocabulary + submission state machine), `tlp.py` (TLP 2.0 markings), `extension/` (the pre-CVE property extension, its JSON Schema, and typed builders) |
| `aivs-server` | `auth/policy.py` (the single authorization decision point), `auth/mtls.py` (certificate identity), `db/models.py` (the data model), `audit/log.py` (append-only writer), `taxii/`, `api/`, `portal/`, `services/`, `notify/` |
| `aivs-client` | `aivs enroll`, `aivs poll`, `aivs submit`, `aivs ack` |

---

## Quickstart

Requires Python 3.12+, [uv](https://docs.astral.sh/uv/), PostgreSQL 16+ with
`pgcrypto`, and Docker for the full stack.

```bash
git clone <repository-url> && cd AIVulnSharing
uv sync

# Create the two-tier CA (once, ideally on an air-gapped machine), then move
# the root key to offline media.
deploy/ca/init-ca.sh --org "Your ISAC" \
  --root-cn "Your ISAC AIVS Root CA" \
  --intermediate-cn "Your ISAC AIVS Issuing CA"

# Configure. Every default is the safe value; AIVS_ENVIRONMENT defaults to
# "production", so a forgotten setting fails closed rather than open.
$EDITOR .env
uv run python -m aivs_server.config     # → configuration OK for environment=...

# Schema, migrating as the database owner. Naming the app's role (a login that
# is not a superuser and owns nothing) grants it what the app needs and refuses
# one that could drop the append-only triggers. The app connects as that role.
AIVS_APP_DB_ROLE=aivs_app \
  uv run alembic -c packages/aivs-server/alembic.ini upgrade head

# Verify the append-only enforcement actually took, as the app's role. Do not
# skip this: the evidentiary guarantee the product rests on can silently fail.
psql -U aivs_app -c "DELETE FROM audit_log WHERE id = 1;"
#   expected: ERROR: permission denied for table audit_log

# Run, application only, behind your own proxy:
uv run aivs-server
# or the whole stack (nginx + app + postgres), which does all of the above in
# containers: deploy/README.md section 3.
```

Then follow [`docs/operator-runbook.md`](docs/operator-runbook.md) §1 to create
the ISAC's own organization, the first system administrator, and the initial
circles.

### As a member firm

```console
$ pip install aivs-client
$ aivs enroll --org meridian-global            # key + CSR generated locally
$ aivs poll --collection section9 --since auto # NDJSON STIX on stdout
```

The private key never leaves your machine; only the CSR is sent to the ISAC.
Start at [`docs/onboarding.md`](docs/onboarding.md).

### Tests

```bash
uv run pytest                        # everything
uv run pytest -m authz               # the deny-by-default authorization proof
uv run pytest -m conformance         # TAXII 2.1 / STIX 2.1 conformance
uv run pytest -m "not db and not e2e"   # no database required
uv run ruff check . && uv run mypy . && uv run bandit -c pyproject.toml -r packages
```

---

## Documentation

| Document | For |
| --- | --- |
| [Architecture](docs/architecture.md) | How the system fits together, the request lifecycle, and why `distributions` is materialised rather than computed |
| [Threat model](docs/threat-model.md) | STRIDE per trust boundary, with an honest residual-risk register |
| [Authorization model](docs/authz-model.md) | Organizations, circles, roles, and the full subject × resource × action matrix |
| [STIX extension](docs/stix-extension.md) | Every field, exploit chains, TLP 2.0, versioning policy, worked JSON |
| [TAXII mapping](docs/taxii-mapping.md) | Media types, endpoints, filters, headers, response shapes |
| [Deployment topology](docs/deployment-topology.md) | Both hosting modes, network layers, PKI and certificate lifecycle |
| [Onboarding](docs/onboarding.md) | Member-firm-facing: enrolment through first successful poll |
| [Operator runbook](docs/operator-runbook.md) | ISAC staff: first run, review and distribution, embargoes, backup, incidents |
| [Identity federation](docs/identity-federation.md) | Two ISAC-operated IdP tenants, OIDC, JIT provisioning, passkeys — design, unbuilt |
| [Sharing agreement outline](docs/sharing-agreement-outline.md) | A non-lawyer's skeleton for counsel to draft from |
| [Encryption design](docs/encryption-design.md) | Content sealed to its recipients (BYOK) — optional and deferred; design, unbuilt |
| [Post-quantum readiness](docs/pqc-readiness.md) | Every cryptographic use, whether it is quantum-safe, and what changes when |
| [Data inventory](docs/data-inventory.md) | Every table's data class, what protects it at rest, and what happens when a member leaves |
| [GOLD EAGLE integration](docs/gold-eagle-integration.md) | CVE handoff and return path — design, not scheduled |
| [Open decisions](docs/open-decisions.md) | Choices not yet made, and the record of those that were |
| [Commercial terms](docs/commercial-terms.md) | What an ISAC will ask of a hosted or supported deployment — draft for counsel |

---

## Design decisions worth knowing before you read the code

A few choices are load-bearing enough that changing them breaks correctness
rather than style. Each is documented where it is implemented, and expanded in
`docs/architecture.md`.

**`distributions` is a materialised table, not a computed view.** TAXII paging is
a cursor over `date_added`, which must be stable and monotonic. A computed
visibility view would make an embargoed object materialise *behind* clients'
cursors the instant its embargo lifted — every client that had polled since
distribution would skip it, permanently and silently. The stored timestamp is the
release instant, and the read-time comparison `date_added <= now` **is** the
embargo gate. The scheduler that flips embargo status is a convenience; if it
dies, nothing leaks early.

**`stix2.parse(allow_custom=False)` does not reject unknown
`extension-definition--` property extensions.** Verified against stix2 3.0.2: an
unknown `x-foo-ext` key raises, an unknown `extension-definition--…` key parses
silently and passes the body through as an opaque dict. Since AIVS redistributes
what it accepts, that would make it a delivery mechanism for arbitrary
unvalidated content. `assert_extensions_allowed` enforces an explicit two-entry
allowlist on every inbound object.

**Circle membership governs TAXII visibility even for system administrators.**
`can_read_circle` has no admin bypass. An ISAC that wants to read a circle joins
it visibly, appearing in the membership list, rather than silently appearing in
every member's feed. Members can verify who receives what they share by
inspection, and that answer is only worth something if it is complete.

**Identity is the SHA-256 certificate fingerprint, computed by the application.**
Not the subject DN, which gets reissued and reused. Not nginx's
`$ssl_client_fingerprint`, which is SHA-1. The proxy forwards the full PEM and
the application parses it and re-checks the validity window itself, which removes
the proxy from the set of components that must be correct for identity to be
sound.

**The audit log is append-only in PostgreSQL, not by convention.** Statement-level
triggers raise on UPDATE, DELETE, and TRUNCATE; the application role is granted
only INSERT and SELECT. A superuser can still drop the triggers — which is stated
plainly in the migration, and is why deployment guidance has the application
connect as a non-superuser that does not own those tables.

---

## Status

Pre-1.0 and under active development. Treat enum values and the STIX extension
as stable — they are wire contracts, persisted in PostgreSQL enum types and
consumed by member firms' clients. Adding a value is a compatible change;
renaming or removing one is not.

**Built** means in the code with tests. **Designed** means a design document
exists and nothing is built. **Planned** means it is on the roadmap, listed in
build order, and nothing is built.

| Capability | Status |
| --- | --- |
| TAXII 2.1 server; STIX 2.1 with the pre-CVE property extension | Built |
| Sharing circles with TLP 2.0 floors; explicit and rule-based membership, held as intervals so that joining grants participation, not the archive | Built |
| Server-enforced embargoes: release instant, extension, early release | Built |
| Human-only editorial checkpoint; ISAC roles `isac_editor`, `isac_analyst`, `isac_membership`, `system_admin` | Built |
| Anonymous distribution with server-assigned attribution, and an audited reveal | Built |
| Receipts of retrieval and acknowledgment | Built |
| Contentless webhooks ("poll to collect") | Built |
| Analyst portal: password + TOTP, sessions bound to the client certificate | Built |
| Append-only audit trail, enforced by trigger | Built |
| Detection rules over the platform's own audit log, emitted as OCSF and CEF; syslog/TLS log forwarding; `/readyz`, `/metrics` and an admin status page | Built |
| Pause distribution; quarantine an organisation, including on a detection's proposal (or automatically, if the ISAC chooses) | Built |
| Hybrid post-quantum TLS key exchange (X25519MLKEM768 first) | Built in the proxy configuration and pinned by test; negotiation verified by hand, end-to-end test planned. See [`pqc-readiness.md`](docs/pqc-readiness.md) |
| Secrets sealed at rest under a named, rotatable algorithm and key | Built |
| Reproducible CycloneDX SBOM | Built |
| Member CLI: `aivs enroll`, `poll`, `submit`, `ack` | Built |
| Federated identity for people (the ISAC's own IdP tenants, passkeys) | Member tenant built (next row); staff tenant and passkeys designed — [`identity-federation.md`](docs/identity-federation.md) |
| Content sealed to its recipients (BYOK) | Designed; **optional and deferred** — [`encryption-design.md`](docs/encryption-design.md) |
| GOLD EAGLE CVE handoff and return path | Designed, not scheduled — [`gold-eagle-integration.md`](docs/gold-eagle-integration.md) |
| Contributions on public CVEs: one canonical page per vulnerability, "what's available" (remediation, mitigation, detection, validation), the split by disclosure, the vendor as a case party, KEV enrichment, telemetry back to the submitter | Planned — next |
| Members sign in with the ISAC's SSO and a second factor over ordinary TLS; certificates stay for machines, ISAC staff and `TLP:RED` | Built — opt-in public listener ([`identity-federation.md`](docs/identity-federation.md) §11) |
| Depth ("tell me what to do" through raw objects), print, IoC pack, Sigma conversion | Planned |
| Member posture and evidence packs | Planned |
| Text documents (advisories) with versions, comments, proposals and document-only grants | Planned |
| Approved-MSSP programme | Planned |
| Directory integration with the ISAC's AD / Entra ID | Planned |
| Platform detections published to the ISAC as STIX sightings; a cryptographic bill of materials beside the SBOM | Planned |
| Real-time co-editing; fraud TTPs and fraud entities; AI assist (controlled models only) | Later — designed when a member asks |

### How success will be measured

These are the measures the product is built to move. **None is collected yet**;
each lists what has to exist before it can be.

| Measure | Why it matters | Collectable once |
| --- | --- | --- |
| Lead time versus NVD and KEV | The number that justifies the dues: how much earlier members knew | KEV enrichment and the canonical vulnerability page |
| Share of advisories with something to do (readiness not `none`) | Whether the page answers "what do we do" | "What's available" |
| Analyst minutes per advisory | Whether the ISAC's staff scale | Canonical page and the review queue's timings |
| Contributions per member per quarter | Whether members share, not only read | Contributions on public CVEs |
| Share of members with at least one contribution a month; median time to first contribution; 30-day repeat rate | Breadth, so one large firm's volume cannot stand in for participation | Contributions on public CVEs |
| Telemetry-back rate | Whether submitters learn that what they posted mattered | Telemetry back to the submitter |
| Evidence packs produced | Whether "prove you were told" is being used | Evidence packs |

---

## Security

**Do not open a public issue for a security vulnerability in AIVS itself.**

Report it privately to the maintainers, or to the hosting ISAC's security contact
if you found it against a deployed instance. Include the affected component, a
reproduction, and your assessment of impact. You will get an acknowledgment
within three business days.

Note the distinction, because this project is about vulnerability disclosure and
the two channels are easy to confuse:

- **A vulnerability in AIVS** — the server, the client, the schemas package —
  goes to the maintainers through the private channel above.
- **A vulnerability you want to share through AIVS** goes to your hosting ISAC as
  a submission, subject to the `discovery_scope` rules. See
  [`docs/onboarding.md`](docs/onboarding.md) §10.

Findings against a deployed instance's operational posture — CA handling, network
exposure, backup practice — belong to the ISAC operating it, not to this
repository.

---

## Licence

Apache-2.0. See [LICENSE](LICENSE).
