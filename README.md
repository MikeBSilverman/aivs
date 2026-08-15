# AIVS — pre-CVE AI vulnerability sharing

**ISAC-in-a-box for the disclosure window that does not exist yet.**

AIVS is a sharing system for AI-discovered vulnerabilities in the phase *before*
a CVE is published: structured, embargoed early warning delivered to GSIBs,
Section 9 firms, and other critical infrastructure operators, over standard
TAXII 2.1 and STIX 2.1.

It is deployed **by an ISAC**, for its own members. Apache-2.0 licensed.

---

## The problem

Frontier AI models have made vulnerability discovery cheap. Firms running model-
driven analysis over their own code and their own estates are finding more, and
finding it faster — including multi-step exploit chains that no single scanner
would have flagged. A separate effort, GOLD EAGLE, helps firms convert that
output into CVEs at scale.

That leaves a gap AIVS fills. Between the moment a firm knows about a
vulnerability and the moment a CVE is published, there is a window — days to
months — in which the finding is real, the risk is live, and there is no
structured way to warn peers who are exposed to the same thing. Today that
warning travels by phone call and mailing list, if it travels at all.

Financial-sector ISACs have not addressed AI-driven vulnerability intelligence.
The AI-system category in particular — prompt injection, model supply chain,
agentic tooling — has no disclosure norms at all, and it is precisely where large
firms are now most exposed and least served. That is the white space.

---

## Working on AIVS

Read [CLAUDE.md](CLAUDE.md) before contributing. It carries the verification
gates, the test-database isolation rule, and the correctness rules that exist
because the opposite was written first — each one with the failure that
produced it, so the reasoning survives the next refactor.

## What AIVS is

A single-tenant sharing server an ISAC runs for its members:

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

### What AIVS is deliberately not

It is **not a channel for undisclosed vulnerabilities in uninvolved third
parties' software.** v1 accepts three scopes, and there is no fourth:

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

# Schema. Naming the app's database role applies the append-only grants.
AIVS_APP_DB_ROLE=aivs_app \
  uv run alembic -c packages/aivs-server/alembic.ini upgrade head

# Verify the append-only enforcement actually took. Do not skip this: the
# evidentiary guarantee the product rests on can silently fail to apply.
psql -U aivs_app -c "DELETE FROM audit_log WHERE id = 1;"
#   expected: ERROR: table audit_log is append-only; DELETE is not permitted

# Run
docker compose up -d          # nginx + app + postgres
# or, application only, behind your own proxy:
uv run aivs-server
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
| [Sharing agreement outline](docs/sharing-agreement-outline.md) | A non-lawyer's skeleton for counsel to draft from |

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

Pre-1.0 and under active development. The shared contract (`aivs-schemas`), the
data model, the mTLS identity layer, the authorization policy module, and the
append-only audit enforcement are implemented. Treat enum values and the STIX
extension as stable — they are wire contracts, persisted in PostgreSQL enum types
and consumed by member firms' clients. Adding a value is a compatible change;
renaming or removing one is not.

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
