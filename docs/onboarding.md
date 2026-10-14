# Onboarding a member firm

For the engineer at a member firm who will actually wire this up. You have done
this for other feeds; this one is a TAXII 2.1 server behind mutual TLS, with two
differences worth knowing before you start:

1. **You need a client certificate issued by the ISAC**, not an API key. Your
   private key is generated on your machine and never leaves it.
2. **Reachability is separate from authentication.** You will either be a
   WireGuard peer or on an IP allowlist, and that gets you as far as the TLS
   handshake — nothing more.

Budget half a day for the technical work and however long your legal team needs
for the membership agreement, which is the actual long pole.

---

## The path

```
 1. Agreement signed              (legal — start this first)
 2. ISAC enrols your organization → status: pending
 3. You generate a key + CSR      (locally; the key never leaves)
 4. ISAC signs; registers the SHA-256 fingerprint
 5. ISAC activates you            → status: active
 6. ISAC adds you to circles      → your collections appear
 7. You configure a TAXII client and poll
 8. Optional: webhooks, submitting, acknowledgments
```

Steps 2, 4, 5, and 6 are ISAC-side. Everything else is yours.

---

## 1. Before you start

Have these ready. Chasing them mid-way is what makes this take a week instead of
an afternoon.

| Item | Notes |
| --- | --- |
| Signed membership agreement | Covers TLP handling, embargo obligations, and the own-product/own-estate/AI-system attestation if you intend to submit. |
| Organization legal name and a short slug | The slug is lowercase alphanumeric with hyphens, 3–64 characters, database-enforced: `^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`. Pick something durable — `meridian-global`, not `mg-test2`. |
| Organization type | `gsib`, `section9`, or `crit_infra`. Determines which circles you are eligible for. |
| A technical contact and a security contact | Different people, ideally. |
| Egress IP ranges, or a WireGuard public key | Which one depends on the ISAC's mode. |
| Where TAXII content lands | TIP, SIEM, ticketing. Decide before you generate certificates — it determines how many you need. |

**Decide how many certificates you want now.** One per system is the right
answer: the certificate is the identity, and per-system certificates mean you can
rotate or revoke one without an outage everywhere else. A typical firm has three:

| Label | Used by |
| --- | --- |
| `taxii-prod` | The TIP or SIEM connector that polls |
| `submit-batch` | Whatever posts your own findings, if you submit |
| `soc-analyst` | Portal access for your analysts |

Multiple concurrent active certificates per organization are normal and
supported.

---

## 2. Generate a key and CSR

**Do this on the machine that will use the certificate, or on a machine you
control that can transfer the key securely.** The private key must not travel by
email, ticket, or chat.

### With the AIVS CLI

```console
$ pip install aivs-client
$ aivs enroll --org meridian-global
```

`aivs enroll` generates the key locally and writes a CSR. Only the CSR is sent to
the ISAC.

### With OpenSSL

Equivalent, and fine if you would rather not install another tool:

```bash
# EC is the AIVS CA's default algorithm
openssl ecparam -name prime256v1 -genkey -noout -out meridian-taxii-prod.key
chmod 600 meridian-taxii-prod.key

openssl req -new \
  -key meridian-taxii-prod.key \
  -out meridian-taxii-prod.csr \
  -subj "/O=Meridian Global Bank/CN=meridian-global-taxii-prod"
```

Subject conventions:

| Field | Value |
| --- | --- |
| `O` | Your legal entity name |
| `CN` | `<your-slug>-<label>`, e.g. `meridian-global-taxii-prod` |

The CN is for human recognition in the ISAC's console. **It is not your
identity** — AIVS keys identity on the SHA-256 fingerprint of the issued
certificate. You can reuse a CN across rotations without ambiguity.

Your certificate will be valid for **365 days**. Plan rotation accordingly (§12).

RSA is accepted if your platform cannot do EC:

```bash
openssl req -new -newkey rsa:3072 -nodes \
  -keyout meridian-taxii-prod.key -out meridian-taxii-prod.csr \
  -subj "/O=Meridian Global Bank/CN=meridian-global-taxii-prod"
```

### Send the ISAC

- the `.csr` file (safe to send over ordinary channels — it contains only your
  public key and subject);
- the label you want it recorded under;
- what will use it.

**Never send the `.key`.** If anyone asks you to, that is an incident, not a
process step.

---

## 3. The ISAC signs and registers you

The ISAC signs the CSR against the AIVS issuing CA and registers the resulting
certificate's SHA-256 fingerprint in `client_certificates`. You get back:

- your signed certificate (`.crt`);
- the CA chain (`ca-chain.pem`) — the issuing CA and the root;
- the instance hostname and API root;
- WireGuard peer configuration, if applicable.

**Verify the fingerprint out of band.** The fingerprint is the identity of
record, and it takes ten seconds:

```console
$ openssl x509 -in meridian-taxii-prod.crt -noout -fingerprint -sha256
SHA256 Fingerprint=A3:12:...:F0
```

Lowercase it and strip the colons to get the form AIVS stores. Confirm it against
what the ISAC read back to you over a channel that is not the one the certificate
arrived on.

Also verify the CA chain against the root fingerprint the ISAC publishes in its
governance documentation. You are installing a trust anchor; check it once,
properly.

```bash
openssl x509 -in ca-chain.pem -noout -fingerprint -sha256
openssl verify -CAfile ca-chain.pem meridian-taxii-prod.crt
```

At this point your organization is still `pending` and **every request will be
denied**. `is_active()` is the first check in every authorization predicate.
Activation is a separate ISAC step.

---

## 4. Network reachability

### WireGuard

The ISAC gives you a peer config. Generate your keypair locally:

```bash
wg genkey | tee meridian.key | wg pubkey > meridian.pub
```

Send the **public** key. A typical peer config:

```ini
[Interface]
PrivateKey = <contents of meridian.key>
Address    = 10.77.0.14/32

[Peer]
PublicKey  = <ISAC's public key>
Endpoint   = aivs-gw.example.org:51820
AllowedIPs = 10.77.0.0/24
PersistentKeepalive = 25
```

`AllowedIPs` should be the AIVS overlay range only. Do not route your default
gateway through it.

### IP allowlist

Send the ISAC your egress ranges in CIDR form. Tell them when the ranges change,
*before* they change — a silent NAT reconfiguration presents as "all our polls
started returning connection refused" and burns an afternoon.

### Verify

```console
$ curl -v https://aivs.example.org/taxii2/ 2>&1 | grep -E 'Connected|handshake'
```

Expect the TCP connection to succeed and the TLS handshake to fail — you have not
presented a certificate yet. If the connection itself fails, it is layer 1: the
overlay or the allowlist, not your certificate.

---

## 5. First authenticated request

```console
$ curl --cert meridian-taxii-prod.crt \
       --key  meridian-taxii-prod.key \
       --cacert ca-chain.pem \
       -H 'Accept: application/taxii+json;version=2.1' \
       https://aivs.example.org/taxii2/
```

Expected:

```json
{
  "title": "Example Financial ISAC",
  "description": "Pre-CVE AI vulnerability sharing for member firms.",
  "default": "https://aivs.example.org/taxii2/aivs/",
  "api_roots": ["https://aivs.example.org/taxii2/aivs/"]
}
```

Then list your collections:

```console
$ curl --cert meridian-taxii-prod.crt --key meridian-taxii-prod.key \
       --cacert ca-chain.pem \
       -H 'Accept: application/taxii+json;version=2.1' \
       https://aivs.example.org/taxii2/aivs/collections/
```

### If you get `{}` back

That is a valid, spec-conformant response meaning **you belong to no circles
yet**. Empty TAXII responses omit the property entirely rather than returning an
empty array. It is not an error and not a bug — ask the ISAC to add you to
circles.

### If you get 401

In order of likelihood:

| Cause | Check |
| --- | --- |
| Client certificate not presented | Did `curl` actually send it? Use `-v` and look for "Client certificate". |
| Chain too deep | The proxy sets `ssl_verify_depth 2` — leaf plus intermediate. A certificate issued under an extra CA layer will not validate. |
| Certificate not yet registered | Ask the ISAC to confirm the fingerprint is on file. |
| Certificate expired or not yet valid | `openssl x509 -noout -dates`. The application re-checks the window itself with a 5-minute skew tolerance — a badly wrong clock on your side will do this. |
| Certificate revoked | Ask the ISAC. |

The response will not tell you which. That is deliberate — the reason is recorded
in the ISAC's audit log and never returned to the caller. Ask them; they can read
it.

### If you get 404 on a collection you were told about

You are not in its circle, or you have the wrong id. AIVS returns 404 rather than
403 for collections outside your visibility, because the existence of a circle is
itself information.

---

## 6. Configure your TAXII client

AIVS is a standard TAXII 2.1 server. Configure it as you would any other, with a
client certificate.

| Setting | Value |
| --- | --- |
| Discovery URL | `https://aivs.example.org/taxii2/` |
| API root | `https://aivs.example.org/taxii2/aivs/` |
| Collection id | The UUID from step 5 — stable for the life of the deployment |
| Auth | Client certificate (mTLS). No API key, no basic auth. |
| Accept | `application/taxii+json;version=2.1` |
| Poll interval | 5–15 minutes. More often gains nothing; content becomes visible on a stored timestamp, not on demand. The proxy rate-limits each certificate to 20 r/s (burst 40) and answers **429** above that — a poller should never come close. |
| Version filter | `match[version]=last` is the **default**. Set `all` if you want history. |

### Cursor handling — the part that goes wrong

AIVS returns `X-TAXII-Date-Added-Last` on every non-empty page. **That value, and
only that value, is your cursor.**

```
poll:  GET /taxii2/aivs/collections/{id}/objects/?added_after=<stored cursor>&limit=100
       → 200, X-TAXII-Date-Added-Last: 2026-03-11T14:41:07.902Z
       → store that as the new cursor

more:  if the envelope has "more": true, follow "next" — do NOT advance the
       cursor until you reach the last page, then store its date-added-last

empty: {} with no date-added headers — keep the cursor unchanged
```

Three rules:

1. **Never use wall-clock time as the cursor.** Your clock and the server's
   `date_added` sequence are different things, and the drift will silently skip
   content.
2. **Never advance the cursor mid-pagination.** Follow `next` to the end.
3. **`added_after` is exclusive.** Feeding back the last value you saw yields no
   duplicates.

An embargoed object becomes visible at its release instant, and its `date_added`
is that instant — later than the objects distributed around it. Correct cursor
handling is what guarantees you receive it. Incorrect cursor handling is how a
firm silently misses exactly the warnings that were held back as most sensitive.

### With the CLI instead

```console
$ aivs poll --collection section9 --since auto
```

`aivs poll` keeps its own cursor per collection and writes newline-delimited STIX
to stdout, so piping into a TIP or SIEM ingest is a one-liner and re-running it
never re-delivers content you already have.

---

## 7. What arrives

STIX 2.1 `vulnerability` SDOs with the AIVS pre-CVE property extension, plus
`relationship` and `grouping` objects for exploit chains, plus the
`extension-definition`, `identity`, and TLP 2.0 `marking-definition` objects
needed to interpret them standalone.

A TIP that knows nothing of AIVS will still parse everything and file it
correctly. To read the extension properties, look for:

```
extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6
```

Full field reference: [`stix-extension.md`](stix-extension.md).

### Fields worth wiring into triage on day one

| Field | Use |
| --- | --- |
| `discovery_scope` | `own_product` and `own_estate` are a named firm's disclosure about itself. `ai_system` is a class of finding, likely relevant to your own AI deployments. Route them differently. |
| `affected_products[].purl` / `.cpe` | Match against your SBOM. This is the highest-value automation here. |
| `cvss_v4_base_score` / `_severity` | CVSS **v4.0**, not v3.1. If your pipeline assumes v3.1 vectors, it will mis-parse. |
| `cve_status` | `pre-cve` means no CVE exists yet. Your vulnerability management process probably keys on CVE ids; you need a path for findings that have none. Solve this before content starts arriving, not after. |
| `exploit_chain_position` | Present means this is one step of a chain. Look for the `grouping` with `context: "exploit-chain"` and treat the chain as the unit of risk, not the step. |
| `ai_reproduction_available` | Whether the submitter *holds* a reproduction. AIVS never distributes one. |

### TLP 2.0

Every object carries a TLP 2.0 marking in `object_marking_refs`. These are TLP
**2.0** identifiers, which have different UUIDs from their TLP 1.0 namesakes.

| Marking | Handling |
| --- | --- |
| `TLP:AMBER` | Your organization and its clients, on a need-to-know basis. |
| `TLP:AMBER+STRICT` | **Your organization only.** Not clients, not vendors, not your MSSP. |
| `TLP:RED` | Named recipients only. |

If your TIP maps markings by UUID, load the TLP 2.0 identifiers explicitly —
mapping a TLP 2.0 AMBER id as "unknown" and defaulting to permissive is a
disclosure incident waiting for a slow week. The identifiers are in
[`stix-extension.md`](stix-extension.md) §5.

Your handling obligations are contractual, not advisory. See the membership
agreement.

---

## 8. Embargoes

Some content is distributed under embargo. AIVS enforces this **server-side**:
an embargoed object is simply not visible to you until its release instant, at
which point it appears in your feed with a `date_added` equal to that instant.

You will not receive an embargoed object early, and you cannot poll harder to get
it sooner. The `embargo_release_at` property in the extension is advisory
metadata telling you when the submitter intends release; the authoritative gate
is server-side.

Once you receive it, the embargo obligation is contractual: do not disclose,
publish, or share outside the permitted scope before the release date. What
counts as a breach is in the membership agreement, and the ISAC has receipts
showing precisely when your organization retrieved the content.

---

## 9. Optional: webhooks

Rather than polling for freshness alone, register an HTTPS endpoint to be
notified when something appears.

```console
$ curl --cert ... --key ... -X POST \
    https://aivs.example.org/api/v1/webhooks \
    -H 'Content-Type: application/json' \
    -d '{"url": "https://soc.meridian.example/hooks/aivs",
         "events": ["submission.distributed", "embargo.released"]}'
```

Constraints and expectations:

- **HTTPS only** — enforced by a database check constraint, not just validation.
- The HMAC secret is returned **once, at creation**. Store it immediately; it
  cannot be retrieved again.
- **Verify the signature on every delivery.** An unverified webhook is an
  unauthenticated POST from the internet, and treating it as a trigger for
  privileged action is a vulnerability you have added to your own estate.
- Notifications carry **metadata and identifiers only, never embargoed content**.
  Fetch the content over TAXII.
- Delivery is retried up to 5 times with a 5-second timeout. Repeated failures
  increment a counter and the webhook may be disabled.
- **Webhooks are a convenience, not the channel of record.** Keep polling. The
  receipt that proves you were warned is your TAXII retrieval, not a webhook
  delivery.

---

## 10. Optional: submitting

If your firm contributes, you need `contributor` in the target
circle. Reading a circle does not imply writing to it.

**What AIVS accepts:**

| `discovery_scope` | Meaning |
| --- | --- |
| `own_product` | A vulnerability in a product **you** build and ship. |
| `own_estate` | A vulnerability in **your own** deployed environment. |
| `ai_system` | An AI-system vulnerability generally — prompt injection, model supply chain, agentic tooling. |

**What AIVS does not accept:** undisclosed vulnerabilities in an uninvolved third
party's software. There is no `discovery_scope` value for it. This is not
squeamishness — distributing someone else's unpatched vulnerability without their
consent creates coordinated-disclosure and tortious-interference exposure for
you and for the ISAC. If you have found something in a vendor's product, that is
a coordinated disclosure to the vendor, and AIVS is not the channel for it.

Your `discovery_scope` selection is an **attestation**. The ISAC reviews it, but
it cannot verify it, and the membership agreement makes a false attestation a
breach.

Flow:

```
you:  POST the submission (draft)  → state: draft
you:  attach STIX objects
you:  transition to submitted      → state: submitted
ISAC: reviews scope, content, TLP  → state: validated
ISAC: distributes to circles       → state: distributed
```

**You never distribute your own content.** The ISAC's review is a structural part
of the workflow, not a courtesy. Expect a delay measured in hours to days, and
tell the ISAC if something is genuinely urgent — that is a conversation, not a
flag.

Choose at submission time:

| Choice | Effect |
| --- | --- |
| TLP designation | Must be at least as restrictive as the target circle's floor. |
| `distribute_anonymously` | Rewrites `created_by_ref` to the ISAC's identity and withholds you from every member-facing view. **The ISAC still knows.** Anonymity is from other members, not from the ISAC. |
| Embargo policy | `timer` (requires a release time), `coordinated`, or `manual`. |

```console
$ aivs submit finding.json
```

Validate locally first — `aivs-schemas` is the same package the server uses, so
what passes locally passes server-side:

```python
from aivs_schemas.extension.builders import validate_stix_object

validate_stix_object(obj)  # raises UnknownExtensionError / ExtensionValidationError
```

---

## 11. Optional: acknowledgments

Retrieval receipts are written automatically when you pull content. Beyond that
you can assert:

| Type | Meaning |
| --- | --- |
| `retrieved` | Written by the server on delivery. Not yours to assert. |
| `acknowledged` | A human at your firm has seen it. |
| `actioned` | Your firm has done something about it. |

```console
$ aivs ack 0f9c1e2a-... --type actioned --note "Patched in change CHG-44821"
```

Worth doing. `acknowledged` and `actioned` are what turn "the feed delivered it"
into "we responded to it" — which is the question your regulator will ask, and
the ISAC's receipts are the answer that exists whether or not you contributed to
it. Automatic `retrieved` receipts are deduplicated to one per submission per day,
so polling frequently does not distort the record.

---

## 12. Ongoing

| Task | Cadence |
| --- | --- |
| Confirm polling is current and the cursor is advancing | Weekly — a stalled cursor is silent |
| Certificate expiry review | Monthly; rotate at 60 days out |
| Rotate certificates | Certificates are valid 365 days. Overlap, do not cut over. |
| Review who at your firm holds portal accounts | Quarterly |
| Notify the ISAC of egress range changes | **Before** they change |
| Report a suspected key compromise | Immediately — revocation is effective on the next request |

### Rotation, concretely

```
day 0     generate a new key + CSR
day 0     ISAC signs and registers      → two active certificates
day 0-14  move each system to the new one at its own pace
day 14    confirm nothing uses the old one (the ISAC can see last_seen_at)
day 14    ISAC revokes the old one
```

Both certificates are valid at once because both are `active` rows in the ISAC's
database. There is no cutover window and no outage.

### If a key is compromised

Tell the ISAC immediately. Revocation is a status flip checked on every request —
effective on the next one, with no CRL propagation delay. Then generate a new key
and CSR. Do not wait for a maintenance window; the exposure is live.

---

## Reference

- [`stix-extension.md`](stix-extension.md) — every extension field, TLP 2.0 identifiers, worked examples
- [`taxii-mapping.md`](taxii-mapping.md) — endpoints, filters, headers, response shapes
- [`authz-model.md`](authz-model.md) — what your role grants
