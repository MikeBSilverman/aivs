# The AIVS pre-CVE STIX 2.1 property extension

AIVS carries vulnerability intelligence as ordinary STIX 2.1 `vulnerability`
SDOs with one property-extension attached. Nothing about the object is
proprietary: a member firm's TIP that knows nothing of AIVS still parses the
object, still reads its `name`, `description`, and `object_marking_refs`, and
still files it correctly. The extension adds the properties a pre-CVE finding
needs and STIX has no place for — how an AI system found it, what it affects,
what the embargo is, and where it sits relative to CVE publication.

This extension serves the pre-CVE lane, which is the front of what AIVS covers:
the platform is meant to follow a vulnerability from that first finding through
CVE issuance to the detection, mitigation and verification work that follows.
The later stages are planned as an additive version 2.0 of this extension —
vocabularies for remediation, detection and exploitation status taken from
existing standards rather than invented — and nothing of it is built. Version
1.0 below is what the server accepts today.

Implementation: `packages/aivs-schemas/src/aivs_schemas/extension/`.

---

## 1. Identifiers

| Thing | Value |
| --- | --- |
| Extension definition id | `extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6` |
| Authoring identity | `identity--e50b8964-5a9a-4d4b-a016-16ea043c2c56` |
| Extension type | `property-extension` |
| Applies to | the `vulnerability` SDO |
| Current schema version | `1.0` (the value of `aivs_schema_version`) |
| `extension-definition` object `version` | `1.0.0` |

The extension definition id is **minted once and never changes**. A new
identifier would be a new, unrecognised extension to every member's TIP, and
every consumer's parsing rule would have to be updated. `extension_definition_sdo()`
enforces this at load time: if `definition.json` declares an id other than the
constant in `builders.py`, it raises `RuntimeError` rather than serving a
mismatched pair.

The authoring identity is the **AIVS project's** identity, deliberately distinct
from any hosting ISAC's identity. The extension is shared across deployments; the
ISAC identity is per-instance and appears in `created_by_ref` on content.

### The extension-definition SDO

Published in every distributed bundle, so a consumer meeting the extension for
the first time can resolve what it means without an out-of-band lookup:

```json
{
  "type": "extension-definition",
  "spec_version": "2.1",
  "id": "extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6",
  "created_by_ref": "identity--e50b8964-5a9a-4d4b-a016-16ea043c2c56",
  "created": "2026-01-01T00:00:00.000Z",
  "modified": "2026-01-01T00:00:00.000Z",
  "name": "AIVS Pre-CVE AI Vulnerability Extension",
  "description": "Adds pre-disclosure properties to the STIX vulnerability SDO for vulnerabilities discovered by AI systems and shared ahead of CVE publication: how the finding was discovered and by which model or harness, the affected products, a CVSS v4.0 assessment, embargo state, remediation guidance, and the finding's position relative to public CVE issuance.",
  "schema": "https://schemas.aivs.example/aivs-pre-cve/1.0/schema.json",
  "version": "1.0.0",
  "extension_types": ["property-extension"]
}
```

---

## 2. Security note: why AIVS validates extensions itself

**`stix2.parse(..., allow_custom=False)` does not reject unknown property
extensions keyed by an `extension-definition--<uuid>` identifier.** It validates
only that the identifier is well-formed, then passes the extension body through
as an opaque dictionary.

Verified against `stix2` 3.0.2:

| Input | `stix2.parse(allow_custom=False)` |
| --- | --- |
| Unknown `x-foo-ext` key in `extensions` | raises `InvalidValueError` |
| Unknown `extension-definition--…` key in `extensions` | **parses silently** |

That asymmetry matters here more than in most STIX deployments, because AIVS
**redistributes what it accepts**. `allow_custom=False` alone would let a
submitter smuggle arbitrary unvalidated content — attacker-chosen keys and values
of any shape — into objects that AIVS then stores and hands to every member of a
circle, with the ISAC's implicit endorsement.

Two functions close the gap, and both run on every inbound object:

```python
ALLOWED_EXTENSION_IDS = frozenset(
    {
        AIVS_EXTENSION_ID,  # extension-definition--530ad906-…
        TLP20_EXTENSION_DEFINITION_ID,  # extension-definition--60a3c5c5-…
    }
)
```

- **`assert_extensions_allowed(obj)`** rejects any object whose `extensions`
  object contains a key outside that allowlist, raising `UnknownExtensionError`.
  It rejects rather than ignores: silently dropping an unrecognised extension
  would change the meaning of content a member may have relied on, and silently
  keeping it would redistribute unvalidated data.
- **`validate_stix_object(obj)`** runs the allowlist check and then validates any
  AIVS extension body against the JSON Schema, raising `ExtensionValidationError`
  with up to five path-qualified messages.

Neither is optional, and callers must apply them to **every object in a bundle**,
not only the ones they intend to read. An object AIVS ignores is still an object
AIVS stores and redistributes.

Note also that only two extension ids are accepted. The TLP 2.0 definition is on
the list because TLP 2.0 markings are themselves property extensions (§5) —
without it, a correctly marked object would be rejected.

---

## 3. Fields

`extension_type` is fixed at `"property-extension"` and is required. The JSON
Schema sets `additionalProperties: false`, so an unrecognised property name is a
rejection, not a pass-through.

Property names follow STIX 2.1 §7.3.2.1: ASCII lowercase, digits, and underscore
only.

### Required

| Property | Type | Constraints | Meaning |
| --- | --- | --- | --- |
| `extension_type` | string | `const: "property-extension"` | STIX-mandated. |
| `aivs_schema_version` | string | `^[0-9]+\.[0-9]+$` | Version of this extension schema the object was authored against. Consumers use it to decide whether they understand the payload. Currently `"1.0"`. |
| `discovery_scope` | string | `own_product` \| `own_estate` \| `ai_system` | The submitter's relationship to the affected system. |
| `cve_status` | string | `pre-cve` \| `requested` \| `assigned` \| `published` | Where the finding sits relative to public CVE issuance. |
| `affected_products` | array | 1–200 items, shape below | What is affected. |

`discovery_scope` is the field that keeps AIVS clear of the coordinated-
disclosure consent problem. The extension accepts no value meaning "a third
party's software". The server's enum reserves two for the planned split by
disclosure (`disclosed_third_party`, `coordinated_disclosure`), and every path
refuses them, with the text an unknown value gets, until that split's
enforcement lands:

| Value | Meaning |
| --- | --- |
| `own_product` | A vulnerability in a product the submitter builds and ships. |
| `own_estate` | A vulnerability in the submitter's own deployed environment. |
| `ai_system` | An AI-system vulnerability generally — prompt injection, model supply chain, agentic tooling. |

`cve_status` exists because AIVS serves the `pre-cve` window, and the later
values let a submission stay useful as it progresses toward publication rather
than being abandoned at the point a CVE id appears.

### `affected_products` item shape

`additionalProperties: false`; `vendor` and `product` required.

| Property | Type | Constraints |
| --- | --- | --- |
| `vendor` | string | 1–200 chars |
| `product` | string | 1–200 chars |
| `version_range` | string | ≤ 200 chars |
| `cpe` | string | must match `^cpe:2\.3:[aho*\-]`, ≤ 500 chars |
| `purl` | string | must start with `pkg:`, ≤ 500 chars |

`purl` is offered alongside `cpe` because it is considerably more practical for
software dependencies, and a submitter reporting a library finding usually has
one and not the other.

### Optional

| Property | Type | Constraints | Meaning |
| --- | --- | --- | --- |
| `ai_discovery_method` | string | enum, below | How the finding was discovered, when an AI system discovered it. Optional within 1.0 (relaxing a constraint needs no version bump, section 6): defence content on a public CVE need not have been AI-discovered. |
| `ai_model_name` | string | ≤ 200 | Model that performed or led the discovery. |
| `ai_harness_name` | string | ≤ 200 | Harness or tool wrapping the model. |
| `ai_harness_version` | string | ≤ 100 | |
| `ai_confidence` | integer | 0–100 | Submitter's confidence the finding is real and exploitable. **Absent means not asserted, which is not the same as low.** |
| `ai_reproduction_available` | boolean | | Whether the submitter *holds* a working reproduction. Deliberately a boolean and not the reproduction itself: AIVS distributes warning, not weaponised proof-of-concept. |
| `cvss_v4_vector` | string | `^CVSS:4\.0/`, ≤ 400 | |
| `cvss_v4_base_score` | number | 0–10 | |
| `cvss_v4_severity` | string | `none`\|`low`\|`medium`\|`high`\|`critical` | |
| `embargo_policy` | string | `timer`\|`coordinated`\|`manual` | |
| `embargo_release_at` | string | STIX timestamp, `…Z` | The submitter's intended release instant. **Advisory metadata for the consumer; the authoritative gate is server-side visibility** (`distributions.date_added`). |
| `remediation_summary` | string | ≤ 5000 | |
| `workaround_available` | boolean | | |
| `cve_id` | string | `^CVE-[0-9]{4}-[0-9]{4,}$` | |
| `exploit_chain_position` | integer | 1–100 | 1-based position within an exploit chain. |

`ai_discovery_method` values (hyphenated, matching STIX style):
`sast-harness`, `dast`, `fuzzing`, `exploit-chain-search`, `model-audit`,
`red-team`, `manual-review`, `other`.

### Conditional rules

Three `allOf` clauses in the JSON Schema, each with a stated reason:

1. **`cve_id` is required when `cve_status` is `assigned` or `published`, and
   forbidden otherwise.** Prevents a placeholder id being read as authoritative
   during the pre-CVE window. Note the "forbidden" half — passing a `cve_id` with
   `cve_status: "pre-cve"` is a validation *failure*, not a warning.
2. **`embargo_policy: "timer"` requires `embargo_release_at`.** A timer embargo
   without a release time is not an embargo.
3. **`cvss_v4_base_score` requires `cvss_v4_vector`.** A score without its vector
   cannot be audited or recomputed.

### Where the two validators differ

The extension is declared twice: as a `stix2` `@CustomExtension` (so objects can
be constructed and round-tripped through the library) and as the JSON Schema (the
authority for inbound validation). They are not identical, and the JSON Schema is
strictly the tighter of the two:

| | `stix2` registration | JSON Schema |
| --- | --- | --- |
| `cvss_v4_severity` | `StringProperty` — any string | enumerated |
| `embargo_policy` | `StringProperty` — any string | enumerated |
| `embargo_release_at` | `StringProperty` | timestamp pattern |
| `cve_id` | `StringProperty` | `CVE-` pattern **and** the conditional rule |
| `affected_products` | `ListProperty(DictionaryProperty)` — no inner shape | full item schema, 1–200 items |
| string length caps | none | per-field `maxLength` |

**Validate inbound content with `validate_stix_object`, never with `stix2` type
construction alone.** Constructing via `build_extension_body` is safe: it runs
`validate_stix_object` on the body before returning it, so a caller cannot build
an invalid body and discover it at distribution time.

---

## 4. Exploit chains

Frontier models do not mostly find isolated bugs; they find sequences. AIVS
expresses a chain with plain STIX graph structure rather than a bespoke field, so
a TIP that knows nothing of AIVS still renders it as a graph.

Three pieces:

1. Each step is its own `vulnerability` SDO with the AIVS extension, carrying
   `exploit_chain_position` (1-based).
2. Consecutive steps are joined by a `relationship` with
   `relationship_type: "chains-to"`, source = the earlier step, target = the
   next. STIX permits producer-defined relationship types; this one is defined
   here so consumers can traverse chains deterministically.
3. The whole chain is collected by a `grouping` with
   `context: "exploit-chain"`, whose `object_refs` lists the vulnerabilities and
   the relationships. `grouping-context-ov` is an open vocabulary, so a
   producer-defined value is spec-conformant.

```
grouping (context: "exploit-chain")
   │ object_refs
   ├─► vulnerability A   position 1 ──chains-to──► vulnerability B   position 2
   ├─► vulnerability B                                   │
   ├─► vulnerability C   position 3   ◄──chains-to───────┘
   ├─► relationship A→B
   └─► relationship B→C
```

Traversal rule for consumers: find groupings with `context == "exploit-chain"`,
take their `object_refs`, and order the vulnerabilities either by
`exploit_chain_position` or by walking the `chains-to` edges. Both orderings must
agree; if they do not, treat the `chains-to` edges as authoritative and the
positions as a hint, since positions are a per-object assertion and edges are
relational facts.

The constants are exported so no consumer has to hard-code the strings:

```python
from aivs_schemas.extension.builders import (
    RELATIONSHIP_CHAINS_TO,  # "chains-to"
    EXPLOIT_CHAIN_GROUPING_CONTEXT,  # "exploit-chain"
)
```

---

## 5. TLP 2.0

Every distributed object carries a TLP 2.0 marking in `object_marking_refs`.
Three facts, recorded in `aivs_schemas/tlp.py` so they are not rediscovered the
hard way:

**TLP 2.0 markings are not in the STIX 2.1 specification.** The STIX 2.1 OASIS
Standard (June 2021) predates TLP 2.0 (August 2022) and defines only the four
TLP 1.0 markings in §7.2.1.4. TLP 2.0 is defined in the OASIS
`cti-stix-common-objects` repository, which is the source of truth for the
identifiers below.

**TLP 2.0 GREEN, AMBER, and RED have different UUIDs from their TLP 1.0
namesakes**, and TLP 2.0 uses the `extensions` property-extension form rather
than TLP 1.0's `definition_type`/`definition` pair. Mixing the two generations
produces markings that look right and mean nothing.

**The `stix2` library ships TLP 1.0 constants only** and actively rejects
attempts to construct a TLP:CLEAR via its `TLPMarking` type, so AIVS declares
these as literal mappings. They parse and round-trip cleanly through
`stix2.parse`.

| Designation | Marking definition id |
| --- | --- |
| `TLP:CLEAR` | `marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487` |
| `TLP:GREEN` | `marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb` |
| `TLP:AMBER` | `marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421` |
| `TLP:AMBER+STRICT` | `marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003` |
| `TLP:RED` | `marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1` |

TLP 2.0 extension definition id:
`extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d`.

A marking object as AIVS emits it — note the absence of `modified`, because
marking definitions are not versionable and adding one would make the object
invalid:

```json
{
  "type": "marking-definition",
  "spec_version": "2.1",
  "id": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
  "created": "2022-10-01T00:00:00.000Z",
  "name": "TLP:AMBER+STRICT",
  "extensions": {
    "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
      "extension_type": "property-extension",
      "tlp_2_0": "amber+strict"
    }
  }
}
```

Names are capitalised with no spaces, per FIRST: `TLP:AMBER+STRICT`, never
`TLP: Amber+Strict`.

**Legacy TLP 1.0 identifiers are recognised but never emitted, and never
upgraded.** `tlp_for_marking_id()` returns `None` for a TLP 1.0 id rather than
mapping it to its TLP 2.0 namesake: TLP 1.0 AMBER and TLP 2.0 AMBER carry
materially different handling obligations, and guessing on a member's behalf is
not AIVS's to do. Note also that TLP 2.0 has no equivalent for TLP:WHITE, which
it replaced with TLP:CLEAR.

Restrictiveness is ordered `clear < green < amber < amber_strict < red`
(`TLP_RESTRICTIVENESS`). `tlp_at_least_as_restrictive(candidate, floor)` is the
check that a submission is never distributed into a circle under a marking looser
than that circle's `minimum_tlp`.

---

## 6. Versioning policy

**Additive-only within 1.x.** Within the `1.x` series:

| Change | Allowed? |
| --- | --- |
| Add an optional property | Yes — bump to `1.1`, `1.2`, … |
| Add a value to an existing enum | Yes, with care: consumers pinned to `1.0` will see a value they do not recognise. Treat as `1.x+1`. |
| Relax a constraint (raise a `maxLength`, widen a numeric range) | Yes |
| Add a new required property | **No** — that is `2.0` |
| Remove or rename a property | **No** — that is `2.0` |
| Remove an enum value | **No** — that is `2.0` |
| Tighten a constraint so previously valid content fails | **No** — that is `2.0` |
| Change the extension definition id | **Never** |

The rule follows from what a consumer must be able to assume: an object
declaring `aivs_schema_version: "1.7"` must still be fully readable by a consumer
that implements `1.0`, ignoring the properties it does not know. That holds only
if every `1.x` addition is optional.

`aivs_schema_version` is the version a *consumer* branches on. It is bumped
independently of the `aivs-schemas` package version — `aivs_schemas.__init__`
exports `AIVS_EXTENSION_VERSION` separately from `__version__` for exactly this
reason. The `extension-definition` SDO's own `version` field
(`1.0.0`) tracks the same series in semver form.

A `2.0` would be a new schema file (`schema-2.0.json`) served under the same
extension definition id, with the definition SDO's `modified` and `version`
updated. Consumers would branch on `aivs_schema_version`, which is precisely why
it is required on every object.

Corresponding rule for the enums in `aivs_schemas.enums`, stated in that module:
values are a wire contract, persisted in PostgreSQL enum types and consumed by
member firms' clients. **Adding a member is a compatible change; renaming or
removing one is not**, and requires a migration plus a schema version bump.

---

## 7. Worked examples

### 7.1 A single pre-CVE finding in the submitter's own product

```json
{
  "type": "vulnerability",
  "spec_version": "2.1",
  "id": "vulnerability--8f2c1e0a-4d3b-4a91-9f6c-2b7e5d1a0c34",
  "created_by_ref": "identity--3a1f9c22-5b6d-4e70-8f21-9c4d7e2b1a55",
  "created": "2026-03-04T09:12:00.000Z",
  "modified": "2026-03-04T09:12:00.000Z",
  "name": "Authentication bypass in Meridian Payments Gateway session resumption",
  "description": "A crafted resumption ticket causes the gateway to reuse a prior session's authorisation context, permitting operations under another tenant's identity. Discovered by an automated SAST harness; confirmed by manual reproduction.",
  "object_marking_refs": [
    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003"
  ],
  "extensions": {
    "extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6": {
      "extension_type": "property-extension",
      "aivs_schema_version": "1.0",
      "ai_discovery_method": "sast-harness",
      "ai_model_name": "claude-mythos-5",
      "ai_harness_name": "meridian-codeaudit",
      "ai_harness_version": "2.4.1",
      "ai_confidence": 92,
      "ai_reproduction_available": true,
      "discovery_scope": "own_product",
      "affected_products": [
        {
          "vendor": "Meridian Global",
          "product": "Payments Gateway",
          "version_range": ">=4.2.0 <4.2.7",
          "purl": "pkg:maven/com.meridian/payments-gateway@4.2.6"
        }
      ],
      "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
      "cvss_v4_base_score": 9.2,
      "cvss_v4_severity": "critical",
      "embargo_policy": "timer",
      "embargo_release_at": "2026-04-01T00:00:00.000Z",
      "remediation_summary": "Upgrade to 4.2.7. As a mitigation, disable session resumption by setting gateway.session.resume=false; this costs roughly 8ms per connection and has no functional impact.",
      "workaround_available": true,
      "cve_status": "pre-cve"
    }
  }
}
```

Points to note: no `cve_id`, because `cve_status` is `pre-cve` and the schema
*forbids* one there. `embargo_release_at` is present because `embargo_policy` is
`timer`. `cvss_v4_vector` accompanies the score. `ai_reproduction_available` is
`true` but no reproduction is attached — AIVS distributes warning, not exploit.

### 7.2 An AI-system finding, distributed anonymously

```json
{
  "type": "vulnerability",
  "spec_version": "2.1",
  "id": "vulnerability--c40b7a19-2e88-4f5d-b3a6-71d0e9c48f12",
  "created_by_ref": "identity--0d5e7b91-a3c4-4f28-9b60-4e1a7c33d802",
  "created": "2026-03-11T14:40:00.000Z",
  "modified": "2026-03-11T14:40:00.000Z",
  "name": "Indirect prompt injection via retrieved document metadata in agentic loan-review tooling",
  "description": "Attacker-controlled text in a PDF's XMP metadata is incorporated into the agent's context without delimiting, allowing the attacker to redirect tool selection. Affects any deployment of the pattern, not a single vendor's implementation.",
  "object_marking_refs": [
    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421"
  ],
  "extensions": {
    "extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6": {
      "extension_type": "property-extension",
      "aivs_schema_version": "1.0",
      "ai_discovery_method": "red-team",
      "ai_confidence": 78,
      "ai_reproduction_available": true,
      "discovery_scope": "ai_system",
      "affected_products": [
        { "vendor": "Multiple", "product": "RAG document ingestion pipelines" }
      ],
      "cve_status": "pre-cve",
      "embargo_policy": "coordinated",
      "remediation_summary": "Strip or delimit non-body document metadata before it enters the model context. Treat retrieved content as untrusted input to tool-selection decisions."
    }
  }
}
```

`created_by_ref` here is the **hosting ISAC's** identity, because the submission
set `distribute_anonymously`. The submitter remains resolvable to the ISAC
through the receipts and audit trail, and to no one else. `embargo_policy` is
`coordinated`, so no `embargo_release_at` is required.

### 7.3 An exploit chain

Three vulnerabilities, two `chains-to` relationships, one grouping. Abbreviated
to the structural properties.

```json
[
  {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--11111111-1111-4111-8111-111111111111",
    "created": "2026-05-02T08:00:00.000Z",
    "modified": "2026-05-02T08:00:00.000Z",
    "name": "Unauthenticated template read in Aurora Portal",
    "object_marking_refs": ["marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1"],
    "extensions": {
      "extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6": {
        "extension_type": "property-extension",
        "aivs_schema_version": "1.0",
        "ai_discovery_method": "exploit-chain-search",
        "discovery_scope": "own_product",
        "affected_products": [{ "vendor": "Aurora", "product": "Portal" }],
        "cve_status": "pre-cve",
        "exploit_chain_position": 1
      }
    }
  },
  {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--22222222-2222-4222-8222-222222222222",
    "created": "2026-05-02T08:00:00.000Z",
    "modified": "2026-05-02T08:00:00.000Z",
    "name": "Template contents disclose an internal service token",
    "object_marking_refs": ["marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1"],
    "extensions": {
      "extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6": {
        "extension_type": "property-extension",
        "aivs_schema_version": "1.0",
        "ai_discovery_method": "exploit-chain-search",
        "discovery_scope": "own_product",
        "affected_products": [{ "vendor": "Aurora", "product": "Portal" }],
        "cve_status": "pre-cve",
        "exploit_chain_position": 2
      }
    }
  },
  {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--33333333-3333-4333-8333-333333333333",
    "created": "2026-05-02T08:00:00.000Z",
    "modified": "2026-05-02T08:00:00.000Z",
    "name": "Internal service token grants ledger write access",
    "object_marking_refs": ["marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1"],
    "extensions": {
      "extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6": {
        "extension_type": "property-extension",
        "aivs_schema_version": "1.0",
        "ai_discovery_method": "exploit-chain-search",
        "discovery_scope": "own_estate",
        "affected_products": [{ "vendor": "Aurora", "product": "Ledger Service" }],
        "cve_status": "pre-cve",
        "exploit_chain_position": 3,
        "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "cvss_v4_base_score": 10.0,
        "cvss_v4_severity": "critical"
      }
    }
  },
  {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "created": "2026-05-02T08:00:00.000Z",
    "modified": "2026-05-02T08:00:00.000Z",
    "relationship_type": "chains-to",
    "source_ref": "vulnerability--11111111-1111-4111-8111-111111111111",
    "target_ref": "vulnerability--22222222-2222-4222-8222-222222222222",
    "description": "The unauthenticated read is what exposes the template containing the token."
  },
  {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "created": "2026-05-02T08:00:00.000Z",
    "modified": "2026-05-02T08:00:00.000Z",
    "relationship_type": "chains-to",
    "source_ref": "vulnerability--22222222-2222-4222-8222-222222222222",
    "target_ref": "vulnerability--33333333-3333-4333-8333-333333333333"
  },
  {
    "type": "grouping",
    "spec_version": "2.1",
    "id": "grouping--cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    "created": "2026-05-02T08:00:00.000Z",
    "modified": "2026-05-02T08:00:00.000Z",
    "name": "Aurora Portal unauthenticated read to ledger write",
    "context": "exploit-chain",
    "object_refs": [
      "vulnerability--11111111-1111-4111-8111-111111111111",
      "vulnerability--22222222-2222-4222-8222-222222222222",
      "vulnerability--33333333-3333-4333-8333-333333333333",
      "relationship--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      "relationship--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    ],
    "object_marking_refs": ["marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1"]
  }
]
```

Note the CVSS placement: the individual steps are unremarkable, and the score
that matters is on the terminal step, which is what the chain actually achieves.
Scoring links in isolation is how chains get triaged as three low-severity issues
and ignored.

---

## 8. Building bodies in Python

```python
import datetime as dt
from aivs_schemas.enums import AIDiscoveryMethod, CVEStatus, DiscoveryScope
from aivs_schemas.extension.builders import (
    AIVS_EXTENSION_ID,
    build_extension_body,
    validate_stix_object,
)
from aivs_schemas.tlp import TLP, marking_id_for

body = build_extension_body(
    ai_discovery_method=AIDiscoveryMethod.SAST_HARNESS,
    discovery_scope=DiscoveryScope.OWN_PRODUCT,
    cve_status=CVEStatus.PRE_CVE,
    affected_products=[
        {
            "vendor": "Meridian Global",
            "product": "Payments Gateway",
            "version_range": ">=4.2.0 <4.2.7",
        },
    ],
    ai_model_name="claude-mythos-5",
    ai_confidence=92,
    cvss_v4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cvss_v4_base_score=9.2,
    cvss_v4_severity="critical",
    embargo_policy="timer",
    embargo_release_at=dt.datetime(2026, 4, 1, tzinfo=dt.UTC),
)

obj = {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--8f2c1e0a-4d3b-4a91-9f6c-2b7e5d1a0c34",
    "created": "2026-03-04T09:12:00.000Z",
    "modified": "2026-03-04T09:12:00.000Z",
    "name": "Authentication bypass in session resumption",
    "object_marking_refs": [marking_id_for(TLP.AMBER_STRICT)],
    "extensions": {AIVS_EXTENSION_ID: body},
}
validate_stix_object(obj)
```

`build_extension_body` is keyword-only throughout: eighteen mostly-optional
fields of similar types make positional calls unreadable and easy to transpose.
It fills `extension_type` and `aivs_schema_version` for you, drops `None`
optionals, and validates the result before returning it.

Timestamps go through `format_stix_timestamp`, which requires UTC with a literal
`Z` and millisecond precision, and **refuses a naive datetime** rather than
assuming UTC — guessing a timezone on an embargo release time is exactly the kind
of assumption that publishes content hours early.
