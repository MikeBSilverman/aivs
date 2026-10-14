# AIVS ↔ TAXII 2.1 mapping

AIVS speaks TAXII 2.1 (OASIS Standard, June 2021) for content delivery. A member
firm's existing TAXII client — the one already pointed at their other feeds —
works against AIVS with a certificate and a collection id and nothing else.

This document is the conformance contract: media types, endpoints, headers,
filters, and resource shapes, with the places AIVS makes a specific choice inside
the spec's latitude called out explicitly.

---

## 1. Media types

Get these wrong and clients fail in ways that look like authorization problems.

| Context | Media type |
| --- | --- |
| TAXII resources (discovery, api-root, collections, envelope, manifest, status, error) | `application/taxii+json;version=2.1` |
| STIX content, as advertised in a collection's `media_types` and accepted on `POST /objects/` | `application/stix+json;version=2.1` |

Rules AIVS follows:

- Every TAXII response carries `Content-Type: application/taxii+json;version=2.1`.
- A request with an `Accept` header that matches neither the TAXII media type nor
  `*/*` gets **406 Not Acceptable**.
- `POST /objects/` requires
  `Content-Type: application/taxii+json;version=2.1`; a mismatch is
  **415 Unsupported Media Type**. The envelope is TAXII; the objects inside it are
  STIX.
- The `version=2.1` parameter is not optional. A client sending bare
  `application/taxii+json` is speaking an ambiguous dialect and is treated as
  acceptable on `Accept` but not on `Content-Type`.
- The parameter is written without a space (`;version=2.1`), matching the spec's
  examples.

---

## 2. Endpoints

AIVS serves **one API root**. There is one tenant, one trust domain, and one
retention policy per instance; multiple API roots would model a distinction AIVS
does not have.

`{base}` is `AIVS_PUBLIC_BASE_URL`, which must be `https://` outside development
(`validate_production_posture`). `{api-root}` below is the single API root path,
served beneath the `/taxii2/` prefix — `/taxii2/aivs/` in the examples here. That
placement is not arbitrary: `deploy/nginx/nginx.conf` gives `location /taxii2/`
its own document-free Content-Security-Policy (`default-src 'none'; sandbox`),
which costs nothing on an endpoint that never returns HTML and neutralises
content-sniffing tricks against a browser pointed at it. The native API lives
under `/api/` and gets the same treatment.

| Method | Path | Resource returned |
| --- | --- | --- |
| GET | `{base}/taxii2/` | Discovery |
| GET | `{base}/{api-root}/` | API Root |
| GET | `{base}/{api-root}/status/{status-id}/` | Status |
| GET | `{base}/{api-root}/collections/` | Collections |
| GET | `{base}/{api-root}/collections/{id}/` | Collection |
| GET | `{base}/{api-root}/collections/{id}/manifest/` | Manifest |
| GET | `{base}/{api-root}/collections/{id}/objects/` | Envelope |
| POST | `{base}/{api-root}/collections/{id}/objects/` | Status |
| GET | `{base}/{api-root}/collections/{id}/objects/{object-id}/` | Envelope |
| DELETE | `{base}/{api-root}/collections/{id}/objects/{object-id}/` | — |
| GET | `{base}/{api-root}/collections/{id}/objects/{object-id}/versions/` | Versions |

Trailing slashes are required by the specification and are not optional in AIVS.

### Endpoints AIVS restricts

**`POST /objects/`** — collections have `can_write = false` by default
(`taxii_collections.can_write`, model default `False`). TAXII POST is not the
normal intake path, because the AIVS workflow needs a `discovery_scope`, a TLP
designation, an anonymization choice, and an embargo, and TAXII's envelope has
nowhere to put any of them. Submission goes through the native API. Where a
collection *is* made writable, a POST creates a submission in `draft` for the
posting organization — it does **not** distribute anything. Distribution still
requires the hosting ISAC to move the submission through `validated` →
`distributed`.

A POST to a collection with `can_write = false` returns **403**, not 405: the
route exists, the caller is not permitted to use it on this collection.

**`DELETE /objects/{object-id}/`** — always **403**. Distributed content is
never deleted from a collection. Once members hold it, removal would be a false
promise, and it would silently break every client's `added_after` cursor by
shortening the sequence behind them. The AIVS equivalent is to supersede the
submission, which leaves the old version readable
(`VISIBLE_SUBMISSION_STATES = {distributed, superseded}`) and adds a new one.

### Authorization on every endpoint

`GET /collections/` lists only the collections whose circle the caller belongs to
— `readable_circle_ids(ctx)`. A collection the caller cannot read is not listed
and returns **404** when addressed directly, not 403: the existence of a circle
is itself information (see [`authz-model.md`](authz-model.md)).

There is no system-administrator bypass. A hosting ISAC that wants a circle's
TAXII feed joins that circle.

---

## 3. Response headers

Two TAXII-specific headers appear on every response that carries a set of objects
— the objects endpoint and the manifest endpoint:

| Header | Value |
| --- | --- |
| `X-TAXII-Date-Added-First` | The `date_added` of the **first** item in this page. |
| `X-TAXII-Date-Added-Last` | The `date_added` of the **last** item in this page. |

Because results are sorted ascending by `date_added`, `-Last` is the value a
client feeds back as `added_after` on its next poll. That is the whole polling
protocol, and it is why `distributions.date_added` is a stored, immutable column
rather than a computed expression — see [`architecture.md`](architecture.md) §6.

Both headers are **omitted entirely** when the page contains no objects. There is
no first or last item to report, and emitting an empty or zero-valued header
would give a client something meaningless to store as a cursor.

The values are STIX timestamps in UTC with millisecond precision and a literal
`Z`, matching `format_stix_timestamp`.

---

## 4. Filter parameters

Applicable to `GET /objects/`, `GET /objects/{object-id}/`,
`GET /manifest/`, and `GET /versions/` as the spec allows.

| Parameter | Applies to | Behaviour |
| --- | --- | --- |
| `added_after` | objects, manifest, versions | Return only items whose `date_added` is **strictly greater than** the supplied timestamp. Exclusive, so feeding back `X-TAXII-Date-Added-Last` yields no duplicates. Must be a valid STIX timestamp; anything else is **400**. |
| `limit` | objects, manifest, versions | Maximum items in this page. Clamped to `AIVS_TAXII_MAX_PAGE_SIZE` (default 500). Absent means `AIVS_TAXII_DEFAULT_PAGE_SIZE` (default 100). A `limit` above the maximum is silently clamped, not rejected — the spec allows a server to return fewer than requested. |
| `next` | objects, manifest, versions | Opaque continuation token from the previous response. Signed (`itsdangerous`) so a client cannot craft or tamper with a cursor to page outside its own visibility. |
| `match[id]` | objects, manifest | One or more STIX object ids, comma-separated. |
| `match[type]` | objects, manifest | One or more STIX object types, comma-separated (`vulnerability`, `relationship`, `grouping`, …). |
| `match[version]` | objects, manifest | Which versions of each matching object. See below. |
| `match[spec_version]` | objects, manifest | STIX specification version. AIVS stores only `2.1` — a database check constraint enforces it (`spec_version = '2.1'`) — so `match[spec_version]=2.0` legitimately matches nothing. |

Comma-separated values within one `match[…]` parameter are OR'd; different
`match[…]` parameters are AND'd. Repeating a parameter is equivalent to a
comma-separated list.

### `match[version]` semantics

A STIX object version is the `(id, modified)` pair. AIVS stores versions as
separate `stix_objects` rows under a `(stix_id, modified)` unique constraint,
which is exactly the granularity this filter needs.

| Value | Returns |
| --- | --- |
| `last` | The most recent version of each matching object, by `modified`. **This is the default when `match[version]` is absent.** |
| `first` | The earliest version of each matching object, by `modified`. |
| `all` | Every stored version of each matching object. |
| a STIX timestamp | The version whose `modified` equals that timestamp exactly. |

Multiple values may be combined: `match[version]=first,last` returns both ends;
`match[version]=all` supersedes anything combined with it.

The default being `last` is the single most common source of "the server is
hiding data" reports. A client that wants history must ask for it.

### Pagination contract

- Results are sorted **ascending by `date_added`**, then by `seq` (the
  distribution row's monotonic identity, not its random id) for objects sharing
  a timestamp, on the objects, manifest and versions endpoints alike. This is
  the same column order as the index `ix_distributions_circle_paging`
  (`circle_id, date_added, seq`); the index exists precisely to make this sort a
  range scan rather than a sort of the whole circle.
- `more: true` in the envelope means at least one further page exists, and `next`
  carries the cursor for it.
- `more: false` (or absent) means this is the last page, and `next` is omitted.
- Keyset pagination, not offset: a page boundary is `(date_added, id)`, so
  inserts arriving during a client's sweep land after the cursor rather than
  shifting rows across page boundaries.

---

## 5. Resource shapes

### Discovery — `GET /taxii2/`

```json
{
  "title": "Example Financial ISAC",
  "description": "Pre-CVE AI vulnerability sharing for member firms.",
  "contact": "aivs-ops@example.org",
  "default": "https://aivs.example.org/taxii2/aivs/",
  "api_roots": ["https://aivs.example.org/taxii2/aivs/"]
}
```

`title` comes from `AIVS_INSTANCE_NAME`. URLs are absolute and built from
`AIVS_PUBLIC_BASE_URL`.

### API Root — `GET /{api-root}/`

```json
{
  "title": "AIVS",
  "description": "Single API root for this instance.",
  "versions": ["application/taxii+json;version=2.1"],
  "max_content_length": 5242880
}
```

`max_content_length` reports `AIVS_MAX_BODY_BYTES` (default 5 MiB) in bytes, so a
client knows the request-body ceiling before it hits it.

### Collections — `GET /{api-root}/collections/`

```json
{
  "collections": [
    {
      "id": "4b1f8c02-9d3e-4a17-b6c5-0e2f7a91d834",
      "title": "Section 9 Pre-CVE",
      "description": "TLP:AMBER+STRICT or tighter. Section 9 designated firms.",
      "alias": "section9",
      "can_read": true,
      "can_write": false,
      "media_types": ["application/stix+json;version=2.1"]
    }
  ]
}
```

`id` is the `taxii_collections` UUID and is stable for the life of the
deployment, because members hard-code it in their client configuration. `alias`
is the human-friendly handle (unique across the instance) and may also be used in
place of the id in the path.

**If the caller can read no collections, the response is `{}`** — the
`collections` property is omitted entirely, not returned as `[]`. This is a
specification requirement, and it is a real interoperability trap: some clients
distinguish the two.

### Collection — `GET /{api-root}/collections/{id}/`

The same object without the enclosing array.

### Envelope — `GET /{api-root}/collections/{id}/objects/`

```json
{
  "more": true,
  "next": "eyJkIjoiMjAyNi0wMy0wNFQwOToxMjowMC4wMDBaIiwiaSI6IjkxNGYuLi4ifQ.k3nT…",
  "objects": [
    {
      "type": "vulnerability",
      "spec_version": "2.1",
      "id": "vulnerability--8f2c1e0a-4d3b-4a91-9f6c-2b7e5d1a0c34",
      "created": "2026-03-04T09:12:00.000Z",
      "modified": "2026-03-04T09:12:00.000Z",
      "name": "Authentication bypass in session resumption",
      "object_marking_refs": [
        "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003"
      ],
      "extensions": {
        "extension-definition--530ad906-a948-4467-8fd2-7fd13639ded6": {
          "extension_type": "property-extension",
          "aivs_schema_version": "1.0",
          "…": "…"
        }
      }
    }
  ]
}
```

Response headers on this page:

```
Content-Type: application/taxii+json;version=2.1
X-TAXII-Date-Added-First: 2026-03-04T09:14:22.118Z
X-TAXII-Date-Added-Last: 2026-03-11T14:41:07.902Z
```

**An empty result is `{}`**, with `objects` omitted and both `X-TAXII-Date-Added-*`
headers absent. Not `{"objects": []}`, and not a 404.

Objects are served from `stix_objects.raw` verbatim. Storage keeps the canonical
form opaque in JSONB precisely so a member's object round-trips byte-identical
rather than being lossily reassembled from relational columns.

Every envelope AIVS distributes also carries the objects a consumer needs to
interpret it standalone: the AIVS `extension-definition` SDO, the relevant TLP
2.0 `marking-definition` objects, and the authoring `identity` SDO.

### Manifest — `GET /{api-root}/collections/{id}/manifest/`

```json
{
  "more": false,
  "objects": [
    {
      "id": "vulnerability--8f2c1e0a-4d3b-4a91-9f6c-2b7e5d1a0c34",
      "date_added": "2026-03-04T09:14:22.118Z",
      "version": "2026-03-04T09:12:00.000Z",
      "media_type": "application/stix+json;version=2.1"
    }
  ]
}
```

`version` is the object's `modified` timestamp — the STIX version identifier —
not a sequence number. `date_added` is the `distributions.date_added` for *this
circle*, which for an embargoed object is its release instant rather than its
distribution instant.

The manifest is the cheap way to answer "what changed" without transferring
bodies. **Empty manifest responses are `{}`** — `objects` omitted.

### Versions — `GET /{api-root}/collections/{id}/objects/{object-id}/versions/`

```json
{
  "more": false,
  "versions": [
    "2026-03-04T09:12:00.000Z",
    "2026-03-18T11:02:41.000Z"
  ]
}
```

A bare array of `modified` timestamps, one per version, in the order the
versions reached this collection for the caller: by the `date_added` of each
version's first distribution the caller can see, then `seq`. **Not** by
`modified`. Only arrival order lets `added_after` = `X-TAXII-Date-Added-Last`
(or `next`) continue a listing without skipping a version, since a correction
can be distributed before a backfilled earlier version; a client that wants
modification order sorts the strings. A version two submissions carry is listed
once, at its first arrival. **Empty versions responses are `{}`** — `versions`
omitted.

### Status — `GET /{api-root}/status/{status-id}/`

Backed by the `taxii_status` table, whose columns mirror the resource one for
one.

```json
{
  "id": "2f7c6a41-0b8d-4e39-9a52-c1d4e8b7f603",
  "status": "complete",
  "request_timestamp": "2026-03-04T09:11:58.400Z",
  "total_count": 4,
  "success_count": 3,
  "successes": [
    { "id": "vulnerability--8f2c…", "version": "2026-03-04T09:12:00.000Z", "message": "stored" }
  ],
  "failure_count": 1,
  "failures": [
    {
      "id": "vulnerability--c40b…",
      "version": "2026-03-04T09:12:00.000Z",
      "message": "AIVS extension failed validation: cve_id: 'cve_id' should not be valid under {'required': ['cve_id']}"
    }
  ],
  "pending_count": 0,
  "pendings": []
}
```

`status` is `pending` or `complete` — enforced by a check constraint
(`status IN ('pending', 'complete')`). A status resource is scoped to the
organization that created it (`taxii_status.org_id`); another org requesting it
gets 404.

Note what a `success` here means: the object was **accepted and stored** against
a submission. It does not mean the object is visible to anyone. Visibility
requires the ISAC's `validated` → `distributed` transitions and, for embargoed
content, the passing of `date_added`.

### Error

```json
{
  "title": "Access denied",
  "http_status": "403"
}
```

`http_status` is a string, per the spec. AIVS deliberately keeps error resources
thin: `PolicyDenied.reason` and `CertificateRejection.reason` go to the audit log
and are **never** returned to the caller. `error_id`, `details`, and
`external_details` are omitted rather than populated with anything a caller could
use to map the authorization surface.

---

## 6. The empty-response rule, restated

Because it is the single most common conformance defect:

| Endpoint | Empty response body |
| --- | --- |
| `GET /collections/` | `{}` — not `{"collections": []}` |
| `GET /objects/` | `{}` — not `{"objects": []}` |
| `GET /manifest/` | `{}` — not `{"objects": []}` |
| `GET .../versions/` | `{}` — not `{"versions": []}` |

The spec requires the property to be **omitted** when there is nothing to report,
not present-and-empty. Emitting `[]` will pass casual testing and fail against a
strict client. AIVS's conformance tests (`@pytest.mark.conformance`) assert the
`{}` form specifically.

---

## 7. Status codes

| Code | When |
| --- | --- |
| 200 | Success. |
| 202 | `POST /objects/` accepted; body is a Status resource with `status: "pending"`. |
| 400 | Malformed filter parameter, unparseable `added_after`, invalid `next` cursor. |
| 401 | No usable client certificate. The reason is never disclosed. |
| 403 | Authenticated but not permitted — including `POST` to a `can_write: false` collection and any `DELETE`. |
| 404 | The resource does not exist, **or** the caller may not know that it does. Collections outside the caller's circles return 404. |
| 406 | `Accept` matches neither the TAXII media type nor `*/*`. |
| 413 | Body exceeds `AIVS_MAX_BODY_BYTES`. nginx's `client_max_body_size 5m` will usually reject it first, with its own 413. |
| 429 | Rate limited at the proxy. nginx limits each client certificate to 20 r/s with a burst of 40, and each source address to 64 concurrent connections. A collection poller runs at roughly 1 r/s, so a 429 means something is looping. Back off; do not retry immediately. |
| 415 | `Content-Type` on a POST is not `application/taxii+json;version=2.1`. |
| 422 | Body parsed but content failed STIX or AIVS extension validation, where the failure is whole-request rather than per-object. Per-object failures are reported in the Status resource's `failures`, with a 202. |

---

## 8. A worked polling sequence

```
# 1. Discover
GET /taxii2/
Accept: application/taxii+json;version=2.1

# 2. List what this certificate can read
GET /taxii2/aivs/collections/
→ {"collections": [{"id": "4b1f8c02-…", "alias": "section9", …}]}

# 3. First poll: no cursor
GET /taxii2/aivs/collections/4b1f8c02-…/objects/?limit=100
→ 200, X-TAXII-Date-Added-Last: 2026-03-11T14:41:07.902Z
   {"more": false, "objects": [ … ]}

# 4. Subsequent polls: feed back the last date_added
GET /taxii2/aivs/collections/4b1f8c02-…/objects/?added_after=2026-03-11T14:41:07.902Z&limit=100
→ 200, {}                       # nothing new; keep the same cursor

# 5. When more: true, follow next rather than advancing the cursor yourself
GET /taxii2/aivs/collections/4b1f8c02-…/objects/?next=eyJkIjoi…
```

Three client rules that follow from the design:

1. **Persist `X-TAXII-Date-Added-Last`, not "now".** A wall-clock cursor drifts
   against server time and will skip content.
2. **Do not advance the cursor while `more: true`.** Follow `next` to the end of
   the sequence, then store the final page's `X-TAXII-Date-Added-Last`.
3. **On an empty response, keep the cursor unchanged.** Empty is `{}` with no
   date-added headers; there is nothing to store.

Each retrieval writes an `acknowledgments` row of type `retrieved`, deduplicated
to one row per organization per submission per day (`dedupe_day`). Polling every
minute does not produce 1,440 receipts; it produces one, which is what makes the
receipt table readable as evidence.
