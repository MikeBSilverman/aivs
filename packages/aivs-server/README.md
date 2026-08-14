# aivs-server

The AIVS sharing server: a TAXII 2.1 endpoint set, a native REST API for the
workflows TAXII cannot express, and a minimal analyst portal.

Run it behind the reverse proxy in `deploy/nginx`, which terminates mTLS and is
the only thing permitted to reach the application. The application refuses to
start in `production` with any development bypass enabled — see
`aivs_server.config.Settings.validate_production_posture`.

```
uv run alembic -c packages/aivs-server/alembic.ini upgrade head
uv run aivs-server
```

Layout:

| Package | Responsibility |
| --- | --- |
| `auth/` | Client-certificate identity, portal sessions, and `policy.py` — the single authorization decision point |
| `taxii/` | TAXII 2.1 discovery, collections, objects, manifest, and status resources |
| `api/` | Native API: submissions, embargoes, acknowledgments, circles, orgs, certificates, webhooks |
| `services/` | Workflow, distribution, embargo, and STIX validation logic |
| `portal/` | Server-rendered analyst UI (Jinja2 + htmx) |
| `audit/` | Append-only audit writer |
| `notify/` | SSRF-guarded webhook delivery |

Licensed under Apache-2.0.
