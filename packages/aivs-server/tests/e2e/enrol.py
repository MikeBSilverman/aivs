"""Enrol the e2e member through the API, as the ISAC's operator would.

    PYTHONPATH=packages/aivs-server AIVS_E2E_STATE=... uv run python -m tests.e2e.enrol

Run once by ``scripts/e2e.sh up``, after the bootstrap. It signs the ISAC
operator in through the portal and then, with that session as a bearer:
creates the member organisation, registers its certificate, activates it,
creates a circle and adds the member. The circle's id is written back into
``state.json`` for the tests.
"""

from __future__ import annotations

import json
import sys

from tests.e2e.stack import STATE_PATH, load_stack

API = "/api/v1"


def main() -> int:
    stack = load_stack()
    bearer = stack.isac_bearer()
    member_pem = stack.member.cert.read_text(encoding="ascii")

    with stack.client(stack.isac) as isac:
        org = isac.post(
            f"{API}/orgs",
            json={"slug": stack.member_slug, "name": "E2E Member Bank", "org_type": "gsib"},
            headers=bearer,
        )
        org.raise_for_status()
        org_id = org.json()["id"]

        registered = isac.post(
            f"{API}/orgs/{org_id}/certificates",
            json={"certificate_pem": member_pem, "label": "e2e collector"},
            headers=bearer,
        )
        registered.raise_for_status()
        isac.post(f"{API}/orgs/{org_id}/activate", headers=bearer).raise_for_status()

        circle = isac.post(
            f"{API}/circles",
            json={"slug": "e2e-circle", "name": "E2E Circle", "minimum_tlp": "amber"},
            headers=bearer,
        )
        circle.raise_for_status()
        circle_id = circle.json()["id"]
        isac.post(
            f"{API}/circles/{circle_id}/members", json={"org_ids": [org_id]}, headers=bearer
        ).raise_for_status()

    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    state["member"]["org_id"] = org_id
    state["circle_id"] = circle_id
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
    message = f"enrolled {stack.member_slug} ({org_id}) into circle {circle_id}"
    print(message, file=sys.stderr)  # noqa: T201 - a script reporting to its operator
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
