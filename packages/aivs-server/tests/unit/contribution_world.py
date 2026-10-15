"""Builders for the contribution-rule tests: canonical records, contributions, the workflow.

Not a test module. The canonical record is seeded straight into the database --
its own filing path is not what these tests are about -- and every contribution
then goes through the real API, so a rule is proven on the path members use.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from aivs_schemas.enums import TLP, DiscoveryScope, SubmissionState
from aivs_schemas.extension.builders import AIVS_EXTENSION_ID
from aivs_server.db import models
from tests.conftest import proxy_headers, seed_filing, seeded_owner_token

API = "/api/v1/submissions"
STAMP = "2026-08-01T00:00:00.000Z"
LATER = "2026-09-01T00:00:00.000Z"


def stamp_of(when: dt.datetime) -> str:
    return when.isoformat().replace("+00:00", "Z")


def vulnerability_raw(
    stix_id: str, *, cve_status: str, modified: str = STAMP, **extra: Any
) -> dict:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id,
        "created": STAMP,
        "modified": modified,
        "name": "The ISAC's record",
        "extensions": {AIVS_EXTENSION_ID: {"cve_status": cve_status}},
        **extra,
    }


async def seed(
    session,
    org: models.Organization,
    raw: dict,
    *,
    circle: models.Circle | None,
    tlp: TLP = TLP.AMBER,
    state: SubmissionState = SubmissionState.DISTRIBUTED,
    discovery_scope: DiscoveryScope = DiscoveryScope.OWN_ESTATE,
) -> models.Submission:
    """One submission carrying ``raw``, distributed to ``circle`` if one is given."""
    now = dt.datetime.now(dt.UTC)
    modified = dt.datetime.fromisoformat(raw["modified"].replace("Z", "+00:00"))
    submission = models.Submission(
        state=state,
        tlp=tlp,
        discovery_scope=discovery_scope,
        title=raw.get("name", "seeded"),
        distributed_at=now if state is SubmissionState.DISTRIBUTED else None,
    )
    await seed_filing(session, submission, org)
    await session.flush()
    stored = models.StixObject(
        stix_id=raw["id"],
        type=raw["type"],
        spec_version="2.1",
        created=modified,
        modified=modified,
        submission_id=submission.id,
        raw=raw,
        owner_token=await seeded_owner_token(session, submission, raw["id"]),
    )
    session.add(stored)
    await session.flush()
    if circle is not None:
        session.add(
            models.Distribution(
                stix_object_id=stored.id,
                circle_id=circle.id,
                submission_id=submission.id,
                date_added=now - dt.timedelta(minutes=1),
            )
        )
    await session.commit()
    return submission


def course_of_action_about(target: str, *, name: str = "Disable the agent plugin") -> list[dict]:
    """A workaround and the relationship that says what it mitigates."""
    coa_id = f"course-of-action--{uuid.uuid4()}"
    return [
        {
            "type": "course-of-action",
            "spec_version": "2.1",
            "id": coa_id,
            "created": STAMP,
            "modified": STAMP,
            "name": name,
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": STAMP,
            "modified": STAMP,
            "relationship_type": "mitigates",
            "source_ref": coa_id,
            "target_ref": target,
        },
    ]


def opinion_about(target: str, *, opinion: str = "agree", **extra: Any) -> dict:
    return {
        "type": "opinion",
        "spec_version": "2.1",
        "id": f"opinion--{uuid.uuid4()}",
        "created": STAMP,
        "modified": STAMP,
        "opinion": opinion,
        "object_refs": [target],
        **extra,
    }


def bundle_of(*objects: dict) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(objects)}


async def file(client, pem, objects, *, scope="own_product", tlp="amber", anonymous=False):
    return await client.post(
        API,
        json={
            "title": "Contribution",
            "discovery_scope": scope,
            "tlp": tlp,
            "distribute_anonymously": anonymous,
            "bundle": bundle_of(*objects),
        },
        headers=proxy_headers(pem),
    )


async def submit_and_validate(
    client, pem, submission_id, editor_headers, *, sender=None, **validate_body: Any
):
    """Send the filing for review, then validate it as the editor.

    ``sender`` is who sends it: the filer by default, the editor for the ISAC's
    automation, whose own filings only an editor may send (Mike, Q35).
    """
    submitted = await client.post(
        f"{API}/{submission_id}/submit", json={}, headers=sender or proxy_headers(pem)
    )
    assert submitted.status_code == 200, submitted.text
    return await client.post(
        f"{API}/{submission_id}/validate", json=validate_body, headers=editor_headers
    )


async def distribute(client, submission_id, editor_headers, circle):
    return await client.post(
        f"{API}/{submission_id}/distribute",
        json={"circle_ids": [str(circle.id)]},
        headers=editor_headers,
    )
