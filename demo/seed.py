"""Seed a demonstration instance.

Creates a small but realistic community: a hosting ISAC, three member firms
across three sharing circles, and one AI-discovered exploit chain moving through
the workflow. Intended for showing the system to ISAC leadership and prospective
member firms.

**Uses its own database.** Defaults to ``aivs_demo`` so it can never disturb the
test database or a development one. Pass ``--database-url`` to override.

Everything here is fictional. The firms do not exist and the vulnerability is
invented; nothing in this file is real intelligence.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import itertools
import os
import uuid

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aivs_schemas.enums import (
    TLP,
    AIDiscoveryMethod,
    CircleRole,
    CVEStatus,
    DiscoveryScope,
    OrgStatus,
    OrgType,
    SubmissionState,
)
from aivs_schemas.extension.builders import (
    AIVS_EXTENSION_ID,
    EXPLOIT_CHAIN_GROUPING_CONTEXT,
    RELATIONSHIP_CHAINS_TO,
    build_extension_body,
)
from aivs_server.db.base import Base
from aivs_server.db.models import (
    Circle,
    CircleMembership,
    Distribution,
    Organization,
    StixObject,
    Submission,
    TaxiiCollection,
)
from aivs_server.services.attribution import FilingRecord, owner_tokens_for, record_filing
from aivs_server.taxii.resources import truncate_to_taxii_precision

DEFAULT_DATABASE_URL = os.environ.get(
    "AIVS_DEMO_DATABASE_URL",
    "postgresql+psycopg://aivs@127.0.0.1:55432/aivs_demo",
)

#: The fictional community.
ISAC = ("example-isac", "Example Financial ISAC", OrgType.ADMIN)
MEMBERS = [
    ("meridian-global", "Meridian Global Bank", OrgType.GSIB),
    ("atlantic-clearing", "Atlantic Clearing Corporation", OrgType.SECTION9),
    ("ridgeline-utilities", "Ridgeline Utilities Co-operative", OrgType.CRIT_INFRA),
]
CIRCLES = [
    ("gsib", "GSIB Circle", TLP.AMBER_STRICT),
    ("section9", "Section 9 Circle", TLP.AMBER_STRICT),
    ("crit-infra-general", "Critical Infrastructure (General)", TLP.AMBER),
]
#: Which firms sit in which circles. Ridgeline is deliberately absent from the
#: two tighter circles, so the demo can show content reaching some members and
#: not others.
MEMBERSHIP = {
    "gsib": [("meridian-global", CircleRole.CONTRIBUTOR)],
    "section9": [
        ("atlantic-clearing", CircleRole.CONTRIBUTOR),
        ("meridian-global", CircleRole.MEMBER),
    ],
    "crit-infra-general": [
        ("ridgeline-utilities", CircleRole.MEMBER),
        ("atlantic-clearing", CircleRole.MEMBER),
    ],
}


def stix_timestamp(moment: dt.datetime) -> str:
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{moment.microsecond // 1000:03d}Z"


def build_exploit_chain(identity_id: str) -> list[dict]:
    """A three-step chain in a fictional agentic-AI runtime.

    Modelled the way AIVS intends chains to be expressed: separate vulnerability
    objects joined by ``chains-to`` relationships and collected by a grouping,
    so a consumer can traverse the chain deterministically rather than parsing
    it out of prose.
    """
    created = dt.datetime.now(dt.UTC) - dt.timedelta(hours=6)
    stamp = stix_timestamp(created)

    steps = [
        (
            "Unsanitised tool output reaches the planner context",
            "A tool result is concatenated into the planning context without "
            "delimiting, so text returned by a fetched document is interpreted "
            "as instruction.",
            AIDiscoveryMethod.EXPLOIT_CHAIN_SEARCH,
            8.1,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
        ),
        (
            "Planner may select credential-bearing tools without re-authorisation",
            "Once instruction-carrying text is in context, the planner can select "
            "a tool holding stored credentials; no second authorisation gate "
            "applies between planning and execution.",
            AIDiscoveryMethod.MODEL_AUDIT,
            9.1,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        ),
        (
            "Egress allowlist bypassed via redirect following",
            "The HTTP tool follows redirects before applying the egress "
            "allowlist, so an allowlisted host can hand off to one that is not.",
            AIDiscoveryMethod.SAST_HARNESS,
            7.7,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        ),
    ]

    objects: list[dict] = []
    vulnerability_ids: list[str] = []

    for position, (name, description, method, score, vector) in enumerate(steps, start=1):
        stix_id = f"vulnerability--{uuid.uuid4()}"
        vulnerability_ids.append(stix_id)
        objects.append(
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": stix_id,
                "created_by_ref": identity_id,
                "created": stamp,
                "modified": stamp,
                "name": name,
                "description": description,
                "extensions": {
                    AIVS_EXTENSION_ID: build_extension_body(
                        ai_discovery_method=method,
                        discovery_scope=DiscoveryScope.AI_SYSTEM,
                        cve_status=CVEStatus.PRE_CVE,
                        affected_products=[
                            {
                                "vendor": "Northwind Systems",
                                "product": "AgentRuntime",
                                "version_range": ">=2.0.0,<2.4.1",
                            }
                        ],
                        ai_model_name="claude-mythos-5",
                        ai_harness_name="northwind-chain-search",
                        ai_confidence=88,
                        ai_reproduction_available=True,
                        cvss_v4_vector=vector,
                        cvss_v4_base_score=score,
                        remediation_summary=(
                            "Upgrade to 2.4.1. As an interim control, disable "
                            "redirect following on the HTTP tool and require "
                            "re-authorisation before credential-bearing tool use."
                        ),
                        workaround_available=True,
                        exploit_chain_position=position,
                    )
                },
            }
        )

    # chains-to relationships, in exploit order.
    for earlier, later in itertools.pairwise(vulnerability_ids):
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created_by_ref": identity_id,
                "created": stamp,
                "modified": stamp,
                "relationship_type": RELATIONSHIP_CHAINS_TO,
                "source_ref": earlier,
                "target_ref": later,
            }
        )

    objects.append(
        {
            "type": "grouping",
            "spec_version": "2.1",
            "id": f"grouping--{uuid.uuid4()}",
            "created_by_ref": identity_id,
            "created": stamp,
            "modified": stamp,
            "name": "Northwind AgentRuntime credential-exfiltration chain",
            "context": EXPLOIT_CHAIN_GROUPING_CONTEXT,
            "object_refs": vulnerability_ids,
        }
    )
    return objects


async def seed(database_url: str, *, reset: bool) -> None:
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    async with engine.begin() as connection:
        if reset:
            await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)

    async with factory() as session:
        organizations: dict[str, Organization] = {}
        for slug, name, org_type in [ISAC, *MEMBERS]:
            org = Organization(
                slug=slug,
                name=name,
                org_type=org_type,
                status=OrgStatus.ACTIVE,
                stix_identity_id=f"identity--{uuid.uuid4()}",
            )
            session.add(org)
            organizations[slug] = org
        await session.flush()

        circles: dict[str, Circle] = {}
        for slug, name, floor in CIRCLES:
            circle = Circle(slug=slug, name=name, minimum_tlp=floor)
            session.add(circle)
            circles[slug] = circle
        await session.flush()

        for circle_slug, members in MEMBERSHIP.items():
            for org_slug, role in members:
                session.add(
                    CircleMembership(
                        circle_id=circles[circle_slug].id,
                        org_id=organizations[org_slug].id,
                        role=role,
                    )
                )
            session.add(
                TaxiiCollection(
                    circle_id=circles[circle_slug].id,
                    title=circles[circle_slug].name,
                    alias=circle_slug,
                    can_read=True,
                    can_write=True,
                )
            )
        await session.flush()

        # Meridian files the chain, the ISAC validates it, and it goes to the
        # two tighter circles under a short embargo.
        submitter = organizations["meridian-global"]
        objects = build_exploit_chain(submitter.stix_identity_id)

        submission = Submission(
            state=SubmissionState.DISTRIBUTED,
            tlp=TLP.AMBER_STRICT,
            discovery_scope=DiscoveryScope.AI_SYSTEM,
            title="Northwind AgentRuntime credential-exfiltration chain (pre-CVE)",
            summary=(
                "Three chained weaknesses allowing untrusted document text to "
                "drive credential-bearing tool use and exfiltrate to a host "
                "outside the egress allowlist. Vendor notified; fix in 2.4.1."
            ),
            distributed_at=dt.datetime.now(dt.UTC),
        )
        session.add(submission)
        await session.flush()
        await record_filing(
            session,
            submission,
            FilingRecord(
                org_id=submitter.id, created_by=None, proxy_editor=None, proxy_consent=None
            ),
        )
        tokens = await owner_tokens_for(
            session, submitter.id, (obj["id"] for obj in objects), owner_is_isac=False
        )

        stored: list[StixObject] = []
        for obj in objects:
            moment = dt.datetime.fromisoformat(obj["modified"].replace("Z", "+00:00"))
            row = StixObject(
                stix_id=obj["id"],
                type=obj["type"],
                spec_version="2.1",
                created=moment,
                modified=moment,
                submission_id=submission.id,
                raw=obj,
                owner_token=tokens[obj["id"]],
                name=obj.get("name"),
            )
            session.add(row)
            stored.append(row)
        await session.flush()

        # Released 30 seconds out, so a live demonstration can show content
        # invisible and then visible without anyone waiting around.
        release_at = truncate_to_taxii_precision(dt.datetime.now(dt.UTC) + dt.timedelta(seconds=30))
        for circle_slug in ("gsib", "section9"):
            for row in stored:
                session.add(
                    Distribution(
                        stix_object_id=row.id,
                        circle_id=circles[circle_slug].id,
                        submission_id=submission.id,
                        date_added=release_at,
                    )
                )

        await session.commit()

    await engine.dispose()

    print("Seeded demonstration instance.")  # noqa: T201 - operator-facing script
    print(f"  organisations : {len([ISAC, *MEMBERS])}")  # noqa: T201
    print(f"  circles       : {len(CIRCLES)}")  # noqa: T201
    print(f"  objects       : {len(objects)} in one exploit chain")  # noqa: T201
    print(f"  releases at   : {release_at.isoformat()} (~30s from now)")  # noqa: T201
    print()  # noqa: T201
    print("Ridgeline Utilities is deliberately outside the two tighter circles,")  # noqa: T201
    print("so it should see nothing at all.")  # noqa: T201


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed an AIVS demonstration instance.")
    parser.add_argument("--database-url", default=DEFAULT_DATABASE_URL)
    parser.add_argument(
        "--reset",
        action="store_true",
        help=("Drop and recreate the schema first. Point it at a scratch database."),
    )
    args = parser.parse_args()

    if "aivs_test" in args.database_url:
        parser.error("refusing to seed the test database; use aivs_demo")

    asyncio.run(seed(args.database_url, reset=args.reset))


if __name__ == "__main__":
    main()
