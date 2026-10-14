"""A circle to share in, for the tests of the contribution lanes (Phase E, "making members share").

Not a test module. The ISAC's records are seeded straight into the database --
their own filing path is not what these tests are about -- and every
contribution then goes through the real API, so a rule is proven on the path
members use.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from aivs_schemas.enums import TLP, CircleRole, OperatorRole, OrgType
from aivs_server.db import models
from tests.conftest import proxy_headers
from tests.unit.contribution_world import seed, vulnerability_raw

API = "/api/v1"


@dataclass
class Party:
    """An organisation in the circle: its certificate, and one signed-in analyst."""

    org: models.Organization
    pem: str
    operator: models.Operator
    #: A person, signed in over the organisation's certificate.
    person: dict[str, str]

    @property
    def machine(self) -> dict[str, str]:
        """The organisation's certificate alone: no person behind the request."""
        return proxy_headers(self.pem)


@dataclass
class SharingWorld:
    circle: models.Circle
    collection: models.TaxiiCollection
    #: Contributes to the circle.
    member: Party
    #: Reads the circle only.
    reader: Party
    #: A vendor that contributes to the circle.
    vendor: Party
    #: The ISAC's own machine identity. In no circle: it contributes and never
    #: reads, so no path may make it a member (``CIRCLE_ELIGIBLE_ORG_TYPES``).
    #: An earlier version joined it as a contributor through the raw fixture,
    #: and the tests then proved a rule in a world that cannot exist.
    automation: Party
    #: An ISAC editor, signed in.
    editor: dict[str, str]
    isac_org: models.Organization
    #: The ISAC's records in the circle, by state.
    published: str
    pre_cve: str
    published_red: str


async def _party(
    slug: str,
    org_type: OrgType,
    role: CircleRole | None,
    circle: models.Circle,
    fixtures: dict[str, Any],
) -> Party:
    org = await fixtures["make_org"](slug, org_type=org_type)
    pem, _ = await fixtures["make_cert"](org)
    operator, _seed = await fixtures["make_operator"](org, roles=(OperatorRole.ANALYST,))
    if role is not None:
        await fixtures["join_circle"](org, circle, role=role)
    return Party(org, pem, operator, await fixtures["human_headers"](operator, pem))


async def _record(session, isac_org, circle, *, cve_status: str, tlp: TLP = TLP.AMBER) -> str:
    stix_id = f"vulnerability--{uuid.uuid4()}"
    await seed(
        session, isac_org, vulnerability_raw(stix_id, cve_status=cve_status), circle=circle, tlp=tlp
    )
    return stix_id


async def build_sharing_world(session, isac, isac_org, **fixtures: Any) -> SharingWorld:
    circle = await fixtures["make_circle"]("sharing")
    collection = await fixtures["make_collection"](circle)
    contributor = CircleRole.CONTRIBUTOR
    member = await _party("meridian-global", OrgType.GSIB, contributor, circle, fixtures)
    reader = await _party("atlantic-clearing", OrgType.GSIB, CircleRole.MEMBER, circle, fixtures)
    vendor = await _party("acme-software", OrgType.VENDOR, contributor, circle, fixtures)
    automation = await _party("isac-automation", OrgType.AUTOMATION, None, circle, fixtures)
    _isac_org, editor = isac
    return SharingWorld(
        circle=circle,
        collection=collection,
        member=member,
        reader=reader,
        vendor=vendor,
        automation=automation,
        editor=editor,
        isac_org=isac_org,
        published=await _record(session, isac_org, circle, cve_status="published"),
        pre_cve=await _record(session, isac_org, circle, cve_status="pre-cve"),
        published_red=await _record(session, isac_org, circle, cve_status="published", tlp=TLP.RED),
    )


async def one_click(client, headers: dict[str, str], target: str, kind: str = "seen"):
    return await client.post(
        f"{API}/objects/{target}/contributions", json={"kind": kind}, headers=headers
    )
