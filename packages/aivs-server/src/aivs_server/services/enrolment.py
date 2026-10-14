"""Rules on what may be enrolled, shared by the API and the portal.

Both doors build the organisation from ``OrganizationCreate``; this is the
one place either asks whether the instance is ready for it, so a rule placed
here cannot be skipped by using the other door.
"""

from __future__ import annotations

from aivs_schemas.enums import OrgType

__all__ = ["enrolment_problem"]


def enrolment_problem(org_type: OrgType, *, government_receipts_policy_agreed: bool) -> str | None:
    """Why an organisation of ``org_type`` cannot be enrolled yet, or ``None``.

    A government recipient's retrieval receipts and audit rows are kept like any
    member's: a receipt proves an agency retrieved a warning at a time, which
    is a discoverable record and a records-request conversation with every
    member's counsel. The membership agreement answers that first
    (sharing-agreement-outline §10), and the ISAC records that it has by
    setting ``government_receipts_policy_agreed``.
    """
    if org_type is OrgType.GOVERNMENT and not government_receipts_policy_agreed:
        return (
            "a government organisation can be enrolled only once the membership "
            "agreement answers how its retrieval receipts are treated "
            "(sharing agreement section 10); then set "
            "AIVS_GOVERNMENT_RECEIPTS_POLICY_AGREED"
        )
    return None
