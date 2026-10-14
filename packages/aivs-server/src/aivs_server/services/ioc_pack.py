"""The IoC pack: one vulnerability's current indicators, as CSV a SOC can load.

A member's analysts load indicators into tools that are not STIX-aware -- a
SIEM lookup table, a firewall block list, a spreadsheet. The pack is a
serialiser over the objects the caller can already see (NFR-I2), so it adds no
visibility decision of its own: it is handed the gathered objects and writes
some of them out.

Two rules govern what is written:

* **Only current indicators** (SF-46). An expired indicator, or one stored
  before ``valid_until`` was required, is left out of the pack, because a pack
  is what members load into block lists and a block list has no expiry of its
  own. TAXII still serves them: a TAXII consumer reads ``valid_until`` and
  decides, and withholding objects there would break the version history.
* **Cells cannot become formulas** (SF-29). Every value is member-supplied
  text; a pattern or name beginning with ``=``, ``+``, ``-`` or ``@`` would run
  as a formula in the spreadsheet the analyst opens it in. Such a cell is
  prefixed with an apostrophe, the convention spreadsheets read as "text".
"""

from __future__ import annotations

import csv
import datetime as dt
import io
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy.ext.asyncio import AsyncSession

from aivs_schemas.enums import AckVia
from aivs_schemas.tlp import TLP_NAMES, tlp_for_marking_id
from aivs_server.audit.log import AuditAction, record
from aivs_server.auth.context import AuthContext
from aivs_server.services.guidance import is_current_indicator, provenance
from aivs_server.services.receipts import record_retrievals
from aivs_server.services.vulnerability_objects import (
    VisibleObject,
    VulnerabilityObjects,
    gather_vulnerability,
)

__all__ = [
    "IOC_PACK_COLUMNS",
    "IocPack",
    "build_ioc_pack",
    "export_ioc_pack",
    "spreadsheet_safe",
]

IOC_PACK_COLUMNS: Final[tuple[str, ...]] = (
    "vulnerability",
    "indicator_id",
    "name",
    "pattern_type",
    "pattern",
    "valid_from",
    "valid_until",
    "tlp",
    "provenance",
)

#: Leading characters a spreadsheet treats as the start of a formula. Tab and
#: carriage return are on OWASP's list too: some importers strip them and then
#: read what follows.
_FORMULA_PREFIXES: Final[tuple[str, ...]] = ("=", "+", "-", "@", "\t", "\r")


@dataclass(frozen=True)
class IocPack:
    """The CSV text and the indicators it carries, which the caller records as retrieved."""

    text: str
    indicators: tuple[VisibleObject, ...]


def build_ioc_pack(objects: VulnerabilityObjects, *, now: dt.datetime) -> IocPack:
    """The pack for one vulnerability: its current indicators, one row each, by name."""
    current = tuple(
        sorted(
            (obj for obj in objects.of_type("indicator") if _is_packable(obj.raw, now)),
            key=lambda obj: (str(obj.raw.get("name", "")), obj.stix_id),
        )
    )
    label = _vulnerability_label(objects.vulnerability.raw)
    return IocPack(_csv(_row(label, obj.raw) for obj in current), current)


async def export_ioc_pack(
    session: AsyncSession,
    ctx: AuthContext,
    vulnerability_stix_id: str,
    *,
    via: AckVia,
    now: dt.datetime,
) -> IocPack:
    """Build the pack for ``ctx`` and record that its organisation retrieved it.

    An export is a retrieval like a TAXII poll (SF-51): the receipt is what an
    auditor reads to see that the member collected a warning, and it is what
    the ``bulk_retrieval`` detection counts, so a session or certificate used
    to pull pack after pack is noticed the way a scraped feed is. The receipt
    covers the vulnerability and every indicator in the pack, and only those
    distributed to the caller: an indicator left out as expired was not
    retrieved, and an ISAC reviewer reading content it holds for triage is not
    a recipient. A receipt for the reviewer would make the ISAC look like a
    member that collected the warning, and the acknowledgment gate, which
    admits whoever has a retrieval receipt, would then let the ISAC
    acknowledge a member's submission as if it had received it.

    Does not commit: the caller commits once, so the receipt and the audit row
    land together or not at all.

    Raises :class:`~aivs_server.services.vulnerability_objects.VulnerabilityHiddenError`
    when the caller cannot see the vulnerability.
    """
    objects = await gather_vulnerability(session, ctx, vulnerability_stix_id, now=now)
    pack = build_ioc_pack(objects, now=now)
    await record_retrievals(
        session,
        org_id=ctx.org_id,
        submission_ids={
            obj.submission_id
            for obj in (objects.vulnerability, *pack.indicators)
            if obj.date_added is not None
        },
        via=via,
        actor_ref=ctx.actor_id,
        now=now,
    )
    await record(
        session,
        action=AuditAction.EXPORT_RETRIEVED,
        ctx=ctx,
        resource_type="vulnerability",
        resource_id=vulnerability_stix_id,
        details={"export": "ioc_pack", "via": via.value, "indicator_count": len(pack.indicators)},
    )
    return pack


def spreadsheet_safe(value: str) -> str:
    """``value``, made inert if a spreadsheet would read it as a formula."""
    return f"'{value}" if value.startswith(_FORMULA_PREFIXES) else value


def _is_packable(indicator: Mapping[str, Any], now: dt.datetime) -> bool:
    return not indicator.get("revoked") and is_current_indicator(indicator, now)


def _vulnerability_label(vulnerability: Mapping[str, Any]) -> str:
    for reference in vulnerability.get("external_references") or ():
        if isinstance(reference, Mapping) and reference.get("source_name") == "cve":
            return str(reference.get("external_id", ""))
    return str(vulnerability.get("name", ""))


def _tlp(indicator: Mapping[str, Any]) -> str:
    for marking_id in indicator.get("object_marking_refs") or ():
        tlp = tlp_for_marking_id(str(marking_id))
        if tlp is not None:
            return TLP_NAMES[tlp]
    return ""


def _row(vulnerability_label: str, indicator: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        vulnerability_label,
        str(indicator["id"]),
        str(indicator.get("name", "")),
        str(indicator.get("pattern_type", "")),
        str(indicator.get("pattern", "")),
        str(indicator.get("valid_from", "")),
        str(indicator.get("valid_until", "")),
        _tlp(indicator),
        provenance(indicator),
    )


def _csv(rows: Iterable[tuple[str, ...]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(IOC_PACK_COLUMNS)
    writer.writerows(tuple(spreadsheet_safe(cell) for cell in row) for row in rows)
    return buffer.getvalue()
