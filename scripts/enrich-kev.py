#!/usr/bin/env python3
"""File CISA KEV status onto the ISAC's vulnerability records, as ordinary submissions.

Run by the operator, as the ISAC's automation organisation, with that
organisation's mTLS certificate:

    uv run python scripts/enrich-kev.py \\
        --kev-file known_exploited_vulnerabilities.json [--dry-run]

The KEV catalogue is a file the operator downloads from CISA beforehand. The
script makes no request to anyone but the AIVS instance, so the stack gains no
egress and the server no scheduler.

It reads the ISAC's own records from ``/api/v1/isac-records/vulnerabilities``,
which answers the automation organisation alone, newest version each, chosen
by the server by who filed them. Not over TAXII: the automation organisation
reads no circle. And not by ``created_by_ref``, which distribution sets to the
ISAC's identity on every anonymous member submission too.

For each record that carries the intelligence extension 2.0 and names a CVE
that KEV lists, the script files a newer version with ``kev_listed``, ``kev_date_added``,
``kev_due_date`` and ``kev_ransomware_use`` set. It files nothing for a record
that already says what KEV says. Each version is an ordinary submission: it is
the ISAC's own record, so ownership allows it (``services/ownership.py``); its
source is ``system``, so the AI gate applies; and an editor validates it like
anything else before any member receives it.

A record still on the 1.0 extension is reported and skipped, since 2.0 needs
fields only the ISAC's analyst can supply (affected products, discovery scope).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, TextIO

from aivs_client.config import load_config
from aivs_client.transport import AivsError, NativeClient, build_http_client
from aivs_schemas.enums import TLP
from aivs_schemas.extension.builders import (
    AIVS_EXTENSION_ID,
    AIVS_INTEL_EXTENSION_ID,
    AIVS_PROVENANCE_EXTENSION_ID,
    SERVER_WRITTEN_PROVENANCE,
    format_stix_timestamp,
)
from aivs_schemas.tlp import tlp_for_marking_id

#: KEV's ``knownRansomwareCampaignUse`` values, which the extension adopts verbatim.
RANSOMWARE_USE: Final[frozenset[str]] = frozenset({"Known", "Unknown"})


def kev_by_cve(catalogue: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    """The KEV entries by CVE id, as the extension's fields."""
    entries: dict[str, dict[str, str]] = {}
    for item in catalogue.get("vulnerabilities") or []:
        cve = item.get("cveID")
        if not isinstance(cve, str):
            continue
        fields = {"kev_date_added": item["dateAdded"], "kev_due_date": item["dueDate"]}
        ransomware = item.get("knownRansomwareCampaignUse")
        if ransomware in RANSOMWARE_USE:
            fields["kev_ransomware_use"] = ransomware
        entries[cve.upper()] = fields
    return entries


def enriched_version(
    record: Mapping[str, Any], kev: Mapping[str, Mapping[str, str]], *, now: dt.datetime
) -> dict[str, Any] | None:
    """A newer version of ``record`` saying what KEV says, or ``None`` if nothing changes."""
    extension = (record.get("extensions") or {}).get(AIVS_INTEL_EXTENSION_ID)
    if record.get("type") != "vulnerability" or not isinstance(extension, Mapping):
        return None
    cve = extension.get("cve_id")
    listed = kev.get(cve.upper()) if isinstance(cve, str) else None
    if listed is None:
        return None
    wanted = {"kev_listed": True, **listed}
    if all(extension.get(key) == value for key, value in wanted.items()):
        return None
    stamp = format_stix_timestamp(now)
    if stamp <= str(record.get("modified", "")):
        return None
    version = {key: value for key, value in record.items() if key != "object_marking_refs"}
    version["modified"] = stamp
    version["extensions"] = _without_server_review(
        {**record["extensions"], AIVS_INTEL_EXTENSION_ID: {**extension, **wanted}}
    )
    return version


def _without_server_review(extensions: Mapping[str, Any]) -> dict[str, Any]:
    """The extensions less the review an editor's validation wrote onto the record.

    That review was of the previous version. The server refuses a submission
    that carries one, and writes this version's when an editor validates it.
    """
    provenance = extensions.get(AIVS_PROVENANCE_EXTENSION_ID)
    if not isinstance(provenance, Mapping):
        return dict(extensions)
    kept = {k: v for k, v in provenance.items() if k not in SERVER_WRITTEN_PROVENANCE}
    rest = {k: v for k, v in extensions.items() if k != AIVS_PROVENANCE_EXTENSION_ID}
    if set(kept) <= {"extension_type"}:
        return rest
    return {**rest, AIVS_PROVENANCE_EXTENSION_ID: kept}


def tlp_of(record: Mapping[str, Any]) -> TLP:
    """The TLP the record was distributed at: a version is never looser (SF-49)."""
    marked = [tlp_for_marking_id(ref) for ref in record.get("object_marking_refs") or []]
    known = [tlp for tlp in marked if tlp is not None]
    if len(known) != 1:
        msg = f"{record.get('id')} does not carry exactly one TLP marking"
        raise ValueError(msg)
    return known[0]


def _still_on_1_0(record: Mapping[str, Any]) -> bool:
    extensions = record.get("extensions") or {}
    return AIVS_EXTENSION_ID in extensions and AIVS_INTEL_EXTENSION_ID not in extensions


def _file(native: NativeClient, record: Mapping[str, Any], version: dict[str, Any]) -> str:
    extension = version["extensions"][AIVS_INTEL_EXTENSION_ID]
    created = native.create_submission(
        title=f"KEV status for {extension['cve_id']}",
        summary="Filed by the KEV enrichment script from CISA's catalogue.",
        discovery_scope=extension["discovery_scope"],
        tlp=tlp_of(record).value,
        bundle={"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [version]},
    )
    native.submit(created["id"], reason="KEV enrichment")
    return str(created["id"])


def _say(line: str, stream: TextIO = sys.stdout) -> None:
    stream.write(line + "\n")


def run(args: argparse.Namespace) -> int:
    kev = kev_by_cve(json.loads(Path(args.kev_file).read_text(encoding="utf-8")))
    config = load_config(
        base_url=args.url, certificate=args.cert, private_key=args.key, ca_bundle=args.ca
    )
    with build_http_client(config) as http:
        native = NativeClient(http)
        now = dt.datetime.now(dt.UTC)
        for record in native.isac_vulnerabilities():
            if _still_on_1_0(record):
                _say(f"skipped {record['id']}: extension 1.0, which carries no KEV fields")
                continue
            version = enriched_version(record, kev, now=now)
            if version is None:
                continue
            if args.dry_run:
                _say(f"would file {record['id']}")
                continue
            try:
                _say(f"filed {record['id']} as submission {_file(native, record, version)}")
            except (AivsError, ValueError) as exc:
                _say(f"refused {record['id']}: {exc}", sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--kev-file", required=True, help="CISA's KEV catalogue, as JSON")
    parser.add_argument("--dry-run", action="store_true", help="say what would be filed")
    for name in ("url", "cert", "key", "ca"):
        parser.add_argument(f"--{name}", default=None)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
