"""Starting configuration for a member's TIP: the instance's addresses, filled in.

A member's first day goes wrong on the AIVS side of the configuration: the
discovery URL, the API root, which collection ids to name, and that TAXII here
needs the member's client certificate. This writes those facts into the shape
each TIP expects, so the member edits two certificate paths rather than
transcribing identifiers.

It writes AIVS's side and nothing more. Connector option names change between
connector versions, so each snippet says so and names the options it fills;
the member checks them against its own connector's documentation. No secret
is ever in a snippet: certificate and key paths are placeholders the member
replaces.
"""

from __future__ import annotations

import enum
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

__all__ = ["CollectionRef", "Tip", "tip_config"]

_API_ROOT: Final[str] = "aivs"


class Tip(enum.StrEnum):
    OPENCTI = "opencti"
    MISP = "misp"
    SPLUNK = "splunk"


@dataclass(frozen=True)
class CollectionRef:
    collection_id: uuid.UUID
    title: str


_CAVEAT: Final[str] = (
    "Starting point written by AIVS: check the option names against your "
    "connector version's documentation. TAXII here requires your organisation's "
    "client certificate; replace the two paths below with yours."
)


def tip_config(tip: Tip, base_url: str, collections: Sequence[CollectionRef]) -> str:
    """The snippet for ``tip``, naming only ``collections`` (those the caller may read)."""
    base = base_url.rstrip("/")
    return _WRITERS[tip](f"{base}/taxii2/", f"{base}/taxii2/{_API_ROOT}/", collections)


def _opencti(discovery: str, api_root: str, collections: Sequence[CollectionRef]) -> str:
    names = ",".join(f"{_API_ROOT}.{c.collection_id}" for c in collections) or "(none readable)"
    return (
        f"# OpenCTI TAXII 2.1 connector (environment).\n# {_CAVEAT}\n"
        f"# API root: {api_root}\n"
        f"{_titles(collections)}"
        f"TAXII2_DISCOVERY_URL={discovery}\n"
        "TAXII2_V21=true\n"
        f"TAXII2_COLLECTIONS={names}\n"
        "TAXII2_VERIFY_SSL=true\n"
        "TAXII2_INTERVAL=1\n"
        "TAXII2_INITIAL_HISTORY=24\n"
        "# The client certificate: the option names depend on the connector\n"
        "# version; the values are your organisation's certificate and key.\n"
        "# /path/to/your-org-client.pem\n"
        "# /path/to/your-org-client.key\n"
    )


def _profile(tool: str, discovery: str, api_root: str, collections: Sequence[CollectionRef]) -> str:
    """The values any TAXII 2.1 client needs, for a TIP whose input format varies."""
    urls = "".join(
        f"collection_url = {api_root}collections/{c.collection_id}/objects/\n" for c in collections
    )
    return (
        f"# {tool}: the values your TAXII 2.1 client or add-on needs.\n# {_CAVEAT}\n"
        f"{_titles(collections)}"
        f"discovery_url = {discovery}\n"
        f"api_root = {api_root}\n"
        "taxii_version = 2.1\n"
        f"{urls}"
        "client_certificate = /path/to/your-org-client.pem\n"
        "client_key = /path/to/your-org-client.key\n"
        "verify_server_certificate = true\n"
    )


def _misp(discovery: str, api_root: str, collections: Sequence[CollectionRef]) -> str:
    return _profile("MISP", discovery, api_root, collections)


def _splunk(discovery: str, api_root: str, collections: Sequence[CollectionRef]) -> str:
    return _profile("Splunk", discovery, api_root, collections)


def _titles(collections: Sequence[CollectionRef]) -> str:
    """The readable collections as comment lines; a title cannot end the comment."""
    lines = "".join(f"#   {c.collection_id}  {' '.join(c.title.split())}\n" for c in collections)
    return "# Collections you can read:\n" + (lines or "#   (none)\n")


_WRITERS: Final[Mapping[Tip, Callable[[str, str, Sequence[CollectionRef]], str]]] = {
    Tip.OPENCTI: _opencti,
    Tip.MISP: _misp,
    Tip.SPLUNK: _splunk,
}
