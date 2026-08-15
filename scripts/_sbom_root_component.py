"""Name the subject of a generated SBOM.

``cyclonedx-py environment`` describes the packages it found in an environment.
It has no way to know which product that environment *is*, so it leaves
``metadata.component`` unset -- and a CycloneDX document without one is an
inventory rather than a bill of materials for anything. Consumers key on that
field: it is what makes two releases of AIVS comparable to each other rather
than to an anonymous list of wheels.

The commit is recorded as a property rather than squeezed into the version, so
``version`` stays the release number a member firm sees while the exact source
remains recoverable.

Run by ``scripts/generate-sbom.sh``; reads its inputs from the environment so
the shell script stays the single place that knows the paths.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

SUPPLIER = "Aequora"
PROJECT_URL = "https://dev.azure.com/mikesilverman/AIVulnSharing"


def main() -> int:
    sbom_path = Path(os.environ["AIVS_SBOM_FILE"])
    version = os.environ.get("AIVS_VERSION", "0.0.0")
    commit = os.environ.get("AIVS_COMMIT", "unknown")

    document = json.loads(sbom_path.read_text(encoding="utf-8"))

    document.setdefault("metadata", {})["component"] = {
        "type": "application",
        "bom-ref": f"pkg:pypi/aivs-server@{version}",
        "name": "aivs-server",
        "version": version,
        "description": (
            "AIVS pre-CVE AI vulnerability sharing server: TAXII 2.1 endpoints, "
            "native API, and analyst portal"
        ),
        "purl": f"pkg:pypi/aivs-server@{version}",
        "supplier": {"name": SUPPLIER, "url": [PROJECT_URL]},
        "licenses": [{"license": {"id": "Apache-2.0"}}],
        "properties": [
            {"name": "aivs:source:commit", "value": commit},
            # Says out loud what this document does and does not cover. The
            # container also carries a Debian base layer, which a Python
            # environment scan cannot see and which a reviewer must not assume
            # is absent just because it is not listed here.
            {"name": "aivs:sbom:scope", "value": "python-runtime-dependencies"},
        ],
    }

    sbom_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
