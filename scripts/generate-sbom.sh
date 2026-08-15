#!/usr/bin/env bash
# =============================================================================
# Generate a CycloneDX SBOM for the AIVS server.
#
# An ISAC deploying this will be asked for a software bill of materials by its
# own third-party risk function, and by every member firm that assesses it. This
# produces one that is *true of what ships* rather than of a developer's working
# tree:
#
#   * built from the committed lockfile with --frozen, so it cannot silently
#     resolve something newer than CI verified;
#   * runtime dependencies only -- pytest and ruff are not in the deployed
#     image and must not appear in its bill of materials;
#   * generated from an installed environment rather than parsed out of a
#     requirements file, because that is what carries licence metadata and a
#     real dependency graph.
#
# The root component is injected afterwards. cyclonedx-py describes the
# environment it inspected and has no way to know which product that environment
# *is*, so without this the document is an inventory rather than an SBOM of
# anything in particular.
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUT_DIR="${1:-${REPO_ROOT}/dist}"
OUT_FILE="${OUT_DIR}/aivs-server-sbom.cdx.json"

# Built outside the repository so it is never mistaken for the working venv and
# never lands in a build context or a commit.
BUILD_VENV="$(mktemp -d)/sbom-venv"
trap 'rm -rf "$(dirname "${BUILD_VENV}")"' EXIT

mkdir -p "${OUT_DIR}"
cd "${REPO_ROOT}"

echo "==> Resolving the runtime environment from the lockfile"
# --frozen: fail rather than update the lock. An SBOM that quietly re-resolved
# would describe something no CI run ever tested.
UV_PROJECT_ENVIRONMENT="${BUILD_VENV}" uv sync --no-dev --frozen --package aivs-server >/dev/null

echo "==> Generating CycloneDX 1.6"
# --output-reproducible strips timestamps and serial numbers, so an unchanged
# lockfile produces a byte-identical document and a reviewer can diff two
# releases to see exactly what moved.
uv run cyclonedx-py environment "${BUILD_VENV}" \
    --of JSON \
    --sv 1.6 \
    --output-reproducible \
    -o "${OUT_FILE}"

echo "==> Naming the subject of the document"
AIVS_VERSION="$(uv run python -c 'import importlib.metadata as m; print(m.version("aivs-server"))')" \
AIVS_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
AIVS_SBOM_FILE="${OUT_FILE}" \
uv run python "${SCRIPT_DIR}/_sbom_root_component.py"

COMPONENTS="$(AIVS_SBOM_FILE="${OUT_FILE}" uv run python -c '
import json, os
print(len(json.load(open(os.environ["AIVS_SBOM_FILE"]))["components"]))
')"

echo
echo "SBOM written to ${OUT_FILE}"
echo "  components : ${COMPONENTS}"
echo "  format     : CycloneDX 1.6 (JSON)"
