#!/usr/bin/env bash
# The full suite in two phases: everything else on parallel workers, then the
# audit-stream ("horizon") tests serially. Same tests and coverage as a plain
# `pytest`, in a third of the time.
#
# Usage: scripts/test-parallel.sh [WORKERS] [test paths or pytest args...]
#   No paths: the whole suite, with coverage (the landing gate). With paths:
#   just those, without coverage (the inner loop).
#
# Each worker gets its own database, <base>_gw0 and so on, created by
# tests/conftest.py, because cleanup is TRUNCATE and two processes sharing one
# database block each other (CLAUDE.md section 3). The audit stream serves rows
# below the oldest transaction open anywhere on the cluster, and parallel
# workers always have one open, so those tests run alone afterwards; under a
# worker they refuse to run rather than time out.
#
# Workers are capped by free memory, because the machine is shared: a run of
# 8 beside another project's `pytest -n auto` left 600 MB free and the OS
# killed a third session's verification chain (2026-10-15). Each worker costs
# about 200 MB plus its database backends; budget 500 MB, keep 3 GB in hand,
# and refuse to start rather than run with fewer than two.
#
# Exit status is non-zero if either phase failed, or 3 if memory was too low
# to start. Coverage from both phases is combined into .coverage, ready for
# `coverage report --fail-under`.
set -uo pipefail

requested="${1:-8}"
shift || true

available_mb=$(awk '/^MemAvailable:/ { print int($2 / 1024) }' /proc/meminfo)
affordable=$(( (available_mb - 3072) / 500 ))
workers=$(( requested < affordable ? requested : affordable ))
if (( workers < 2 )); then
    echo "only ${available_mb} MB available: not starting (need 3 GB plus 500 MB a worker)" >&2
    exit 3
fi
echo "${workers} workers (${available_mb} MB available, ${requested} requested)"

# Coverage only over the whole suite: narrowed to some paths, the configured
# fail_under would fail a run whose tests all passed.
cov=(--cov=aivs_server --cov=aivs_schemas --cov=aivs_client --cov-report=)
append=(--cov-append)
if (( $# > 0 )); then
    cov=(--no-cov)
    append=()
fi
uv run pytest -q -p no:cacheprovider -n "${workers}" -m "not horizon" "${cov[@]}" "$@"
parallel=$?
uv run pytest -q -p no:cacheprovider -m horizon "${cov[@]}" "${append[@]}" "$@"
serial=$?
# Narrowed to some paths, finding no horizon test there is not a failure
# (pytest's 5); over the whole suite it is, because 40 of them exist.
if (( serial == 5 && $# > 0 )); then
    serial=0
fi

echo "parallel phase exit=${parallel}, horizon phase exit=${serial}"
[[ ${parallel} -eq 0 && ${serial} -eq 0 ]]
