#!/usr/bin/env bash
#
# AIVS demonstration: an AI-discovered exploit chain moving through the system.
#
# Runs against a seeded instance and prints a narrated transcript. Intended for
# showing AIVS to ISAC leadership and prospective member firms, so it explains
# what is happening rather than only doing it.
#
# The story it tells, in order:
#
#   1. Three member firms sit in three sharing circles. One firm is deliberately
#      outside the two tighter circles.
#   2. A GSIB files a three-step exploit chain in a fictional agentic-AI runtime,
#      discovered by a model-driven harness.
#   3. The hosting ISAC validates it and releases it under a short embargo.
#   4. Before the embargo lifts, nobody can read it -- including the members it
#      was released to.
#   5. After it lifts, the two tighter circles receive it and the third still
#      sees nothing.
#   6. Retrieval receipts record who collected it and when, which is the
#      artefact a member shows their regulator.
#
# Usage:
#   demo/scenario.sh                  # against the seeded aivs_demo database
#   AIVS_DEMO_DATABASE_URL=... demo/scenario.sh
#
# Prerequisites: `uv sync` has been run, and `python demo/seed.py --reset` has
# seeded the database. This script reads the database directly rather than
# speaking HTTP, so it needs no running server, no certificates, and no network
# -- which makes it safe to run on a laptop in front of an audience.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

DB_URL="${AIVS_DEMO_DATABASE_URL:-postgresql+psycopg://aivs@127.0.0.1:55432/aivs_demo}"

# Colour only when attached to a terminal, so piping to a file stays readable.
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
    BLUE=$'\033[38;5;67m'; GREEN=$'\033[38;5;71m'; AMBER=$'\033[38;5;178m'
else
    BOLD=""; DIM=""; RESET=""; BLUE=""; GREEN=""; AMBER=""
fi

say() { printf '\n%s%s%s\n' "${BOLD}${BLUE}" "$1" "${RESET}"; }
note() { printf '%s%s%s\n' "${DIM}" "$1" "${RESET}"; }
good() { printf '%s%s%s\n' "${GREEN}" "$1" "${RESET}"; }
hold() { printf '%s%s%s\n' "${AMBER}" "$1" "${RESET}"; }

run_query() {
    # Runs one read-only query through the application's own visibility logic,
    # so what the demo shows is what a member would actually receive -- not a
    # convenient approximation written for the demo.
    AIVS_DEMO_DATABASE_URL="${DB_URL}" uv run --quiet python demo/_query.py "$@"
}

printf '%s\n' "${BOLD}AIVS demonstration${RESET}"
note "Instance: ${DB_URL}"
note "Everything below is fictional. The firms do not exist and the"
note "vulnerability is invented."

say "1. The community"
run_query community

say "2. What Meridian Global Bank filed"
run_query submission

say "3. Before the embargo lifts"
note "The content has been released to the GSIB and Section 9 circles, but its"
note "visibility timestamp is still in the future."
hold "$(run_query visibility)"
note ""
note "Nothing is gated on a scheduler having run. An embargoed object simply has"
note "a future date_added, so a scheduler that is down delays notification but"
note "cannot leak content early."

say "4. Waiting for the embargo to lift"
REMAINING="$(run_query seconds_until_release)"
if (( REMAINING > 0 )); then
    note "Releasing in ${REMAINING}s..."
    sleep "$((REMAINING + 1))"
else
    note "Already released."
fi

say "5. After the embargo lifts"
good "$(run_query visibility)"
note ""
note "Ridgeline sees nothing: it is not in either circle this was released to."
note ""
note "The hosting ISAC also sees nothing here, and that is deliberate rather than"
note "an oversight. Circle membership governs collection visibility even for the"
note "instance operator -- an ISAC that wants to read a circle joins it, visibly,"
note "so that a member's view of who receives their content is complete. The"
note "ISAC's oversight runs through the submission workflow instead, which is"
note "separately authorised and separately audited."

say "6. Who received it"
note "Simulating each member's TAXII poll, which is what writes a receipt."
run_query poll

say "7. The evidentiary record"
note "This is what an ISAC shows a regulator: we warned them, and here is when"
note "their systems collected it."
run_query receipts

say "Summary"
cat <<'SUMMARY'
  - One firm filed an AI-discovered exploit chain before any CVE existed.
  - The hosting ISAC decided what was shared, and with whom.
  - The embargo held without depending on a running scheduler.
  - Two circles received it; the third, correctly, saw nothing.
  - Collection is recorded per member, per day, as an audit trail that
    cannot be edited afterwards -- the tables refuse UPDATE and DELETE.
SUMMARY
printf '\n'
