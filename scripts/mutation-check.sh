#!/usr/bin/env bash
# Re-apply every recorded defect and confirm the tests written to catch it fail.
#
# Each security fix here was proven by putting the defect back and watching a
# test go red -- by hand, with the proof left in a commit message. A proof that
# lives in a commit message cannot notice when the patch stops applying or the
# test stops catching it, so it silently becomes a claim. This turns each one
# into a file that is re-checked: packages/aivs-server/tests/mutations/*.patch.
#
# Usage: scripts/mutation-check.sh [MUTATION_ID ...]     (default: all)
#
# Outcomes per patch:
#   killed          its named tests failed, as they must
#   SURVIVED        its named tests passed with the defect in place -- a finding
#   NO LONGER APPLIES   the code moved; rewrite the patch against it
#   ERROR           the tests could not run (collection error, test renamed):
#                   that proves nothing, so it is treated like a survivor
# Exit status is non-zero unless every patch is killed (4: refused, because a
# file it would mutate has uncommitted changes -- see below).
#
# Run it in a dedicated `git worktree` or in CI, never in a tree other sessions
# are using: while a patch is applied, its files hold the defect.
#
# Uses its own database (AIVS_TEST_DATABASE_URL, default aivs_ci): the suite's
# cleanup is TRUNCATE, and two runs sharing a database block each other
# indefinitely (CLAUDE.md section 3).

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

readonly MUTATIONS_DIR="packages/aivs-server/tests/mutations"
export AIVS_TEST_DATABASE_URL="${AIVS_TEST_DATABASE_URL:-postgresql+psycopg://aivs@127.0.0.1:55432/aivs_ci}"

# The bytecode-cache trap (CLAUDE.md section 2): Python reuses a .pyc whose
# source has the same size and whole-second mtime, so two same-size mutations
# of one file inside a second run the first one's code and credit the wrong
# test. Never write bytecode, and delete what is there before every run.
export PYTHONDONTWRITEBYTECODE=1

work_dir="$(mktemp -d)"
log="${work_dir}/pytest.log"
mutated_files=()

# Put every file the current mutation touched back exactly as it was, from a
# copy taken before the patch went on. A copy, not `git apply -R`: the working
# tree may hold uncommitted edits, and a reverse apply that half-fails would
# leave a defect in it.
restore_tree() {
    local file
    for file in "${mutated_files[@]}"; do
        cp -p "${work_dir}/orig/${file}" "${file}"
    done
    local restored=("${mutated_files[@]}")
    mutated_files=()
    # Checked against the tree, not the copies: the sums were taken from the
    # files before the patch went on.
    if ((${#restored[@]})) && ! sha256sum --quiet -c "${work_dir}/sums"; then
        echo "FATAL: could not restore ${restored[*]}" >&2
        exit 3
    fi
}

cleanup() {
    restore_tree
    rm -rf "${work_dir}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

clear_bytecode() {
    find packages -name __pycache__ -type d -prune -exec rm -rf {} +
}

tests_named_in() { sed -n 's/^Expect red: //p' "$1"; }
files_changed_by() { git apply --numstat "$1" | cut -f3; }

run_tests() {
    clear_bytecode
    uv run --frozen pytest -q -p no:cacheprovider "$@" >"${log}" 2>&1
}

select_patches() {
    if (($# == 0)); then
        ls "${MUTATIONS_DIR}"/*.patch
        return
    fi
    local id
    for id in "$@"; do
        ls "${MUTATIONS_DIR}/${id}"__*.patch
    done
}

mapfile -t patches < <(select_patches "$@")

# Every patch is applied to the working tree, so for the length of a run the
# files it touches *are* the defect. Another session reading or committing the
# same tree would see, or commit, a deliberately broken file -- which nearly
# happened when this ran in a tree shared by three sessions. So refuse to mutate
# a file that has uncommitted changes: they are someone's work in progress, and
# this tree is not a dedicated one. Run in a `git worktree` of your own, or in
# CI. MUTATION_CHECK_ALLOW_DIRTY=1 overrides, for a tree you know is yours.
if [[ "${MUTATION_CHECK_ALLOW_DIRTY:-}" != "1" ]]; then
    mapfile -t dirty < <(for patch in "${patches[@]}"; do files_changed_by "${patch}"; done \
        | sort -u | while read -r file; do
            git diff --quiet HEAD -- "${file}" || echo "${file}"
        done)
    if ((${#dirty[@]})); then
        echo "refusing: these files have uncommitted changes, so this looks like a shared tree:" >&2
        printf '  %s\n' "${dirty[@]}" >&2
        echo "run in a worktree of your own (git worktree add --detach <dir> HEAD)," >&2
        echo "or set MUTATION_CHECK_ALLOW_DIRTY=1 if this tree is yours alone" >&2
        exit 4
    fi
fi

# Baseline: every named test must pass on the unmutated tree, or a "killed"
# below would only mean "was already failing".
mapfile -t all_tests < <(for patch in "${patches[@]}"; do tests_named_in "${patch}"; done | sort -u)
echo "baseline: ${#all_tests[@]} tests named by ${#patches[@]} mutations"
if ! run_tests "${all_tests[@]}"; then
    echo "baseline FAILED -- the named tests do not pass on the unmutated tree:" >&2
    tail -30 "${log}" >&2
    exit 2
fi

failures=0
printf '%-60s %s\n' "MUTATION" "OUTCOME"
for patch in "${patches[@]}"; do
    name="$(basename "${patch}" .patch)"
    if ! git apply --check "${patch}" 2>/dev/null; then
        printf '%-60s %s\n' "${name}" "NO LONGER APPLIES"
        failures=$((failures + 1))
        continue
    fi

    mapfile -t files < <(files_changed_by "${patch}")
    rm -rf "${work_dir}/orig"
    for file in "${files[@]}"; do
        mkdir -p "${work_dir}/orig/$(dirname "${file}")"
        cp -p "${file}" "${work_dir}/orig/${file}"
    done
    sha256sum "${files[@]}" >"${work_dir}/sums"

    mutated_files=("${files[@]}")
    git apply "${patch}"
    mapfile -t tests < <(tests_named_in "${patch}")
    set +e
    run_tests "${tests[@]}"
    status=$?
    set -e
    restore_tree

    case "${status}" in
        1) outcome="killed" ;;
        0) outcome="SURVIVED"; failures=$((failures + 1)) ;;
        *) outcome="ERROR (pytest exit ${status})"; failures=$((failures + 1)) ;;
    esac
    printf '%-60s %s\n' "${name}" "${outcome}"
    if [[ "${outcome}" != "killed" && -n "${MUTATION_CHECK_VERBOSE:-}" ]]; then
        tail -30 "${log}"
    fi
done

echo
if ((failures)); then
    echo "${failures} of ${#patches[@]} mutations not killed"
    exit 1
fi
echo "all ${#patches[@]} mutations killed"
