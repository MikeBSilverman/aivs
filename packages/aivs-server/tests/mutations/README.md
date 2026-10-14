# Mutation proofs

Each `.patch` here puts back a defect this repository once had, or a guard's
absence, and names the tests that must fail while it is in place.
`scripts/mutation-check.sh` applies each one, runs only its tests, requires them
to fail, and restores the tree. CI runs the set nightly
(`.github/workflows/mutations.yml`).

**Why this exists.** Every security fix here was proven by re-applying the defect
and watching a test go red, and the proof was then left in a commit message.
A proof in a commit message cannot notice when the code moves and the patch no
longer applies, or when a later edit to the test means it no longer catches the
defect. Both happen silently, and the test goes on reading as a guarantee. A
patch that is re-run turns both into a red build.

## Running

```bash
scripts/mutation-check.sh            # all of them
scripts/mutation-check.sh M17 M18    # some, by id
MUTATION_CHECK_VERBOSE=1 scripts/mutation-check.sh   # show pytest's tail for anything not killed
```

It refuses to run without `AIVS_TEST_DATABASE_URL`, and there is no default:
name a database no other run is using (CLAUDE.md section 3). The default was
`aivs_ci` until a run from one session truncated tables under another. It writes no bytecode and clears
`__pycache__` before each run, because a cached `.pyc` of the same size and
second as the previous mutation runs that mutation instead (CLAUDE.md section 2).

## Outcomes

| Outcome | Meaning | What to do |
| --- | --- | --- |
| `killed` | The named tests failed with the defect in place. | Nothing. |
| `SURVIVED` | They passed with the defect in place. | A finding: the test no longer proves what it claims. Fix the test. Never weaken the patch to make it pass. |
| `NO LONGER APPLIES` | The code it mutates has moved. | Rewrite the patch against the new code so it re-applies the *same* defect, and confirm it is killed. |
| `ERROR` | The tests could not run, for example a renamed test or a collection error. | Treated like a survivor, because it proves nothing. Fix the name or the patch. |

Before any mutation, the script runs every named test on the unmutated tree. A
test that already fails would otherwise count as "killed".

## Writing one

- One defect per patch, and the smallest hunk that re-applies it. Make it a
  diff against `HEAD`, so it applies to a clean checkout.
- Name it `M<nn>__<what-goes-wrong>.patch`, and never reuse an id.
- Give it a header above the diff, which `git apply` ignores:

  ```
  Mutation M17: the issuing CA is matched by name, not by signature
  Re-applies: 06d0d8f "Verify the issuing CA by signature, at registration and on every request"

  Expect red: packages/aivs-server/tests/unit/test_issuing_ca_pin.py::test_a_forgery_carrying_the_ca_name_is_refused
  ```

  Add one `Expect red:` line per test node, listing only tests that must fail.
  Each listed test must pass on the unmutated tree; the baseline run checks
  that.
- Prefer re-applying the defect as it was originally written over a generic
  "delete the guard". An equivalent mutant tells you nothing. For example,
  dropping the portal-session term from `_isac_human` changes nothing today,
  because a certificate-only context carries no operator roles. Re-applying
  "a certificate at the admin organisation holds every role" is the defect
  that test was written for.
