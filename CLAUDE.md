# Working rules for AIVS

Operating guidance for anyone working in this repository, human or agent. Most
of it was learned by getting something wrong first; where that is the case the
failure is described, because a rule whose reason is missing gets dropped the
first time it is inconvenient.

Read `docs/architecture.md` for what the system *is*. This file is about how to
work on it safely.

---

## 1. Write the rule down, in the same session you learn it

**If you learn something that would change how the next person works, it goes in
this file before the session ends.** Not into a summary, not into a mental note,
not into a reply the user will scroll past — into the repository.

This is first because everything else here exists only because it was written
down, and because the alternative silently fails:

- **A session's memory does not survive it.** The next session starts with the
  repository and nothing else. A rule that lives only in a conversation is a
  rule that will be rediscovered by repeating its failure.
- **A delegated agent inherits nothing but its prompt.** Not the context, not
  the conventions, not the three things that already went wrong today. If a
  constraint matters to work you hand off, it has to be in the repo or in the
  prompt — assuming it carries over is how the same mistake gets made twice in
  parallel.
- **A human joining later reads files, not history.** Commit messages help, but
  nobody greps six months of them before making a change.

### What belongs here

The test: **would someone waste time, or take a risk, rediscovering this?** If
yes, write it. Specifically —

- a failure mode with a non-obvious cause (the test-database hang; the coverage
  instrumentation)
- a rule whose reason is not visible from the code (why `404` and not `403`)
- a convention that is easy to violate accidentally (locking on mutating routes)
- a tool or environment behaviour that surprised you (routers not flattening;
  how reviews must be framed)

Do **not** write what the code already says. A rule restating a function's
signature is noise, and noise is what makes people stop reading the file that
contains the rules that matter.

### Where it goes

| Kind of knowledge | Home |
| --- | --- |
| How to work on this repo safely | this file |
| Why the system is shaped the way it is | `docs/` |
| Why *this line* is the way it is | a comment, at that line |
| Why *this change* was made | the commit message |
| A decision still being made | a design note in `docs/`, marked as such |

### Write the failure with the rule

Every rule below names the thing that went wrong to produce it. That is
deliberate. A rule without its reason gets deleted the first time it is
inconvenient, by someone who cannot tell whether it is load-bearing or
superstition. One sentence of "this cost us X" is what makes it survive.

Correcting an existing rule is worth as much as adding one. If something here is
wrong, or was right and no longer is, change it in the same commit as the code
that made it wrong.

## 2. Verification gates

Nothing lands without all of these passing:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy packages/aivs-schemas/src packages/aivs-server/src packages/aivs-client/src
uv run bandit -c pyproject.toml -r packages/*/src
uvx semgrep==1.173.0 scan --config p/python --config p/owasp-top-ten \
  --exclude-rule generic.nginx.security.request-host-used.request-host-used \
  --no-git-ignore --metrics=off --error packages/ demo/ scripts/ deploy/
uv export --no-emit-workspace --format requirements-txt -o /tmp/audit.txt
uv run pip-audit --strict --requirement /tmp/audit.txt
find . -name '*.sh' -not -path './.venv/*' -not -path './.git/*' -print0 | xargs -0 -n1 bash -n
find . -name '*.sh' -not -path './.venv/*' -not -path './.git/*' -print0 \
  | xargs -0 uvx --from shellcheck-py==0.11.0.1 shellcheck -S warning   # CI: the runner's shellcheck
uv run alembic -c packages/aivs-server/alembic.ini check     # no model/migration drift
uv run pytest -q --cov=aivs_server --cov=aivs_schemas --cov=aivs_client   # or, locally:
scripts/test-parallel.sh           # the same tests and coverage in a third of the time
uv run coverage report --fail-under=93 --include='*/aivs_server/auth/*,*/aivs_server/services/distribution.py,*/aivs_server/services/embargo.py,*/aivs_server/services/publication.py,*/aivs_server/taxii/queries.py'
gitleaks dir . --config .gitleaks.toml    # before any commit that adds files
```

`.github/workflows/ci.yml` runs the same set in the same order, plus zizmor over
the workflows and gitleaks over the full history. Fast checks first, so
a formatting mistake fails in a minute rather than after the full suite.

**The suite runs in parallel, except the tests that read the audit stream.**
`scripts/test-parallel.sh` runs everything on `pytest-xdist` workers, each on
its own database (`<base>_gw0`, … from `conftest.py`, for the TRUNCATE
reason in section 3), then the `horizon`-marked tests on their own. Serial
it took 20-27 minutes; parallel it takes 8, with the same 1,974 tests and the
same coverage. The audit stream serves rows below the oldest transaction open
anywhere on the cluster. Parallel workers always have one open, so six
auditor tests stalled for their full minute and failed on a timeout that
named nothing. Under a worker a `horizon` test now refuses to run, with the
instruction, rather than skip, because a skip reads as covered. Any new test
that pages the audit stream gets the marker (one, from 3b, was missed and
passed or failed on timing until T1 found it by reading). "On their own"
means alone on the *cluster*, not only within the run: another session's
suite or mutation shard holds the horizon back just as a worker does.

**The machine is shared, so a parallel run budgets memory.** Eight workers
beside another project's `pytest -n auto` left 600 MB free, and the OS killed
a third session's verification chain, which produced no result. The runner
reads `MemAvailable`, gives each worker 500 MB, keeps 3 GB in hand, and
refuses to start rather than run on fewer than two. It reads that figure
once, at start, so two runs launched together each book the same free memory:
when jobs run side by side, give each its worker count and split the budget
by hand. Before a long chain (the full mutation set, e2e), say so to the
other sessions and wait for quiet.

**What runs when.** While working: lint, types, and `scripts/test-parallel.sh
<paths>` for what changed, without coverage. To land a commit:
- every gate above, with the full suite through `scripts/test-parallel.sh`;
- every mutation patch whose `+++` target is a file the commit changes, which
  is the "run that patch in the same commit" rule below;
- e2e when compose, `deploy/` or nginx change.
A change to `conftest.py` or anything every test runs through changes every
test, so it runs the full mutation set: a fixture that starts refusing a
privilege turns proofs to ERROR anywhere. The full set runs nightly in CI
(`mutations.yml`), but only over what has been pushed. Until main is pushed,
run the full set locally before the push that would carry it.

**Shard the full mutation set, and run the horizon proofs last, alone.**
`mutation-check.sh` patches files in place, so it is serial within a tree;
run it in several detached worktrees, each with its own database and a slice
of the ids. Every patch whose "Expect red" names a `horizon` test goes in a
shard of its own that starts after the others finish. Beside another shard
that test stalls on the cluster-wide horizon and fails, and in a mutation run
a failure is a kill: the proof would pass without proving anything. (T1,
planning 3c's run.)

**A gate is its exit status, not its output.** Two sessions landed a commit
with bandit red, each having read bandit through `tail`: the last lines said
`High: 0`, and the low-severity B106 above them failed the gate with exit 1.
A summary line is the tool describing its findings, not deciding the gate.
Record each gate's exit status (`cmd; echo "exit=$?"`, or a runner that stops
on the first non-zero) and read the output only to see why.

**Audit the lockfile, not the installed environment.** The gate was
`pip-audit --skip-editable --strict`, which in a uv workspace can only ever
fail: uv installs the three workspace members as editable, and `--strict` counts
every skipped distribution as an error. It sat red without anyone noticing
because the flags read as if they cooperated. Exporting with
`--no-emit-workspace` drops our own packages — which have no advisories to check
anyway — and audits every third-party pin, so `--strict` means what it says. It
is also the same source of truth the SBOM is built from, so the set of
dependencies the gate cleared is exactly the set the SBOM describes.

**The SBOM is a release artifact, and it is reproducible.**
`scripts/generate-sbom.sh` builds a runtime-only environment from the frozen
lock and emits CycloneDX 1.6; an unchanged lockfile produces byte-identical
output, so two releases can be diffed to see precisely which dependency moved.
CI also scans the built image with syft, because a Python-environment scan
cannot see the Debian base layer and that layer is most of what a member firm's
scanner will flag. Neither document subsumes the other; publish both.

**The shell gate finds its scripts; it does not list them.** CI's shellcheck
step globbed `deploy/ca/*.sh scripts/*.sh`, so `deploy/db/init/10-app-role.sh`
(which the database container runs on its first start) and
`demo/scenario.sh` were never checked, while the step reported green. A
`find` over the tree, not `git ls-files`, so a local run covers a script not yet
committed (the semgrep lesson below).

**Semgrep defaults to git-tracked files only.** Run locally over a working tree
with new files in it, it skips exactly the code you just wrote and reports
clean -- which reads as "reviewed" and is not. `--no-git-ignore` is in the gate
so a local run means what a CI run means. The same shape as the `pip-audit`
flags above: an option whose default quietly narrows what a security gate
covers, while the output still says "completed successfully".

**Start the stack, not only the compose file.** `docker compose config` checks
syntax and merges files. It cannot show two containers competing for one
address, and the first `up` on a clean host failed on exactly that, in a file
that had passed every gate. `scripts/e2e.sh up` builds a throwaway CA and
environment and starts the real stack; run it, and `uv run pytest -m e2e` with
`AIVS_E2E_STATE` set, for any change to compose files or `deploy/`.

**Render the compose file.** `docker-compose.yml` was invalid under Compose
2.40 (`pids_limit` beside `deploy.resources.limits` is refused) for as long as
nobody here could run Docker, so every claim about the deployment stack was
untested. `docker compose config` with dummy values for the required variables
is cheap and belongs with every change to a compose file.

**Coverage is instrumented for greenlet.** `[tool.coverage.run]` sets
`concurrency = ["greenlet", "thread"]`. Without it coverage.py loses its trace
function across SQLAlchemy's greenlet switches and records only statements
containing an `await` — understating the total by about 8 points and claiming
whole loops never ran in tests that demonstrably exercise them. It put CI below
its own `fail_under` gate for a reason nobody would have guessed from the
report, and the natural response to a gate that is red for an invisible reason
is to lower the gate. Do not remove it.

**Scan for secrets before the commit, not after.** Committed history is forever
once the repository is public; a key-shaped string in it is flagged by every
scanner that ever runs, whatever the comment beside it says. The CI migration
key was a base64 literal until gitleaks found it — it is minted in-step now.
False positives go in `.gitleaks.toml` as a *rule-level* allowlist matching the
call shape, with the argument written beside it. A top-level `[[allowlists]]`
with `targetRules` parsed cleanly in gitleaks 8.28 and was silently not
applied, which is the same shape as the semgrep and pip-audit defaults above.

**A test that asserts "gone" must first assert "there".** The offboarding
test read the data inventory's operational tables and asserted the member
held none of their rows afterwards, never that it held any before. Three
tables its fixture left empty passed whatever offboarding did, and one of
them (`inbound_emails`, misclassified as operational) was not deleted at all.
An assertion of absence over a list is vacuous for every entry that started
empty; assert the list was populated, so a new entry nobody fills fails.

**A refusal test must show which check refused.** The end-to-end test for a
certificate signed by the root CA passed while the CA pin it is named for was
disabled: the certificate was not registered, so it was refused anyway. Assert
the reason (the audit row names it), not only the status.

**Destructive tooling permits only what it can prove it owns.** The e2e
`down` first refused only volumes labelled for *another* project, so it
deleted an unlabelled `aivs_pgdata`. "Fail closed by allow-list" applies to
scripts as much as to the application.

**Test a reader against the rows its writer produces.** The detection rules
read audit `details` by key and were tested on hand-built rows, so renaming
`circles` in the distribution audit row would have silenced a rule with the
suite green. The same review found the heartbeat tests registering names by
hand (deleting a background job changed nothing), and migration tests that
checked a trigger's *name* (a trigger that raised a NOTICE passed). Drive the
real write, then read; attempt the operation the control refuses. A seeded
row is a hand-built row too: the KEV script's tests seeded the ISAC's record
straight into the database, without the review stamp validation writes, so a
script that would have been refused on every real record passed. Where a
fixture must seed, build the row with the writer's own functions.

**A threshold event is gated on the value the reader is shown.** Telemetry
withheld counts below k, and a "first retrieval" milestone fired at a raw
count of 1, so a milestone that never arrived said "exactly zero" where the
count said "fewer than 5". Silence is observed too. And when a rule is
tightened (one-sided suppression made two-sided), re-run the older guard's
mutation: the new rule can make it redundant, and its test then asserts nothing.

**Mutation proofs are files, and they are re-run.** Each security fix's
"re-apply the defect" proof is a patch in `packages/aivs-server/tests/mutations/`,
naming the tests it must turn red. `scripts/mutation-check.sh` applies each one,
runs those tests, and restores the file by checksum; CI runs it nightly. Three
rules: a patch re-applies *the defect as it was written*, not merely a deleted
guard (deleting one term of `_isac_human` survived because another term covered
for it, which is a test gap, not a pass). If you change a line a patch touches,
run that patch in the same commit; when it no longer applies, rewrite it against
the new code, and never delete it to make the run green. And run it only in a
worktree of your own or in CI: while a patch is applied, its files hold the
defect, and the script refuses a tree whose target files have uncommitted
changes. A patch naming several tests must turn each of them red: the
runner once took pytest's exit status as the verdict, so one red test credited
the patch with all of them, and a patch carrying two defects (M412) was
"killed" by the half that belonged to another patch. Turning that on found two
more patches (M03, M11) naming a test that pinned a different control.

**A mutation proof can run the wrong code.** Python reuses a cached `.pyc`
when the source's mtime (whole seconds) and size match. Two mutations of one
file that change it by the same number of bytes within the same second run the
*first* mutation's bytecode, and the result is credited to the wrong test.
Found while proving the client tests: a "caught" mutation was really the
previous one. Run mutation proofs with `PYTHONDONTWRITEBYTECODE=1` and delete
the module's `__pycache__` before each run.

**A mutation must leave every name a fixture patches.** M987 deleted an
import that the 3c `logins` fixture monkeypatches, so its tests errored at
setup and never ran the defect; the strict runner listed them as "still
green", and the proof looked like a gap in the tests rather than in the
patch (T1, slice 3c). Move the call, keep the name: a patch re-applies the
defect, and a fixture failing is not the defect.

**A proof is retired only with the code it guards, and never for being
covered.** When a commit removes a code path by design, its proof goes in
that commit, the message says why and names the proof that still covers the
property, and the id stays unused (M1089, slice 3g). A proof that survives
because another guard covers for it is the other case, and it is not
retired: it is a test gap, closed by a test that shows which check refused
(M600 and M1089 in slice 3f, where the first draft called the proof invalid).

**A mutation's defect must not depend on row order, or on where an object
was loaded.** M1074 took `select(Operator).limit(1)` with no ORDER BY and was
killed in one run and survived the next; it now takes the oldest by a stated
order. M1102 and M1103 moved a service call onto the member session while
the row stayed loaded on the staff one, and an ORM object flushes on the
session that loaded it, so the defect never reached the login it was meant
to test. Move the load with the write (T1, slices 3e-3g).

**Run the full suite before a commit's mutation proofs.** A proof's baseline
is its named tests passing on the unmutated tree; 3e's first mutation run
failed its baseline on a test the targeted run had not included
(`test_one_clock`'s allow-list), and an hour of shards was spent finding a
failure the suite would have shown in eight minutes (T1).

**A patch that applies is not a patch in the right place.** Three ways a
proof stops proving what it names while still applying cleanly:

- **A moved patch can land on a lookalike line.** M944 was regenerated onto a
  different `database_now` call with identical surrounding lines, applied
  cleanly, and showed up only as PARTLY KILLED. After moving or regenerating
  a patch, diff its new hunk against the old one, and read PARTLY KILLED as a
  placement problem before a test problem.
- **A removed function lives on in the patches.** When you rename or delete
  a function, grep `tests/mutations/` for it as well as the source. A patch
  that *adds* a call has no context line to break: M606 still imported a
  function the lists refactor deleted, applied, and reported ERROR at
  collection, which proves nothing.
- **A defect has to reach what the test reads.** M984 wrote the owner tag
  into a template variable the page never received, so it rendered empty
  and survived.

**Never change a tree while a verification job runs on it.** The result then
describes neither the old tree nor the new one. Stop the job, change the
tree, and start the job again from the new commit.

**`caplog.text` is only the messages.** A test that asserts "no content in the
logs" against `caplog.text` passes while content sits in a structured field
(`extra=`), which is where this codebase puts everything. Assert over the
records' fields -- `str(vars(record))` -- or the check is decorative. Found by
a mutation that logged the query string and passed.

**`ruff check --fix` with a narrowed `--select` deletes valid suppressions.**
RUF100 then counts every `noqa` for a rule outside the selection as unused and
strips it: an import-order fix removed `# noqa: F401 - registers every table`
and `# noqa: S506 - SafeLoader subclass`. Fix import order with `--select I`
alone, and never pair RUF100 with a narrowed selection.

**A requirement row is a claim, so it carries its test's id.** Rows in
`docs/security-requirements.md` and `docs/non-functional-requirements.md` land
only with `@pytest.mark.requirement("<id>")` on a collected, unskipped test, and
`tests/test_requirements_pinned.py` checks both directions. When a later phase
extends a row, rewrite its text in the same commit as the new test, not before.

**Suppressions are arguments, not annotations.** A `noqa`, `nosec`, or
`type: ignore` needs a comment saying why the rule does not apply here. If the
honest answer is "the rule is right but fixing it is work", fix it. The one
standing exception is `bind_host` in `config.py`, which is argued in place. A
dismissed CodeQL or Dependabot alert is a suppression too: dismiss it with the
argument in the comment (280 characters at most) and the test that pins it, or
fix the code. The first public scan's three alerts were all false positives; the
two redirect ones were still turned into a checked helper
(`redirect_within_portal`) before the residual one was dismissed.

---

## 3. The test database (this has bitten us three times)

**Every concurrent test run needs its own database.**

Cleanup between tests is `TRUNCATE`, which takes an `ACCESS EXCLUSIVE` lock. Two
pytest processes against one database do not race — the second blocks on the
first *indefinitely*, and the suite appears to hang with no output and no error.
The first two times this happened it cost about fifteen minutes each, and the
second time a queued `DROP TABLE` from a stalled run corrupted the schema and
produced 122 spurious errors that looked exactly like a real regression.

```bash
# Concurrent run, or any process that is not the primary suite:
AIVS_TEST_DATABASE_URL="postgresql+psycopg://aivs@127.0.0.1:55432/aivs_ci" uv run pytest -q
```

`conftest.py` now sets a `lock_timeout` so this fails in fifteen seconds with a
message naming the cause instead of hanging. Do not remove it.

**Several sessions can share one working tree, each owning separate files**
(`terminal-*.md`, which git ignores, carry the task list). Each runs tests on its
own database: `aivs_ci` and `aivs_ci2` for the helpers. Then a green suite in
the shared tree tests everyone's uncommitted work together, not what one commit
contains. Commit by explicit path, never `git add -A`. When a file holds another
session's edits too, stage your hunk alone, by building the index copy from
`HEAD` plus your change. Then verify the commit in a clean `git worktree` of
`HEAD` before pushing. Helper sessions deliver a finished task as a patch
against a named `HEAD`, verified in a clean worktree of that `HEAD` plus the
patch alone. Patches live under `.git/` (for example `.git/aivs-patches/`),
not `/tmp`: a reboot cleared `/tmp` and took every delivered patch and
worktree with it, while commits survived. And a commit is not verified until
its run *finished*: one whose check died with that reboot carried a migration
that failed on every fresh install. Separating two sessions' hunks after the fact is how a commit
once carried another session's unfinished requirement rows. The main thread
alone orders migrations, since two sessions adding one on the same parent fork
`alembic heads` and every migrated-schema test errors. And when a run fails on
an import nobody you know of changed, check `git status` before debugging: a
shared tree can hold another session mid-edit.

**The suite connects as a superuser, which readiness refuses.** Outside `dev`
`/readyz` answers 503 while the app's connection could undo the append-only
triggers, and the suite runs as the embedded cluster's `aivs` in environment
`test`. A test that needs a ready instance takes the `safe_database_role`
fixture, which stands in for the application role at that one check; do not
make the instance `dev` instead, which changes what else the request is held to.

**Settings are session-scoped in the suite.** A module needing a different
setting overrides the `app` fixture and swaps `app.state.settings` for a
`model_copy`; overriding `settings` itself raises `ScopeMismatch`.

**The local database trusts every login; CI's checks passwords.** A test that
creates a role and connects as it passes here with no password and fails every
connection in CI (the app-role grant tests did, on a pushed main). Give such a
role a password and put it in the URL. To reproduce a CI-only database failure,
run CI's own Postgres image by digest with `POSTGRES_PASSWORD` on a spare port
and point `AIVS_TEST_DATABASE_URL` at it.

**Measure coverage on a frozen tree.** coverage.py reads the source at report
time, so a file another session edits during the run is reported against its
new text. One run in the shared tree showed `policy.py` at 35% with every test
green. Run the coverage gate in a worktree.

**Push the commit you verified, not the branch.** A worktree check of one
commit followed by `git push origin main` pushed two more commits that had
landed meanwhile, unverified. Push the SHA: `git push origin <sha>:main`. And
gate the push on the test exit status itself: `pytest ...; git push` with `;`
pushed after two failures.

**Never point an analysis or review process at `aivs_test`.** A single read
query that leaves its transaction open holds locks the suite needs. If a review
needs database facts, give it its own database or have it compile SQL offline:

```python
str(query.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
```

**One open transaction anywhere on the cluster stalls the audit stream, in
tests too.** The stream serves only below `pg_snapshot_xmin(pg_current_snapshot())`,
and that horizon is the oldest running transaction in *any* database on the
cluster. So a stream test's outcome depends on other suites' work: a defect where
the stream served back its own reads passed for a day because concurrent suites
held the horizon back, and failed every time on an idle cluster. A stream test
writes a marker and polls until the marker is served, and any loop that pages
"to the end" is bounded and fails rather than spins. In production the same fact
is residual risk R19 (runbook §9.6 says how to find the stalling connection).

Databases in use: `aivs_dev` (migrations), `aivs_test` (primary suite),
`aivs_ci` (concurrent runs), `aivs_demo` (`demo/seed.py`, which refuses to touch
the test database).

---

## 4. Delegated security review

Reviews of this codebase work well and are worth running. Two things govern
whether they succeed.

### Frame by property, not by attack

A subagent receives **only its prompt** — none of the surrounding context
establishing that this is first-party code under a defensive mandate. A prompt
written in offensive vocabulary therefore reads as context-free offensive
tasking and is declined, regardless of any "this is our own code" preamble.

Empirically, in this repository:

| Framing | Outcome |
| --- | --- |
| "Can `get_auth_context` return a context for an org the caller does not control?" | Ran, found real defects |
| "Verify this invariant holds, or show precisely where it does not" | Ran, found real defects |
| "Find injection, path traversal, header smuggling; can a CSR with CA:TRUE survive?" | Declined |

Same analysis, same findings, different wrapper. Ask whether a property holds.
Name the invariant. Say "show where this fails" rather than "break this".

Reviews of deployment and cryptographic configuration are the ones most likely
to trip on phrasing — describe them as *checking the configuration against its
own documented intent*, which is both accurate and what you actually want.

### Shard by trust surface, not by file count

The best finding of the session — a paging bug that silently dropped content —
required one reviewer holding the embargo *write* path and the paging *read*
path in view at once. Split across two agents, neither would have seen it.

Current surfaces: proxy→app identity; TAXII read path and visibility; the write
path (submission → distribution); identity lifecycle (enrolment, certificates,
circles); deployment configuration; and the test suite's own integrity.

Ask for `CONFIRMED` / `PLAUSIBLE` / `VERIFIED-SOUND` separately. The last one is
not padding — it records what was actually covered, which is how you know what
the review does *not* tell you.

---

## 5. Correctness rules with teeth

Each of these is here because the opposite was written first.

**Fail closed by allow-list.** `validate_production_posture` originally read
`if environment != "production": return` — so staging, which for an ISAC mirrors
production and holds real embargoed intelligence, skipped every safety check.
Now it exempts `dev` explicitly and holds everything else to the strict posture.
Write safety checks as "permit only this", never "deny only that".

**Keyset tiebreakers must be monotonic.** Pagination sorts on
`(date_added, seq)`. `seq` is an identity column, not the row's random UUID
primary key: within one `date_added` a random tiebreaker lets a
later-committing row sort *below* an existing cursor, and `added_after` polling
never looks backwards. The row is then never delivered — a warning a member
would swear they never received. Relatedly, `release_at` may not be backdated,
for exactly the same reason.

**A listing sorts on the key its continuation compares.** The versions
endpoint sorted on `modified` and was continued with `added_after`, which
compares `date_added`; a page cut in one order and resumed in the other skipped
a version for good. Every paged listing sorts on `(date_added, seq)`, one row
per thing listed, so `added_after`, `next` and the date-added headers all mean
the same position.

**A cursor a consumer follows pages in commit order, not insert order.** An
identity id is assigned at insert and committed whenever, so a row from a slow
transaction can commit below a cursor that has already passed it. The audit and
receipt streams page on `(xact_id, id)` and serve only below the snapshot's
`xmin`: a late row is served late, never skipped. TAXII gets the same guarantee
from the publication lock and `earliest_publication_instant`.

**A log that records its own reading must not be fed by it.** Every page of
`/api/v1/audit/events` wrote an `audit.read` row and the stream returned it, so
a client draining to empty was handed its previous read on every poll and never
finished; the suite spun for an hour at 4.7 GB. Now a page that served only
reads, or nothing, is recorded as `audit.read.quiet`, which is never served. The
instance's mode decides the rest: `condensed` (the default) serves an hourly
`audit.read.summary` per reader instead of the reads, and `full` serves each
`audit.read`. Either way the reads a poller can be served are finite, for one
poller or two reading each other's. A read is judged by the mode in force at its
own transaction, never the current one, so a change of mode re-sorts nothing
already exported. Test it by comparing what each page contained with what the
server recorded for it; waiting for 'an empty page' passes whenever the
cluster's horizon lags.

**Stamp the next millisecond, never the current one.** `added_after` is a
strict comparison at TAXII's millisecond precision, and a reader in the current
millisecond may already have reported it as `X-TAXII-Date-Added-Last`. The
publication lock orders commits; it cannot separate two stamps that truncate to
the same value. Early release learned this first and distribution did not, so
both now go through `earliest_publication_instant`.

**Visibility has one clock, the database's.** `date_added`, a reader's "now",
the cursors readers issue and the edges of a membership interval are all
compared with one another, so all of them come from `db.clock.database_now`
(read after the lock the comparison depends on; the publication lock helpers
return it). They came from each replica's Python clock: a replica an hour fast
served embargoes an hour early and closed memberships an hour late, and a
writer behind a fast reader stamped below a cursor already issued. A new
`dt.datetime.now()` next to anything compared with `date_added` reopens that,
and one did: the portal's one-click was written after the API's was moved, and
read the app's clock again. `test_one_clock` now refuses any
`now=dt.datetime.now(...)` argument whose call is not on its allow-list with a
reason; add to the list only what decides no visibility. Residual: a step back
of the database host's own clock.

**A flag derived from a stamp is decided with the stamp, not re-read from a
clock.** "Embargoed" was `date_added > now` after `date_added` had been set a
millisecond past `now` by construction, so every immediate distribution was
recorded as an embargo, "released" by the sweeper, and announced twice. Decide
the flag where the choice is made and carry it.

**Release by the clock has no transaction to refuse in.** A timer embargo
becomes readable when `date_added` passes, with no writer present; that is what
lets the sweeper be down (NFR-A3). So any rule that must hold "at release" is
checked *before* the time arrives -- the sweeper re-checks each pending timer
every pass and holds one that fails -- and what slips through the last interval
is reported after, not silently accepted. Early release, an operator's act,
re-checks and refuses.

**A stop button stops the announcements too.** Pause hid content from every
reader, while the embargo sweeper went on releasing and the dispatcher went on
telling members "poll for submission X". Contentless still says that something
exists. Anything that acts unattended (sweepers, dispatchers, schedulers)
checks the pause itself.

**Distribution is one transaction.** `distribute_submission` deliberately does
not commit; the router commits once, covering the visibility rows, the state
change, and the audit record. A member paging concurrently must see the whole
batch or none of it.

**Mutating routes take a row lock.** `load_submission(..., for_update=True)`.
Without it, transitions are an unguarded read-modify-write and a concurrent
distribute silently overrides a submitter's withdrawal — their only stop button.

**Commit inside the `try`.** A value too long for its column means the member's
bundle is malformed, which is a 400. With the commit outside the handler the
`DataError` escapes to the catch-all and a member's typo is reported as a server
fault. Bound the values at ingest as well, so the error names the object.

**A refusal that could confirm existence is one constant string.** The
disclosure split answers an absent, an invisible and a member-owned target with
`disclosure.UNKNOWN_TARGET`, and its test compares response bodies byte for
byte. Write that pair before writing the message, or a helpful message becomes
an oracle.

**Validate-time rules live in `apply_transition`, not in a route.** The API and
the portal both reach validation through it; a rule placed in one route is a
rule the other door skips.

**A shortcut inherits every check of the path it shortcuts.** The one-click fast
lane skips the editor, not the circle's contributor role -- but as first written
it published into every circle the member could *read*, because "who may
contribute here" was enforced only in the TAXII write path. When a new path
reaches the same effect as an existing one, list the checks the old path makes
and route through them. Who may take the shortcut is an allow-list too: the
lanes refused machines and the automation type, so ISAC staff with no editor
role published in the ISAC's name, and replaced an editor's record, wherever
the ISAC held a contributor membership.

**Authorization comes before format.** The TAXII inbox first answered 415 before
its 404/403 checks. A uniform 415 is no oracle, but "refused before anything
about the resource is looked at" stops being true, and the next format check
may not be uniform. Order: who may, then the content type, then the body.

**Anything id-addressable answers 404, never 403.** Distinguishing "exists but
forbidden" from "does not exist" turns an endpoint into an existence oracle over
the whole namespace. One endpoint getting this wrong undoes the care every
sibling takes. This applies to submissions, collections, receipts, certificates.

**Refusal is surface-specific, and the difference must be proved rather than
exempted.** The machine surface returns 401; the portal redirects to sign in,
because a 401 leaves a person with nowhere to go. The authorization matrix
therefore splits by surface and asserts both, plus that no portal route serves
content or performs a write without a session. Lumping them together would have
been wrong in either direction: either the portal gets a free pass, or the API
starts redirecting.

**Timestamps round-trip exactly.** TAXII carries milliseconds; PostgreSQL stores
microseconds. Every write of `date_added` passes through
`truncate_to_taxii_precision`, or a member echoing `X-TAXII-Date-Added-Last`
back as `added_after` re-receives the last object on *every* poll.

**Moving a visibility timestamp is asymmetric.** Lowering one that is still in
the future is safe — no member's cursor can have passed it. Lowering one below
`now` is not, which is why backdating at distribution time is refused. Raising
one after release is not either, because members already hold the content. Three
directions, three different answers; the code enforces each separately and
`services/embargo.py` explains why.

**"Currently" in a doc is a claim like any other.** `open-decisions.md`
described sealed JWE payloads as the "current behaviour" for months; none
existed. That is "a model with no caller", written in prose. Before writing
"currently" or "today", grep for the code. Design docs carry a `Status:` line at
the top, and anything that mentions an unbuilt design says "designed" or
"planned".

**Refuse a reserved value before parsing it, with the text an unknown value
gets.** Converting a string to the enum and then checking membership gives two
different refusals: the enum's own for an unknown value, ours for a reserved
one. That difference tells a caller which values the server already knows. The
portal did exactly this with the reserved `DiscoveryScope` values until it was
caught.

**Docs that list an enum's values are a second description of it.** Reserving
two `DiscoveryScope` values made five docs' "there is no fourth value" false in
one commit. When an enum gains a value, even a reserved one, grep the docs for
its siblings.

**Two descriptions of one thing will drift.** The STIX extension is described by
both a JSON Schema and a `stix2` registration; they diverged within a day. A
test now asserts they enumerate the same properties. Any time you write a second
description of something, write the test that pins them together. That includes
prose: the authorization table in `docs/authz-model.md` is what a member's
counsel reads, and it showed a receipts policy two changes old until a test
started comparing it with the asserted matrix. Generate such a table from the
code's own description, then pin it.

**Version resolution is scoped to what the caller can see.** `match[version]=last`
resolves the latest *visible* version. Resolving globally then filtering would
return nothing for an object whose newest version is withheld — from which the
caller infers that it exists. An acceptance is an answer too: ingest admitted
a coordinated contribution on a vendor opinion still under embargo, which told
the member the vendor had agreed. Every input to an ingest-time decision goes
through the caller's visibility, not only the main lookup.

**A model or table with no caller is a claim the system does not keep.** The
`embargoes` table, `EmbargoUpsert`, and the `Webhook` model all existed and were
documented before anything read or wrote them — so `SubmissionDetail.embargo`
reported "no embargo" for content that was under one, and an operator checking
the obvious place got a wrong answer. Either wire it up or delete it; a schema
that describes a feature nobody implemented is worse than an absent feature,
because it reads as done.

**Unused code is untested code, and the type checker only helps once it is
called.** `session_scope` was written as an async generator without
`@asynccontextmanager`. It type-checked and linted clean for the whole time it
had no caller, and failed the moment the embargo sweeper first used it. When you
write a helper "for later", either use it now or expect it to be wrong.

**Success and failure paths must persist symmetrically.** `authenticate_operator`
committed its failure bookkeeping and left its success bookkeeping to the
caller, so a successful login did not clear the lockout counter unless session
creation also succeeded. Whenever one branch of a function commits, check what
the other branch owes.

**Anonymity is a promise the server can only partly keep.** The pipeline rewrites
`created_by_ref`; it cannot sanitise free text. Self-identifying structure
is refused at ingest and again at distribution rather than stripped: the
submitter's own `identity` SDO, and any reference to its registered identifier
outside `created_by_ref` (a `where_sighted_refs` naming itself passed until the
Phase A review). The residual limit, free text, is documented rather than papered
over.

**A rule about a type applies whether or not its extension is present.** An
indicator rule (an expiry is required) checked only when the AIVS extension was
present could be avoided by leaving the extension off. Type policy runs on the
STIX type.

**Check the property against the state, not against the request that changed it.**
`distribute_anonymously` was validated only inside the code path that stored a
bundle, so a PATCH that set the flag and carried no bundle skipped the check
entirely. If a rule is "this submission must never look like X", it belongs
wherever the submission is read or acted on — not only where the field was
written. The same check now runs at ingest *and* at distribution.

**Attribution is the server's to assign, on every path.** Ingest never looked at
`created_by_ref`, and distribution rewrote it only for anonymous submissions — so
a member could file content under a peer's STIX identity, and the named firm
could neither see nor contest it. Whenever one branch of a conditional sanitises
a field, ask what the other branch does with it.

**A flag that is stored and displayed must be enforced, or deleted.**
`TaxiiCollection.can_read` was written at creation, returned in the collection
resource, and consulted by nothing. `can_write` was advertised as true with no
TAXII write endpoint behind it. A security control that only appears in a
response body is worse than its absence, because it reads as enforced.

**Prove "never content" with a principal, not a predicate.** The auditor role
was closed in every policy predicate (`is_active` excluded it) and still read its
firm's submissions, postures and OpenVEX export, through routes that key on
`ctx.org_id` without asking policy. Adding auditor principals to the authorization
matrix found them on the first run. A role that should reach almost nothing is
refused at the door (`get_auth_context`, `current_session`) and let through by
name (`AuditorContext`), so a route written later is closed to it as well.

**Placeholders must be too short, too malformed, or too obviously fake to pass
validation.** `deploy/env.example` shipped secrets long enough to clear the
32-character minimum, and compose's `${VAR:?}` only fires on unset or empty — so
a half-edited `.env` produced a production stack running on secrets published in
this repository, with every healthcheck green. Placeholders now fail closed twice:
below the length floor, and refused by name (`REPLACE_ME`).

**Third-party convenience arguments can cancel each other out silently.**
`httpx.Client(cert=..., verify="<path>")` drops `cert` entirely — the string
branch of `create_ssl_context` returns before `load_cert_chain` is reached. The
client pinned the CA and then connected anonymously, and the only configuration
that worked was the one that dropped the pin. When two security-relevant options
interact, build the object explicitly and assert the result.

**Compose multi-value options concatenate across files; they do not replace.**
`ports:` in `docker-compose.dev.yml` *added* to the base file's mapping rather
than overriding it, so the dev stack published a privileged port on every
interface. Use `!override`, and verify with `docker compose config`.

**A runbook procedure is an interface; changing what it drives breaks it.**
Moving the key-encryption key into a file was tested in code and left runbook
§7.4 telling operators to set the key in the environment, which the app now
refuses. That would have stopped the instance from starting in the middle of a
rotation after a suspected key disclosure, which is exactly when a rotation
happens. Compose also had no way to mount a previous key. The steps that matter
in an incident get a test that reads the runbook and the files it names
(`test_deployment_contract.py`).

**"Permit only dev", never "deny only production" — and that includes the docs.**
`show_docs = not settings.is_production` meant a staging instance, which for an
ISAC mirrors production and holds real embargoed intelligence, served an
unauthenticated `/openapi.json` enumerating the whole admin surface. The rule
already governed the `dev_*` flags; it governs every environment branch.

**Record the address the proxy saw, not the TCP peer.** Behind nginx the peer
is always nginx, so `audit_log.source_ip` held the proxy's address on every
row, and the `auth_failure_burst` detection grouped every member's failures as
one "prober" named after our own proxy. `request_source_ip` reads `X-Real-IP`
only when the proxy check passes; the peer is for the proxy check and nothing
else. An abuse test written as the attacker's sequence found it. The unit
tests for the rule had used synthetic audit rows and could not.

**A `getattr(obj, "name", None)` of a value nobody writes never fails.** The
403 handler read `request.state.auth_context` to say who was refused; nothing
set it, so every `authz.denied` row had no actor and the runbook's weekly
"denials from one org" review was impossible. It type-checked, linted and
passed every test, because the test asserted the 403 and not the row. When a
handler reads state by name, a test asserts the value arrived.

**Responses that skip the middleware stack still need its headers.** Starlette
routes the `Exception` handler to `ServerErrorMiddleware`, *outside* the user
middleware — so 500s carried no CSP, no `no-store`, and no correlation id. If a
handler is registered for `Exception`, it is responsible for its own headers.

**Store at the precision you advertise.** `date_added` was truncated to
milliseconds and `modified` was not, so the manifest advertised a version string
that `match[version]` — which compares for exact equality — then matched nothing.
Two descriptions of one timestamp will drift; make them one.

**Adding someone to a group grants participation, not the archive.**
`visible_content_clause` bounds visibility by `circle_memberships.joined_at` as
well as by circle. Without that term, adding an organisation to a circle handed
them every object ever distributed there — years of other firms' embargoed
content, retroactively, in one call. `joined_at` is a column of its own rather
than a reading of `created_at`, because it is settable: an organisation re-added
after an administrative mistake must be able to keep the history it legitimately
had, and a column that always means "now" would push operators into editing the
database. This is also what made rule-based membership safe to build at all.

**A membership is an interval, and status is not membership.** Suspension used
to delete rule-managed rows; reactivation re-created them with `joined_at =
now()`, so a lapsed renewal silently cost a member years of a circle's back
catalogue. Removal deleted the row too, so the rule quietly reinstated firms an
operator had taken out. Now leaving closes `[joined_at, left_at)` and records
`ended_by`; rejoining opens a new interval; visibility is the union of the
intervals; a GiST exclusion constraint forbids overlap, so a `joined_at` repair
cannot overlap an earlier interval. The constraint does not stop a start moving
*earlier into the gap* after an earlier interval -- adjacent ranges do not
overlap -- and that handed over exactly what a "new interval" reconnection had
withheld. So `add_circle_members` refuses any earlier start for an organisation
that has left the circle before; a backdating repair is for one that never
left. Suspension and quarantine touch none of it — they are refused per
request. Anything that reads membership filters on the *open*
interval (notifications got this wrong: a former member was told about content
released after it left).

**Every writer of a state goes through the one function that knows all of its
states.** Activate and suspend were written twice (API and portal) before
quarantine existed, and each set the new status whatever the old one was. So
"activate" returned a quarantined member to service with no fresh certificate,
no backlog decision and no reconnection record. Adding a state means finding
every writer of the column; one writer makes that a single place.

**A row lock does not refresh what the session already holds.** With
`expire_on_commit=False`, `session.get(..., with_for_update=True)` and a
locking `select` return the identity-map copy loaded earlier in the request,
not the row they just locked. A self-quarantine read its own org as ACTIVE
after the ISAC had suspended it, and wrote QUARANTINED over SUSPENDED. Every
locked load passes `populate_existing=True`. And a test of a stale read must
hold a reference to the first load: the identity map is weak, so an unreferenced
object is collected and reloaded fresh, and the test passes against the bug.

**`autoflush=False`, so flush before you query what you just changed.** The
sessionmaker disables autoflush deliberately. `activate_org` set a status and
then reconciled circle rules against it; the reconcile query read the *old*
status and matched nothing, silently. Any read that depends on a pending write
in the same transaction needs an explicit `await session.flush()`.

**`with_for_update(key_share=True)` is not a share lock.** SQLAlchemy renders
it `FOR NO KEY UPDATE`, which is exclusive and conflicts with itself; `FOR KEY
SHARE` needs `read=True` as well. The webhook lock was written the first way
under a docstring saying readers never wait for each other, and every
notification to one member queued behind every other until slice 3c recorded
162 of them. Assert the compiled SQL, not the keyword.

**An INSERT-only grant needs `implicit_returning=False`.** SQLAlchemy appends
`RETURNING id` to every insert, even a Core one, and Postgres refuses
RETURNING without SELECT. A table the member login may write but not read
sets it, and the login gets USAGE on the table's sequence (slice 3c).

**`ON CONFLICT` with a named target needs SELECT on the target's columns.**
The member's retrieval receipt was an INSERT ... ON CONFLICT ON CONSTRAINT
... DO NOTHING, and once the member login lost SELECT on `acknowledgments`
the insert itself was refused (slice 3e). An INSERT-only table uses `DO
NOTHING` with no target, which is safe only while every other unique key is
one a caller cannot repeat; and SQLAlchemy then reports `rowcount` as -1, so
nothing may depend on the count.

**A test that records an allow-list as expected cannot judge it.** The member
login could read every operator's Argon2id password hash, ISAC staff
included, for two slices, while the grants classification test was green:
it pinned SELECT on `operators` as intended. T1 found it by reading
`MEMBER_GRANTS` against the operators model while planning 3e. A
classification test proves the database matches the list; only reading each
entry against what the path needs proves the list is right. Do that for
every grant a slice keeps, not only the ones it adds.

**An empty `ARRAY[]` has no inferable element type.** `Column != []` compiles to
an untyped `ARRAY[]` that Postgres cannot compare, so the filter matches nothing
and says nothing. Use `func.cardinality(col) > 0`.

**`col.not_in(<empty>)` matches every row.** A mutation meant to make automation
"own everything" returned an empty owner set; every id became foreign, the
refusal still fired, and the mutation survived with no test gap at all. When a
mutation survives, first check that the defect it writes actually runs.

**Stored ciphertext says how it was made.** Every value `auth/secretbox.py`
writes carries a format version, an algorithm id and a key fingerprint. That is
what makes changing the cipher or the key a re-wrap run at leisure
(`rewrap_secrets`) instead of a migration run on the day something forced the
change. A format that omits them makes the first choice permanent, and the cost
is invisible until it is urgent. The same applies to anything else durable we
sign, wrap, or derive: name the parameters in the artefact. Algorithm ids are on
disk in deployments we do not control — never renumber or reuse one.

**A Pydantic "after" validator's return value is not re-validated.** The
key-encryption-key check started as one validator over both the required key and
the optional previous one, mapping an empty string to `None` because that is how
compose and Kubernetes spell "unset". For the *required* field that would have
silently stored `None` — pydantic accepts an after-validator's return without
re-checking the declared type — turning a startup failure into an
`AttributeError` at first use. Never let a shared validator widen a required
field's domain; split it, and let the strict field stay strict.

**A value bound to a row id must be built after the id exists.** SQLAlchemy
applies `default=uuid.uuid4` at INSERT, not at construction, so `obj.id` is
`None` while the object is being populated. Anything sealed, signed, or hashed
against the row's identity therefore has to generate the id explicitly and pass
it in. This is invisible until the seal fails to open, which happens on a later
request, in a different module.

**Tell the operator when the thing they clicked did not happen.** Every portal
workflow failure redirected to the same page as a success, with no message. An
operator whose distribution was refused by a circle's TLP floor had no way to
know the members were never warned. Failure paths need their own outcome.

---

## 6. Secrets and key material

**Nothing cryptographic is ever committed.** `.gitignore` denies key and
certificate extensions by default, and test certificates are *generated at test
time* in `conftest.py` precisely so no pattern has to be relaxed. If you find
yourself adding a negation to `.gitignore`, stop.

The application never receives a private key. `register_certificate` takes a
certificate and derives the fingerprint itself — a caller-supplied fingerprint
that did not match would bind an identity to material nobody holds.

The repository is public on GitHub (`MikeBSilverman/aivs`), authenticated
through `gh`; no token is in a remote URL or in the repository. The old Azure
DevOps remote is kept as `azure` and no longer pushed to; its pipeline was
retired once GitHub Actions ran green.

**Workflows run with this repository's token, so they are code with
privileges.** Never `pull_request_target`: it runs a fork's code with the
base repository's token. Every action is pinned to a commit SHA with its
version in a comment (Dependabot rewrites both), every container image by
digest, `persist-credentials: false` on every checkout, `permissions:
contents: read` as the floor and restated per job, and no `curl | sh`
installer. zizmor runs in CI to hold the line.

**Base images are pinned by digest where they are named.** The Dockerfile's
bases were tag defaults behind `ARG PYTHON_IMAGE`, with the digest form
documented as a `--build-arg` that neither CI nor e2e passed -- so the image the
SBOM described was whatever the tag meant that day. The indirection also hid
the bases from Dependabot, which reads `FROM` lines literally: its docker
updater was configured and updated nothing. Digests go in the `FROM` line and
in compose's image defaults; `test_deployment_contract.py` refuses one without.

---

## 7. Migrations

Autogenerate, then read what it produced. `alembic check` runs in CI and must
report no drift, so a schema that exists only because someone ran `create_all`
locally fails the build.

Replace the generated docstring with the reasoning when a migration exists for a
non-obvious correctness reason — `6439704af276` (the paging key) is the model to
follow. A reviewer should not have to reconstruct why a column exists.

**A new enum value cannot be used in the transaction that added it.**
Migrations here share one transaction, so a later revision whose index
predicate or default names the value fails with `UnsafeNewEnumValueUsage` on
a fresh install, and passes on any instance that already had it. Run that step
in `op.get_context().autocommit_block()` (`219524b682c5`).

**An enum value is a migration, and `alembic check` does not see it.** The suite
builds its schema from the Python enums, so a value added without
`ALTER TYPE ... ADD VALUE IF NOT EXISTS` passed every gate and would have failed
on the first production write. `tests/migrations` now compares every Postgres
enum type's labels with its Python enum.

**`alembic check` cannot see triggers or exclusion constraints**, and
autogenerate does not emit `ExcludeConstraint` at all. The test suite builds
its schema with `create_all` plus hand-written triggers, so tests of those
protections prove the fixture, not the migration. `tests/migrations/` migrates
a scratch database to head and asks Postgres what exists; any protection that
lives only in a migration gets an assertion there.

**The application role is granted by the migration step, and "append-only"
means "carries the deny trigger".** The shipped stack connected the app as the
Postgres image's superuser, which owns every table and can drop the triggers,
while three docs promised a non-superuser role; nothing created one. Now
`aivs_server.db.grants` runs after every `alembic upgrade` (in `env.py`, same
transaction), grants `AIVS_APP_DB_ROLE` DML on every table, strips update,
delete and truncate from each table with an `aivs_deny_mutation` trigger, and
refuses a role that is a superuser, an owner or a member of one. A new
append-only table gets that trigger or the app can rewrite it. Test a role's
confinement by connecting as it and attempting the write, and match
"permission denied" rather than "append-only": both are SQLSTATE 42501, and
only the message shows which layer refused.

---

## 8. Code structure

This codebase gets read far more than it gets written. Reviewers, auditors at
member firms, and whoever is on call when something breaks all read it, and they
are usually reading it to answer one question: is this right? Every rule in
section 5 was a defect that sat in code someone had already read. Code that
takes effort to follow gets skimmed, and skimmed code is where defects hide.
The bar for every function: **a professional programmer new to the repository
can read it once, top to bottom, and say what it does and why it is correct.**

**One function, one job.** The single responsibility principle: a function has
one reason to change. If describing it takes "and" (validates the bundle *and*
rewrites attribution *and* records the audit row), split it. The orchestrating
function that is left should read as a list of named steps. Many of the defects
in section 5 lived in a branch nobody was looking at because it shared a
function with the branch they were looking at. Attribution was rewritten on one
path and not on the other; failure bookkeeping was committed and success
bookkeeping was not. A function with one job has fewer branches to forget.

**One level of abstraction per function.** A function either says *what*
happens (`check_tlp_floor`, `record_visibility`, `commit`) or *how* (building
the query, walking the bundle, formatting the header). It should not do both. If
a policy decision sits next to string slicing or raw SQL construction, move the
mechanics into a named helper. The reader can then check the policy without
parsing the mechanics, and check the mechanics without keeping the policy in
mind.

**Keep nesting shallow. Three levels is the ceiling.** Use guard clauses and
return early. Pull loop bodies out into functions, and replace `if` ladders
with lookups. Every level of nesting is another condition the reader has to
keep in mind to know when a line runs, and the line nested five levels deep is
the one nobody checks. In a fail-closed codebase this matters even more: a guard
clause at the top (`if not caller_can_see(obj): raise NotFound`) can be checked
at a glance, while the same refusal buried in an `else` four levels down cannot.

**Keep cyclomatic complexity at 10 or below per function.** That is
mccabe's default, and the point past which a function cannot be covered by a
readable set of tests. Branch count, statement count and return count are already
gated by ruff's `PL` rules. A function that needs a suppression to pass them
needs splitting, not a suppression (section 2: suppressions are arguments). The
one documented exception is type-dispatch and state-machine functions, for
which `max-returns` is raised in `pyproject.toml` with its reason.

Both limits are gated: `C90` (max-complexity 10) and `PLR1702` (max 3 nested
blocks) are in `pyproject.toml`. `PLR1702` is a ruff *preview* rule, so lint
preview is on with `explicit-preview-rules`, which enables preview for the
rules named and nothing else. Check a gate fires by giving it something to
refuse: a probe passed with `--select` on the command line, which replaces the
configured selection, and reported nothing. The seven functions over the limits
on 2026-10-13 were refactored first, so the gates started green.

**Name things positively.** Use `is_visible`, `has_session`, `allow_docs`,
`include_withdrawn`. Do not use `is_not_visible`, `no_session`,
`disable_docs`, `skip_withdrawn`. Negation belongs at the use site, where it
reads once (`if not is_visible`), and not in the name, where it reads twice
(`if not is_not_visible`). This is not just style. `show_docs = not
settings.is_production` was a negative condition that read as "development only"
and actually meant "everything except production". That served the staging
instance's admin surface to anyone who asked (section 5). A positive allow-list
name (`docs_enabled = settings.is_dev`) states the condition that grants access,
which is the only condition a fail-closed reader needs to check. The same
applies to booleans in configuration, database columns and function parameters.

**Names say what, at the level the caller works at.** A function is named for
its effect (`distribute_submission`, `resolve_latest_visible_version`), not its
mechanism (`process`, `handle`, `do_update`). A variable is named for what it
holds, not its type (`embargoed_ids`, not `id_set`). If a name needs a comment
to explain it, rename it.

**Write for the person debugging it.**

- Bind intermediate results to named variables rather than nesting calls three
  deep, so a breakpoint or a log line has something to show.
- Raise as close to the cause as possible, with an exception that says which
  object and which rule. "TLP floor AMBER refused RED content in circle X" can
  be acted on; "invalid submission" cannot.
- Log decisions, not just events. "distribution refused: TLP floor" is worth
  more at 3 a.m. than "distribute called". Carry the correlation id, and keep
  content out of logs (see section 5 on what the server can keep private).
- Prefer pure functions for logic, with I/O at the edges. A function that takes
  values and returns a value can be tested and debugged in a REPL. A function
  that takes a session and commits cannot.

**Refactoring is not a licence to change behaviour.** Splitting a function that
enforces a section 5 rule is exactly when the rule gets lost: the lock moves
into a helper that one caller no longer calls, or the commit ends up outside the
`try`. Refactor with the tests green before and after, and keep the security
property's check in one place that the new structure obviously routes through.

**Practices, each with the failure it prevents.**

- **Parse, don't validate.** Turn input into a typed object once, at the
  boundary, and pass the object. A function that re-checks a string it was
  handed will one day be called from the one place that forgot to.
  `DiscoveryScope` is the model.
- **Make illegal states unrepresentable.** A state machine is an enum plus a
  transition table in `aivs-schemas`, never a set of booleans that can both be
  true. The submission machine is the model.
- **Immutable by default.** `frozen=True` for values; never mutate an argument.
  `AuthContext` being frozen is why the authorization matrix means anything.
- **Dependencies point inward.** `services/` import `db/` and `auth/`; routers
  import `services/`; nothing in `services/` imports FastAPI. A service that
  takes a `Request` cannot be tested without one.
- **Take what you need, not where to find it.** Pass the setting, not
  `settings`; pass the org, not a session plus an id to look it up — except
  where the row lock is the point, and then say so.
- **Explicit over implicit for anything security-relevant.** No default values
  for `for_update`, `anonymous`, `expires_at`; the caller states the choice
  where a reviewer reads it.
- **Exceptions are typed and raised near the cause.** `except Exception` only in
  the one handler that owns the response headers (section 5), and around a
  parser fed untrusted bytes whose failures are not ours to enumerate:
  `email_intake._readable`. The standard library's email parser raised
  `AttributeError` for `From: x:;y`, and an intake catching only the
  errors it expected left that message first in the inbox, stopping every
  run for every member (T1's review of O3). Catch it there, call the input
  unreadable, and record nothing else about it.
- **Time is injected.** A function that reads the clock takes `now` from its
  caller, so embargo and membership tests are exact.
- **Tests state the property.** One behaviour per test, named for it. Prove the
  test can fail by re-applying the defect; a test that passes either way
  asserts nothing, and this suite has contained several.
- **No speculative generality.** No base class with one subclass, no registry
  with one entry, no helper or column "for later" — section 5 records what each
  of those cost.
- **Delete, don't comment out.** Ruff's `ERA` is on; git holds the history.
- **A commit does one thing.** Refactor, fix and feature are separate commits,
  so a security fix can be read alone and reverted alone.

---

## 9. Comments and commit messages

Comments say **why**, never what. The bar: would this sentence still be worth
reading in a year, to someone who can already read the code? If it restates the
line below it, delete it.

Commit messages describe the change and the reasoning, and name defects found
along the way — including ones introduced earlier in the same session. That
history is how the next person learns what is fragile here.
