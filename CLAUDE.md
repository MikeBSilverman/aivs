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
uv run alembic -c packages/aivs-server/alembic.ini check     # no model/migration drift
uv run pytest -q
gitleaks dir . --config .gitleaks.toml    # before any commit that adds files
```

`azure-pipelines.yml` runs the same set in the same order. Fast checks first, so
a formatting mistake fails in a minute rather than after the full suite.

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

**Semgrep defaults to git-tracked files only.** Run locally over a working tree
with new files in it, it skips exactly the code you just wrote and reports
clean -- which reads as "reviewed" and is not. `--no-git-ignore` is in the gate
so a local run means what a CI run means. The same shape as the `pip-audit`
flags above: an option whose default quietly narrows what a security gate
covers, while the output still says "completed successfully".

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

**Suppressions are arguments, not annotations.** A `noqa`, `nosec`, or
`type: ignore` needs a comment saying why the rule does not apply here. If the
honest answer is "the rule is right but fixing it is work", fix it. The one
standing exception is `bind_host` in `config.py`, which is argued in place.

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

**Never point an analysis or review process at `aivs_test`.** A single read
query that leaves its transaction open holds locks the suite needs. If a review
needs database facts, give it its own database or have it compile SQL offline:

```python
str(query.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
```

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

**Two descriptions of one thing will drift.** The STIX extension is described by
both a JSON Schema and a `stix2` registration; they diverged within a day. A
test now asserts they enumerate the same properties. Any time you write a second
description of something, write the test that pins them together.

**Version resolution is scoped to what the caller can see.** `match[version]=last`
resolves the latest *visible* version. Resolving globally then filtering would
return nothing for an object whose newest version is withheld — from which the
caller infers that it exists.

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
(an `identity` SDO) is refused at ingest rather than stripped, and the residual
limit is documented rather than papered over.

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

**"Permit only dev", never "deny only production" — and that includes the docs.**
`show_docs = not settings.is_production` meant a staging instance, which for an
ISAC mirrors production and holds real embargoed intelligence, served an
unauthenticated `/openapi.json` enumerating the whole admin surface. The rule
already governed the `dev_*` flags; it governs every environment branch.

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
cannot reach into a gap. Suspension and quarantine touch none of it — they are
refused per request. Anything that reads membership filters on the *open*
interval (notifications got this wrong: a former member was told about content
released after it left).

**`autoflush=False`, so flush before you query what you just changed.** The
sessionmaker disables autoflush deliberately. `activate_org` set a status and
then reconciled circle rules against it; the reconcile query read the *old*
status and matched nothing, silently. Any read that depends on a pending write
in the same transaction needs an explicit `await session.flush()`.

**An empty `ARRAY[]` has no inferable element type.** `Column != []` compiles to
an untyped `ARRAY[]` that Postgres cannot compare, so the filter matches nothing
and says nothing. Use `func.cardinality(col) > 0`.

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

Credentials for Azure DevOps live outside the repository (`~/.git-credentials-aivs`,
mode 0600); the remote URL carries no token.

---

## 7. Migrations

Autogenerate, then read what it produced. `alembic check` runs in CI and must
report no drift, so a schema that exists only because someone ran `create_all`
locally fails the build.

Replace the generated docstring with the reasoning when a migration exists for a
non-obvious correctness reason — `6439704af276` (the paging key) is the model to
follow. A reviewer should not have to reconstruct why a column exists.

**`alembic check` cannot see triggers or exclusion constraints**, and
autogenerate does not emit `ExcludeConstraint` at all. The test suite builds
its schema with `create_all` plus hand-written triggers, so tests of those
protections prove the fixture, not the migration. `tests/migrations/` migrates
a scratch database to head and asks Postgres what exists; any protection that
lives only in a migration gets an assertion there.

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

The complexity and nesting limits are *not yet gated*. Turning on `C901`
(max 10) and `PLR1702` (max 3 nested blocks, a preview rule) found seven
functions over the limit as of 2026-10-13. A gate that starts out red gets
ignored, so these should be refactored first and the gate turned on in the same
commit. Until then, these are review rules, and new code must not add to the
list.

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
  the one handler that owns the response headers (section 5).
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
