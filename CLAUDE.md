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
uv run pip-audit --skip-editable --strict
uv run alembic -c packages/aivs-server/alembic.ini check     # no model/migration drift
uv run pytest -q
```

`azure-pipelines.yml` runs the same set in the same order. Fast checks first, so
a formatting mistake fails in a minute rather than after the full suite.

**Coverage is instrumented for greenlet.** `[tool.coverage.run]` sets
`concurrency = ["greenlet", "thread"]`. Without it coverage.py loses its trace
function across SQLAlchemy's greenlet switches and records only statements
containing an `await` — understating the total by about 8 points and claiming
whole loops never ran in tests that demonstrably exercise them. It put CI below
its own `fail_under` gate for a reason nobody would have guessed from the
report, and the natural response to a gate that is red for an invisible reason
is to lower the gate. Do not remove it.

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

---

## 8. Comments and commit messages

Comments say **why**, never what. The bar: would this sentence still be worth
reading in a year, to someone who can already read the code? If it restates the
line below it, delete it.

Commit messages describe the change and the reasoning, and name defects found
along the way — including ones introduced earlier in the same session. That
history is how the next person learns what is fragile here.
