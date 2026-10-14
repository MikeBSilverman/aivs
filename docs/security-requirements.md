# Security requirements

Each row is a security property the system holds today, together with the
tests that prove it. A row lands in the same commit as its test, never
before: a requirement listed without a test reads as enforced and is not
(CLAUDE.md §5, "A flag that is stored and displayed must be enforced").

Every id here is applied as a `requirement` marker on at least one collected
test, and every marker names a row here.
`tests/test_requirements_pinned.py` checks both directions, so deleting or
skipping the last test that pins a row fails the suite. That check is NFR-M3
in [`non-functional-requirements.md`](non-functional-requirements.md).

Ids come from the build plan's security findings and are stable. They are not
contiguous, because a row lands only with its phase. Where a row's full
resolution spans phases, the row states the part that is pinned today and
names the phase that extends it.

| Id | Requirement | Why | Pinned by | Since |
| --- | --- | --- | --- | --- |
| SF-6 | A submitter cannot claim an ISAC review. An inbound object whose provenance extension sets `human_reviewed_by_ref` or `reviewed_at` is refused at ingest; those fields are the ISAC's to write when it validates. Deriving the source type from the principal, so a machine identity cannot file as a person, extends this in phase E. | A reviewer field in the payload would let content reach a member labelled as human-reviewed when nobody at the ISAC looked at it, and the AI gate relies on that label. | `aivs-schemas/tests/test_extension_2_0.py`, `unit/test_index_columns.py` | E |
| SF-10 | Publication order equals commit order. A second distribution, an early embargo release, and a read that issues a paging cursor each wait for a publication still in flight. | A cursor issued past a batch that commits later skips that batch for good: a warning the member never receives. | `unit/test_publication_lock.py` | A |
| SF-24 | A bundle is accepted whole or not at all. One object that fails validation, including on its discovery scope, refuses every object in the bundle. | A partly stored bundle distributes objects whose context was refused, and the submitter cannot tell which half reached the circle. | `unit/test_disclosure_scopes.py` | D |
| SF-42 | Editorial control is human-only. The ISAC's machine certificate alone neither validates nor enrols, and membership staff never read what members filed. | A machine identity that can distribute is a key whose theft publishes to every member, and the host holds the CA that issues it. | `unit/test_isac_roles.py` | A |
| SF-43 | Circle membership is a set of intervals. A rejoining member reads both of its intervals and nothing distributed in the gap, and intervals cannot overlap, in the fixture schema and in the migrated one. | A single join time handed a rejoining member everything distributed while it was out. | `unit/test_membership_intervals.py`, `migrations/test_migrated_schema.py` | A |
| SF-44 | Naming an anonymous submitter is its own audited editorial action, with a reason, distinct from routine review. | Without it, every ISAC reader saw the identity in an ordinary read, and the anonymity promise depended on nobody looking. | `unit/test_submission_workflow.py` | A |
| SF-46 | Every inbound indicator states when it stops being valid. `valid_until` is required and later than `valid_from`; an indicator naming a network address may be valid for at most 90 days, any other for at most two years; and its `pattern_type` is one a member can run. Excluding expired indicators from packs and readiness extends this in phases E and F. | An indicator with no end is blocked by members for years, long after the address has passed to someone else. | `aivs-schemas/tests/test_extension_2_0.py`, `unit/test_index_columns.py` | E |
| SF-61 | A released embargo notifies the circle's current members only, never an organisation that has left. | Notifications were bounded by join time alone, so a former member was told that content it could no longer see existed. | `unit/test_notifications.py` | A |
| SF-63 | Pausing distribution withholds everything not already visible, including an embargo that comes due during the pause, until the pause is released. | The first pause blocked new stamps only; an embargo stamped beforehand still became visible mid-incident. | `unit/test_pause_distribution.py` | A |
| SF-64 | The `isac_analyst` role reads submissions in order to prepare them and holds no editorial verb. | Every ISAC staff member able to push RED is one more person whose compromise publishes it. | `unit/test_isac_roles.py` | A |
| SF-71 | The committed proxy configuration puts the hybrid post-quantum group `X25519MLKEM768` alone in its first tuple, so the server prefers it even over a classical key share the client sent first, with a classical fallback in a later tuple; and the default proxy image is built on an OpenSSL that implements ML-KEM. Against the running proxy, the opt-in end-to-end tier (`e2e/test_pqc.py`) shows an OpenSSL 3.5 client negotiating `X25519MLKEM768` in both orders and a classical-only client connecting with `X25519`; it is not counted as a pin, because the ordinary run skips it. | TLS traffic carrying embargoed intelligence, recorded today, is readable once a quantum adversary exists; key exchange is the part that cannot be fixed retroactively. | `unit/test_proxy_config.py` | A |
| SF-73 | Each TOTP code signs an operator in once (RFC 6238 section 5.2): a code for the time step last accepted, or an earlier one, is refused and counts towards the lockout, and two concurrent sign-ins with one code let exactly one in. | The same code signed in any number of times inside its 90-second window, so a code read over a shoulder or captured by a phishing page could be replayed while it lasted. | `unit/test_sessions.py` | D |
