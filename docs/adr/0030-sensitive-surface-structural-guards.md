# 0030 — Fail-closed structural guards over the sensitive schema and retention registration

- **Status:** Accepted
- **Enforced by:** three DB-free, sub-second guard tests in the per-push
  structural-guard gate (CLAUDE.md *Pre-push Quality Checklist*):
  `cargo test -p hort-app --test no_sensitive_drops` (token-aware source-scan
  of `migrations/`), `cargo test -p hort-app --test expand_contract_guard`
  (the same scan cross-checked against the checked-in destructive-DDL
  manifest `migrations/CONTRACTIONS.toml` and the workspace version), and
  `cargo test -p hort-app --test retention_registration_guard` (allowlist +
  no-wildcard exhaustive `match` over `StreamCategory`, so a new variant is a
  compile error in the guard until classified). Weakening any matcher, list
  or manifest entry to make a failure pass is a blocking review finding.
- **Supersedes:** —

## Context

Two surfaces share a failure mode: a one-line regression is catastrophic,
silent, and invisible to coverage percentage — the bad change *runs
successfully*, so no test that merely executes the code can object.

**Schema migrations.** The migration runner executes whatever SQL sits under
`migrations/`. A migration containing `DROP TABLE users`, `DROP TABLE IF
EXISTS permission_grants`, or `ALTER TABLE api_tokens DROP CONSTRAINT
api_tokens_pkey` destroys the authorization model, the credential store, or
the integrity of the immutable event ledger (ADR 0002) — and sails through a
green CI run, because dropping a table is a perfectly valid migration.
Operator guidance ("do not drop sensitive tables in a migration") enforced
nothing.

**Schema migrations, second failure mode (added by the 2026-08-29
amendment).** The same runner has a second way to be catastrophic without
being invalid: a migration that is *correct for the release it ships in* and
fatal to the release still running. Every upgrade has a window in which the
new schema and the old binaries coexist — the Helm pre-upgrade migration hook
commits before a single new pod is Ready, and a rolling update keeps old pods
serving until the new ones pass their probes. Additive DDL is harmless in that
window; destructive DDL is not. This is not hypothetical: migration
`020_drop_artifacts_is_deleted.sql` dropped `artifacts.is_deleted` in 0.12.0,
the same release whose code removed the last predicate naming it, and the
still-running 0.11.0 fleet failed *every* artifact query the instant the hook
completed (incident #215). In a self-hosting deployment — hort mirroring the
images hort itself is upgraded from — the broken old pod was also load-bearing
for the new pod's image pull, so the failure pinned itself: roughly 22 minutes
of outage that could roll neither forward nor back. As with the drop shapes,
CI was green throughout, because the migration was valid SQL and the release
it shipped in was internally consistent.

**Eventstore retention.** Automated stream deletion (seal, then delete or
archive once a retention floor elapses) is fail-closed by *registration*: the
retention sweep
(`crates/hort-app/src/use_cases/eventstore_retention_use_case.rs`) skips any
candidate stream whose `StreamCategory` has no registered
`CategoryRetentionRule`, and the rule set is built by the pure, code-held
`canonical_retention_rules` function — not a database or policy value an
operator can misconfigure. The residual hazard therefore lives at the
registration site itself: a developer seeding a privileged category
(`Authorization`, `User`, `Admin`, `Policy`, …) into the rule set, or a new
`StreamCategory` variant added in `hort-domain` silently defaulting into
deletion eligibility.

## Decision

Three permanent, fail-closed structural guards protect these surfaces. All are
DB-free, network-free, sub-second tests registered in the per-push gate.

**(a) No migration may drop or de-constrain a sensitive table**
(`crates/hort-app/tests/no_sensitive_drops.rs`). Every `*.sql` file under the
workspace-root `migrations/` tree is scanned — comments and string literals
stripped first, identifiers matched as whole tokens, never substrings — for
three destructive shapes against the maintained sensitive set: `DROP TABLE
<name>`, `DROP TABLE IF EXISTS <name>`, and `ALTER TABLE <name> … DROP
CONSTRAINT`. The sensitive set is code-maintained, inline in the test, and
covers:

- the authorization model — `users`, `claim_mappings`, `permission_grants`,
  `oidc_issuers`, `service_accounts`;
- the credential store — `api_tokens`;
- repository and upstream configuration — `repositories`,
  `repository_upstream_mappings`;
- the task queue — `jobs`;
- the event-store ledger — `events`, any table in the `events_` prefix
  family, and the applied-migration ledger `_sqlx_migrations`.

Widening the list (a new sensitive table) is a deliberate, self-contained,
review-gated edit to the test. Removing an entry, or weakening the matcher so
a drop passes, is a blocking review finding — if a migration genuinely must
drop a sensitive table, the correct response is to question the migration.

#### Amendment 2026-06-28 — the DROP + re-ADD same-name enum-CHECK widening exception (`_check`-only)

The de-constrain shape (`ALTER TABLE <sensitive> … DROP CONSTRAINT <c>`)
carves out one refinement, restricted by a **fail-closed allow-list to
constraint names ending in `_check`** (case-insensitive): a `DROP CONSTRAINT
<c>` where `<c>` is a `_check` name, **immediately paired with an `ADD
CONSTRAINT <c>` of the same name on the same table** in the same migration, is
an enum-`CHECK` **widening**, not a de-constrain — the table emerges still
constrained, with an equivalent-or-stricter constraint, so it does not breach
the "no migration may drop or de-constrain a sensitive table" boundary (whose
stated intent is the integrity / primary-key drop that leaves the table *less*
protected).

The `_check`-only restriction is load-bearing. The earlier shape-based
exemption (any same-name, same-table re-add) did **not** verify the re-add was
equivalent-or-stricter, so it was fail-open to the attack
`ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_pkey; ALTER TABLE api_tokens
ADD CONSTRAINT api_tokens_pkey CHECK (true);` — drop a primary key, re-add a
no-op same-named CHECK — under which the table emerges **less** protected while
the guard passed. The only constraint that is ever legitimately drop+re-added
under the same name to *widen* is an enum `CHECK` (PostgreSQL has no in-place
`CHECK` alter and auto-names such constraints `<table>_<col>_check`); integrity
constraints (`_pkey` / `_fkey` / `_key` / `_unique`, or any non-`_check` name)
are **never** legitimately drop+re-added to widen, so their drop is **always**
flagged regardless of any same-name re-add. The control is an **allow-list**
(`name.to_ascii_lowercase().ends_with("_check")`), not a deny-list, precisely
so that an unconventionally-named integrity constraint cannot slip through the
exemption — a deny-list of known-bad suffixes would be fail-open to a name it
did not anticipate.

A **bare** `DROP CONSTRAINT` with no matching same-table same-name re-add, a
`DROP CONSTRAINT` of any non-`_check` name (even with a same-name re-add), and
any `DROP TABLE` / `DROP TABLE IF EXISTS`, remain hard failures.

The motivating case is widening an enum `CHECK` constraint — the only way to
extend an allowed-value set (e.g. adding a worker task kind to the `jobs.kind`
`CHECK`) is to drop and re-add the same named `_check` constraint over a
superset of values. Pre-1.0, such a widening is done **in place** in the
defining CREATE (per ADR 0022 — the `jobs.kind` widening that originally
motivated this exemption now lives in the `009_scan_jobs_and_findings.sql`
baseline), so no current migration exercises the exemption; it is retained
because `ALTER`-as-new-numbered-migration resumes once a non-wipeable
production DB exists (1.0), at which point a `jobs.kind` widen again takes the
DROP + re-ADD same-`_check` shape this guard exempts. The exemption is
**table-scoped**: the
matching `ADD CONSTRAINT <c>` must be on the **same table** as the DROP — a
same-name `ADD CONSTRAINT` on a *different* table does **not** exempt a
sensitive de-constrain (that would be a false negative). The exception's
enforced shape — the `_check`-only allow-list, what counts as a widening versus
a genuine de-constrain, the no-op-CHECK-replaces-pkey negative case, and the
cross-table negative self-test — lives in
`crates/hort-app/tests/no_sensitive_drops.rs` (the `is_widenable_check_name`
allow-list, the `readds_constraint(table, cname)` helper, and their
self-checks); the test is the executable boundary, this note is its rationale.

**(b) Automated event-stream retention may only ever target the four
permitted categories** (`crates/hort-app/tests/retention_registration_guard.rs`).
The guard pins `RETENTION_PERMITTED = {Artifact, AuthAttempts, DownloadAudit,
TokenUse}` and asserts three things: every rule `canonical_retention_rules`
emits has a category in the allowlist; the categories it emits equal the
allowlist *exactly* (so dropping a deliberately-rotated audit category is as
much a regression as adding a privileged one); and a `match` with **no
wildcard arm** classifies every `StreamCategory` variant as permitted or
forbidden, with counts pinned at 4 permitted / 9 forbidden. Because
`StreamCategory` is not `#[non_exhaustive]`, a future variant fails to
compile the guard until it is consciously classified — a new category forces
a decision rather than silently becoming deletable.

The four permitted categories are *preserved*, not exempted, on purpose:
`AuthAttempts` (≥6-month floor), `DownloadAudit` (≥90-day floor), and
`TokenUse` (≥36-month floor) are the high-volume rotated audit streams whose
retention rules exist precisely to bound their growth, and `Artifact` is the
lifecycle category whose streams seal only after the `ArtifactPurged`
terminal event. Exempting the audit categories from retention would reopen
unbounded audit-stream growth; the guard bans the dangerous additions while
keeping the intended deletions.

### Amendment 2026-08-29 — (c) the expand/contract policy for destructive DDL

*Authorised by the refined→ready confirmation on issue #214; incident record
#215.*

**The policy.** Destructive DDL — `DROP COLUMN`, `DROP TABLE`, `RENAME` of a
table or a column, a column type change, and `SET NOT NULL` on an existing
column — may ship only in a release **strictly after** the last release whose
code references the affected identifier. **Expand and contract never share a
release.** Schema change is therefore always two releases:

1. **Expand.** Add the new column or table, dual-write if there is a cutover,
   move every reader onto it, and remove the last reference to the old
   identifier. All of this is safe in one release: the previous release's
   binaries never name the new identifier, and the old one is still there for
   them.
2. **Contract.** In a *later* release, drop / rename / narrow the old
   identifier. By then no supported binary names it.

A contraction is a deliberate, scheduled, release-notes-flagged event, not a
tidy-up that rides along with the refactor that made it possible. The
changelog convention that makes it visible to operators — a `### Migration
notice` entry naming the object and the minimum tolerating binary version —
is specified in `RELEASING.md` and is part of this decision.

**The guard mechanism** (`crates/hort-app/tests/expand_contract_guard.rs`).
Every `*.sql` under `migrations/` is scanned with the same token-aware
discipline as guard (a) — comments and SQL string literals stripped first,
identifiers compared as whole tokens, never substrings; the shared lexer both
guards walk lives in `crates/hort-app/tests/sql_scan/mod.rs`. Recognised
destructive shapes yield either a **removal** (`DROP TABLE`, `DROP COLUMN`,
the source side of a `RENAME`) or a **narrowing** (`ALTER COLUMN … TYPE`,
`SET NOT NULL`). Each is cross-checked against the checked-in manifest
`migrations/CONTRACTIONS.toml`, whose entries carry the migration file name,
the affected identifiers (`table` or `table.column`), a
`reference_removed_in = "X.Y.Z"` release, and a required `note`. The guard
fails when:

- **(a) a contraction is undeclared** — destructive DDL in a migration with no
  manifest entry; and symmetrically when an entry's declared `identifiers` do
  not *exactly* equal the set the scanner extracts from that migration, when
  an entry names a migration that does not exist, or when an entry claims a
  contraction the migration no longer performs. The two-way equality is what
  stops the manifest decaying into stale prose;
- **(b) the timing gap is absent** — the workspace version (from the root
  `Cargo.toml`) is not strictly greater than the entry's
  `reference_removed_in`. A `X.Y.Z-dev` tree is not greater than `X.Y.Z`, so
  authoring the contraction in the same cycle that removed the last reference
  fails; waiting one cycle passes;
- **(c) the claim is untrue of the present** — SQL text in the workspace's
  production sources (`crates/*/src/**/*.rs`) still names a removed
  identifier.

The manifest is seeded with the tree's existing destructive migrations
(`009`, `014`, `020`) so the guard starts from reality; `020`'s entry records
the incident above as the exemplar.

**The guard's limits, and the reviewer step it delegates.** The guard is
hermetic by design — no `git`, no network, sub-second — which means it can
only inspect the tree in front of it. It therefore **cannot see past
releases**, and so cannot verify the one thing `reference_removed_in` actually
asserts: that the release before it was the last whose code named the
identifier. Check (b) enforces the arithmetic and check (c) confirms the claim
is at least true of the present; the honesty of the version itself is a
**mandatory review step**. For every new manifest entry the reviewer runs, per
identifier:

```bash
git grep <identifier> v<reference_removed_in>
```

and confirms no SQL at that tag names it (an English-word hit in prose is not
a reference; the check is about SQL identifiers). Skipping this makes the
manifest a wish rather than a record.

Two further limits, stated so a green run is not mistaken for a proof. Check
(c) reads SQL that appears as Rust **string literals**; a query assembled at
runtime from a `const` column name or `format!`-ed from fragments is invisible
to it. And the scanner matches statement shapes, not effects: a `TYPE` change
is flagged whether it narrows or widens (the fail-closed direction, since
deciding needs type semantics the guard lacks), while a `DROP TABLE`
immediately followed by a `CREATE TABLE` of the same name in the same
migration is *not* a contraction — the identifier is present before and after,
so no binary breaks on its account. That last exemption is what keeps the
pre-1.0 prototype-replacement migrations out of the manifest; dropping a
*sensitive* table that way remains an unconditional failure under guard (a),
so the two guards compose rather than overlap.

**Composition with the other decisions.** ADR 0022 (pre-1.0 in-place
migration edits) is why the two historical same-release contractions in the
manifest were survivable at all: alpha deployments wipe the database between
releases, so no previous-release binary was serving against the migrated
schema. That excuse expires with the wipe contract, which is precisely why the
policy becomes mechanical now. ADR 0048 (release/staging model) supplies the
release boundaries the policy counts in.

**The remaining gap, and the follow-on item.** This guard is a *build-time*
control: it stops a contraction from being authored too early. It does nothing
at *runtime* — a binary started against a schema that has already contracted
past what it understands still starts, and still fails on first query. Closing
that requires a runtime schema-compatibility fence in the migrate/boot path,
which is a follow-on item on the same initiative and is specified separately;
it is named here only so that this decision is not mistaken for full
coverage.

**The runtime fence (backlog 145).** Built as the follow-on item named above.
Every hort Postgres connection now sets `application_name =
"hort-{server|worker}/<workspace-version>"` (one call site per binary —
`hort_server::pg_identity::connect_options` / `hort_worker::pg_identity::connect_options`,
both thin wrappers over the shared, zero-I/O
`hort_config::pg_identity::pg_application_name`). Before applying, `hort-server
migrate` computes the pending migration set and, only when at least one
pending migration is a declared contraction (`migrations/CONTRACTIONS.toml`),
queries `pg_stat_activity` for hort-shaped clients other than itself. Finding
any whose stamped version is older than the current binary — or hort-shaped
with no version segment at all, a client that predates this scheme,
fail-closed — refuses the run and names the offending clients. An
expand-only pending set is never fenced, so routine rolling upgrades stay
hook-driven and unattended. The operator override is `--allow-running-fleet`
(env `HORT_ALLOW_RUNNING_FLEET`, plumbed through the Helm migrate Job,
default off), loudly logged when used. This closes the runtime half of the
gap: the build-time guard above stops a contraction from being *authored*
too early, and this fence stops it from being *applied* into a fleet that is
still running the old binary.

## Consequences

- A regression class that coverage percentage cannot detect — a destructive
  migration that executes cleanly, a retention rule that deletes privileged
  streams on schedule — becomes a red test (or a compile error) on every
  push, with no database required.
- Every schema change that drops or de-constrains a sensitive table, and
  every new `StreamCategory` variant or fifth retention category, pays a
  deliberate edit to the corresponding guard. That friction is the point: the
  lists are audited security boundaries, and the diff to a guard test is the
  review signal.
- Forbidden: weakening a matcher or list entry to make a failing change pass;
  adding a wildcard arm to the category classification; registering a
  privileged category in `canonical_retention_rules` without amending this
  decision.
- Interaction with ADR 0022 (pre-1.0 in-place migration edits): the scan runs
  over the migrations tree as it exists, so an in-place edit that introduces a
  sensitive drop fails identically to a new migration file. The two decisions
  compose.
- The migration guard scans statement shapes, not effects: `DROP COLUMN` on a
  sensitive table is deliberately out of scope for guard (a) (the table's
  existence and identity survive), as is any destructive statement against
  non-sensitive tables. Guard (c) covers exactly that gap from the other
  direction — not "is this table security-critical" but "does any still-running
  binary name this identifier".
- Every destructive migration now costs a `migrations/CONTRACTIONS.toml` entry
  in the same diff, and a contraction can no longer be authored in the cycle
  that made it possible — it waits for the next release. That is a real delay
  on schema cleanup, accepted deliberately: the alternative is the failure
  mode in the Context, where the cleanup's cost is paid by the previous
  release's fleet instead of by the calendar.
- A release containing a contraction is no longer a routine upgrade. It
  carries a `### Migration notice` changelog entry (RELEASING.md), and
  operators running self-hosting or Flux-remediated deployments need the
  handling in the upgrade how-to. Contractions are therefore worth batching:
  several in one flagged release cost one maintenance window, spread across
  three releases they cost three.
- Guard (c) is build-time only. Nothing yet stops an operator starting an old
  binary against a contracted schema; the runtime fence named above is
  tracked as a separate item on this initiative.

## Alternatives considered

- **Runbook guidance only (the prior state for migrations).** Rejected: it
  enforced nothing — a destructive migration passed every CI tier because the
  migration runner happily executes valid SQL.
- **Naive substring matching for the migration scan.** Rejected: real
  migrations legitimately drop non-sensitive tables, mention drops inside
  reversal-runbook comments, and contain identifiers that embed sensitive
  names as substrings (`repo_security_scores` vs `repositories`,
  `user_preferences` vs `users`). The matcher strips comments and string
  literals and compares whole identifiers, and the test pins both positive
  and negative self-checks so a refactor cannot silently weaken it.
- **A runtime candidacy predicate for retention** (an
  `is_retention_eligible()` defaulting to `false`, consumed by an
  artifact-retention-policy `candidate_streams()`). Rejected on two grounds:
  it contradicts the as-built code — eventstore retention is *already*
  fail-closed by registration, and the artifact-retention policy entity
  (which drives `ArtifactPurged`) is a different surface from eventstore
  stream deletion — and a predicate returning `false` for the rotated audit
  categories would make them never retention-eligible, reopening the
  unbounded audit-stream growth their rules bound. The right residual control
  is a registration-site guard, not a second runtime filter.
- **A wildcard arm in the category classification.** Rejected: a `_ => false`
  arm would be fail-closed at runtime but silent at review time — a new
  variant would compile without anyone deciding its retention status. The
  no-wildcard match converts that into a compile error in the guard, which is
  the stronger property.
- **Deriving `reference_removed_in` by having the guard run `git grep` against
  the previous tag** (instead of a checked-in manifest). Rejected: it would
  make a per-push structural guard depend on a git binary, on tag history
  being fetched (CI clones are routinely shallow, and a worktree or an
  exported tarball has no tags at all), and on network state — three ways for
  a security-relevant guard to fail *open* on infrastructure grounds rather
  than on the code. The manifest keeps the guard hermetic and moves the one
  unverifiable claim to a named, single-command review step, where a human
  failing to do it is at least visible in the diff.
- **A `historical = true` / `grandfathered` escape hatch on manifest entries**,
  so the seeded pre-policy contractions could be marked exempt. Rejected: an
  exemption flag on a fail-closed guard is the first thing a rushed change
  reaches for, and no reviewer can distinguish "historical" from "I set the
  flag". The seeded entries need no exemption — their
  `reference_removed_in` values are older than the current version, so check
  (b) passes on the arithmetic alone, and their `note` fields carry the honest
  account of what happened.
- **Flagging `DROP INDEX` / `DROP CONSTRAINT` as contractions.** Rejected as
  out of scope for guard (c): application SQL never names an index or a
  constraint, so removing one cannot break a running binary the way a dropped
  column does. (De-constraining a *sensitive* table is a different concern
  entirely and is an unconditional failure under guard (a).) Including them
  would add manifest churn with no failure mode behind it — noise that
  devalues the entries that matter.
- **Scanning the whole workspace, tests included, for check (c).** Rejected:
  the shapes that legitimately name a removed identifier live almost entirely
  in test code — an `information_schema` probe asserting the column is *gone*,
  and this guard family's own fixture strings. Including them would force a
  file allow-list, which rots and is itself a weakening surface. Production
  sources are the corpus that answers the actual question ("does a running
  binary still issue this query"), and a stale query in a test fails loudly
  against a real database.

## References

- `crates/hort-app/tests/no_sensitive_drops.rs` — the migration drop guard:
  sensitive-table list, destructive-shape matcher, the `_check`-only
  redefinition allow-list, positive/negative self-checks.
- `crates/hort-app/tests/expand_contract_guard.rs` — the expand/contract
  guard: destructive-DDL scanner (removals vs narrowings), manifest
  cross-check, version arithmetic, production-source SQL scan, and the
  fixture-driven red/green self-checks that pin all three.
- `crates/hort-app/tests/sql_scan/mod.rs` — the lexer both migration guards
  walk: comment/string stripping, tokenizer, table-name parser. Shared so the
  two cannot drift into differing notions of what a SQL identifier is.
- `migrations/CONTRACTIONS.toml` — the checked-in destructive-DDL manifest,
  including the `020` incident exemplar.
- `crates/hort-app/tests/retention_registration_guard.rs` — the retention
  registration guard: `RETENTION_PERMITTED` allowlist, exhaustive
  classification, count pins.
- `crates/hort-app/src/use_cases/eventstore_retention_use_case.rs` —
  `canonical_retention_rules`, `CategoryRetentionRule`, and the sweep's
  skip of unregistered categories.
- `crates/hort-domain/src/events/` — `StreamCategory` (13 variants) and the
  event-store vocabulary.
- `migrations/` — the scanned tree (workspace root).
- [0002](0002-event-sourced-artifact-lifecycle.md) — the event-sourced
  lifecycle whose ledger tables and stream categories these guards protect.
- [0022](0022-pre-1.0-edit-existing-migrations.md) — in-place pre-1.0
  migration edits; composed with guards (a) and (c) as described above, and
  the wipe contract whose expiry makes guard (c) necessary.
- [0024](0024-architect-skill-as-enforcement-index.md) — the
  enforcement-index discipline these guards participate in.
- [0026](0026-streaming-metadata-projection.md) — the sibling
  guard-test-enforced decision establishing the per-push structural-guard
  pattern.
- [0048](0048-release-branch-staging-strategy.md) — the release/staging model
  supplying the release boundaries guard (c) counts in.
- `RELEASING.md` — the `### Migration notice` changelog convention for a
  release whose migration set contains a contraction.
- `docs/architecture/how-to/deploy/upgrade.md` — the operator-side counterpart:
  what the expand/contract guarantee buys, and what to do for the releases
  that are flagged.
- Full design history: preserved in the frozen pre-1.0 development history
  (git).
