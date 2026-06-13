# 0030 — Fail-closed structural guards over the sensitive schema and retention registration

- **Status:** Accepted
- **Enforced by:** two DB-free, sub-second guard tests in the per-push
  structural-guard gate (CLAUDE.md *Pre-push Quality Checklist*):
  `cargo test -p hort-app --test no_sensitive_drops` (token-aware source-scan
  of `migrations/`) and `cargo test -p hort-app --test
  retention_registration_guard` (allowlist + no-wildcard exhaustive `match`
  over `StreamCategory`, so a new variant is a compile error in the guard
  until classified). Weakening either matcher or list to make a failure pass
  is a blocking review finding.
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

Two permanent, fail-closed structural guards protect these surfaces. Both are
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
  sensitive table is deliberately out of scope (the table's existence and
  identity survive), as is any destructive statement against non-sensitive
  tables.

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

## References

- `crates/hort-app/tests/no_sensitive_drops.rs` — the migration drop guard:
  sensitive-table list, comment/string stripping, token-aware matcher,
  positive/negative self-checks.
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
  migration edits; composed with guard (a) as described above.
- [0024](0024-architect-skill-as-enforcement-index.md) — the
  enforcement-index discipline these guards participate in.
- [0026](0026-streaming-metadata-projection.md) — the sibling
  guard-test-enforced decision establishing the per-push structural-guard
  pattern.
- Full design history: preserved in the frozen pre-1.0 development history
  (git).
