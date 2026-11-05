# 390 — A negative quarantine window cannot reach the projection

**Issue:** #253 · **Branch:** `agent/253-a-negative-window-cannot-reach-the-projection`
· single item.

**Governing decisions:** ADR 0007 (the time gate the value feeds) · ADR 0030
(expand/contract — read below for what it actually reaches here) · ADR 0015
(a policy field must be enforced by its consumer or rejected at apply; this is
the same rule one level down, at the column).

## The property that should hold and does not

**`quarantine_duration_secs` is a duration, and a duration is not negative.**
Three places could state that and none does.

1. **The column.** `migrations/005_policy.sql:46` declares
   `quarantine_duration_secs bigint NOT NULL` with no `CHECK`. The comment on
   the neighbouring `rescan_interval_hours` says rejecting a negative value is
   the apply pipeline's business and not the schema's.
2. **`PolicyUseCase::create_policy`** writes `cmd.quarantine_duration_secs`
   straight through — `crates/hort-app/src/use_cases/policy_use_case.rs:777`.
3. **The update path.** `desired_projection` applies
   `FieldChange::Set(v)` to `desired.quarantine_duration_secs` unchecked —
   `policy_use_case.rs:2796`. **The issue names only `create_policy`; this
   second site is mine and must be closed with it**, or the invariant has a
   door left open next to the one being shut.

The YAML path is tight and stays untouched: `hort-config::validate_scan_policy`
parses through `humantime::parse_duration`, and
`apply_config_use_case::humantime_secs` goes `Duration::as_secs()` (u64) →
`i64::try_from`, where a negative value is not representable. So the live
operator path is safe today; what is open is a hand-edited row, a restored
dump, and two latent application writers.

## What the one existing defence is, and why it is not the answer

`crates/hort-adapters-postgres/src/quarantine_release_candidates.rs:299` clamps
with `.max(0)`, added by #250. Its own comment states the semantics: *"makes
zero and negative resolve the same way — both say the window is behind us — and
keeps the cutoff off the future side of `now`"*. **That clamp stays.** It costs
nothing and it is the right posture for a reader that cannot trust a table it
does not own.

But it is **one** reader's answer. The shape to avoid is N consumers with N
answers in place of one invariant at the source.

## Three things to settle before writing SQL, in this order

### 1. The census — which consumers read this column, and what does each do with a negative value?

`grep -rn "quarantine_duration_secs" crates/*/src` and give the verdict per
site: clamped, equivalent-to-zero by arithmetic, or observably different.
**The answer decides step 3**, so it comes first and it goes in the report as a
list, not as a count.

A deadline comparison is plausibly indifferent (an anchor plus a negative
duration is a deadline already past, which is what zero gives too). A value
that reaches a client — a `Retry-After`, a reported window — plausibly is not.
Do not assume either; read each site.

### 2. What the expand/contract guard actually reaches

The issue says adding a `CHECK` is schema-narrowing and therefore falls under
ADR 0030. **Check that against the guard rather than against the sentence.**
`crates/hort-app/tests/expand_contract_guard.rs` enumerates the destructive DDL
it rejects — `DROP COLUMN`, `DROP TABLE`, table-or-column `RENAME`, a column
type change, `SET NOT NULL`. If an added `CHECK` is not in that set, then
**no `migrations/CONTRACTIONS.toml` entry is required and no release split is
mechanically forced** — state that finding with the line you read it at.

The guard is the authority on its own rule. What it does *not* answer is the
next point, which is the real risk and survives whatever the guard says.

### 3. The boot-failure risk, which is the substance

Migrations run at startup. `ALTER TABLE … ADD CONSTRAINT … CHECK (…)`
validates every existing row, so **one violating row turns the next deploy into
a boot failure** — the worst possible shape for a hygiene fix. I cannot read
any installation's data and will not ask for it, so the migration has to be
correct without knowing.

Two shapes, and the census from step 1 decides between them:

- **(a) Fix up, then constrain, in one migration.** `UPDATE … SET
  quarantine_duration_secs = 0 WHERE quarantine_duration_secs < 0` immediately
  before the `ADD CONSTRAINT`. Single release, no deferred validation, and the
  constraint is valid for every row from the moment it exists. This is correct
  **if** step 1 finds every consumer already resolves a negative value the way
  it resolves zero — then the `UPDATE` makes the stored value agree with what
  readers already see and changes nothing observable.
- **(b) `NOT VALID`, and stop there.** `ADD CONSTRAINT … CHECK (…) NOT VALID`
  checks new writes and leaves existing rows alone. Correct whatever the census
  says, but it leaves the invariant untrue of the stored data and owes a later
  `VALIDATE CONSTRAINT` that nothing schedules — the deferral shape this
  codebase has been bitten by.

**Take (a) if the census supports it, and say in the commit body that it does
and where you read it.** Take (b) only if a consumer is observably different on
a negative value, in which case the `UPDATE` would be a behaviour change
hiding inside a hygiene migration — and then say so and stop, rather than
designing the behaviour change here.

## The two application guards

Both sites reject with `DomainError::Validation`, the named rejection this file
already uses at ten sites (`policy_use_case.rs:878`, `:899`, `:1050` and so
on) — a message naming the field and the value, never a bare constraint
violation surfacing from the adapter.

Put the check where **both** writers reach it rather than copying it: the two
sites build the same `ScanPolicyProjection` shape, so one validation over the
projection-to-be-written is one rule. If that is not possible without
restructuring, two call sites of one private helper is acceptable; two
independent comparisons are not.

## Acceptance

- The column rejects a negative value, or the report states which of (a)/(b)
  was taken and why the census supports it.
- `create_policy` **and** the update path reject a negative value with
  `DomainError::Validation` naming the field, not a constraint violation.
- The census from step 1 is in the report as a per-site list with verdicts.
- The `.max(0)` clamp in the adapter is untouched.
- Migration numbering checked (`ls migrations/ | tail -5`); no
  `CONTRACTIONS.toml` edit unless the guard demands one, and never an edit that
  makes the guard pass.
- No issue, MR or backlog reference in any code, SQL or YAML comment.
- Gate green, `#[serial(hort_pg_db)]` on every DB-bound test.
