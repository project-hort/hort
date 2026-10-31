# 349 — The jobs-row state has exactly one owner

**Issue:** #388 · **Branch:** `agent/388-scan-obligation`
**Governing decisions:** ADR 0007 (release authority — a verdict, not elapsed
time, releases an artifact) · ADR 0060 (`Contended` is the retryable-busy
outcome) · #331 E91 (the flaky test that shares this file, not this defect).

## What is true today

A `kind='scan'` job's row state is written **twice per execution, by two
owners**, and the second write undoes the first.

| | Site | What it writes |
|---|---|---|
| 1 | `crates/hort-app/src/use_cases/scan_orchestration.rs` `record_outcome` — six call sites (`:1239`, `:1299`, `:1341`, `:1403`, `:1429`, `:1446`) | `mark_completed` / `mark_failed` / `reschedule`, chosen per outcome |
| 2 | `crates/hort-app/src/task_dispatcher.rs:927-931`, reached because `crates/hort-app/src/task_handlers/scan.rs:189-191` returns `TaskOutcome::Completed` for **every** `ScanRunOutcome` | `mark_completed` |

`reschedule` sets `status='pending'` and does **not** touch `attempts`
(`RESCHEDULE_SET`, `crates/hort-adapters-postgres/src/jobs_repository.rs:305`).
The result-write fence is `AND attempts = $2` only — deliberately not the
status, which a guard test pins (`:1987`). So write 2's fence matches and
turns the scheduled retry into `status='completed'`.

Reported from a live instance: 16 artifacts whose scan row reads
`status=completed, attempts=1` with `last_error` naming a transient compose
failure, no `ScanCompleted`, no verdict, `last_scan_at` NULL, and a release
sweep that correctly declines forever.

## Why this is a defect

**The job row is the system's only record that it still owes the artifact a
verdict.** Release is earned by a verdict (ADR 0007), so an artifact whose
scan claims to be finished without emitting one enters a state the domain has
no name for: quarantined, window elapsed, no verdict, nobody owing one. The
event stream ends at `ArtifactQuarantined` and will end there permanently.

**The terminal arm is clobbered too.** A scan `record_outcome` resolved as
`failed` also reads back `completed`, so at the one place an operator looks,
"answered", "still owes an answer" and "gave up" are one word.

**The licensing comment is wrong in exactly the two arms that matter.** It
claims the second `mark_completed` is an idempotent no-op; that holds only
where `record_outcome` itself ended at `completed`.

## The change

**The dispatcher is the single owner of the `jobs` row state. The scan path
owns events and artifact state, and nothing else.**

1. `record_outcome` loses all six row writes and keeps everything else — the
   `ScanCompleted` / reject / delta event work and the artifact-state
   transitions, including `ScanIndeterminate` on an exhausted budget.
2. `ScanTaskHandler::run` returns the truthful outcome instead of a blanket
   `Completed`: `Completed { result_summary }` for the completed and
   skipped-no-backends arms; `Failed { reason, retry: true }` for the
   transient arm; `Failed { reason, retry: false }` for `NothingAnalysable`
   and the retry-exhausted arm.
3. The reason strings move unchanged into `TaskOutcome::Failed.reason`. They
   are the operator-visible `last_error` text and this unit does not reword
   them.

**This is not a behaviour change beyond the fix, and each half is measured:**

- The backoff curve is identical. There is exactly one `compute_backoff`
  (`crates/hort-app/src/retry_backoff.rs:77`) and both the dispatcher and the
  scan path already call it, so the waits stay 60 s / 5 min / 30 min / 60 min.
- **The attempt budget is NOT automatically identical, and carrying it is the
  one thing the handoff must get right.** There are two caps. The scan path
  reads `self.config.max_attempts`, which an operator sets via
  `HORT_SCANNER_MAX_ATTEMPTS` (`crates/hort-worker/src/config.rs:566`,
  `parse_u32_default(..., 5)`). The dispatcher uses `JOB_ATTEMPT_CAP`, a
  compile-time `const u32 = 5` (`crates/hort-app/src/task_dispatcher.rs:260`).
  Its own doc comment says the two are "the same number on purpose … so a
  scan row hits one budget rather than two disagreeing ones" — the agreement
  is held by a comment, not by construction. At the default they agree; at any
  configured value they do not, and a naive handoff would silently replace an
  operator's configured scan budget with 5. So this unit either carries the
  scan's configured cap into the handoff or derives `JOB_ATTEMPT_CAP` from the
  same configuration. It must not leave two caps agreeing by comment.

- The fail-closed ordering is strengthened: the artifact's transition to
  `ScanIndeterminate` must precede the row's terminal write, and with the row
  write behind the handler's return that holds by construction instead of by
  a comment.

## The structural close

Convention already assumed the dispatcher owned the row, and it did not hold.
So this unit carries a guard in the family of `capped_stream_reads` — a
DB-free source scan under `crates/*/tests/`, **with no allow-list**:

- **Scoped to the application layer**: no `crates/hort-app/**` file other than
  `task_dispatcher.rs` calls `mark_completed` / `mark_failed` / `reschedule`.
- A paired **positive** assertion that the adapter's own terminal resolution
  of an unmappable claimed row is still present
  (`crates/hort-adapters-postgres/src/jobs_repository.rs:1433-1482`). That
  call is deliberate — an unmappable row is unmappable on every later claim,
  so re-queueing it would trade silent loss for a hot loop — and a guard that
  forbade it would be wrong.
- Counter-assertions so a rename cannot make it vacuously green: the scan
  handler still reaches the dispatcher, and the three methods still exist on
  the `JobsRepository` port.

The census is measured, and it is **three** production files, not two:
`hort-app/src/task_dispatcher.rs` (4 calls),
`hort-app/src/use_cases/scan_orchestration.rs` (6, which this unit removes),
and `hort-adapters-postgres/src/jobs_repository.rs` (1, which stays). That is
why the assertion is layer-scoped rather than "exactly one file" — the naive
form fails on correct code. No other `TaskHandler` writes the row, and the
scan handler has no hidden row-write helper: its error path returns
`TaskOutcome::fail` to the dispatcher.

## Acceptance

1. A scan whose composition fails with budget left leaves `status='pending'`,
   `locked_by=NULL`, `last_error` = the compose message, and is re-claimed
   after the backoff. Asserted against a real row, not a mock.
2. The same scan with the budget spent leaves `status='failed'`, and the
   artifact's state follows the **existing** two-way split, which this unit
   does not change:
   - artifact **already `quarantined`** → it stays quarantined, with no
     `ScanIndeterminate`, and becomes eligible for the failed-job-driven
     stranded-rescan selector
     (`crates/hort-app/src/use_cases/scan_orchestration.rs:1395-1405`,
     `crates/hort-adapters-postgres/src/rescan_candidates.rs:265-277`). The
     code says why: "will be re-picked by the rescan sweep once the scanner
     recovers". **This is the reported operator's case**, so the fix makes
     those artifacts visible and recoverable rather than terminal.
   - any other state → `record_scan_indeterminate` first, then the terminal
     row (`scan_orchestration.rs:1407-1433`).
3. **A persistence failure at the cap must not produce a terminal row with no
   matching artifact verdict.** If `record_outcome` fails while writing the
   event or the transition, the handler returns a retryable failure; at the
   cap the dispatcher writes `failed` regardless
   (`task_handlers/scan.rs:177-185`, `task_dispatcher.rs:957-1004`). The
   handoff needs an explicit disposition for that case — a recoverable
   obligation, not a silent terminal row.
3. `NothingAnalysable` leaves `status='failed'`.
4. The happy path is unchanged: `status='completed'` with the same
   `result_summary` keys (`scanner`, `finding_count`, `assessment`).
5. The guard fails on a reintroduced row write in `scan_orchestration.rs`.
6. **Counter-assertion.** A test that drives the transient arm twice pins
   that `attempts` advances per claim — a fix that re-fenced on status instead
   of removing the second writer would be green on (1) and still leave two
   owners.
7. `hort-app` needs 100% for any branch added there; DB-backed tests carry
   `#[serial(hort_pg_db)]`.

## Out of scope

- The upstream fetch failure that produced the reported errors. Separate unit.
- The fence itself. `AND attempts = $2` is correct and the guard test that
  pins "no status fence" stays — this unit removes the second writer instead
  of re-fencing against it.
- Making the reported 16 artifacts servable *by itself*. With the retry
  surviving, those artifacts — all `quarantined` — stay quarantined with a
  `failed` job row and become eligible for the stranded-rescan selector, so
  they recover once the layer fetch does. What this unit buys is that the
  obligation stops being invisible; whether the fetch then succeeds is unit
  350's territory.

## What the independent review changed

Reviewed by `codex/gpt-6-sol` against the code; three of this unit's claims
did not survive, and each correction above was re-verified here before being
written in:

1. The two attempt caps are not automatically the same number — one is
   operator-configurable, the other a `const`.
2. The row-write census is three production files, not two, so the guard is
   layer-scoped and *pins* the adapter's deliberate call instead of forbidding
   it. The naive "exactly one file" form would have failed on correct code.
3. An exhausted scan does **not** always leave the artifact indeterminate — a
   quarantined one deliberately stays quarantined. The original acceptance
   criterion would have tested a correct behaviour out of the code, and it
   described the reported operator's own case wrongly.

Plus one gap that was not a wrong claim but a missing one: the
persistence-failure-at-the-cap disposition, now acceptance criterion 3.
