# 006 — Resilience: a failed initial scan strands artifacts permanently (auto-recovery)

- **Source:** GitLab issue #6 (spec approved by maintainer 2026-07-14: "(a), (b) and (c) confirmed")
- **Type:** bug (resilience) — domain/app + adapter + docs. Security-boundary-adjacent.
- **Model hint:** **capable** — touches the quarantine/scan lifecycle and the ADR 0007 release predicate; the transient-vs-terminal distinction is a design decision.
- **Reviewable unit:** may split into **(1) worker/app scan-retry classification + rescan-selection** (one coherent change, shared tests) and **(2) docs** — the implementer may propose the split; keep the ADR-0007 reasoning in item (1).

## Problem

When the scanner is unavailable during an artifact's **initial** scan, the scan job
finishes with "all backends failed"; the artifact stays `quarantine_status='quarantined'`
with **no release authority**, and nothing re-scans it — `select_eligible`
(`crates/hort-adapters-postgres/src/rescan_candidates.rs`) only picks
`quarantine_status IN ('released', NULL)`. A transient scanner outage therefore strands
every artifact pulled during it, permanently, until a manual re-enqueue. Manual recovery
needs admin-tier auth, which is unavailable on a Dex-off deploy (`registry.hort.rs`) —
there the operator workaround was a raw `enqueue_scan` DB insert.

## Read first

- `crates/hort-app/src/task_handlers/scan.rs` — the scan task handler
  (`ScanRunOutcome::{Completed, SkippedNoBackends, Failed}`; how `Failed` is recorded).
- `crates/hort-app/src/scanning.rs` — `run_scan` / `record_outcome` / the live-backend-set
  handling ("transiently empty" note); where "all backends failed" originates.
- `crates/hort-app/src/task_handlers/cron_rescan_tick.rs` + the port
  `crates/hort-domain/src/ports/rescan_candidates.rs` — the rescan sweep.
- `crates/hort-adapters-postgres/src/rescan_candidates.rs` + its test
  `crates/hort-adapters-postgres/tests/rescan_candidates.rs`.
- `crates/hort-worker/src/config.rs` — `HORT_SCANNER_MAX_ATTEMPTS` (default 5).
- **ADR 0007** (`docs/adr/0007-fail-closed-quarantine-release-predicate.md`) — the
  controlling invariant.

## Design constraints (ADR 0007 — do NOT violate)

**This change adds NO new release authority.** The five authorities stay exactly
`{ScanSucceeded, ScanWaived, AdminOverride, CuratorWaiver, PolicyReEvaluation}`;
`quarantine_until <= now()` is never a release authority. A retried/re-enqueued scan that
succeeds provides the *existing* `ScanSucceeded` authority; findings → `rejected`. We are
not releasing stranded artifacts on a timer — we are giving the scan a chance to actually
run.

**The core design decision — distinguish two failure modes** (record it in the spec; it
is a clarification *within* ADR 0007, not a change to its release predicate — but if the
implementer concludes it needs to alter `scan_indeterminate`'s terminal semantics, that is
an ADR-0007 amendment → escalate an `agent:decision` first, do not just change it):

- **Scanner-execution / infrastructure failure** ("all backends failed" = the scan could
  not *run*: backends unreachable, live set transiently empty): **transient**.
  → **(a)** retry within the job (the `Failed` outcome must return a *retryable*
  `TaskOutcome` so the dispatcher reschedules up to `HORT_SCANNER_MAX_ATTEMPTS`, with the
  existing backoff), and if retries exhaust during a prolonged outage the artifact stays
  `quarantined` with a **persisted signal that its last scan errored** (NOT terminal
  `scan_indeterminate`).
  → **(b)** `select_eligible` (or a companion query) additionally re-picks
  `quarantine_status='quarantined'` artifacts whose **last scan errored** and which have
  **no in-flight `kind='scan'` job**, so the sweep re-enqueues a fresh scan once the
  scanner recovers.
- **Scan-ran-but-indeterminate** (scanner executed, result unparseable/ambiguous):
  **terminal** `scan_indeterminate` per ADR 0007 — **unchanged**. Not auto-rescanned by
  (b) (it needs admin override / exclusion re-eval, per ADR 0007). Keep this lane distinct.

## (c) Docs

`docs/architecture/how-to/…` — recovering stranded artifacts + a **non-admin operator
path on Dex-off deploys** (the current workaround is a raw `enqueue_scan` insert; document
the supported recovery, ideally the sweep now self-heals so the manual path is a
fallback). Cross-reference ADR 0007.

## Anti-patterns to avoid (architect checklist)

- (b) must NOT re-pick `rejected` or `scan_indeterminate` (terminal) — only
  quarantined-errored. Do not widen the release predicate.
- No silent `UPDATE` of quarantine state without a domain event.
- The "errored last scan" signal must be a real persisted fact (event and/or job-row
  state), not inferred from a timer.

## Observability

- `#[tracing::instrument]` (no `err`) on the app-layer retry/re-enqueue decision;
  `info!` when a transient scan failure is classified retryable and when the sweep
  re-enqueues a stranded artifact (security-relevant state-adjacent).
- If a new metric is added (e.g. a `hort_quarantine_*` / rescan re-enqueue counter with a
  `reason`-style label), update `docs/metrics-catalog.md` in the same change and assert it
  in a test (`metrics::with_local_recorder`). No new label value without the catalog.

## Acceptance criteria

1. A scanner-execution failure ("all backends failed") is **retried** (not terminal); with
   `HORT_SCANNER_MAX_ATTEMPTS` attempts before it settles to a *recoverable* quarantined-
   errored state (NOT `scan_indeterminate`).
2. The rescan sweep re-enqueues a scan for a quarantined artifact whose last scan errored
   and has no in-flight scan job; once the scanner is back, the artifact scans and
   releases via the normal `ScanSucceeded` authority (or is `rejected` on findings).
3. A genuinely-indeterminate scan still goes terminal `scan_indeterminate` (ADR 0007
   unchanged); (b) does not touch it.
4. `select_eligible` still excludes `rejected`, in-flight-scan, and recently-scanned
   artifacts (existing `rescan_candidates.rs` tests still pass).
5. **`hort-domain` + `hort-app` at 100% on new code; `hort-adapters-postgres` ≥ 85%.**
   Every new `hort-adapters-postgres` test that touches the shared DB carries
   `#[serial(hort_pg_db)]` (mandatory — CLAUDE.md DB-isolation contract).
6. Observability + metrics-catalog requirements above met.
7. Full local gate green (fmt / clippy / `cargo test --workspace` / audit / deny).

## Verification (for the cockpit report)

- A test proving a transient scan failure is retried then (post-exhaustion) leaves the
  artifact in a re-pickable state; a test proving the sweep re-enqueues it; a test proving
  a successful rescan releases via `ScanSucceeded` (not a timer).
- A test proving `scan_indeterminate` is NOT re-picked by (b).
- The `rescan_candidates.rs` suite still green (all `#[serial(hort_pg_db)]`).
