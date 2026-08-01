# 058 — #90: single-transition ingest+quarantine (provenance TOCTOU fix)

**Issue:** #90 (root cause confirmed on the issue: TOCTOU, two facets, one cause).
**Read first:** `crates/hort-app/src/use_cases/ingest_use_case.rs::ingest_inner` — the
enqueue block (~2776-2830, `provenance_will_run` + `commit_transition_with_enqueues`) and
the quarantine block (~3120-3280, policy resolve + #46 carve-out + anchor + second
transition); `crates/hort-app/src/use_cases/provenance_orchestration.rs` (~230-300,
`window_open` derivation + the *false* "ingest always quarantines before enqueuing"
comment; verdict persist path via `apply_verdict`/`complete_provenance`);
`crates/hort-adapters-postgres/src/artifact_repo.rs:35-69` (full-row last-writer-wins
UPSERT); ADR 0007 (permissive `duration=0` mode, #46 carve-out, release predicate —
all UNCHANGED); ADR 0039 (hold-read, cascade); ADR 0041.

## Defect (settled on #90)

`ingest_inner` commits `ArtifactIngested` atomically **with** the scan/provenance-verify
enqueues, then emits `ArtifactQuarantined` (setting `quarantine_window_start`) in a
**second** transition. A worker picking the verify job up inside the gap loads the
anchor-less snapshot and (facet 1) reads `window_open = false` ⇒ terminal
`Rejected{Unsigned}`, `rejection_reason = None` — no API exit; (facet 2) persists its
verdict by writing the stale full-row snapshot back, clobbering the anchor the quarantine
transition committed (projection diverges from its own events: `rejected` / `NULL`).
Observed at ~25-31% of all first-party signed OCI pushes.

## Work

1. **Single-transition ingest+quarantine.** Resolve the scan policy, the #46
   referenced-tree carve-out, and the window anchor **before** the first commit; emit
   `ArtifactIngested` + `ArtifactQuarantined` (+ `ScanRequested`) in **one**
   `commit_transition_with_enqueues` append, enqueues riding the same commit. No enqueued
   job can ever observe an anchor-less subject; the crash-gap property is preserved
   (jobs and events land atomically — do NOT move the enqueues to a later transition).
   Preserve exactly: permissive `duration=0` (no quarantine event, status `None`),
   carve-out anchor backdating, `trust_upstream_publish_time` min-clamp, dedup
   early-return (untouched), event order within the append.
2. **Orchestrator None-anchor defense (defense-in-depth).** In the
   `NoAttestation × Required` arm: a `None` `quarantine_window_start` on an artifact
   whose status is `None`/young must never resolve terminally — bounded requeue
   (one delayed retry is enough once (1) lands) instead of `Rejected{Unsigned}`.
   An anchor-less artifact past the bound keeps the current terminal behavior
   (ADR 0007's "no anchor ⇒ no indefinite hold" rationale stands).
3. **No stale-snapshot write-back on verdict commits.** The scan/provenance verdict
   persist path must apply the state transition to a **fresh** row (re-load inside the
   verdict commit, or a column-scoped UPDATE) so a concurrently-committed transition's
   columns survive. Scope: the verdict paths, not a general rewrite of the UPSERT.
4. **Tests.** `hort-app` 100% on changed paths. Regression tests pin both facets:
   (a) structural — the ingest append for a quarantining ingest contains
   `ArtifactIngested` AND `ArtifactQuarantined` in one transition (a job enqueued by
   that commit can never see an anchor-less row); (b) a racing verdict commit does not
   erase `quarantine_window_start`/`quarantine_status` written by a concurrent
   transition (projection/event consistency). Any DB-backed test carries
   `#[serial(hort_pg_db)]`.

## Scope / acceptance

- Release predicate, ADR 0007 authorities, permissive mode, carve-out semantics, dedup:
  byte-for-byte behavior preserved (only the transition boundary moves).
- No new metrics/labels without `docs/metrics-catalog.md` update (a requeue counter, if
  added in (2), needs the catalog entry in the same change).
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check`.

**Model hint:** capable (event-transition semantics, concurrency, cross-layer).
