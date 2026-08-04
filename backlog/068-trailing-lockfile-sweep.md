# 068 — en-bloc batch 8: trailing lockfile sweep (lru, rand, webbrowser)

**Issue:** #103 · **Branch:** `agent/103-trailing-lockfile-sweep`
**Plan:** #95 note 5282 (en-bloc plan) — trailing lockfile-only sweep from the
2026-08-04 renovate run (dashboard #20, !299/!300 + the rate-limited
`webbrowser` branch). Batch-2-shaped (#96 precedent): in-requirement patch
bumps, lockfile-only, zero code changes expected. Independent of #102
(batch 7) — no ordering constraint.

## Scope

1. Scoped lockfile bumps — `cargo update -p <crate> --precise <version>`, no
   `Cargo.toml` changes, no unrelated lock drift:
   - `lru` 0.18.1 → 0.18.2
   - `rand` 0.10.1 → 0.10.2 (the workspace 0.10 entry ONLY — the transitive
     `rand 0.8.6` / `rand 0.9.4` old-generation entries are other crates'
     pins and stay untouched)
   - `webbrowser` 1.2.2 → 1.2.3
2. `tokio` 1.53.1 (!291) is already on develop since batch 2 — explicitly NOT
   part of this batch; the stale renovate MR auto-closes on re-evaluation.
3. Attribution regen in the same change (ADR 0049): patch re-versions of
   non-workspace crates are dependency-graph changes.
4. `# AUDIT-ONLY` re-check: `cargo tree -i <crate> -e normal` for every
   `.cargo/audit.toml` ignore; move/mirror markers if reachability changed.

## Out of scope

Batch 7 (#102 reqwest+object_store) and 7b (sqlx), upstream-watch group,
deferred human decisions, any `Cargo.toml` requirement change.

## Scope / acceptance

- Zero source-file changes expected; if any bump forces a code change, STOP
  and report (that would mean the bump is not in-requirement — mis-mapped).
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `cargo test --workspace`, `cargo audit --deny warnings`,
  `cargo deny check` — all in the report as evidence.
- No renovate checkboxes; !299/!300 auto-close on merge; the `webbrowser`
  rate-limited dashboard entry resolves without its MR ever being created.

**Model hint:** small (mechanical lockfile bumps; no API surface).
