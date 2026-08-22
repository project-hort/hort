# 132 — Release-sweep candidacy must fall back to the default quarantine window

Issue: #190. Scheduled for the 0.12.0 cycle — do not merge before the 0.11.0
promotion.

## Why

`quarantine_release_candidates` resolves each repo's effective window as
repo-scoped policy → global policy → **nothing**: with no resolvable policy
row the repo is dropped from candidacy and the sweep logs
`tick complete (no candidates)` forever
(`crates/hort-adapters-postgres/src/quarantine_release_candidates.rs:188-200`).

Every other consumer of the window falls back to
`DefaultPolicy::quarantine_duration_secs()` (86 400) — ingest
(`ingest_use_case.rs:2938-2941`, `:4346-4351`), the scan fast path
(`quarantine_use_case.rs:554-566`), `is_window_elapsed`
(`quarantine_use_case.rs:1134-1140`), and the read-path deadline
(`artifact_use_case.rs:643-650`). So a repo whose policy row is archived,
re-scoped, or racing a gitops re-apply still **quarantines everything for
24 h at ingest** while the sweep never considers the rows. Full-window
artifacts (an OCI image index can never be a referenced-tree descendant, so
it always carries the full window) strand permanently, with the API deadline
reading "expired".

The module doc (`:13-19`) asserts the opposite premise — "`DefaultPolicy`
carries no quarantine window … an unconfigured repo never quarantines today" —
contradicted by `crates/hort-domain/src/policy/scan.rs:167-169`. The comment
must not survive the fix.

## What to do

1. Fallback in the candidacy resolution:
   `repo_scoped.get(&repo).copied().or(global_duration)` gains
   `.or(Some(<default>))`. **Layering note:** check whether the adapter may
   import `hort_domain::policy::scan::DefaultPolicy` directly (adapters may
   depend on domain — verify against the dep graph) or whether the default
   must arrive through the port contract; flag the choice in the report.
2. Rewrite the module doc's resolution ladder to name the default tier
   truthfully.
3. Promote the sweep's two skip-reason logs from `debug!` to `info!`
   (`quarantine_release_sweep.rs` consumer side, `:1516-1520` and
   `:1563-1567` in `quarantine_use_case.rs`) — the condition was invisible at
   production log level exactly when it mattered.

## Tests

- DB-gated: quarantined artifact, **zero** policy rows → candidate once the
  default window has elapsed. Must carry `#[serial(hort_pg_db)]` per the
  crate contract.
- DB-gated: repo-scoped 0s policy still contributes no candidates (explicit
  operator zero honoured — nothing quarantines there anyway).
- Existing candidacy tests unchanged.

## Scope boundaries

- No change to ingest, fast path, or the authority gate.
- No change to policy application/projection code.
- The #189 OCI push-path fixes (edge atomicity, race→500) are a separate item
  on that issue.

## Done when

- The DB test above passes; `cargo test --workspace` green; full local gate
  incl. audit/deny.
- `hort-adapters-postgres` coverage ≥ 85 % maintained.
