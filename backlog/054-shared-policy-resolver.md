# 054 — #76 (item 1/2): extract the shared active-scan-policy resolver

**Issue:** #76 (spec approved on the issue — note 3788)
**Read first:** `crates/hort-app/src/use_cases/quarantine_use_case.rs::resolve_active_policy_for_repo`
(~1067 — the canonical copy, incl. its "extract on a second caller" comment), then the six
duplicates: `discovery_use_case.rs`, `ingest_use_case.rs`, `promotion_use_case.rs`,
`scan_orchestration.rs`, `provenance_orchestration.rs`, `seed_import_use_case.rs`
(each `fn resolve_active_policy_for_repo`).

## Design (settled on #76)

Pure refactor, ZERO behavior change. One shared helper in `hort-app` (e.g.
`use_cases/policy_resolution.rs`), signature ~
`resolve_active_policy_for_repo(policy_projections: &dyn PolicyProjectionRepository, repo_id: Uuid) -> AppResult<Option<ScanPolicyProjection>>`
— repo-scoped-over-global selection over `list_active()`, exactly the quarantine copy's
semantics. Migrate all SEVEN call sites; delete the private copies.

## Scope / acceptance

- All seven use cases call the shared helper; no private `resolve_active_policy_for_repo` remains.
- Existing selection tests move with (or cover) the helper: repo-scoped beats global; global
  fallback; absent → None. hort-app 100%-coverage rules apply.
- No signature/behavior change at any caller; existing tests stay green unmodified.
- Gate: fmt, clippy -D warnings, cargo test --workspace.

**Model hint:** small/mechanical.
