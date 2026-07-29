# 055 — #76 (item 2/2): policy-duration-aware quarantine_deadline hydration

**Issue:** #76 (spec approved on the issue — note 3788). Depends on item 054 (shared resolver).
**Read first:** `crates/hort-app/src/use_cases/artifact_use_case.rs::hydrate_quarantine_deadline`
(~577 + its stale doc comment), `hort_domain::policy::effective_quarantine_deadline`,
the Retry-After consumers: `hort-http-oci/src/quarantine.rs::check_quarantine`,
`hort-http-maven/src/lib.rs` (~474), `hort-http-pypi/src/metadata_endpoint.rs::build_quarantined_response`;
`discovery_use_case.rs` (~277) for the resolve-then-compute precedent;
`hort-http-oci/src/blobs.rs` (~214) release-wait comment block (stale rationale to update).

## Design (settled on #76)

- `ArtifactUseCase` gains `Arc<dyn PolicyProjectionRepository>` (constructor + hort-server
  composition root wiring).
- `hydrate_quarantine_deadline` becomes async; ONLY when `quarantine_status == Quarantined`
  AND `quarantine_window_start.is_some()`: resolve policy via the shared 054 helper
  (fallback `DefaultPolicy::quarantine_duration_secs`) and set
  `quarantine_deadline = effective_quarantine_deadline(anchor, duration)`. Every other
  status: `None`, and NO policy-port call (happy read path pays zero extra I/O).
- No handler changes; None-deadline fallbacks (OCI 1h default) stay for anchor-less rows.
- Update the stale doc comments (hydration fn; blobs.rs release-wait block — its
  "use is_window_elapsed, not the hydrated field" guidance stays, the rationale text updates).
- Read-path only: NO events, NO release-predicate change; `is_window_elapsed` untouched.

## Scope / acceptance

- Tests (hort-app 100%): quarantined+anchor+repo policy → anchor+policy duration;
  quarantined+anchor no policy → anchor+DefaultPolicy; non-quarantined / no anchor → None
  AND zero policy-port interactions (mock asserts).
- One per-format handler test updated to assert Retry-After reflects a multi-minute window
  (>1s) instead of the 1s clamp.
- Gate: fmt, clippy -D warnings, cargo test --workspace.

**Model hint:** capable (touches the quarantine-serving path; ADR 0007-adjacent).
