# 067 — en-bloc batch 7: reqwest 0.13 + object_store 0.14 (ADR 0010 TLS-builder surface)

**Issue:** #102 · **Branch:** `agent/102-reqwest-0-13`
**Plan:** #95 note 5282 (en-bloc plan) — batch 7, first half; `sqlx` 0.9 is its
own later batch (7b). `object_store` 0.14 was deferred here from batch 3 (#97,
drop-and-report: it requires reqwest ^0.13 — that unblock condition is met by
this batch).

## Context

`reqwest` is the workspace's single egress HTTP stack. ADR 0010 mandates that
every TLS-opening client is built via `reqwest::Client::builder()` with
`apply_to_reqwest_builder` layered on (system trust store +
`HORT_EXTRA_CA_BUNDLE`); `Client::new()` is architecturally forbidden outside
`cfg(test)`. A major reqwest bump therefore touches the project's whole
TLS/egress security surface at once, which is why the plan schedules it alone.

Current pins (workspace `Cargo.toml`):

- `reqwest = { version = "0.12", default-features = false, features = ["json",
  "stream", "charset", "http2", "system-proxy", "rustls-tls-native-roots"] }`
- `object_store = { version = "0.13", features = ["aws"] }`

Direct `reqwest` dependents (verified via `grep -l '^reqwest' crates/*/Cargo.toml`):
`hort-adapters-advisory-osv`, `hort-adapters-upstream-http`,
`hort-adapters-oidc`, `hort-adapters-provenance-sigstore`,
`hort-notifier-webhook`, `hort-cli`. Vendored `extra_ca.rs` modules (the ADR
0010 build path) additionally exist in `hort-adapters-storage` (object_store
TLS), `hort-config`, and `hort-worker`.

## Scope

1. Bump workspace pins: `reqwest` `0.12` → `0.13`, `object_store` `0.13` →
   `0.14` (keep `aws`). Preserve `default-features = false` and verify each
   listed reqwest feature still exists in 0.13 with the same meaning —
   especially `rustls-tls-native-roots`, `system-proxy`, `http2`. A renamed or
   split feature is migrated to the equivalent, and the report states the
   mapping. Scoped `cargo update`; no unrelated lock drift.
2. **ADR 0010 TLS-parity sweep (load-bearing deliverable).** For every client
   construction site in the six direct dependents plus the storage/config/
   worker `extra_ca` paths, the report states:
   - built via `Client::builder()` + `apply_to_reqwest_builder` (no
     `Client::new()` anywhere outside `cfg(test)`);
   - trust-root behavior identical (system roots + `HORT_EXTRA_CA_BUNDLE`; no
     insecure knob, no verification downgrade);
   - the `dns_guard` redirect/resolver integration (`hort-adapters-
     upstream-http`, `hort-notifier-webhook`) compiles against 0.13 with
     identical egress-guard semantics (redirect policy, resolver override).
3. **Version-unification check (STOP condition).** The active build graph must
   unify on reqwest 0.13. If any active-graph third-party consumer (`sigstore`,
   `openidconnect`, the `oci-client` chain, `object_store`) still pins ^0.12
   and forces a duplicate reqwest, STOP and report — a dual-reqwest/dual-TLS
   egress graph is a decision for the architect, not a shippable state.
4. `object_store` 0.14 in `hort-adapters-storage`: migrate any changed
   builder/API surface. The CAS streaming contract (`StoragePort::put(stream)
   → ContentHash`, incremental SHA-256, no buffering) is untouched; existing
   storage suites pass with assertions unmodified.
5. No behavioral changes; existing suites pass unmodified. Add coverage only
   where a compile-fix exposes an untested path.
6. Attribution regen in the same change (ADR 0049). `# AUDIT-ONLY` re-check:
   `cargo tree -i <crate> -e normal` for every `.cargo/audit.toml` ignore;
   move/mirror markers if reachability changed.

## Out of scope

Batch 7b (`sqlx` 0.9), upstream-watch group, deferred human decisions
(toolchain MSRV, postgres 18, deploy-image tags).

## Scope / acceptance

- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `cargo test --workspace`, `cargo audit --deny warnings`,
  `cargo deny check` — all in the report as evidence.
- No renovate checkboxes; !289 (reqwest 0.13) auto-closes on merge, !290
  (sqlx 0.9) stays open for 7b.

**Model hint:** capable (TLS/egress security surface; the parity sweep is
security work, not just compile-fixing).
