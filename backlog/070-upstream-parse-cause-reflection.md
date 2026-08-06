# 070 — #124: stop reflecting upstream-registry parse causes in client error bodies

**Issue:** #124 (spec on the issue, approved). Sibling of #123 (request-derived echo
sweep, commit `8aac48c5`) — this item covers the **upstream-derived** reflection class:
content from the configured upstream registry (not the requester's own input) relayed
verbatim into client-facing error bodies on the simple-index / pull-through paths.

**Read first:**
- The reflection vector: `crates/hort-http-core/src/error.rs` —
  `DomainError::Validation(_) → (400, domain_err.to_string())`; any upstream parse
  `cause` threaded into `Validation` reaches the wire verbatim.
- The three confirmed producer→render chains (all thread an upstream-body parse
  `cause` string into `DomainError::Validation(cause)`):
  - **PyPI:** `crates/hort-http-pypi/src/simple_index.rs:316-328,614-617`
    (`IndexFetchError::{MetadataMalformed,VersionObjectTooLarge}{cause}`) →
    `crates/hort-http-pypi/src/index_source.rs:402,421`.
  - **Cargo:** `crates/hort-http-cargo/src/index_cache.rs:355-362` (projector
    `Validation` message captured as `MetadataMalformed{cause}`) →
    `crates/hort-http-cargo/src/index_source.rs:274-284`.
  - **npm:** `crates/hort-http-npm/src/index_source.rs:286-343` (three
    `Validation(cause)` arms) and the packument consumers
    (`crates/hort-http-npm/src/packument.rs:170,296,445-448`).
- The shared error home + coarse-to-typed mapping fns:
  `crates/hort-formats-upstream/src/lib.rs:427-498` (`PackumentFetchError` /
  `IndexFetchError` → `UpstreamFetchError`) — check whether these paths also render
  upstream causes client-side.
- The #123 pattern to mirror (generic constant client message + `tracing::warn!`
  carrying the cause and upstream/repo identifiers as structured fields): see the
  `8aac48c5` diff in `hort-http-{oci,npm,pypi}`.

## Work

1. **Typed boundary, not string laundering.** Prefer a dedicated error variant /
   branch for "upstream index/metadata invalid" over threading pre-formatted strings
   through `DomainError::Validation` — the type distinction is what structurally
   prevents the next `cause` from reaching a response body. Check per crate whether
   the fetch-error type can map to the HTTP response directly (bypassing
   `Validation`). Producers in `hort-formats-upstream` and the per-format helper
   types keep their rich internal messages — the boundary is the HTTP mapping, not
   the error construction.
2. **Client body:** a generic constant message (e.g. "upstream index metadata
   invalid") with no upstream-derived content interpolated. **Server side:** the
   `cause` goes to `tracing::warn!` (upstream faults are operator-relevant) with the
   upstream/repository identifiers as structured fields.
3. **Status semantics:** an upstream parse failure surfacing as **400 Bad Request**
   blames the requester for an upstream fault. Mirror the codebase's established
   wire-map shape for upstream-invalid conditions (the npm/pypi `upstream_pull`
   maps) — message AND status. If that established mapping itself uses 400, keep
   400 for cross-format consistency and note it in the report; do NOT invent a new
   status class without checking what pip/cargo/npm CLIs tolerate on index routes.
4. **Sweep:** all `IndexFetchError`/`PackumentFetchError` render sites in the three
   crates, plus any other `DomainError::Validation(format!(…))` site on these
   index/pull-through paths that interpolates **upstream-derived** (not
   request-derived) content. Request-derived echoes were #123's scope — do not
   re-touch them.
5. **Metrics:** verify each swept path already emits
   `UpstreamErrorKind::parse_error`; wire it where missing (the metrics catalog
   already covers the label).
6. **Tests, per path:** feed a malformed upstream body (fixture) carrying a marker
   string; assert the marker is absent from the client response body (status/code
   otherwise unchanged) and, where the harness supports it, present in captured
   tracing.

## Scope / acceptance

- No behavior change on retry/caching for upstream failures; no change to the #123
  request-echo handling.
- No client-facing body on these paths contains upstream-derived text after the
  sweep; every swept site logs the cause server-side.
- Comments state invariants only — no issue/directive provenance in code comments.
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check`.

**Model hint:** sonnet (multi-crate but pattern-following; the #123 diff is the
template).
