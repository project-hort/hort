# 061 — #95: axum ecosystem upgrade — axum 0.8, axum-extra 0.12, axum-server 0.8, tower-http 0.7

**Issue:** #95 (spec approved on the issue; batch 1 of the en-bloc plan).
**Read first:** the #95 issue description + the plan comment (contract); the failing
renovate pipeline evidence (9+ × E0195 on `from_request_parts` — pipeline 5014, job
42820); axum 0.8 changelog/migration notes (native-async `FromRequestParts`/
`FromRequest`, route template `:param` → `{param}` and wildcard `*key` → `{*key}`,
`Handler` bound changes); every manual extractor impl in `hort-http-core`
(`src/authz.rs`, principal extraction, `WriteRepoAccess`/`DeleteRepoAccess`/…);
router assembly in `hort-server/src/http.rs` + every `hort-http-<format>` route
registration; `MatchedPath` metric label usage in `hort-http-core` middleware.

## Work

1. Bump workspace deps: `axum` → 0.8, `axum-extra` → 0.12, `axum-server` → 0.8,
   `tower-http` → 0.7 (one coherent set; `cargo update` for the four + their
   ecosystem-internal deps only).
2. Migrate every `from_request_parts` / `from_request` impl to the 0.8 native-async
   signatures. Mechanical — no logic changes.
3. Sweep ALL route registrations for the 0.8 template syntax (`:param` → `{param}`,
   `*wildcard` → `{*wildcard}`) across `hort-server` and every `hort-http-<format>`
   crate; sweep for `Handler`/`IntoResponse` bound fallout.
4. **No behavioral change**: error shapes, middleware order, auth semantics
   byte-identical. The existing handler test suites are the wire-contract pin — they
   must pass UNMODIFIED except where a test itself registers a route template using
   the old syntax (adjust syntax only, never assertions).
5. Note in the report: `MatchedPath`-derived `path` metric label VALUES change shape
   with the template syntax (`/v2/:repo_key/...` → `/v2/{repo_key}/...`) — allowed
   (still route templates, catalog rules unaffected), but list the before/after so
   the MR description can carry the dashboard heads-up.
6. Attribution regenerated in the same change (ADR 0049); `# AUDIT-ONLY` marker
   re-check per the CLAUDE.md rule.

## Scope / acceptance

- Renovate !277/!278 auto-close when this reaches `develop`; do not touch them.
- `hort-http-core` ≥ 85% coverage maintained; no new tests required beyond syntax
  adjustments (the suites pin the contract), but every compile-fixed impl must still
  be covered by an existing test — if one isn't, add the missing coverage.
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check`.

**Model hint:** capable (cross-crate mechanical migration with a wide blast radius —
correctness rides on the sweep being exhaustive).
