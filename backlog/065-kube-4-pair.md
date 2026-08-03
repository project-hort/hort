# 065 — #100: en-bloc batch 5 — kube 4 + k8s-openapi 0.28 (coupled pair)

**Issue:** #100 (spec on the issue is the contract; batch 5 of the #95 en-bloc plan).
**Read first:** the #100 issue description; CLAUDE.md → *Pre-push Quality Checklist*;
the `Cargo.toml` comment block at the `kube`/`k8s-openapi` declarations (it encodes
the pairing rationale you must update); kube 4.x release notes.

## Work

1. Bump the pair in the workspace root: `kube` 3.1 → 4 (keep
   `default-features = false, features = ["client", "rustls-tls"]`; verify the 4.x
   feature names) + `k8s-openapi` 0.27 → 0.28 (keep `features = ["latest"]`).
2. Update the pairing comment block (kube-major ↔ k8s-openapi-major, and the
   `latest`-release K8s API surface it names).
3. Migrate kube-4 fallout in `crates/hort-adapters-kubernetes/src/{lib,payload,secret_writer}.rs`
   and the two composition roots (`hort-server`, `hort-worker`) mechanically.
   No behavioral change — the secret-writer suite pins the contract, assertions
   unmodified.
4. **STOP condition:** fallout beyond mechanical call-site adjustment (config/auth
   model change altering the opt-in wiring semantics) → STOP and report.
5. Scoped `cargo update` for the pair + their internals; no unrelated lock drift.
6. Attribution regen in the same change (ADR 0049); `# AUDIT-ONLY` re-check
   (`cargo tree -i <crate> -e normal`).
7. Do NOT ask interactive questions — the report is the escalation channel.

## Scope / acceptance

- Out of scope: everything else (batches 6–7, upstream-watch group, deferred
  human decisions).
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check` — all
  in the report as evidence.
- No renovate checkboxes; the rate-limited kube/k8s-openapi entries resolve on merge.

**Model hint:** small model (contained mechanical pair bump); STOP rather than
escalate effort if it turns non-mechanical.
