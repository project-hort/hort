# 066 — #101: en-bloc batch 6 — jsonwebtoken 11 (auth-surface major)

**Issue:** #101 (spec on the issue is the contract; batch 6 of the #95 en-bloc plan).
**Read first:** the #101 issue description; jsonwebtoken 10→11 changelog/migration
notes; the OIDC adapter's Cargo.toml comment on why decode-without-verify needs
the two-step dance; CLAUDE.md → *Pre-push Quality Checklist*.

## Work

1. Bump `jsonwebtoken` 10.4 → 11 (workspace pin, keep `aws_lc_rs` feature).
2. Migrate call sites: `hort-adapters-oidc/src/{lib,multi_issuer}.rs` (~37 sites,
   JWKS/issuer validation) + `hort-app/src/oci_token_signing.rs` (~10 sites, OCI
   token issuance). Mechanical only.
3. **Validation-parity table in the report** (the load-bearing deliverable):
   enumerate every v11 change to `Validation` defaults/semantics touching our
   usage — `required_spec_claims`, aud/iss checking, algorithm restriction,
   leeway, key handling — and state per call site that behavior is identical.
   Pin back explicitly any changed default (no silent loosening OR tightening).
4. Existing OIDC/OCI suites pass with assertions unmodified. Every compile-fixed
   site covered by an existing test; add coverage where missing.
5. **STOP condition:** v11 removes/alters an API such that validation parity
   cannot be demonstrated mechanically → STOP and report.
6. Scoped `cargo update`; no unrelated lock drift. Attribution regen (ADR 0049);
   `# AUDIT-ONLY` re-check (`cargo tree -i <crate> -e normal`).
7. Do NOT ask interactive questions — the report is the escalation channel.

## Scope / acceptance

- Out of scope: batch 7 (reqwest+object_store, sqlx), upstream-watch group,
  deferred human decisions.
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check` — all
  in the report as evidence.
- No renovate checkboxes; the jsonwebtoken-11.x entry resolves on merge.

**Model hint:** capable (auth-surface major; the validation-parity analysis is
security work, not just compile-fixing).
