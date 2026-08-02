# 060 — #96: en-bloc lockfile-compatible bump batch (12 crates)

**Issue:** #96 (spec approved on the issue; batch 2 of the #95 en-bloc plan).
**Read first:** the #96 issue description (the exact crate list is the contract);
CLAUDE.md → *Pre-push Quality Checklist* (attribution + audit/deny + AUDIT-ONLY
marker rules).

## Work

1. On this branch, in the sandbox: `cargo update -p <crate> --precise <version>` for
   exactly: `bytes` 1.12.1, `clap_complete` 4.6.8, `dashmap` 6.2.1, `http` 1.5.0,
   `humantime` 2.4.0, `hyper` 1.11.0, `jsonwebtoken` 10.4.0, `regex` 1.13.1,
   `rustls-pki-types` 1.15.1, `tokio` 1.53.1, `uuid` 1.24.0, `zeroize` 1.9.0.
   `Cargo.lock`-only — zero `Cargo.toml` requirement changes.
2. **Drop-and-report rule:** if any bump forces a code or requirement change, drop it
   from the batch and note it in the report (it belongs to a later batch) — do NOT
   fix code here.
3. Regenerate `THIRD-PARTY-LICENSES.{md,json}` in the same commit (ADR 0049).
4. Re-check every `# AUDIT-ONLY` marker in `.cargo/audit.toml` with
   `cargo tree -i <crate> -e normal` (the rc.10 trap) — mirror to `deny.toml` if any
   previously-inactive crate became active-graph-reachable.

## Scope / acceptance

- One commit (bumps + attribution) or two (bumps, attribution) — implementer's choice.
- Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo audit --deny warnings`, `cargo deny check` — all in
  the report as evidence.
- Renovate's corresponding dashboard entries auto-resolve post-merge; no dashboard
  checkboxes.

**Model hint:** small model (mechanical).
