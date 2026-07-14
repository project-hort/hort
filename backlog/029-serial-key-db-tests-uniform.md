# 029 — Uniform `#[serial(hort_pg_db)]` on the crate's DB-touching tests

- **Source:** GitLab issue #29. **Direction confirmed by maintainer 2026-07-14: path (b) — uniform compliance** (add the key to all DB-touching tests, even where a given test is already isolated by construction).
- **Type:** chore (test hygiene) — `hort-adapters-postgres` test files only.
- **Model hint:** **small** — mechanical, pattern work (add an attribute + an import). Ideal small-model directive. Needs a `cargo`-capable env (the architect host has none) → cockpit directive.
- **Reviewable unit:** one directive.

## Context (validated)

The CLAUDE.md DB-test isolation contract states *every* `hort-adapters-postgres` test
that acquires a real connection MUST carry `#[serial(hort_pg_db)]`. Validation on #29
found the originally-named test (`list_candidates_excludes_oci_format`) is in fact
isolated by construction (scoped query + unique-key repo), so it is not an active
*defect* — but the rule is a **blanket "MUST" for review-enforceability** (per-test
non-interference analysis doesn't scale to review), and the maintainer chose uniform
compliance. So: bring the whole crate's `tests/` into compliance, don't just patch one test.

## Scope — the 9 files with **zero** `#[serial]` today

Add `#[serial(hort_pg_db)]` to **every test that acquires a real DB connection**
(calls `admin_pool()` / `maybe_pool()`) in:

| File | DB-touching tests |
|---|---|
| `tests/patch_candidate_repo.rs` | 6 |
| `tests/api_token_repo.rs` | 10 |
| `tests/subscription_repo.rs` | 11 |
| `tests/migration_009_jobs_and_findings.rs` | 10 |
| `tests/migration_010_rescan_and_advisory.rs` | 3 |
| `tests/migration_011_gitops_machine_identity.rs` | 7 |
| `tests/repo_security_score_repository.rs` | 8 |
| `tests/api_token_revocation_listener.rs` | 3 |
| `tests/events_role_hardening.rs` | 7 |

(~65 tests total; all `#[tokio::test]`. Grep-derived counts — the implementer confirms
per file, since a rare non-DB helper test in a file must NOT get the key.)

## Mechanics

- The macro is `serial_test::serial`; `serial_test = { workspace = true }` is already a
  dev-dep — no `Cargo.toml` change. Add `use serial_test::serial;` to any file that
  lacks it.
- The key is the **crate-wide** `#[serial(hort_pg_db)]` (same string every existing
  serialized test uses — do not invent a new key).
- **Mirror the existing attribute order** used elsewhere in the crate (e.g.
  `tests/rescan_candidates.rs`) so the diff reads uniformly.
- Only tests that touch the shared DB need it. A pure/helper `#[test]` that never
  acquires a connection does not (there likely are none in these files, but check).

## Out of scope

- Files that already carry the key (e.g. `rescan_candidates.rs`, `jobs_repository.rs`,
  `curation_queue_repository.rs`, `api_tokens_migration.rs`, …) — leave untouched.
- Inline `#[cfg(test)]` `--lib` DB tests in `src/*.rs` (this directive is the `tests/`
  integration targets; if the implementer wants to sweep those too, flag it — not required here).
- A structural guard test to prevent regression (grep `tests/` for DB-touching-without-serial)
  is a reasonable **optional follow-up** but is NOT part of (b); mention it in the report
  if you think it's worth a separate issue, don't build it here.

## Acceptance criteria

1. Every DB-connection-acquiring test in the 9 files above carries `#[serial(hort_pg_db)]`;
   `use serial_test::serial;` present in each.
2. No new key string invented; no `Cargo.toml` change; files already compliant untouched.
3. `cargo test --workspace` still green (DB-gated tests self-skip without `DATABASE_URL`);
   with `DATABASE_URL` set, the crate's `tests/` run serialized under the one key.
4. Full local gate green (fmt / clippy -D warnings / `cargo test --workspace` / audit / deny).

## Verification (for the cockpit report)

- Per-file before/after count of `#[serial(hort_pg_db)]` occurrences.
- A grep proving no DB-touching test in these files lacks the key after the change.
- `cargo test --workspace` output (0 failed).
