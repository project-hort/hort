# 153 — refactor the 10 rust:S3776 cognitive-complexity findings to ≤ 50

**Issue:** #220 · **Branch:** `agent/220-sonar-complexity` · Item 1 of 2 (item 154 re-tightens the gate afterwards; one MR when both are done).

## Problem

SonarQube's gate is red on `new_violations: 4 GT 0`; the full open set is 10
findings, all `rust:S3776` (cognitive complexity > 50), all CRITICAL. The
posture decision: refactor, never threshold-raise, never rule-ignore.

## The 10 functions (resolved on develop `2dbb1e18`; line numbers drift — locate by name)

| Function | File | Complexity |
|---|---|---|
| `rust_string_literals` | `crates/hort-app/tests/expand_contract_guard.rs` | 88 |
| `scan_migration` | `crates/hort-app/tests/expand_contract_guard.rs` | 89 |
| `validate_repository` | `crates/hort-config/src/repository.rs` | 67 |
| `put_manifest_dispatch` | `crates/hort-http-oci/src/manifests_write.rs` | 65 |
| `parse_params` | `crates/hort-adapters-upstream-http/src/challenge.rs` | 62 |
| `vuln_to_finding` | `crates/hort-adapters-scanner-osv/src/parse.rs` | 61 |
| `ingest_inner` | `crates/hort-app/src/use_cases/ingest_use_case.rs` | 60 |
| `build_app_context` | `crates/hort-server/src/composition.rs` | 57 |
| `from_env` | `crates/hort-server/src/config.rs` | 54 |
| `record_scan_result` | `crates/hort-app/src/use_cases/quarantine_use_case.rs` | 52 |

## Task

Pure structure-preserving refactors: extract named helper functions (and/or
flatten nesting via early returns) until every listed function is at or
under cognitive complexity 50. Rules:

1. **No behavior change, provably.** Every existing test passes UNCHANGED —
   no test edit is acceptable except moving a test to follow an extracted
   helper (same assertions). If a refactor would require changing a test's
   assertion, stop and flag it in the report instead.
2. **Helpers are real units, not line-count dodges**: a helper gets a name
   that states its job, takes the narrowest parameters that make sense, and
   returns a value (avoid `&mut`-threading state bags where a return value
   works). Match each file's existing naming/comment idiom.
3. **Cognitive complexity, not cyclomatic**: nesting is the main cost —
   prefer extracting deeply-nested blocks (match arms with inner ifs,
   loop bodies) and early-return flattening over splitting flat sequences.
   Rough self-check: after the refactor no function should have > ~4
   nesting levels or a 100+-line body with mixed concerns.
4. **Order of care** (highest risk first, smallest diffs first within):
   the two test-file scanners (`scan_migration`, `rust_string_literals`) are
   guard tests — keep their scanning semantics byte-exact (the guard's
   detection power is the invariant; note in the report how you convinced
   yourself no pattern branch was lost). `record_scan_result`,
   `ingest_inner`, `put_manifest_dispatch` are security-relevant paths —
   extraction only, no reordering of gate checks; `put_manifest_dispatch`
   just gained the `manifest_write_contention` checks — keep each
   check adjacent to its call site when extracting.
5. **Coverage tiers hold**: `hort-app` 100% (extracted helpers inherit
   coverage via the existing tests; add a unit test only where extraction
   creates a genuinely new public-ish seam), others ≥ 85%.
6. Comment discipline: invariants only.

## Explicitly NOT in scope

- The gate re-tighten (`allow_failure` removal) — item 154, after the
  branch pipeline's sonar analysis confirms the findings are gone.
- Refactoring anything not on the list (no opportunistic sweeps).
- Any `sonar-project.properties`/CI change.

## Acceptance

- All 10 functions restructured; the report lists per function what was
  extracted and the reasoning that complexity is now ≤ 50 (structural
  argument: nesting depth removed, branches relocated — no need to compute
  the exact metric).
- Full pre-push gate green (`fmt`, `clippy -D warnings`,
  `cargo test --workspace`, `audit`, `deny`); zero test modifications
  (or each one flagged with its reason).
- The architect verifies the actual Sonar verdict from the branch
  pipeline's `quality:sonar-findings` log after push (analysis runs on
  branch pipelines; that log is the item's external acceptance evidence).

## Governing decisions

#219 D1 (advisory posture parked FOR this work) · no-deadline/design-
cleanliness mandate (refactor over threshold-tuning) · coverage tiers
(CLAUDE.md) · guard-test detection power as invariant (ADR 0030-family for
the expand-contract guard).
