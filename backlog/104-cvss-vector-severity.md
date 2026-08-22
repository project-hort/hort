# 104 — Compute CVSS base scores from vectors in OSV severity extraction

**Issue:** #151 · **Branch:** `agent/151-cvss-vector-scores` · **Scope:**
`crates/hort-adapters-scanner-osv`, `crates/hort-adapters-advisory-osv`,
`Cargo.toml`/`Cargo.lock` (new dep `cvss`), `THIRD-PARTY-LICENSES.{md,json}`

## Why

OSV frequently delivers severity as a bare CVSS vector with no pre-computed
number — RustSec advisories almost always do. Verified against `api.osv.dev`
for RUSTSEC-2023-0071 (the Marvin advisory on the `rsa` crate):

    "severity": [{ "type": "CVSS_V3",
                   "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" }]

That vector computes to base score 5.9 (Medium) under the CVSS 3.1 spec. The
current extraction in `hort-adapters-scanner-osv/src/severity.rs` (bands
mirrored in `hort-adapters-advisory-osv`'s severity module) tries a numeric
`groups[].max_severity`, then a trailing-`/<float>` heuristic, then a text
label. A pure vector survives none of these, so a fully-scored advisory lands
"unscored" and the fail-closed rule in `parse.rs`
(`unwrap_or(SeverityThreshold::Critical)`, test
`severity_falls_back_to_critical_when_score_absent_fail_closed`) records
Critical. Every vector-only Medium advisory therefore trips
`severityThreshold: high` policies. The CVSS spec defines how a vector
scores; not computing it is implementation drift (spec wins).

## Change

1. **Both** severity modules gain a vector branch: when `severity[].score`
   parses as a CVSS v3.x vector, compute the base score and band it exactly
   like a numeric input. Insert BEFORE the trailing-float heuristic; the
   numeric `max_severity` stays the preferred input. If the two modules can
   share the logic without violating the crate layering, extract it; if not,
   keep them textually mirrored like the existing bands and say so in each.
2. Dependency: the RustSec-maintained `cvss` crate (parses v3.x, computes
   base scores). CVSS_V2 entries stay out of scope — they band `None` and
   fall through to the existing fail-closed path.
3. **The SUP-4 rule is untouched.** Malformed vector or genuinely absent
   severity still fails closed to Critical. Do not weaken, rename, or
   special-case it — this change only stops feeding it false "unscored"
   inputs.

## Tests

- Real Marvin fixture (the OSV JSON above) → Medium, in BOTH adapters.
- Band boundaries via vectors: a ≥9.0 vector → Critical, a <4.0 vector → Low.
- `CVSS:3.1/GARBAGE` → `None` → SUP-4 records Critical (pin alongside the
  existing fail-closed test, do not replace it).
- Existing numeric + label paths: unchanged (regression assertions).

## Dependency discipline (CLAUDE.md — mandatory, same change)

- `cargo audit` + `cargo deny check` after adding `cvss`; re-check every
  `# AUDIT-ONLY` marker in `.cargo/audit.toml` with `cargo tree -i <crate>`.
- `scripts/regenerate-attribution.sh` and commit the updated
  `THIRD-PARTY-LICENSES.{md,json}` in the same commit as the dep add.

## Verification

- `cargo test --workspace` green (structural guards included).
- Coverage ≥85% on both adapter crates; the banding logic is pure — cover it
  exhaustively.
- No change to `hort-domain`/`hort-app` expected; if one becomes necessary,
  stop and report instead of widening scope.

## Out of scope

The registry-side rescan + policy-reevaluation of rsa 0.9.10 (operator step
after deploy), and the per-advisory acceptance feature (#148 option B).
