# 354 — A policy duration the system cannot compute with is refused, and the sweep survives one anyway

**Issue:** #389 · **Branch:** `agent/389-bounded-policy-duration`
**Governing decisions:** ADR 0007 (release authority — the sweep this protects
is what grants it) · ADR 0015 (the apply-time-rejection shape, and why this is
*not* an instance of it) · #331 E93 (where this was first recorded).

## What is true today

`quarantineDuration` is a humantime string validated **only** for
parseability — `crates/hort-config/src/scan_policy.rs:48` declares it,
`:275` validates it through `parse_humantime`, and `:398-400` is that function:
a bare `humantime::parse_duration`. There is no upper bound anywhere in the
file.

Two independent sites then convert it to `i64` seconds, and **both carry a
panic asserting a validation that was never written**:

| Site | The assertion |
|---|---|
| `crates/hort-app/src/use_cases/apply_config_use_case.rs:1983` | `i64::try_from(dur.as_secs()).expect("INVARIANT: duration validated to fit in i64")` |
| `crates/hort-app/src/gitops/event_sourced.rs:777` | the same conversion, and the message says it outright: *"validator should have rejected"* |

`chrono::Duration::seconds` in 0.4.45 is
`expect(TimeDelta::try_seconds(seconds), "TimeDelta::seconds out of bounds")`,
and `try_seconds` returns `None` above `i64::MAX / 1_000` (≈ 9.223e15) — read
from the crate source at tag `v0.4.45`, not from memory. The release sweep
forms `now - chrono::Duration::seconds(secs)` at
`crates/hort-adapters-postgres/src/quarantine_release_candidates.rs:289`, in
the per-repository cutoff loop. The `.max(0)` on the line above clamps only
the negative side.

## Why this is a defect

Two panics are reachable from one unvalidated operator field:

- `as_secs() > i64::MAX` → the **gitops apply** dies in the conversion. A
  configuration value crashes the apply instead of being refused with a
  message.
- `as_secs()` between ≈ 9.223e15 and `i64::MAX` → the apply *succeeds*, the
  value is stored, and the **release sweep** dies.
  `quarantineDuration: "300000000years"` (≈ 9.5e15 s) is in that window.

The second is the serious one. The sweep is deployment-wide and single, so one
policy with an absurd duration stops **every** release in the installation, in
a crash loop, and nothing about the input told the operator they had done it.

## The change — two halves with different jobs

### Half 1: refuse it at apply (the structural close)

Write the check the two panics already claim exists, in
`hort_config::scan_policy::validate_scan_policy`, beside the humantime parse
that is already there.

- The bound is **derived, not invented**: a duration must survive
  `TimeDelta::try_seconds`, i.e. `as_secs() <= i64::MAX / 1_000`. Name it as a
  constant. The rule is "a duration the system can compute with", and one
  check closes both panics.
- The refusal names the value, the bound and the field.
- **Leave both conversion panics in place.** They become true instead of
  asserting a check nobody performs. Do **not** substitute
  `unwrap_or(default)`: a silently clamped quarantine window is a security
  decision nobody took.
- If the bound cannot be expressed without `chrono` inside `hort-config`,
  stop and report what you would need rather than hard-coding
  `9223372036854775`.

### Half 2: the sweep stops being able to panic (owner's decision, 2026-10-31)

`try_seconds` instead of `seconds` at
`quarantine_release_candidates.rs:289`; a repository whose stored duration is
not representable is **named in an `error!` and skipped**, and the remaining
repositories' candidates come back normally.

This is not defence against the gap half 1 closes. It is the behaviour the
sweep should have for **any** uncomputable row, however it arrived — a
hand-written row, a migration, a future writer. Half 1 also cannot heal a
value already stored: that one keeps killing the sweep until the YAML is
corrected and re-applied, so without half 2 an installation already in the
crash loop has no way out but a config change.

**The skip must not be silent.** The log line carries the repository id and
the value that makes it uncomputable, so "no releases in this repository" can
never be read as calm.

Note the site moved: unit 353 replaced the per-duration-group queries with one
ordered query, but the per-repository cutoff loop that computes `secs` survives
and is still where the panic is.

## Acceptance

1. `quarantineDuration: "300000000years"` is refused at apply, with the value,
   the bound and the field name in the message.
2. `"100000000000years"` (over `i64::MAX` seconds) is refused by the **same**
   check, not a second one.
3. A duration exactly at the bound is accepted; one second over is refused.
   The bound is a named constant, not a literal in two places.
4. Counter-assertion: `24h`, `0s` and `7d` stay accepted, and a malformed or
   negative duration is still refused by the existing check.
5. Both conversion paths are covered — a test drives the **gitops** path
   (`gitops/event_sourced.rs`), not only the apply path. Covering one would
   leave the other holed.
6. The sweep survives an uncomputable stored row: a hand-set
   `quarantine_duration_secs` above the bound does **not** panic
   `select_expired`; that repository is skipped and named in the log with its
   id and value, and the other repositories' candidates are returned.
7. Counter-assertion to 6: with only computable durations the selection is
   unchanged — the same candidates in the same order as unit 353 left it.
8. `hort-config` ≥ 85 %, `hort-app` 100 % for new branches; DB-backed tests
   carry `#[serial(hort_pg_db)]`.

## Out of scope

- Any other humantime field. The census found `quarantine_duration` to be the
  only one reaching `chrono::Duration::seconds`; a second field with the same
  shape would be its own unit.
- Clamping, defaulting or rounding a value the operator set. Refuse or skip,
  never silently alter.
- The `0` case. `quarantineDuration: 0s` is a declaration (release
  immediately) and stays accepted.
