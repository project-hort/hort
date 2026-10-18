# 308 — The audit invariant keeps its assertion

**Issue:** #345 · **Branch:** `agent/345-curation-owns-the-manual-release`
**Governing decisions:** ADR 0007 (the manual release and its attribution),
ADR 0012 / ADR 0038 (why the acting identity is the audit record's point).

**Depends on item 304**, which removed the path the assertion was written
against. Independent of items 305–307.

## What is true today

`AUDIT-info-1` is a named invariant: **the manual release's success log line
carries the acting `user_id`.** Until item 304 it had exactly one assertion,
`admin_release_success_log_carries_user_id`, and that test died with the route
it tested.

The invariant itself is intact in code — `CurationUseCase::waive`'s success
line emits `actor_id = %user_id`
(`crates/hort-app/src/use_cases/curation_use_case.rs:715`; re-measure) — but
**nothing asserts it**, so a future edit that drops the field is green.

The obstacle is why item 304 left it: asserting a `tracing` field needs a
capture subscriber, and `curation_use_case.rs` has none. Three near-identical
capture layers already exist under three different names, each private to its
own test module:

| Layer | File |
|---|---|
| `AuditCapturingLayer` + `install_audit_passthrough_subscriber` | `crates/hort-app/src/use_cases/quarantine_use_case.rs:9498` |
| `F7CapturingLayer` | `crates/hort-app/src/use_cases/apply_config_use_case/service_accounts.rs:754` |
| `CapturingLayer` | `crates/hort-app/src/use_cases/repository_access.rs:959` |

A fourth copy is what the duplication rule forbids (three structurally similar
blocks is already the threshold), and `crates/hort-app/src/use_cases/test_support.rs`
— where this crate's shared test machinery lives — carries no tracing harness
at all.

## What to do

1. **Lift one capture harness into `use_cases::test_support`**, under
   `#[cfg(test)]`, with the shape the three copies agree on: a `Layer` that
   records each event's target, level, message and fields into a shared buffer,
   plus the passthrough-subscriber install that survives libtest's parallelism.
   Take the richest of the three as the base (`AuditCapturingLayer` records
   fields, which is what an audit assertion needs) and document on it **what it
   is for**: asserting that a named audit invariant's field is actually emitted.
2. **Re-assert AUDIT-info-1 on the surviving path.** A test on
   `CurationUseCase::waive` that captures the success line and asserts the
   `actor_id` field is present **and carries the acting user's id** — not merely
   that some field exists. Name it for the invariant so a grep for
   `AUDIT-info-1` finds it.
3. **Leave the three existing copies alone unless the swap is mechanical.** If a
   copy can adopt the lifted harness by deleting its local definition and
   changing an import, do it, one file at a time, and say so. If it cannot —
   a different field set, a different install discipline — leave it and say
   which, with the difference named. Do **not** rewrite a passing audit test to
   fit the shared harness; the harness exists to serve the assertions, not the
   other way round.
4. **Say in the report whether any other named audit invariant lost its
   assertion** in the same removal. Grep the `AUDIT-info-` and `AUDIT-` comment
   blocks in `hort-app` and state, per invariant, where its assertion lives now.

## Explicitly out of scope

- Any production-code change. This unit adds no behaviour; if the invariant
  turns out to be false in code, stop and report that instead of fixing it
  here.
- A new audit field, a new log line, or a change to what `waive` logs.
- Converting the three existing copies when the swap is not mechanical (task 3).

## Acceptance

- `use_cases::test_support` exports the capture harness, documented, under
  `#[cfg(test)]`.
- A test named for AUDIT-info-1 asserts `actor_id` is emitted on `waive`'s
  success line with the acting user's id. **Non-vacuity: delete the
  `actor_id` field from the log line, show the test red, restore it** — and put
  that output in the report.
- The report states, per named audit invariant in `hort-app`, where its
  assertion lives.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p hort-app` — check, fmt, clippy and that
  crate's tests. Judge by the output, not the rc, and quote the totals. Do
  **not** run `cargo test --workspace`, `cargo audit`, `cargo deny` or the
  attribution script: together they outlast a worker's foreground tool window,
  so the harness backgrounds them and the run ends with the gate killed and the
  report lost. The architect runs the full gate on the same tree before any MR.
