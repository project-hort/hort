# 309 — The other half of the audit invariant, and the comment that hid it

**Issue:** #345 · **Branch:** `agent/345-curation-owns-the-manual-release`
**Governing decisions:** ADR 0007 (the release paths whose audit lines this
invariant covers).

**Depends on item 308**, which lifted the capture harness this unit uses.

## What is true today

`AUDIT-info-2` is a named invariant with **two** halves
(`crates/hort-app/src/use_cases/quarantine_use_case.rs:9484`–`:9487`;
re-measure): the `correlation_id` rides the `record_scan_result` line **and**
the `release_expired` success line.

- The `record_scan_result` half holds and is **asserted**
  (`record_scan_result_log_carries_correlation_id`).
- The `release_expired` half holds in code — `:2143` emits
  `correlation_id = %correlation_id` on the `"released expired artifact"` line
  — and **nothing asserts it.** The one capture test on that line,
  `release_expired_info_log_carries_resolved_authority_kind` (~`:8822`),
  asserts only `authority=scan_succeeded` / `authority=scan_waived`.

**And a comment points the reader away from the gap.** The doc of
`release_expired_fail_closed_logs_skip` (~`:9977`) says:

> *"The success-line + correlation_id assertions are covered by
> `release_expired_info_log_carries_resolved_authority_kind`."*

That is false for the `correlation_id` half. A reviewer who follows the
cross-reference concludes the half is covered, which is how it stayed
invisible — **a false coverage claim is worse than silence**, because silence
invites a check and a citation ends one.

This is not a regression from the one-authority work: the gap predates it (the
same single assertion exists at the public snapshot) and nothing in items
302–308 touched that path. It is in this issue because it is the **other half
of the same named invariant** whose first half item 308 just re-asserted, and
because 308's lifted harness is what makes the assertion cheap and honest.

## What to do

1. **Assert the `release_expired` half.** Use the harness item 308 lifted into
   `use_cases::test_support` (`tracing_capture`), not the file-local
   `(Level, String)` copy: the claim is *this field equals this value*, and a
   flattened line cannot carry it — the equality is the point, exactly as in
   308. Assert `correlation_id` on the `"released expired artifact"` info line
   equals the correlation id the caller passed in.
2. **Mind the name clash.** `quarantine_use_case.rs`'s test module defines its
   own `install_audit_passthrough_subscriber`, and `test_support` now exports
   one too. Qualify or alias at the call site; do **not** rename or delete the
   file-local copy — its six existing capture tests depend on it, and
   converting them is explicitly another item's question.
3. **Correct the false cross-reference** at ~`:9977` to say what the named test
   actually asserts (the resolved authority kind), and point at the new test
   for the `correlation_id` half.
4. **Re-read the `AUDIT-info-2` comment block** and make sure each half it
   names now points at the test that holds it. If the block's wording implies
   more coverage than exists anywhere, fix the wording — the block is the
   index a reviewer trusts.

## Explicitly out of scope

- Any production-code change. Both halves of the invariant hold in code; if
  one turns out not to, stop and report that.
- Converting the three file-local capture copies (item 308 §4 measured why a
  mechanical swap is impossible; it is its own item if it is ever worth doing).
- Any other audit invariant. The census in item 308's report says there are
  exactly two named ones.

## Acceptance

- A test asserts `correlation_id` **equals** the id that candidate's append
  carried, on the `release_expired` success line, through the shared
  `tracing_capture` harness. (Corrected 2026-10-11: an earlier wording said
  "the caller's correlation id". There is no caller-supplied id on this path —
  the sweep mints one per candidate with `Uuid::new_v4()` and
  `AppendEvents::correlation_id` is documented as always server-generated, so
  the assertable equality is log line ↔ appended event, which is also the join
  an operator makes.)
- **Non-vacuity: delete `correlation_id = %correlation_id` from that log line,
  show the test red with its output, restore it.**
- The doc comment at ~`:9977` no longer claims coverage that does not exist,
  and the `AUDIT-info-2` block names a holding test per half.
- `grep -riE 'audit[-_]info[-_]2' crates/hort-app/src` finds the block and both
  halves' tests. Put the output in the report.
- Gate: the **unit gate**, one-shot capture:
  `bash handover/gate-unit.sh -p hort-app` — judge by the output, not the rc,
  and quote the totals. Do **not** run `cargo test --workspace`, `cargo audit`,
  `cargo deny` or the attribution script: together they outlast a worker's
  foreground tool window, so the harness backgrounds them and the run ends with
  the gate killed and the report lost. The architect runs the full gate on the
  same tree before any MR.
