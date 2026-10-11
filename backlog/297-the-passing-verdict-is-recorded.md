# 297 — A scan verdict that does not block is recorded, not only one that does

**Issue:** #344 · **Branch:** `agent/344-scan-verdict-release-authority`
**Governing decisions:** ADR 0007 (the fail-closed release predicate and its
authorities), ADR 0041 (continuous scan-policy enforcement). No ADR change in
this item — it adds no rule, it records a fact the system already derives.

**First of five.** Items 298–301 consume what this one writes.

## What is true today

`QuarantineUseCase::record_scan_result`
(`crates/hort-app/src/use_cases/quarantine_use_case.rs`) computes the scan
verdict and appends `PolicyEvaluated` **only when it blocks**: the push sits
inside `if findings_recorded { … result: PolicyResult::Fail … }` (around
`:432`–`:446`), and `PolicyResult::Pass` appears nowhere in the file.

So a scan that ran, found things, and decided they do not block leaves **no
record of the decision**. The stream says a scan completed and how many
findings it carried; it does not say that the verdict was *reached* or what it
was.

That absence is load-bearing downstream: the release sweep cannot read a
verdict it was never given, which is why it fell back on counting findings
(item 298 closes that, and cannot without this item).

**The precedent is in the same crate.** `PolicyResult::Pass` is already written
in production by the promotion path —
`crates/hort-app/src/use_cases/promotion_use_case.rs:278`, `:326`, `:375` —
where a passing gate is recorded as an event. The scan path is the outlier, not
the pioneer.

## What to do

1. **Append `PolicyEvaluated { result: Pass }` when the verdict does not
   block**, from the same place the `Fail` is appended, in the same batch as
   the `ScanCompleted` it belongs to. Mirror the promotion path's field usage
   rather than inventing a shape: same event, same `policy_id` resolution, same
   violations field (empty).
2. **Keep it one append per verdict.** A scan produces exactly one
   `PolicyEvaluated`, `Pass` or `Fail`, never both and never none. State that
   invariant where the append happens — it is what items 298 and 301 rely on.
3. **Do not change what `ScanCompleted` carries.** `finding_count` keeps
   counting all findings and the severity summary stays as it is; this item
   adds the verdict beside them, it does not reinterpret them.
4. **No new event type, no new variant, no new metric.** If you find yourself
   adding one, stop and report — the shape already exists.

## Explicitly out of scope

- The sweep's authority derivation (item 298) and the authority value itself
  (item 299). This item only makes the fact available.
- Re-blocking a released artifact (item 300).
- Any backfill. Artifacts scanned before this item carry no `Pass` event, and
  item 298 keeps the existing clean-scan path precisely so that no backfill is
  needed.

## Acceptance

- A scan with findings none of which breach the threshold appends
  `ScanCompleted` **and** `PolicyEvaluated{Pass}` in one batch, with the
  policy attribution the `Fail` path already carries.
- A scan whose findings breach the threshold still appends exactly one
  `PolicyEvaluated{Fail}` and the paired `ArtifactRejected`, unchanged — assert
  the batch, not just the status.
- A clean scan (no findings at all) appends `PolicyEvaluated{Pass}` too: "the
  verdict was reached and it passed" is the same statement whether the finding
  list was empty or merely harmless. A test pins both shapes.
- No test asserts the **absence** of a `PolicyEvaluated` for a passing scan; if
  one exists today, it encoded the gap and the report says which one changed.
- Gate: full local gate, one-shot capture, foreground, report before exit.
