# 264 — `ScanPolicy.maxArtifactAge` is accepted at apply and inert at runtime

**Issue:** #334 · **Branch:** `agent/334-struktur-332`
**Governing decisions:** ADR 0015 (a policy field accepted at apply and
ignored by its consumer is a hard block; the structural close is an
apply-time linter rejection). This is the fourth instance of the class
unit 260 closed three of — same ADR, same pattern, same placement rule.

## Why

`ScanPolicy.maxArtifactAge` travels the whole configuration path and is
never read by anything that decides:

- `crates/hort-config/src/scan_policy.rs:74` declares it on the spec and
  `:244` validates its **format** (`90d` parses, garbage is rejected).
- `crates/hort-app/src/use_cases/apply_config_use_case.rs:1775` converts it
  to `max_artifact_age_secs` on the projection.
- `crates/hort-adapters-postgres/src/policy_projection_repo.rs` persists and
  reads back the column; `crates/hort-app/src/gitops/event_sourced.rs:332`
  drift-detects it and `:624` writes it into the config snapshot.

And then nothing consumes it. The evaluator exists —
`hort_domain::policy::evaluate_age_gates`
(`crates/hort-domain/src/policy/age.rs:30`), which turns an exceeded cap
into a `Medium` `PolicyViolation` with rule id `max-artifact-age` — but
**its only callers are its own `#[cfg(test)]` tests**. Verified: the eight
call sites in `age.rs` are all tests, and `policy/mod.rs:38` re-exports it
to no one. No scan-result evaluation, no release decision and no retention
pass ever asks the question.

So an operator who writes `maxArtifactAge: 90d` has declared a staleness
cap, can read it back from the policy, sees it in the config snapshot and
in drift detection — and no artifact is ever flagged for age. That is the
ADR 0015 shape exactly, and it is the *same* shape as row 6
(`PrefetchPolicy.maxAgeDays`), one policy kind over.

**The admin API is not a second door.** `UpdateScanPolicyCommand`
(`crates/hort-app/src/use_cases/policy_use_case.rs:156`) carries the field,
but nothing outside `policy_use_case.rs` constructs that command — verified
by grep across `crates/`. Gitops apply is the only live writer, so the
apply-time row is the complete close. Do **not** add an HTTP-side guard;
there is no HTTP side.

## What to do

Add row 13, mirroring rows 10–12 from unit 260 exactly.

1. **The validator.** A new
   `validate_scan_policy_max_artifact_age_not_implemented(state) ->
   Vec<ValidationError>` in `crates/hort-config/src/desired.rs`, modelled on
   `validate_scan_policy_license_policy_not_implemented` at `:1197`. The
   predicate is simpler than row 10's: `max_artifact_age` is
   `Option<String>`, so **any `Some` is the reject** and the inert default is
   the absent field — the row 6 predicate, not the row 10 one. Name the
   envelope in the message, say that the cap is not evaluated and that
   removing the field is how to apply.

2. **The rule.** `LinterRule::ScanPolicyMaxArtifactAgeNotImplemented` in
   `crates/hort-app/src/lint/static_validate.rs`, **appended after row 12**
   (`VirtualMemberFormatNotEnforced`, `:265`), with the same doc note the
   rows above carry: apply aborts on the first row with error findings, so
   appending is the only placement that cannot change which message an
   already-failing config rejects with. Add
   `RULE_SCAN_POLICY_MAX_ARTIFACT_AGE_NOT_IMPLEMENTED =
   "scan_policy_max_artifact_age_not_implemented"` beside the consts at
   `:146`/`:161` and return it from `metric_rule()`. Reject + metric.

3. **Wire it** into the validator pass beside rows 10–12
   (`static_validate.rs:580-598`) and register it on the apply side where
   `ScanPolicyLicensePolicyNotImplemented` is registered
   (`apply_config_use_case.rs:704`).

4. **Classify it in `PRE_WRITE_REJECT_ROWS`.** The match at
   `apply_config_use_case.rs:7208` is wildcard-free by design (unit 259), so
   the new variant **will not compile** until it is classified. It is a
   pre-write reject, like rows 9–12.

5. **The shipped fixture sets it.**
   `scripts/native-tests/fixtures/gitops-policies/policies/scanpolicy-default-quarantine.yaml:12`
   carries `maxArtifactAge: 90d`. Remove the line. That file already carries
   the scar from unit 260 — read its `licensePolicy: {}` comment, which says
   in so many words that an apply-time rejection here "would park the whole
   smoke stack at boot". Four host-test scripts consume this tree
   (`test-gitops-policies.sh`, `test-vulnerability-scan.sh`,
   `test-notifications-rbac.sh`, `test-rescanning.sh`); none asserts the
   value — the only `maxArtifactAge` occurrence under `scripts/` is the
   fixture line itself. Leave a comment in the fixture in the shape of the
   neighbouring one, stating the invariant and not the provenance.

6. **Docs.** `docs/architecture/reference/apply-time-linter-rows.md`: a
   Table 1 row (13, rule + metric, subject
   `ScanPolicy.maxArtifactAge`, rejects "any value") and a **retirement
   trigger** row — retired when a consumer feeds `max_artifact_age_secs` and
   the artifact's ingest instant through `evaluate_age_gates` and folds the
   violation into the accumulator. Sweep the other docs the way unit 260
   did only where they enumerate the rows.

**Do not** touch the format validation at `scan_policy.rs:244`, and do not
delete `evaluate_age_gates`. The evaluator is the implementation this row is
held open for; the row withdraws the operator surface until something calls
it.

## Acceptance

- A gitops tree with `maxArtifactAge:` set on any `ScanPolicy` is rejected
  at apply, before the first write, naming the envelope and the field.
- The same tree with the field removed applies unchanged.
- The metric `hort_apply_config_linter_total{rule="scan_policy_max_artifact_age_not_implemented"}`
  ticks on the rejection.
- `gitops_trees_validate.rs` covers the new row the way it covers rows
  10–12, and every checked-in gitops tree in the repository still validates
  — the fixture sweep is part of this unit, not a follow-up.
- The reference doc lists row 13 in both tables.
- Gate green: `cargo fmt --check`, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo test --workspace --no-fail-fast`,
  `cargo-audit audit --deny warnings`, `cargo deny check`.
