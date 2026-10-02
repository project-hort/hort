# 240 — `UnusedFor` is accepted at apply and silently means `AgeExceeds`

**Issue:** #299 · **Branch:** `agent/299-unusedfor-apply-rejection`
**Governing decisions:** ADR 0015 (apply-time rejection of accepted-but-inert
policy fields; `max_age_days` is the canonical exemplar) · #287 part 2 /
`backlog/225-unused-for-download-input.md` (the usage signal itself, still
deferred) · #281 (the deferral decision).

## Why

`UnusedFor` is writable, accepted at apply, and means something other than what
it says. The chain, each link verified in the code:

1. `crates/hort-app/src/use_cases/retention_use_case.rs:470` hands the evaluator
   a hard-coded `last_downloaded_at: None`, with its own comment saying the
   anchor has no source. No port supplies a usage signal.
2. `crates/hort-domain/src/retention/evaluate.rs:168` falls back to `created_at`
   in the `None` arm.
3. So `UnusedFor(30d)` **is** `AgeExceeds(30d)`. An artifact downloaded
   yesterday expires as soon as it is old enough.
4. Nothing rejects it at apply. `validate_retention_policy`
   (`crates/hort-config/src/retention_policy.rs:244`) resolves the predicate and
   calls `PolicyPredicate::validate()`, which is purely structural; the linter
   rows in `crates/hort-app/src/lint/static_validate.rs` have no retention
   variant at all.

This is worse than the inert case ADR 0015 names. An inert field does nothing;
this one does something else. An operator writing `UnusedFor(90d)` is deciding
about *usage* — "what nobody fetches any more may go" — and gets a decision
about *age*. On a proxy cache the gap is small. On a hosted repository it is the
difference between "unused" and "stable and in constant use": an artifact that
has sat for a year and is pulled daily is the last thing to go under one reading
and the first under the other.

## Scope

**This item does not implement the usage signal.** That is
`backlog/225-unused-for-download-input.md`, deferred until the first real
cleanup has been measured, and the deferral stands. This item closes only the
hole the deferral left open: while the signal is missing, the policy must not be
accepted.

## Two precedents, on different axes — read both

- **The category precedent** is `max_age_days`: `LinterRule::
  PrefetchMaxAgeDaysNotImplemented` (`static_validate.rs:134`) backed by
  `hort_config::desired::validate_prefetch_max_age_days_not_implemented`
  (`desired.rs:967`). It is ADR 0015's named exemplar, it emits
  `hort_apply_config_linter_total`, and its message states the missing
  capability and tells the operator what to do.
- **The shape precedent for a retention rule** is
  `push_retention_policy_scope_reference_errors` (`desired.rs:1174`), which
  already walks `state.retention_policies`, resolves a `serde_json::Value`
  field through `scope_from_value`, and reports per envelope.

Note the field is **not** a typed predicate on the envelope: `RetentionPolicySpec
.predicate` is a `serde_json::Value` resolved through `predicate_from_value`. Any
rule must resolve it first, and must not double-report when the resolve itself
already failed.

## The placement decision this item has to make

Two insertion points are defensible and they differ in what the operator gets:

- **inside `validate_retention_policy`** — the predicate is already resolved
  there and already validated, so the rule is a few lines and reaches both the
  apply path and the `validate-config` CLI for free. No metric.
- **as a new `LinterRule` row** — mirrors the `max_age_days` exemplar exactly:
  its own rule constant, a `metric_rule()` entry, a place in the documented row
  table and the ordering test. Emits `hort_apply_config_linter_total`.

Decide with an argument. The criterion that should settle it: whether a
rejection of this class is one an operator should be able to *see having
happened* on a fleet, which is what the counter is for and what ADR 0015's
exemplar chose.

## Acceptance

- A gitops envelope carrying `UnusedFor` — at the root **or nested inside a
  `Composite`** — is rejected at apply, with a message that names the reason
  (no usage signal exists; the predicate would fall back to age) and the
  alternative (`AgeExceeds`, if age is what was meant).
- A test that catches a **nested** `UnusedFor`. A rule that only inspects the
  root predicate is the obvious and wrong implementation; `is_security_driven`
  (`predicate.rs:109`) is the in-tree example of a recursive walk over the same
  tree.
- Every other predicate is untouched — in particular `AgeExceeds`, which has
  the semantics `UnusedFor` accidentally delivers today.
- The rule carries its own **retraction condition** in its doc comment: it goes
  away in the same commit that wires the usage signal. A guard that outlives its
  reason is the failure this repository has now seen three times.
- The placement decision is argued in the commit body.
- Gate green.

## Explicitly not in this item

- No usage signal, no `last_downloaded_at` port, no download-projection read.
- No change to `PolicyPredicate::validate()`. The predicate is structurally
  valid; what is missing is an adapter, and a domain-level rejection would make
  `UnusedFor` unconstructible and have to be undone in the domain later.
- No removal of the `UnusedFor` variant or its `ExpirationReason::UnusedTtl`.
