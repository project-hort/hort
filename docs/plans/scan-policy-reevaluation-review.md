# ADR 0041 (continuous scan-policy enforcement) — architect review

- **Reviewed:** `docs/adr/0041-continuous-scan-policy-enforcement.md` (Status: Proposed)
- **Companion design doc:** `docs/plans/scan-policy-reevaluation.md`
- **Reviewer:** hort-architect
- **Date:** 2026-06-28
- **Verdict:** **Approve the direction; three findings must be resolved in the
  design doc before implementation.** Claims verified against the code
  (file:line below), not the spec's self-citation.

Branch-local review scaffolding (doc-lifecycle D7 — durable record is the ADR +
the design doc + the how-to; remove before merge to main).

## Summary verdict

The design is materially stronger than the discarded draft (per-artifact admin
rescan-to-un-reject) and surfaces a real, code-confirmed **fail-open** gap that
the draft missed. Approve the approach. Do **not** implement until the design doc
resolves ① the cross-axis conjunction (and the pre-existing bug it exposes), ②
the async + paginated tightening pass, and ③ the widened audit event — and
corrects two spec lines (the provenance "Composes" matrix cell and the "no new
release surface" framing).

## What's right (endorse)

- **The fail-open finding is real — confirmed in code.** `update_policy`
  (`crates/hort-app/src/use_cases/policy_use_case.rs:379-640`) and
  `remove_exclusion` (`:1417-1619`) both return `Ok(())` with **no**
  re-evaluation pass. Tightening the scan policy (raise the bar / add a blocked
  class / `negligible_action: Block` / remove an exclusion) re-judges nothing, so
  an artifact the operator just declared unacceptable stays downloadable. The
  discarded draft would have left this open; this design closes it.
- **The evidence/interpretation split is the correct model** — stored
  `scan_findings` are the evidence; the policy is the interpretation; re-derive
  the verdict via the pure `evaluate_scan_result`, no scanner. Matches ADR 0040's
  persist-fact/derive-interpretation precedent.
- **No new release authority** — reuses authority #5 (`PolicyReEvaluation`); ADR
  0007's enumerated predicate is untouched on the release side (modulo finding ①).
- **Planning hygiene present** — the design doc carries the §0 deferred-items
  sweep, the re-validated ADR 0007 rationale, and a §5 observability section with
  a catalog-bound `hort_policy_reevaluation_*{result}` metric.
- **Number collision reconciled** — the discarded ADR + its plan docs are staged
  for deletion; the "Replaces" line + Alternatives fold the prior draft.

## Findings

### ① CRITICAL — the cross-axis composition the spec promises does not exist, and the *existing* pass already fails open across axes

ADR line 130 claims a newly-scan-passing artifact "still requires provenance
clearance to release." The code contradicts this:

- `Artifact::re_evaluate` (`crates/hort-domain/src/entities/artifact.rs:720-751`)
  checks **only** `quarantine_status == Rejected` + the quarantine deadline. No
  rejection-reason, curation, or provenance check before `Rejected → Released`.
- `re_evaluate_after_exclusion`
  (`crates/hort-domain/src/policy/re_evaluation.rs:145-181`) re-runs **scan-only**
  (CVE thresholds + `negligible_action`).
- `list_rejected_for_policy`
  (`crates/hort-adapters-postgres/.../artifact_repo.rs:679`) returns **every**
  `Rejected` artifact under the policy, `WHERE quarantine_status = 'rejected'`,
  regardless of *why* it was rejected.

**Consequence (today, not hypothetical):** adding a scan exclusion can release an
artifact that is rejected for **curation or provenance** if its scan findings now
pass — a live cross-axis fail-open. The generalised pass would inherit it and
*widen* it to the `Released`/`Quarantined` population.

The release decision must be the **conjunction** — `scan ∧ curation ∧
provenance`. So the spec's "reuses the existing `re_evaluate` machinery, no new
release surface" **understates the work**: the loosen direction needs genuine new
composition logic, and landing it fixes a pre-existing bug.

**Required:** change the matrix's provenance cell from "Composes" to "must be
*made* to compose (new work + existing-bug fix)"; add an explicit conjunction
invariant; add a backlog item for the cross-axis composition (and the existing
post-exclusion-pass fix).

### ② HIGH — the synchronous, 10k-capped pass doesn't scale, and truncation leaves the tightening gap partly open

`run_post_exclusion_re_evaluation_pass` runs **synchronously inside**
`add_exclusion` (`policy_use_case.rs:1011`) with a single-query **10,000-row cap**
that truncates-and-warns (`:1062-1076`), relying on "the next exclusion-add or
manual sweep" for the remainder.

Generalising to the full active population:
- A synchronous pass blocks the `update_policy` request on a large repository.
- Worse — for a **tighten**, a truncated pass leaves the >10k remainder at the
  *old* verdict (still downloadable), with no guaranteed next trigger. That
  re-opens the very fail-open this ADR exists to close, silently, above 10k
  artifacts.

**Required:** make the pass **async (a worker task) and fully paginated** over the
whole population, with the §5 metric reporting completeness — not a capped single
query in the request path.

### ③ MEDIUM — the audit event must widen (confirmed)

`ArtifactReEvaluated` (`crates/hort-domain/src/events/artifact_events.rs`,
emitted at `policy_use_case.rs:1338`) carries a **non-optional
`trigger_exclusion_id`**; it cannot represent an `update_policy` /
`remove_exclusion` / `reactivate` trigger. The spec acknowledges this.

**Required:** specify the widened shape (the trigger as a sum over the driving
policy event) as an append-only addition (ADR 0002), no past mutation.

## Minor

- **Elevate the dry-run** from "desirable follow-on" toward MVP-adjacent:
  re-rejecting a large `Released` population blocks live consumers mid-flight. The
  §5 metric is the floor; a preview ("how many would this tighten pull?") is cheap
  insurance given the blast radius. Acceptable to defer *only if* finding ② lands
  (async + observable).
- **Spec-review checklist:** inbound port (CLI/HTTP triggers), error shapes,
  quarantine invariants — addressed; no layer violations; §0 sweep recorded;
  observability + metric-catalog noted. Passes the checklist modulo the findings.

## Bottom line

Approve the approach. Resolve ① (the conjunction + existing-bug fix), ② (async +
paginated tightening pass), ③ (the widened audit event) in the design doc, and
correct the two spec lines (the provenance "Composes" cell; the "no new release
surface" framing) before implementation.
