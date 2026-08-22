# 0016 — Cross-opt-in interaction matrix for release-gate-influencing knobs

- **Status:** Accepted
- **Enforced by:** design-doc review — any new operator opt-in that lets untrusted input influence the release-gate computation must register its interaction with every existing such opt-in in the matrix before implementation. Dangerous combinations are rejected fail-closed at gitops apply time (e.g. `trust_upstream_publish_time_requires_scan_backends`).
- **Supersedes:** —

## Context

Individual opt-ins can each be safe and bounded, yet collapse a security invariant **when combined**. The canonical case: `trust_upstream_publish_time = true` (anchors the quarantine deadline to an upstream-asserted `published_at`) and `scan_backends: []` (waives scanner-clean as a release authority) are each individually documented and bounded — but set together on overlapping scopes they collapse the Gate-2 observation window to ≤ sweep-tick latency. No single opt-in's review would have caught it.

## Decision

Every new operator opt-in that lets untrusted input influence the release predicate / index advertisement / quarantine deadline must, **in its design doc before implementation**, enumerate its interaction with each existing opt-in in the **cross-opt-in interaction matrix**. "Interaction" = when both are set on overlapping scopes, what is the combined effect on the gate? A combination that collapses a Gate-2 observation window or releases authority by silent fallback is an **apply-time-reject** case.

The structural close is **fail-closed apply-time rejection** of the dangerous combination — never a runtime "fall back to a degraded authority" path, which would re-introduce the collapse with an escape hatch. The matrix grows a column whenever a new such opt-in lands; an opt-in landing without its matrix row is a review hard-block.

The canonical matrix table is maintained in the architect skill (`.claude/commands/hort-architect.md` → "Cross-opt-in interaction matrix"); the rows below record each registered opt-in and its verdict as of the ADR's latest amendment.

### Registered rows

- **`ScanPolicy.scan_backends: []`** × **`trust_upstream_publish_time = true`** — **apply-rejected** (`trust_upstream_publish_time_requires_scan_backends`): together the deadline is anchored to attacker-asserted `published_at` *and* release no longer requires a successful scan, collapsing the Gate-2 window to ≤ sweep-tick latency. The canonical exemplar.
- **`RepositoryUpstreamMapping.trust_upstream_publish_time = true`** × **content-level `first_seen_at` anchoring** ([0054](0054-content-level-age-evidence-anchors-quarantine.md)) — **benign by construction, documented**: the two sources compose as a minimum, and the trusted-upstream value may only move the anchor earlier. The scoping rule is what keeps it benign — a mapping's opt-in never transits repositories, so an untrusted mirror's claim cannot shorten a repository proxying the genuine upstream. `first_seen_at` itself registers no new attacker-asserted input (an observation cannot be backdated), so it needs no apply-time rejection rule; the existing `trust_upstream_publish_time_requires_scan_backends` rejection continues to apply unchanged to the second source.
- **`RepositoryUpstreamMapping.trust_upstream_publish_time = true`** × **`Repository.index_mode: IncludePending`** — **benign, documented**: `NonServableStatusFilter` runs first and the mode's additive set (`Unknown`) was never gate-eligible.
- **`ScanPolicy.provenance_mode: Required`** (hold-until-signed — ADR 0027 amendment, issue #13) — **benign, documented (NOT apply-rejected).** `Required` provenance only *tightens* the release gate: it is an AND-precondition on the timer arm (ADR 0027/0007) and adds no release authority. The provenance *hold window* is bounded by the same quarantine deadline the other knobs move, so:
  - × **`trust_upstream_publish_time = true`** — **benign**: a shrunk deadline shortens the *legitimate signer's* time-to-sign (an availability effect on first-party CI, surfaced as `held_pending_signature`), and can **never** release an unsigned artifact. `Pending` never timer-releases; an expiry with no signature rejects `Unsigned` (fail-closed). Safety is intact; only the operator's signing budget shrinks.
  - × **`scan_backends: []`** — **benign**: a scan waiver (`ScanWaived`) does not grant provenance clearance. Under `Required`, `Cleared` still requires a `ProvenanceVerified` event on the artifact stream; a waived scan cannot substitute for a signature.

  Because the interaction only ever *tightens* (never releases-by-fallback), there is no dangerous combination to fail-closed-reject — the correct verdict is documented-benign, not apply-time rejection.

## Consequences

- A new release-gate-influencing knob cannot be added without analysing it against every existing one — the interaction is enumerated, not discovered in production.
- Dangerous combinations fail at apply, loudly, rather than silently degrading the gate at runtime.
- The matrix is a living artifact; it is the audit record of why each combination is safe or rejected.

## Alternatives considered

- **Review each opt-in in isolation.** Rejected: the canonical case above proves a combination can be unsafe while each part is safe; isolation review structurally cannot catch it.
- **Runtime fallback to a weaker authority when a dangerous combo is set.** Rejected: that is the collapse with an escape hatch; fail-closed apply-time rejection is the only safe close.

## References

- The architect skill → "Cross-opt-in interaction matrix" table and anti-pattern *cross-opt-in collapse of a Gate-2-style invariant*.
- `crates/hort-app/src/use_cases/` — `ApplyConfigUseCase` linter (`trust_upstream_publish_time_requires_scan_backends`).
