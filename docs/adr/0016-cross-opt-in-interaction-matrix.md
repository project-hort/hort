# 0016 — Cross-opt-in interaction matrix for release-gate-influencing knobs

- **Status:** Accepted
- **Enforced by:** design-doc review — any new operator opt-in that lets untrusted input influence the release-gate computation must register its interaction with every existing such opt-in in the matrix before implementation. Dangerous combinations are rejected fail-closed at gitops apply time (e.g. `trust_upstream_publish_time_requires_scan_backends`).
- **Supersedes:** —

## Context

Individual opt-ins can each be safe and bounded, yet collapse a security invariant **when combined**. The canonical case: `trust_upstream_publish_time = true` (anchors the quarantine deadline to an upstream-asserted `published_at`) and `scan_backends: []` (waives scanner-clean as a release authority) are each individually documented and bounded — but set together on overlapping scopes they collapse the Gate-2 observation window to ≤ sweep-tick latency. No single opt-in's review would have caught it.

## Decision

Every new operator opt-in that lets untrusted input influence the release predicate / index advertisement / quarantine deadline must, **in its design doc before implementation**, enumerate its interaction with each existing opt-in in the **cross-opt-in interaction matrix**. "Interaction" = when both are set on overlapping scopes, what is the combined effect on the gate? A combination that collapses a Gate-2 observation window or releases authority by silent fallback is an **apply-time-reject** case.

The structural close is **fail-closed apply-time rejection** of the dangerous combination — never a runtime "fall back to a degraded authority" path, which would re-introduce the collapse with an escape hatch. The matrix grows a column whenever a new such opt-in lands; an opt-in landing without its matrix row is a review hard-block.

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
