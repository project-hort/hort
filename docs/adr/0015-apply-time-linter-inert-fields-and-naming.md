# 0015 — Apply-time rejection of inert policy fields and misleading config names

- **Status:** Accepted
- **Enforced by:** the `ApplyConfigUseCase` gitops linter rejects, at apply time, a policy field that is accepted but not yet enforced at runtime (e.g. `max_age_days` while its consumer is unbuilt). Misleading-config-name hazards are caught at design-doc review (pre-v1.0 fix = in-place rename).
- **Supersedes:** —

## Context

Operators set risk-significant values (`max_age_days: 90`, severity thresholds) and make threat-model decisions on the assumption the field is load-bearing. If gitops apply *accepts* a field that the consuming use case silently ignores, the operator believes a control is active that does nothing — a silent footgun. Separately, an enum variant whose name implies the opposite of its behaviour leads operators to choose the more-permissive option while reaching for "more conservative".

## Decision

A new field on `PrefetchPolicy` / `ScanPolicy` / `RetentionPolicy` / `RepositoryUpstreamMapping` / etc. must be **either** enforced by the consuming use case **or** rejected at gitops apply. Accepting it while the consumer ignores it is a hard block. The structural close is an **apply-time linter rejection** whose message tells the operator the field is not yet enforced (`RetentionPolicy.max_age_days` is the exemplar — the linter rejects any non-`None` value until the consumer ships). The alternative model is removing the operator surface entirely until the feature works.

**Config naming:** a variant whose name suggests the opposite of its behaviour is caught at design-doc-review time. Pre-v1.0 the fix is an in-place rename (the `FilterQuarantined → IncludePending` rename is the exemplar — the old name retained *more* versions than `ReleasedOnly`, the inverse of what "filter" implies); post-v1.0 it becomes a deprecation cycle, which is why the check lives at review, not implementation.

## Consequences

- An operator cannot set a risk-significant field that does nothing — apply fails loudly and says the field is not yet enforced.
- "Aspirational acceptance" (ship the field now, enforce it later) is the failure mode this prevents.
- Risk decisions are never made on a misread variant name; naming hazards are a design-review gate.

## Alternatives considered

- **Accept the field now, enforce it later.** Rejected: this is exactly the inert-field footgun — the operator trusts a dormant control.
- **Runtime warning log instead of apply-time rejection.** Rejected: logs are missed; fail-closed at apply is what guarantees the operator sees it.

## References

- `crates/hort-app/src/use_cases/` — `ApplyConfigUseCase` linter.
- The architect skill → anti-patterns *policy field accepted at apply, inert at runtime* and *operator-config naming hazard*.
