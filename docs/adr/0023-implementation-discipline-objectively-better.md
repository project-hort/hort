# 0023 — The design wins by default; deviations require an "objectively better" case

- **Status:** Accepted
- **Enforced by:** review discipline — an implementation that does not match the design (a plan document, a backlog item, an explicit "mirror X" instruction, or established precedent) must declare the deviation in its commit/PR body and justify why the alternative is *concretely* better. "Defensible"/"plausible"/"it works" are not sufficient; absent the objectively-better case, the design is followed.
- **Supersedes:** —

## Context

A capable implementer can construct a plausible argument for almost any alternative. If "I can argue for it" were the bar, the design would carry no authority and every plan would be silently re-litigated at implementation time — producing inconsistency across items that were meant to cohere. The design is the agreed cross-item contract; it needs a high, explicit bar to overturn.

## Decision

**The design wins by default.** An implementation may deviate only when the alternative is **objectively better** — a concrete advantage the design did not have, a measurable cost reduction on a cost the design acknowledged, or a correctness fix where the design was wrong (flag it, get the design amended, then implement). What does **not** qualify: "defensible", "plausible", "I can construct an argument", or "it works" (most alternatives work; the bar is *better*).

If you deviate, **declare it** in the commit body and the PR description: what the design said, what you did, why it is objectively better. If you cannot make that case, follow the design.

**Reviewer's duty:** before labelling something a deviation, verify it actually is one — a choice that mirrors a codebase convention the design named (e.g. a task handler "mirroring `CronRescanTickHandler`"'s port-only shape) is the design's own answer, not a deviation; and verify the cited better alternative actually exists in the layer being criticised (e.g. `build_mock_ctx` is for `AppContext` HTTP tests, not `hort-app` task-handler tests). Hedging language ("probably fine", "I can see arguments") is the same warning sign on the reviewer side.

## Consequences

- Plans retain authority; cross-item coherence is preserved.
- Genuine improvements still land — but with an explicit, recorded justification, not silently.
- Both implementer and reviewer are held to "verdict, not hedge"; an unprovable deviation label is withdrawn, not shipped.

## Alternatives considered

- **"Defensible" as the deviation bar.** Rejected: everything is defensible; the design would carry no weight and every item would drift.
- **No deviations ever (design is absolute).** Rejected: the design is sometimes wrong or pays an avoidable cost; the objectively-better escape hatch (with amendment) captures real improvements without opening the floodgates.

## References

- CLAUDE.md → "Implementation Discipline — when to deviate from the design" (worked examples).
- The architect skill → Implementer's / Reviewer's discipline.
