# 0024 — The architect skill is the enforcement index for these ADRs

- **Status:** Accepted
- **Enforced by:** this ADR is an *index*, not a peer decision — the architect skill (`.claude/commands/<architect>.md`) is the live, actively-applied enforcement surface (anti-pattern checklist, review checklists, structural rules) for the decisions recorded in ADRs 0001–0023. It points at them; it does not add a new architectural choice.
- **Supersedes:** —

## Context

ADRs 0001–0023 record *why* each load-bearing decision exists. But a decision record is inert unless something checks it on every change. The architect skill is what an implementer reads before writing code and what a reviewer applies before approving it — it is where each decision becomes an enforced rule (compile-error, dep-graph, test, or review check). The risk this ADR addresses is the skill and the ADR set drifting apart: a rule enforced with no recorded rationale, or a recorded decision no longer enforced.

## Decision

The architect skill is the **enforcement index** over ADRs 0001–0023. Each structural anti-pattern in the skill maps to the ADR that records the decision it enforces; each ADR names the skill rule that enforces it (the "Enforced by" line). This ADR exists to make that relationship explicit and to forbid reading the skill as a free-standing source of architectural decisions — new architectural decisions are recorded as ADRs (via the doc-distillation workflow), and the skill enforces them.

A corollary discipline (the doc-distillation rule): an ADR whose enforcing mechanism no longer compiles/lints/tests is a **defect to file**, not a decision to memorialize. Conversely, a structural rule enforced by the skill with no ADR behind it is a missing ADR.

## Consequences

- The skill and the ADR set are kept in lock-step: enforcement ⇄ rationale is a two-way reference.
- A new architectural decision goes through an ADR, not by quietly adding a rule to the skill with no record of why.
- This ADR carries no new decision of its own; it is intentionally an index, so it does not read as self-referential authority.

## Alternatives considered

- **Treat the architect skill as the canonical decision source (no ADRs).** Rejected: the skill is procedural and changes with tooling; the *why* needs a stable, individually-citable record, which is what ADRs provide.
- **Omit this ADR (leave the skill↔ADR relationship implicit).** Rejected: the drift risk (enforced-without-rationale / recorded-without-enforcement) is real; making the index explicit is what lets the doc-distillation code-first check detect drift.

## References

- `.claude/commands/hort-architect.md` — the architect skill (enforcement index), which includes the doc-distillation workflow (how ADRs are written/maintained).
- ADRs [0001](0001-hexagonal-zero-io-domain.md)–[0023](0023-implementation-discipline-objectively-better.md).
- [0000](0000-historical-decisions-index.md) — the decision index and open-items register.
