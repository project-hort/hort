# Architectural decisions: a reading guide

hort maintains Architecture Decision Records (ADRs) in `docs/adr/`. They explain *why* the project chose specific boundaries and tradeoffs. They are valuable contributor context, but **an ADR is not an API contract or proof that a proposed feature is implemented**.

## Suggested reading path

| Question | Starting point |
| --- | --- |
| Why is the domain independent of infrastructure? | [ADR 0001 — Hexagonal zero-I/O domain](https://github.com/project-hort/hort/blob/main/docs/adr/0001-hexagonal-zero-io-domain.md) |
| Why model artifact transitions as events? | [ADR 0002 — Event-sourced lifecycle](https://github.com/project-hort/hort/blob/main/docs/adr/0002-event-sourced-artifact-lifecycle.md) |
| How is content integrity enforced? | [ADR 0003 — Streaming CAS](https://github.com/project-hort/hort/blob/main/docs/adr/0003-streaming-enforced-cas.md) |
| Why have dedicated HTTP crates for each format? | [ADR 0008 — Per-format HTTP boundaries](https://github.com/project-hort/hort/blob/main/docs/adr/0008-per-format-adapter-free-http-crates.md) |
| Why must event delivery account for ordering and late commits? | [ADR 0061 — Store-driven notification delivery](https://github.com/project-hort/hort/blob/main/docs/adr/0061-store-driven-notification-delivery.md) |

## How to use an ADR during development

1. Identify the architectural constraint affected by your change.
2. Read the corresponding ADR **and its context**, including alternatives and consequences.
3. Compare the decision to current crates and tests. An accepted design can evolve, and some ADRs describe future work.
4. Explain any intentional departure in the pull request. Propose a new decision record for a substantial architectural reversal.

For historical context, see the [ADR source index](https://github.com/project-hort/hort/tree/main/docs/adr/). The developer portal curates a starting set rather than exposing every historical record in its navigation.
