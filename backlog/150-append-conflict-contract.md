# 150 — ADR 0060 + shared append-conflict primitive (read-decide-append)

**Issue:** #221 · **Branch:** `agent/221-append-conflict-contract` · Item 1 of 2.

## Problem

ADR 0004 makes concurrent writers to one event stream "conflict loudly" via
the expected-version append — but no standing decision defines what a writer
does with the loud conflict. Four call sites answer it four ways today:
bounded hand-rolled retry (token-exchange), explicit result classification
(curation), a hard `Internal` 500 mapping (OCI group attach / ref set), and
swallow-to-warn (the generic ingest group hook). The class keeps recurring
because each site is patched individually.

## Deliverables

1. **ADR 0060 — append-conflict reaction contract** (relates 0004). On
   `DomainError::Conflict` from an expected-version append a writer MUST:
   (a) re-read the stream/aggregate; (b) re-evaluate its intent against the
   refreshed state — if already satisfied (member present, ref already at
   target, state already reached), succeed idempotently; (c) otherwise
   rebuild the event batch against the refreshed version and re-append,
   bounded (small attempt cap, jitter); (d) at exhaustion surface a
   *retryable-busy* outcome — 503 + `Retry-After` at HTTP edges, a typed
   error internally. **A `Domain(Conflict)` surfacing as HTTP 500 is a
   defect by definition.** Sanctioned exceptions (deliberate non-retry
   semantics) are named in the ADR: curation's user-facing conflict results,
   and the group primary-role race (the loser must learn the privileged
   assignment did not stick). Add the ADR to the 0000 index.
2. **Shared primitive in `hort-app`** implementing the contract — a
   read-decide-append combinator, e.g.

   ```rust
   pub async fn append_with_conflict_retry<T, F>(
       attempts: u8,
       mut cycle: F,
   ) -> AppResult<T>
   where
       F: AsyncFnMut() -> AppResult<ConflictCycleOutcome<T>>,
   ```

   (exact signature is the implementer's; the shape must force the caller
   to express "re-read + intent re-check + rebuild" as one closure per
   attempt and must distinguish `Satisfied(T)` / `Retry` / terminal errors).
   Lives in `crates/hort-app/src/` next to the use cases; no I/O of its
   own; 100% unit coverage (attempt exhaustion, immediate success,
   satisfied-on-recheck, non-Conflict error passthrough, bound respected).
3. **Retryable-busy error shape**: reuse the existing contention vocabulary
   from the !443 work (`manifest_write_contention` maps to 503 +
   `Retry-After` at the OCI edge) — the primitive's exhaustion error must be
   mappable to that same response without new HTTP surface.

## NOT in this item

Adoption at the broken sites (item 151). No behavior change to any use case
yet — this item is contract + primitive + tests only, mergeable without any
caller.

## Acceptance

- ADR 0060 in `docs/adr/`, indexed in 0000, naming the four-answers evidence
  and the sanctioned exceptions.
- Primitive with 100% coverage in `hort-app` (coverage tier).
- `cargo test --workspace` green; full pre-push gate.
- Comment discipline: invariants only, no issue refs in code/ADR body
  provenance beyond the ADR's own decision-record conventions.

## Governing decisions

ADR 0004 (loud optimistic concurrency — unchanged, this defines the reaction) ·
#62 fix + !443 (precedents the contract generalizes) · hort-app 100%
coverage tier.
