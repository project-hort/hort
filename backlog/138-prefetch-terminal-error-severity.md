# 138 — Terminal prefetch failure logs at ERROR, decided once at completion

Issue: #158, Item A (confirmed spec in the issue description). Milestone
0.12.0 — dispatch after the 0.11.0 promotion.

**Read first:** the prefetch task handlers in `crates/hort-app/src/task_handlers/`
(`prefetch_dependencies.rs` and the leaf prefetch handler), their
job-completion log lines, and the architect guide's observability rules
(severity semantics by layer; what NOT to log).

## Rule (from the spec, binding)

Severity is decided **once, at the job-completion line**, from the whole
outcome:

- terminal outcome with `urls_succeeded == 0` AND at least one non-404 hard
  failure → the job-completion line is **ERROR**;
- everything else (partial success; all-404 — a BOM legitimately has no JAR;
  non-terminal attempts) stays as today — per-URL lines remain WARN.

No new config surface. The decision input is data the completion path already
holds (the per-URL outcome set); if it does not hold the non-404-hard-failure
bit today, thread it from where the per-URL WARNs are emitted — do not
re-derive by parsing log state.

## Governing decisions

Observability rules in the architect guide (severity by layer); no ADR
governs log severity levels — record "none beyond the guide" in the report if
that matches your reading.

## Acceptance

- Handler-layer test with mocked ports: forced storage failure on every URL →
  completion line at ERROR (assert via the tracing test subscriber the crate
  already uses for log assertions, if present — else the metrics/outcome
  channel that feeds the line).
- BOM case (1 of 2 URLs, the missing one 404) → completion line NOT ERROR.
- Partial success with one hard failure → NOT ERROR (spec: only the
  fully-failed terminal case escalates).
- `hort-app` 100 % on touched code; full local gate.
