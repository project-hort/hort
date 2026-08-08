# 090 — #135 item 2: declared lifecycle tables + dependency-edge registry + guards

**Issue:** #135. Dispatched AFTER item 089 (its late-joiner pair becomes the
registry's first entry). Representation change ONLY — behavior byte-identical.

## Work

1. Lift the implicit transition guards into per-lifecycle declared `const`
   tables in `hort-domain` (state × event → next + required triggers),
   consumed by the existing guard methods. Any divergence discovered between
   a table and the guard it replaces is a STOP-and-report, never a silent fix.
2. Dependency-edge registry: every standing cross-artifact lifecycle
   dependency names BOTH trigger ends; first entry = subject⇄constituent
   (subject-verify→cascade / constituent-ingest→self-clear, item 089).
3. Structural guards (DB-free `tests/` targets, `retention_registration_guard`
   pattern): unclassified state×event cells fail; one-ended registry entries
   fail; messages name both code sites.
4. Auto-generate the lifecycle DOT from the tables (test-emitted or
   build-generated artifact under `docs/architecture/`), replacing hand-drawn
   lifecycle diagrams.
5. Architect-doc anti-pattern entry: the both-ends-trigger rule.

## Scope / acceptance

- `hort-domain` 100% tier; guards run via plain `cargo test --workspace`.
- Full pre-push suite (Rust diff).

**Model hint:** sonnet.
