# 357 — `repository.storage.path` is deprecated at apply and says so

**Issue:** #331, entry **E101** · **Branch:** `agent/331-e101-storage-path-deprecated` · single item.

## Problem

`RepositorySpec.storage.path` (`crates/hort-config/src/repository.rs`,
`StorageSpec`) is parsed, persisted to `repository.storage_path`, and selected
back in ~10 adapter queries — and **never consumed**. Placement is done solely
by the one global CAS adapter wired at serve start from
`HORT_STORAGE_BACKEND`. There is no validation and no apply-time check.

Its sibling `storage.backend` is equally placement-inert but **is** held
honest: enum-validated at parse and cross-checked at apply against the
effective global backend, with a mismatch rejected fail-closed. `path` has no
such control because it has no global counterpart to cross-check against — and
the `StorageSpec` doc comment names both fields as inert in one sentence while
building a control for only one of them.

Aggravating: `path` is `String`, not `Option`, and `StorageSpec` carries
`deny_unknown_fields`. An operator who wants to state `backend` is therefore
**forced to invent a path that does nothing**.

This is CLAUDE.md's hard-block class, *"Policy field accepted at apply, inert
at runtime"*. The canonical exemplar is `PrefetchPolicy.max_age_days`, which
the linter **rejects** (`RULE_PREFETCH_MAX_AGE_DAYS_NOT_IMPLEMENTED`, row 6).

## The correction — deprecate and warn, do not reject

**The maintainer's decision (2026-11-01): a non-aborting deprecation warning,
not a rejection.** The distinction from `max_age_days` is sound and should be
recorded in the code: `max_age_days` was never in use, so rejecting broke
nobody; `storage.path` is set in 43 config files in this repo alone plus
operator trees, so a reject would fail every existing apply. Deprecate-then-
remove is the path for a field already in use.

1. **`StorageSpec.path` becomes `Option<String>`.** Existing YAML keeps
   parsing unchanged; `storage: { backend: filesystem }` becomes valid, which
   is what makes the remedy in the warning reachable.
2. **A new apply-linter row: a warning, one per repository whose `path` is
   set.** Mirror row 6's shape exactly — a `RULE_*` const, a `LinterRule`
   variant, a `hort_config::desired::validate_*` function — but push to
   `report.warnings` via `LintFinding::warning(...)` rather than
   `report.errors`. Carry the repository key in a `WarnContext` so the apply
   path's `tracing::warn!` has it as a structured field, not only in prose.
   The message states: the value does not route placement, placement comes
   from the deployment-level `HORT_STORAGE_BACKEND`, and the remedy is to drop
   the `path:` line.
3. **`docs/metrics-catalog.md` in the same change**, as row 6's own doc
   comment requires of its rule label.
4. **Remove `path:` from this repo's own config.** 35 of 39 files under
   `deploy/compose/example-config/repositories/` and 8 under
   `scripts/alpha-fixtures/`. Keep the `storage:` block and its `backend:`.
   The field routes nothing, so this changes no behaviour — and it takes our
   own warning count to zero so the signal only ever fires on an operator
   tree. `alpha_fixtures` is a guard test over that fixture tree; it must stay
   green.
5. **Correct the `StorageSpec` doc comment.** It currently reads as though
   both fields get equivalent honesty treatment. It must now say plainly:
   `backend` is cross-checked and rejected on mismatch; `path` is deprecated,
   warned at apply, and routes nothing.

### Not in scope

- **No DDL.** `repository.storage_path` stays. Dropping it is expand/contract
  (ADR 0030) and belongs one release after the last code reference goes.
- **No removal of the field** from the schema, and no reject. Both are the
  follow-on once operators have had a release with the warning.
- Do not touch `storage.backend` or its mismatch reject.

## Acceptance

- `storage: { backend: filesystem }` with no `path` parses and applies clean,
  with no warning.
- A repository declaring `path` applies **successfully** and emits exactly one
  warning naming that repository, with the repository key available as a
  structured field. Asserted on the rendered message *and* the field — a
  tracing field name must not stand where its value belongs (see
  `composition.rs`'s prose tests for the idiom and why).
- The apply is **not** aborted by the warning.
- `hort_apply_config_linter_total` carries the new `rule` label, and
  `docs/metrics-catalog.md` describes it.
- This repo's own trees carry no `path:`, and `alpha_fixtures` is green.
- `CHANGELOG.md`: one `### Deprecated` line — an operator will see a new
  warning at apply and needs to know what to do about it. This is observable,
  unlike a log-wording fix.
