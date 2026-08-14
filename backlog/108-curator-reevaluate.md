# 108 — Curator-invokable per-artifact re-evaluation (`hort-cli curation reevaluate`)

Issue: #152. One reviewable unit: endpoint + use case + CLI subcommand + tests.

## What

A curator can recompute a `Rejected` artifact's verdict from its stored
findings under the currently-active policy, without a policy mutation and
without forcing an outcome. The recompute delegates to the same domain
derivation the policy-mutation pass already uses; the result is whatever
`decide_rejected_transition` derives: `StillRejected`, `ResetToQuarantined`,
or `ResetToReleased`.

Motivating class: verdict inputs changed while the policy did not — a
scanner-side fix re-banding severities, a manual rescan re-recording findings.
Today nothing enqueues the recompute in that case, and the fail-closed rule in
the quarantine use case correctly refuses to un-reject on a clean scan signal
alone.

## Shape (mirror the waive family)

1. **Endpoint** — `POST /api/v1/admin/curation/quarantine/:artifact_id/reevaluate`.
   Mirror `crates/hort-http-core/src/handlers/admin/curation/waive.rs` for the
   path family, the `CurateOrAdminPrincipal` gate, and the status-code mapping
   conventions. Register in the curation router alongside waive.
2. **Source-state guard** — `Rejected` only (waive's single-source-state
   discipline; waive itself is `Quarantined` only). `ScanIndeterminate`,
   `Quarantined`, `Released` → the family's guard error. Window releases
   belong to the sweep, not to curators.
3. **Use case** — new `hort-app` curation-family use case (port-only deps, per
   the task-handler/use-case shape). Load: the artifact's last `ScanCompleted`
   summary; per-finding rows when resolvable (per-finding mode preferred,
   aggregate fallback preserved); the resolved active policy + exclusion set;
   the **computed quarantine deadline** — never the bare anchor (the domain doc
   warns the anchor type-checks and releases early). Delegate to
   `hort-domain/src/policy/re_evaluation.rs::decide_rejected_transition` —
   share the derivation path with
   `crates/hort-app/src/task_handlers/policy_reevaluation.rs`; extract a shared
   helper if reuse would otherwise duplicate the load-and-derive block, do NOT
   copy it.
4. **Events** — emit the same curator-attributed transition events the
   existing reevaluation vocabulary carries. Reuse existing event variants;
   a new variant requires demonstrated necessity, not symmetry.
5. **CLI** — `hort-cli curation reevaluate <artifact-id>` mirroring `waive`'s
   argument and output conventions (envelope printed, exit codes per outcome).
6. **Idempotence** — re-invoking on a `StillRejected` artifact returns the
   outcome envelope again; no repeated events, no state churn.

## Out of scope

- The policy-wide `policy-reevaluation` admin-task variant (dropped by the
  issue's direction — the policy-mutation pass keeps auto-running as today).
- The gitops `maintainer-dev` global `curate` grant (operational precondition,
  separate one-file MR when this ships).
- Any change to waive semantics or to the fail-closed no-un-reject rule.

## Tests (coverage tiers apply)

- `hort-app` use case at the **100% tier**: all three transition outcomes;
  guard rejection per non-`Rejected` source state; missing/unresolvable
  per-finding rows → aggregate fallback; missing `ScanCompleted` summary →
  error path; idempotent re-invoke (no duplicate events).
- Handler tests per the curation-family conventions
  (`hort-http-core` mock-ctx harness): authz gate (curate passes, plain write
  does not), status-code mapping per outcome and per guard error.
- CLI test per the existing `curation` test shape
  (`crates/hort-cli/tests/curation_*.rs`).
- Any new DB-backed adapter test carries `#[serial(hort_pg_db)]`.

## Acceptance

- A `Rejected` artifact whose findings re-band below threshold under the
  active policy flips to Released (window elapsed) or Quarantined (window
  open) via one authenticated `hort-cli curation reevaluate` call.
- A `Rejected` artifact whose findings still exceed threshold reports
  `StillRejected` and remains untouched.
- No new dependency; no migration expected (uses existing rows/events).
