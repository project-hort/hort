# 092 — #134: split VALID_TASK_KINDS — admin-invoke allowlist vs event-payload vocabulary

**Issue:** #134 (refinement on the issue; the emitter inventory is the
design-verification step and comes FIRST). Code-verified starting state:
`VALID_TASK_KINDS` (`hort-domain/src/events/authorization_events.rs:309`)
serves both the admin task-invoke allowlist (`hort-http-admin-tasks/params.rs`)
and `TaskInvoked::validate` / `TaskFailed::validate`; the SQL CHECK
(migration 009:66) keeps `'scan'` while the constant deliberately dropped it.
No live collision today (poison rows resolve via `mark_failed`, no event) —
this closes the future-divergence seam. Bonus fix included: the stale
claim-path comment at `hort-adapters-postgres/src/jobs_repository.rs:~1065`
still claims `"scan"` is in `VALID_TASK_KINDS` (false since the churn fix).

## Work

1. **Emitter inventory FIRST:** enumerate every emitter of `TaskInvoked` and
   `TaskFailed` (file:line in the report). Assign each event's `validate` to
   the list matching its emitters' domain:
   - `TaskInvoked` emitted only by the admin invoke path → validates against
     `ADMIN_INVOKABLE_TASK_KINDS` (current list, semantics unchanged).
   - `TaskFailed`: if ANY emitter can legitimately carry a non-admin-invokable
     jobs kind (e.g. `'scan'`) → it validates against `EVENT_TASK_KINDS`
     (= the SQL CHECK set). If NO emitter can, BOTH stay on the admin list
     and `EVENT_TASK_KINDS` exists solely for the lock-step guard —
     validation is NOT widened without a producing emitter. Either outcome
     is fine; the report states the inventory and the assignment.
2. **Split the constant** into `ADMIN_INVOKABLE_TASK_KINDS` and
   `EVENT_TASK_KINDS`, each with a doc comment naming its single consumer;
   move the `"scan"`-absence invariant comment to the admin list; the admin
   allowlist consumer moves accordingly. Zero behavior change unless step 1
   mandates one — then it is called out explicitly in report + commit body.
3. **Lock-step structural guard** (DB-free `tests/` target, token-scan
   pattern like `no_sensitive_drops`): parse migration 009's `kind IN (…)`
   list and assert it equals `EVENT_TASK_KINDS` exactly; failure message
   names both sites.
4. **Fix the stale `jobs_repository.rs` comment** (current reachability:
   bare-`scan` rows are legacy/poison only; the admin path can no longer
   create them).

## Scope / acceptance

- `hort-domain` 100% tier on touched branches; guard DB-free.
- Full pre-push suite (Rust diff; one-shot capture idiom).
- CI-tier verifiable ⇒ normal immediate-MR flow applies after my review (no
  human E2E gate needed for this one).

**Model hint:** sonnet.
