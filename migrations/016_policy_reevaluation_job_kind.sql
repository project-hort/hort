-- 016_policy_reevaluation_job_kind.sql
--
-- Adds the `'policy-reevaluation'` worker task kind to the `jobs.kind`
-- CHECK constraint (ADR 0041 Item 3). The kind runs
-- `PolicyUseCase::run_policy_re_evaluation_pass` off the request path:
-- a gate-affecting scan-policy mutation (`update_policy` gate fields,
-- `add_exclusion`, `remove_exclusion`, `reactivate_policy`) enqueues one
-- row of this kind, the worker claims it, and the pass re-derives every
-- in-scope artifact's verdict from its stored findings under the bumped
-- policy — transitioning in both directions (loosen / tighten). The kind
-- carries no release authority of its own (the pass re-runs the same
-- fail-closed gate over stored evidence; ADR 0007 preserved); it is the
-- async vehicle for the population pass, not a destructive task.
--
-- Append-only ALTER per ADR 0022 (amended 2026-06-27): from 0.9.5 on a
-- schema change is a NEW numbered ALTER migration rather than an in-place
-- edit of 009, because pre-release deployments (registry.hort.rs + the
-- platform mirror) now run the applied schema and an in-place edit of
-- 009's inline CHECK would break their `_sqlx_migrations` checksums
-- (`VersionMismatch`). The inline CHECK in 009 is anonymous, so Postgres
-- auto-named it `jobs_kind_check`; drop that and re-add a named
-- constraint carrying the full kind set plus the new literal.
--
-- Keep the literal in lock-step with the `VALID_TASK_KINDS` allow-list in
-- `crates/hort-domain/src/events/authorization_events.rs` and the
-- `TaskHandler::kind()` return of `PolicyReEvaluationHandler`. The
-- DB-gated enqueue tests
-- (`crates/hort-adapters-postgres/tests/migration_016_policy_reevaluation_kind.rs`
-- and `crates/hort-server/tests/task_use_case_enqueue_real_db.rs`) pin the
-- lock-step.
--
-- GRANTs / role wiring: none — the table already exists with the
-- post-004 default-privileges convention (ADR 0009); altering a CHECK
-- constraint touches no privileges.
--
-- Reversal (sqlx::migrate! is UP-only; no paired *.down.sql):
--   ALTER TABLE public.jobs DROP CONSTRAINT jobs_kind_check;
--   ALTER TABLE public.jobs ADD CONSTRAINT jobs_kind_check
--       CHECK (kind IN ( ... original 009 set, minus 'policy-reevaluation' ));

ALTER TABLE public.jobs
    DROP CONSTRAINT jobs_kind_check;

ALTER TABLE public.jobs
    ADD CONSTRAINT jobs_kind_check CHECK (kind IN (
        'scan',
        'cron-rescan-tick',
        'advisory-watch-tick',
        'retention-evaluate',
        'retention-purge',
        'eventstore-archive',
        'staging-sweep',
        'noop',
        'service-account-rotation',
        'eventstore-checkpoint',
        'replay-seen-prune',
        'quarantine-release-sweep',
        'seed-import',
        'prefetch-tick',
        'prefetch',
        'prefetch-dependencies',
        'prefetch-row-retention-sweep',
        'wheel-metadata-backfill',
        'provenance-verify',
        'scanner-registry-prune',
        'verify-event-chain',
        -- ADR 0041 Item 3: async scan-policy re-evaluation pass.
        'policy-reevaluation'
    ));
