-- Migration 009 — vulnerability scanning + admin-task framework — folded
-- union of:
--
--   * scan job lifecycle table
--   * per-finding projection
--   * per-repo aggregate projection
--   * `artifacts.last_scan_at` denorm column
--   * scanner worker liveness registry
--   * generalised `jobs` table (kind / params / actor / priority /
--     trigger_source / result_summary)
--
-- Hyphen-separated `kind` literals: the eight v1 task kinds are
-- `'scan'`, `'cron-rescan-tick'`, `'advisory-watch-tick'`,
-- `'retention-evaluate'`, `'retention-purge'`, `'eventstore-archive'`,
-- `'staging-sweep'`, `'noop'`. Underscore variants (`cron_rescan_tick`
-- etc.) are bugs, not synonyms; the CHECK constraint here matches the
-- `TaskHandler::kind()` returns.
--
-- GRANTs / role wiring: this migration ships NO explicit
-- `GRANT … TO hort_app_role` statements. The post-004 convention
-- (ADR 0009) is that migrations rely on the operator's role-bootstrap
-- recipe:
--
--   ALTER DEFAULT PRIVILEGES FOR ROLE hort_admin IN SCHEMA public
--       GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES    TO hort_app_role;
--   ALTER DEFAULT PRIVILEGES FOR ROLE hort_admin IN SCHEMA public
--       GRANT USAGE,  SELECT, UPDATE         ON SEQUENCES TO hort_app_role;
--
-- Default privileges apply to FUTURE objects `hort_admin` creates, which
-- is exactly the case here. Migrations 005, 006, 007, 008 follow the
-- same convention; only 004 (events table) carries explicit GRANTs
-- because it has unusual privileges (mutation REVOKEs after a trigger).
-- This migration does not need that.
--
-- Reversal: sqlx::migrate! runs UP-only; the project does not maintain
-- paired *.down.sql files. Manual reversal command if ever needed:
--
--   DROP TABLE IF EXISTS public.scanner_registry      CASCADE;
--   DROP TABLE IF EXISTS public.repo_security_scores  CASCADE;
--   DROP TABLE IF EXISTS public.scan_findings         CASCADE;
--   DROP TABLE IF EXISTS public.jobs                  CASCADE;
--   DROP INDEX IF EXISTS public.artifacts_last_scan_at_idx;
--   ALTER TABLE public.artifacts DROP COLUMN IF EXISTS last_scan_at;

DROP TABLE IF EXISTS public.scans                CASCADE;
DROP TABLE IF EXISTS public.scan_findings        CASCADE;
DROP TABLE IF EXISTS public.repo_security_scores CASCADE;
DROP TABLE IF EXISTS public.scan_configs         CASCADE;

-- ---------------------------------------------------------------------------
-- jobs (folded union — table named `jobs` from day 1)
-- ---------------------------------------------------------------------------

CREATE TABLE public.jobs (
    -- Identity.
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Cross-kind dispatch. Hyphen-separated literals match
    -- `TaskHandler::kind()` returns. The constraint is the SQL mirror of
    -- the `VALID_TASK_KINDS` allow-list in
    -- `crates/hort-domain/src/events/authorization_events.rs` — keep in
    -- lock-step. Pre-1.0, kinds are added here in place (ADR 0022); the
    -- prior 012/014/015/016 forward-ALTER chain was collapsed back into
    -- this file once the chain stopped earning its keep (DB-wipe-per-alpha
    -- makes the in-place edit free, and a single defining migration is
    -- easier to read than a chain).
    kind            text NOT NULL CHECK (kind IN (
        'scan',
        'cron-rescan-tick',
        'advisory-watch-tick',
        'retention-evaluate',
        'retention-purge',
        'eventstore-archive',
        'staging-sweep',
        'noop',
        'service-account-rotation',     -- service-account key rotation
        'eventstore-checkpoint',        -- tamper-evident chain anchor (ADR 0002)
        'replay-seen-prune',            -- JWT anti-replay seen-set cleanup
        'quarantine-release-sweep',     -- quarantine window release (ADR 0007 + ADR 0020)
        'seed-import',                  -- operator one-shot quarantine seed
        'prefetch-tick',                -- scheduled prefetch trigger
        'prefetch',                     -- per-(repo, package, version) prefetch ingest
        'prefetch-dependencies',        -- transitive prefetch cascade
        'prefetch-row-retention-sweep', -- terminal prefetch* row GC
        'wheel-metadata-backfill',      -- PEP 658 metadata backfill for pre-existing wheels
        'provenance-verify',            -- Sigstore/cosign provenance verify; enqueued at ingest
        -- Liveness breadcrumb written by the `hort-server verify-event-chain`
        -- CLI's `JobsRepository::record_run_completion` after a run completes.
        -- NOT a worker-dispatched `TaskHandler` kind (the verify run is a
        -- direct `hort-server` subcommand, scheduled by the
        -- `cronJobs.verifyEventChain` CronJob), so it is intentionally
        -- absent from `VALID_TASK_KINDS` (the admin-task-invoke allow-list).
        -- The boot-time `hort_event_chain_verify_overdue` gauge reads the
        -- newest `kind='verify-event-chain' AND status='completed'` row.
        -- Added in place per the pre-1.0 migration discipline (ADR 0022);
        -- persistent DBs MUST re-migrate when this migration's checksum
        -- changes.
        'verify-event-chain'            -- event-chain verify-run liveness breadcrumb
    )),
    params          jsonb NOT NULL DEFAULT '{}'::jsonb,
    actor_id        uuid REFERENCES public.users(id),
    -- Explicit ranking among trigger sources:
    --   ingest=0 (default)  →  advisory=5  →  cron=10  →  manual=20
    -- The worker's claim query orders by `priority DESC, created_at ASC`,
    -- so higher priority drains first. The CHECK bounds the column at
    -- the operator-misuse boundary (`smallint` already caps at 32767;
    -- the BETWEEN keeps the semantic ordering deliberate).
    priority        smallint NOT NULL DEFAULT 0
                    CHECK (priority BETWEEN 0 AND 100),
    trigger_source  text NOT NULL DEFAULT 'manual' CHECK (trigger_source IN (
        -- `'seed-import'` is a separate trigger-source so the
        -- `hort-server seed-import` subcommand's enqueues are
        -- distinguishable from other `'manual'` enqueues in the audit
        -- trail. Added in place per the pre-1.0 migration discipline
        -- (ADR 0022); DB MUST be re-migrated when this migration's
        -- checksum changes.
        --
        -- `'prefetch'` distinguishes cascade-spawned child rows (the
        -- transitive walk `PrefetchDependenciesHandler` enqueues for each
        -- not-already-held dep) from cron / advisory / ingest / manual.
        -- The handler-spawned origin matters for the dedup invariant
        -- (`'prefetch'` enqueues are *always* guarded by the L3
        -- `target_key` partial unique index) and for audit attribution (an
        -- unexpectedly high `'prefetch'` rate is a runaway cascade, not a
        -- runaway operator). Added in place per ADR 0022.
        --
        -- `'self_service'` is the operator-initiated `hort-cli prefetch`
        -- ROOT enqueue, distinct from the cascade-spawned `'prefetch'`
        -- children above: an unexpectedly high `'self_service'` rate is
        -- a runaway operator, not a runaway cascade. Added in place
        -- (ADR 0022); DB MUST be re-migrated when this migration's
        -- checksum changes.
        --
        -- `'scheduled'` is the `prefetch-tick` ROOT enqueue: the worker
        -- tick enqueues `kind='prefetch'` leaf rows for the newest
        -- not-held versions of each tracked package. Distinct from
        -- `'self_service'` (operator CLI) and `'prefetch'` (cascade
        -- child). NOT `'prefetch'`, so the ingested leaf is a SEED that
        -- re-fires the transitive cascade. Added in place (ADR 0022);
        -- persistent DBs MUST re-migrate (checksum changes).
        'manual', 'cron', 'advisory', 'ingest', 'seed-import', 'prefetch',
        'self_service', 'scheduled'
    )),
    -- `TaskOutcome::Completed { result_summary }`
    -- lands here. NULL while the job is running or pending; populated on
    -- completion.
    result_summary  jsonb,

    -- L3 dedup key for the transitive prefetch cascade.
    --
    -- Canonical shape:
    --     "{repo_id}|{format}|{normalised_package}|{version}"
    --
    -- (Components separated by U+007C VERTICAL LINE. The format key is
    -- the [`RepositoryFormat::Display`] string — `"npm"`/`"pypi"`/
    -- `"cargo"`/etc. — so a future format never collides with a
    -- different format's name. The package name is post-normalisation
    -- — `FormatHandler::normalize_name` runs at the cascade site
    -- before the key is composed, mirroring the artifact projection's
    -- lookup key.)
    --
    -- NULL for every non-`prefetch%` kind — scan / cron / sweep /
    -- noop rows do not use the L3 dedup index and pay no per-INSERT
    -- index cost. The cascade is the only producer of non-NULL
    -- values.
    --
    -- The two partial unique indexes below (`jobs_prefetch_unique` +
    -- `jobs_prefetch_dependencies_unique`) absorb concurrent cascade
    -- re-walks of the same (repo, package, version) cohort —
    -- design §2.3's three-level dedup, L3:
    --
    --   L1 — PullDedup (single-flight upstream pull)
    --   L2 — artifacts path-UNIQUE (terminal ingest absorb)
    --   L3 — partial unique on jobs.target_key WHERE …pending|running
    --
    -- Status-scoping the WHERE clause is load-bearing twice:
    --   1. blocks a *concurrent* re-walk (in-flight kind row exists)
    --   2. permits a *later* re-walk (terminal rows fall out of the
    --      index, so a new walk after a failed/expired job is
    --      allowed — the cascade is stateless and re-derives missing
    --      subtrees from `artifacts`).
    --
    -- The cascade enqueues via batch
    --   INSERT INTO jobs (...) VALUES (...), (...), ...
    --       ON CONFLICT (target_key) WHERE …pending|running DO NOTHING
    -- so duplicate-cohort detection IS the insert — no read-then-insert
    -- race window between the planner and the writer.
    target_key      text,
    -- typed columns rather than packing them into `params` so the
    -- existing scan repo queries (claim, complete, fail) stay strongly
    -- typed and indexable.
    artifact_id     uuid,
    repository_id   uuid,
    content_hash    text,
    format          text,

    -- Worker claim / lifecycle. Used by every kind, not just scan.
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    attempts        integer NOT NULL DEFAULT 0,
    locked_by       text,
    locked_until    timestamptz,
    last_error      text,

    -- Server-derived per-UTC-day idempotency key for the destructive-cron
    -- single-flight invariant (ADR 0028, promoted from Redis to a durable
    -- DB partial-unique index). When `idempotency_key IS NOT NULL` the
    -- `jobs_idempotency_key_uq` index below rejects a second insert with
    -- the same key — the HTTP handler derives the key as
    -- `cron:<kind>:<YYYY-MM-DD>` for every destructive kind so the
    -- invariant is structural rather than dependent on operator discipline.
    -- NULL for every non-destructive enqueue — the partial predicate is
    -- inert and the column carries no storage cost.
    --
    -- Charset CHECK mirrors `IdempotencyKey::try_from` in
    -- `crates/hort-domain/src/types/idempotency_key.rs` 1:1 — defense in
    -- depth so a raw-SQL writer that bypasses the domain layer cannot
    -- smuggle a malformed key into the index. The character class is
    -- `[-A-Za-z0-9._:/]` and the length range is 1..=256.
    --
    -- Split into TWO CHECK predicates against the same column:
    --   - charset regex: `^[-A-Za-z0-9._:/]+$` (no `{m,n}` — Postgres
    --     ERE caps `{m,n}` repetition counts at 255, so a single
    --     `{1,256}` quantifier surfaces as `2201B invalid_regular_
    --     expression "invalid repetition count(s)"`. Using `+` for "one
    --     or more" sidesteps the cap; length is enforced separately.)
    --   - length predicate: `char_length(...) BETWEEN 1 AND 256` —
    --     direct comparison, no regex involved, exact 1:1 match with
    --     the Rust validator's `s.is_empty()` + `s.len() > 256` checks
    --     (the latter is byte-length; the charset regex above admits
    --     only single-byte ASCII bytes, so byte- and char-length are
    --     identical for any accepted input).
    idempotency_key text NULL
                    CONSTRAINT jobs_idempotency_key_charset_chk CHECK (
                        idempotency_key IS NULL
                        OR idempotency_key ~ '^[-A-Za-z0-9._:/]+$'
                    )
                    CONSTRAINT jobs_idempotency_key_length_chk CHECK (
                        idempotency_key IS NULL
                        OR char_length(idempotency_key) BETWEEN 1 AND 256
                    ),

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz
);

-- At most one IN-FLIGHT scan job per artifact. The partial unique
-- constrains `(artifact_id)` only for rows whose `status IN
-- ('pending','running')`; once a scan transitions to `completed` or
-- `failed` the row drops out of the index, freeing the artifact for a
-- fresh rescan. Without the status filter, a single completed scan would
-- block every subsequent rescan with a 409 ("409 ONLY on in-flight scans").
--
-- Cross-kind rows commonly have `artifact_id IS NULL` and are excluded
-- from the index by the second clause.
--
-- Pre-1.0 in-place edit (per `feedback_pre_release_migrations`): an
-- earlier draft of this migration omitted the status predicate. If a
-- developer DB is already stamped against the old shape the
-- `_sqlx_migrations` content-hash will drift and sqlx will refuse to
-- start. Operator response: drop and recreate the dev DB
-- (`dropdb && createdb && cargo run …`) — the v2 line is pre-GA and
-- does not preserve developer-DB data across schema fixes.
CREATE UNIQUE INDEX jobs_scan_unique
    ON public.jobs (artifact_id)
    WHERE kind = 'scan'
      AND artifact_id IS NOT NULL
      AND status IN ('pending', 'running');

-- Claim index covering ALL kinds. Workers select the highest-priority
-- pending job in their kind set; ordering ties break on creation order.
CREATE INDEX jobs_claim_idx
    ON public.jobs (kind, priority DESC, created_at)
    WHERE status = 'pending';

-- L3 partial unique indexes for the transitive prefetch cascade. Mirrors
-- the `jobs_scan_unique` shape verbatim:
-- the index entry exists only while the row's status is
-- `pending`/`running`, so a terminal `completed`/`failed` row falls
-- out of the index and permits a future re-walk of the same
-- `(repo, package, version)`. See the `target_key` column comment
-- above for the L1/L2/L3 dedup hierarchy and the canonical key
-- shape.
--
-- One index per kind (not a single combined index on
-- `kind IN ('prefetch','prefetch-dependencies')`) so the SQL CHECK +
-- index WHERE-clause stay 1:1 with the Rust `VALID_TASK_KINDS`
-- additions — a fourth `prefetch%` kind in the future opts in by
-- adding its own partial index, not by editing a shared `IN ()` list
-- (the planner emits one INSERT per kind; the batch-INSERT semantics
-- match the per-kind index 1:1).
--
-- `target_key IS NOT NULL` is a defensive belt-and-braces predicate.
-- The cascade always populates `target_key` on `prefetch%` enqueues,
-- but the column is nullable for the other twelve kinds. Without
-- the predicate, a (theoretical) `prefetch%` row with a NULL
-- target_key would silently fall out of the index (PostgreSQL drops
-- NULL keys from unique indexes by default) — the predicate makes
-- such a row a constraint violation at INSERT time instead.
CREATE UNIQUE INDEX jobs_prefetch_unique
    ON public.jobs (target_key)
    WHERE kind = 'prefetch'
      AND target_key IS NOT NULL
      AND status IN ('pending', 'running');

CREATE UNIQUE INDEX jobs_prefetch_dependencies_unique
    ON public.jobs (target_key)
    WHERE kind = 'prefetch-dependencies'
      AND target_key IS NOT NULL
      AND status IN ('pending', 'running');

-- Partial-unique index over the destructive-cron idempotency key
-- (ADR 0028). The HTTP handler derives the key server-side as
-- `cron:<kind>:<YYYY-MM-DD>` for every destructive kind
-- (`retention-purge`, `retention-evaluate`, `eventstore-archive`) before
-- calling `TaskUseCase::enqueue`. The adapter `enqueue_task` runs an
-- `INSERT … ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT
-- NULL DO NOTHING` against this index — a second insert with the same key
-- returns `EnqueueOutcome::Duplicate` (no new row, the existing row's id
-- surfaced to the handler as a 200 + the prior task_job_id).
--
-- Unlike the prefetch indexes above this is NOT status-scoped — the
-- per-UTC-day claim persists across terminal states. A failed destructive
-- job's claim survives until the next UTC day's CronJob firing; operator
-- recovery within the same day is the explicit, audited
-- `DELETE FROM jobs WHERE id = <failed_id>` path (the CronJob schedule IS
-- the retry mechanism; hand-rolling a same-day retry-after-failure path
-- defeats `concurrencyPolicy: Forbid`).
CREATE UNIQUE INDEX jobs_idempotency_key_uq
    ON public.jobs (idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Per-table autovacuum tuning so the `jobs` base table does not bloat
-- under cascade load. A closure-warm enqueues thousands of rows per
-- ingest; each row transitions `pending → running → completed/failed`
-- (three updates), then ages out via the retention sweep below. Without
-- per-table tuning the 20%-of-table autovacuum threshold lets dead tuples
-- accumulate to millions before the daemon kicks in, blowing up the
-- partial claim/dedup index sizes.
--
-- A much tighter factor + a small base threshold so the daemon runs after
-- every few thousand dead tuples rather than after every few hundred
-- thousand. These are runtime-tunable knobs; an operator with a different
-- workload mix overrides via psql without a migration.
ALTER TABLE public.jobs SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_vacuum_threshold    = 1000,
    autovacuum_analyze_scale_factor = 0.05,
    autovacuum_analyze_threshold    = 500
);

-- ---------------------------------------------------------------------------
-- scan_findings (per-finding projection)
-- ---------------------------------------------------------------------------

-- M1 — `severity` CHECK matches the four-value taxonomy used by the
-- domain `SeverityThreshold` enum, the `severity_to_sql` SQL renderer
-- in `crates/hort-adapters-postgres/src/scan_findings_repository.rs`,
-- and the metrics catalog (`hort_scan_findings_total.severity ∈
-- {critical, high, medium, low}`). The Trivy adapter folds incoming
-- `NEGLIGIBLE` to `Low` as a conservative fallback, so no v2 code path
-- ever writes `'negligible'` to this column.
--
-- H9 — Length CHECKs cap unbounded text columns. `purl` ≤ 512 (a
-- generous over-approximation of practical purl encodings); CVE / GHSA
-- identifiers are well under 128; titles are operator-facing summaries
-- (≤ 1024); `source_scanner` is a registered backend name (≤ 64).
--
-- M4 — `artifact_id` REFERENCES `artifacts(id) ON DELETE CASCADE` so
-- finding rows disappear when the artifact is deleted. The composite
-- PK already orders `artifact_id` first, so the FK rides the same
-- index and adds no write amplification.
CREATE TABLE public.scan_findings (
    artifact_id        uuid NOT NULL REFERENCES public.artifacts(id) ON DELETE CASCADE,
    scan_id            uuid NOT NULL,
    purl               text NOT NULL
        CONSTRAINT scan_findings_purl_length CHECK (octet_length(purl) <= 512),
    vulnerability_id   text NOT NULL
        CONSTRAINT scan_findings_vulnerability_id_length CHECK (octet_length(vulnerability_id) <= 128),
    severity           text NOT NULL
        CONSTRAINT scan_findings_severity_check CHECK (severity IN (
            'critical', 'high', 'medium', 'low'
        )),
    cvss_score         real,
    source_scanner     text NOT NULL
        CONSTRAINT scan_findings_source_scanner_length CHECK (octet_length(source_scanner) <= 64),
    title              text NOT NULL
        CONSTRAINT scan_findings_title_length CHECK (octet_length(title) <= 1024),
    detected_at        timestamptz NOT NULL,
    PRIMARY KEY (artifact_id, scan_id, purl, vulnerability_id, source_scanner)
);

CREATE INDEX scan_findings_artifact_idx ON public.scan_findings (artifact_id);
CREATE INDEX scan_findings_cve_idx      ON public.scan_findings (vulnerability_id);
CREATE INDEX scan_findings_severity_idx ON public.scan_findings (severity)
    WHERE severity IN ('critical', 'high');

-- ---------------------------------------------------------------------------
-- repo_security_scores (per-repo aggregate projection)
-- ---------------------------------------------------------------------------

-- M2 — `updated_at DEFAULT now()` lets projector inserts omit the
-- column on the happy path; explicit writes still override.
-- M3 — `repository_id REFERENCES repositories(id) ON DELETE CASCADE`
-- so the projection row vanishes when the repository is deleted. The
-- column is still the PRIMARY KEY (one score row per repository).
CREATE TABLE public.repo_security_scores (
    repository_id      uuid PRIMARY KEY REFERENCES public.repositories(id) ON DELETE CASCADE,
    quarantined_count  integer NOT NULL DEFAULT 0,
    rejected_count     integer NOT NULL DEFAULT 0,
    released_count     integer NOT NULL DEFAULT 0,
    critical_count     integer NOT NULL DEFAULT 0,
    high_count         integer NOT NULL DEFAULT 0,
    medium_count       integer NOT NULL DEFAULT 0,
    low_count          integer NOT NULL DEFAULT 0,
    last_scan_at       timestamptz,
    updated_at         timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- scanner_registry (worker liveness)
-- ---------------------------------------------------------------------------
-- Worker-coordination state — mutable, not event-sourced. Each scanner
-- worker upserts on boot and refreshes `last_heartbeat` every 60 seconds.

-- L7 — `backends` cardinality CHECK: a worker that registers with an
-- empty backend array contributes nothing. The CHECK turns "no
-- declared backends" into a DB-side error so misconfigured workers
-- fail loudly at boot instead of silently never claiming any jobs.
CREATE TABLE public.scanner_registry (
    worker_id      text PRIMARY KEY,
    backends       text[] NOT NULL
        CONSTRAINT scanner_registry_backends_nonempty CHECK (cardinality(backends) >= 1),
    registered_at  timestamptz NOT NULL,
    last_heartbeat timestamptz NOT NULL
);

-- ---------------------------------------------------------------------------
-- artifacts.last_scan_at (per-artifact denorm)
-- ---------------------------------------------------------------------------
-- The cron-rescan eligibility query reads exactly this column. Existing
-- rows take NULL ("never scanned, eligible"); the first `ScanCompleted`
-- after migration populates the value via
-- `QuarantineUseCase::record_scan_result` in the same Postgres transaction
-- as the event append. The partial index covers the two live, downloadable
-- terminal states the eligibility query considers:
-- `quarantine_status='released'` and `quarantine_status IS NULL` (the
-- permissive-default state — no operator policy / quarantineDuration 0).
-- It excludes `quarantined`/`rejected`/`scan_indeterminate`.

ALTER TABLE public.artifacts ADD COLUMN last_scan_at timestamptz;

CREATE INDEX artifacts_last_scan_at_idx
    ON public.artifacts (last_scan_at)
    WHERE quarantine_status = 'released' OR quarantine_status IS NULL;

-- ---------------------------------------------------------------------------
-- GRANT defensive-fallback (ADR 0009 role-bootstrap recipe)
-- ---------------------------------------------------------------------------
-- The header note above explains the post-004 convention (ADR 0009):
-- migrations rely on the operator's `ALTER DEFAULT PRIVILEGES … FOR ROLE
-- hort_admin` recipe to grant the runtime role access to FUTURE objects.
-- If the operator forgot to run that recipe before applying 009,
-- `hort_app_role` ends up unable to read or mutate any of the four new
-- tables — the running service then fails every scan-related query with
-- `permission denied`. The conditional GRANT below catches that footgun:
-- if `hort_app_role` exists, grant the standard CRUD set on the four
-- tables this migration creates. If the role does not exist (greenfield
-- bootstrap before role creation), the block is a no-op and the
-- operator's later role-creation step picks up default privileges as
-- designed.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hort_app_role') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON public.jobs,
               public.scan_findings,
               public.repo_security_scores,
               public.scanner_registry
            TO hort_app_role;
    END IF;
END $$;
