//! PostgreSQL implementation of [`RescanCandidatesRepository`].
//!
//! Runs the canonical eligibility query: left-join `artifacts` to
//! `policy_projections` via the repo→policy chain (a repo-scoped
//! policy shadows the global default; archived rows are excluded),
//! filter `quarantine_status IN ('released', NULL)` and an effective
//! `rescan_interval_hours > 0`, compare `last_scan_at` against that
//! interval, and exclude artifacts that already have an in-flight
//! `kind='scan'` job. The result is bounded by `LIMIT $batch_size`
//! (the handler pins `1000`).
//!
//! `quarantine_status IS NULL` is admitted alongside `'released'`
//! because a permissive-default artifact (no operator policy, or a
//! policy with `quarantine_duration_secs = 0`) is a live, downloadable
//! terminal state. Excluding it would leave every out-of-the-box
//! deployment's artifacts un-rescanned.
//!
//! Also implements `select_stranded` (issue #6; widened by issue #115
//! defect (a) cure) — a companion eligibility query for
//! `quarantine_status='quarantined'` artifacts whose scan either could
//! not run at all (every backend errored, exhausted retries) OR was
//! never even requested (no `kind='scan'` job row exists — the
//! seed-import stranding gap item1 of #115 stops at the source; this
//! sweep recovers artifacts already stranded that way before that fix),
//! gated by the same resolved-policy-scans guard `select_eligible` uses
//! so a `scan_backends: []` (ScanWaived) artifact is never treated as
//! stranded. See the port's module doc and this impl's `select_stranded`
//! doc comment.
//!
//! # Repo→policy resolution
//!
//! `policy_projections.scope` is JSONB:
//! - `"Global"` for the unit variant
//! - `{"Repository": "<uuid>"}` for the tuple variant
//!
//! For each artifact row, the resolved policy is:
//!
//! 1. If a non-archived `Repository(repo_id)` policy exists for the
//!    artifact's `repository_id`, that policy wins.
//! 2. Otherwise, if a non-archived `Global` policy exists, it applies.
//! 3. Otherwise the hardcoded `DefaultPolicy` applies: the `LEFT JOIN`
//!    yields a NULL `rescan_interval_hours`, and `COALESCE(_, $3)`
//!    substitutes `DefaultPolicy::rescan_interval_hours()` (24h) —
//!    resolution tier 3. No-policy artifacts are rescanned, not skipped.
//!
//! The shadowing semantics mirror
//! `crates/hort-adapters-postgres/src/artifact_repo.rs::list_rejected_for_policy`'s
//! per-policy filter, just inverted: that one is "given a policy,
//! find its artifacts"; this one is "given each artifact, pick its
//! one resolved policy".

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::policy::scan::DefaultPolicy;
use hort_domain::ports::rescan_candidates::{RescanCandidate, RescanCandidatesRepository};
use hort_domain::types::ContentHash;

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL adapter for the rescan eligibility query.
pub struct PgRescanCandidatesRepository {
    pool: PgPool,
}

impl PgRescanCandidatesRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl RescanCandidatesRepository for PgRescanCandidatesRepository {
    fn select_eligible<'a>(
        &'a self,
        batch_size: u32,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>> {
        Box::pin(async move {
            tracing::debug!(batch_size, %now, "select_eligible");
            // The `LATERAL` subquery picks the resolved policy per
            // artifact: a repo-scoped non-archived policy if one
            // exists, otherwise a non-archived Global. The outer
            // `LEFT JOIN` keeps artifacts with no resolved policy;
            // `COALESCE(p.rescan_interval_hours, $3)` then applies the
            // `DefaultPolicy` 24h interval to them (policy resolution tier 3).
            //
            // The `now()` comparison uses the application-supplied
            // timestamp, not the database's `now()`, so per-tick
            // semantics stay coherent across retries and tests can
            // pin the comparison time.
            //
            // `repositories.format` carries the lowercase format token
            // (`'npm'`, `'pypi'`, …) that `enqueue_scan` writes into
            // `jobs.format`.
            let sql = r#"
                SELECT a.id            AS artifact_id,
                       a.repository_id AS repository_id,
                       a.checksum_sha256 AS content_hash,
                       r.format::text  AS format,
                       COALESCE(p.rescan_interval_hours, $3) AS rescan_interval_hours
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
                LEFT JOIN LATERAL (
                    SELECT pp.rescan_interval_hours
                    FROM policy_projections pp
                    WHERE pp.archived = false
                      AND (
                            (pp.scope ? 'Repository'
                              AND (pp.scope->>'Repository')::uuid = a.repository_id)
                         OR (pp.scope ? 'Global'
                              AND NOT EXISTS (
                                SELECT 1 FROM policy_projections pp2
                                WHERE pp2.archived = false
                                  AND pp2.scope ? 'Repository'
                                  AND (pp2.scope->>'Repository')::uuid = a.repository_id
                              ))
                          )
                    ORDER BY (pp.scope ? 'Repository') DESC
                    LIMIT 1
                ) p ON TRUE
                WHERE COALESCE(p.rescan_interval_hours, $3) > 0
                  AND (a.quarantine_status = 'released'
                       OR a.quarantine_status IS NULL)
                  AND (
                        a.last_scan_at IS NULL
                     OR a.last_scan_at
                          < $1 - make_interval(
                                     hours => COALESCE(p.rescan_interval_hours, $3))
                      )
                  AND NOT EXISTS (
                        SELECT 1 FROM jobs j
                        WHERE j.kind = 'scan'
                          AND j.artifact_id = a.id
                          AND j.status IN ('pending', 'running')
                      )
                LIMIT $2
            "#;

            let rows = sqlx::query(sql)
                .bind(now)
                .bind(i64::from(batch_size))
                .bind(DefaultPolicy::rescan_interval_hours())
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "RescanCandidate", "select_eligible"))?;

            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let artifact_id: Uuid = row.try_get("artifact_id").map_err(|e| decode_err(&e))?;
                let repository_id: Uuid =
                    row.try_get("repository_id").map_err(|e| decode_err(&e))?;
                let content_hash_str: String =
                    row.try_get("content_hash").map_err(|e| decode_err(&e))?;
                let content_hash: ContentHash = content_hash_str.parse().map_err(|e| {
                    DomainError::Invariant(format!(
                        "rescan_candidates: invalid content_hash for artifact {artifact_id}: {e}"
                    ))
                })?;
                let format: String = row.try_get("format").map_err(|e| decode_err(&e))?;
                let rescan_interval_hours: i32 = row
                    .try_get("rescan_interval_hours")
                    .map_err(|e| decode_err(&e))?;
                out.push(RescanCandidate {
                    artifact_id,
                    repository_id,
                    content_hash,
                    format,
                    rescan_interval_hours,
                });
            }
            Ok(out)
        })
    }

    fn select_stranded<'a>(
        &'a self,
        batch_size: u32,
    ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>> {
        Box::pin(async move {
            tracing::debug!(batch_size, "select_stranded");
            // The first `LATERAL` subquery picks the artifact's single
            // most-recent `kind='scan'` job row (any status), ordered by
            // `created_at DESC` — `idx_jobs_scan_artifact_created_at`
            // (migration 015) covers this as a direct index scan. It is a
            // `LEFT JOIN LATERAL` (not `JOIN`, issue #115 defect (a) —
            // widened from the original issue #6 shape): an artifact with
            // NO `kind='scan'` job at all yields `last_job.status IS
            // NULL`, which the widened predicate below now admits
            // alongside `'failed'`. That is the seed-import-stranding
            // recovery case — item1 of #115 stops NEW artifacts from
            // stranding job-less, but artifacts already quarantined
            // job-less in deployed environments before that fix need
            // this widened sweep to recover; there is no manual
            // per-artifact rescan surface, so this IS the remediation for
            // them, not an alternative to one.
            //
            // The second `LATERAL` subquery mirrors `select_eligible`'s
            // repo-scoped-else-global policy resolution exactly (see this
            // impl's `select_eligible` for the full resolution-order
            // comment) but selects `scan_backends` instead of
            // `rescan_interval_hours`. A job-less (or failed-job)
            // quarantined artifact is stranded ONLY when its resolved
            // policy actually scans: `scan_backends: []` (ScanWaived) is
            // an explicit operator opt-out of scanning, and such an
            // artifact is NOT stranded — it releases via the existing
            // `ScanWaived` release authority (ADR 0007), and enqueueing a
            // scan for it would contradict the operator's own policy. No
            // resolved policy row (`p.scan_backends IS NULL`) falls back
            // to `DefaultPolicy::block_on_critical_default_backends()`
            // (`["trivy"]`, non-empty) via `COALESCE(cardinality(..), $2)`
            // — out-of-the-box deployments with zero `ScanPolicy` rows
            // still get stranded artifacts recovered.
            //
            // `quarantine_status = 'quarantined'` (NOT `'released'`/`NULL`
            // — that's `select_eligible`'s predicate, and NOT
            // `'scan_indeterminate'`/`'rejected'` — those are terminal,
            // ADR 0007, never auto-rescanned). The
            // in-flight exclusion reuses the same shape as
            // `select_eligible` and is covered by the existing
            // `jobs_scan_unique` partial unique index (migration 009).
            let sql = r#"
                SELECT a.id            AS artifact_id,
                       a.repository_id AS repository_id,
                       a.checksum_sha256 AS content_hash,
                       r.format::text  AS format
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
                LEFT JOIN LATERAL (
                    SELECT j.status
                    FROM jobs j
                    WHERE j.kind = 'scan'
                      AND j.artifact_id = a.id
                    ORDER BY j.created_at DESC
                    LIMIT 1
                ) last_job ON TRUE
                LEFT JOIN LATERAL (
                    SELECT pp.scan_backends
                    FROM policy_projections pp
                    WHERE pp.archived = false
                      AND (
                            (pp.scope ? 'Repository'
                              AND (pp.scope->>'Repository')::uuid = a.repository_id)
                         OR (pp.scope ? 'Global'
                              AND NOT EXISTS (
                                SELECT 1 FROM policy_projections pp2
                                WHERE pp2.archived = false
                                  AND pp2.scope ? 'Repository'
                                  AND (pp2.scope->>'Repository')::uuid = a.repository_id
                              ))
                          )
                    ORDER BY (pp.scope ? 'Repository') DESC
                    LIMIT 1
                ) p ON TRUE
                WHERE a.quarantine_status = 'quarantined'
                  AND (last_job.status = 'failed' OR last_job.status IS NULL)
                  AND COALESCE(cardinality(p.scan_backends), $2) > 0
                  AND NOT EXISTS (
                        SELECT 1 FROM jobs j2
                        WHERE j2.kind = 'scan'
                          AND j2.artifact_id = a.id
                          AND j2.status IN ('pending', 'running')
                      )
                LIMIT $1
            "#;

            let rows = sqlx::query(sql)
                .bind(i64::from(batch_size))
                .bind(DefaultPolicy::block_on_critical_default_backends().len() as i32)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "RescanCandidate", "select_stranded"))?;

            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let artifact_id: Uuid = row.try_get("artifact_id").map_err(|e| decode_err(&e))?;
                let repository_id: Uuid =
                    row.try_get("repository_id").map_err(|e| decode_err(&e))?;
                let content_hash_str: String =
                    row.try_get("content_hash").map_err(|e| decode_err(&e))?;
                let content_hash: ContentHash = content_hash_str.parse().map_err(|e| {
                    DomainError::Invariant(format!(
                        "rescan_candidates: invalid content_hash for artifact {artifact_id}: {e}"
                    ))
                })?;
                let format: String = row.try_get("format").map_err(|e| decode_err(&e))?;
                out.push(RescanCandidate {
                    artifact_id,
                    repository_id,
                    content_hash,
                    format,
                    // Sentinel — see the field's doc comment on
                    // `RescanCandidate`. This query has no interval
                    // concept.
                    rescan_interval_hours: 0,
                });
            }
            Ok(out)
        })
    }
}

fn decode_err(e: &sqlx::Error) -> DomainError {
    tracing::warn!(error = %e, "rescan_candidates row decode failed");
    DomainError::Invariant(format!("rescan_candidates row decode: {e}"))
}
