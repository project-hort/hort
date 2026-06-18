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
                  AND a.is_deleted = false
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
}

fn decode_err(e: &sqlx::Error) -> DomainError {
    tracing::warn!(error = %e, "rescan_candidates row decode failed");
    DomainError::Invariant(format!("rescan_candidates row decode: {e}"))
}
