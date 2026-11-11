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
//! **Both queries exclude soft-deleted rows** (`a.deleted_at IS NULL`).
//! A deleted artifact is no longer part of the repository's served
//! catalog, so scanning it buys no serving decision — and `ArtifactDeleted`
//! is the terminal event on its stream, so a scan verdict appended
//! afterwards would put a lifecycle event past the terminal and make a
//! replay reconstruct a deleted artifact as live. Because both queries are
//! bounded by `LIMIT`, a deleted row does not merely appear: it consumes a
//! batch slot a real candidate then does not get, which is how a backlog
//! of deleted rows can starve rescanning outright.
//!
//! Also implements `select_stranded` (ADR 0007's retry-exhaustion split,
//! its later widening to artifacts with no scan job at all, and its "A
//! reached verdict supersedes an absent one" amendment) — a companion
//! eligibility query for
//! `quarantine_status IN ('quarantined', 'scan_indeterminate')`
//! artifacts whose scan either could not run at all (every backend
//! errored, exhausted retries) OR was never even requested (no
//! `kind='scan'` job row exists — the seed-import path no longer strands
//! artifacts that way, and this sweep recovers the ones it stranded
//! before that fix) OR reached no verdict at all and was last requested
//! longer ago than the resolved rescan interval, gated by the same
//! resolved-policy-scans guard `select_eligible` uses so a
//! `scan_backends: []` (ScanWaived) artifact is never treated as
//! stranded. See the port's module doc and this impl's `select_stranded`
//! doc comment.
//!
//! And `select_composite_unassessed` — live OCI image manifests with no
//! recorded composite assessment, the population that is neither held
//! (so `select_stranded` cannot see it) nor interval-stale (so
//! `select_eligible` cannot either) while the evidence it serves on
//! predates the composed verdict carrying release authority. See the
//! port's module doc.
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
                  AND a.deleted_at IS NULL
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
                let common = decode_common(&row)?;
                let rescan_interval_hours: i32 = row
                    .try_get("rescan_interval_hours")
                    .map_err(|e| decode_err(&e))?;
                out.push(common.into_candidate(rescan_interval_hours));
            }
            Ok(out)
        })
    }

    fn select_stranded<'a>(
        &'a self,
        batch_size: u32,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>> {
        Box::pin(async move {
            tracing::debug!(batch_size, %now, "select_stranded");
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
            // It also selects that job's `created_at`, which is what the
            // absent-verdict arm compares against. See the third
            // disjunct below.
            //
            // The second `LATERAL` subquery mirrors `select_eligible`'s
            // repo-scoped-else-global policy resolution exactly (see this
            // impl's `select_eligible` for the full resolution-order
            // comment) but selects `scan_backends` and
            // `rescan_interval_hours`. A job-less (or failed-job)
            // quarantined artifact is stranded ONLY when its resolved
            // policy actually scans: `scan_backends: []` (ScanWaived) is
            // an explicit operator opt-out of scanning, and such an
            // artifact is NOT stranded — it releases via the existing
            // `ScanWaived` release authority (ADR 0007), and enqueueing a
            // scan for it would contradict the operator's own policy. No
            // resolved policy row (`p.scan_backends IS NULL`) falls back
            // to `DefaultPolicy::block_on_critical_default_backends()`
            // (`["trivy"]`, non-empty) via `COALESCE(cardinality(..), $3)`
            // — so a deployment with zero `ScanPolicy` rows has its
            // stranded artifacts *in* this result set rather than
            // excluded from it. Whether they are then recovered depends
            // on this query being run at all: `CronRescanTickHandler`
            // is its only production caller and the chart ships that
            // tick off (`scheduledTasks.cronRescanTick.enabled:
            // false`).
            //
            // `quarantine_status IN ('quarantined', 'scan_indeterminate')`
            // — NOT `'released'`/`NULL`, that's `select_eligible`'s
            // predicate, and NOT `'rejected'`.
            //
            // `scan_indeterminate` is in scope because an artifact held
            // for want of a scan verdict accepts one that is reached
            // (ADR 0007, "A reached verdict supersedes an absent one"):
            // a non-blocking verdict returns it to the hold and a
            // blocking one condemns it, so a rescan has somewhere to
            // land. A state nothing re-picks is terminal in practice
            // whatever the transition table says, which is why the two
            // halves are one decision — this query IS the mechanism that
            // delivers the healing, since there is no per-artifact
            // operator rescan surface that bypasses it. Soft-deleted
            // rows stay excluded for both statuses (`a.deleted_at IS
            // NULL`, which `live_reads_exclude_deleted` governs).
            //
            // `rejected` stays excluded, and the asymmetry is the point:
            // a recorded rejection is a positive statement about the
            // artifact and stays terminal, while an absent verdict is a
            // statement about hort's own coverage. `re_evaluate` is the
            // exit from the former and this sweep is not.
            //
            // **The third disjunct, and why the status word cannot carry
            // the absent-verdict arm.** A scan in which every backend ran
            // and reported that it had nothing to analyse is a completed
            // job — nothing failed — and the artifact it leaves behind is
            // held with no verdict and no deadline. So a predicate that
            // reads only the job's status reaches that artifact exactly
            // as long as the job row misdescribes itself, which is not a
            // property to depend on. The arm therefore asks the
            // artifact's own status (`scan_indeterminate` already means
            // "no verdict was reached") and bounds the re-ask by time:
            // the most recent scan request must be older than the
            // resolved `rescan_interval_hours`. That timestamp advances
            // the moment this sweep enqueues, so the re-ask is
            // self-limiting whatever the next answer is — an artifact
            // whose verdict is reached leaves the status, and one whose
            // abstention is fixed is re-asked no more often than the
            // policy already re-scans a released artifact.
            //
            // `NULLIF(p.rescan_interval_hours, 0)` reads a configured `0`
            // as "no resolved interval" and falls back to
            // `DefaultPolicy::rescan_interval_hours()` ($4). `0` turns
            // off the interval rescan of a live, already-assessed
            // artifact; reading it as an instruction to hold an
            // unassessed artifact forever would make this query
            // unreachable for exactly the operators who disabled cadence
            // rescanning, and `make_interval(hours => 0)` would in any
            // case admit every row on every tick.
            //
            // The arm is additive: a `scan_indeterminate` artifact whose
            // last scan job errored or is absent is still picked up
            // immediately, as before. The cooldown only governs the rows
            // the first two disjuncts cannot see.
            //
            // The in-flight exclusion reuses the same shape as
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
                    SELECT j.status, j.created_at
                    FROM jobs j
                    WHERE j.kind = 'scan'
                      AND j.artifact_id = a.id
                    ORDER BY j.created_at DESC
                    LIMIT 1
                ) last_job ON TRUE
                LEFT JOIN LATERAL (
                    SELECT pp.scan_backends, pp.rescan_interval_hours
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
                WHERE a.quarantine_status IN ('quarantined', 'scan_indeterminate')
                  AND a.deleted_at IS NULL
                  AND (
                        last_job.status = 'failed'
                     OR last_job.status IS NULL
                     OR (
                          a.quarantine_status = 'scan_indeterminate'
                          AND last_job.created_at
                                < $2 - make_interval(
                                           hours => COALESCE(
                                               NULLIF(p.rescan_interval_hours, 0), $4))
                        )
                      )
                  AND COALESCE(cardinality(p.scan_backends), $3) > 0
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
                .bind(now)
                .bind(DefaultPolicy::block_on_critical_default_backends().len() as i32)
                .bind(DefaultPolicy::rescan_interval_hours())
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "RescanCandidate", "select_stranded"))?;

            decode_sentinel_candidates(rows)
        })
    }

    fn select_composite_unassessed<'a>(
        &'a self,
        batch_size: u32,
    ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>> {
        Box::pin(async move {
            tracing::debug!(batch_size, "select_composite_unassessed");
            // Live OCI image manifests with no recorded composite
            // assessment. The population neither companion query can
            // see: it is not held, so `select_stranded`'s statuses
            // exclude it, and its own `last_scan_at` may be minutes old,
            // so `select_eligible`'s interval excludes it too — while the
            // evidence it is serving on was reached under the earlier
            // rule, in which a composed image's verdict carried no
            // release authority.
            //
            // **A manifest row is `path LIKE 'manifests/sha256:%'`** —
            // the coords convention `hort-http-oci::coords` writes, and
            // the same discrimination
            // `ArtifactRepository::find_oci_image_manifests_without_kind`
            // uses. `ArtifactKind` is not persisted, so the path is what
            // there is to read.
            //
            // **An image index is excluded**, discriminated on the stored
            // media type (`artifact_metadata.metadata->>'oci_media_type'`,
            // mirroring `hort-http-oci::manifests::resolve_media_type`'s
            // read). An index composes nothing of its own — its children
            // are the manifests that do — so a composite assessment is
            // not something it can lack. A row with no
            // `artifact_metadata` row, or one whose `oci_media_type`
            // field is absent, is NOT excluded, mirroring
            // `resolve_media_type`'s own fallback to the single-image
            // default.
            //
            // **The predicate is the absence of an observation row, not
            // the absence of a successful one**, and that is what makes
            // the sweep self-limiting with no interval of its own: every
            // composite scan records a row, whatever it concluded, so a
            // reassessed manifest leaves the set on the next tick. A
            // manifest whose composite assessment is already recorded —
            // including one recording a refusal — is reached by the
            // ordinary interval sweep like any other released artifact,
            // and re-deriving a refusal from the same immutable bytes
            // would reach the same answer anyway.
            //
            // Reading the observation projection here is a *selection*,
            // not a decision: it answers "has this manifest ever been
            // composite-assessed?" and nothing about whether to release
            // one. The verdict still comes from the scan the enqueued job
            // runs and from the artifact's own event stream, which is the
            // separation `shadow_observation_has_no_authority` pins.
            //
            // Same resolved-policy-scans guard as `select_stranded`: a
            // `scan_backends: []` scope is an explicit operator opt-out
            // and enqueueing a scan under it would contradict the
            // operator's own policy. Same in-flight exclusion, and the
            // same `a.deleted_at IS NULL` (`live_reads_exclude_deleted`).
            let sql = r#"
                SELECT a.id            AS artifact_id,
                       a.repository_id AS repository_id,
                       a.checksum_sha256 AS content_hash,
                       r.format::text  AS format
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
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
                WHERE a.deleted_at IS NULL
                  AND (a.quarantine_status = 'released'
                       OR a.quarantine_status IS NULL)
                  AND a.path LIKE 'manifests/sha256:%'
                  AND COALESCE(cardinality(p.scan_backends), $2) > 0
                  AND NOT EXISTS (
                        SELECT 1 FROM composite_scan_observations o
                        WHERE o.artifact_id = a.id
                      )
                  AND NOT EXISTS (
                        SELECT 1 FROM artifact_metadata m
                        WHERE m.artifact_id = a.id
                          AND m.metadata->>'oci_media_type' IN ($3, $4)
                      )
                  AND NOT EXISTS (
                        SELECT 1 FROM jobs j
                        WHERE j.kind = 'scan'
                          AND j.artifact_id = a.id
                          AND j.status IN ('pending', 'running')
                      )
                LIMIT $1
            "#;

            let rows = sqlx::query(sql)
                .bind(i64::from(batch_size))
                .bind(DefaultPolicy::block_on_critical_default_backends().len() as i32)
                .bind(hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE)
                .bind(hort_domain::oci::DOCKER_MANIFEST_LIST_MEDIA_TYPE)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(&e, "RescanCandidate", "select_composite_unassessed")
                })?;

            decode_sentinel_candidates(rows)
        })
    }
}

/// The four columns every candidate query selects, decoded.
///
/// The interval is deliberately not among them: `select_eligible` reads
/// it off its own row and the two companion queries carry the sentinel
/// (see [`RescanCandidate::rescan_interval_hours`]), so sharing the
/// common four is what keeps one decode from being written three times.
struct CommonCandidateColumns {
    artifact_id: Uuid,
    repository_id: Uuid,
    content_hash: ContentHash,
    format: String,
}

impl CommonCandidateColumns {
    fn into_candidate(self, rescan_interval_hours: i32) -> RescanCandidate {
        RescanCandidate {
            artifact_id: self.artifact_id,
            repository_id: self.repository_id,
            content_hash: self.content_hash,
            format: self.format,
            rescan_interval_hours,
        }
    }
}

fn decode_common(row: &sqlx::postgres::PgRow) -> DomainResult<CommonCandidateColumns> {
    let artifact_id: Uuid = row.try_get("artifact_id").map_err(|e| decode_err(&e))?;
    let repository_id: Uuid = row.try_get("repository_id").map_err(|e| decode_err(&e))?;
    let content_hash_str: String = row.try_get("content_hash").map_err(|e| decode_err(&e))?;
    let content_hash: ContentHash = content_hash_str.parse().map_err(|e| {
        DomainError::Invariant(format!(
            "rescan_candidates: invalid content_hash for artifact {artifact_id}: {e}"
        ))
    })?;
    let format: String = row.try_get("format").map_err(|e| decode_err(&e))?;
    Ok(CommonCandidateColumns {
        artifact_id,
        repository_id,
        content_hash,
        format,
    })
}

/// Decode the rows of a query with no interval concept, stamping the
/// sentinel documented on [`RescanCandidate::rescan_interval_hours`].
fn decode_sentinel_candidates(
    rows: Vec<sqlx::postgres::PgRow>,
) -> DomainResult<Vec<RescanCandidate>> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(decode_common(&row)?.into_candidate(0));
    }
    Ok(out)
}

fn decode_err(e: &sqlx::Error) -> DomainError {
    tracing::warn!(error = %e, "rescan_candidates row decode failed");
    DomainError::Invariant(format!("rescan_candidates row decode: {e}"))
}
