//! PostgreSQL implementation of [`QuarantineReleaseCandidatesRepository`].
//!
//! Returns up to `batch_size` quarantined artifacts whose computed
//! deadline (`quarantine_window_start + effective_duration`) has
//! elapsed. The effective duration is `ScanPolicy.quarantineDuration`
//! resolved with the same precedence
//! `QuarantineUseCase::record_scan_result` uses:
//!
//! 1. **Repo-scoped non-archived policy** for `artifacts.repository_id`
//!    → that policy's `quarantine_duration_secs`.
//! 2. **Global non-archived policy** when no repo-scoped match exists
//!    → that policy's `quarantine_duration_secs`.
//! 3. **`DefaultPolicy::quarantine_duration_secs()`** (86 400 s)
//!    otherwise — the same tier every other quarantine-window
//!    consumer falls back to (ingest, the scan fast path,
//!    `is_window_elapsed`, the read-path deadline). A repo with no
//!    resolvable policy row still quarantines everything for 24 h at
//!    ingest, so it must still surface release candidates once that
//!    window elapses.
//!
//! Cost is bounded by **number of policies**, not number of artifacts:
//! there are typically a handful of distinct durations,
//! so the adapter groups repos by their effective duration and issues
//! one indexed range scan per distinct duration `D`:
//!
//! ```text
//! WHERE quarantine_status = 'quarantined'
//!   AND repository_id = ANY($repos_for_D)
//!   AND quarantine_window_start <= $now - D
//! ```
//!
//! The partial index `idx_artifacts_quarantine_release_cursor ON
//! (release_attempt_at NULLS FIRST, quarantine_window_start) WHERE
//! quarantine_status = 'quarantined'` makes the `<= constant` predicate
//! an indexed scan and satisfies the ordering below without a sort.
//!
//! **Fair candidacy — the attempt cursor.** Rows are ordered
//! `release_attempt_at ASC NULLS FIRST, quarantine_window_start ASC`, and
//! [`QuarantineReleaseCandidatesRepository::mark_attempted`] stamps the
//! whole batch after each tick. Window-start-only ordering made the
//! selection a fixed point: a candidate that the fail-closed authority
//! gate or the provenance gate permanently holds is never released and so
//! never leaves the head of the ordering, and once such rows filled a
//! whole batch the sweep stopped reaching any other artifact in the
//! deployment at all. With the cursor, never-attempted rows lead — a
//! fresh artifact past its deadline is served on the next tick regardless
//! of backlog size — and attempted rows rotate behind them, so a backlog
//! of N is fully re-attempted every `ceil(N / batch_size)` ticks.
//!
//! `release_attempt_at` is **operational scheduling metadata,
//! deliberately not event-sourced** — the same class as the task queue's
//! scheduling columns. It records *when* the sweep last considered a row,
//! never *what* it decided; nothing outside this ordering reads it, and a
//! replay that ignores it reconstructs the identical artifact. The
//! candidacy/authority layering (ADR 0007) is untouched: candidacy is
//! still "window elapsed" in SQL, authority is still the per-artifact
//! check in `release_expired`. The cursor reorders which candidates a
//! bounded batch re-checks first; it can never authorize a release.
//!
//! **Permissive opt-in preserved.** An operator policy with
//! `quarantine_duration_secs = 0` is permissive mode — the policy
//! *exists* but its window collapses to zero. Such repos contribute no
//! candidates because the SQL filter drops the duration with `> 0`
//! (matches `record_scan_result` and the rescan-candidates' `> 0`
//! treatment).
//!
//! See `crates/hort-app/src/task_handlers/quarantine_release_sweep.rs`
//! for the handler that consumes this port and feeds the result into
//! `QuarantineUseCase::release_expired`, which enforces the
//! fail-closed authority predicate per artifact.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::policy::scan::DefaultPolicy;
use hort_domain::ports::quarantine_release_candidates::{
    QuarantineReleaseCandidate, QuarantineReleaseCandidatesRepository,
};

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL adapter for the quarantine-release candidacy query.
pub struct PgQuarantineReleaseCandidatesRepository {
    pool: PgPool,
}

impl PgQuarantineReleaseCandidatesRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl QuarantineReleaseCandidatesRepository for PgQuarantineReleaseCandidatesRepository {
    fn select_expired<'a>(
        &'a self,
        batch_size: u32,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<Vec<QuarantineReleaseCandidate>>> {
        Box::pin(async move {
            tracing::debug!(batch_size, %now, "select_expired");

            // -----------------------------------------------------------------
            // Step 1 — resolve every quarantined repo's effective duration.
            //
            // Read every non-archived policy projection's `scope` +
            // `quarantine_duration_secs`, then walk the quarantined-
            // artifact rows to build the `repo → duration` map. Cost is
            // O(policies + quarantined_repos), bounded by the policy set
            // size: "Cost is bounded by *number of policies*, never
            // number of artifacts."
            //
            // Per-repo precedence (mirrors
            // `QuarantineUseCase::record_scan_result`):
            //   repo-scoped non-archived > global non-archived
            //   > `DefaultPolicy::quarantine_duration_secs()`.
            //
            // A repo with no matched policy row still resolves to the
            // 86 400s default — the same window ingest applied when it
            // quarantined those artifacts in the first place.
            // -----------------------------------------------------------------

            // Pull active policies grouped by scope. Tiny rowcount — at
            // most a handful per deployment — so a single fetch_all is
            // cheaper than a per-repo LATERAL.
            #[derive(Debug)]
            struct PolicyRow {
                repo_id: Option<Uuid>, // Some(_) ⇒ Repository(uuid); None ⇒ Global
                quarantine_duration_secs: i64,
            }
            let policy_rows: Vec<PolicyRow> = sqlx::query(
                r#"
                SELECT
                    CASE
                        WHEN pp.scope ? 'Repository'
                        THEN (pp.scope->>'Repository')::uuid
                        ELSE NULL
                    END AS repo_id,
                    pp.quarantine_duration_secs AS quarantine_duration_secs
                FROM policy_projections pp
                WHERE pp.archived = false
                  AND (pp.scope ? 'Repository' OR pp.scope ? 'Global')
                "#,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "QuarantineReleaseCandidate", "list_active_policies"))?
            .into_iter()
            .map(|row| {
                let repo_id: Option<Uuid> = row.try_get("repo_id").map_err(|e| decode_err(&e))?;
                let quarantine_duration_secs: i64 = row
                    .try_get("quarantine_duration_secs")
                    .map_err(|e| decode_err(&e))?;
                Ok::<PolicyRow, DomainError>(PolicyRow {
                    repo_id,
                    quarantine_duration_secs,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

            // Split into repo-scoped (overrides) and the global default.
            let mut repo_scoped: HashMap<Uuid, i64> = HashMap::new();
            let mut global_duration: Option<i64> = None;
            for p in policy_rows {
                match p.repo_id {
                    Some(repo) => {
                        // Repo-scoped policy. If somehow multiple rows
                        // exist (apply pipeline should prevent this),
                        // first read wins — the apply pipeline enforces
                        // at most one non-archived policy per scope.
                        repo_scoped
                            .entry(repo)
                            .or_insert(p.quarantine_duration_secs);
                    }
                    None => {
                        global_duration.get_or_insert(p.quarantine_duration_secs);
                    }
                }
            }

            // Walk the quarantined repos. The set of repos that currently
            // hold any quarantined artifact is the only set we need a
            // duration for; resolve each via the precedence above.
            //
            // Soft-deleted artifacts are excluded here and in the
            // per-duration scan below: deletion is the terminal event on
            // the artifact's stream, so releasing one afterwards would
            // append a lifecycle event past the terminal and make a
            // replay reconstruct a deleted artifact as live.
            let quarantined_repos: Vec<Uuid> = sqlx::query(
                r#"
                SELECT DISTINCT repository_id
                FROM artifacts
                WHERE quarantine_status = 'quarantined'
                  AND quarantine_window_start IS NOT NULL
                  AND deleted_at IS NULL
                "#,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                map_sqlx_error(&e, "QuarantineReleaseCandidate", "list_quarantined_repos")
            })?
            .into_iter()
            .map(|row| {
                row.try_get::<Uuid, _>("repository_id")
                    .map_err(|e| decode_err(&e))
            })
            .collect::<Result<Vec<_>, _>>()?;

            // Group repos by their resolved effective duration. Precedence
            // is repo-scoped non-archived policy > global non-archived
            // policy > `DefaultPolicy::quarantine_duration_secs()` — the
            // same three-tier resolution every other consumer of the
            // quarantine window uses (`QuarantineUseCase::record_scan_result`,
            // the scan fast path, `is_window_elapsed`, the read-path
            // deadline). A resolved duration of `<= 0` (the permissive
            // opt-in: an explicit policy with `quarantine_duration_secs =
            // 0`) still contributes no candidates — permissive mode is
            // exactly "no quarantine hold," so no release-sweep work.
            let mut by_duration: HashMap<i64, Vec<Uuid>> = HashMap::new();
            for repo in quarantined_repos {
                let effective = repo_scoped
                    .get(&repo)
                    .copied()
                    .or(global_duration)
                    .or(Some(DefaultPolicy::quarantine_duration_secs()));
                if let Some(secs) = effective {
                    if secs > 0 {
                        by_duration.entry(secs).or_default().push(repo);
                    }
                }
            }

            if by_duration.is_empty() {
                return Ok(Vec::new());
            }

            // -----------------------------------------------------------------
            // Step 2 — one indexed scan per distinct duration.
            //
            // The partial index
            // `idx_artifacts_quarantine_release_cursor ON
            // (release_attempt_at NULLS FIRST, quarantine_window_start)
            // WHERE quarantine_status = 'quarantined'` supports this: it
            // serves the ORDER BY directly (same column order, same
            // NULLS FIRST) while `quarantine_window_start <= <constant>`
            // filters inside the index, and `repository_id = ANY(...)`
            // is applied before the heap fetch.
            //
            // The ORDER BY is the anti-starvation contract, not a
            // cosmetic: never-attempted rows (NULL cursor) lead, so a
            // freshly-expired artifact is served on the next tick no
            // matter how large the unreleasable backlog ahead of it is;
            // stamped rows rotate behind them in stamp order.
            // -----------------------------------------------------------------
            let mut candidates: Vec<QuarantineReleaseCandidate> = Vec::new();
            // Iteration order over a HashMap is non-deterministic, which
            // is fine — the handler does not rely on candidate ordering
            // (release_expired is loop-driven and per-artifact).
            for (duration_secs, repos) in by_duration {
                let cutoff = now - chrono::Duration::seconds(duration_secs);
                let remaining = (batch_size as i64).saturating_sub(candidates.len() as i64);
                if remaining <= 0 {
                    break;
                }
                let rows = sqlx::query(
                    r#"
                    SELECT id AS artifact_id
                    FROM artifacts
                    WHERE quarantine_status = 'quarantined'
                      AND repository_id = ANY($1)
                      AND quarantine_window_start <= $2
                      AND deleted_at IS NULL
                    ORDER BY release_attempt_at ASC NULLS FIRST, quarantine_window_start ASC
                    LIMIT $3
                    "#,
                )
                .bind(&repos)
                .bind(cutoff)
                .bind(remaining)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    map_sqlx_error(
                        &e,
                        "QuarantineReleaseCandidate",
                        "select_expired_per_duration",
                    )
                })?;

                for row in rows {
                    let artifact_id: Uuid =
                        row.try_get("artifact_id").map_err(|e| decode_err(&e))?;
                    candidates.push(QuarantineReleaseCandidate { artifact_id });
                }
            }

            Ok(candidates)
        })
    }

    fn mark_attempted<'a>(
        &'a self,
        ids: &'a [Uuid],
        at: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async move {
            if ids.is_empty() {
                return Ok(());
            }
            tracing::debug!(count = ids.len(), %at, "mark_attempted");

            // One statement for the whole batch. A per-id UPDATE would
            // put a round-trip per candidate on a path that runs with up
            // to a full batch every tick; `= ANY($1)` keeps it at one.
            //
            // No `quarantine_status` / `deleted_at` guard: the stamp is a
            // scheduling cursor, so writing it to a row that has since
            // been released or deleted is harmless (the row is no longer
            // a candidate, and nothing but candidacy ordering reads the
            // column). Adding a guard would only risk skipping the stamp
            // on a row that raced back into the pool.
            sqlx::query(
                r#"
                UPDATE artifacts
                SET release_attempt_at = $2
                WHERE id = ANY($1)
                "#,
            )
            .bind(ids)
            .bind(at)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "QuarantineReleaseCandidate", "mark_attempted"))?;

            Ok(())
        })
    }
}

fn decode_err(e: &sqlx::Error) -> DomainError {
    tracing::warn!(error = %e, "quarantine_release_candidates row decode failed");
    DomainError::Invariant(format!("quarantine_release_candidates row decode: {e}"))
}

// ---------------------------------------------------------------------------
// Tests — DB-backed; gated on `maybe_pool()` per crate convention.
// Every #[serial(hort_pg_db)] DB test gates on `maybe_pool()` returning
// `Some` (the suite serialises against the shared dev DB; the suite
// silently no-ops on a CI box with no DB configured).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    use serde_json::json;
    use serial_test::serial;
    use sqlx::PgPool;

    /// Mirrors the per-module `maybe_pool` pattern in
    /// `crates/hort-adapters-postgres/src/terminal_stream_reader.rs` etc.
    /// — silently no-ops when `DATABASE_URL` is unset (CI without a
    /// Postgres service); otherwise builds an isolated DB via
    /// `test_support::isolated_db_from` so the test cannot corrupt
    /// other suites running concurrently.
    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;
        Some(pool)
    }

    /// Seed a minimal repository row with a unique key and return its id.
    async fn seed_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("it-qrc-{}", id.simple());
        sqlx::query(
            r#"INSERT INTO public.repositories (
                   id, key, name, format, repo_type, storage_backend, storage_path,
                   replication_priority
               ) VALUES (
                   $1, $2, $3,
                   'pypi'::repository_format,
                   'hosted'::repository_type,
                   'filesystem', $4,
                   'local_only'::replication_priority
               )"#,
        )
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .execute(pool)
        .await
        .expect("seed repository row");
        id
    }

    /// Seed a quarantined artifact whose window started `started` and
    /// return its id.
    async fn seed_quarantined_artifact(pool: &PgPool, repo: Uuid, started: DateTime<Utc>) -> Uuid {
        let id = Uuid::new_v4();
        let key = id.simple().to_string();
        let sha256 = format!("{key}{key}");
        sqlx::query(
            r#"INSERT INTO public.artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   quarantine_status, quarantine_window_start
               ) VALUES (
                   $1, $2, 'qrc-it', 'qrc-it', '0.0.0', $3,
                   0, $4, 'application/octet-stream', $4,
                   'quarantined', $5
               )"#,
        )
        .bind(id)
        .bind(repo)
        .bind(format!("simple/qrc-it/{key}.tar.gz"))
        .bind(&sha256)
        .bind(started)
        .execute(pool)
        .await
        .expect("seed quarantined artifact row");
        id
    }

    /// Read an artifact's fairness cursor straight from the row.
    async fn read_release_attempt_at(pool: &PgPool, id: Uuid) -> Option<DateTime<Utc>> {
        sqlx::query_scalar("SELECT release_attempt_at FROM public.artifacts WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read release_attempt_at")
    }

    /// Seed a non-archived repository-scoped policy with the requested
    /// `quarantine_duration_secs`.
    async fn seed_repo_scoped_policy(pool: &PgPool, repo_id: Uuid, quarantine_duration_secs: i64) {
        let policy_id = Uuid::new_v4();
        let name = format!("it-qrc-policy-{}", policy_id.simple());
        let scope = json!({ "Repository": repo_id });
        sqlx::query(
            r#"INSERT INTO public.policy_projections (
                   policy_id, name, scope, severity_threshold,
                   rescan_interval_hours, quarantine_duration_secs,
                   require_approval, archived,
                   stream_version
               ) VALUES (
                   $1, $2, $3, 'high',
                   24, $4,
                   false, false,
                   1
               )"#,
        )
        .bind(policy_id)
        .bind(&name)
        .bind(&scope)
        .bind(quarantine_duration_secs)
        .execute(pool)
        .await
        .expect("seed repo-scoped policy_projections row");
    }

    /// `select_expired` returns an empty `Vec` on an empty database —
    /// no policies, no artifacts, no quarantined repos to resolve a
    /// duration for in the first place, so the default-duration
    /// fallback never even gets consulted.
    ///
    /// `#[serial(hort_pg_db)]` per CLAUDE.md "DB-backed test isolation
    /// (parallel-safety contract)": any new hort-adapters-postgres test
    /// that touches the shared DB MUST carry the crate-wide serial
    /// key. The isolated_db_from helper still uses a per-test schema,
    /// but the serial key keeps the inline `--lib` suite ordered.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_returns_empty_on_empty_db() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let repo = PgQuarantineReleaseCandidatesRepository::new(pool);
        let out = repo
            .select_expired(1000, Utc::now())
            .await
            .expect("select_expired must succeed on empty db");
        assert!(
            out.is_empty(),
            "no policies + no artifacts ⇒ no candidates; got {} rows",
            out.len()
        );
    }

    /// A quarantined artifact in a repo with **zero** resolvable policy
    /// rows (no repo-scoped, no Global) becomes a release candidate once
    /// `DefaultPolicy::quarantine_duration_secs()` (86 400 s) has
    /// elapsed. This is the defect this module fixes: previously such a
    /// repo resolved to `None` and was dropped from candidacy forever.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_falls_back_to_default_duration_when_no_policy_resolves() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let repo = seed_repo(&pool).await;
        let now = Utc::now();
        let started = now
            - chrono::Duration::seconds(DefaultPolicy::quarantine_duration_secs())
            - chrono::Duration::seconds(1);
        let artifact = seed_quarantined_artifact(&pool, repo, started).await;

        let out = PgQuarantineReleaseCandidatesRepository::new(pool)
            .select_expired(1000, now)
            .await
            .expect("select_expired Ok");

        assert_eq!(
            out.iter().map(|c| c.artifact_id).collect::<Vec<_>>(),
            vec![artifact],
            "an artifact past the default window in a policy-less repo must be a candidate"
        );
    }

    /// The counterpart of the fallback test above: before the default
    /// window has elapsed, the same policy-less artifact is NOT a
    /// candidate.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_default_duration_not_yet_elapsed_is_not_a_candidate() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let repo = seed_repo(&pool).await;
        let now = Utc::now();
        let started = now - chrono::Duration::seconds(DefaultPolicy::quarantine_duration_secs())
            + chrono::Duration::seconds(60);
        let artifact = seed_quarantined_artifact(&pool, repo, started).await;

        let out = PgQuarantineReleaseCandidatesRepository::new(pool)
            .select_expired(1000, now)
            .await
            .expect("select_expired Ok");

        assert!(
            !out.iter().any(|c| c.artifact_id == artifact),
            "an artifact inside the default window must not be a candidate yet"
        );
    }

    /// Permissive opt-in: an explicit repo-scoped policy with
    /// `quarantine_duration_secs = 0` must never contribute a candidate,
    /// no matter how long ago the artifact's window started. The
    /// default-duration fallback added by this fix must not override an
    /// operator's explicit zero.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_explicit_zero_duration_never_a_candidate() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let repo = seed_repo(&pool).await;
        seed_repo_scoped_policy(&pool, repo, 0).await;
        let now = Utc::now();
        // Started far in the past — would be well past the default
        // window if the zero-duration policy did not exist.
        let started = now - chrono::Duration::days(365);
        let artifact = seed_quarantined_artifact(&pool, repo, started).await;

        let out = PgQuarantineReleaseCandidatesRepository::new(pool)
            .select_expired(1000, now)
            .await
            .expect("select_expired Ok");

        assert!(
            !out.iter().any(|c| c.artifact_id == artifact),
            "quarantine_duration_secs = 0 must permanently exclude the repo from candidacy"
        );
    }

    // -----------------------------------------------------------------
    // Fair candidacy — the attempt cursor
    // -----------------------------------------------------------------

    /// A never-attempted artifact (`release_attempt_at IS NULL`) is
    /// served ahead of an already-attempted one **even though its
    /// quarantine window started later**. This is the ordering that
    /// stops a permanently-unreleasable head of the backlog from
    /// occupying the batch forever: under the old
    /// `ORDER BY quarantine_window_start` the older row would lead on
    /// every tick, for good.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_serves_never_attempted_before_attempted() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let repo = seed_repo(&pool).await;
        let now = Utc::now();
        let window = chrono::Duration::seconds(DefaultPolicy::quarantine_duration_secs());
        // `older` has the earlier window start — it would win outright
        // on window-start ordering alone.
        let older =
            seed_quarantined_artifact(&pool, repo, now - window - chrono::Duration::days(9)).await;
        let newer =
            seed_quarantined_artifact(&pool, repo, now - window - chrono::Duration::days(1)).await;

        let adapter = PgQuarantineReleaseCandidatesRepository::new(pool.clone());
        adapter
            .mark_attempted(&[older], now - chrono::Duration::minutes(5))
            .await
            .expect("mark_attempted Ok");

        let out = adapter
            .select_expired(1000, now)
            .await
            .expect("select_expired Ok");

        assert_eq!(
            out.iter().map(|c| c.artifact_id).collect::<Vec<_>>(),
            vec![newer, older],
            "NULLS FIRST: the never-attempted candidate leads, the stamped one rotates behind",
        );
    }

    /// Among candidates that have all been attempted, the *least
    /// recently* attempted leads — the rotation is by stamp, and the
    /// window start only breaks ties within the same stamp.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_orders_attempted_candidates_by_stalest_stamp() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let repo = seed_repo(&pool).await;
        let now = Utc::now();
        let window = chrono::Duration::seconds(DefaultPolicy::quarantine_duration_secs());
        let recently_tried =
            seed_quarantined_artifact(&pool, repo, now - window - chrono::Duration::days(9)).await;
        let long_ago_tried =
            seed_quarantined_artifact(&pool, repo, now - window - chrono::Duration::days(1)).await;

        let adapter = PgQuarantineReleaseCandidatesRepository::new(pool.clone());
        adapter
            .mark_attempted(&[recently_tried], now - chrono::Duration::minutes(1))
            .await
            .expect("mark_attempted Ok");
        adapter
            .mark_attempted(&[long_ago_tried], now - chrono::Duration::hours(6))
            .await
            .expect("mark_attempted Ok");

        let out = adapter
            .select_expired(1000, now)
            .await
            .expect("select_expired Ok");

        assert_eq!(
            out.iter().map(|c| c.artifact_id).collect::<Vec<_>>(),
            vec![long_ago_tried, recently_tried],
            "the stalest attempt leads regardless of window start",
        );
    }

    /// One `mark_attempted` call stamps every id in the batch with the
    /// same instant — the bulk contract. A per-id round trip on a
    /// thousand-row batch is exactly what the `= ANY($1)` form avoids.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn mark_attempted_stamps_the_whole_batch_in_one_call() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let repo = seed_repo(&pool).await;
        let now = Utc::now();
        let a = seed_quarantined_artifact(&pool, repo, now - chrono::Duration::days(3)).await;
        let b = seed_quarantined_artifact(&pool, repo, now - chrono::Duration::days(3)).await;
        let untouched =
            seed_quarantined_artifact(&pool, repo, now - chrono::Duration::days(3)).await;

        assert!(read_release_attempt_at(&pool, a).await.is_none());

        // Whole-second instant: `timestamptz` stores microseconds, so a
        // `Utc::now()` carrying nanoseconds would not round-trip
        // bit-identically and the assertion would be about Postgres'
        // resolution rather than about the stamp.
        let at = DateTime::from_timestamp(now.timestamp() - 30, 0).expect("valid timestamp");
        PgQuarantineReleaseCandidatesRepository::new(pool.clone())
            .mark_attempted(&[a, b], at)
            .await
            .expect("mark_attempted Ok");

        assert_eq!(read_release_attempt_at(&pool, a).await, Some(at));
        assert_eq!(read_release_attempt_at(&pool, b).await, Some(at));
        assert!(
            read_release_attempt_at(&pool, untouched).await.is_none(),
            "the stamp must touch exactly the ids it was handed",
        );
    }

    /// An empty batch is a no-op, not a statement against every row.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn mark_attempted_with_no_ids_leaves_every_row_untouched() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let repo = seed_repo(&pool).await;
        let now = Utc::now();
        let artifact =
            seed_quarantined_artifact(&pool, repo, now - chrono::Duration::days(3)).await;

        PgQuarantineReleaseCandidatesRepository::new(pool.clone())
            .mark_attempted(&[], now)
            .await
            .expect("mark_attempted Ok");

        assert!(read_release_attempt_at(&pool, artifact).await.is_none());
    }

    /// The candidacy index must match the ORDER BY exactly — same
    /// column order, and `NULLS FIRST` spelled out (it is not the ASC
    /// default). If they drift apart the query still returns correct
    /// rows, so no functional test would notice; it just silently
    /// degrades to sorting every quarantined row per tick.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn candidacy_index_matches_the_selection_ordering() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let indexdef: Option<String> = sqlx::query_scalar(
            "SELECT indexdef FROM pg_indexes \
             WHERE schemaname = 'public' AND tablename = 'artifacts' \
               AND indexname = 'idx_artifacts_quarantine_release_cursor'",
        )
        .fetch_optional(&pool)
        .await
        .expect("probe index definition");

        let def = indexdef.expect("idx_artifacts_quarantine_release_cursor must exist");
        assert!(
            def.contains("release_attempt_at NULLS FIRST"),
            "leading key must be the cursor with NULLS FIRST; got {def}",
        );
        assert!(
            def.contains("quarantine_window_start"),
            "window start must remain the second key so the range predicate stays in \
             the index; got {def}",
        );
        assert!(
            def.contains("quarantined"),
            "the index must stay partial on the quarantined set; got {def}",
        );
    }

    /// **Starvation regression.** More unreleasable candidates than fit
    /// in one batch, plus one newer artifact behind them: the newer one
    /// must be reached within two select→mark cycles.
    ///
    /// This is the production failure reproduced in miniature — a
    /// deployment whose oldest batch-worth of candidates could never
    /// self-release (parent-gated blobs) released nothing, anywhere,
    /// ever again. The batch size is parameterised here rather than the
    /// handler's 1000 so the shape is testable; the ordering property
    /// under test is identical at either size.
    ///
    /// "Unreleasable" is modelled by what the adapter can actually see:
    /// the rows stay `quarantined` across ticks (no release ever
    /// happens), so under window-start ordering they would re-fill every
    /// batch forever.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_does_not_starve_a_newer_candidate_behind_a_full_unreleasable_batch() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        const BATCH: u32 = 3;

        let repo = seed_repo(&pool).await;
        let now = Utc::now();
        let window = chrono::Duration::seconds(DefaultPolicy::quarantine_duration_secs());

        // A backlog strictly larger than one batch, all older than the
        // newcomer, none of which will ever release.
        let mut stuck = Vec::new();
        for days_old in 0..(BATCH + 1) {
            stuck.push(
                seed_quarantined_artifact(
                    &pool,
                    repo,
                    now - window - chrono::Duration::days(10 + i64::from(days_old)),
                )
                .await,
            );
        }
        // The newcomer: past its deadline, but the youngest of the lot.
        let newcomer =
            seed_quarantined_artifact(&pool, repo, now - window - chrono::Duration::minutes(1))
                .await;

        let adapter = PgQuarantineReleaseCandidatesRepository::new(pool.clone());

        // Two ticks of the real loop: select a batch, then stamp exactly
        // what was selected (what the handler does after
        // `release_expired` returns).
        let mut seen: Vec<Uuid> = Vec::new();
        for tick in 0..2 {
            let batch = adapter
                .select_expired(BATCH, now + chrono::Duration::seconds(tick))
                .await
                .expect("select_expired Ok");
            let ids: Vec<Uuid> = batch.iter().map(|c| c.artifact_id).collect();
            assert_eq!(
                ids.len(),
                BATCH as usize,
                "the backlog is larger than a batch, so every tick fills it",
            );
            adapter
                .mark_attempted(&ids, now + chrono::Duration::seconds(tick))
                .await
                .expect("mark_attempted Ok");
            seen.extend(ids);
        }

        assert!(
            seen.contains(&newcomer),
            "a newly-expired artifact must be reached within ceil(N/batch) ticks, not \
             starved forever behind an unreleasable backlog",
        );
        assert!(
            stuck.iter().all(|id| seen.contains(id)),
            "and the rotation must still re-attempt the whole backlog — fairness is a \
             rotation, not a de-prioritisation",
        );
    }
}
