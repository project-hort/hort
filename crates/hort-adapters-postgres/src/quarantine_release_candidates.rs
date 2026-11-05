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
//! there are typically a handful of distinct durations, and the adapter
//! resolves each quarantined repo's effective duration into a cutoff
//! instant, then carries the resulting `(repo, cutoff)` pairs into **one**
//! ordered scan:
//!
//! ```text
//! WHERE quarantine_status = 'quarantined'
//!   AND quarantine_window_start <= cutoff_for(repository_id)
//! ORDER BY release_attempt_at ASC NULLS FIRST, quarantine_window_start ASC
//! LIMIT $batch_size
//! ```
//!
//! **One query, one `LIMIT`** — because the batch budget must not be
//! consumable by one duration group. The earlier shape issued a query per
//! distinct duration and spent a shared budget across them, so the
//! (`HashMap`) visit order decided which groups were queried at all; see
//! Step 2 for the starvation that follows from that and why ordering
//! *within* a batch is a different question.
//!
//! The partial index `idx_artifacts_quarantine_release_cursor ON
//! (release_attempt_at NULLS FIRST, quarantine_window_start) WHERE
//! quarantine_status = 'quarantined'` satisfies the ordering without a
//! sort; the exact per-repo deadline test is a join predicate, and the
//! broadest of the cutoffs rides along as an index-condition pre-filter
//! (Step 2).
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
//! **Selection is by deadline, never by current policy.** An operator
//! policy with `quarantine_duration_secs = 0` is permissive mode — the
//! policy *exists* but its window collapses to zero. That is a window of
//! zero length, not an absent one: its cutoff is `now`, so every artifact
//! such a repo still holds is past its deadline and is selected here. In
//! steady state that set is empty — both minting paths in
//! `IngestUseCase` (`decide_and_apply_quarantine` and
//! `register_by_hash_inner`) skip the `Quarantined` transition outright
//! when the resolved duration is `<= 0` — so admitting these repos costs
//! nothing. The set is non-empty exactly in the cases that matter: an
//! artifact held under a longer window that an operator has since
//! shortened, or one a corrective path
//! (`ProvenanceMisrejectionRepairUseCase`) put back into the hold. Those
//! artifacts have no other exit — nothing moves `quarantine_window_start`
//! once it is stamped — so excluding their repo from candidacy strands
//! them `quarantined` permanently.
//!
//! **One uncomputable row costs one repository, not the sweep.** The
//! cutoff is `now` offset by the resolved duration, and a stored
//! `quarantine_duration_secs` large enough that no such instant exists
//! used to panic — on a deployment-wide, every-tick sweep, which made
//! one policy row stop every release in the installation in a crash
//! loop. That repository is now skipped, named at `error!` level with
//! the value that cannot be computed with, and every other
//! repository's candidates come back normally. See `repo_cutoff`.
//!
//! Whether a selected artifact may actually be released is decided per
//! artifact in `release_expired`: the scan-axis authority (ADR 0007) and
//! the provenance clearance (ADR 0027). Nothing in this module authorizes
//! a release.
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

            // Turn each quarantined repo's resolved effective duration into
            // the cutoff instant its artifacts' windows must have started
            // at or before, and keep the `(repo, cutoff)` pairs for the
            // single query below. Precedence is repo-scoped non-archived
            // policy > global non-archived policy >
            // `DefaultPolicy::quarantine_duration_secs()` — the same
            // three-tier resolution every other consumer of the quarantine
            // window uses (`QuarantineUseCase::record_scan_result`, the
            // scan fast path, `is_window_elapsed`, the read-path deadline).
            // It stays here in Rust rather than being re-typed in SQL: this
            // is the tier chain's only copy that can read the domain's own
            // default.
            //
            // Every resolved duration whose cutoff can be computed at all
            // produces a pair (`repo_cutoff` carries the one exception,
            // which is a defective stored row rather than a policy
            // decision): this step selects by DEADLINE only. A permissive
            // window is a zero-length window, not an absent one — its
            // cutoff is `now`, which is the same arithmetic
            // `effective_quarantine_deadline(anchor, 0)` gives the scan
            // fast path — so every artifact the repo still holds is past
            // its deadline and belongs in the candidate set. Deciding here
            // that a repo's artifacts should not be released would be an
            // authority decision, and those belong to `release_expired`
            // (ADR 0007 scan authority, ADR 0027 provenance clearance).
            //
            // The `.max(0)` clamp makes zero and negative resolve the same
            // way — both say the window is behind us — and keeps the
            // cutoff off the future side of `now`, where a negative
            // duration would otherwise select rows whose window has NOT
            // elapsed.
            //
            // The two arrays are filled in this one loop, so they stay the
            // same length and every repo keeps its own cutoff. The repo
            // list arrived `DISTINCT`, which the join below relies on: a
            // repeated repo would match its artifacts once per copy and
            // return the same id several times inside one batch, spending
            // the budget on duplicates.
            let mut cutoff_repos: Vec<Uuid> = Vec::with_capacity(quarantined_repos.len());
            let mut cutoffs: Vec<DateTime<Utc>> = Vec::with_capacity(quarantined_repos.len());
            // The latest of all the cutoffs, tracked here because this loop
            // already visits every one of them. Step 2 explains what it is
            // for.
            let mut broadest_cutoff: Option<DateTime<Utc>> = None;
            for repo in quarantined_repos {
                let secs = repo_scoped
                    .get(&repo)
                    .copied()
                    .or(global_duration)
                    .unwrap_or_else(DefaultPolicy::quarantine_duration_secs)
                    .max(0);
                let Some(cutoff) = repo_cutoff(repo, secs, now) else {
                    continue;
                };
                broadest_cutoff = Some(broadest_cutoff.map_or(cutoff, |widest| widest.max(cutoff)));
                cutoff_repos.push(repo);
                cutoffs.push(cutoff);
            }

            // No pair survived the loop. Either no repository holds a
            // quarantined artifact at all — the honest meaning of "no
            // candidates" — or every quarantined repository's duration
            // was uncomputable, in which case `repo_cutoff` has already
            // named each one at `error!` level. There is nothing to
            // query either way.
            let Some(broadest_cutoff) = broadest_cutoff else {
                return Ok(Vec::new());
            };

            // -----------------------------------------------------------------
            // Step 2 — one ordered scan over every expired candidate.
            //
            // **The budget must not be consumable by one duration group.**
            // The per-repo cutoffs ride in as a `(repo, cutoff)` relation
            // and the `LIMIT` is applied once, over the whole candidate set
            // in cursor order, so `release_attempt_at` is a single global
            // rotation.
            //
            // The shape this replaced issued one query per distinct
            // duration and spent a shared budget across them, breaking out
            // when it ran dry — which made the iteration order decide
            // which duration groups were queried **at all**. A group
            // holding a batch-worth of rows the authority or provenance
            // gate never releases could therefore fill the budget on every
            // tick while a releasable artifact in another group was never
            // selected, and the wait had no bound: that order came from a
            // `HashMap` and so was re-drawn per process rather than
            // advancing. Ordering *within* a returned batch genuinely is
            // irrelevant — the handler is loop-driven and per-artifact —
            // but that is a different question from which rows reach the
            // batch, and only the first one is the handler's.
            //
            // The partial index
            // `idx_artifacts_quarantine_release_cursor ON
            // (release_attempt_at NULLS FIRST, quarantine_window_start)
            // WHERE quarantine_status = 'quarantined'` serves the ORDER BY
            // directly (same column order, same NULLS FIRST). The exact
            // deadline test is per row, against that row's own repo cutoff,
            // so it cannot be an index condition — `$3`, the latest of all
            // the cutoffs, restores one that can be. It is a widening of
            // the exact test and never narrower: a row that qualifies under
            // its own `now - D_repo` necessarily satisfies
            // `now - min(D)`, so the pre-filter rejects only rows the join
            // predicate would reject anyway, inside the index and without a
            // heap fetch.
            //
            // The ORDER BY is the anti-starvation contract, not a
            // cosmetic: never-attempted rows (NULL cursor) lead, so a
            // freshly-expired artifact is served on the next tick no
            // matter how large the unreleasable backlog ahead of it is;
            // stamped rows rotate behind them in stamp order.
            // -----------------------------------------------------------------
            let rows = sqlx::query(
                r#"
                WITH deadline(repository_id, cutoff) AS (
                    SELECT * FROM unnest($1::uuid[], $2::timestamptz[])
                )
                SELECT a.id AS artifact_id
                FROM artifacts a
                JOIN deadline d ON d.repository_id = a.repository_id
                WHERE a.quarantine_status = 'quarantined'
                  AND a.quarantine_window_start <= $3
                  AND a.quarantine_window_start <= d.cutoff
                  AND a.deleted_at IS NULL
                ORDER BY a.release_attempt_at ASC NULLS FIRST, a.quarantine_window_start ASC
                LIMIT $4
                "#,
            )
            .bind(&cutoff_repos)
            .bind(&cutoffs)
            .bind(broadest_cutoff)
            .bind(i64::from(batch_size))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "QuarantineReleaseCandidate", "select_expired"))?;

            let mut candidates: Vec<QuarantineReleaseCandidate> = Vec::with_capacity(rows.len());
            for row in rows {
                let artifact_id: Uuid = row.try_get("artifact_id").map_err(|e| decode_err(&e))?;
                candidates.push(QuarantineReleaseCandidate { artifact_id });
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

/// The instant a repository's quarantine windows must have started at
/// or before, or `None` when that instant does not exist.
///
/// `now - duration` is fallible twice over, and both failures are
/// reachable from a stored `quarantine_duration_secs`: a
/// [`chrono::TimeDelta`] holds at most `i64::MAX` milliseconds, and
/// subtracting one from `now` leaves the representable `DateTime` range
/// well before that. `TimeDelta::seconds` and `DateTime - TimeDelta`
/// both panic on their own bound, so the arithmetic is done through
/// their checked forms and the two failures share one verdict — there
/// is no useful distinction between "no `TimeDelta`" and "no instant":
/// either way this repository has no deadline to select against.
///
/// **Skipped, never guessed.** The caller drops the repository from the
/// candidacy query and keeps sweeping the others, so one defective row
/// costs that repository's releases instead of every release in the
/// deployment — this loop runs on a single deployment-wide sweep that
/// re-enters every tick, so a panic here is a crash loop with no
/// release path out of it. Substituting a default or a clamped window
/// is not available: the quarantine window is a security decision, and
/// inventing one here would release artifacts under a duration no
/// operator set.
///
/// Fail-closed, and **loud**: the artifacts stay quarantined, which is
/// the safe direction, but "this repository had nothing to release" and
/// "this repository cannot be computed" are the same observation from
/// outside — so the `error!` carries the repository id and the value
/// that cannot be computed with.
///
/// `hort_config::scan_policy::MAX_POLICY_DURATION_SECS` refuses an
/// uncomputable `quarantineDuration` at apply time, so a row reaching
/// the `None` branch did not come through apply: a hand-edited row, a
/// migration, a future writer, or a value stored before that bound
/// existed. Apply-time validation cannot heal a row already written,
/// which is why this is not redundant with it.
fn repo_cutoff(repo: Uuid, secs: i64, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let cutoff = chrono::TimeDelta::try_seconds(secs).and_then(|window| {
        // Checked: `now - window` is out of range long before
        // `TimeDelta` itself is.
        now.checked_sub_signed(window)
    });
    if cutoff.is_none() {
        tracing::error!(
            repository_id = %repo,
            quarantine_duration_secs = secs,
            "quarantine release sweep: this repository's effective quarantine duration has no \
             representable deadline, so its release candidates cannot be selected — skipping \
             it and sweeping the remaining repositories. Its quarantined artifacts stay held \
             until the duration is corrected; correct the ScanPolicy quarantineDuration for \
             this repository (or the global policy it inherits from) and re-apply."
        );
    }
    cutoff
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
    /// `quarantine_duration_secs`, leaving `provenance_mode` at the
    /// column default (`verify_if_present`).
    async fn seed_repo_scoped_policy(pool: &PgPool, repo_id: Uuid, quarantine_duration_secs: i64) {
        seed_repo_scoped_policy_with_provenance(
            pool,
            repo_id,
            quarantine_duration_secs,
            "verify_if_present",
        )
        .await;
    }

    /// Seed a non-archived repository-scoped policy with an explicit
    /// `provenance_mode`. `provenance_backends` stays at its
    /// `{cosign}` default so the
    /// `policy_projections_provenance_backends_nonempty_unless_off`
    /// constraint holds for every mode.
    async fn seed_repo_scoped_policy_with_provenance(
        pool: &PgPool,
        repo_id: Uuid,
        quarantine_duration_secs: i64,
        provenance_mode: &str,
    ) {
        let policy_id = Uuid::new_v4();
        let name = format!("it-qrc-policy-{}", policy_id.simple());
        let scope = json!({ "Repository": repo_id });
        sqlx::query(
            r#"INSERT INTO public.policy_projections (
                   policy_id, name, scope, severity_threshold,
                   rescan_interval_hours, quarantine_duration_secs,
                   require_approval, archived, provenance_mode,
                   stream_version
               ) VALUES (
                   $1, $2, $3, 'high',
                   24, $4,
                   false, false, $5,
                   1
               )"#,
        )
        .bind(policy_id)
        .bind(&name)
        .bind(&scope)
        .bind(quarantine_duration_secs)
        .bind(provenance_mode)
        .execute(pool)
        .await
        .expect("seed repo-scoped policy_projections row");
    }

    /// Seed a repository-scoped policy whose quarantine window is
    /// negative, the way one that **predates**
    /// `policy_projections_quarantine_duration_secs_nonnegative` exists.
    ///
    /// That constraint is `NOT VALID`: it refuses every write from its
    /// migration onwards and leaves rows written before it exactly as
    /// they stand. So a row already in the table is the only state a
    /// negative window survives in — and it is the whole reason the
    /// `.max(0)` clamp this module applies stays. Reproducing the state
    /// means writing the row while the constraint is absent and then
    /// restoring it as the migration left it, which is what the
    /// before-and-after here does; the database is this test's own
    /// (`isolated_db_from`), so no sibling can observe the gap.
    ///
    /// Seeding it any other way would be seeding a row the schema
    /// refuses — a premise no installation can reach, which would make
    /// the clamp below it answer about nothing.
    async fn seed_legacy_negative_window_policy(pool: &PgPool, repo_id: Uuid, secs: i64) {
        assert!(
            secs < 0,
            "the legacy shape this builds is a negative window"
        );
        sqlx::query(
            "ALTER TABLE public.policy_projections
                 DROP CONSTRAINT policy_projections_quarantine_duration_secs_nonnegative",
        )
        .execute(pool)
        .await
        .expect("the non-negativity constraint exists to be lifted");

        seed_repo_scoped_policy(pool, repo_id, secs).await;

        sqlx::query(
            "ALTER TABLE public.policy_projections
                 ADD CONSTRAINT policy_projections_quarantine_duration_secs_nonnegative
                 CHECK (quarantine_duration_secs >= 0) NOT VALID",
        )
        .execute(pool)
        .await
        .expect("restoring it NOT VALID leaves the row just written alone");
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

    /// **Production strand regression.** A repository switched to
    /// `quarantine_duration_secs = 0` while artifacts sat inside a longer
    /// window: those artifacts must still be selected. Nothing else moves
    /// `quarantine_window_start` once it is stamped, so a repo excluded
    /// from candidacy holds its artifacts `quarantined` forever with
    /// `release_attempt_at = NULL` — the observed failure (29 artifacts
    /// held nineteen days, recoverable only by a manual per-artifact
    /// waive).
    ///
    /// A zero window is a window of zero length: its cutoff is `now`, so
    /// every held artifact is past its deadline.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_zero_window_repo_still_selects_artifacts_held_under_a_prior_window() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let repo = seed_repo(&pool).await;
        // The switch already happened: the live policy is permissive...
        seed_repo_scoped_policy(&pool, repo, 0).await;
        let now = Utc::now();
        // ...but the artifact was anchored minutes before it, well inside
        // the 24h window that was in force at ingest.
        let started = now - chrono::Duration::minutes(12);
        let artifact = seed_quarantined_artifact(&pool, repo, started).await;

        let out = PgQuarantineReleaseCandidatesRepository::new(pool)
            .select_expired(1000, now)
            .await
            .expect("select_expired Ok");

        assert_eq!(
            out.iter().map(|c| c.artifact_id).collect::<Vec<_>>(),
            vec![artifact],
            "an artifact held under a prior window must stay selectable after the repo \
             goes permissive — the sweep is its only exit",
        );
    }

    /// Selection never consults the provenance gate. A held artifact in a
    /// permissive repo under `provenance_mode = 'required'` is a
    /// candidate exactly like any other; whether it may be RELEASED is
    /// `release_expired`'s decision (ADR 0027), and the app-layer sweep
    /// test
    /// `release_expired_zero_window_repo_holds_a_provenance_required_candidate`
    /// pins that it refuses and enqueues the final `provenance-verify`.
    ///
    /// The pair matters: permissive is an opt-in on the quarantine
    /// window, never an opt-out of provenance, and the two halves of that
    /// claim live in two layers.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_zero_window_repo_selects_a_provenance_required_candidate() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let repo = seed_repo(&pool).await;
        seed_repo_scoped_policy_with_provenance(&pool, repo, 0, "required").await;
        let now = Utc::now();
        let artifact =
            seed_quarantined_artifact(&pool, repo, now - chrono::Duration::minutes(12)).await;

        let out = PgQuarantineReleaseCandidatesRepository::new(pool)
            .select_expired(1000, now)
            .await
            .expect("select_expired Ok");

        assert_eq!(
            out.iter().map(|c| c.artifact_id).collect::<Vec<_>>(),
            vec![artifact],
            "candidacy is deadline-only: a provenance-Required artifact is selected and \
             then refused by the release gate, not hidden from the sweep",
        );
    }

    /// A permissive repository that holds nothing contributes nothing:
    /// step 1 selects only repositories with a `quarantined` row, so the
    /// repo never reaches the grouping at all and no per-duration scan
    /// runs for it. This is what makes admitting zero-duration repos free
    /// in steady state — under `quarantineDuration: 0` ingest never
    /// quarantines, so the held set is empty.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_zero_window_repo_with_no_quarantined_artifacts_contributes_nothing() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let empty_repo = seed_repo(&pool).await;
        seed_repo_scoped_policy(&pool, empty_repo, 0).await;
        // A second, policy-less repo that DOES hold an expired artifact,
        // so the query has work to do and the assertion is about the
        // permissive repo's absence rather than about an empty result.
        let holding_repo = seed_repo(&pool).await;
        let now = Utc::now();
        let held = seed_quarantined_artifact(
            &pool,
            holding_repo,
            now - chrono::Duration::seconds(DefaultPolicy::quarantine_duration_secs() + 1),
        )
        .await;

        let out = PgQuarantineReleaseCandidatesRepository::new(pool)
            .select_expired(1000, now)
            .await
            .expect("select_expired Ok");

        assert_eq!(
            out.iter().map(|c| c.artifact_id).collect::<Vec<_>>(),
            vec![held],
            "a repo holding no quarantined artifact contributes no candidates",
        );
    }

    /// A negative `quarantine_duration_secs` behaves exactly as zero.
    /// The column's non-negativity CHECK is `NOT VALID`, so a row
    /// written before it still carries one and this adapter — which
    /// reads the projection, not the validated YAML — can encounter it.
    /// See [`seed_legacy_negative_window_policy`] for why that is the
    /// only shape it arrives in, and why it is the shape seeded here.
    ///
    /// The clamp is what keeps the cutoff at `now` instead of
    /// `now + |secs|`: an unclamped negative duration would put the
    /// cutoff in the FUTURE and select artifacts whose window has not
    /// elapsed, turning a bad row into an early release.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_negative_duration_behaves_as_zero_without_a_future_cutoff() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let repo = seed_repo(&pool).await;
        seed_legacy_negative_window_policy(&pool, repo, -3600).await;
        let now = Utc::now();
        // Anchored in the past: past the clamped (zero) window.
        let elapsed =
            seed_quarantined_artifact(&pool, repo, now - chrono::Duration::minutes(5)).await;
        // Anchored in the future: inside any window, and the row an
        // unclamped `now - (-3600s)` cutoff would wrongly select.
        let not_yet =
            seed_quarantined_artifact(&pool, repo, now + chrono::Duration::minutes(30)).await;

        let out = PgQuarantineReleaseCandidatesRepository::new(pool)
            .select_expired(1000, now)
            .await
            .expect("select_expired Ok");

        let ids: Vec<Uuid> = out.iter().map(|c| c.artifact_id).collect();
        assert_eq!(
            ids,
            vec![elapsed],
            "a negative duration resolves to a cutoff of `now`, exactly as zero does",
        );
        assert!(
            !ids.contains(&not_yet),
            "the cutoff must never land after `now` — that would select an unelapsed window",
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

    // -----------------------------------------------------------------
    // Fair candidacy — across duration groups
    // -----------------------------------------------------------------

    /// **Cross-group starvation regression.** Two duration groups: the
    /// first holds a full batch of rows that never release, the second
    /// holds one that can. The releasable row is selected on the **first**
    /// tick, because the batch's single `LIMIT` is applied over both
    /// groups at once in cursor order.
    ///
    /// The assertion is the exact ordering rather than mere membership,
    /// and that is what makes it a regression test. The shape this
    /// replaced queried one duration group at a time against a shared
    /// budget, so it returned either the long group's three rows (budget
    /// spent, the other group never queried at all) or the short group's
    /// single row followed by two of the long group's — never the
    /// window-start-ordered interleaving below, under either visit order.
    /// And the visit order came from a `HashMap`, so which of those two a
    /// deployment got was re-drawn per process rather than progressing.
    ///
    /// "Never releases" is modelled by what the adapter can see, as in
    /// `select_expired_does_not_starve_a_newer_candidate_behind_a_full_unreleasable_batch`:
    /// the rows stay `quarantined` across ticks because no release ever
    /// happens, which is the signature of a candidate the authority
    /// (ADR 0007) or provenance (ADR 0027) gate permanently holds. Why
    /// such a row is held is `release_expired`'s business; this test is
    /// about the batch slot it occupies.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_reaches_a_second_duration_group_behind_a_full_batch() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        const BATCH: u32 = 3;

        // Group one: a 1 h window.
        let held_repo = seed_repo(&pool).await;
        seed_repo_scoped_policy(&pool, held_repo, 3600).await;
        // Group two: a 60 s window. A distinct duration, so the old shape
        // put it in a separate `HashMap` bucket.
        let releasable_repo = seed_repo(&pool).await;
        seed_repo_scoped_policy(&pool, releasable_repo, 60).await;

        let now = Utc::now();
        // A full batch in the long-window group, every row well past its
        // own 1 h deadline, none of which will ever release.
        let held_oldest =
            seed_quarantined_artifact(&pool, held_repo, now - chrono::Duration::hours(5)).await;
        let held_middle =
            seed_quarantined_artifact(&pool, held_repo, now - chrono::Duration::hours(4)).await;
        let held_newest =
            seed_quarantined_artifact(&pool, held_repo, now - chrono::Duration::hours(3)).await;
        // One row in the short-window group, waiting *between* the first
        // two: no ordering the per-group budget could produce matches the
        // global one, in either visit order.
        let releasable =
            seed_quarantined_artifact(&pool, releasable_repo, now - chrono::Duration::minutes(270))
                .await;

        let adapter = PgQuarantineReleaseCandidatesRepository::new(pool.clone());

        // Repeated calls agree: candidacy is a function of the rows, no
        // longer of a map order a process draws once at startup.
        for call in 0..4 {
            let out = adapter
                .select_expired(BATCH, now)
                .await
                .expect("select_expired Ok");
            assert_eq!(
                out.iter().map(|c| c.artifact_id).collect::<Vec<_>>(),
                vec![held_oldest, releasable, held_middle],
                "call {call}: one LIMIT over both duration groups in cursor order — a \
                 releasable artifact must not wait on a group whose rows never release",
            );
        }

        // Acceptance: the within-group rotation is unchanged. Stamp what
        // tick one considered and the long group's remaining row, still
        // never-attempted, leads tick two.
        adapter
            .mark_attempted(&[held_oldest, releasable, held_middle], now)
            .await
            .expect("mark_attempted Ok");
        let tick_two = adapter
            .select_expired(BATCH, now + chrono::Duration::seconds(1))
            .await
            .expect("select_expired Ok");
        assert_eq!(
            tick_two.first().map(|c| c.artifact_id),
            Some(held_newest),
            "the never-attempted remainder leads the next tick — the cursor still \
             rotates, now across the whole candidate set rather than inside a group",
        );
    }

    /// Every row is tested against **its own** repository's cutoff, not
    /// against some other group's.
    ///
    /// Three rows across two durations, chosen so a pairing that drifted —
    /// the repo array and the cutoff array falling out of step — flips the
    /// answer in both directions: the 2-minute-old row in the 60 s repo is
    /// a candidate and would not be under the 1 h cutoff, and the
    /// 30-minute-old row in the 1 h repo is not and would be under the
    /// 60 s one.
    ///
    /// This also pins the broadest-cutoff pre-filter as a widening and
    /// nothing more. That predicate admits everything at or before
    /// `now - 60s`, which includes the 30-minute-old row; the per-row join
    /// predicate is what rejects it.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_tests_each_row_against_its_own_repository_cutoff() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let short_repo = seed_repo(&pool).await;
        seed_repo_scoped_policy(&pool, short_repo, 60).await;
        let long_repo = seed_repo(&pool).await;
        seed_repo_scoped_policy(&pool, long_repo, 3600).await;

        let now = Utc::now();
        let short_expired =
            seed_quarantined_artifact(&pool, short_repo, now - chrono::Duration::minutes(2)).await;
        let long_expired =
            seed_quarantined_artifact(&pool, long_repo, now - chrono::Duration::hours(2)).await;
        let long_not_yet =
            seed_quarantined_artifact(&pool, long_repo, now - chrono::Duration::minutes(30)).await;

        let out = PgQuarantineReleaseCandidatesRepository::new(pool)
            .select_expired(1000, now)
            .await
            .expect("select_expired Ok");

        let ids: Vec<Uuid> = out.iter().map(|c| c.artifact_id).collect();
        assert_eq!(
            ids,
            vec![long_expired, short_expired],
            "each row's deadline is its own repository's; a cutoff borrowed from \
             another group either strands a candidate or selects an unelapsed window",
        );
        assert!(
            !ids.contains(&long_not_yet),
            "a row inside its own window must stay out, however broad another \
             group's cutoff is",
        );
    }

    /// **Counter-assertion — the single-group case is untouched.** With
    /// one duration there is nothing to be fair across, so the one-query
    /// form must return exactly what the per-duration form returned: the
    /// `batch_size` stalest rows in cursor order, with the remainder
    /// rotating in behind them on the next tick.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_single_duration_group_keeps_its_cursor_order_and_limit() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        const BATCH: u32 = 3;

        // No policy row at all: the default-duration tier, which is the
        // common deployment shape — every repo on one window.
        let repo = seed_repo(&pool).await;
        let now = Utc::now();
        let window = chrono::Duration::seconds(DefaultPolicy::quarantine_duration_secs());

        let mut seeded = Vec::new();
        for days_past_deadline in [4_i64, 3, 2, 1] {
            seeded.push(
                seed_quarantined_artifact(
                    &pool,
                    repo,
                    now - window - chrono::Duration::days(days_past_deadline),
                )
                .await,
            );
        }

        let adapter = PgQuarantineReleaseCandidatesRepository::new(pool.clone());
        let tick_one = adapter
            .select_expired(BATCH, now)
            .await
            .expect("select_expired Ok");
        assert_eq!(
            tick_one.iter().map(|c| c.artifact_id).collect::<Vec<_>>(),
            seeded[..3].to_vec(),
            "one group, one LIMIT: the three stalest rows, oldest window first",
        );

        adapter
            .mark_attempted(
                &tick_one
                    .iter()
                    .map(|c| c.artifact_id)
                    .collect::<Vec<Uuid>>(),
                now,
            )
            .await
            .expect("mark_attempted Ok");

        let tick_two = adapter
            .select_expired(BATCH, now + chrono::Duration::seconds(1))
            .await
            .expect("select_expired Ok");
        assert_eq!(
            tick_two.iter().map(|c| c.artifact_id).collect::<Vec<_>>(),
            vec![seeded[3], seeded[0], seeded[1]],
            "the never-attempted row leads, the stamped ones rotate behind it in \
             stamp order — unchanged by the single-query form",
        );
    }

    /// A hand-set `quarantine_duration_secs` the sweep cannot compute a
    /// deadline from costs that repository's candidates and nothing
    /// else: `select_expired` returns `Ok`, the defective repository's
    /// artifact is absent, and the healthy repository's artifact comes
    /// back exactly as it would have on its own.
    ///
    /// The value is written straight to `policy_projections` because
    /// that is the only way it can exist — apply refuses it
    /// (`hort_config::scan_policy::MAX_POLICY_DURATION_SECS`), and the
    /// rows this guard is for are the ones that did not come through
    /// apply. Before the guard this call panicked, and because the
    /// sweep is single and deployment-wide, that stopped every release
    /// in the installation rather than this one repository's.
    ///
    /// `#[serial(hort_pg_db)]` per CLAUDE.md's parallel-safety
    /// contract.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn select_expired_skips_repo_whose_stored_duration_has_no_deadline() {
        let Some(pool) = maybe_pool().await else {
            eprintln!("skipping: no DATABASE_URL");
            return;
        };

        let now = Utc::now();
        let elapsed = now
            - chrono::Duration::seconds(DefaultPolicy::quarantine_duration_secs())
            - chrono::Duration::seconds(1);

        // The defective repository: a window that elapsed long ago, and
        // a stored duration with no representable deadline.
        let broken_repo = seed_repo(&pool).await;
        seed_repo_scoped_policy(&pool, broken_repo, i64::MAX).await;
        let broken_artifact = seed_quarantined_artifact(&pool, broken_repo, elapsed).await;

        // The healthy repository beside it, on the default duration.
        let healthy_repo = seed_repo(&pool).await;
        let healthy_artifact = seed_quarantined_artifact(&pool, healthy_repo, elapsed).await;

        let out = PgQuarantineReleaseCandidatesRepository::new(pool)
            .select_expired(1000, now)
            .await
            .expect("an uncomputable stored duration must not fail the whole sweep");

        let ids: Vec<Uuid> = out.iter().map(|c| c.artifact_id).collect();
        assert_eq!(
            ids,
            vec![healthy_artifact],
            "the healthy repository's candidate must come back and the defective \
             repository's must not; got {ids:?}"
        );
        assert!(
            !ids.contains(&broken_artifact),
            "an artifact whose repository has no computable deadline cannot be a candidate — \
             the deadline test it would have to pass does not exist"
        );
    }

    // ===================================================================
    // `repo_cutoff` — the uncomputable-duration skip
    //
    // DB-free: the decision is pure arithmetic over `(secs, now)`, so
    // these run in every gate including one with no `DATABASE_URL`.
    // The end-to-end half — that a defective row costs its own
    // repository and nothing else — is
    // `select_expired_skips_repo_whose_stored_duration_has_no_deadline`
    // below.
    // ===================================================================

    /// Minimal capturing subscriber layer: records `(level, rendered
    /// fields)` per event. The skip's whole contract is that it is not
    /// silent, so the message and both fields are what the tests
    /// assert.
    #[derive(Clone, Default)]
    struct CapturedEvents {
        records: std::sync::Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturedEvents {
        fn register_callsite(
            &self,
            _meta: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn enabled(
            &self,
            _meta: &tracing::Metadata<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) -> bool {
            true
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct V(String);
            impl tracing::field::Visit for V {
                fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                    self.0.push_str(&format!("{}={v:?} ", f.name()));
                }
                fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
                    self.0.push_str(&format!("{}={v} ", f.name()));
                }
                fn record_i64(&mut self, f: &tracing::field::Field, v: i64) {
                    self.0.push_str(&format!("{}={v} ", f.name()));
                }
            }
            let mut v = V(String::new());
            event.record(&mut v);
            self.records
                .lock()
                .unwrap()
                .push((*event.metadata().level(), v.0));
        }
    }

    /// Run `repo_cutoff` under a thread-local capturing subscriber and
    /// return its verdict together with the records it emitted.
    ///
    /// A global no-op passthrough is installed once first: `tracing`
    /// caches per-callsite interest, and a callsite first reached with
    /// no subscriber at all caches as "never" for the rest of the test
    /// binary — which would make every assertion below vacuously pass
    /// depending on test order. `rebuild_interest_cache` then
    /// re-evaluates against the thread-local subscriber. Mirrors the
    /// capture block in `hort-app`'s
    /// `task_handlers/quarantine_release_sweep.rs`.
    fn capture_repo_cutoff(
        repo: Uuid,
        secs: i64,
        now: DateTime<Utc>,
    ) -> (Option<DateTime<Utc>>, Vec<(tracing::Level, String)>) {
        use std::sync::OnceLock;
        use tracing_subscriber::layer::SubscriberExt;

        /// Discards every event; its only job is to keep callsite
        /// interest out of the permanently-cached "never" state.
        struct Passthrough;
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Passthrough {
            fn register_callsite(
                &self,
                _meta: &'static tracing::Metadata<'static>,
            ) -> tracing::subscriber::Interest {
                tracing::subscriber::Interest::sometimes()
            }
        }
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::Registry::default().with(Passthrough),
            );
        });

        let layer = CapturedEvents::default();
        let records = layer.records.clone();
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let verdict = {
            let _guard = tracing::subscriber::set_default(subscriber);
            tracing::callsite::rebuild_interest_cache();
            repo_cutoff(repo, secs, now)
        };
        let out = records.lock().unwrap().clone();
        (verdict, out)
    }

    /// An ordinary duration resolves to `now - duration` and says
    /// nothing. The counter-assertion to every skip test below: if this
    /// one logged, the capture harness would be reporting noise rather
    /// than the skip.
    #[test]
    fn repo_cutoff_computes_an_ordinary_duration_silently() {
        let repo = Uuid::from_u128(0x0a);
        let now = Utc::now();
        let secs = DefaultPolicy::quarantine_duration_secs();

        let (verdict, records) = capture_repo_cutoff(repo, secs, now);

        assert_eq!(
            verdict,
            Some(now - chrono::Duration::seconds(secs)),
            "a computable duration must still produce exactly `now - duration`"
        );
        assert!(
            !records
                .iter()
                .any(|(level, _)| *level == tracing::Level::ERROR),
            "a computable duration must not log at error level; got {records:?}"
        );
    }

    /// A zero-length window — the permissive-mode policy — resolves to
    /// `now` and is not a skip. Pinned here because the skip branch
    /// sits on the same arithmetic, and collapsing the two would strand
    /// every artifact in a permissive repository.
    #[test]
    fn repo_cutoff_treats_a_zero_window_as_now() {
        let (verdict, records) = capture_repo_cutoff(Uuid::from_u128(0x0b), 0, Utc::now());
        assert!(verdict.is_some(), "a zero window is a window, not a skip");
        assert!(!records
            .iter()
            .any(|(level, _)| *level == tracing::Level::ERROR));
    }

    /// A stored duration past `TimeDelta`'s own limit is skipped, not
    /// panicked on, and the log names the repository and the value.
    #[test]
    fn repo_cutoff_skips_and_names_a_duration_past_the_timedelta_limit() {
        let repo = Uuid::from_u128(0x0c);
        let secs = i64::MAX;
        assert!(
            chrono::TimeDelta::try_seconds(secs).is_none(),
            "fixture precondition: this value must be the TimeDelta-limit case"
        );

        let (verdict, records) = capture_repo_cutoff(repo, secs, Utc::now());

        assert_eq!(verdict, None, "an unrepresentable duration must be skipped");
        let errors: Vec<_> = records
            .iter()
            .filter(|(level, _)| *level == tracing::Level::ERROR)
            .collect();
        assert_eq!(errors.len(), 1, "exactly one error record; got {records:?}");
        let rendered = &errors[0].1;
        assert!(
            rendered.contains(&repo.to_string()),
            "the log must name the repository id so the skip is attributable; got {rendered}"
        );
        assert!(
            rendered.contains(&secs.to_string()),
            "the log must name the value that cannot be computed with; got {rendered}"
        );
        assert!(
            rendered.contains("skipping"),
            "the log must say the repository was skipped — 'no releases here' must not read \
             as calm; got {rendered}"
        );
    }

    /// The second half of the guard, and the reason the verdict is
    /// `checked_sub_signed` rather than `try_seconds` alone: a duration
    /// `TimeDelta` holds perfectly well can still have no `DateTime`
    /// behind it, because the representable calendar range runs out
    /// roughly three orders of magnitude earlier. This value is inside
    /// the apply-time bound, so it is a duration an operator could set
    /// today and have accepted.
    #[test]
    fn repo_cutoff_skips_a_duration_with_no_representable_instant() {
        let repo = Uuid::from_u128(0x0d);
        // ~31.7 million years: a valid `TimeDelta`, and far outside the
        // `DateTime<Utc>` calendar range.
        let secs: i64 = 1_000_000_000_000_000;
        assert!(
            chrono::TimeDelta::try_seconds(secs).is_some(),
            "fixture precondition: this value must be a valid TimeDelta, so the test is \
             exercising the instant-range failure and not the TimeDelta one"
        );
        assert!(
            u64::try_from(secs).expect("non-negative")
                <= hort_config_max_policy_duration_secs_for_test(),
            "fixture precondition: this value is accepted by the apply-time bound, so the \
             skip is not redundant with it"
        );

        let (verdict, records) = capture_repo_cutoff(repo, secs, Utc::now());

        assert_eq!(verdict, None, "no instant ⇒ no cutoff ⇒ skip");
        let errors: Vec<_> = records
            .iter()
            .filter(|(level, _)| *level == tracing::Level::ERROR)
            .collect();
        assert_eq!(errors.len(), 1, "exactly one error record; got {records:?}");
        assert!(errors[0].1.contains(&repo.to_string()));
        assert!(errors[0].1.contains(&secs.to_string()));
    }

    /// `hort-config` is not a dependency of this crate (the adapter
    /// layer does not parse gitops YAML), so the apply-time bound is
    /// restated here for the one fixture precondition that needs it.
    /// `chrono::TimeDelta::MAX.num_seconds()` is the same derivation
    /// `hort_config::scan_policy::MAX_POLICY_DURATION_SECS` uses, so
    /// the two cannot disagree.
    fn hort_config_max_policy_duration_secs_for_test() -> u64 {
        chrono::TimeDelta::MAX.num_seconds() as u64
    }
}
