//! Outbound port for the cron-rescan eligibility query.
//!
//! `CronRescanTickHandler` (in `hort-app::task_handlers::cron_rescan_tick`)
//! delegates the SQL-side eligibility predicate — joining `artifacts`
//! to `policy_projections` via the repo→policy chain, filtering
//! `quarantine_status='released'` and `rescan_interval_hours > 0`,
//! comparing `last_scan_at` against the policy interval, and excluding
//! artifacts that already have an in-flight `kind='scan'` job — to this
//! port. Keeping the SQL inside the Postgres adapter and exposing the
//! result as a flat `Vec<RescanCandidate>` lets the handler stay a pure
//! orchestration step (port boundary + dispatch loop only).
//!
//! Eligibility reads the
//! per-artifact `artifacts.last_scan_at` denorm column,
//! NOT `repo_security_scores.last_scan_at` (which is per-repo). See
//! `docs/architecture/explanation/scanning-pipeline.md`.
//!
//! [`RescanCandidatesRepository::select_stranded`] is a companion
//! eligibility query (issue #6 / ADR 0007) for a *different* predicate:
//! `quarantine_status='quarantined'` artifacts whose scan could not even
//! **run** (every configured scanner backend failed) and exhausted
//! `HORT_SCANNER_MAX_ATTEMPTS` retries. That failure mode is
//! transient/infrastructure, not a genuinely-ambiguous scan result, so it
//! does NOT transition the artifact to the terminal `scan_indeterminate`
//! status (ADR 0007 unchanged) — the artifact simply stays `quarantined`
//! with a persisted "last scan errored" fact (`jobs.status='failed'` on
//! its most recent `kind='scan'` row). `select_stranded` finds exactly
//! those artifacts (with no in-flight scan job) so the sweep can give the
//! scan another chance once the scanner recovers. See
//! `docs/architecture/how-to/recover-stranded-artifacts.md`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// One eligible artifact returned by [`RescanCandidatesRepository::select_eligible`].
///
/// All fields are the inputs `JobsRepository::enqueue_scan` needs to
/// insert a fresh `kind='scan'` row plus the policy interval the
/// candidate was matched against (carried for observability — the
/// handler does not branch on `rescan_interval_hours`, but emitting it
/// in tracing fields makes per-policy debugging tractable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RescanCandidate {
    /// The artifact that is eligible for re-scan.
    pub artifact_id: Uuid,
    /// The artifact's parent repository — bound directly into the
    /// `jobs.repository_id` column so the worker dispatch loop need
    /// not re-resolve it.
    pub repository_id: Uuid,
    /// Content-addressable storage hash. Required by `enqueue_scan` so
    /// the resulting `jobs` row carries the same content reference the
    /// scan worker streams from `StoragePort::get`.
    pub content_hash: ContentHash,
    /// Lowercase format token (`"npm"`, `"pypi"`, `"oci"`, …) — sourced
    /// from `repositories.format` via the SQL join. Matches the
    /// `Repository.format` `Display` impl the worker dispatches on.
    pub format: String,
    /// The resolved policy's `rescan_interval_hours`. Carried for
    /// per-candidate tracing only; the eligibility query already filtered
    /// `> 0` and the past-interval predicate.
    ///
    /// **Sentinel `0` for [`RescanCandidatesRepository::select_stranded`]
    /// candidates**: the stranded-recovery predicate has no interval
    /// concept (it re-picks as soon as the last scan attempt errored, not
    /// after a policy-derived wait), so this field is not meaningful for
    /// those rows. Kept on the shared struct rather than forking a
    /// second candidate type — `enqueue_scan` (the only consumer) never
    /// reads this field either way.
    pub rescan_interval_hours: i32,
}

/// Outbound port for the rescan eligibility query.
///
/// The Postgres adapter implements this against the canonical SQL
/// (joining `artifacts` to `policy_projections` via the repo→policy
/// chain — repo-scoped policies shadow the global default; archived
/// rows are excluded). The handler crate (`hort-app`) calls this method
/// once per tick and iterates the returned `Vec` to enqueue scan jobs.
pub trait RescanCandidatesRepository: Send + Sync {
    /// Return up to `batch_size` artifacts whose policy-derived rescan
    /// interval has elapsed and that have no in-flight scan job.
    ///
    /// `now` is the wall-clock timestamp the handler captured at the
    /// start of the tick — passed in (rather than read inside the
    /// adapter via `now()`) so per-tick semantics stay coherent across
    /// retries and so tests can pin the comparison time.
    fn select_eligible<'a>(
        &'a self,
        batch_size: u32,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>>;

    /// Return up to `batch_size` **stranded** artifacts: `quarantine_status
    /// = 'quarantined'` with a most-recent `kind='scan'` job in
    /// `status='failed'` (a scanner-execution failure that exhausted
    /// retries — see the module doc) and no in-flight `kind='scan'` job.
    ///
    /// Distinct query from [`Self::select_eligible`] — different source
    /// status (`quarantined`, not `released`/`NULL`), no interval/`now`
    /// gating (a stranded artifact is eligible immediately, not after a
    /// policy-derived wait), and a different "was it scanned" signal (the
    /// most recent `jobs` row's status, not `artifacts.last_scan_at`).
    /// Kept as a companion method rather than folded into
    /// `select_eligible`'s SQL so that well-tested query's shape stays
    /// untouched.
    fn select_stranded<'a>(
        &'a self,
        batch_size: u32,
    ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time dyn-compatibility assertion. Mirrors the pattern in
    /// [`crate::ports::policy_projection_repository`].
    fn _assert_dyn_compatible(_: Box<dyn RescanCandidatesRepository>) {}

    /// Runtime size_of probe — only resolves if the trait is dyn-compatible.
    #[test]
    fn rescan_candidates_repository_is_dyn_compatible() {
        let _ = size_of::<&dyn RescanCandidatesRepository>();
    }

    /// `RescanCandidate` is `Clone + PartialEq` so handler tests can
    /// compare expected vs. observed candidate lists without bespoke
    /// per-field assertions.
    #[test]
    fn rescan_candidate_is_clone_and_partial_eq() {
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .expect("valid sha256 hex");
        let c = RescanCandidate {
            artifact_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            content_hash: hash,
            format: "npm".into(),
            rescan_interval_hours: 24,
        };
        let cloned = c.clone();
        assert_eq!(c, cloned);
    }

    /// A handler-style smoke test that drives both trait methods through
    /// a single `Box<dyn>` to prove dispatch + both `BoxFuture`
    /// signatures compile. One `Stub` exercising both methods (rather
    /// than a separate `Stub` per method, each only calling the one it's
    /// testing) so neither implementation body is dead weight from the
    /// other test's perspective.
    #[tokio::test]
    async fn select_eligible_and_select_stranded_dispatch_through_trait_object() {
        struct Stub;
        impl RescanCandidatesRepository for Stub {
            fn select_eligible<'a>(
                &'a self,
                _batch_size: u32,
                _now: DateTime<Utc>,
            ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn select_stranded<'a>(
                &'a self,
                _batch_size: u32,
            ) -> BoxFuture<'a, DomainResult<Vec<RescanCandidate>>> {
                Box::pin(async {
                    Ok(vec![RescanCandidate {
                        artifact_id: Uuid::nil(),
                        repository_id: Uuid::nil(),
                        content_hash:
                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                                .parse()
                                .expect("valid sha256 hex"),
                        format: "npm".into(),
                        rescan_interval_hours: 0,
                    }])
                })
            }
        }

        let port: Box<dyn RescanCandidatesRepository> = Box::new(Stub);

        let eligible = port.select_eligible(1000, Utc::now()).await.expect("Ok");
        assert!(eligible.is_empty());

        let stranded = port.select_stranded(1000).await.expect("Ok");
        assert_eq!(stranded.len(), 1);
        assert_eq!(stranded[0].rescan_interval_hours, 0);
    }
}
