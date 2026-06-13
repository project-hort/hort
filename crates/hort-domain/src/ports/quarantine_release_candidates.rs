//! Outbound port for the quarantine release-sweep candidacy query
//! (ADR 0007).
//!
//! `QuarantineReleaseSweepHandler` (in
//! `hort-app::task_handlers::quarantine_release_sweep`) delegates the
//! SQL-side candidacy predicate — computing the effective per-repo
//! `ScanPolicy.quarantineDuration` (repo-scoped → global → default),
//! grouping repos by their handful of distinct durations, and issuing
//! one indexed range scan per distinct duration `D`
//! (`quarantine_status='quarantined' AND repository_id = ANY($repos_for_D)
//! AND quarantine_window_start <= now() - D AND is_deleted = false`)
//! — to this port. Keeping the SQL inside the Postgres adapter and
//! exposing the result as a flat `Vec<QuarantineReleaseCandidate>`
//! lets the handler stay a pure orchestration step (port boundary +
//! dispatch loop only). The partial index
//! `idx_artifacts_quarantine_window_start ON (quarantine_window_start)
//! WHERE quarantine_status='quarantined'` supports
//! the range scan.
//!
//! **Authority discipline.** The candidacy query
//! filters by the *computed* window deadline only. It is **never**
//! evidence of release authority — `QuarantineUseCase::release_expired`
//! enforces the F-6 fail-closed predicate (`ScanSucceeded` /
//! `ScanWaived`) per artifact and skips candidates that lack one. A
//! window-expired candidate with no clean scan stays quarantined; the
//! sweep loop continues. See `release_expired` (~L979 of
//! `crates/hort-app/src/use_cases/quarantine_use_case.rs`) for the
//! per-artifact authority resolution.

use uuid::Uuid;

use crate::error::DomainResult;

use super::BoxFuture;

/// One quarantined artifact whose computed window deadline has elapsed.
///
/// The release sweep operates per `Uuid`; the full artifact is loaded
/// by `release_expired` via [`crate::ports::artifact_repository::ArtifactRepository::find_by_id`].
/// Keeping the candidate row minimal — just the id — avoids duplicating
/// fields the use case re-reads anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineReleaseCandidate {
    /// The artifact whose quarantine observation window has elapsed
    /// (`quarantine_window_start + effective_duration <= now()`). The
    /// release authority is re-resolved per artifact in
    /// `release_expired`; this row is purely candidacy.
    pub artifact_id: Uuid,
}

/// Outbound port for the §2.4 candidacy query.
///
/// The Postgres adapter implements this by:
///
/// 1. Reading every active `policy_projections` row to compute the
///    `repo → effective duration` map (repo-scoped policies shadow the
///    global default, mirroring `QuarantineUseCase::record_scan_result`'s
///    precedence; the third tier is
///    `DefaultPolicy::quarantine_duration_secs` — a repo with no
///    matched policy contributes no candidates).
/// 2. Grouping repos by their distinct duration values (there are at
///    most a handful — number of policies, not number of artifacts).
/// 3. Issuing one indexed range scan per distinct duration `D`
///    (`quarantine_window_start <= $now - D` AND
///    `repository_id = ANY($repos_for_D)` AND
///    `quarantine_status = 'quarantined'` AND `is_deleted = false`).
/// 4. Union-ing the per-duration result sets and applying the
///    global `LIMIT $batch_size` (the handler pins this — design
///    §2.4 / Item 1b acceptance — to bound per-tick load).
pub trait QuarantineReleaseCandidatesRepository: Send + Sync {
    /// Return up to `batch_size` quarantined artifacts whose computed
    /// per-repo deadline `quarantine_window_start + effective_duration`
    /// is `<= now`.
    ///
    /// `now` is the wall-clock the handler captured at the start of the
    /// tick — passed in (rather than read inside the adapter) so per-
    /// tick semantics stay coherent across retries and so tests can pin
    /// the comparison time. Mirrors
    /// [`crate::ports::rescan_candidates::RescanCandidatesRepository::select_eligible`]
    /// exactly.
    fn select_expired<'a>(
        &'a self,
        batch_size: u32,
        now: chrono::DateTime<chrono::Utc>,
    ) -> BoxFuture<'a, DomainResult<Vec<QuarantineReleaseCandidate>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;

    /// Compile-time dyn-compatibility assertion. Mirrors the pattern in
    /// [`crate::ports::rescan_candidates`].
    fn _assert_dyn_compatible(_: Box<dyn QuarantineReleaseCandidatesRepository>) {}

    /// Runtime size_of probe — only resolves if the trait is dyn-compatible.
    #[test]
    fn quarantine_release_candidates_repository_is_dyn_compatible() {
        let _ = size_of::<&dyn QuarantineReleaseCandidatesRepository>();
    }

    /// `QuarantineReleaseCandidate` is `Clone + PartialEq` so handler
    /// tests can compare expected vs. observed candidate lists without
    /// bespoke per-field assertions.
    #[test]
    fn quarantine_release_candidate_is_clone_and_partial_eq() {
        let c = QuarantineReleaseCandidate {
            artifact_id: Uuid::nil(),
        };
        let cloned = c.clone();
        assert_eq!(c, cloned);
    }

    /// A handler-style smoke test that drives the trait through a
    /// `Box<dyn>` to prove dispatch + the `BoxFuture` signature compile.
    #[tokio::test]
    async fn select_expired_dispatches_through_trait_object() {
        use chrono::DateTime;
        struct Stub;
        impl QuarantineReleaseCandidatesRepository for Stub {
            fn select_expired<'a>(
                &'a self,
                _batch_size: u32,
                _now: DateTime<Utc>,
            ) -> BoxFuture<'a, DomainResult<Vec<QuarantineReleaseCandidate>>> {
                Box::pin(async { Ok(Vec::new()) })
            }
        }

        let port: Box<dyn QuarantineReleaseCandidatesRepository> = Box::new(Stub);
        let out = port.select_expired(1000, Utc::now()).await.expect("Ok");
        assert!(out.is_empty());
    }
}
