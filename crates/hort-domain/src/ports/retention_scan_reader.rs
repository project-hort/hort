//! Outbound port the **retention** evaluator
//! uses to read the scan projections it needs to evaluate the
//! security-driven predicates (`HasFindingAboveSeverity` /
//! `HasFindingAboveCvss` / `HasFixAvailable` / `HasFindingDetectedFor`)
//! and to enforce the scan-freshness gate.
//!
//! # Why a *new, separate* trait (not extra methods on
//! [`ScanFindingsRepository`](super::scan_findings_repository::ScanFindingsRepository))
//!
//! A trait named `ScanFindingsRepository` already ships
//! (`insert_batch` only). Adding read methods to *that* trait
//! would mutate an existing port signature surface (every existing
//! impl + every mock would have to grow the methods), and
//! changing an existing well-designed port signature is forbidden. So the
//! retention read surface is a **distinct, purely-additive** trait —
//! zero existing impls are touched. It reuses the shipped row types so
//! nothing is redefined.
//!
//! # Source of the rows
//!
//! - `repo_security_score` reads the per-repo `repo_security_scores`
//!   projection. `last_scan_at` on that row is the
//!   per-repo "most recent `ScanCompleted`" the freshness gate compares
//!   against (`2 × resolved_rescan_interval`).
//! - `list_findings_for_artifact` reads the per-finding `scan_findings`
//!   projection.
//!
//! ## Projection precision
//!
//! `scan_findings` projects the source advisory's `fixed_versions`
//! (migration 029), so `HasFixAvailable` can match a finding with a
//! non-empty array. Rows written before that migration retain its empty
//! default until the artifact is rescanned, so they conservatively do
//! not match on fix availability. `references` and `aliases` remain only
//! in the per-finding CAS blob and read as empty through this port.

use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::Finding;

use super::repo_security_score_repository::RepoSecurityScore;
use super::BoxFuture;

/// Read-only outbound port for the retention evaluator.
///
/// Two reads, both against shipped scan projections. Purely
/// additive — introduces no change to any existing port. The Postgres
/// adapter implements it against `scan_findings` + `repo_security_scores`;
/// unit tests use an in-memory mock.
pub trait RetentionScanReader: Send + Sync {
    /// Every current `scan_findings` row for `artifact_id`, mapped to
    /// the shipped [`Finding`] value type.
    ///
    /// Returns an empty `Vec` for an artifact with no findings (a clean
    /// scan, or one that has never been scanned — the caller
    /// distinguishes "never scanned" via [`Self::repo_security_score`]'s
    /// `last_scan_at`, not via an empty findings list). `fixed_versions`
    /// is projected; `references` and `aliases` are empty on every
    /// returned row. See the module-level precision note.
    fn list_findings_for_artifact(
        &self,
        artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<Finding>>>;

    /// The per-repository `repo_security_scores` projection row, or
    /// `None` when the repository has no row yet (no scan has ever
    /// completed in it). The freshness gate keys off the row's `last_scan_at`.
    fn repo_security_score(
        &self,
        repo_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Option<RepoSecurityScore>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time dyn-compatibility assertion (mirrors the pattern in
    /// [`crate::ports::scan_findings_repository`]).
    #[test]
    fn retention_scan_reader_is_dyn_compatible() {
        let _ = size_of::<&dyn RetentionScanReader>();
    }

    /// A no-op impl proves the trait can be `dyn`-cast and stands in
    /// for adapter impls in cross-crate tests.
    struct EmptyReader;
    impl RetentionScanReader for EmptyReader {
        fn list_findings_for_artifact(
            &self,
            _artifact_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<Vec<Finding>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn repo_security_score(
            &self,
            _repo_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<Option<RepoSecurityScore>>> {
            Box::pin(async { Ok(None) })
        }
    }

    #[tokio::test]
    async fn empty_reader_returns_empty_findings_and_no_score() {
        let r = EmptyReader;
        assert!(r
            .list_findings_for_artifact(Uuid::nil())
            .await
            .unwrap()
            .is_empty());
        assert!(r.repo_security_score(Uuid::nil()).await.unwrap().is_none());
    }

    /// `DomainError` round-trips through both return signatures — the
    /// adapter surfaces SQL failures this way and the use case maps
    /// them to `AppError::Domain`.
    #[tokio::test]
    async fn errors_round_trip_through_port_signatures() {
        use crate::error::DomainError;
        struct ErrReader;
        impl RetentionScanReader for ErrReader {
            fn list_findings_for_artifact(
                &self,
                _artifact_id: Uuid,
            ) -> BoxFuture<'_, DomainResult<Vec<Finding>>> {
                Box::pin(async { Err(DomainError::Invariant("findings read failed".into())) })
            }
            fn repo_security_score(
                &self,
                _repo_id: Uuid,
            ) -> BoxFuture<'_, DomainResult<Option<RepoSecurityScore>>> {
                Box::pin(async { Err(DomainError::Invariant("score read failed".into())) })
            }
        }
        let r = ErrReader;
        assert!(matches!(
            r.list_findings_for_artifact(Uuid::nil()).await.unwrap_err(),
            DomainError::Invariant(_)
        ));
        assert!(matches!(
            r.repo_security_score(Uuid::nil()).await.unwrap_err(),
            DomainError::Invariant(_)
        ));
    }
}
