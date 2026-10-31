//! Outbound port the **retention** evaluator
//! uses to read the scan projections it needs to evaluate the
//! security-driven predicates (`HasFindingAboveSeverity` /
//! `HasFindingAboveCvss` / `HasFixAvailable` / `HasFindingDetectedFor`).
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
//!   projection. **No production caller today.** The freshness gate it
//!   was written for reads the artifact's own most-recent
//!   `ScanCompleted` off its event stream instead
//!   (`RetentionUseCase::scan_is_fresh`), because this row's
//!   `last_scan_at` is a per-repo `MAX`: a fresh scan on a *different*
//!   artifact in the same repository would otherwise rescue a stale one
//!   from the gate. The method stays because the per-repo aggregate is
//!   the natural read for a repository-level retention signal, but
//!   nothing is deciding on it — do not describe it as the gate's input.
//! - `list_findings_for_artifact` reads the per-finding `scan_findings`
//!   projection, scoped to the artifact's **last** scan. That projection
//!   is per-scan history — every run writes under a fresh `scan_id` and
//!   nothing removes the previous run's rows — and this port's consumer
//!   decides whether to delete the artifact, so the union of every scan
//!   ever run is the wrong evidence: a vulnerability a later scan no
//!   longer reports must drive no retention decision.
//! - `first_observed_at` reads the SAME projection **across** scans, on
//!   purpose, and is the one read here that does. Its question is how
//!   long we have known about a named vulnerability, which the last
//!   scan's rows cannot answer — they all carry that scan's
//!   `detected_at`. It is safe where a counting read would not be
//!   because the caller keys it on the vulnerability ids the last scan
//!   still reports: a retracted vulnerability is never asked about, so
//!   the history it has in the table cannot reach a retention decision.
//!
//! ## Projection precision
//!
//! `scan_findings` projects the source advisory's `fixed_versions`
//! (migration 029), so `HasFixAvailable` can match a finding with a
//! non-empty array. Rows written before that migration retain its empty
//! default until the artifact is rescanned, so they conservatively do
//! not match on fix availability. `references` and `aliases` remain only
//! in the per-finding CAS blob and read as empty through this port.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::Finding;

use super::repo_security_score_repository::RepoSecurityScore;
use super::BoxFuture;

/// Our own first observation of each named vulnerability, as
/// [`RetentionScanReader::first_observed_at`] answers it: lowercased
/// `vulnerability_id` → earliest `detected_at`. An id the artifact has
/// never carried is **absent**, never a sentinel date.
pub type FirstObservations = Vec<(String, DateTime<Utc>)>;

/// Read-only outbound port for the retention evaluator.
///
/// Three reads, all against shipped scan projections. The Postgres
/// adapter implements it against `scan_findings` + `repo_security_scores`;
/// unit tests use an in-memory mock.
pub trait RetentionScanReader: Send + Sync {
    /// The `scan_findings` rows the artifact's **last scan** recorded,
    /// mapped to the shipped [`Finding`] value type. Earlier scans' rows
    /// stay in the projection and are not returned — see the module docs
    /// for why that scoping is the port's contract and not an adapter
    /// detail.
    ///
    /// Returns an empty `Vec` for an artifact whose last scan found
    /// nothing (whatever earlier scans reported), and for one that has
    /// never been scanned — the caller tells those apart from its own
    /// read of the artifact's event stream, not from an empty findings
    /// list. `fixed_versions` and `advisory_published_at` are projected;
    /// `references` and
    /// `aliases` are empty on every returned row. See the module-level
    /// precision note.
    fn list_findings_for_artifact(
        &self,
        artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<Finding>>>;

    /// The per-repository `repo_security_scores` projection row, or
    /// `None` when the repository has no row yet (no scan has ever
    /// completed in it).
    ///
    /// The row's `last_scan_at` is a per-repo `MAX` and is **not** what
    /// the scan-freshness gate reads — see the module docs.
    fn repo_security_score(
        &self,
        repo_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Option<RepoSecurityScore>>>;

    /// Our own earliest observation of each named vulnerability on this
    /// artifact — `MIN(scan_findings.detected_at)` per
    /// (`artifact_id`, `vulnerability_id`), over **every** scan the
    /// artifact has had.
    ///
    /// This is rung 2 of the
    /// [`resolve_finding_age_anchor`](crate::retention::resolve_finding_age_anchor)
    /// ladder: the fallback when no backend published a date for the
    /// vulnerability. It is a bound on the publication date, never
    /// earlier than it, so falling back here can only make an artifact
    /// look *younger* and therefore less likely to expire.
    ///
    /// `vulnerability_ids` are the ids of the artifact's **last** scan's
    /// findings, lowercased. The keys in the returned pairs are the same
    /// lowercased ids — matching the case-insensitive vulnerability
    /// identity the cross-backend finding merge already uses, so one
    /// feed spelling `ghsa-…` and another `GHSA-…` are one vulnerability
    /// here too.
    ///
    /// Ids with no row are **absent** from the result rather than
    /// carrying a sentinel: "we have no record of ever seeing this"
    /// and "we first saw it at the epoch" are opposite answers, and the
    /// anchor resolver has to be able to tell them apart. An empty
    /// `vulnerability_ids` returns an empty result without a query.
    fn first_observed_at<'a>(
        &'a self,
        artifact_id: Uuid,
        vulnerability_ids: &'a [String],
    ) -> BoxFuture<'a, DomainResult<FirstObservations>>;
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
        fn first_observed_at<'a>(
            &'a self,
            _artifact_id: Uuid,
            _vulnerability_ids: &'a [String],
        ) -> BoxFuture<'a, DomainResult<FirstObservations>> {
            Box::pin(async { Ok(Vec::new()) })
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
        assert!(r
            .first_observed_at(Uuid::nil(), &["cve-1".to_string()])
            .await
            .unwrap()
            .is_empty());
    }

    /// `DomainError` round-trips through every return signature — the
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
            fn first_observed_at<'a>(
                &'a self,
                _artifact_id: Uuid,
                _vulnerability_ids: &'a [String],
            ) -> BoxFuture<'a, DomainResult<FirstObservations>> {
                Box::pin(async { Err(DomainError::Invariant("first-observed read failed".into())) })
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
        assert!(matches!(
            r.first_observed_at(Uuid::nil(), &["cve-1".to_string()])
                .await
                .unwrap_err(),
            DomainError::Invariant(_)
        ));
    }
}
