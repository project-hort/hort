//! Outbound port for the per-finding scan-result projection.
//!
//! `scan_findings` is a projection table keyed on
//! `(artifact_id, scan_id, purl, vulnerability_id, source_scanner)`.
//! Rows are populated by `QuarantineUseCase::record_scan_result` in
//! the same Postgres transaction as the corresponding `ScanCompleted`
//! event append (invariant: no orphan projections).
//!
//! The port itself only carries the typed row shape and the
//! `insert_batch` operation. The actual cross-port atomicity is owned
//! by [`crate::ports::artifact_lifecycle::ArtifactLifecyclePort`]'s
//! `commit_scan_result` method, which threads a single SQL transaction
//! across the event-store append, this projection, and the artifact
//! state mutation.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::entities::scan_policy::SeverityThreshold;
use crate::error::DomainResult;

use super::BoxFuture;

/// One row in the `scan_findings` projection.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanFindingsRow {
    pub artifact_id: Uuid,
    pub scan_id: Uuid,
    pub purl: String,
    pub vulnerability_id: String,
    pub severity: SeverityThreshold,
    pub cvss_score: Option<f32>,
    pub source_scanner: String,
    pub title: String,
    pub detected_at: DateTime<Utc>,
    /// Mirrors [`crate::types::Finding::informational_class`] — the raw OSV
    /// `database_specific.informational` class verbatim (RustSec
    /// `unmaintained` / `unsound` / `notice`), or `None` for a scored
    /// vulnerability. Persisting the class (the fact) rather than a derived
    /// boolean keeps the negligible-lane routing stable under
    /// exclusion-triggered re-evaluation — including `negligible_action =
    /// block` — and lets a future per-class policy re-derive from stored
    /// findings. A Finding reconstructed from `scan_findings` reads the class
    /// back rather than defaulting to `None`.
    pub informational_class: Option<String>,
}

/// Outbound port for the `scan_findings` projection.
///
/// `insert_batch` is the only operation in v1 — the projection is
/// append-only, written inline with `ScanCompleted` event appends.
/// Reads of the projection (cron rescan, hort-cli reverse
/// vulnerability lookup) ride a separate read-model port, not this
/// one.
///
/// The default `insert_batch` returns `Ok(())` so test mocks that
/// don't exercise the projection write inherit a no-op without
/// having to fabricate an empty impl manually. Production adapters
/// override.
pub trait ScanFindingsRepository: Send + Sync {
    /// Insert a batch of scan findings.
    ///
    /// The caller (`commit_scan_result` in the lifecycle adapter) is
    /// responsible for supplying a transaction context — this method
    /// is invoked *inside* an open SQL transaction so the rows land
    /// atomically with the event append.
    ///
    /// Idempotency: the table's primary key is
    /// `(artifact_id, scan_id, purl, vulnerability_id,
    /// source_scanner)`. A duplicate row for the same scan id is a
    /// programming error — not an operator-recoverable condition.
    /// Implementations surface duplicates as
    /// `DomainError::Conflict`.
    fn insert_batch<'a>(&'a self, rows: &'a [ScanFindingsRow]) -> BoxFuture<'a, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DomainError;

    /// Compile-time assertion that the port is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn ScanFindingsRepository>();
    }

    #[test]
    fn scan_findings_row_clone_eq_debug() {
        let r = ScanFindingsRow {
            artifact_id: Uuid::nil(),
            scan_id: Uuid::nil(),
            purl: "pkg:npm/foo@1".into(),
            vulnerability_id: "CVE-1".into(),
            severity: SeverityThreshold::High,
            cvss_score: Some(7.0),
            source_scanner: "trivy".into(),
            title: "t".into(),
            detected_at: DateTime::<Utc>::from_timestamp(0, 0).expect("ts"),
            informational_class: None,
        };
        let cloned = r.clone();
        assert_eq!(r, cloned);
        // Debug format must be non-empty.
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ScanFindingsRow"));
    }

    /// A no-op implementation to exercise the `dyn`-cast and to
    /// stand in for adapter implementations in cross-crate tests.
    struct NoopFindingsRepo;
    impl ScanFindingsRepository for NoopFindingsRepo {
        fn insert_batch<'a>(
            &'a self,
            _rows: &'a [ScanFindingsRow],
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn noop_insert_batch_returns_ok() {
        let repo = NoopFindingsRepo;
        repo.insert_batch(&[]).await.unwrap();
    }

    #[tokio::test]
    async fn noop_insert_batch_with_one_row_returns_ok() {
        let repo = NoopFindingsRepo;
        let row = ScanFindingsRow {
            artifact_id: Uuid::nil(),
            scan_id: Uuid::nil(),
            purl: "pkg:npm/foo@1".into(),
            vulnerability_id: "CVE-1".into(),
            severity: SeverityThreshold::Critical,
            cvss_score: None,
            source_scanner: "trivy".into(),
            title: "t".into(),
            detected_at: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
            informational_class: None,
        };
        repo.insert_batch(std::slice::from_ref(&row)).await.unwrap();
    }

    /// Confirm that `DomainError::Conflict` (duplicate-row case
    /// surfaced by adapters) round-trips through the trait's return
    /// type.
    #[tokio::test]
    async fn err_conflict_round_trips_through_port_signature() {
        struct ConflictRepo;
        impl ScanFindingsRepository for ConflictRepo {
            fn insert_batch<'a>(
                &'a self,
                _rows: &'a [ScanFindingsRow],
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Conflict("dup".into())) })
            }
        }
        let r = ConflictRepo;
        let err = r.insert_batch(&[]).await.unwrap_err();
        assert!(matches!(err, DomainError::Conflict(_)));
    }
}
