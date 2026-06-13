//! Outbound port for the per-artifact SBOM-component projection.
//!
//! `sbom_components` is a `(artifact_id, purl)`-keyed
//! reverse index populated alongside `scan_findings` in
//! `QuarantineUseCase::record_scan_result`. The
//! advisory-watch tick joins it on `(ecosystem, name)` to
//! find every artifact affected by a fresh OSV diff entry; the cron
//! rescan reads `last_scan_at` directly off `artifacts` and
//! does not touch this projection.
//!
//! ## Atomicity
//!
//! The write surface (`replace_for_artifact`) is exposed here for
//! standalone admin / migration tooling, but the production-path
//! cross-port atomicity (events + scan_findings + sbom_components +
//! artifact state in one Postgres transaction) is owned by
//! [`crate::ports::artifact_lifecycle::ArtifactLifecyclePort::commit_scan_result_with_score`],
//! which threads the components slice through to the same lifecycle
//! adapter that already writes `scan_findings`. This mirrors
//! `ScanFindingsRepository::insert_batch`: callers that exercise the
//! trait outside that lifecycle path get a self-contained transaction
//! here; the production hot path doesn't go through this method.
//!
//! ## REPLACE semantics
//!
//! `replace_for_artifact` is a DELETE-then-INSERT, not an UPSERT. A
//! component dropped from the latest SBOM must disappear from the
//! projection so the advisory-watch query never sees stale members
//! that the artifact no longer carries.
//!
//! ## Empty version-list shortcut
//!
//! `list_artifacts_by_match` MUST short-circuit return an empty Vec
//! when `versions.is_empty()`. An OSV entry that resolves to no
//! affected versions is a producer bug, and a SQL `WHERE version =
//! ANY('{}')` would already return zero rows in Postgres — but the
//! explicit shortcut documents the invariant at the port boundary
//! and saves a round-trip.

use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::sbom::{Ecosystem, SbomComponent};

use super::BoxFuture;

/// Outbound port for the `sbom_components` projection.
pub trait SbomComponentRepository: Send + Sync {
    /// Replace the entire row set for `artifact_id` with `components`.
    ///
    /// DELETE every existing `(artifact_id, purl)` row, then INSERT
    /// the supplied components — both inside a single transaction.
    /// Empty `components` is a valid input (the artifact had a
    /// manifest with no listed dependencies); existing rows are
    /// removed and no rows are inserted.
    ///
    /// **Production note:** the scan-result hot path does NOT call
    /// this method directly — it threads the components through
    /// `ArtifactLifecyclePort::commit_scan_result_with_score` so the
    /// SBOM-replace lands inside the same Postgres tx as the event
    /// append + per-finding rows + artifact mutation. This method is
    /// the standalone-tooling surface (admin one-shot, rebuild
    /// scripts, tests).
    fn replace_for_artifact<'a>(
        &'a self,
        artifact_id: Uuid,
        components: &'a [SbomComponent],
    ) -> BoxFuture<'a, DomainResult<()>>;

    /// Return DISTINCT `artifact_id`s whose SBOM contains a component
    /// matching `(ecosystem, name, version ∈ versions)`.
    ///
    /// Drives the advisory-watch tick — for
    /// each fresh OSV diff entry, identify the artifacts in the
    /// registry that need a re-scan.
    ///
    /// **Empty `versions` is a no-op:** implementations MUST return
    /// `Ok(vec![])` without issuing SQL. An empty version list is
    /// either a producer bug or an OSV entry that resolved to no
    /// affected versions; either way the query is unsafe (`WHERE
    /// version = ANY('{}')` is a write of intent we want to avoid)
    /// and the explicit short-circuit prevents stray cluster load.
    fn list_artifacts_by_match<'a>(
        &'a self,
        ecosystem: &'a Ecosystem,
        name: &'a str,
        versions: &'a [String],
    ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DomainError;

    /// Compile-time assertion that the port is dyn-compatible. Mirrors
    /// the same probe in `ScanFindingsRepository`.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn SbomComponentRepository>();
    }

    /// Minimal no-op impl used to exercise the trait-object cast and
    /// stand in for adapter implementations in cross-crate tests.
    struct NoopSbomRepo;
    impl SbomComponentRepository for NoopSbomRepo {
        fn replace_for_artifact<'a>(
            &'a self,
            _artifact_id: Uuid,
            _components: &'a [SbomComponent],
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn list_artifacts_by_match<'a>(
            &'a self,
            _ecosystem: &'a Ecosystem,
            _name: &'a str,
            _versions: &'a [String],
        ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn noop_replace_for_artifact_returns_ok() {
        let repo = NoopSbomRepo;
        repo.replace_for_artifact(Uuid::nil(), &[]).await.unwrap();
    }

    #[tokio::test]
    async fn noop_replace_for_artifact_with_one_component_returns_ok() {
        let repo = NoopSbomRepo;
        let components = vec![SbomComponent {
            purl: "pkg:npm/foo@1".into(),
            name: "foo".into(),
            version: Some("1".into()),
            ecosystem: Ecosystem::Npm,
            licenses: vec![],
            direct_dependency: true,
        }];
        repo.replace_for_artifact(Uuid::nil(), &components)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn noop_list_artifacts_by_match_empty_versions_returns_empty() {
        let repo = NoopSbomRepo;
        let got = repo
            .list_artifacts_by_match(&Ecosystem::Npm, "foo", &[])
            .await
            .unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn noop_list_artifacts_by_match_with_versions_runs() {
        let repo = NoopSbomRepo;
        let versions = vec!["1.0".into(), "2.0".into()];
        let got = repo
            .list_artifacts_by_match(&Ecosystem::Npm, "foo", &versions)
            .await
            .unwrap();
        assert!(got.is_empty());
    }

    /// `DomainError::Invariant` round-trips through the trait return
    /// type. Mirrors the ScanFindingsRepository conflict
    /// round-trip test.
    #[tokio::test]
    async fn err_round_trips_through_port_signature() {
        struct FailingRepo;
        impl SbomComponentRepository for FailingRepo {
            fn replace_for_artifact<'a>(
                &'a self,
                _artifact_id: Uuid,
                _components: &'a [SbomComponent],
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }

            fn list_artifacts_by_match<'a>(
                &'a self,
                _ecosystem: &'a Ecosystem,
                _name: &'a str,
                _versions: &'a [String],
            ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>> {
                Box::pin(async { Err(DomainError::Invariant("boom".into())) })
            }
        }
        let r = FailingRepo;
        let err = r.replace_for_artifact(Uuid::nil(), &[]).await.unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        let err = r
            .list_artifacts_by_match(&Ecosystem::Npm, "n", &["1".into()])
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
    }
}
