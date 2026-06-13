//! Outbound port the **refcount-reconcile** sweep
//! (`RefcountReconcileUseCase::sweep_drift`) uses to bring
//! the `content_references` refcount projection back into agreement
//! with the authoritative `artifacts` + `artifact_metadata` tables.
//!
//! # Why this exists
//!
//! The `content_references` projection is
//! *eventually authoritative*: the `primary_content` /
//! `metadata_blob` writes on the ingest paths (and the
//! `delete_by_source` sweep on the reject paths) run **post-commit and
//! warn-on-fail** (the deliberate "Authority posture
//! (eventual)"). A transient PG outage between the event append and
//! the projection write/delete leaves drift:
//!
//! - a missing `primary_content` row for an ingested artifact;
//! - a mis-targeted `primary_content` row (target hash no longer
//!   matches `artifacts.checksum_sha256`);
//! - a missing `metadata_blob` row for an artifact whose
//!   `artifact_metadata.metadata_blob` is non-null;
//! - a stale row whose source artifact is `quarantine_status =
//!   'rejected'` (the `ArtifactRejected` cascading delete is itself a
//!   warn-on-fail A1 variant).
//!
//! This sweep is the **named reconcile mechanism** that posture
//! depends on, and
//! the precondition `PurgeUseCase` refuses to start without.
//! It MUST converge to a no-op on a clean projection (idempotent +
//! re-runnable).
//!
//! # Why a *new, separate* additive port (not extra methods on
//! [`ContentReferenceIndex`](super::content_reference_index::ContentReferenceIndex))
//!
//! Identical reasoning to the B3
//! [`RetentionScanReader`](super::retention_scan_reader::RetentionScanReader)
//! split. The B3.5 scope contract forbids changing any existing
//! port/trait signature; `ContentReferenceIndex` already ships with
//! `insert` / `find_by_target` / `delete_by_source` plus several
//! impls and mocks. Adding the scan/repair surface to *that* trait
//! would mutate an existing port signature. So the reconcile surface
//! is a **distinct, purely-additive** trait — zero existing impls
//! touched. It reuses the shipped
//! [`ContentHash`](crate::types::ContentHash) type so nothing is
//! redefined.
//!
//! # Why the port returns drift *cases* (data), not a "reconcile" verb
//!
//! Keeping the scan and the repair as separate port operations that
//! exchange typed drift-case data lets the `hort-app`
//! `RefcountReconcileUseCase` stay pure orchestration (100%
//! mock-testable per the `hort-app` coverage tier — log `info!` per
//! repo, `warn!` per drift case, return a summary) while the SQL
//! (set-based scan, idempotent upsert/delete) stays in the Postgres
//! adapter (≥85% integration-tested). The use case never embeds SQL;
//! the adapter never embeds tracing/summary policy.

use uuid::Uuid;

use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// One drift case the reconcile sweep must repair, scoped to a single
/// `(repository_id, source_artifact_id, kind)` projection slot.
///
/// The variants map 1:1 to the B3.5 acceptance bullets. Each carries
/// exactly the data the `warn!` line needs — `(artifact_id, kind,
/// action)` — and the data the adapter needs to apply the idempotent
/// repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefcountRepair {
    /// No `(repo, artifact, "primary_content")` row exists for an
    /// artifact that has one — create it pointing at
    /// `artifacts.checksum_sha256`.
    CreatePrimaryContent {
        source_artifact_id: Uuid,
        expected_hash: ContentHash,
    },
    /// A `(repo, artifact, "primary_content")` row exists but its
    /// `target_content_hash` no longer matches
    /// `artifacts.checksum_sha256` — repair it in place.
    RepairPrimaryContent {
        source_artifact_id: Uuid,
        found_hash: ContentHash,
        expected_hash: ContentHash,
    },
    /// No `(repo, artifact, "metadata_blob")` row exists for an
    /// artifact whose `artifact_metadata.metadata_blob` is non-null —
    /// create it (or repair a mis-targeted one) pointing at that hash.
    /// A single variant covers both create and mis-target repair
    /// because the idempotent upsert is identical either way; the
    /// `found_hash` (when present) is carried only for the `warn!`
    /// audit line.
    UpsertMetadataBlob {
        source_artifact_id: Uuid,
        found_hash: Option<ContentHash>,
        expected_hash: ContentHash,
    },
    /// A `content_references` row exists whose source artifact is
    /// `quarantine_status = 'rejected'` — delete every row for that
    /// source (the warn-on-fail `ArtifactRejected` cascade did not
    /// land). `kind` is the kind observed on the row that flagged the
    /// drift, for the `warn!` line; the repair sweeps all kinds for
    /// the source.
    DeleteRejectedSourceRows {
        source_artifact_id: Uuid,
        kind: String,
    },
}

impl RefcountRepair {
    /// The source artifact id this drift case is scoped to. Used by
    /// the use case's `warn!` line and to dedupe repeated
    /// rejected-source rows within one repo's drift set.
    pub fn source_artifact_id(&self) -> Uuid {
        match self {
            RefcountRepair::CreatePrimaryContent {
                source_artifact_id, ..
            }
            | RefcountRepair::RepairPrimaryContent {
                source_artifact_id, ..
            }
            | RefcountRepair::UpsertMetadataBlob {
                source_artifact_id, ..
            }
            | RefcountRepair::DeleteRejectedSourceRows {
                source_artifact_id, ..
            } => *source_artifact_id,
        }
    }

    /// Stable `kind` label for the `warn!` `(artifact_id, kind,
    /// action)` triple. `DeleteRejectedSourceRows` reports the
    /// observed kind that flagged the drift.
    pub fn kind_label(&self) -> &str {
        match self {
            RefcountRepair::CreatePrimaryContent { .. }
            | RefcountRepair::RepairPrimaryContent { .. } => "primary_content",
            RefcountRepair::UpsertMetadataBlob { .. } => "metadata_blob",
            RefcountRepair::DeleteRejectedSourceRows { kind, .. } => kind,
        }
    }

    /// Stable `action` label for the `warn!` triple.
    pub fn action_label(&self) -> &'static str {
        match self {
            RefcountRepair::CreatePrimaryContent { .. } => "create_primary_content",
            RefcountRepair::RepairPrimaryContent { .. } => "repair_primary_content",
            RefcountRepair::UpsertMetadataBlob { .. } => "upsert_metadata_blob",
            RefcountRepair::DeleteRejectedSourceRows { .. } => "delete_rejected_source_rows",
        }
    }
}

/// The complete drift set for one repository — the output of one
/// [`RefcountReconcilePort::scan_repo_drift`] call. An empty `repairs`
/// vec means the projection is converged for that repo (the sweep is a
/// no-op for it).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepoDrift {
    pub repairs: Vec<RefcountRepair>,
}

/// Read+repair outbound port for the refcount-reconcile
/// sweep. Purely additive — introduces no change to any existing
/// port. The Postgres adapter implements the scan as set-based SQL
/// against `artifacts` / `artifact_metadata` / `content_references`;
/// unit tests use an in-memory mock.
pub trait RefcountReconcilePort: Send + Sync {
    /// Every repository id that has at least one artifact row. The
    /// sweep iterates these so it can log `info!` per (repo,
    /// mode-summary) and bound each scan to a single repo's working
    /// set.
    fn list_repository_ids(&self) -> BoxFuture<'_, DomainResult<Vec<Uuid>>>;

    /// Compute the full drift set for one repository: missing /
    /// mis-targeted `primary_content`, missing / mis-targeted
    /// `metadata_blob`, and stale rows whose source artifact is
    /// `rejected`. A converged projection returns an empty
    /// [`RepoDrift`].
    fn scan_repo_drift(&self, repo_id: Uuid) -> BoxFuture<'_, DomainResult<RepoDrift>>;

    /// Apply one drift-case repair idempotently. Create/repair is an
    /// upsert on the projection PK; the rejected-source delete sweeps
    /// every kind for the source. Re-applying an already-applied
    /// repair is a no-op (the sweep is re-runnable).
    fn apply_repair<'a>(
        &'a self,
        repo_id: Uuid,
        repair: &'a RefcountRepair,
    ) -> BoxFuture<'a, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const HASH_B: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    fn hash(s: &str) -> ContentHash {
        s.parse().unwrap()
    }

    /// Compile-time dyn-compatibility assertion (mirrors the pattern in
    /// [`crate::ports::retention_scan_reader`]).
    #[test]
    fn refcount_reconcile_port_is_dyn_compatible() {
        let _ = size_of::<&dyn RefcountReconcilePort>();
    }

    #[test]
    fn source_artifact_id_extracts_for_every_variant() {
        let a = Uuid::new_v4();
        assert_eq!(
            RefcountRepair::CreatePrimaryContent {
                source_artifact_id: a,
                expected_hash: hash(HASH_A),
            }
            .source_artifact_id(),
            a
        );
        assert_eq!(
            RefcountRepair::RepairPrimaryContent {
                source_artifact_id: a,
                found_hash: hash(HASH_B),
                expected_hash: hash(HASH_A),
            }
            .source_artifact_id(),
            a
        );
        assert_eq!(
            RefcountRepair::UpsertMetadataBlob {
                source_artifact_id: a,
                found_hash: None,
                expected_hash: hash(HASH_A),
            }
            .source_artifact_id(),
            a
        );
        assert_eq!(
            RefcountRepair::DeleteRejectedSourceRows {
                source_artifact_id: a,
                kind: "primary_content".into(),
            }
            .source_artifact_id(),
            a
        );
    }

    #[test]
    fn kind_and_action_labels_are_stable() {
        let a = Uuid::new_v4();
        let create = RefcountRepair::CreatePrimaryContent {
            source_artifact_id: a,
            expected_hash: hash(HASH_A),
        };
        assert_eq!(create.kind_label(), "primary_content");
        assert_eq!(create.action_label(), "create_primary_content");

        let repair = RefcountRepair::RepairPrimaryContent {
            source_artifact_id: a,
            found_hash: hash(HASH_B),
            expected_hash: hash(HASH_A),
        };
        assert_eq!(repair.kind_label(), "primary_content");
        assert_eq!(repair.action_label(), "repair_primary_content");

        let meta = RefcountRepair::UpsertMetadataBlob {
            source_artifact_id: a,
            found_hash: Some(hash(HASH_B)),
            expected_hash: hash(HASH_A),
        };
        assert_eq!(meta.kind_label(), "metadata_blob");
        assert_eq!(meta.action_label(), "upsert_metadata_blob");

        let del = RefcountRepair::DeleteRejectedSourceRows {
            source_artifact_id: a,
            kind: "oci_subject".into(),
        };
        assert_eq!(del.kind_label(), "oci_subject");
        assert_eq!(del.action_label(), "delete_rejected_source_rows");
    }

    #[test]
    fn repo_drift_default_is_empty() {
        assert!(RepoDrift::default().repairs.is_empty());
    }

    /// A no-op impl proves the trait can be `dyn`-cast and stands in
    /// for adapter impls in cross-crate tests.
    struct EmptyPort;
    impl RefcountReconcilePort for EmptyPort {
        fn list_repository_ids(&self) -> BoxFuture<'_, DomainResult<Vec<Uuid>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn scan_repo_drift(&self, _repo_id: Uuid) -> BoxFuture<'_, DomainResult<RepoDrift>> {
            Box::pin(async { Ok(RepoDrift::default()) })
        }
        fn apply_repair<'a>(
            &'a self,
            _repo_id: Uuid,
            _repair: &'a RefcountRepair,
        ) -> BoxFuture<'a, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn empty_port_returns_no_repos_and_no_drift() {
        let p = EmptyPort;
        assert!(p.list_repository_ids().await.unwrap().is_empty());
        assert!(p
            .scan_repo_drift(Uuid::nil())
            .await
            .unwrap()
            .repairs
            .is_empty());
        p.apply_repair(
            Uuid::nil(),
            &RefcountRepair::CreatePrimaryContent {
                source_artifact_id: Uuid::nil(),
                expected_hash: hash(HASH_A),
            },
        )
        .await
        .unwrap();
    }

    /// `DomainError` round-trips through every return signature — the
    /// adapter surfaces SQL failures this way and the use case maps
    /// them to `AppError::Domain`.
    #[tokio::test]
    async fn errors_round_trip_through_port_signatures() {
        use crate::error::DomainError;
        struct ErrPort;
        impl RefcountReconcilePort for ErrPort {
            fn list_repository_ids(&self) -> BoxFuture<'_, DomainResult<Vec<Uuid>>> {
                Box::pin(async { Err(DomainError::Invariant("repo list failed".into())) })
            }
            fn scan_repo_drift(&self, _repo_id: Uuid) -> BoxFuture<'_, DomainResult<RepoDrift>> {
                Box::pin(async { Err(DomainError::Invariant("scan failed".into())) })
            }
            fn apply_repair<'a>(
                &'a self,
                _repo_id: Uuid,
                _repair: &'a RefcountRepair,
            ) -> BoxFuture<'a, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Invariant("repair failed".into())) })
            }
        }
        let p = ErrPort;
        assert!(matches!(
            p.list_repository_ids().await.unwrap_err(),
            DomainError::Invariant(_)
        ));
        assert!(matches!(
            p.scan_repo_drift(Uuid::nil()).await.unwrap_err(),
            DomainError::Invariant(_)
        ));
        assert!(matches!(
            p.apply_repair(
                Uuid::nil(),
                &RefcountRepair::DeleteRejectedSourceRows {
                    source_artifact_id: Uuid::nil(),
                    kind: "primary_content".into(),
                },
            )
            .await
            .unwrap_err(),
            DomainError::Invariant(_)
        ));
    }
}
