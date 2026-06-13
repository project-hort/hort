pub mod api_token_use_case;
pub mod apply_config_use_case;
pub mod artifact_group_use_case;
pub mod artifact_use_case;
pub mod authenticate_use_case;
pub mod cas_scrub_use_case;
pub mod content_reference;
// Curator decisions: `waive` + `block` (single-artifact and
// `BlockTarget::VersionList` with continue-on-error), plus the `list_*`
// reads backing the HTTP / CLI surfaces. See
// `docs/architecture/how-to/curator-workflow.md`.
pub mod curation_use_case;
// Repo-keyed discovery endpoint
// (`GET /api/v1/repositories/{repo_key}/discovery/versions/{package}`).
// Composes the extended `ArtifactRepository::package_version_status`
// (3-tuple, with `quarantine_until`) with `UpstreamMetadataPort::
// list_versions`, overlaying per-version status. Deliberately does NOT
// compose the unified index pipeline
// (`docs/architecture/explanation/index-construction.md`).
pub mod discovery_use_case;
// Admin-only effective-permissions inspection surface
// (`GET /api/v1/admin/users/:user_id/effective-permissions`).
// The audit-time mitigation for additive-claims operator-discipline
// cost. See `docs/architecture/how-to/operate/claim-based-rbac.md`.
pub mod effective_permissions_use_case;
// `EventStoreRetentionUseCase::archive_terminal_streams`. Seals whole
// terminal / age-gated streams once their audit-retention floor has
// elapsed, routing every seal through the adapter chokepoint (the
// `StreamSealed` tombstone is emitted by the adapter, never
// reimplemented here). Two seal modes; registered with the worker via
// the retention registration seam.
pub mod eventstore_retention_use_case;
pub mod group_reconcile_use_case;
// Shared `IndexFilter` implementations
// (`NonServableStatusFilter` + `IndexModeFilter`) used by the
// per-format unified serve handlers. The
// trait/spine-type definitions they implement live in
// `index_serve` (this module's sibling); `hort-formats::index_serve`
// re-exports them so format-crate consumers have one import path.
pub mod index_filters;
// Format-agnostic index-construction trait skeleton
// (`docs/architecture/explanation/index-construction.md`): `IndexFilter`,
// `IndexBuilder`, `VersionEntry`, `PerVersionPayload`, `BuildContext`.
// Defined here
// (not in `hort-formats`) because the in-`hort-app` filter
// implementations would otherwise need a circular `hort-app →
// hort-formats` edge. `hort-formats::index_serve` is a re-export façade.
pub mod index_serve;
// Quarantine-aware index-serve filter, the
// format-agnostic core (`filter_served_versions`) + the npm reference
// `VersionOrdering` implementation (`NpmSemverOrdering`). Reused
// unchanged for PyPI / Cargo / Maven with their respective
// `VersionOrdering` implementations.
pub mod index_serve_filter;
pub mod ingest_use_case;
// `POST /api/v1/artifacts/:id/rescan` use case.
// Lives in `hort-app` (not `hort-http-admin-security`) per the layered
// architecture: use cases hold the RBAC / conflict-detection /
// enqueue orchestration; the HTTP adapter is a thin wrapper that
// extracts the principal + path and maps `AppError` → `ApiError`.
pub mod manual_rescan_use_case;
pub mod multi_hash;
// OCI Distribution-Spec `/v2/auth` token exchange. See module-level
// doc.
pub mod oci_token_exchange_use_case;
pub mod pat_cache;
pub mod pat_validation_use_case;
// Admin-only read of the patch-candidate quarantine surface. See
// `docs/architecture/how-to/quarantine-patch-release.md`.
pub mod patch_candidate_use_case;
pub mod policy_use_case;
// Prefetch trigger `on_dist_tag_move`
// (`docs/architecture/explanation/prefetch-pipeline.md`).
// Stateless planner consumed by the per-format index/metadata serve
// sites (`hort-http-npm`, `hort-http-cargo`); emits
// `hort_prefetch_skipped_total` per skipped version +
// `hort_prefetch_enqueued_total` per planned version. The format crate
// iterates the returned plan and spawns its per-version pull
// (`PullDedup` inside the spawn handles concurrent dedup).
pub mod prefetch_use_case;
// Shared `fire_hot_path_trigger` helper that collapses the
// previously-duplicated per-format hot-path prefetch-trigger pattern
// (npm / pypi / cargo). OCI deliberately keeps its dedicated
// `fire_prefetch_trigger_oci` — the manifest-fetch digest-divergence
// path doesn't match this helper's parse-body-and-pick-newest
// contract.
pub mod prefetch_trigger;
pub mod promotion_use_case;
// `PurgeUseCase::process_expired`, the destructive storage-GC walk.
// Second stage of the two-stage retention split; refuses to run until
// the refcount-reconcile gate reports convergence.
pub mod purge_use_case;
pub mod quarantine_use_case;
// `RbacResolveUseCase` backing
// `POST /api/v1/admin/rbac/resolve` (the admin what-if resolver:
// IdP groups → claims → effective `(repo, permission)` grants). No IdP
// query, no cache; admin-gated read-only.
pub mod rbac_resolve_use_case;
pub mod ref_use_case;
// The I/O-bearing orchestrator behind
// `POST /api/v1/repositories/{repo_key}/prefetch`. Wraps the pure
// `PrefetchUseCase` planner (unchanged) with repo resolution, RBAC +
// token-kind gates, per-item upstream version resolution, pre-flight
// `package_version_status` checks, and per-item job enqueue via
// `JobsRepository::enqueue_task`. The pure planner stays pure per
// its own module docstring; this is the persistent-job-enqueue
// companion to `fire_hot_path_trigger`.
pub mod self_service_prefetch_use_case;
// `RefcountReconcileUseCase::sweep_drift`.
// Brings the eventually-authoritative `content_references` refcount
// projection back into agreement with `artifacts` + `artifact_metadata`.
// HARD PREREQUISITE for `PurgeUseCase`, whose start-gate
// refuses to run until this sweep has converged at least once.
pub mod refcount_reconcile_use_case;
pub mod repository_access;
pub mod repository_use_case;
// Seed-import cutover path.
// Bulk-registers an operator-supplied dependency set with backdated
// `quarantine_window_start` anchors so the *time* gate is already
// elapsed at import. NOT `ScanWaived`: a dirty scan still rejects.
pub mod seed_import_use_case;
// `RetentionPolicyUseCase`, the
// gitops-authored event-sourced retention-policy create/update/archive
// path (append `RetentionPolicyChanged` + upsert
// `retention_policy_projections`). Mirrors the `PolicyUseCase`
// append-then-upsert shape; archive is terminal (no reactivation).
pub mod retention_policy_use_case;
// `RetentionUseCase::evaluate_policies`.
// The runtime retention evaluator (predicate match + `ArtifactExpired`
// append). Storage GC is `PurgeUseCase`.
pub mod retention_use_case;
// `ProvenanceOrchestrationUseCase`. The worker-side
// `provenance-verify` flow: fetch attestation bundles (OCI Referrers /
// content-reference surface) + the CAS preimage, dispatch each applicable
// `ProvenancePort`, fold to one verdict, apply `complete_provenance`.
// See ADR 0027.
pub mod provenance_orchestration;
pub(crate) mod scan_history;
pub mod scan_orchestration;
// Read-side use case backing
// `GET /api/v1/repositories/:name/security-score` and
// `GET /api/v1/security-score`.
pub mod security_score_use_case;
// Pure-async filter evaluation function. See
// `docs/architecture/explanation/event-notifications.md`.
pub mod subscription_filter;
// `SubscriptionUseCase`. See
// `docs/architecture/explanation/event-notifications.md`.
pub mod subscription_use_case;
pub mod task_use_case;
// Application-layer adapter for the
// `UpstreamIndexCacheInvalidator` domain port. Evicts cached upstream
// packument / simple-index / sparse-index entries when an artifact
// transitions to `Rejected`. Best-effort defense-in-depth cache
// hygiene; the `NonServableStatusFilter` on the next index
// build is the load-bearing close
// (`docs/architecture/explanation/index-construction.md`).
pub mod upstream_index_cache_invalidator;
pub mod user_use_case;
// PEP 658 `.metadata` read-path use case.
// Resolves the wheel artifact via the visibility-gated
// `find_visible_by_path` hop, gates on the same per-artifact
// quarantine-status filter as the wheel download, looks up the
// `wheel_metadata` ContentReference row, and streams the bytes back
// from CAS. See `docs/architecture/how-to/pypi-pull-through.md`.
pub mod wheel_metadata_use_case;

pub use group_reconcile_use_case::{GroupReconcileUseCase, ReconcileReport};
pub use policy_use_case::{
    AddExclusionCommand, CreatePolicyCommand, FieldChange, PolicyUseCase, RemoveExclusionCommand,
    UpdatePolicyCommand,
};

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use uuid::Uuid;

use hort_domain::error::DomainError;
use hort_domain::events::StreamId;
use hort_domain::ports::event_store::{EventStore, ExpectedVersion, ReadFrom};

use crate::error::{AppError, AppResult};

/// Maximum number of events allowed in a single artifact stream.
/// Streams exceeding this limit indicate a bug or abuse and are rejected.
const STREAM_EVENT_CAP: u64 = 200;

/// Read a stream's current position and compute the `ExpectedVersion` for
/// the next append.
///
/// When `enforce_cap` is true, returns `DomainError::Conflict` if the stream
/// exceeds [`STREAM_EVENT_CAP`] events.
pub(crate) async fn read_expected_version(
    events: &dyn EventStore,
    stream_id: &StreamId,
    enforce_cap: bool,
) -> AppResult<ExpectedVersion> {
    let stream_events = events
        .read_stream(stream_id, ReadFrom::Start, STREAM_EVENT_CAP + 1)
        .await?;

    if enforce_cap && stream_events.len() as u64 > STREAM_EVENT_CAP {
        return Err(DomainError::Conflict(format!(
            "stream {stream_id} exceeds {STREAM_EVENT_CAP}-event cap"
        ))
        .into());
    }

    Ok(match stream_events.last() {
        Some(last) => ExpectedVersion::Exact(last.stream_position),
        None => ExpectedVersion::NoStream,
    })
}

/// Verified caller privileges, constructed by the inbound adapter from the
/// authenticated session. Never from request body input.
///
/// This struct ensures privilege checks are explicit parameters, not
/// ambient state (ADR 0001).
///
/// Each `is_*` flag mirrors a `Permission` (or a synthetic role like
/// reviewer): the HTTP edge derives the flag from the caller's resolved
/// permission grants and passes the struct down. Adding a new flag is
/// the standard extension shape — every existing flag follows it.
pub struct CallerPrivileges {
    pub is_admin: bool,
    pub is_reviewer: bool,
    /// Derived at the HTTP edge from the caller
    /// holding `Permission::Curate`. Gates the curation use case
    /// (`waive` / `block` / `list_*`) and is accepted (alongside
    /// `is_admin`) by `PolicyUseCase::{add_exclusion, remove_exclusion}`.
    pub is_curator: bool,
    pub writable_repository_ids: Vec<Uuid>,
}

impl CallerPrivileges {
    /// Require admin privilege. Returns `Forbidden` if not an admin.
    pub fn require_admin(&self) -> AppResult<()> {
        if self.is_admin {
            Ok(())
        } else {
            Err(AppError::Domain(DomainError::Forbidden(
                "admin privilege required".into(),
            )))
        }
    }

    /// Require reviewer privilege. Admins implicitly have reviewer access.
    pub fn require_reviewer(&self) -> AppResult<()> {
        if self.is_reviewer || self.is_admin {
            Ok(())
        } else {
            Err(AppError::Domain(DomainError::Forbidden(
                "reviewer privilege required".into(),
            )))
        }
    }

    /// Require curate **or** admin privilege.
    ///
    /// `Permission::Curate` is the day-to-day decision authority over
    /// quarantined / rejected artifacts and finding-exclusions;
    /// `Permission::Admin` is a strict superset by design (admins can do
    /// everything a curator can, plus more — including `admin_release`
    /// of `ScanIndeterminate` artifacts, which curator cannot).
    /// Accept either authority so an admin is not forced to also carry
    /// the curator permission to perform a curator action.
    ///
    /// Mirrors `require_admin` in shape: returns
    /// `AppError::Domain(DomainError::Forbidden(_))` on denial. The
    /// inbound HTTP layer maps that to 403 via the standard error map.
    pub fn require_curate_or_admin(&self) -> AppResult<()> {
        if self.is_curator || self.is_admin {
            Ok(())
        } else {
            Err(AppError::Domain(DomainError::Forbidden(
                "curate or admin privilege required".into(),
            )))
        }
    }

    /// Require write access to a specific repository. Admins have global write.
    pub fn require_write_access(&self, repo_id: Uuid) -> AppResult<()> {
        if self.is_admin || self.writable_repository_ids.contains(&repo_id) {
            Ok(())
        } else {
            Err(AppError::Domain(DomainError::Forbidden(format!(
                "write access required for repository {repo_id}"
            ))))
        }
    }
}

#[cfg(test)]
mod read_expected_version_tests {
    use std::sync::Arc;

    use hort_domain::events::StreamId;
    use hort_domain::ports::event_store::ExpectedVersion;

    use super::*;
    use crate::use_cases::test_support::*;

    #[tokio::test]
    async fn empty_stream_returns_no_stream() {
        let events = Arc::new(MockEventStore::new());
        let stream_id = StreamId::artifact(Uuid::new_v4());

        let version = read_expected_version(&*events, &stream_id, false)
            .await
            .unwrap();
        assert_eq!(version, ExpectedVersion::NoStream);
    }

    #[tokio::test]
    async fn existing_stream_returns_exact() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let dummy: Vec<_> = (0..3)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy);

        let version = read_expected_version(&*events, &stream_id, false)
            .await
            .unwrap();
        assert_eq!(version, ExpectedVersion::Exact(2));
    }

    #[tokio::test]
    async fn cap_enforced_rejects_oversized_stream() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let dummy: Vec<_> = (0..201)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy);

        let err = read_expected_version(&*events, &stream_id, true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("200-event cap"));
    }

    #[tokio::test]
    async fn cap_not_enforced_allows_oversized_stream() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        // MockEventStore returns up to max_count events, so 201 events
        // with read limit 201 returns all 201 — last position is 200.
        let dummy: Vec<_> = (0..201)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy);

        let version = read_expected_version(&*events, &stream_id, false)
            .await
            .unwrap();
        assert_eq!(version, ExpectedVersion::Exact(200));
    }

    #[tokio::test]
    async fn cap_at_exactly_200_is_allowed() {
        let events = Arc::new(MockEventStore::new());
        let artifact_id = Uuid::new_v4();
        let stream_id = StreamId::artifact(artifact_id);

        let dummy: Vec<_> = (0..200)
            .map(|i| dummy_persisted_event(&stream_id, artifact_id, i))
            .collect();
        events.set_stream(&stream_id, dummy);

        let version = read_expected_version(&*events, &stream_id, true)
            .await
            .unwrap();
        assert_eq!(version, ExpectedVersion::Exact(199));
    }
}

#[cfg(test)]
mod caller_privileges_tests {
    use super::*;
    use uuid::Uuid;

    fn admin_privileges() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: true,
            is_reviewer: false,
            is_curator: false,
            writable_repository_ids: vec![],
        }
    }

    fn reviewer_privileges() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: false,
            is_reviewer: true,
            is_curator: false,
            writable_repository_ids: vec![],
        }
    }

    fn curator_privileges() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: false,
            is_reviewer: false,
            is_curator: true,
            writable_repository_ids: vec![],
        }
    }

    fn unprivileged() -> CallerPrivileges {
        CallerPrivileges {
            is_admin: false,
            is_reviewer: false,
            is_curator: false,
            writable_repository_ids: vec![],
        }
    }

    #[test]
    fn require_admin_with_admin() {
        admin_privileges().require_admin().unwrap();
    }

    #[test]
    fn require_admin_without_admin() {
        let err = unprivileged().require_admin().unwrap_err();
        assert!(err.to_string().contains("admin"));
    }

    #[test]
    fn require_reviewer_with_reviewer() {
        reviewer_privileges().require_reviewer().unwrap();
    }

    #[test]
    fn require_reviewer_admin_implies_reviewer() {
        admin_privileges().require_reviewer().unwrap();
    }

    #[test]
    fn require_reviewer_without_privilege() {
        let err = unprivileged().require_reviewer().unwrap_err();
        assert!(err.to_string().contains("reviewer"));
    }

    #[test]
    fn require_write_access_with_matching_repo() {
        let repo_id = Uuid::new_v4();
        let privs = CallerPrivileges {
            is_admin: false,
            is_reviewer: false,
            is_curator: false,
            writable_repository_ids: vec![repo_id],
        };
        privs.require_write_access(repo_id).unwrap();
    }

    #[test]
    fn require_write_access_without_matching_repo() {
        let err = unprivileged()
            .require_write_access(Uuid::new_v4())
            .unwrap_err();
        assert!(err.to_string().contains("write access"));
    }

    #[test]
    fn require_write_access_admin_has_global_write() {
        admin_privileges()
            .require_write_access(Uuid::new_v4())
            .unwrap();
    }

    // -- require_curate_or_admin --------------------------------------------

    /// Curator-only caller is accepted: this is the day-to-day path the
    /// curate role exists to gate (waive / block / finding-exclusion).
    #[test]
    fn require_curate_or_admin_with_curator() {
        curator_privileges().require_curate_or_admin().unwrap();
    }

    /// Admin caller is accepted: `Admin` is a superset of `Curate` by
    /// design; an admin should not need to also carry the curator
    /// permission to perform a curator action.
    #[test]
    fn require_curate_or_admin_with_admin() {
        admin_privileges().require_curate_or_admin().unwrap();
    }

    /// Caller holding both (e.g. operator with both grants) is still
    /// accepted — the OR semantics are short-circuit on either flag.
    #[test]
    fn require_curate_or_admin_with_both() {
        let privs = CallerPrivileges {
            is_admin: true,
            is_reviewer: false,
            is_curator: true,
            writable_repository_ids: vec![],
        };
        privs.require_curate_or_admin().unwrap();
    }

    /// Neither flag set → denial. Mirrors the `require_admin_without_admin`
    /// shape: an `AppError::Domain(DomainError::Forbidden(_))` whose
    /// message mentions the required authority.
    #[test]
    fn require_curate_or_admin_without_either_denies() {
        let err = unprivileged().require_curate_or_admin().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("curate") || msg.contains("admin"),
            "denial message must name the required authority, got: {msg}"
        );
    }

    /// Reviewer privilege alone does NOT confer curator authority:
    /// reviewer is the approval-flow role, curator is the
    /// quarantine / finding-exclusion role — distinct
    /// permissions, distinct grants. A reviewer must not silently
    /// bypass `require_curate_or_admin`.
    #[test]
    fn require_curate_or_admin_reviewer_alone_does_not_pass() {
        let err = reviewer_privileges().require_curate_or_admin().unwrap_err();
        assert!(err.to_string().contains("curate") || err.to_string().contains("admin"));
    }
}
