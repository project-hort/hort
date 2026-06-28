//! Shared mock implementations and test helpers for use case tests.
//!
//! Provides `MockArtifactRepository`, `MockEventStore`, `MockRepositoryRepository`,
//! `MockStoragePort`, and common helper functions (`sample_artifact`,
//! `sample_repository`, `api_actor`, privilege helpers, etc.).
//!
//! Available in downstream crate tests via `features = ["test-support"]`.

#![allow(clippy::new_without_default)]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::entities::artifact::{Artifact, ArtifactMetadata, QuarantineStatus};
use hort_domain::entities::artifact_group::{ArtifactGroup, ArtifactGroupMember};
use hort_domain::entities::curation_rule::CurationRule;
use hort_domain::entities::mutable_ref::{MutableRef, RefTarget};
use hort_domain::entities::repository::{
    IndexMode, PrefetchPolicy, ReplicationPriority, Repository, RepositoryFormat, RepositoryType,
};
use hort_domain::entities::scan_policy::{ExclusionProjection, ScanPolicyProjection};
use hort_domain::entities::user::{AuthProvider, User};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{
    Actor, ApiActor, ArtifactQuarantined, DomainEvent, PersistedEvent, RejectionReason,
    StreamCategory, StreamId,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

use futures::stream::{self, BoxStream};
use hort_domain::ports::artifact_group_lifecycle::{
    ArtifactGroupLifecyclePort, GroupCommitOutcome, GroupMemberCommit,
};
use hort_domain::ports::artifact_group_repository::ArtifactGroupRepository;
use hort_domain::ports::artifact_lifecycle::ArtifactLifecyclePort;
use hort_domain::ports::artifact_metadata_repository::ArtifactMetadataRepository;
use hort_domain::ports::artifact_repository::ArtifactRepository;
use hort_domain::ports::content_reference_index::{ContentReference, ContentReferenceIndex};
use hort_domain::ports::curation_rule_repository::CurationRuleRepository;
use hort_domain::ports::event_store::{
    AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
};
use hort_domain::ports::format_handler::{FormatHandler, GroupMembership, MetadataStrategy};
use hort_domain::ports::identity_provider::{IdentityProvider, IdpClaims, OidcValidationError};
use hort_domain::ports::jobs_repository::{
    JobRow, JobsRepository, ListJobsFilter, ListJobsPage, ScanJob,
};
use hort_domain::ports::kubernetes_secret_writer::{
    KubernetesSecretWriter, ManagedSecret, ManagedSecretSpec,
};
use hort_domain::ports::oidc_issuer_repository::OidcIssuerRepository;
use hort_domain::ports::policy_projection_repository::PolicyProjectionRepository;
use hort_domain::ports::ref_lifecycle::{RefCommitOutcome, RefLifecyclePort};
use hort_domain::ports::ref_registry::RefRegistryPort;
use hort_domain::ports::replay_guard::{ReplayClaim, ReplayGuardError, ReplayGuardPort, ReplayKey};
use hort_domain::ports::repo_security_score_repository::{
    RepoSecurityScore, RepoSecurityScoreRepository, ScoreDelta,
};
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::{
    RepositoryUpstreamMapping, RepositoryUpstreamMappingRepository,
};
use hort_domain::ports::scan_findings_repository::{ScanFindingsRepository, ScanFindingsRow};
use hort_domain::ports::service_account_repository::ServiceAccountRepository;
use hort_domain::ports::stateful_upload_staging::StatefulUploadStagingPort;
use hort_domain::ports::storage::{PutResult, StoragePort, StreamItem};
use hort_domain::ports::upstream_proxy::{
    ArtifactFetch, BlobFetch, BlobStream, ManifestFetch, ManifestFetchOutcome,
    MetadataFetchOutcome, ReferrerDescriptor, UpstreamProxy,
};
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_domain::ports::user_repository::UserRepository;
use hort_domain::ports::BoxFuture;
use hort_domain::types::sbom::SbomComponent;
use hort_domain::types::{ArtifactCoords, ByteRange, ContentHash, LimitedList, Page, PageRequest};

use crate::metrics::UpstreamFetchError;
use crate::use_cases::CallerPrivileges;

// ---------------------------------------------------------------------------
// BoxFut alias
// ---------------------------------------------------------------------------

pub type BoxFut<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

// ---------------------------------------------------------------------------
// MockArtifactRepository
// ---------------------------------------------------------------------------

pub struct MockArtifactRepository {
    artifacts: Mutex<HashMap<Uuid, Artifact>>,
    /// Per-policy filter set used by `list_rejected_for_policy` to
    /// approximate the SQL shadowing rule (repo-scoped wins over
    /// global). Keyed by `policy_id`, value is the set of
    /// `repository_id`s the policy resolves to. Tests seed via
    /// [`seed_rejected_for_policy`](Self::seed_rejected_for_policy);
    /// when no entry exists for a queried `policy_id`, the mock returns
    /// every rejected artifact.
    rejected_policy_filter: Mutex<HashMap<Uuid, Vec<Uuid>>>,
    /// Per-policy filter set used by `list_active_for_policy` to
    /// approximate the SQL shadowing rule (repo-scoped wins over
    /// global) for the **tighten** direction (ADR 0041). Keyed by
    /// `policy_id`, value is the set of `repository_id`s the policy
    /// resolves to. Tests seed via
    /// [`seed_active_for_policy`](Self::seed_active_for_policy); when no
    /// entry exists for a queried `policy_id`, the mock returns every
    /// active (`Quarantined` / `Released`) artifact.
    active_policy_filter: Mutex<HashMap<Uuid, Vec<Uuid>>>,
    /// Allowlist for
    /// [`find_pypi_wheels_without_kind`](ArtifactRepository::find_pypi_wheels_without_kind).
    /// `None` means "every wheel artifact in the mock is a candidate"
    /// (the simple case); `Some(set)` means "only these artifacts are
    /// candidates" (used to model the NOT-EXISTS exclusion the SQL
    /// adapter enforces against `content_references`).
    pypi_wheels_without_kind_filter: Mutex<Option<std::collections::HashSet<Uuid>>>,
}

impl MockArtifactRepository {
    pub fn new() -> Self {
        Self {
            artifacts: Mutex::new(HashMap::new()),
            rejected_policy_filter: Mutex::new(HashMap::new()),
            active_policy_filter: Mutex::new(HashMap::new()),
            pypi_wheels_without_kind_filter: Mutex::new(None),
        }
    }

    /// Pin the allowlist that
    /// [`ArtifactRepository::find_pypi_wheels_without_kind`] returns.
    /// `None` (the default) returns every wheel; `Some(set)` restricts
    /// to ids in the set — used by `WheelMetadataBackfillHandler` tests
    /// to model "these wheels have no `wheel_metadata`
    /// ContentReference" against a separately-seeded
    /// [`MockContentReferenceIndex`].
    pub fn set_pypi_wheels_without_kind_filter(
        &self,
        allowed: Option<std::collections::HashSet<Uuid>>,
    ) {
        *self.pypi_wheels_without_kind_filter.lock().unwrap() = allowed;
    }

    pub fn insert(&self, artifact: Artifact) {
        self.artifacts.lock().unwrap().insert(artifact.id, artifact);
    }

    /// Friendly alias for [`Self::insert`] for the
    /// cascade tests, which read "seed this artifact" more clearly
    /// than "insert this artifact".
    pub fn seed_artifact(&self, artifact: Artifact) {
        self.insert(artifact);
    }

    /// Seed a synthetic `(name, version, status)`
    /// row directly into the projection so
    /// [`Self::package_version_status`] returns it. Used by cascade
    /// tests to mark a dependency as "already held" without
    /// constructing a full [`Artifact`] payload.
    ///
    /// The mock derives the projection from full artifact rows
    /// (matching the SQL shape); this helper synthesises a minimal
    /// stub artifact per `(version, status)` entry under
    /// `repository_id = repo_id`, `name = package`.
    pub fn seed_package_version_status(
        &self,
        repo_id: Uuid,
        package: &str,
        rows: Vec<(String, QuarantineStatus)>,
    ) {
        let now = Utc::now();
        for (idx, (version, status)) in rows.into_iter().enumerate() {
            // Distinct sha per row so the artifacts map keys do not
            // collide (the map is keyed by `id`; the sha is just a
            // payload field). Use a deterministic-but-unique sha
            // derived from name+version so seeded rows are stable
            // across test runs.
            let mut sha_seed = format!("{package}-{version}-{idx}-{}", Uuid::new_v4());
            sha_seed.truncate(64);
            while sha_seed.len() < 64 {
                sha_seed.push('0');
            }
            // Replace any non-hex char with '0'.
            let sha_hex: String = sha_seed
                .chars()
                .map(|c| {
                    if c.is_ascii_hexdigit() {
                        c.to_ascii_lowercase()
                    } else {
                        '0'
                    }
                })
                .collect();
            let sha: ContentHash = sha_hex.parse().expect("synthetic sha");
            let a = Artifact {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                name: package.to_string(),
                name_as_published: package.to_string(),
                version: Some(version),
                path: format!("seeded-{package}-{idx}"),
                size_bytes: 0,
                sha256_checksum: sha,
                sha1_checksum: None,
                md5_checksum: None,
                content_type: "application/octet-stream".to_string(),
                quarantine_status: status,
                rejection_reason: None,
                quarantine_window_start: None,
                quarantine_deadline: None,
                upstream_published_at: None,
                uploaded_by: None,
                is_deleted: false,
                created_at: now,
                updated_at: now,
            };
            self.insert(a);
        }
    }

    pub fn get(&self, id: Uuid) -> Option<Artifact> {
        self.artifacts.lock().unwrap().get(&id).cloned()
    }

    /// Snapshot every artifact currently in the mock — order
    /// unspecified. Exists so
    /// `SeedImportUseCase` tests can assert on the final state of
    /// the persisted artifact row without first having to extract
    /// the id from the lifecycle commit log.
    pub fn snapshot_all(&self) -> Vec<Artifact> {
        self.artifacts.lock().unwrap().values().cloned().collect()
    }

    /// Seed which `repository_id`s a `policy_id` resolves to. Used by
    /// [`list_rejected_for_policy`](ArtifactRepository::list_rejected_for_policy)
    /// tests to approximate the SQL shadowing rule without wiring a
    /// real `PolicyProjectionRepository` into the mock.
    pub fn seed_rejected_for_policy(&self, policy_id: Uuid, repo_ids: Vec<Uuid>) {
        self.rejected_policy_filter
            .lock()
            .unwrap()
            .insert(policy_id, repo_ids);
    }

    /// Seed which `repository_id`s a `policy_id` resolves to for the
    /// **tighten** direction. Used by
    /// [`list_active_for_policy`](ArtifactRepository::list_active_for_policy)
    /// tests to approximate the SQL shadowing rule without wiring a real
    /// `PolicyProjectionRepository` into the mock. Mirrors
    /// [`Self::seed_rejected_for_policy`].
    pub fn seed_active_for_policy(&self, policy_id: Uuid, repo_ids: Vec<Uuid>) {
        self.active_policy_filter
            .lock()
            .unwrap()
            .insert(policy_id, repo_ids);
    }
}

impl ArtifactRepository for MockArtifactRepository {
    fn find_by_id(&self, id: Uuid) -> BoxFut<'_, DomainResult<Artifact>> {
        let result = self
            .artifacts
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or_else(|| DomainError::NotFound {
                entity: "Artifact",
                id: id.to_string(),
            });
        Box::pin(async move { result })
    }

    fn find_by_checksum(&self, sha256: &ContentHash) -> BoxFut<'_, DomainResult<Option<Artifact>>> {
        let sha = sha256.as_ref().to_string();
        let result = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .find(|a| a.sha256_checksum.as_ref() == sha)
            .cloned();
        Box::pin(async move { Ok(result) })
    }

    fn find_by_repo_and_checksum(
        &self,
        repository_id: Uuid,
        sha256: &ContentHash,
    ) -> BoxFut<'_, DomainResult<Option<Artifact>>> {
        let sha = sha256.as_ref().to_string();
        let result = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .find(|a| a.repository_id == repository_id && a.sha256_checksum.as_ref() == sha)
            .cloned();
        Box::pin(async move { Ok(result) })
    }

    fn list_by_repository(
        &self,
        repository_id: Uuid,
        page: PageRequest,
    ) -> BoxFut<'_, DomainResult<Page<Artifact>>> {
        let all = self.artifacts.lock().unwrap();
        let mut items: Vec<Artifact> = all
            .values()
            .filter(|a| a.repository_id == repository_id)
            .cloned()
            .collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        let total = items.len() as u64;
        let items = items
            .into_iter()
            .skip(page.offset as usize)
            .take(page.limit as usize)
            .collect();
        Box::pin(async move { Ok(Page { items, total }) })
    }

    fn delete(&self, id: Uuid) -> BoxFut<'_, DomainResult<()>> {
        let existed = self.artifacts.lock().unwrap().remove(&id).is_some();
        Box::pin(async move {
            if existed {
                Ok(())
            } else {
                Err(DomainError::NotFound {
                    entity: "Artifact",
                    id: id.to_string(),
                })
            }
        })
    }

    fn find_by_path(
        &self,
        repository_id: Uuid,
        path: &str,
    ) -> BoxFut<'_, DomainResult<Option<Artifact>>> {
        let result = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .find(|a| a.repository_id == repository_id && a.path == path)
            .cloned();
        Box::pin(async move { Ok(result) })
    }

    fn list_distinct_names(
        &self,
        repository_id: Uuid,
        page: PageRequest,
    ) -> BoxFut<'_, DomainResult<Page<String>>> {
        let mut names: Vec<String> = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .filter(|a| a.repository_id == repository_id)
            .map(|a| a.name.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        names.sort();
        let total = names.len() as u64;
        let items: Vec<String> = names
            .into_iter()
            .skip(page.offset as usize)
            .take(page.limit as usize)
            .collect();
        Box::pin(async move { Ok(Page { items, total }) })
    }

    fn find_by_name_in_repo(
        &self,
        repository_id: Uuid,
        normalized_name: &str,
        page: PageRequest,
    ) -> BoxFut<'_, DomainResult<Page<Artifact>>> {
        let mut items: Vec<Artifact> = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .filter(|a| a.repository_id == repository_id && a.name == normalized_name)
            .cloned()
            .collect();
        items.sort_by(|a, b| a.version.cmp(&b.version));
        let total = items.len() as u64;
        let items: Vec<Artifact> = items
            .into_iter()
            .skip(page.offset as usize)
            .take(page.limit as usize)
            .collect();
        Box::pin(async move { Ok(Page { items, total }) })
    }

    fn find_by_name_as_published(
        &self,
        repository_id: Uuid,
        raw_name: &str,
        page: PageRequest,
    ) -> BoxFut<'_, DomainResult<Page<Artifact>>> {
        let mut items: Vec<Artifact> = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .filter(|a| a.repository_id == repository_id && a.name_as_published == raw_name)
            .cloned()
            .collect();
        items.sort_by(|a, b| a.version.cmp(&b.version));
        let total = items.len() as u64;
        let items: Vec<Artifact> = items
            .into_iter()
            .skip(page.offset as usize)
            .take(page.limit as usize)
            .collect();
        Box::pin(async move { Ok(Page { items, total }) })
    }

    fn find_canonical_name_by_collision_key<'a>(
        &'a self,
        repository_id: Uuid,
        collision_key: &'a str,
    ) -> BoxFut<'a, DomainResult<Option<String>>> {
        // Spec 075 — fold each stored name (lowercase + `_` → `-`) and
        // return the first whose folded form matches. Mirrors the Postgres
        // adapter's `replace(lower(name), '_', '-')` probe so the use-case
        // collision test exercises the same fold as production.
        let found = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .filter(|a| a.repository_id == repository_id && !a.is_deleted)
            .map(|a| a.name.clone())
            .find(|name| name.to_lowercase().replace('_', "-") == collision_key);
        Box::pin(async move { Ok(found) })
    }

    fn list_active_for_repo(
        &self,
        repository_id: Uuid,
    ) -> BoxFut<'_, DomainResult<LimitedList<Artifact>>> {
        // Drives the retroactive curation
        // pass. Returns artifacts whose `quarantine_status` is one of
        // `Quarantined` or `Released`. Tests seeding via [`Self::insert`]
        // can craft the status field directly to control which artifacts
        // the retroactive pass sees.
        use hort_domain::entities::artifact::QuarantineStatus;
        let items: Vec<Artifact> = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .filter(|a| {
                a.repository_id == repository_id
                    && matches!(
                        a.quarantine_status,
                        QuarantineStatus::Quarantined | QuarantineStatus::Released
                    )
                    && !a.is_deleted
            })
            .cloned()
            .collect();
        // Mock truncates at the same `LIMIT_LIST_MAX_ITEMS` cap as
        // production so use-case tests behave identically. The over-fetch
        // detection is approximated via `from_overfetch` on the materialised
        // `Vec`.
        let cap = hort_domain::types::LIMIT_LIST_MAX_ITEMS as usize;
        Box::pin(async move { Ok(LimitedList::from_overfetch(items, cap)) })
    }

    fn list_rejected_for_policy(
        &self,
        policy_id: Uuid,
    ) -> BoxFut<'_, DomainResult<LimitedList<Artifact>>> {
        // Drives the post-exclusion-add
        // re-evaluation pass. The mock has no policy_projections wired
        // in (each test seeds its own `MockPolicyProjectionRepository`),
        // so the v1 mock semantics are: "return every rejected artifact
        // whose `repository_id` is in the
        // [`Self::rejected_policy_filter`] map for `policy_id`, or every
        // rejected artifact when no filter has been seeded".
        //
        // Tests for `PolicyUseCase::add_exclusion` re-eval pass seed via
        // [`Self::seed_rejected_for_policy`] so a single mock can back
        // both the per-test policy_projections wiring and this method
        // without re-implementing the SQL shadowing rule.
        let filter = self
            .rejected_policy_filter
            .lock()
            .unwrap()
            .get(&policy_id)
            .cloned();
        use hort_domain::entities::artifact::QuarantineStatus;
        let items: Vec<Artifact> = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .filter(|a| {
                a.quarantine_status == QuarantineStatus::Rejected
                    && !a.is_deleted
                    && match &filter {
                        Some(repo_ids) => repo_ids.contains(&a.repository_id),
                        // No filter seeded — return all rejected
                        // artifacts. Useful for the "zero rejected"
                        // pass-through test.
                        None => true,
                    }
            })
            .cloned()
            .collect();
        let cap = hort_domain::types::LIMIT_LIST_MAX_ITEMS as usize;
        Box::pin(async move { Ok(LimitedList::from_overfetch(items, cap)) })
    }

    fn list_active_for_policy(
        &self,
        policy_id: Uuid,
        page: PageRequest,
    ) -> BoxFut<'_, DomainResult<Page<Artifact>>> {
        // Drives the ADR 0041 tighten direction. Mirror the SQL adapter's
        // semantics: `Quarantined` / `Released`, not soft-deleted, whose
        // active scan-policy resolves to `policy_id`. The shadowing rule is
        // approximated by the per-policy `repository_id` filter seeded via
        // [`Self::seed_active_for_policy`]; with no filter, every active
        // artifact matches.
        //
        // Returns a real [`Page`] (NOT a capped `LimitedList`) so the pass's
        // uncapped page walk is exercised end-to-end — the >10k pagination
        // test seeds more than `LIMIT_LIST_MAX_ITEMS` rows and asserts every
        // one is visited. `page.offset` / `page.limit` paginate; `total`
        // reflects the full in-scope row count.
        use hort_domain::entities::artifact::QuarantineStatus;
        let filter = self
            .active_policy_filter
            .lock()
            .unwrap()
            .get(&policy_id)
            .cloned();
        let mut items: Vec<Artifact> = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .filter(|a| {
                matches!(
                    a.quarantine_status,
                    QuarantineStatus::Quarantined | QuarantineStatus::Released
                ) && !a.is_deleted
                    && match &filter {
                        Some(repo_ids) => repo_ids.contains(&a.repository_id),
                        None => true,
                    }
            })
            .cloned()
            .collect();
        // Stable order so the offset/limit window is deterministic across
        // pages — the adapter does not guarantee order, but a stable order
        // keeps the mock-backed pagination walk free of skips/dupes.
        items.sort_by_key(|a| a.id);
        let total = items.len() as u64;
        let items: Vec<Artifact> = items
            .into_iter()
            .skip(page.offset as usize)
            .take(page.limit as usize)
            .collect();
        Box::pin(async move { Ok(Page { items, total }) })
    }

    fn package_version_status(
        &self,
        repository_id: Uuid,
        package: &str,
    ) -> BoxFut<'_, DomainResult<Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>>> {
        // Mirror the SQL adapter shape: filter to
        // `(repository_id, name)` matches, skip soft-deleted, drop null
        // versions (the format does not version this file — nothing to
        // advertise), return raw `(version, quarantine_status,
        // quarantine_until)` triples.
        //
        // The third tuple element is
        // `artifact.quarantine_deadline`; the SQL adapter projects the
        // same column. Discovery uses it to discriminate `Quarantined`
        // from `QuarantinedAwaitingRelease`.
        let pkg = package.to_owned();
        let mut triples: Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)> = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .filter(|a| a.repository_id == repository_id && a.name == pkg && !a.is_deleted)
            .filter_map(|a| {
                a.version
                    .clone()
                    .map(|v| (v, a.quarantine_status, a.quarantine_deadline))
            })
            .collect();
        // Deterministic order for test assertions; the adapter does not
        // guarantee order — callers must not depend on it — but a stable
        // order keeps mock-backed tests deterministic.
        triples.sort_by(|x, y| x.0.cmp(&y.0));
        Box::pin(async move { Ok(triples) })
    }

    fn package_version_anchors(
        &self,
        repository_id: Uuid,
        package: &str,
    ) -> BoxFut<'_, DomainResult<Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)>>> {
        // Discovery-only read: per-version status + the immutable
        // quarantine anchor (`quarantine_window_start`). Mirrors the SQL
        // adapter's `package_version_anchors`.
        let pkg = package.to_owned();
        let mut triples: Vec<(String, QuarantineStatus, Option<DateTime<Utc>>)> = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .filter(|a| a.repository_id == repository_id && a.name == pkg && !a.is_deleted)
            .filter_map(|a| {
                a.version
                    .clone()
                    .map(|v| (v, a.quarantine_status, a.quarantine_window_start))
            })
            .collect();
        triples.sort_by(|x, y| x.0.cmp(&y.0));
        Box::pin(async move { Ok(triples) })
    }

    /// Mock for the backfill candidacy query. Mirrors
    /// the SQL contract:
    /// - `path LIKE '%.whl'` (wheel-shaped artifacts only)
    /// - `is_deleted = false`
    /// - NOT EXISTS a `content_references` row for `(artifact, kind)`
    ///
    /// The mock has no direct handle to the `MockContentReferenceIndex`;
    /// instead, tests inject "candidate" wheels by inserting Artifact
    /// rows whose path ends `.whl` and orchestrate the negative half
    /// (the NOT-EXISTS pruning) by separately seeding the
    /// `wheel_metadata` ContentReference rows on the
    /// `MockContentReferenceIndex` and re-querying. This matches how
    /// the production handler uses the two ports — the SQL adapter
    /// joins; the test stack composes the two mocks across a single
    /// orchestration.
    ///
    /// To support that, the mock returns every wheel artifact under
    /// repos seeded so far; tests that need the NOT-EXISTS exclusion
    /// behaviour can use [`Self::set_pypi_wheels_without_kind_filter`]
    /// to inject a per-test allowlist of artifact ids.
    fn find_pypi_wheels_without_kind(
        &self,
        _kind: &str,
        limit: u32,
    ) -> BoxFut<'_, DomainResult<Vec<Artifact>>> {
        let filter = self.pypi_wheels_without_kind_filter.lock().unwrap().clone();
        let mut items: Vec<Artifact> = self
            .artifacts
            .lock()
            .unwrap()
            .values()
            .filter(|a| {
                a.path.ends_with(".whl")
                    && !a.is_deleted
                    && match &filter {
                        // No filter seeded — every wheel is a candidate.
                        None => true,
                        // Filter seeded — only ids in the set are candidates
                        // (i.e. the test is modelling "these artifacts
                        // have no `wheel_metadata` row").
                        Some(allowed) => allowed.contains(&a.id),
                    }
            })
            .cloned()
            .collect();
        // Stable order for test assertions — sort by id so repeated
        // invocations on the same seeded state return the same prefix.
        items.sort_by_key(|a| a.id);
        items.truncate(limit as usize);
        Box::pin(async move { Ok(items) })
    }
}

// ---------------------------------------------------------------------------
// MockArtifactMetadataRepository
// ---------------------------------------------------------------------------

/// Map-backed mock for the read-only [`ArtifactMetadataRepository`] port.
///
/// Handler tests in the `hort-http-<format>` crates use this via the
/// `test-support` feature on the `hort-app` dev-dependency. Seed with
/// [`insert`](Self::insert) before
/// exercising a handler that calls `list_by_artifact_ids` (e.g. the PyPI
/// simple project index).
pub struct MockArtifactMetadataRepository {
    entries: Mutex<HashMap<Uuid, ArtifactMetadata>>,
}

impl MockArtifactMetadataRepository {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Seed a metadata row keyed by `artifact_id`.
    pub fn insert(&self, metadata: ArtifactMetadata) {
        self.entries
            .lock()
            .unwrap()
            .insert(metadata.artifact_id, metadata);
    }
}

impl ArtifactMetadataRepository for MockArtifactMetadataRepository {
    fn find_by_artifact_id(
        &self,
        artifact_id: Uuid,
    ) -> BoxFut<'_, DomainResult<Option<ArtifactMetadata>>> {
        let result = self.entries.lock().unwrap().get(&artifact_id).cloned();
        Box::pin(async move { Ok(result) })
    }

    fn list_by_artifact_ids(
        &self,
        ids: &[Uuid],
    ) -> BoxFut<'_, DomainResult<HashMap<Uuid, ArtifactMetadata>>> {
        let entries = self.entries.lock().unwrap();
        let mut result: HashMap<Uuid, ArtifactMetadata> = HashMap::new();
        for id in ids {
            if let Some(m) = entries.get(id) {
                result.insert(*id, m.clone());
            }
        }
        Box::pin(async move { Ok(result) })
    }
}

// ---------------------------------------------------------------------------
// MockPolicyProjectionRepository
// ---------------------------------------------------------------------------

/// Map-backed mock for the [`PolicyProjectionRepository`] port.
///
/// Use case tests for `PolicyUseCase`, `ApplyConfigUseCase`, and the
/// scan-result rewire seed projections + exclusions through this
/// mock. Failure-injection hooks (`fail_next_*`) cover the strict-atomic
/// abort paths exercised by gitops apply tests.
///
/// Lifted to the shared module — previously each test
/// module rolled its own private duplicate. The two pre-existing private
/// copies (`policy_use_case::tests::MockPolicyProjections`,
/// `apply_config_use_case::tests::MockPolicyProjections`) are kept by the
/// caller test modules where the API surface is wider; new callers reuse
/// this shared mock.
pub struct MockPolicyProjectionRepository {
    by_id: Mutex<HashMap<Uuid, ScanPolicyProjection>>,
    by_name: Mutex<HashMap<String, ScanPolicyProjection>>,
    upserts: Mutex<Vec<ScanPolicyProjection>>,
    next_upsert_error: Mutex<Option<DomainError>>,
    exclusions: Mutex<HashMap<Uuid, Vec<ExclusionProjection>>>,
    exclusion_upserts: Mutex<Vec<ExclusionProjection>>,
    exclusion_deletes: Mutex<Vec<Uuid>>,
    next_upsert_exclusion_error: Mutex<Option<DomainError>>,
    next_delete_exclusion_error: Mutex<Option<DomainError>>,
    next_list_exclusions_error: Mutex<Option<DomainError>>,
    /// Failure-injection for `list_active`. Arms once, clears after
    /// the first call — follows the same one-shot pattern as the other
    /// `fail_next_*` hooks in this mock. Used by coverage
    /// tests that must exercise the policy-resolution-error degraded
    /// path inside `scanner_label_for_failed`.
    next_list_active_error: Mutex<Option<DomainError>>,
}

impl MockPolicyProjectionRepository {
    pub fn new() -> Self {
        Self {
            by_id: Mutex::new(HashMap::new()),
            by_name: Mutex::new(HashMap::new()),
            upserts: Mutex::new(Vec::new()),
            next_upsert_error: Mutex::new(None),
            exclusions: Mutex::new(HashMap::new()),
            exclusion_upserts: Mutex::new(Vec::new()),
            exclusion_deletes: Mutex::new(Vec::new()),
            next_upsert_exclusion_error: Mutex::new(None),
            next_delete_exclusion_error: Mutex::new(None),
            next_list_exclusions_error: Mutex::new(None),
            next_list_active_error: Mutex::new(None),
        }
    }

    /// Seed an active projection. Mirrors a successful prior `upsert`.
    pub fn insert(&self, projection: ScanPolicyProjection) {
        self.by_id
            .lock()
            .unwrap()
            .insert(projection.policy_id, projection.clone());
        self.by_name
            .lock()
            .unwrap()
            .insert(projection.name.clone(), projection);
    }

    /// Seed an exclusion against its `policy_id`. Mirrors a successful
    /// prior `upsert_exclusion`.
    pub fn insert_exclusion(&self, exclusion: ExclusionProjection) {
        self.exclusions
            .lock()
            .unwrap()
            .entry(exclusion.policy_id)
            .or_default()
            .push(exclusion);
    }

    pub fn upserts(&self) -> Vec<ScanPolicyProjection> {
        self.upserts.lock().unwrap().clone()
    }

    pub fn exclusion_upserts(&self) -> Vec<ExclusionProjection> {
        self.exclusion_upserts.lock().unwrap().clone()
    }

    pub fn exclusion_deletes(&self) -> Vec<Uuid> {
        self.exclusion_deletes.lock().unwrap().clone()
    }

    pub fn fail_next_upsert(&self, e: DomainError) {
        *self.next_upsert_error.lock().unwrap() = Some(e);
    }

    pub fn fail_next_upsert_exclusion(&self, e: DomainError) {
        *self.next_upsert_exclusion_error.lock().unwrap() = Some(e);
    }

    pub fn fail_next_delete_exclusion(&self, e: DomainError) {
        *self.next_delete_exclusion_error.lock().unwrap() = Some(e);
    }

    pub fn fail_next_list_exclusions(&self, e: DomainError) {
        *self.next_list_exclusions_error.lock().unwrap() = Some(e);
    }

    /// Arms a one-shot error for the next `list_active` call.
    /// Mirrors the pattern of the other `fail_next_*` hooks. Used by
    /// `scanner_label_for_failed` degraded-path coverage tests.
    pub fn fail_next_list_active(&self, e: DomainError) {
        *self.next_list_active_error.lock().unwrap() = Some(e);
    }
}

impl PolicyProjectionRepository for MockPolicyProjectionRepository {
    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>> {
        let res = self.by_id.lock().unwrap().get(&id).cloned();
        Box::pin(async move { Ok(res) })
    }

    fn find_by_name(
        &self,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>> {
        // Mirror the production adapter contract: `find_by_name` returns
        // active rows only (the partial-active-name index intent on
        // `policy_projections`).
        let res = self
            .by_name
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .filter(|p| !p.archived);
        Box::pin(async move { Ok(res) })
    }

    fn find_by_name_including_archived(
        &self,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>> {
        let res = self.by_name.lock().unwrap().get(name).cloned();
        Box::pin(async move { Ok(res) })
    }

    fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<ScanPolicyProjection>>> {
        if let Some(e) = self.next_list_active_error.lock().unwrap().take() {
            return Box::pin(async move { Err(e) });
        }
        let res: Vec<_> = self
            .by_id
            .lock()
            .unwrap()
            .values()
            .filter(|p| !p.archived)
            .cloned()
            .collect();
        Box::pin(async move { Ok(res) })
    }

    fn list_exclusions_for_policy(
        &self,
        policy_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<ExclusionProjection>>> {
        if let Some(e) = self.next_list_exclusions_error.lock().unwrap().take() {
            return Box::pin(async move { Err(e) });
        }
        let res = self
            .exclusions
            .lock()
            .unwrap()
            .get(&policy_id)
            .cloned()
            .unwrap_or_default();
        Box::pin(async move { Ok(res) })
    }

    fn upsert(&self, projection: &ScanPolicyProjection) -> BoxFuture<'_, DomainResult<()>> {
        if let Some(e) = self.next_upsert_error.lock().unwrap().take() {
            return Box::pin(async move { Err(e) });
        }
        self.by_id
            .lock()
            .unwrap()
            .insert(projection.policy_id, projection.clone());
        self.by_name
            .lock()
            .unwrap()
            .insert(projection.name.clone(), projection.clone());
        self.upserts.lock().unwrap().push(projection.clone());
        Box::pin(async move { Ok(()) })
    }

    fn upsert_exclusion(&self, exclusion: &ExclusionProjection) -> BoxFuture<'_, DomainResult<()>> {
        if let Some(e) = self.next_upsert_exclusion_error.lock().unwrap().take() {
            return Box::pin(async move { Err(e) });
        }
        self.exclusions
            .lock()
            .unwrap()
            .entry(exclusion.policy_id)
            .or_default()
            .push(exclusion.clone());
        self.exclusion_upserts
            .lock()
            .unwrap()
            .push(exclusion.clone());
        Box::pin(async move { Ok(()) })
    }

    fn delete_exclusion(&self, exclusion_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        if let Some(e) = self.next_delete_exclusion_error.lock().unwrap().take() {
            return Box::pin(async move { Err(e) });
        }
        for bucket in self.exclusions.lock().unwrap().values_mut() {
            bucket.retain(|e| e.exclusion_id != exclusion_id);
        }
        self.exclusion_deletes.lock().unwrap().push(exclusion_id);
        Box::pin(async move { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// MockCurationRuleRepository
// ---------------------------------------------------------------------------

/// In-memory [`CurationRuleRepository`] for ingest-gate tests.
///
/// Defaults to empty: `list_for_repo` returns `Vec::new()` so the
/// curation gate falls through to `Allow` without any seeding. Tests that
/// exercise `Block` / `Warn` paths seed via [`Self::set_rules_for_repo`].
/// Mutations are stored against `repository_id`, mirroring the
/// `repository_curation_rules` junction's per-repo set semantics.
///
/// The mock implements every port method but only the read path
/// (`list_for_repo`, `find_by_id`, `find_by_name`) has non-trivial
/// behaviour — the apply-pipeline writers (`save_managed`,
/// `delete_managed`, `set_curation_rules_for_repository`) are no-ops
/// because the curation gate doesn't exercise them. The dedicated
/// `apply_config_use_case::tests::MockCurationRuleRepo` private mock
/// covers those paths.
pub struct MockCurationRuleRepository {
    by_repo: Mutex<HashMap<Uuid, Vec<CurationRule>>>,
    by_id: Mutex<HashMap<Uuid, CurationRule>>,
    /// Reverse-index for `list_repos_for_rule`.
    /// Mirrors the `repository_curation_rules` junction's reverse view —
    /// when a test calls [`Self::set_rules_for_repo`] the entries are
    /// added automatically; an explicit [`Self::link_rule_to_repo`]
    /// helper exists for tests that want the reverse-index without also
    /// populating `by_repo`.
    by_rule: Mutex<HashMap<Uuid, Vec<Uuid>>>,
    next_list_for_repo_error: Mutex<Option<DomainError>>,
}

impl MockCurationRuleRepository {
    pub fn new() -> Self {
        Self {
            by_repo: Mutex::new(HashMap::new()),
            by_id: Mutex::new(HashMap::new()),
            by_rule: Mutex::new(HashMap::new()),
            next_list_for_repo_error: Mutex::new(None),
        }
    }

    /// Replace the rule set linked to `repository_id`. Order is preserved
    /// — tests asserting first-match-wins must seed in declaration order.
    /// The reverse-index `by_rule` is updated atomically so a subsequent
    /// `list_repos_for_rule(rule_id)` call returns this `repository_id`.
    pub fn set_rules_for_repo(&self, repository_id: Uuid, rules: Vec<CurationRule>) {
        // Update the rule-by-id store and reverse-index for the new set.
        for rule in &rules {
            self.by_id.lock().unwrap().insert(rule.id, rule.clone());
            let mut by_rule = self.by_rule.lock().unwrap();
            let entry = by_rule.entry(rule.id).or_default();
            if !entry.contains(&repository_id) {
                entry.push(repository_id);
            }
        }
        // Purge reverse-index entries that pointed to this repo from
        // rules NOT in the new set — `set_rules_for_repo` is a replace.
        let new_rule_ids: std::collections::HashSet<Uuid> = rules.iter().map(|r| r.id).collect();
        {
            let mut by_rule = self.by_rule.lock().unwrap();
            for (rid, repos) in by_rule.iter_mut() {
                if !new_rule_ids.contains(rid) {
                    repos.retain(|r| *r != repository_id);
                }
            }
        }

        self.by_repo.lock().unwrap().insert(repository_id, rules);
    }

    /// Reverse-index seed helper. Adds a `(rule_id → repository_id)`
    /// edge without modifying `by_repo`. Useful for tests that drive
    /// `list_repos_for_rule` directly without the full
    /// `set_rules_for_repo` plumbing — typically the apply-pipeline
    /// retroactive-evaluation tests where the rule is freshly created
    /// inside the apply.
    pub fn link_rule_to_repo(&self, rule_id: Uuid, repository_id: Uuid) {
        let mut by_rule = self.by_rule.lock().unwrap();
        let entry = by_rule.entry(rule_id).or_default();
        if !entry.contains(&repository_id) {
            entry.push(repository_id);
        }
    }

    /// One-shot failure injection on `list_for_repo`. Consumed on the
    /// next call. Used to assert the ingest gate propagates lookup
    /// failures rather than silently allowing.
    pub fn fail_next_list_for_repo(&self, e: DomainError) {
        *self.next_list_for_repo_error.lock().unwrap() = Some(e);
    }
}

impl CurationRuleRepository for MockCurationRuleRepository {
    fn find_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<Option<CurationRule>>> {
        let n = name.to_string();
        let r = self
            .by_id
            .lock()
            .unwrap()
            .values()
            .find(|r| r.name == n)
            .cloned();
        Box::pin(async move { Ok(r) })
    }

    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Option<CurationRule>>> {
        let r = self.by_id.lock().unwrap().get(&id).cloned();
        Box::pin(async move { Ok(r) })
    }

    fn list_for_repo(&self, repository_id: Uuid) -> BoxFuture<'_, DomainResult<Vec<CurationRule>>> {
        if let Some(err) = self.next_list_for_repo_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        let rules = self
            .by_repo
            .lock()
            .unwrap()
            .get(&repository_id)
            .cloned()
            .unwrap_or_default();
        Box::pin(async move { Ok(rules) })
    }

    fn list_managed_by_gitops(&self) -> BoxFuture<'_, DomainResult<Vec<CurationRule>>> {
        let v = self.by_id.lock().unwrap().values().cloned().collect();
        Box::pin(async move { Ok(v) })
    }

    fn save_managed(&self, _rule: &CurationRule) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn delete_managed(&self, _name: &str) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn set_curation_rules_for_repository(
        &self,
        _repository_id: Uuid,
        _rule_ids: &[Uuid],
    ) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn list_repos_for_rule(&self, rule_id: Uuid) -> BoxFuture<'_, DomainResult<Vec<Uuid>>> {
        let v = self
            .by_rule
            .lock()
            .unwrap()
            .get(&rule_id)
            .cloned()
            .unwrap_or_default();
        Box::pin(async move { Ok(v) })
    }
}

// ---------------------------------------------------------------------------
// MockRepositoryRepository
// ---------------------------------------------------------------------------

pub struct MockRepositoryRepository {
    repositories: Mutex<HashMap<Uuid, Repository>>,
    /// One-shot failure injection for `find_by_key`. Consumed on the
    /// next call. Used by OCI handler tests to simulate pool
    /// exhaustion / transient SQL failures so we can verify the
    /// handler emits 500 INTERNAL instead of collapsing to 404.
    next_find_by_key_error: Mutex<Option<DomainError>>,
    /// Virtual-member edges per virtual repo.
    /// Stored as a flat `HashMap<virtual_id, Vec<member_id>>` because
    /// the apply use case only needs whole-membership-set semantics
    /// (compute the diff between declared and current).
    virtual_members: Mutex<HashMap<Uuid, Vec<Uuid>>>,
    /// Call ordering is also asserted by tests — the in-mock counters let
    /// tests confirm "save_managed was called before
    /// add_virtual_member" without needing a separate spy crate.
    /// `Mutex<Vec<...>>` records every event in order.
    pub call_log: Mutex<Vec<MockCall>>,
    /// One-shot failure injection for `save_managed`. Used to
    /// verify strict-atomic abort: if the second managed write
    /// fails, the first one is NOT rolled back (no rollback in v1)
    /// but the use case still returns Err.
    next_save_managed_error: Mutex<Option<DomainError>>,
    /// One-shot failure injection for `find_by_id` (infra-error paths).
    next_find_by_id_error: Mutex<Option<DomainError>>,
    /// One-shot failure injection for `get_virtual_members`.
    next_get_virtual_members_error: Mutex<Option<DomainError>>,
}

/// One entry in `MockRepositoryRepository::call_log`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockCall {
    Save(Uuid),
    Delete(Uuid),
    SaveManaged(Uuid, [u8; 32]),
    DeleteManaged(Uuid),
    AddMember(Uuid, Uuid),
    RemoveMember(Uuid, Uuid),
    ReplaceMembers(Uuid, Vec<Uuid>),
}

impl MockRepositoryRepository {
    pub fn new() -> Self {
        Self {
            repositories: Mutex::new(HashMap::new()),
            next_find_by_key_error: Mutex::new(None),
            virtual_members: Mutex::new(HashMap::new()),
            call_log: Mutex::new(Vec::new()),
            next_save_managed_error: Mutex::new(None),
            next_find_by_id_error: Mutex::new(None),
            next_get_virtual_members_error: Mutex::new(None),
        }
    }

    pub fn insert(&self, repo: Repository) {
        self.repositories.lock().unwrap().insert(repo.id, repo);
    }

    /// Seed a single failure — the next `find_by_key` call returns
    /// `Err(err)`. Cleared after the call. `err` should be a
    /// non-`NotFound` variant (e.g. `Invariant`, `Conflict`) to
    /// simulate infrastructure errors; `NotFound` is what a plain
    /// missing key produces anyway.
    pub fn fail_next_find_by_key(&self, err: DomainError) {
        *self.next_find_by_key_error.lock().unwrap() = Some(err);
    }

    /// Seed a single failure for the next `find_by_id` call (consumed once).
    pub fn fail_next_find_by_id(&self, err: DomainError) {
        *self.next_find_by_id_error.lock().unwrap() = Some(err);
    }

    /// Seed a single failure for the next `get_virtual_members` call.
    pub fn fail_next_get_virtual_members(&self, err: DomainError) {
        *self.next_get_virtual_members_error.lock().unwrap() = Some(err);
    }

    /// Seed a managed virtual-member edge. Used by tests that
    /// start from a non-empty membership set.
    pub fn seed_virtual_member(&self, virtual_id: Uuid, member_id: Uuid) {
        self.virtual_members
            .lock()
            .unwrap()
            .entry(virtual_id)
            .or_default()
            .push(member_id);
    }

    /// Snapshot the call log in order. Tests use this to assert call
    /// order ("save_managed before add_virtual_member") and to count
    /// specific operations.
    pub fn calls(&self) -> Vec<MockCall> {
        self.call_log.lock().unwrap().clone()
    }

    /// Inject a one-shot failure on the next `save_managed` call.
    /// Cleared on consumption.
    pub fn fail_next_save_managed(&self, err: DomainError) {
        *self.next_save_managed_error.lock().unwrap() = Some(err);
    }
}

impl RepositoryRepository for MockRepositoryRepository {
    fn find_by_id(&self, id: Uuid) -> BoxFut<'_, DomainResult<Repository>> {
        if let Some(err) = self.next_find_by_id_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        let result = self
            .repositories
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or_else(|| DomainError::NotFound {
                entity: "Repository",
                id: id.to_string(),
            });
        Box::pin(async move { result })
    }

    fn find_by_key(&self, key: &str) -> BoxFut<'_, DomainResult<Repository>> {
        if let Some(err) = self.next_find_by_key_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        let result = self
            .repositories
            .lock()
            .unwrap()
            .values()
            .find(|r| r.key == key)
            .cloned()
            .ok_or_else(|| DomainError::NotFound {
                entity: "Repository",
                id: key.to_string(),
            });
        Box::pin(async move { result })
    }

    fn list(
        &self,
        page: PageRequest,
        search: Option<&str>,
    ) -> BoxFut<'_, DomainResult<Page<Repository>>> {
        // The OCI global-catalog handler enumerates all repositories via
        // this method and filters by visibility downstream. Returning an
        // empty page silently hid every repo from the catalog output, which
        // was fine while no test depended on `list`. Implement the same
        // shape as the Postgres adapter: substring match on `key`,
        // alphabetical by `key`, `offset`/`limit` paginated.
        let search = search.unwrap_or("").to_string();
        let all = self.repositories.lock().unwrap();
        let mut filtered: Vec<Repository> = all
            .values()
            .filter(|r| search.is_empty() || r.key.contains(&search))
            .cloned()
            .collect();
        filtered.sort_by(|a, b| a.key.cmp(&b.key));
        let total = filtered.len() as u64;
        let start = (page.offset as usize).min(filtered.len());
        let end = (start + page.limit as usize).min(filtered.len());
        let items = filtered[start..end].to_vec();
        Box::pin(async move { Ok(Page { items, total }) })
    }

    fn save(&self, repository: &Repository) -> BoxFut<'_, DomainResult<()>> {
        // Tests assert the public CRUD path is NOT touched by the apply
        // pipeline. Recording the call lets a test confirm "save was never
        // called during apply" rather than relying on state-equality, which
        // can pass for the wrong reason.
        self.call_log
            .lock()
            .unwrap()
            .push(MockCall::Save(repository.id));
        self.repositories
            .lock()
            .unwrap()
            .insert(repository.id, repository.clone());
        Box::pin(async { Ok(()) })
    }

    fn delete(&self, id: Uuid) -> BoxFut<'_, DomainResult<()>> {
        self.call_log.lock().unwrap().push(MockCall::Delete(id));
        self.repositories.lock().unwrap().remove(&id);
        Box::pin(async { Ok(()) })
    }

    fn get_virtual_members(
        &self,
        virtual_repo_id: Uuid,
    ) -> BoxFut<'_, DomainResult<Vec<Repository>>> {
        if let Some(err) = self.next_get_virtual_members_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        let edges = self
            .virtual_members
            .lock()
            .unwrap()
            .get(&virtual_repo_id)
            .cloned()
            .unwrap_or_default();
        let repos = self.repositories.lock().unwrap();
        let members: Vec<Repository> = edges
            .into_iter()
            .filter_map(|id| repos.get(&id).cloned())
            .collect();
        Box::pin(async move { Ok(members) })
    }

    fn add_virtual_member(
        &self,
        virtual_repo_id: Uuid,
        member_repo_id: Uuid,
    ) -> BoxFut<'_, DomainResult<()>> {
        self.call_log
            .lock()
            .unwrap()
            .push(MockCall::AddMember(virtual_repo_id, member_repo_id));
        self.virtual_members
            .lock()
            .unwrap()
            .entry(virtual_repo_id)
            .or_default()
            .push(member_repo_id);
        Box::pin(async { Ok(()) })
    }

    fn remove_virtual_member(
        &self,
        virtual_repo_id: Uuid,
        member_repo_id: Uuid,
    ) -> BoxFut<'_, DomainResult<()>> {
        self.call_log
            .lock()
            .unwrap()
            .push(MockCall::RemoveMember(virtual_repo_id, member_repo_id));
        if let Some(members) = self
            .virtual_members
            .lock()
            .unwrap()
            .get_mut(&virtual_repo_id)
        {
            members.retain(|id| *id != member_repo_id);
        }
        Box::pin(async { Ok(()) })
    }

    fn replace_virtual_members(
        &self,
        virtual_repo_id: Uuid,
        ordered_member_ids: &[Uuid],
    ) -> BoxFut<'_, DomainResult<()>> {
        // Atomic from a reader's perspective: the whole set is swapped in one
        // locked section (mirrors the adapter's single transaction).
        let ids = ordered_member_ids.to_vec();
        self.call_log
            .lock()
            .unwrap()
            .push(MockCall::ReplaceMembers(virtual_repo_id, ids.clone()));
        self.virtual_members
            .lock()
            .unwrap()
            .insert(virtual_repo_id, ids);
        Box::pin(async { Ok(()) })
    }

    fn get_storage_usage(&self, _repo_id: Uuid) -> BoxFut<'_, DomainResult<u64>> {
        Box::pin(async { Ok(0) })
    }

    fn save_managed(
        &self,
        repository: &Repository,
        digest: &[u8; 32],
    ) -> BoxFut<'_, DomainResult<()>> {
        if let Some(err) = self.next_save_managed_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        self.call_log
            .lock()
            .unwrap()
            .push(MockCall::SaveManaged(repository.id, *digest));
        let mut stored = repository.clone();
        stored.managed_by = hort_domain::entities::managed_by::ManagedBy::GitOps;
        stored.managed_by_digest = Some(*digest);
        self.repositories.lock().unwrap().insert(stored.id, stored);
        Box::pin(async { Ok(()) })
    }

    fn delete_managed(&self, id: Uuid) -> BoxFut<'_, DomainResult<()>> {
        self.call_log
            .lock()
            .unwrap()
            .push(MockCall::DeleteManaged(id));
        // Defence-in-depth check on the mock too: only delete a row
        // whose managed_by is GitOps. Otherwise NotFound (matches the
        // Postgres adapter's WHERE-clause behaviour).
        let mut repos = self.repositories.lock().unwrap();
        let removed = repos
            .get(&id)
            .map(|r| r.managed_by == hort_domain::entities::managed_by::ManagedBy::GitOps)
            .unwrap_or(false);
        if removed {
            repos.remove(&id);
            Box::pin(async { Ok(()) })
        } else {
            Box::pin(async move {
                Err(DomainError::NotFound {
                    entity: "Repository",
                    id: id.to_string(),
                })
            })
        }
    }
}

// ---------------------------------------------------------------------------
// MockUserRepository
// ---------------------------------------------------------------------------

pub struct MockUserRepository {
    users: Mutex<HashMap<Uuid, User>>,
}

impl MockUserRepository {
    pub fn new() -> Self {
        Self {
            users: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, user: User) {
        self.users.lock().unwrap().insert(user.id, user);
    }
}

impl UserRepository for MockUserRepository {
    fn find_by_id(&self, id: Uuid) -> BoxFut<'_, DomainResult<User>> {
        let result =
            self.users
                .lock()
                .unwrap()
                .get(&id)
                .cloned()
                .ok_or_else(|| DomainError::NotFound {
                    entity: "User",
                    id: id.to_string(),
                });
        Box::pin(async move { result })
    }

    fn find_by_username(&self, username: &str) -> BoxFut<'_, DomainResult<Option<User>>> {
        let result = self
            .users
            .lock()
            .unwrap()
            .values()
            .find(|u| u.username == username)
            .cloned();
        Box::pin(async move { Ok(result) })
    }

    fn find_by_email(&self, email: &str) -> BoxFut<'_, DomainResult<Option<User>>> {
        let result = self
            .users
            .lock()
            .unwrap()
            .values()
            .find(|u| u.email == email)
            .cloned();
        Box::pin(async move { Ok(result) })
    }

    fn list(&self, page: PageRequest) -> BoxFut<'_, DomainResult<Page<User>>> {
        let all = self.users.lock().unwrap();
        let mut items: Vec<User> = all.values().cloned().collect();
        items.sort_by(|a, b| a.username.cmp(&b.username));
        let total = items.len() as u64;
        let items = items
            .into_iter()
            .skip(page.offset as usize)
            .take(page.limit as usize)
            .collect();
        Box::pin(async move { Ok(Page { items, total }) })
    }

    fn save(&self, user: &User) -> BoxFut<'_, DomainResult<()>> {
        self.users.lock().unwrap().insert(user.id, user.clone());
        Box::pin(async { Ok(()) })
    }

    fn delete(&self, id: Uuid) -> BoxFut<'_, DomainResult<()>> {
        let existed = self.users.lock().unwrap().remove(&id).is_some();
        Box::pin(async move {
            if existed {
                Ok(())
            } else {
                Err(DomainError::NotFound {
                    entity: "User",
                    id: id.to_string(),
                })
            }
        })
    }

    fn find_by_external_id(
        &self,
        auth_provider: AuthProvider,
        external_id: &str,
    ) -> BoxFut<'_, DomainResult<Option<User>>> {
        let result = self
            .users
            .lock()
            .unwrap()
            .values()
            .find(|u| {
                u.auth_provider == auth_provider && u.external_id.as_deref() == Some(external_id)
            })
            .cloned();
        Box::pin(async move { Ok(result) })
    }

    fn upsert_on_login(&self, user: &User) -> BoxFut<'_, DomainResult<User>> {
        let mut users = self.users.lock().unwrap();
        // Match on (auth_provider, external_id); losing racers see the
        // committed row.
        let existing_id = users
            .values()
            .find(|u| u.auth_provider == user.auth_provider && u.external_id == user.external_id)
            .map(|u| u.id);
        let resolved = match existing_id {
            Some(existing_id) => {
                // Refresh mutable fields; preserve the existing row id.
                let refreshed = User {
                    id: existing_id,
                    username: user.username.clone(),
                    email: user.email.clone(),
                    display_name: user.display_name.clone(),
                    is_admin: user.is_admin,
                    last_login_at: user.last_login_at,
                    updated_at: user.updated_at,
                    ..users.get(&existing_id).cloned().expect("id lookup")
                };
                users.insert(existing_id, refreshed.clone());
                refreshed
            }
            None => {
                users.insert(user.id, user.clone());
                user.clone()
            }
        };
        Box::pin(async move { Ok(resolved) })
    }
}

// ---------------------------------------------------------------------------
// MockPermissionGrantRepository
// ---------------------------------------------------------------------------

/// In-memory [`PermissionGrantRepository`] for use-case and inbound-HTTP
/// handler tests. `list_all` returns the seeded set; the gitops
/// reconcile surface (`list_managed_by_gitops` / `save_managed`) is a
/// no-op because the effective-permissions read path never touches it.
pub struct MockPermissionGrantRepository {
    grants: Mutex<Vec<hort_domain::entities::rbac::PermissionGrant>>,
}

impl Default for MockPermissionGrantRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl MockPermissionGrantRepository {
    pub fn new() -> Self {
        Self {
            grants: Mutex::new(Vec::new()),
        }
    }

    /// Replace the full grant set returned by `list_all`.
    pub fn seed(&self, grants: Vec<hort_domain::entities::rbac::PermissionGrant>) {
        *self.grants.lock().unwrap() = grants;
    }
}

impl hort_domain::ports::permission_grant_repository::PermissionGrantRepository
    for MockPermissionGrantRepository
{
    fn list_all(
        &self,
    ) -> BoxFut<'_, DomainResult<Vec<hort_domain::entities::rbac::PermissionGrant>>> {
        let rows = self.grants.lock().unwrap().clone();
        Box::pin(async move { Ok(rows) })
    }

    fn list_managed_by_gitops(
        &self,
    ) -> BoxFut<'_, DomainResult<Vec<hort_domain::entities::rbac::PermissionGrant>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn save_managed(
        &self,
        _items: &[hort_domain::entities::rbac::PermissionGrant],
    ) -> BoxFut<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// MockClaimMappingRepository
// ---------------------------------------------------------------------------

/// In-memory [`ClaimMappingRepository`](hort_domain::ports::claim_mapping_repository::ClaimMappingRepository)
/// for use-case and inbound-HTTP handler tests. `list_all` returns the
/// seeded set; the gitops reconcile surface (`list_managed_by_gitops` /
/// `save_managed`) is a no-op because the what-if resolver read path
/// (`RbacResolveUseCase`) only calls `list_all`.
pub struct MockClaimMappingRepository {
    mappings: Mutex<Vec<hort_domain::entities::rbac::ClaimMapping>>,
}

impl Default for MockClaimMappingRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl MockClaimMappingRepository {
    pub fn new() -> Self {
        Self {
            mappings: Mutex::new(Vec::new()),
        }
    }

    /// Replace the full mapping set returned by `list_all`.
    pub fn seed(&self, mappings: Vec<hort_domain::entities::rbac::ClaimMapping>) {
        *self.mappings.lock().unwrap() = mappings;
    }
}

impl hort_domain::ports::claim_mapping_repository::ClaimMappingRepository
    for MockClaimMappingRepository
{
    fn list_all(&self) -> BoxFut<'_, DomainResult<Vec<hort_domain::entities::rbac::ClaimMapping>>> {
        let rows = self.mappings.lock().unwrap().clone();
        Box::pin(async move { Ok(rows) })
    }

    fn list_managed_by_gitops(
        &self,
    ) -> BoxFut<'_, DomainResult<Vec<hort_domain::entities::rbac::ClaimMapping>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn save_managed(
        &self,
        _items: &[hort_domain::entities::rbac::ClaimMapping],
    ) -> BoxFut<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// MockApiTokenRepository
// ---------------------------------------------------------------------------

/// Test fixture for [`ApiTokenRepository`].
///
/// Records every `insert`, `revoke`, and `list_for_user` call so
/// downstream test sites can assert insertion counts, revoked token
/// ids, and pagination shape. The repository is in-memory only —
/// `find_by_prefix` always returns `None` (the validator path's hot
/// lookup belongs in `pat_validation_use_case`'s tests, not here).
pub struct MockApiTokenRepository {
    inserts: Mutex<Vec<hort_domain::entities::api_token::ApiToken>>,
    revokes: Mutex<Vec<Uuid>>,
    by_id: Mutex<HashMap<Uuid, hort_domain::entities::api_token::ApiToken>>,
    list_calls: Mutex<Vec<(Uuid, PageRequest)>>,
    canned_list: Mutex<Vec<hort_domain::entities::api_token::ApiToken>>,
    /// One-shot fail-injection slot for
    /// `insert`. When `Some(_)`, the next call to `insert` returns
    /// `Err(<the stored error>)` and clears the slot, BEFORE any
    /// in-memory append. Mirrors `MockRefRegistry::fail_next_insert`
    /// and ten other `fail_next_*` precedents in this file.
    fail_next_insert: Mutex<Option<DomainError>>,
}

impl Default for MockApiTokenRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl MockApiTokenRepository {
    pub fn new() -> Self {
        Self {
            inserts: Mutex::new(Vec::new()),
            revokes: Mutex::new(Vec::new()),
            by_id: Mutex::new(HashMap::new()),
            list_calls: Mutex::new(Vec::new()),
            canned_list: Mutex::new(Vec::new()),
            fail_next_insert: Mutex::new(None),
        }
    }

    /// Pre-seed a token row reachable via `find_by_id`.
    pub fn seed_token(&self, token: hort_domain::entities::api_token::ApiToken) {
        self.by_id.lock().unwrap().insert(token.id, token);
    }

    /// Arm a one-shot insert failure. The next
    /// call to [`ApiTokenRepository::insert`] returns `Err(err)` and
    /// clears the slot. Subsequent inserts succeed normally. Used by
    /// `crates/hort-http-core` exchange-handler tests to drive the genuine
    /// `infrastructure_error` path on `/api/v1/auth/exchange` without
    /// needing a `force_next_error` hook on `ApiTokenUseCase` itself
    /// (which would require trait-wrapping the concrete use case —
    /// explicitly declined per the architecture rule "outbound ports
    /// are traits, use cases are concrete").
    pub fn fail_next_insert(&self, err: DomainError) {
        *self.fail_next_insert.lock().unwrap() = Some(err);
    }

    /// Pre-seed the list returned from `list_for_user`.
    pub fn seed_list(&self, items: Vec<hort_domain::entities::api_token::ApiToken>) {
        *self.canned_list.lock().unwrap() = items;
    }

    pub fn inserted(&self) -> Vec<hort_domain::entities::api_token::ApiToken> {
        self.inserts.lock().unwrap().clone()
    }

    pub fn revoked(&self) -> Vec<Uuid> {
        self.revokes.lock().unwrap().clone()
    }

    pub fn list_calls(&self) -> Vec<(Uuid, PageRequest)> {
        self.list_calls.lock().unwrap().clone()
    }
}

impl hort_domain::ports::api_token_repository::ApiTokenRepository for MockApiTokenRepository {
    fn insert(
        &self,
        token: &hort_domain::entities::api_token::ApiToken,
    ) -> BoxFut<'_, DomainResult<()>> {
        // Head-of-method fail-injection check.
        // Returns Err BEFORE any in-memory append so failure-injection
        // tests can also assert the row was NOT persisted.
        if let Some(e) = self.fail_next_insert.lock().unwrap().take() {
            return Box::pin(async move { Err(e) });
        }
        self.inserts.lock().unwrap().push(token.clone());
        self.by_id.lock().unwrap().insert(token.id, token.clone());
        Box::pin(async { Ok(()) })
    }

    fn find_by_prefix(
        &self,
        _prefix: &str,
    ) -> BoxFut<'_, DomainResult<Option<hort_domain::entities::api_token::ApiToken>>> {
        Box::pin(async { Ok(None) })
    }

    fn find_by_id(
        &self,
        id: Uuid,
    ) -> BoxFut<'_, DomainResult<hort_domain::entities::api_token::ApiToken>> {
        let result =
            self.by_id
                .lock()
                .unwrap()
                .get(&id)
                .cloned()
                .ok_or_else(|| DomainError::NotFound {
                    entity: "ApiToken",
                    id: id.to_string(),
                });
        Box::pin(async move { result })
    }

    fn list_for_user(
        &self,
        user_id: Uuid,
        page: PageRequest,
    ) -> BoxFut<'_, DomainResult<Page<hort_domain::entities::api_token::ApiToken>>> {
        self.list_calls
            .lock()
            .unwrap()
            .push((user_id, page.clone()));
        let items = self.canned_list.lock().unwrap().clone();
        let total = items.len() as u64;
        Box::pin(async move { Ok(Page { items, total }) })
    }

    fn update_last_used(
        &self,
        _token_id: Uuid,
        _at: DateTime<Utc>,
        _client_ip: Option<&str>,
        _user_agent: Option<&str>,
    ) -> BoxFut<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn revoke(&self, token_id: Uuid) -> BoxFut<'_, DomainResult<()>> {
        self.revokes.lock().unwrap().push(token_id);
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// MockEventStore
// ---------------------------------------------------------------------------

pub struct MockEventStore {
    appended: Mutex<Vec<AppendEvents>>,
    streams: Mutex<HashMap<String, Vec<PersistedEvent>>>,
    /// Category-keyed event lists seeded by
    /// `GroupReconcileUseCase` tests so `read_category` returns a
    /// deterministic cross-stream feed. Tests that do not use
    /// `read_category` ignore this map — it defaults to empty.
    category_events: Mutex<HashMap<StreamCategory, Vec<PersistedEvent>>>,
    /// Global positions at which the NEXT `read_category` call should
    /// fail. Pops the smallest-position failure off the queue on each
    /// call — the sweep's page-boundary-driven read loop then observes
    /// a failure at that page and increments `event_read_error` but
    /// continues. Seeded by `inject_category_error_at_global_position`.
    category_error_positions: Mutex<Vec<u64>>,
    /// When `Some`, the NEXT `append` call returns this error instead
    /// of recording the batch (consumed on fire — resets to `None`).
    /// Mirrors the `fail_next_*` injection hooks on the other mocks;
    /// used to exercise an issuance/audit-append infrastructure-failure
    /// path (e.g. the CliSession JWT mint, which appends
    /// `ApiTokenIssued` but persists no row).
    fail_next_append: Mutex<Option<DomainError>>,
}

impl MockEventStore {
    pub fn new() -> Self {
        Self {
            appended: Mutex::new(Vec::new()),
            streams: Mutex::new(HashMap::new()),
            category_events: Mutex::new(HashMap::new()),
            category_error_positions: Mutex::new(Vec::new()),
            fail_next_append: Mutex::new(None),
        }
    }

    /// Arm the NEXT `append` to fail once with `err`. Consumed on fire.
    pub fn fail_next_append(&self, err: DomainError) {
        *self.fail_next_append.lock().unwrap() = Some(err);
    }

    pub fn appended_batches(&self) -> Vec<AppendEvents> {
        self.appended.lock().unwrap().clone()
    }

    pub fn set_stream(&self, stream_id: &StreamId, events: Vec<PersistedEvent>) {
        self.streams
            .lock()
            .unwrap()
            .insert(stream_id.to_string(), events);
    }

    /// Seed the category feed that [`read_category`] serves. Events
    /// are returned in `global_position` order regardless of insertion
    /// order; tests SHOULD still supply them sorted for readability.
    pub fn set_category(&self, category: StreamCategory, events: Vec<PersistedEvent>) {
        self.category_events
            .lock()
            .unwrap()
            .insert(category, events);
    }

    /// Schedule a read error to be returned when the `read_category`
    /// page boundary ALIGNS with a seeded event at
    /// `trigger_after_global_position` — i.e. the sweep's `from`
    /// pointer matches the target after the page that yielded that
    /// event. The mock returns one event (the trigger), the sweep
    /// processes it, advances `from`, then the next page fails once
    /// and is consumed from the queue. This shape lets tests
    /// seed 3 events where the middle event's post-read fails; events
    /// 1 and 3 still flow through.
    pub fn inject_category_error_after_global_position(&self, trigger_after_global_position: u64) {
        self.category_error_positions
            .lock()
            .unwrap()
            .push(trigger_after_global_position);
    }
}

impl EventStore for MockEventStore {
    fn append(&self, batch: AppendEvents) -> BoxFut<'_, DomainResult<AppendResult>> {
        if let Some(err) = self.fail_next_append.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        let count = batch.events.len() as u64;
        self.appended.lock().unwrap().push(batch);
        Box::pin(async move {
            Ok(AppendResult {
                stream_position: count.saturating_sub(1),
                global_positions: (0..count).collect(),
            })
        })
    }

    fn read_stream(
        &self,
        stream_id: &StreamId,
        _from: ReadFrom,
        max_count: u64,
    ) -> BoxFut<'_, DomainResult<Vec<PersistedEvent>>> {
        let key = stream_id.to_string();
        let events = self
            .streams
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .unwrap_or_default();
        let truncated: Vec<PersistedEvent> = events.into_iter().take(max_count as usize).collect();
        Box::pin(async move { Ok(truncated) })
    }

    fn read_category(
        &self,
        category: StreamCategory,
        from: SubscribeFrom,
        max_count: u64,
    ) -> BoxFut<'_, DomainResult<Vec<PersistedEvent>>> {
        // Resolve the starting position: `SubscribeFrom::Start` →
        // position 0 (return all); `AfterGlobal(n)` → return only
        // events with `global_position > n`.
        let start_exclusive = match from {
            SubscribeFrom::Start => None,
            SubscribeFrom::AfterGlobal(n) => Some(n),
        };

        // Pull the seeded events for this category, sort by
        // `global_position`, filter to the window, and truncate.
        let category_events = self.category_events.lock().unwrap();
        let mut filtered: Vec<PersistedEvent> = category_events
            .get(&category)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|e| match start_exclusive {
                Some(n) => e.global_position > n,
                None => true,
            })
            .collect();
        filtered.sort_by_key(|e| e.global_position);

        // Error injection: if the next page start-exclusive matches
        // any queued trigger, pop the trigger and return an error for
        // THIS page. The sweep treats this as an event_read_error and
        // advances past it (the use case's responsibility, not the
        // mock's).
        if let Some(trigger) = start_exclusive {
            let mut queue = self.category_error_positions.lock().unwrap();
            if let Some(pos) = queue.iter().position(|n| *n == trigger) {
                queue.remove(pos);
                return Box::pin(async move {
                    Err(DomainError::Invariant(
                        "mock event store: injected read_category failure".into(),
                    ))
                });
            }
        }

        let truncated: Vec<PersistedEvent> =
            filtered.into_iter().take(max_count as usize).collect();
        Box::pin(async move { Ok(truncated) })
    }

    // Retention stubs: this is the workhorse mock for hort-app tests. No
    // current test reaches the retention paths, so a panic flags
    // accidental misuse rather than silently masking a coverage hole.
    fn delete_stream(&self, _stream_id: StreamId) -> BoxFut<'_, DomainResult<()>> {
        Box::pin(async { unimplemented!("retention path not exercised by these tests") })
    }

    fn archive_stream(&self, _stream_id: StreamId, _target: &str) -> BoxFut<'_, DomainResult<()>> {
        Box::pin(async { unimplemented!("retention path not exercised by these tests") })
    }
}

// ---------------------------------------------------------------------------
// MockArtifactLifecycle
// ---------------------------------------------------------------------------

/// Records each `commit_transition` call and applies the artifact save
/// to a shared `MockArtifactRepository` so assertions can inspect final state.
///
/// The recorded tuple carries the optional `ArtifactMetadata` too.
/// Existing tests destructure with `(artifact, events, _)` or read
/// the first two tuple fields directly.
pub struct MockArtifactLifecycle {
    transitions: Mutex<Vec<(Artifact, AppendEvents, Option<ArtifactMetadata>)>>,
    artifacts: Arc<MockArtifactRepository>,
    /// Optional handle to the [`MockArtifactMetadataRepository`] so the
    /// mock lifecycle can persist `ArtifactMetadata` through to the
    /// metadata repo when `commit_transition` is called with
    /// `metadata: Some(_)`. The real Postgres adapter writes both the
    /// artifact and its metadata in the same transaction; without this
    /// handle the mock would drop the metadata on the floor and any
    /// test that subsequently reads it back (e.g. OCI manifest serve
    /// resolving the stored `oci_media_type` after a pull-through
    /// ingest) would silently fall through to the
    /// no-metadata-row default. A mirror-smoke
    /// regression once surfaced this gap as a 200-with-wrong-content-
    /// type for multi-arch index pulls.
    ///
    /// Optional rather than required so existing callers that don't
    /// care about metadata read-back keep working unchanged; they pass
    /// `None` (the constructor default) and tests that need fidelity
    /// opt in via [`with_metadata_repo`](Self::with_metadata_repo).
    artifact_metadata: Mutex<Option<Arc<MockArtifactMetadataRepository>>>,
    /// Optional handle to the paired
    /// [`MockEventStore`] so the mock's `commit_scan_result` override
    /// pushes events into `appended_batches()` (mirroring the real
    /// Postgres adapter's "events + projection rows + artifact"
    /// single-tx semantics). Optional: legacy tests that exercise
    /// only `commit_transition` skip the wiring.
    event_store: Mutex<Option<Arc<MockEventStore>>>,
    /// Optional handle to the paired
    /// [`MockScanFindingsRepository`] so `commit_scan_result` records
    /// per-finding rows in the same call.
    scan_findings: Mutex<Option<Arc<MockScanFindingsRepository>>>,
    /// `Vec<(artifact_id, last_scan_at)>` — every
    /// `commit_scan_result` call records the timestamp here so
    /// tests can assert the `last_scan_at` write
    /// landed.
    last_scan_at_writes: Mutex<Vec<(Uuid, DateTime<Utc>)>>,
    /// Every `(artifact_id, sbom_components)` pair
    /// passed through `commit_scan_result_with_score`'s new SBOM arg.
    /// `None` (no SBOM extracted) records as `(artifact_id, None)`;
    /// `Some(slice)` records as `(artifact_id, Some(slice.to_vec()))`.
    /// Tests assert the projection-replace surface received the
    /// expected components in the expected branch.
    sbom_replace_calls: Mutex<Vec<(Uuid, Option<Vec<SbomComponent>>)>>,
    /// Every score-delta passed to
    /// `commit_transition_with_score` /
    /// `commit_scan_result_with_score` lands here. Tests assert that
    /// the projector wired the right delta into the lifecycle call;
    /// the lifecycle adapter (in production) applies the delta inside
    /// the same Postgres tx as the event append.
    score_deltas: Mutex<Vec<(Uuid, ScoreDelta)>>,
    /// When set, `commit_transition` returns this error verbatim without
    /// recording the transition. Used by tests exercising error-path
    /// metric emission (e.g. `register_by_hash` must
    /// tick `hort_ingest_total{result="internal"}` when the lifecycle
    /// port fails to commit the artifact + event atomically).
    next_error: Mutex<Option<DomainError>>,
}

impl MockArtifactLifecycle {
    pub fn new(artifacts: Arc<MockArtifactRepository>) -> Self {
        Self {
            transitions: Mutex::new(Vec::new()),
            artifacts,
            artifact_metadata: Mutex::new(None),
            event_store: Mutex::new(None),
            scan_findings: Mutex::new(None),
            last_scan_at_writes: Mutex::new(Vec::new()),
            score_deltas: Mutex::new(Vec::new()),
            sbom_replace_calls: Mutex::new(Vec::new()),
            next_error: Mutex::new(None),
        }
    }

    /// Wire the mock lifecycle to a [`MockArtifactMetadataRepository`]
    /// so `commit_transition`'s `metadata: Some(_)` argument lands in
    /// the repo (matching the real Postgres adapter's
    /// artifact + metadata atomic write). Builder-style so call sites
    /// stay one expression.
    pub fn with_metadata_repo(self, repo: Arc<MockArtifactMetadataRepository>) -> Self {
        *self.artifact_metadata.lock().unwrap() = Some(repo);
        self
    }

    /// Wire the lifecycle mock to the paired
    /// [`MockEventStore`] + [`MockScanFindingsRepository`] so
    /// `commit_scan_result` simulates the real adapter's atomic
    /// `(events + scan_findings + last_scan_at + artifacts)`
    /// transaction. Builder-style.
    pub fn with_scan_result_paired_mocks(
        self,
        events: Arc<MockEventStore>,
        scan_findings: Arc<MockScanFindingsRepository>,
    ) -> Self {
        *self.event_store.lock().unwrap() = Some(events);
        *self.scan_findings.lock().unwrap() = Some(scan_findings);
        self
    }

    /// Return all recorded `(artifact, events, metadata)` triples.
    pub fn committed_transitions(&self) -> Vec<(Artifact, AppendEvents, Option<ArtifactMetadata>)> {
        self.transitions.lock().unwrap().clone()
    }

    /// Every `commit_scan_result` call's
    /// `(artifact_id, last_scan_at)` pair, in call order. Tests
    /// asserting the denorm write happened use this snapshot.
    pub fn last_scan_at_writes(&self) -> Vec<(Uuid, DateTime<Utc>)> {
        self.last_scan_at_writes.lock().unwrap().clone()
    }

    /// Every `(repository_id, ScoreDelta)` passed to
    /// the `_with_score` lifecycle methods, in call order. Tests
    /// asserting the projector wired the right delta into the
    /// lifecycle call use this snapshot. Empty when callers used the
    /// legacy `commit_transition` / `commit_scan_result` paths
    /// (which forward to the `_with_score` variants with `None`).
    pub fn score_deltas(&self) -> Vec<(Uuid, ScoreDelta)> {
        self.score_deltas.lock().unwrap().clone()
    }

    /// Every `(artifact_id, components_or_none)`
    /// passed to `commit_scan_result_with_score`'s new SBOM-components
    /// argument, in call order. Tests asserting the projection-replace
    /// surface received the right slice (or correctly skipped it for
    /// `None`) use this snapshot.
    pub fn sbom_replace_calls(&self) -> Vec<(Uuid, Option<Vec<SbomComponent>>)> {
        self.sbom_replace_calls.lock().unwrap().clone()
    }

    /// Seed a single failure — the next `commit_transition` call returns
    /// `Err(err)` and records no transition. Cleared after the call.
    pub fn fail_next_commit(&self, err: DomainError) {
        *self.next_error.lock().unwrap() = Some(err);
    }
}

impl ArtifactLifecyclePort for MockArtifactLifecycle {
    fn commit_transition(
        &self,
        artifact: &Artifact,
        events: AppendEvents,
        metadata: Option<ArtifactMetadata>,
    ) -> BoxFut<'_, DomainResult<AppendResult>> {
        if let Some(err) = self.next_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        let count = events.events.len() as u64;
        // Propagate the metadata into the paired metadata repo (when
        // wired). Done before recording the transition so the
        // post-commit observable state is consistent: a reader that
        // calls `find_visible_by_id` then `batch_metadata` sees both
        // rows or neither — same as the real adapter's transaction.
        if let (Some(meta), Some(repo)) = (
            metadata.as_ref(),
            self.artifact_metadata.lock().unwrap().as_ref(),
        ) {
            repo.insert(meta.clone());
        }
        self.transitions
            .lock()
            .unwrap()
            .push((artifact.clone(), events, metadata));
        self.artifacts.insert(artifact.clone());
        Box::pin(async move {
            Ok(AppendResult {
                stream_position: count.saturating_sub(1),
                global_positions: (0..count).collect(),
            })
        })
    }

    fn commit_transition_with_score<'a>(
        &'a self,
        artifact: &'a Artifact,
        events: AppendEvents,
        metadata: Option<ArtifactMetadata>,
        score_delta: Option<(Uuid, ScoreDelta)>,
    ) -> BoxFut<'a, DomainResult<AppendResult>> {
        // Record the score delta first, then
        // forward to the legacy `commit_transition` so the rest of
        // the mock state machine (transitions, artifact insert,
        // metadata) keeps working. Failure-injection (`fail_next_commit`)
        // applies BEFORE the score delta is recorded so a forced
        // error doesn't leave a stray delta in the snapshot.
        Box::pin(async move {
            // Replicate the failure check up front (mirrors the
            // legacy `commit_transition` path).
            if let Some(err) = self.next_error.lock().unwrap().take() {
                return Err(err);
            }
            if let Some((repo_id, delta)) = score_delta {
                self.score_deltas.lock().unwrap().push((repo_id, delta));
            }
            // Now do the same work as `commit_transition` (event
            // recording, artifact save, metadata) without re-running
            // the failure check.
            let count = events.events.len() as u64;
            if let (Some(meta), Some(repo)) = (
                metadata.as_ref(),
                self.artifact_metadata.lock().unwrap().as_ref(),
            ) {
                repo.insert(meta.clone());
            }
            self.transitions
                .lock()
                .unwrap()
                .push((artifact.clone(), events, metadata));
            self.artifacts.insert(artifact.clone());
            Ok(AppendResult {
                stream_position: count.saturating_sub(1),
                global_positions: (0..count).collect(),
            })
        })
    }

    fn commit_scan_result_with_score<'a>(
        &'a self,
        artifact: &'a Artifact,
        events: AppendEvents,
        scan_findings_rows: &'a [ScanFindingsRow],
        last_scan_at: DateTime<Utc>,
        score_delta: Option<(Uuid, ScoreDelta)>,
        sbom_components: Option<&'a [SbomComponent]>,
    ) -> BoxFut<'a, DomainResult<AppendResult>> {
        // Same shape as the with_score variant of
        // commit_transition, but for the scan-result dual-write path.
        let artifact_clone = artifact.clone();
        let events_clone = events.clone();
        let rows = scan_findings_rows.to_vec();
        let count = events_clone.events.len() as u64;
        let sbom_owned: Option<Vec<SbomComponent>> = sbom_components.map(<[_]>::to_vec);

        // Failure injection guard. Mirrors the `commit_transition`
        // path: the failure fires BEFORE any state is recorded, so a
        // forced error doesn't leave a stray entry in the snapshot.
        if let Some(err) = self.next_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }

        if let Some((repo_id, delta)) = score_delta {
            self.score_deltas.lock().unwrap().push((repo_id, delta));
        }
        self.last_scan_at_writes
            .lock()
            .unwrap()
            .push((artifact.id, last_scan_at));
        // Record the SBOM-replace surface BEFORE
        // state mutation so tests asserting "no SBOM ⇒ no projection
        // write recorded" see the absence even when the rest of the
        // dual-write path succeeds.
        self.sbom_replace_calls
            .lock()
            .unwrap()
            .push((artifact.id, sbom_owned));
        self.transitions
            .lock()
            .unwrap()
            .push((artifact_clone.clone(), events_clone.clone(), None));
        self.artifacts.insert(artifact_clone);

        let event_store = self.event_store.lock().unwrap().clone();
        let scan_findings = self.scan_findings.lock().unwrap().clone();

        Box::pin(async move {
            if let Some(es) = event_store.as_ref() {
                use hort_domain::ports::event_store::EventStore as _;
                es.append(events_clone).await?;
            }
            if let Some(sf) = scan_findings.as_ref() {
                if !rows.is_empty() {
                    sf.insert_batch(&rows).await?;
                }
            }
            Ok(AppendResult {
                stream_position: count.saturating_sub(1),
                global_positions: (0..count).collect(),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// MockRepoSecurityScoreRepository
// ---------------------------------------------------------------------------

/// Test mock for the [`RepoSecurityScoreRepository`] outbound port.
///
/// Records every `upsert` call and serves rows from `find` by
/// repository_id. Used by the projector's direct-path tests
/// (`apply` reads-modifies-writes through this mock); the lifecycle
/// dual-write path goes through [`MockArtifactLifecycle::score_deltas`]
/// instead.
pub struct MockRepoSecurityScoreRepository {
    rows: Mutex<HashMap<Uuid, RepoSecurityScore>>,
    upsert_calls: Mutex<Vec<RepoSecurityScore>>,
    next_find_error: Mutex<Option<DomainError>>,
    next_upsert_error: Mutex<Option<DomainError>>,
}

impl MockRepoSecurityScoreRepository {
    pub fn new() -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
            upsert_calls: Mutex::new(Vec::new()),
            next_find_error: Mutex::new(None),
            next_upsert_error: Mutex::new(None),
        }
    }

    /// Pre-seed a row so a subsequent `find` returns it.
    pub fn seed(&self, row: RepoSecurityScore) {
        self.rows.lock().unwrap().insert(row.repository_id, row);
    }

    /// Snapshot of every row passed to `upsert`, in call order.
    pub fn upsert_calls(&self) -> Vec<RepoSecurityScore> {
        self.upsert_calls.lock().unwrap().clone()
    }

    /// Arm the next `find` call to return `Err(err)` instead of a row.
    pub fn fail_next_find(&self, err: DomainError) {
        *self.next_find_error.lock().unwrap() = Some(err);
    }

    /// Arm the next `upsert` call to return `Err(err)` instead of OK.
    pub fn fail_next_upsert(&self, err: DomainError) {
        *self.next_upsert_error.lock().unwrap() = Some(err);
    }
}

impl Default for MockRepoSecurityScoreRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl RepoSecurityScoreRepository for MockRepoSecurityScoreRepository {
    fn upsert<'a>(&'a self, score: &'a RepoSecurityScore) -> BoxFut<'a, DomainResult<()>> {
        if let Some(err) = self.next_upsert_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        let cloned = score.clone();
        self.rows
            .lock()
            .unwrap()
            .insert(cloned.repository_id, cloned.clone());
        self.upsert_calls.lock().unwrap().push(cloned);
        Box::pin(async { Ok(()) })
    }

    fn find(&self, repo_id: Uuid) -> BoxFut<'_, DomainResult<Option<RepoSecurityScore>>> {
        if let Some(err) = self.next_find_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        let v = self.rows.lock().unwrap().get(&repo_id).cloned();
        Box::pin(async move { Ok(v) })
    }
}

// ---------------------------------------------------------------------------
// MockStoragePort
// ---------------------------------------------------------------------------

/// `AsyncRead` that delivers a fixed prefix of valid bytes and then
/// yields `io::ErrorKind::InvalidData` at EOF.
///
/// This is a faithful, dependency-free reproduction of the failure
/// shape `hort_adapters_storage::VerifyingReader` produces when a stored
/// blob has been tampered: bytes flow through normally, and the final
/// (would-be-EOF) `poll_read` errors with `InvalidData` instead of
/// signalling end-of-stream. Used only by `MockStoragePort` when armed
/// via [`MockStoragePort::fail_next_get_truncated`]; it intentionally
/// does NOT depend on `hort-adapters-storage` so the per-format
/// adapter-free dep graph is preserved.
struct TruncatingReader {
    prefix: std::io::Cursor<Vec<u8>>,
    errored: bool,
}

impl TruncatingReader {
    fn new(prefix: Vec<u8>) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            errored: false,
        }
    }
}

impl AsyncRead for TruncatingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.errored {
            // Defensive: a well-behaved consumer stops after the error,
            // but if polled again keep returning the same error rather
            // than spuriously signalling clean EOF.
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CAS integrity failure (simulated): blob tampered",
            )));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.prefix).poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                if buf.filled().len() == before {
                    // Prefix exhausted — this would be EOF for a normal
                    // reader; instead error, exactly as `VerifyingReader`
                    // does on an EOF hash mismatch.
                    self.errored = true;
                    std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "CAS integrity failure (simulated): blob tampered",
                    )))
                } else {
                    std::task::Poll::Ready(Ok(()))
                }
            }
            other => other,
        }
    }
}

/// In-memory storage mock for use case tests.
///
/// Collects streams into `Vec<u8>` (acceptable in tests — test artifacts are
/// small), computes SHA-256, and stores bytes in a `HashMap`.
#[allow(dead_code)]
pub struct MockStoragePort {
    data: Mutex<HashMap<ContentHash, Vec<u8>>>,
    /// Keys that should appear in `list_all` as `ReadError` — injected by
    /// scrub-use-case tests to exercise the per-item error path without
    /// needing a real filesystem failure.
    list_errors: Mutex<Vec<String>>,
    /// Keys that should appear in `list_all` as a regular `Hash` entry
    /// but have NO corresponding `get()` content — tests exercise the
    /// `missing` path by combining this with a plain hash that no
    /// `data` entry serves.
    missing_keys: Mutex<Vec<ContentHash>>,
    /// Hashes whose stored content has been "tampered" — the map key
    /// is the hash the CAS says the content should be, the value is
    /// the actual (wrong) bytes. Allows the scrub tests to exercise
    /// the `hash_mismatch` path without needing a real collision.
    tampered: Mutex<HashMap<ContentHash, Vec<u8>>>,
    /// Keys that should appear in `list_all` as `ShardTruncated` —
    /// injected by scrub-use-case tests to
    /// exercise the `shards_truncated` rollup without needing a real
    /// EINTR/`WouldBlock` race.
    shard_truncations: Mutex<Vec<String>>,
    /// Counter incremented on every `put` call — regardless of success or
    /// dedup. Tests that assert "this code path never reaches storage" use
    /// [`put_call_count`] to verify the guard short-circuited.
    put_calls: AtomicUsize,
    /// When set, the next `put` call
    /// returns this error verbatim **after** incrementing
    /// [`put_calls`] and consuming the input stream. Tests asserting
    /// the use case surfaces a CAS-write failure (e.g.
    /// `record_scan_result` aborting before any event-store
    /// append) seed this slot via [`fail_next_put`].
    inject_put_error: Mutex<Option<DomainError>>,
    /// When set, the put call whose 1-based ordinal
    /// equals or exceeds the threshold returns the seeded error,
    /// after that call drains and stops being matched. Tests that
    /// need to target a SECOND or later put (e.g. the wheel-metadata
    /// CAS write, which fires after the wheel's primary content put)
    /// use this hook rather than [`fail_next_put`] which would fire
    /// on the first call. Set via [`fail_put_after_calls`].
    inject_put_error_after: Mutex<Option<(usize, DomainError)>>,
    /// CAS serve-path coverage — when set for a given
    /// `ContentHash`, the next `get` for that hash returns a reader
    /// that yields the registered prefix bytes and then an
    /// `io::ErrorKind::InvalidData` error at EOF, instead of the
    /// stored content. This reproduces exactly what
    /// `hort_adapters_storage`'s `VerifyingReader` does when a stored
    /// blob has been tampered (valid bytes flow, then the EOF
    /// hash-mismatch poll yields `InvalidData`). Mirrors the
    /// one-shot, consumed-on-use posture of [`fail_next_put`] /
    /// `inject_put_error`. Used by the format-handler integration
    /// tests asserting a storage integrity error fails the HTTP
    /// transfer rather than serving a clean 200.
    inject_get_truncated: Mutex<HashMap<ContentHash, Vec<u8>>>,
    /// When a hash is registered here, EVERY
    /// `get` for that hash returns `Err(NotFound)` (persistent, NOT
    /// consumed on use). Mirrors the `inject_get_truncated` HashMap shape
    /// but is permanent so a retrying reader (e.g. the provenance
    /// orchestrator's `fetch_bundles` 3-attempt loop) fails on every
    /// attempt rather than recovering on the second. Used to drive the
    /// post-proxy bundle re-read failure arm.
    inject_get_error: Mutex<std::collections::HashSet<ContentHash>>,
    /// Counter incremented on every `delete` call — used by the
    /// declared-hash rollback tests to assert the
    /// rollback happened when no other row references the hash, and
    /// was skipped when a row does.
    delete_calls: AtomicUsize,
    /// Hashes observed as `delete` arguments, in call order. Tests that
    /// need to assert WHICH hash was rolled back use this; a bare count
    /// suffices for most cases.
    deleted_hashes: Mutex<Vec<ContentHash>>,
    /// Backend label returned by [`StoragePort::backend_label`]. Defaults
    /// to `"memory"` so scrub-use-case tests can assert the metric's
    /// `backend` label without ambiguity. Tests that explicitly want the
    /// `"filesystem"` or `"object_store"` label override via
    /// [`set_backend_label`].
    backend_label: Mutex<&'static str>,
}

#[allow(dead_code)]
impl MockStoragePort {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
            list_errors: Mutex::new(Vec::new()),
            missing_keys: Mutex::new(Vec::new()),
            tampered: Mutex::new(HashMap::new()),
            shard_truncations: Mutex::new(Vec::new()),
            put_calls: AtomicUsize::new(0),
            delete_calls: AtomicUsize::new(0),
            deleted_hashes: Mutex::new(Vec::new()),
            backend_label: Mutex::new("memory"),
            inject_put_error: Mutex::new(None),
            inject_put_error_after: Mutex::new(None),
            inject_get_truncated: Mutex::new(HashMap::new()),
            inject_get_error: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Seed a one-shot `put` failure. The
    /// next `put` call increments [`put_calls`], drains the input
    /// stream, then returns `Err(err)`. Cleared after the call so the
    /// next `put` succeeds. Useful for testing that
    /// `record_scan_result` aborts cleanly when the CAS write fails
    /// (no event-store append, no per-finding rows persisted).
    pub fn fail_next_put(&self, err: DomainError) {
        *self.inject_put_error.lock().unwrap() = Some(err);
    }

    /// Arm a one-shot `put` failure that fires only
    /// on the `(skip + 1)`-th and later put call.
    ///
    /// The first `skip` puts succeed normally; the next put returns
    /// `Err(err)` and the toggle is consumed (subsequent puts
    /// succeed). Used to target the SECOND put in a sequence (e.g.
    /// the wheel-metadata CAS write that fires after the wheel's
    /// primary content put — see
    /// [`crate::use_cases::ingest_use_case`] wheel-metadata hook).
    /// [`fail_next_put`] does not fit because it would consume on
    /// the first call and fail the wheel's own content put.
    pub fn fail_put_after_calls(&self, skip: usize, err: DomainError) {
        *self.inject_put_error_after.lock().unwrap() = Some((skip, err));
    }

    /// CAS serve-path coverage — arm the next `get` for
    /// `hash` to return a reader that delivers `valid_prefix` and
    /// then yields `io::ErrorKind::InvalidData` at EOF, reproducing
    /// the exact shape `hort_adapters_storage::VerifyingReader`
    /// produces when a stored blob is tampered (the accumulated
    /// SHA-256 does not match the expected `ContentHash`). Consumed
    /// on the next `get` for that hash and then cleared, so a
    /// subsequent `get` falls through to normal stored content.
    /// Mirrors the one-shot posture of [`fail_next_put`]. Used by
    /// the format-handler integration tests asserting a storage
    /// integrity error fails the HTTP transfer (the body stream
    /// errors / truncates before `Content-Length` bytes) rather
    /// than serving a clean, fully-delivered 200.
    pub fn fail_next_get_truncated(&self, hash: ContentHash, valid_prefix: Vec<u8>) {
        self.inject_get_truncated
            .lock()
            .unwrap()
            .insert(hash, valid_prefix);
    }

    /// Register `hash` so EVERY subsequent
    /// `get` for it returns `Err(NotFound)`, permanently (NOT consumed
    /// on use). Unlike [`fail_next_get_truncated`] (one-shot), this fails
    /// a retrying reader on every attempt — required to drive the
    /// provenance orchestrator's post-proxy bundle re-read failure arm,
    /// where `fetch_bundles` retries `FETCH_ATTEMPTS` (3) times and a
    /// one-shot failure would simply recover on the second attempt.
    pub fn fail_get_persistent(&self, hash: ContentHash) {
        self.inject_get_error.lock().unwrap().insert(hash);
    }

    /// Return a snapshot of all stored content hashes.
    pub fn stored_hashes(&self) -> Vec<ContentHash> {
        self.data.lock().unwrap().keys().cloned().collect()
    }

    /// Pre-populate storage with content at a known hash (for download tests).
    pub fn insert_content(&self, hash: ContentHash, content: Vec<u8>) {
        self.data.lock().unwrap().insert(hash, content);
    }

    /// Register a synthetic `StreamItem::ReadError` for `list_all` to
    /// yield. Used by scrub-use-case tests to exercise the
    /// `result="read_error"` emission path.
    pub fn inject_list_error(&self, key: impl Into<String>) {
        self.list_errors.lock().unwrap().push(key.into());
    }

    /// Register a hash that `list_all` will report as present but that
    /// `get()` has no bytes for. Used by scrub-use-case tests to
    /// exercise the `result="missing"` emission path.
    pub fn inject_missing(&self, hash: ContentHash) {
        self.missing_keys.lock().unwrap().push(hash);
    }

    /// Register a hash that `list_all` will report as present, and whose
    /// `get()` returns `content` — but `content` hashes to something
    /// different, simulating a tampered blob. Used by scrub-use-case
    /// tests to exercise the `result="hash_mismatch"` emission path.
    pub fn inject_tampered(&self, hash: ContentHash, content: Vec<u8>) {
        self.tampered.lock().unwrap().insert(hash, content);
    }

    /// Register a synthetic `StreamItem::ShardTruncated` for `list_all`
    /// to yield. Used by scrub-use-case tests
    /// to exercise the `ScrubReport::shards_truncated` rollup without
    /// having to drive a real EINTR/`WouldBlock` race in the
    /// filesystem adapter.
    pub fn inject_shard_truncation(&self, key: impl Into<String>) {
        self.shard_truncations.lock().unwrap().push(key.into());
    }

    /// Override the `backend_label` returned by this mock. Defaults to
    /// `"memory"`; scrub tests that need a catalog-valid label set this
    /// to `"filesystem"` or `"object_store"`.
    pub fn set_backend_label(&self, label: &'static str) {
        *self.backend_label.lock().unwrap() = label;
    }

    /// Number of times `put` has been invoked. Used by tests asserting that
    /// a pre-put validation short-circuit prevented the storage backend
    /// from being touched — the mere fact that `put` returned an `Err`
    /// would not prove this, because other error paths also return `Err`.
    pub fn put_call_count(&self) -> usize {
        self.put_calls.load(Ordering::Relaxed)
    }

    /// Number of times `delete` has been invoked. Used by declared-hash
    /// rollback tests to assert both positive
    /// (rollback happened) and negative (blob shared — rollback
    /// skipped) branches.
    pub fn delete_call_count(&self) -> usize {
        self.delete_calls.load(Ordering::Relaxed)
    }

    /// Snapshot of the hashes passed to `delete`, in call order. Cheap
    /// to clone — tests usually inspect the count, this is the
    /// escape hatch for the rare case that needs to verify WHICH hash
    /// was rolled back.
    pub fn deleted_hashes(&self) -> Vec<ContentHash> {
        self.deleted_hashes.lock().unwrap().clone()
    }
}

impl StoragePort for MockStoragePort {
    fn put(
        &self,
        mut stream: Box<dyn AsyncRead + Send + Unpin>,
    ) -> BoxFut<'_, DomainResult<PutResult>> {
        // 1-based call ordinal (this call is the `call_idx`-th put).
        let call_idx = self.put_calls.fetch_add(1, Ordering::Relaxed) + 1;
        // Capture the seeded failure
        // *before* the async block so the slot is consumed eagerly
        // (matches `fail_next_commit`'s posture on
        // `MockArtifactLifecycle`). The seeded error fires only after
        // the input stream has been drained, mirroring the production
        // adapters' streaming-then-fail order.
        let injected = self.inject_put_error.lock().unwrap().take();
        // Staggered toggle for targeting the second
        // (or later) put. Consume only when `call_idx > skip`;
        // otherwise leave the toggle armed for a later call.
        let injected_after = {
            let mut guard = self.inject_put_error_after.lock().unwrap();
            if let Some((skip, _)) = guard.as_ref() {
                if call_idx > *skip {
                    guard.take().map(|(_, e)| e)
                } else {
                    None
                }
            } else {
                None
            }
        };
        Box::pin(async move {
            let mut buf = Vec::new();
            stream
                .read_to_end(&mut buf)
                .await
                .map_err(|e| DomainError::Invariant(format!("mock storage read failed: {e}")))?;

            if let Some(err) = injected {
                return Err(err);
            }
            if let Some(err) = injected_after {
                return Err(err);
            }

            let size_bytes = buf.len() as u64;
            let hash_hex = format!("{:x}", Sha256::digest(&buf));
            let hash: ContentHash = hash_hex
                .parse()
                .map_err(|e| DomainError::Invariant(format!("invalid hash: {e}")))?;

            let mut data = self.data.lock().unwrap();
            let created = !data.contains_key(&hash);
            data.insert(hash.clone(), buf);
            Ok(PutResult {
                hash,
                size_bytes,
                created,
            })
        })
    }

    fn get(
        &self,
        hash: &ContentHash,
    ) -> BoxFut<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        // A persistent get failure: when `hash`
        // is registered via `fail_get_persistent`, EVERY `get` for it
        // resolves `Err(NotFound)` (never consumed). This fails a
        // retrying reader on every attempt (the provenance
        // orchestrator's `fetch_bundles` loop), driving the post-proxy
        // bundle re-read failure arm. Checked first so it dominates the
        // truncation / tampered / stored-content paths.
        if self.inject_get_error.lock().unwrap().contains(hash) {
            let hash_display = hash.to_string();
            return Box::pin(async move {
                Err(DomainError::NotFound {
                    entity: "content",
                    id: hash_display,
                })
            });
        }
        // CAS serve-path coverage takes highest precedence and
        // is consumed on use: when armed via `fail_next_get_truncated`,
        // return a reader that emits the registered prefix then errors
        // with `io::ErrorKind::InvalidData` at EOF — the exact shape
        // `hort_adapters_storage::VerifyingReader` produces on a tampered
        // blob. `get` itself still resolves `Ok` (the production
        // `download()` use case does not read the stream — the error
        // surfaces only when the HTTP handler streams the body), which
        // is precisely the wiring under test.
        if let Some(prefix) = self.inject_get_truncated.lock().unwrap().remove(hash) {
            let reader = TruncatingReader::new(prefix);
            return Box::pin(
                async move { Ok(Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>) },
            );
        }
        // Tampered entries take precedence: the mock returns the
        // (wrong) bytes the test pre-registered so the scrub use case
        // computes an observed_hash that differs from `hash`.
        let tampered = self.tampered.lock().unwrap().get(hash).cloned();
        let result = tampered.or_else(|| self.data.lock().unwrap().get(hash).cloned());
        let hash_display = hash.to_string();
        Box::pin(async move {
            match result {
                Some(bytes) => {
                    Ok(Box::new(std::io::Cursor::new(bytes)) as Box<dyn AsyncRead + Send + Unpin>)
                }
                None => Err(DomainError::NotFound {
                    entity: "content",
                    id: hash_display,
                }),
            }
        })
    }

    /// Range-honouring read. The mock slices its in-memory `Vec<u8>`
    /// per the resolved offsets, mirroring the production adapters
    /// without filesystem I/O. Same RFC 7233 §2.1 suffix-clamp rule.
    fn get_range(
        &self,
        hash: &ContentHash,
        range: ByteRange,
    ) -> BoxFut<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        let bytes = self.data.lock().unwrap().get(hash).cloned();
        let hash_display = hash.to_string();
        Box::pin(async move {
            let Some(bytes) = bytes else {
                return Err(DomainError::NotFound {
                    entity: "content",
                    id: hash_display,
                });
            };
            let size = bytes.len() as u64;
            let (offset, len) = match range {
                ByteRange::Inclusive { start, end } => (start, end - start + 1),
                ByteRange::From { start } => (start, size - start),
                ByteRange::Suffix { last } => {
                    if last >= size {
                        (0, size)
                    } else {
                        (size - last, last)
                    }
                }
            };
            let off = offset as usize;
            let l = len as usize;
            let slice = bytes[off..(off + l)].to_vec();
            Ok(Box::new(std::io::Cursor::new(slice)) as Box<dyn AsyncRead + Send + Unpin>)
        })
    }

    fn exists(&self, hash: &ContentHash) -> BoxFut<'_, DomainResult<bool>> {
        let exists = self.data.lock().unwrap().contains_key(hash);
        Box::pin(async move { Ok(exists) })
    }

    fn delete(&self, hash: &ContentHash) -> BoxFut<'_, DomainResult<()>> {
        self.delete_calls.fetch_add(1, Ordering::Relaxed);
        self.deleted_hashes.lock().unwrap().push(hash.clone());
        let removed = self.data.lock().unwrap().remove(hash).is_some();
        let hash_display = hash.to_string();
        Box::pin(async move {
            if removed {
                Ok(())
            } else {
                Err(DomainError::NotFound {
                    entity: "content",
                    id: hash_display,
                })
            }
        })
    }

    fn size_of(&self, hash: &ContentHash) -> BoxFut<'_, DomainResult<u64>> {
        let result = match self.data.lock().unwrap().get(hash) {
            Some(bytes) => Ok(bytes.len() as u64),
            None => Err(DomainError::NotFound {
                entity: "content",
                id: hash.to_string(),
            }),
        };
        Box::pin(async move { result })
    }

    fn list_all(&self) -> BoxFuture<'_, DomainResult<BoxStream<'_, StreamItem>>> {
        // Union of:
        //   - hashes in `data` (normal CAS entries)
        //   - tampered hashes (they "exist" per `list_all` but `get`
        //     returns wrong bytes)
        //   - injected missing hashes (they "exist" per `list_all` but
        //     `get` returns NotFound)
        //   - injected list errors (yield as ReadError before hashes).
        //
        // Duplicates are acceptable — the scrubber is idempotent per
        // hash and the metric count reflects what the stream yields.
        let mut items: Vec<StreamItem> = Vec::new();
        for key in self.list_errors.lock().unwrap().iter() {
            items.push(StreamItem::ReadError {
                key: key.clone(),
                err: DomainError::Invariant("injected list error".into()),
            });
        }
        for key in self.shard_truncations.lock().unwrap().iter() {
            items.push(StreamItem::ShardTruncated {
                key: key.clone(),
                err: DomainError::Invariant("injected shard truncation".into()),
            });
        }
        for h in self.data.lock().unwrap().keys() {
            items.push(StreamItem::Hash(h.clone()));
        }
        for h in self.tampered.lock().unwrap().keys() {
            items.push(StreamItem::Hash(h.clone()));
        }
        for h in self.missing_keys.lock().unwrap().iter() {
            items.push(StreamItem::Hash(h.clone()));
        }
        Box::pin(async move {
            let s: BoxStream<'_, StreamItem> = Box::pin(stream::iter(items));
            Ok(s)
        })
    }

    fn backend_label(&self) -> &'static str {
        *self.backend_label.lock().unwrap()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub const VALID_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub fn sample_artifact(status: QuarantineStatus) -> Artifact {
    // The stored column is the observation-window
    // anchor — populated for quarantined/rejected fixtures.
    let quarantine_window_start = match status {
        QuarantineStatus::Quarantined | QuarantineStatus::Rejected => Some(Utc::now()),
        _ => None,
    };
    // A `Rejected` sample artifact defaults to the scan-clearable reason
    // so re-evaluation fixtures (ADR 0041 eligibility guard) admit it;
    // every other status carries no rejection reason.
    let rejection_reason = match status {
        QuarantineStatus::Rejected => Some(RejectionReason::Scanner),
        _ => None,
    };
    Artifact {
        id: Uuid::new_v4(),
        repository_id: Uuid::new_v4(),
        name: "my-pkg".into(),
        name_as_published: "my-pkg".into(),
        version: Some("1.0.0".into()),
        path: "my-pkg/1.0.0/my-pkg-1.0.0.tar.gz".into(),
        size_bytes: 2048,
        sha256_checksum: VALID_SHA256.parse().unwrap(),
        sha1_checksum: None,
        md5_checksum: None,
        content_type: "application/gzip".into(),
        quarantine_status: status,
        rejection_reason,
        quarantine_window_start,
        // Transient computed deadline — hydrated by the use-case layer
        // on read paths; fixtures that exercise `Retry-After` set it
        // explicitly.
        quarantine_deadline: None,
        upstream_published_at: None,
        uploaded_by: None,
        is_deleted: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub fn sample_repository() -> Repository {
    Repository {
        id: Uuid::new_v4(),
        key: format!("repo-{}", Uuid::new_v4()),
        name: "Test Repo".into(),
        description: None,
        format: RepositoryFormat::Generic,
        repo_type: RepositoryType::Hosted,
        storage_backend: "filesystem".into(),
        storage_path: "/data/repos/test".into(),
        upstream_url: None,
        index_upstream_url: None,
        is_public: true,
        download_audit_enabled: false,
        quota_bytes: None,
        replication_priority: ReplicationPriority::OnDemand,
        promotion: None,
        curation_rule_names: Vec::new(),
        index_mode: IndexMode::ReleasedOnly,
        prefetch_policy: PrefetchPolicy::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
        managed_by_digest: None,
    }
}

pub fn api_actor() -> ApiActor {
    ApiActor {
        user_id: Uuid::new_v4(),
    }
}

pub fn dummy_persisted_event(
    stream_id: &StreamId,
    artifact_id: Uuid,
    position: u64,
) -> PersistedEvent {
    PersistedEvent {
        event_id: Uuid::new_v4(),
        stream_id: stream_id.clone(),
        stream_position: position,
        global_position: position + 1,
        event: DomainEvent::ArtifactQuarantined(ArtifactQuarantined {
            artifact_id,
            quarantine_window_start: Utc::now(),
        }),
        correlation_id: Uuid::new_v4(),
        causation_id: None,
        actor: Actor::Api(api_actor()),
        event_version: 1,
        stored_at: Utc::now(),
    }
}

pub fn admin_privileges() -> CallerPrivileges {
    CallerPrivileges {
        is_admin: true,
        is_reviewer: false,
        is_curator: false,
        writable_repository_ids: vec![],
    }
}

pub fn reviewer_privileges() -> CallerPrivileges {
    CallerPrivileges {
        is_admin: false,
        is_reviewer: true,
        is_curator: false,
        writable_repository_ids: vec![],
    }
}

pub fn unprivileged() -> CallerPrivileges {
    CallerPrivileges {
        is_admin: false,
        is_reviewer: false,
        is_curator: false,
        writable_repository_ids: vec![],
    }
}

pub fn write_privileges(repo_ids: Vec<Uuid>) -> CallerPrivileges {
    CallerPrivileges {
        is_admin: false,
        is_reviewer: false,
        is_curator: false,
        writable_repository_ids: repo_ids,
    }
}

// ---------------------------------------------------------------------------
// StubFormatHandler
// ---------------------------------------------------------------------------

/// Test double for the [`FormatHandler`] port.
///
/// `normalize_name` maps each `(raw, out)` tuple in `map` literally; other
/// inputs pass through unchanged. `format_key` returns the caller-supplied
/// `key`, and `metadata_expected_max_bytes` returns `max_bytes` (defaulting
/// to the trait default of 64 KB via [`StubFormatHandler::new`]).
///
/// Used by both `ArtifactUseCase::list_by_raw_name` drift tests and
/// `IngestUseCase` cap-boundary tests — keep it here rather than duplicating
/// across test modules.
pub struct StubFormatHandler {
    pub key: &'static str,
    pub map: Vec<(&'static str, &'static str)>,
    pub max_bytes: usize,
    /// Metadata strategy the stub declares. Defaults to
    /// [`MetadataStrategy::Inline`] (mirroring the trait default).
    /// Ingest-dispatch tests override to
    /// `HashReference { inline_threshold_bytes }`.
    pub strategy: MetadataStrategy,
    /// Summary the stub returns from `extract_metadata_summary`. When
    /// `None`, the trait default (identity) is used. Tests that need to
    /// distinguish the split-payload write from a verbatim pass-through
    /// set a recognisable sentinel value here.
    pub summary: Option<serde_json::Value>,
    /// Canned return value for `classify_group_member`. When `None` the
    /// trait default (also `None`) is preserved; ingest-hook
    /// tests override to `Some(GroupMembership { ... })` to drive the
    /// ingest post-commit hook through the group-add path.
    pub group_membership: Option<GroupMembership>,
    /// Canned return value for `extract_wheel_metadata_bytes`. When
    /// `None` the trait default (`Ok(None)` — "this format/path doesn't
    /// produce wheel METADATA") is preserved; ingest-
    /// hook tests override via [`WheelMetadataStubBehaviour`] to drive
    /// every branch of the post-`ArtifactIngested` extraction hook.
    pub wheel_metadata: Option<WheelMetadataStubBehaviour>,
    /// Spec 075 — when `true`, `collision_key` returns the cargo-style fold
    /// (`Some(lower + _→-)`) so the `ingest_direct` registration-collision
    /// gate engages; when `false` (default) it inherits the trait default
    /// (`None`) and the gate is skipped (npm/pypi behaviour).
    pub collision_fold: bool,
}

/// Canned response shapes for the
/// [`StubFormatHandler`]'s `extract_wheel_metadata_bytes` override.
///
/// Mirrors the production [`PyPiFormatHandler::extract_wheel_metadata_bytes`]'s
/// observed return shape:
///
/// - `EmitBytes(b)` → `Ok(Some(b))` — happy path, the handler returned
///   raw METADATA bytes ready for CAS + `ContentReference`.
/// - `None` → `Ok(None)` — sdist, corrupt-wheel (no `<dist-info>/METADATA`
///   member), or any other "this artifact does not produce PEP 658
///   metadata" non-fatal outcome. The ingest hook treats it as a silent
///   no-op.
/// - `Validation(reason)` → `Err(DomainError::Validation(reason))` —
///   the wheel's METADATA exceeds the 1 MiB cap (the only production
///   path that surfaces `Err(Validation)` today). The ingest hook
///   logs `warn!` and ticks
///   `hort_ingest_total{result="wheel_metadata_extract_failed"}`; the
///   wheel ingest itself remains successful.
#[derive(Debug, Clone)]
pub enum WheelMetadataStubBehaviour {
    /// Return `Ok(Some(bytes))` — happy path.
    EmitBytes(Vec<u8>),
    /// Return `Ok(None)` — non-PEP-658 input (sdist, corrupt wheel).
    None,
    /// Return `Err(DomainError::Validation(reason))` — oversized
    /// METADATA or other validation reject. Non-fatal at the hook.
    Validation(&'static str),
}

impl StubFormatHandler {
    /// Build a stub with default `max_bytes = 64 KB` (matches the trait
    /// default). Callers that need a specific cap set the field directly.
    pub fn new(key: &'static str) -> Self {
        Self {
            key,
            map: Vec::new(),
            max_bytes: 64 * 1024,
            strategy: MetadataStrategy::Inline,
            summary: None,
            group_membership: None,
            wheel_metadata: None,
            collision_fold: false,
        }
    }

    /// Spec 075 — make this stub behave like cargo for the
    /// registration-collision gate: `collision_key` returns
    /// `Some(lower + _→-)`.
    pub fn with_collision_fold(mut self) -> Self {
        self.collision_fold = true;
        self
    }

    /// Override the declared expected max; mirrors per-format overrides
    /// like PyPI's 128 KB or cargo's 16 KB.
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Add a `raw -> out` mapping used by `normalize_name`.
    pub fn with_mapping(mut self, raw: &'static str, out: &'static str) -> Self {
        self.map.push((raw, out));
        self
    }

    /// Flip the declared metadata strategy. Split-dispatch tests
    /// set this to `HashReference { inline_threshold_bytes }` to
    /// exercise the split dispatch.
    pub fn with_strategy(mut self, strategy: MetadataStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Pin the summary value returned from `extract_metadata_summary`.
    /// Used by HashReference tests to verify the event + projection
    /// row carry the summary (not the full payload) after the split.
    pub fn with_summary(mut self, summary: serde_json::Value) -> Self {
        self.summary = Some(summary);
        self
    }

    /// Pin the value returned from `classify_group_member` so
    /// ingest-hook tests can drive the group-add
    /// path without a real multi-file format handler.
    pub fn with_group_membership(mut self, membership: GroupMembership) -> Self {
        self.group_membership = Some(membership);
        self
    }

    /// Pin the canned response shape for
    /// [`FormatHandler::extract_wheel_metadata_bytes`]. The hook in
    /// [`IngestUseCase::ingest_inner`] only invokes the trait method on
    /// `.whl`-suffixed paths, so tests that need to exercise a non-`whl`
    /// path don't bother setting this. See [`WheelMetadataStubBehaviour`]
    /// for the per-variant semantics.
    pub fn with_wheel_metadata(mut self, behaviour: WheelMetadataStubBehaviour) -> Self {
        self.wheel_metadata = Some(behaviour);
        self
    }
}

impl FormatHandler for StubFormatHandler {
    fn format_key(&self) -> &str {
        self.key
    }
    fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
        unimplemented!("StubFormatHandler does not support parse_download_path")
    }
    fn normalize_name(&self, name: &str) -> String {
        for (raw, out) in &self.map {
            if *raw == name {
                return (*out).to_string();
            }
        }
        name.to_string()
    }
    fn collision_key(&self, name: &str) -> Option<String> {
        // Spec 075 — opt into the cargo-style fold only when flagged.
        self.collision_fold
            .then(|| name.to_lowercase().replace('_', "-"))
    }
    fn metadata_expected_max_bytes(&self) -> usize {
        self.max_bytes
    }
    fn metadata_strategy(&self) -> MetadataStrategy {
        self.strategy
    }
    fn extract_metadata_summary(&self, full: &serde_json::Value) -> serde_json::Value {
        self.summary.clone().unwrap_or_else(|| full.clone())
    }
    fn classify_group_member(
        &self,
        _coords: &ArtifactCoords,
        _path: &str,
    ) -> Option<GroupMembership> {
        self.group_membership.clone()
    }
    fn extract_wheel_metadata_bytes(
        &self,
        _coords: &ArtifactCoords,
        _payload: hort_domain::types::PayloadAccess<'_>,
    ) -> DomainResult<Option<bytes::Bytes>> {
        // No override → trait default (Ok(None)). Mirrors every
        // non-PyPI production handler.
        match &self.wheel_metadata {
            None => Ok(None),
            Some(WheelMetadataStubBehaviour::EmitBytes(b)) => {
                Ok(Some(bytes::Bytes::from(b.clone())))
            }
            Some(WheelMetadataStubBehaviour::None) => Ok(None),
            Some(WheelMetadataStubBehaviour::Validation(reason)) => {
                Err(DomainError::Validation((*reason).to_string()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MockIdentityProvider
// ---------------------------------------------------------------------------

/// Deterministic [`IdentityProvider`] double for `AuthenticateUseCase` tests.
///
/// Maps known tokens to pre-registered [`IdpClaims`] via
/// [`register_token`](Self::register_token). Tokens not in the map resolve to
/// [`OidcValidationError::SignatureInvalid`] — the same generic "not
/// cryptographically trustworthy" bucket the production OIDC adapter raises
/// on signature failures, so higher layers can test the error path without
/// running real JWT validation. Tests that need a different failure variant
/// (`Expired`, `ClaimMissing(...)`, etc.) use
/// [`register_error`](Self::register_error).
pub struct MockIdentityProvider {
    claims_by_token: Mutex<HashMap<String, IdpClaims>>,
    errors_by_token: Mutex<HashMap<String, OidcValidationError>>,
}

impl MockIdentityProvider {
    pub fn new() -> Self {
        Self {
            claims_by_token: Mutex::new(HashMap::new()),
            errors_by_token: Mutex::new(HashMap::new()),
        }
    }

    /// Register `claims` as the result of validating `token`. The mock stores
    /// by value — subsequent `validate_token` calls with the same string
    /// return a clone.
    pub fn register_token(&self, token: &str, claims: IdpClaims) {
        self.claims_by_token
            .lock()
            .unwrap()
            .insert(token.to_string(), claims);
    }

    /// Register a specific [`OidcValidationError`] variant as the result of
    /// validating `token`. Lets middleware classifier tests exercise every
    /// path without spinning up the real OIDC adapter + mock IdP server.
    pub fn register_error(&self, token: &str, err: OidcValidationError) {
        self.errors_by_token
            .lock()
            .unwrap()
            .insert(token.to_string(), err);
    }
}

impl IdentityProvider for MockIdentityProvider {
    fn validate_token(&self, token: &str) -> BoxFuture<'_, Result<IdpClaims, OidcValidationError>> {
        // Registered error takes precedence over claims — lets a test
        // "poison" a token that was previously registered with claims.
        if let Some(err) = self.errors_by_token.lock().unwrap().get(token).cloned() {
            return Box::pin(async move { Err(err) });
        }
        let result = self
            .claims_by_token
            .lock()
            .unwrap()
            .get(token)
            .cloned()
            .ok_or(OidcValidationError::SignatureInvalid);
        Box::pin(async move { result })
    }
}

// ---------------------------------------------------------------------------
// MockRefRegistryPort — in-memory read-side mock for MutableRef lookups.
// ---------------------------------------------------------------------------

/// Map-backed mock for the read-only [`RefRegistryPort`].
///
/// Keyed by `(repository_id, namespace, ref_name)` — the same triple that
/// `mutable_refs`' unique index enforces. `RefUseCase` tests seed rows via
/// [`insert`](Self::insert) and assert lookups. `find_by_target` is covered
/// for completeness though the use case under test only exercises `find`.
pub struct MockRefRegistryPort {
    refs: Mutex<HashMap<(Uuid, String, String), MutableRef>>,
}

impl MockRefRegistryPort {
    pub fn new() -> Self {
        Self {
            refs: Mutex::new(HashMap::new()),
        }
    }

    /// Seed a [`MutableRef`] into the mock. Overwrites any prior entry
    /// with the same `(repository_id, namespace, ref_name)` key.
    pub fn insert(&self, r: MutableRef) {
        self.refs.lock().unwrap().insert(
            (r.repository_id, r.namespace.clone(), r.ref_name.clone()),
            r,
        );
    }
}

impl RefRegistryPort for MockRefRegistryPort {
    fn find(
        &self,
        repo: Uuid,
        namespace: &str,
        ref_name: &str,
    ) -> BoxFut<'_, DomainResult<MutableRef>> {
        let key = (repo, namespace.to_string(), ref_name.to_string());
        let result =
            self.refs
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or_else(|| DomainError::NotFound {
                    entity: "MutableRef",
                    id: format!("{repo}/{namespace}/{ref_name}"),
                });
        Box::pin(async move { result })
    }

    fn list(&self, repo: Uuid, namespace: &str) -> BoxFut<'_, DomainResult<Vec<MutableRef>>> {
        let ns = namespace.to_string();
        let mut items: Vec<MutableRef> = self
            .refs
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.repository_id == repo && r.namespace == ns)
            .cloned()
            .collect();
        items.sort_by(|a, b| a.ref_name.cmp(&b.ref_name));
        Box::pin(async move { Ok(items) })
    }

    fn find_by_target(
        &self,
        repo: Uuid,
        target: &RefTarget,
    ) -> BoxFut<'_, DomainResult<Vec<MutableRef>>> {
        let target = target.clone();
        let mut items: Vec<MutableRef> = self
            .refs
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.repository_id == repo && r.target == target)
            .cloned()
            .collect();
        items.sort_by(|a, b| {
            a.namespace
                .cmp(&b.namespace)
                .then_with(|| a.ref_name.cmp(&b.ref_name))
        });
        Box::pin(async move { Ok(items) })
    }
}

// ---------------------------------------------------------------------------
// MockRefLifecyclePort — records move/retire calls + applies projection.
// ---------------------------------------------------------------------------

/// Records each `move_ref` / `retire_ref` call and applies the projection
/// write against a shared [`MockRefRegistryPort`] so assertions can inspect
/// the post-state.
///
/// Mirrors [`MockArtifactLifecycle`]'s shape: two `Mutex<Vec<_>>` of
/// `(entity_post_state, batch)` tuples the tests drain via getter methods,
/// plus atomic call counters so the use case's "no-op short-circuit" test
/// can assert `move_call_count() == 0` after a same-target `set`.
///
/// **Behaviour matches the port contract.** `retire_ref` returns
/// `DomainError::NotFound` when no row exists for the triple — the
/// use case's `retire` test depends on this to assert the `NotFound`
/// propagation without `retire_ref` being called a second time.
pub struct MockRefLifecyclePort {
    refs: Arc<MockRefRegistryPort>,
    moves: Mutex<Vec<(MutableRef, AppendEvents)>>,
    retires: Mutex<Vec<(Uuid, String, String, AppendEvents)>>,
    move_calls: AtomicUsize,
    retire_calls: AtomicUsize,
    /// FIFO queue of outcomes to return from `move_ref`. A
    /// `RefAlreadyExists` entry short-circuits: nothing is recorded,
    /// the projection is untouched, the outcome is returned verbatim.
    /// An empty queue falls through to the default `Committed` path.
    move_injections: Mutex<Vec<RefCommitOutcome>>,
}

impl MockRefLifecyclePort {
    pub fn new(refs: Arc<MockRefRegistryPort>) -> Self {
        Self {
            refs,
            moves: Mutex::new(Vec::new()),
            retires: Mutex::new(Vec::new()),
            move_calls: AtomicUsize::new(0),
            retire_calls: AtomicUsize::new(0),
            move_injections: Mutex::new(Vec::new()),
        }
    }

    /// Enqueue the outcome for the next `move_ref` call. Fires FIFO.
    pub fn inject_move_outcome(&self, outcome: RefCommitOutcome) {
        self.move_injections.lock().unwrap().push(outcome);
    }

    /// Snapshot of every `(ref_post_state, batch)` produced by `move_ref`.
    pub fn recorded_moves(&self) -> Vec<(MutableRef, AppendEvents)> {
        self.moves.lock().unwrap().clone()
    }

    /// Snapshot of every `(repo, namespace, ref_name, batch)` retirement.
    pub fn recorded_retires(&self) -> Vec<(Uuid, String, String, AppendEvents)> {
        self.retires.lock().unwrap().clone()
    }

    /// Total invocations of `move_ref`, including the ones that pass the
    /// adapter's idempotence short-circuit. For the mock the in-trait
    /// path always records, so the counter reflects calls delivered by
    /// the use case.
    pub fn move_call_count(&self) -> usize {
        self.move_calls.load(Ordering::Relaxed)
    }

    /// Total invocations of `retire_ref` regardless of outcome.
    pub fn retire_call_count(&self) -> usize {
        self.retire_calls.load(Ordering::Relaxed)
    }
}

impl RefLifecyclePort for MockRefLifecyclePort {
    fn move_ref(
        &self,
        r: MutableRef,
        batch: AppendEvents,
    ) -> BoxFut<'_, DomainResult<RefCommitOutcome>> {
        self.move_calls.fetch_add(1, Ordering::Relaxed);
        // Pop injection FIRST — a race-lost outcome must NOT record a
        // move, NOR mutate the projection.
        let injection = {
            let mut q = self.move_injections.lock().unwrap();
            if q.is_empty() {
                None
            } else {
                Some(q.remove(0))
            }
        };
        if let Some(outcome) = injection {
            match outcome {
                RefCommitOutcome::Committed => {
                    // Inject a no-op Committed (unused today, but cheap
                    // to support): still records + applies the projection.
                    self.moves.lock().unwrap().push((r.clone(), batch));
                    self.refs.insert(r);
                    return Box::pin(async move { Ok(RefCommitOutcome::Committed) });
                }
                RefCommitOutcome::RefAlreadyExists { existing_id } => {
                    return Box::pin(async move {
                        Ok(RefCommitOutcome::RefAlreadyExists { existing_id })
                    });
                }
            }
        }
        self.moves.lock().unwrap().push((r.clone(), batch));
        self.refs.insert(r);
        Box::pin(async move { Ok(RefCommitOutcome::Committed) })
    }

    fn retire_ref(
        &self,
        repo: Uuid,
        namespace: &str,
        ref_name: &str,
        batch: AppendEvents,
    ) -> BoxFut<'_, DomainResult<()>> {
        self.retire_calls.fetch_add(1, Ordering::Relaxed);
        let key = (repo, namespace.to_string(), ref_name.to_string());
        let existed = self.refs.refs.lock().unwrap().remove(&key).is_some();
        self.retires.lock().unwrap().push((
            repo,
            namespace.to_string(),
            ref_name.to_string(),
            batch,
        ));
        let id = format!("{repo}/{namespace}/{ref_name}");
        Box::pin(async move {
            if existed {
                Ok(())
            } else {
                Err(DomainError::NotFound {
                    entity: "MutableRef",
                    id,
                })
            }
        })
    }
}

// ---------------------------------------------------------------------------
// MockArtifactGroupRepository — read-side mock keyed by
// (repository_id, canonicalised coords) and (artifact_id).
// ---------------------------------------------------------------------------

/// Canonicalise an [`ArtifactCoords`] to the identity-forming JSON
/// shape the real adapter uses for its unique key. Mirrors
/// `coords_to_canonical_json` in `hort-adapters-postgres::artifact_group_repo`
/// but lives here because `hort-app` cannot depend on the adapter crate.
fn canonicalise_coords_for_mock(c: &ArtifactCoords) -> serde_json::Value {
    // `RepositoryFormat` derives Serialize — match the adapter's
    // `serde_json::to_value` path so tests remain byte-stable with
    // the production key.
    let format = serde_json::to_value(&c.format).expect("RepositoryFormat serialises cleanly");
    serde_json::json!({
        "name": c.name,
        "name_as_published": c.name_as_published,
        "version": c.version,
        "format": format,
    })
}

/// Map-backed mock for the read-only [`ArtifactGroupRepository`] port.
///
/// Keyed by `(repository_id, canonical_coords_json)` — the same key the
/// real adapter's unique index enforces. `ArtifactGroupUseCase` tests
/// seed rows via [`insert`](Self::insert) and assert lookups.
pub struct MockArtifactGroupRepository {
    // group rows keyed by (repository_id, canonical_coords_json).
    by_coords: Mutex<HashMap<(Uuid, String), ArtifactGroup>>,
    // group rows keyed by group id for find_by_member lookup.
    by_id: Mutex<HashMap<Uuid, ArtifactGroup>>,
    // member -> group_id mapping.
    member_index: Mutex<HashMap<Uuid, Uuid>>,
}

impl MockArtifactGroupRepository {
    pub fn new() -> Self {
        Self {
            by_coords: Mutex::new(HashMap::new()),
            by_id: Mutex::new(HashMap::new()),
            member_index: Mutex::new(HashMap::new()),
        }
    }

    /// Seed a group. Overwrites any prior entry with the same
    /// `(repository_id, canonical_coords)` key. Indexes every member
    /// for reverse lookup.
    pub fn insert(&self, g: ArtifactGroup) {
        let key = (
            g.repository_id,
            canonicalise_coords_for_mock(&g.coords).to_string(),
        );
        for m in &g.members {
            self.member_index
                .lock()
                .unwrap()
                .insert(m.artifact_id, g.id);
        }
        self.by_id.lock().unwrap().insert(g.id, g.clone());
        self.by_coords.lock().unwrap().insert(key, g);
    }

    /// Append `member` to the group keyed by `group_id`. Updates both
    /// the coords index and the id index so subsequent `find_by_coords`
    /// / `find_by_member` lookups see the new member.
    pub fn push_member(&self, group_id: Uuid, member: &ArtifactGroupMember) {
        let updated = {
            let mut by_id = self.by_id.lock().unwrap();
            let g = by_id.get_mut(&group_id).expect("group exists");
            g.members.push(member.clone());
            g.clone()
        };
        let key = (
            updated.repository_id,
            canonicalise_coords_for_mock(&updated.coords).to_string(),
        );
        self.member_index
            .lock()
            .unwrap()
            .insert(member.artifact_id, group_id);
        self.by_coords.lock().unwrap().insert(key, updated);
    }

    /// Overwrite a group's `primary_role` in both indexes. Used by
    /// the lifecycle mock after a `primary_role_assigned` UPDATE.
    pub fn set_primary_role(&self, group_id: Uuid, role: &str) {
        let updated = {
            let mut by_id = self.by_id.lock().unwrap();
            let g = by_id.get_mut(&group_id).expect("group exists");
            g.primary_role = role.to_string();
            g.clone()
        };
        let key = (
            updated.repository_id,
            canonicalise_coords_for_mock(&updated.coords).to_string(),
        );
        self.by_coords.lock().unwrap().insert(key, updated);
    }
}

impl ArtifactGroupRepository for MockArtifactGroupRepository {
    fn find_by_coords(
        &self,
        repo: Uuid,
        coords: &ArtifactCoords,
    ) -> BoxFuture<'_, DomainResult<Option<ArtifactGroup>>> {
        let key = (repo, canonicalise_coords_for_mock(coords).to_string());
        let result = self.by_coords.lock().unwrap().get(&key).cloned();
        Box::pin(async move { Ok(result) })
    }

    fn find_by_member(
        &self,
        artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Option<ArtifactGroup>>> {
        let gid = self.member_index.lock().unwrap().get(&artifact_id).copied();
        let result = gid.and_then(|id| self.by_id.lock().unwrap().get(&id).cloned());
        Box::pin(async move { Ok(result) })
    }

    fn list_distinct_names(
        &self,
        repo: Uuid,
        primary_role: &str,
        after: Option<&str>,
        limit: u32,
    ) -> BoxFuture<'_, DomainResult<Vec<String>>> {
        let after = after.unwrap_or("").to_string();
        let primary_role = primary_role.to_string();
        let mut names: Vec<String> = self
            .by_id
            .lock()
            .unwrap()
            .values()
            .filter(|g| g.repository_id == repo && g.primary_role == primary_role)
            .map(|g| g.coords.name.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .filter(|n| n.as_str() > after.as_str())
            .collect();
        names.sort();
        let items: Vec<String> = names.into_iter().take(limit as usize).collect();
        Box::pin(async move { Ok(items) })
    }
}

// ---------------------------------------------------------------------------
// MockArtifactGroupLifecyclePort — records commit calls, applies the
// projection write against a shared `MockArtifactGroupRepository`, and
// supports injection of `GroupAlreadyExists` outcomes so the retry loop
// in `ArtifactGroupUseCase::add_member` is testable without a live DB.
// ---------------------------------------------------------------------------

/// One-shot injection queue entry for `commit_member_added`. Each
/// successive call to the port consumes the front of the queue (if
/// any); when the queue is empty the port proceeds with the default
/// Committed path.
#[derive(Debug, Clone)]
pub enum GroupCommitInjection {
    /// Short-circuit the next `commit_member_added` call with
    /// `Ok(GroupAlreadyExists { existing_id })`. No projection or event
    /// application happens.
    AlreadyExists { existing_id: Uuid },
    /// Short-circuit the next `commit_member_added` call with
    /// `Err(DomainError::Conflict(reason))` — used to exercise the
    /// primary-role-assign race path without needing a live DB.
    Conflict { reason: String },
}

pub struct MockArtifactGroupLifecyclePort {
    groups: Arc<MockArtifactGroupRepository>,
    /// Recorded `(change_summary, batch)` for every accepted call.
    /// `change_summary` projects `GroupMemberCommit` to a small
    /// serialisable-in-tests struct; the use case's retry loop is
    /// exercised by asserting on this log.
    commits: Mutex<Vec<RecordedCommit>>,
    removes: Mutex<Vec<(Uuid, Uuid, AppendEvents)>>,
    commit_calls: AtomicUsize,
    remove_calls: AtomicUsize,
    injections: Mutex<Vec<GroupCommitInjection>>,
}

/// Snapshot of one `commit_member_added` call. Only the parts tests
/// inspect — assertions against the entire `GroupMemberCommit` would
/// over-specify and block harmless refactors.
#[derive(Debug, Clone)]
pub struct RecordedCommit {
    pub new_group_id: Option<Uuid>,
    pub member_role: String,
    pub member_artifact_id: Uuid,
    pub primary_role_assigned: Option<String>,
    pub batch: AppendEvents,
}

impl MockArtifactGroupLifecyclePort {
    pub fn new(groups: Arc<MockArtifactGroupRepository>) -> Self {
        Self {
            groups,
            commits: Mutex::new(Vec::new()),
            removes: Mutex::new(Vec::new()),
            commit_calls: AtomicUsize::new(0),
            remove_calls: AtomicUsize::new(0),
            injections: Mutex::new(Vec::new()),
        }
    }

    /// Enqueue an injection that the next `commit_member_added` call
    /// will consume. Injections fire in FIFO order.
    pub fn inject(&self, injection: GroupCommitInjection) {
        self.injections.lock().unwrap().push(injection);
    }

    pub fn recorded_commits(&self) -> Vec<RecordedCommit> {
        self.commits.lock().unwrap().clone()
    }

    pub fn recorded_removes(&self) -> Vec<(Uuid, Uuid, AppendEvents)> {
        self.removes.lock().unwrap().clone()
    }

    pub fn commit_call_count(&self) -> usize {
        self.commit_calls.load(Ordering::Relaxed)
    }

    pub fn remove_call_count(&self) -> usize {
        self.remove_calls.load(Ordering::Relaxed)
    }
}

impl ArtifactGroupLifecyclePort for MockArtifactGroupLifecyclePort {
    fn commit_member_added(
        &self,
        change: GroupMemberCommit,
        batch: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<GroupCommitOutcome>> {
        self.commit_calls.fetch_add(1, Ordering::Relaxed);
        // Pop injection FIRST — a `GroupAlreadyExists` or `Conflict`
        // return must NOT record a commit, NOR mutate the projection.
        let injection = {
            let mut q = self.injections.lock().unwrap();
            if q.is_empty() {
                None
            } else {
                Some(q.remove(0))
            }
        };
        if let Some(inj) = injection {
            return match inj {
                GroupCommitInjection::AlreadyExists { existing_id } => {
                    Box::pin(
                        async move { Ok(GroupCommitOutcome::GroupAlreadyExists { existing_id }) },
                    )
                }
                GroupCommitInjection::Conflict { reason } => {
                    Box::pin(async move { Err(DomainError::Conflict(reason)) })
                }
            };
        }

        // Default happy path: apply the projection write so subsequent
        // `find_by_coords` / `find_by_member` calls see the change.
        if let Some(g) = &change.new_group {
            self.groups.insert(g.clone());
        }
        if let Some(role) = &change.primary_role_assigned {
            // Need the target group id — recover from `new_group`
            // when first-placement, else from the member's already-
            // resolved group (use case carries it via new_group=None
            // + the lifecycle call path — retrievable from the batch's
            // stream id).
            let gid = change
                .new_group
                .as_ref()
                .map(|g| g.id)
                .unwrap_or(batch.stream_id.entity_id);
            self.groups.set_primary_role(gid, role);
        }
        // Append the member to whichever group this call targets.
        let target_group_id = change
            .new_group
            .as_ref()
            .map(|g| g.id)
            .unwrap_or(batch.stream_id.entity_id);
        self.groups.push_member(target_group_id, &change.member);

        self.commits.lock().unwrap().push(RecordedCommit {
            new_group_id: change.new_group.as_ref().map(|g| g.id),
            member_role: change.member.role.clone(),
            member_artifact_id: change.member.artifact_id,
            primary_role_assigned: change.primary_role_assigned.clone(),
            batch,
        });
        Box::pin(async move { Ok(GroupCommitOutcome::Committed) })
    }

    fn commit_member_removed(
        &self,
        group_id: Uuid,
        artifact_id: Uuid,
        batch: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<()>> {
        self.remove_calls.fetch_add(1, Ordering::Relaxed);
        self.removes
            .lock()
            .unwrap()
            .push((group_id, artifact_id, batch));
        Box::pin(async move { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// MockStatefulUploadStagingPort — in-memory HashMap mock for the
// three-phase / chunked stateful upload scratch-space. The real adapter
// writes to disk; the mock keeps the bytes in a `HashMap<Uuid, Vec<u8>>`
// — same address shape, same idempotent-delete contract, zero filesystem
// cost for unit tests.
// ---------------------------------------------------------------------------

/// In-memory mock for [`StatefulUploadStagingPort`]. Appends accumulate
/// in a `Vec<u8>` per session id; `stream_read` returns an `AsyncRead`
/// wrapping a cursor over the bytes; `delete` is idempotent. Matches
/// the real `FilesystemStatefulUploadStaging`'s semantics without
/// touching disk.
pub struct MockStatefulUploadStagingPort {
    chunks: Mutex<HashMap<Uuid, Vec<u8>>>,
}

impl MockStatefulUploadStagingPort {
    pub fn new() -> Self {
        Self {
            chunks: Mutex::new(HashMap::new()),
        }
    }

    /// Number of sessions with at least one chunk staged. Used by
    /// tests asserting delete / GC behaviour.
    pub fn session_count(&self) -> usize {
        self.chunks.lock().unwrap().len()
    }

    /// Total staged bytes for `session_id`, or `None` if no chunk was
    /// ever appended under that id. Used by tests that need to assert
    /// the finalize path drained the correct payload.
    pub fn bytes_for(&self, session_id: Uuid) -> Option<Vec<u8>> {
        self.chunks.lock().unwrap().get(&session_id).cloned()
    }
}

impl StatefulUploadStagingPort for MockStatefulUploadStagingPort {
    fn append(
        &self,
        session_id: Uuid,
        mut stream: Box<dyn AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<u64>> {
        Box::pin(async move {
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.map_err(|e| {
                DomainError::Invariant(format!("mock stateful upload staging read failed: {e}"))
            })?;
            let mut chunks = self.chunks.lock().unwrap();
            let entry = chunks.entry(session_id).or_default();
            entry.extend_from_slice(&buf);
            Ok(entry.len() as u64)
        })
    }

    fn stream_read(
        &self,
        session_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        let result = self
            .chunks
            .lock()
            .unwrap()
            .get(&session_id)
            .cloned()
            .ok_or_else(|| DomainError::NotFound {
                entity: "stateful_upload_staging",
                id: session_id.to_string(),
            });
        Box::pin(async move {
            let bytes = result?;
            Ok(Box::new(std::io::Cursor::new(bytes)) as Box<dyn AsyncRead + Send + Unpin>)
        })
    }

    fn delete(&self, session_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        // Idempotent — missing files are `Ok(())` per the port contract.
        self.chunks.lock().unwrap().remove(&session_id);
        Box::pin(async move { Ok(()) })
    }

    fn list(&self, max: usize) -> BoxFuture<'_, DomainResult<Vec<Uuid>>> {
        // Bounded enumeration — match the filesystem adapter's contract:
        // cap at `max`, ordering unspecified.
        let ids: Vec<Uuid> = self
            .chunks
            .lock()
            .unwrap()
            .keys()
            .copied()
            .take(max)
            .collect();
        Box::pin(async move { Ok(ids) })
    }
}

// ---------------------------------------------------------------------------
// MockContentReferenceIndex — in-memory HashMap mock for the
// generalized content-reference projection (widened to a
// refcount projection).
//
// Keyed by (repository_id, source_artifact_id, kind) to match the
// Postgres adapter's PK shape exactly — upsert semantics fall out of
// `HashMap::insert`, which overwrites within a single key. The same
// source under a different `kind` is a sibling row, NOT a replacement
// (a single `ArtifactIngested` writes a `primary_content`
// row; an OCI manifest with `subject.digest` adds an `oci_subject`
// sibling row; an ingest with a HashReference-strategy metadata blob
// adds a `metadata_blob` sibling). A `Vec<ContentReference>` would
// force the mock to re-implement PK uniqueness in application code
// and quietly diverge from the adapter on that behaviour.
// ---------------------------------------------------------------------------

/// In-memory mock for [`ContentReferenceIndex`]. Entries live in a
/// `HashMap<(Uuid, Uuid, String), ContentReference>` keyed by
/// `(repository_id, source_artifact_id, kind)`, matching the shape of
/// the Postgres table's PRIMARY KEY. `insert` is upsert on the full
/// key (so the same source can hold multiple sibling rows under
/// different kinds simultaneously); `find_by_target` optionally
/// filters by `kind`; `delete_by_source` sweeps every entry whose
/// source matches, regardless of kind.
///
/// Failure-injection hooks (`fail_next_insert`, `fail_next_insert_for_kind`,
/// `fail_next_delete`) cover the warn-on-fail arms in
/// `IngestUseCase`, `QuarantineUseCase`, and `ApplyConfigUseCase`.
/// Those arms log a `tracing::warn!` and return `Ok(())` from the
/// outer use case — the projection write is intentionally post-commit
/// and post-event-append (eventual consistency; the
/// `RefcountReconcileUseCase` sweep heals drift).
/// The toggles let tests branch-cover the `if let Err(e) = …` arms
/// without abandoning the happy-path semantics every other test
/// relies on. The hooks are one-shot: they fire on the next matching
/// call, then clear themselves. `fail_next_insert_for_kind` is the
/// version that targets a specific `kind` value — the only way to
/// reliably exercise the second insert in `ingest_inner` (the
/// `metadata_blob` arm) without also failing the preceding
/// `primary_content` arm.
pub struct MockContentReferenceIndex {
    entries: Mutex<HashMap<(Uuid, Uuid, String), ContentReference>>,
    next_insert_error: Mutex<Option<DomainError>>,
    next_insert_error_for_kind: Mutex<Option<(String, DomainError)>>,
    next_delete_error: Mutex<Option<DomainError>>,
    /// Counts calls to `find_by_sources_and_kind` so
    /// tests can assert the simple-index serve issues exactly ONE
    /// batched lookup (rather than fanning out to N
    /// `find_by_source_and_kind` round-trips per artifact).
    batch_call_count: AtomicUsize,
}

impl MockContentReferenceIndex {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            next_insert_error: Mutex::new(None),
            next_insert_error_for_kind: Mutex::new(None),
            next_delete_error: Mutex::new(None),
            batch_call_count: AtomicUsize::new(0),
        }
    }

    /// Number of times `find_by_sources_and_kind` was
    /// invoked since construction. Used to assert the simple-index
    /// serve fans out exactly ONE batched lookup.
    pub fn batch_call_count(&self) -> usize {
        self.batch_call_count.load(Ordering::SeqCst)
    }

    /// Number of entries currently live in the mock. Used by tests to
    /// assert delete / upsert semantics without driving a full
    /// `find_by_target` round-trip.
    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Arm a one-shot failure on the **next** [`ContentReferenceIndex::insert`]
    /// call regardless of `kind`. The error is consumed by the next call;
    /// subsequent calls succeed unless re-armed. Used by branch-coverage
    /// tests for the warn-on-fail arms when the path under
    /// test only issues one insert call (e.g. the inline-strategy
    /// `ingest_direct` path or `register_by_hash`). For the
    /// `HashReference`-strategy split path, which issues two insert
    /// calls in `(primary_content, metadata_blob)` order, prefer
    /// [`Self::fail_next_insert_for_kind`] to target one arm in
    /// isolation.
    pub fn fail_next_insert(&self, err: DomainError) {
        *self.next_insert_error.lock().unwrap() = Some(err);
    }

    /// Arm a one-shot failure on the **next**
    /// [`ContentReferenceIndex::insert`] call **whose `kind` matches**.
    /// Inserts with a different `kind` are unaffected (they pass through
    /// to the happy path). The error is consumed by the next matching
    /// call. Used by the metadata-blob warn-on-fail branch test to fail
    /// the second insert call on the HashReference split path while
    /// letting the preceding `primary_content` insert succeed.
    pub fn fail_next_insert_for_kind(&self, kind: &str, err: DomainError) {
        *self.next_insert_error_for_kind.lock().unwrap() = Some((kind.to_string(), err));
    }

    /// Arm a one-shot failure on the **next**
    /// [`ContentReferenceIndex::delete_by_source`] call. Used by
    /// branch-coverage tests for the warn-on-fail arms in
    /// the reject paths (`QuarantineUseCase::record_scan_result` and
    /// `ApplyConfigUseCase`'s retroactive-curation rejection). The
    /// rejection itself has already landed by the time this is hit —
    /// the test asserts the outer operation still returns `Ok`, and
    /// asserts the seeded refcount rows are still there (delete
    /// failed → rows remain), so a future change that aborts on
    /// delete-failure would fail this test.
    pub fn fail_next_delete(&self, err: DomainError) {
        *self.next_delete_error.lock().unwrap() = Some(err);
    }
}

impl ContentReferenceIndex for MockContentReferenceIndex {
    fn insert(&self, reference: ContentReference) -> BoxFuture<'_, DomainResult<()>> {
        // Upsert via `HashMap::insert` — the existing entry (if any)
        // for the SAME `(repo, source, kind)` key is replaced, matching
        // the adapter's `ON CONFLICT DO UPDATE` shape. A different
        // `kind` is a different key — a sibling row, not a replacement.
        if let Some(err) = self.next_insert_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        // Kind-targeted toggle — fires only when the inbound kind
        // matches; otherwise leaves the toggle armed for a later call.
        {
            let mut guard = self.next_insert_error_for_kind.lock().unwrap();
            if let Some((target_kind, _)) = guard.as_ref() {
                if target_kind == &reference.kind {
                    let (_, err) = guard.take().expect("just-inspected Some");
                    return Box::pin(async move { Err(err) });
                }
            }
        }
        let key = (
            reference.repository_id,
            reference.source_artifact_id,
            reference.kind.clone(),
        );
        self.entries.lock().unwrap().insert(key, reference);
        Box::pin(async move { Ok(()) })
    }

    fn find_by_target(
        &self,
        repo: Uuid,
        target: &ContentHash,
        kind_filter: Option<&str>,
    ) -> BoxFuture<'_, DomainResult<Vec<ContentReference>>> {
        let target = target.clone();
        let kind_filter = kind_filter.map(str::to_owned);
        let mut out: Vec<ContentReference> = self
            .entries
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.repository_id == repo && e.target_content_hash == target)
            .filter(|e| match kind_filter.as_deref() {
                None => true,
                Some(k) => e.kind == k,
            })
            .cloned()
            .collect();
        // Stable ordering — recorded_at ASC, source_artifact_id ASC.
        // Matches the adapter's ORDER BY so tests that assert on
        // ordering behave identically against either impl.
        out.sort_by(|a, b| {
            a.recorded_at
                .cmp(&b.recorded_at)
                .then_with(|| a.source_artifact_id.cmp(&b.source_artifact_id))
        });
        Box::pin(async move { Ok(out) })
    }

    fn delete_by_source(&self, source: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        // Idempotent — missing entries are `Ok(())` per the port
        // contract (the FK cascade may have already run). Sweeps EVERY
        // kind for the source — matches the adapter's
        // `WHERE source_artifact_id = $1` semantics.
        if let Some(err) = self.next_delete_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        self.entries
            .lock()
            .unwrap()
            .retain(|(_repo, src, _kind), _| *src != source);
        Box::pin(async move { Ok(()) })
    }

    fn find_by_source_and_kind(
        &self,
        repo: Uuid,
        source: Uuid,
        kind: &str,
    ) -> BoxFuture<'_, DomainResult<Option<ContentReference>>> {
        // PK lookup — `(repo, source, kind)` is unique by the
        // adapter contract; the mock keys its `HashMap` on exactly
        // that tuple so this is a one-shot get.
        let entry = self
            .entries
            .lock()
            .unwrap()
            .get(&(repo, source, kind.to_string()))
            .cloned();
        Box::pin(async move { Ok(entry) })
    }

    fn find_by_sources_and_kind(
        &self,
        repo: Uuid,
        sources: &[Uuid],
        kind: &str,
    ) -> BoxFuture<'_, DomainResult<HashMap<Uuid, ContentReference>>> {
        // Batched PK lookup. Records the call so a
        // test can assert "exactly ONE call, not N round-trips".
        self.batch_call_count.fetch_add(1, Ordering::SeqCst);
        let sources_set: std::collections::HashSet<Uuid> = sources.iter().copied().collect();
        let kind = kind.to_string();
        let mut out: HashMap<Uuid, ContentReference> = HashMap::new();
        for ((entry_repo, entry_source, entry_kind), reference) in
            self.entries.lock().unwrap().iter()
        {
            if *entry_repo == repo && entry_kind == &kind && sources_set.contains(entry_source) {
                out.insert(*entry_source, reference.clone());
            }
        }
        Box::pin(async move { Ok(out) })
    }
}

// ---------------------------------------------------------------------------
// MockRepositoryUpstreamMappingRepository — in-memory CRUD mock for
// ---------------------------------------------------------------------------

/// In-memory mock for [`RepositoryUpstreamMappingRepository`]. Entries
/// live in a `HashMap<(Uuid, String), RepositoryUpstreamMapping>` keyed
/// by `(repository_id, path_prefix)`, matching the Postgres adapter's
/// unique constraint exactly. Upsert semantics fall out of
/// `HashMap::insert`; delete is a `remove` call; both forms of `list`
/// scan the values.
pub struct MockRepositoryUpstreamMappingRepository {
    entries: Mutex<HashMap<(Uuid, String), RepositoryUpstreamMapping>>,
}

impl MockRepositoryUpstreamMappingRepository {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl Default for MockRepositoryUpstreamMappingRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl RepositoryUpstreamMappingRepository for MockRepositoryUpstreamMappingRepository {
    fn list_for_repository(
        &self,
        repository_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<RepositoryUpstreamMapping>>> {
        let mut out: Vec<RepositoryUpstreamMapping> = self
            .entries
            .lock()
            .unwrap()
            .values()
            .filter(|m| m.repository_id == repository_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Box::pin(async move { Ok(out) })
    }

    fn list_all(&self) -> BoxFuture<'_, DomainResult<Vec<RepositoryUpstreamMapping>>> {
        let mut out: Vec<RepositoryUpstreamMapping> =
            self.entries.lock().unwrap().values().cloned().collect();
        out.sort_by(|a, b| {
            a.repository_id
                .cmp(&b.repository_id)
                .then_with(|| a.created_at.cmp(&b.created_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        Box::pin(async move { Ok(out) })
    }

    fn upsert(&self, mut mapping: RepositoryUpstreamMapping) -> BoxFuture<'_, DomainResult<()>> {
        // Mirror the adapter's "id stays stable across upsert" rule —
        // when a row already exists at the (repo, prefix) key, keep
        // its id and bump only the mutable fields. The cache-
        // invalidation contract relies on this.
        let key = (mapping.repository_id, mapping.path_prefix.clone());
        let mut guard = self.entries.lock().unwrap();
        if let Some(existing) = guard.get(&key) {
            mapping.id = existing.id;
            mapping.created_at = existing.created_at;
        }
        mapping.updated_at = Utc::now();
        guard.insert(key, mapping);
        Box::pin(async move { Ok(()) })
    }

    fn delete(&self, repository_id: Uuid, path_prefix: &str) -> BoxFuture<'_, DomainResult<()>> {
        let key = (repository_id, path_prefix.to_string());
        self.entries.lock().unwrap().remove(&key);
        Box::pin(async move { Ok(()) })
    }

    // ---- managed-write surface ----

    fn list_managed_by_gitops(
        &self,
    ) -> BoxFuture<'_, DomainResult<Vec<RepositoryUpstreamMapping>>> {
        use hort_domain::entities::managed_by::ManagedBy;
        let mut out: Vec<RepositoryUpstreamMapping> = self
            .entries
            .lock()
            .unwrap()
            .values()
            .filter(|m| m.managed_by == ManagedBy::GitOps)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.repository_id
                .cmp(&b.repository_id)
                .then_with(|| a.path_prefix.cmp(&b.path_prefix))
                .then_with(|| a.id.cmp(&b.id))
        });
        Box::pin(async move { Ok(out) })
    }

    fn save_managed(&self, mapping: &RepositoryUpstreamMapping) -> BoxFuture<'_, DomainResult<()>> {
        use hort_domain::entities::managed_by::ManagedBy;
        // Mirror the adapter's invariant guard.
        let mb = mapping.managed_by;
        if mb != ManagedBy::GitOps {
            return Box::pin(async move {
                Err(DomainError::Invariant(format!(
                    "save_managed called with managed_by={mb} (expected GitOps)"
                )))
            });
        }
        if mapping.managed_by_digest.is_none() {
            return Box::pin(async move {
                Err(DomainError::Invariant(
                    "save_managed called without managed_by_digest".into(),
                ))
            });
        }

        let mut to_store = mapping.clone();
        let key = (to_store.repository_id, to_store.path_prefix.clone());
        let mut guard = self.entries.lock().unwrap();
        if let Some(existing) = guard.get(&key) {
            // Stable-id contract.
            to_store.id = existing.id;
            to_store.created_at = existing.created_at;
        }
        to_store.updated_at = Utc::now();
        guard.insert(key, to_store);
        Box::pin(async move { Ok(()) })
    }

    fn delete_managed_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        use hort_domain::entities::managed_by::ManagedBy;
        // Defensive: only remove if the row is gitops-managed.
        let mut guard = self.entries.lock().unwrap();
        let key_to_remove = guard
            .iter()
            .find(|(_, m)| m.id == id && m.managed_by == ManagedBy::GitOps)
            .map(|(k, _)| k.clone());
        if let Some(key) = key_to_remove {
            guard.remove(&key);
        }
        Box::pin(async move { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// MockUpstreamResolver — synchronous static-table mock.
// ---------------------------------------------------------------------------

/// In-memory mock for [`UpstreamResolver`]. Holds a list of mappings
/// directly (not the grouped HashMap the production
/// `CachingResolver` uses); the resolve algorithm is the same
/// longest-prefix-match logic. Tests that need to exercise the
/// production `ArcSwap` cache wire `CachingResolver` directly; this
/// mock is for `AppContext`-shaped tests that don't care about
/// cache mechanics.
pub struct MockUpstreamResolver {
    mappings: Mutex<Vec<RepositoryUpstreamMapping>>,
}

impl MockUpstreamResolver {
    pub fn new() -> Self {
        Self {
            mappings: Mutex::new(Vec::new()),
        }
    }

    pub fn with_mappings(mappings: Vec<RepositoryUpstreamMapping>) -> Self {
        Self {
            mappings: Mutex::new(mappings),
        }
    }

    pub fn insert(&self, mapping: RepositoryUpstreamMapping) {
        self.mappings.lock().unwrap().push(mapping);
    }

    pub fn entry_count(&self) -> usize {
        self.mappings.lock().unwrap().len()
    }
}

impl Default for MockUpstreamResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamResolver for MockUpstreamResolver {
    fn resolve(
        &self,
        repo_id: Uuid,
        requested_name: &str,
    ) -> Option<(RepositoryUpstreamMapping, String)> {
        use hort_domain::ports::repository_upstream_mapping_repository::UpstreamAuth;
        let guard = self.mappings.lock().unwrap();
        let mut candidates: Vec<&RepositoryUpstreamMapping> = guard
            .iter()
            .filter(|m| m.repository_id == repo_id)
            .collect();
        candidates.sort_by_key(|m| std::cmp::Reverse(m.path_prefix.len()));
        for m in candidates {
            if requested_name.starts_with(&m.path_prefix) {
                let stripped = &requested_name[m.path_prefix.len()..];
                let normalised = if matches!(m.upstream_auth, UpstreamAuth::BearerChallenge)
                    && !stripped.is_empty()
                    && !stripped.contains('/')
                {
                    format!("library/{stripped}")
                } else {
                    stripped.to_string()
                };
                return Some((m.clone(), normalised));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// MockUpstreamProxy — in-memory blob/manifest store keyed by
// (path_prefix, upstream_name, ref).
// ---------------------------------------------------------------------------

/// In-memory mock for [`UpstreamProxy`]. Tests preload responses
/// keyed by `(path_prefix, upstream_name, key)` (where `key` is the
/// digest for blobs or the reference for manifests). `fetch_*`
/// returns the configured payload or
/// `DomainError::Invariant("upstream:not_found:...")` when no entry
/// matches — same sentinel taxonomy the production
/// `HttpUpstreamProxy` uses.
/// Cached blob entry: raw payload + the upstream-declared digest
/// header round-trip + the upstream-declared `Last-Modified` header
/// (the OCI config + layer blob publish-time
/// hint). `last_modified` defaults to `None` for fixtures that don't
/// exercise the hint; the dedicated publish-time-hint tests seed `Some(_)`.
type MockBlobEntry = (Vec<u8>, Option<String>, Option<DateTime<Utc>>);

/// Cached artifact entry: raw payload + the upstream-declared
/// `Last-Modified` header (the cargo `.crate`
/// tarball publish-time hint). `last_modified` defaults to `None`
/// for fixtures that don't exercise the hint.
type MockArtifactEntry = (Vec<u8>, Option<DateTime<Utc>>);

pub struct MockUpstreamProxy {
    blobs: Mutex<HashMap<(String, String, String), MockBlobEntry>>,
    manifests: Mutex<HashMap<(String, String, String), ManifestFetch>>,
    /// One-shot failure for the next `fetch_manifest` call. Drained on
    /// consumption. Used to drive the `UpstreamUnavailable` path
    /// without bringing up an actual upstream — the helper classifies
    /// errors into `UpstreamNotFound` / `UpstreamUnavailable` by
    /// string-matching the rendered domain error, so the injected
    /// error string controls the branch.
    next_manifest_error: Mutex<Option<DomainError>>,
    /// Metadata-fetch fixtures keyed by (path_prefix, path).
    /// Used by pull-through verification tests; ignored if not seeded.
    metadata: Mutex<HashMap<(String, String), Vec<u8>>>,
    /// One-shot failure for the next `fetch_metadata` call.
    next_metadata_error: Mutex<Option<DomainError>>,
    /// Artifact-fetch fixtures keyed by (path_prefix, path). The
    /// stored body is wrapped in a single-chunk BlobStream on read.
    artifacts: Mutex<HashMap<(String, String), MockArtifactEntry>>,
    /// One-shot failure for the next `fetch_artifact` call.
    next_artifact_error: Mutex<Option<DomainError>>,
    /// Referrer fixtures keyed by
    /// `(path_prefix, upstream_name, digest)` (same key shape as
    /// `blobs`). Unseeded keys return the empty "no referrers" default,
    /// matching the production adapter's both-404 outcome.
    referrers: Mutex<HashMap<(String, String, String), Vec<ReferrerDescriptor>>>,
    /// One-shot failure for the next
    /// `fetch_referrers` call. Drained on consumption. Mirrors the
    /// `next_manifest_error` / `next_metadata_error` / `next_artifact_error`
    /// slots; the production arm's referrer-discovery error path
    /// (`warn!` + mode-dependent `apply_fetch_failure`) is only reachable
    /// when `fetch_referrers` itself errors.
    next_referrers_error: Mutex<Option<DomainError>>,
    /// One-shot flag: when set, the next
    /// `fetch_manifest` call returns a `ManifestFetchOutcome` with
    /// `cache_handle: None` (and an otherwise empty envelope) instead of
    /// the seeded fixture. Drives the `land_one_referrer` skip arm that
    /// fires when the upstream manifest fetch yields no cached body.
    next_manifest_no_cache_handle: Mutex<bool>,
}

impl MockUpstreamProxy {
    pub fn new() -> Self {
        Self {
            blobs: Mutex::new(HashMap::new()),
            manifests: Mutex::new(HashMap::new()),
            next_manifest_error: Mutex::new(None),
            metadata: Mutex::new(HashMap::new()),
            next_metadata_error: Mutex::new(None),
            artifacts: Mutex::new(HashMap::new()),
            next_artifact_error: Mutex::new(None),
            referrers: Mutex::new(HashMap::new()),
            next_referrers_error: Mutex::new(None),
            next_manifest_no_cache_handle: Mutex::new(false),
        }
    }

    /// Seed a metadata fixture keyed by `(path_prefix, path)`. Used by
    /// pull-through verification tests. The fixture body is returned
    /// verbatim from `fetch_metadata` regardless of the `accept` list
    /// (production tests don't currently assert on negotiation; the
    /// real adapter's wiremock tests do).
    pub fn insert_metadata(&self, path_prefix: &str, path: &str, body: Vec<u8>) {
        self.metadata
            .lock()
            .unwrap()
            .insert((path_prefix.to_string(), path.to_string()), body);
    }

    /// Seed a one-shot failure on the next `fetch_metadata` call.
    pub fn fail_next_metadata_with(&self, err: DomainError) {
        *self.next_metadata_error.lock().unwrap() = Some(err);
    }

    /// Seed an artifact-stream fixture keyed by `(path_prefix, path)`.
    /// The body is delivered as a single-chunk BlobStream. The
    /// upstream-declared `Last-Modified` header defaults to `None` —
    /// use [`Self::insert_artifact_with_last_modified`] to seed a
    /// fixture exercising the upstream publish-time hint.
    pub fn insert_artifact(&self, path_prefix: &str, path: &str, body: Vec<u8>) {
        self.artifacts
            .lock()
            .unwrap()
            .insert((path_prefix.to_string(), path.to_string()), (body, None));
    }

    /// Seed an artifact-stream fixture with
    /// an upstream-declared `Last-Modified` header. The cargo
    /// publish-time-hint unit test exercises this; default-shaped
    /// fixtures keep using [`Self::insert_artifact`].
    pub fn insert_artifact_with_last_modified(
        &self,
        path_prefix: &str,
        path: &str,
        body: Vec<u8>,
        last_modified: Option<DateTime<Utc>>,
    ) {
        self.artifacts.lock().unwrap().insert(
            (path_prefix.to_string(), path.to_string()),
            (body, last_modified),
        );
    }

    /// Seed a one-shot failure on the next `fetch_artifact` call.
    pub fn fail_next_artifact_with(&self, err: DomainError) {
        *self.next_artifact_error.lock().unwrap() = Some(err);
    }

    /// Seed a one-shot failure on the next `fetch_manifest` call.
    /// Cleared on consumption. Tests that need to
    /// drive the `UpstreamUnavailable` path (5xx / network) inject a
    /// non-`not_found` error here; the helper's string classifier
    /// then routes it to `UpstreamUnavailable` instead of
    /// `UpstreamNotFound`.
    pub fn fail_next_manifest_with(&self, err: DomainError) {
        *self.next_manifest_error.lock().unwrap() = Some(err);
    }

    pub fn insert_blob(
        &self,
        path_prefix: &str,
        upstream_name: &str,
        digest: &str,
        body: Vec<u8>,
        declared_digest: Option<String>,
    ) {
        self.blobs.lock().unwrap().insert(
            (
                path_prefix.to_string(),
                upstream_name.to_string(),
                digest.to_string(),
            ),
            (body, declared_digest, None),
        );
    }

    /// Seed a blob fixture with an
    /// upstream-declared `Last-Modified` header. The OCI
    /// publish-time-hint unit tests exercise this; default-shaped
    /// fixtures keep using [`Self::insert_blob`].
    pub fn insert_blob_with_last_modified(
        &self,
        path_prefix: &str,
        upstream_name: &str,
        digest: &str,
        body: Vec<u8>,
        declared_digest: Option<String>,
        last_modified: Option<DateTime<Utc>>,
    ) {
        self.blobs.lock().unwrap().insert(
            (
                path_prefix.to_string(),
                upstream_name.to_string(),
                digest.to_string(),
            ),
            (body, declared_digest, last_modified),
        );
    }

    pub fn insert_manifest(
        &self,
        path_prefix: &str,
        upstream_name: &str,
        reference: &str,
        manifest: ManifestFetch,
    ) {
        self.manifests.lock().unwrap().insert(
            (
                path_prefix.to_string(),
                upstream_name.to_string(),
                reference.to_string(),
            ),
            manifest,
        );
    }

    /// Seed the referrer descriptors returned by
    /// [`UpstreamProxy::fetch_referrers`] for `(path_prefix,
    /// upstream_name, digest)`. Proxy-provenance tests seed a
    /// Sigstore-bundle referrer here; an unseeded key inherits the
    /// empty default (no upstream signature).
    pub fn insert_referrers(
        &self,
        path_prefix: &str,
        upstream_name: &str,
        digest: &str,
        descriptors: Vec<ReferrerDescriptor>,
    ) {
        self.referrers.lock().unwrap().insert(
            (
                path_prefix.to_string(),
                upstream_name.to_string(),
                digest.to_string(),
            ),
            descriptors,
        );
    }

    /// Seed a one-shot failure on the next
    /// `fetch_referrers` call. Cleared on consumption. Mirrors
    /// [`Self::fail_next_manifest_with`] / [`Self::fail_next_metadata_with`].
    /// The provenance orchestrator's referrer-discovery error arm
    /// (`warn!` + mode-dependent degrade / fail-closed) is only reachable
    /// when this errors.
    pub fn fail_next_referrers_with(&self, err: DomainError) {
        *self.next_referrers_error.lock().unwrap() = Some(err);
    }

    /// Arm the next `fetch_manifest` call to
    /// return a `ManifestFetchOutcome` whose `cache_handle` is `None`
    /// (no cached body), instead of the seeded fixture. One-shot, cleared
    /// on consumption. Drives `land_one_referrer`'s
    /// `let Some(handle) = outcome.cache_handle else { return Ok(false) }`
    /// skip arm.
    pub fn next_manifest_yields_no_cache_handle(&self) {
        *self.next_manifest_no_cache_handle.lock().unwrap() = true;
    }
}

impl Default for MockUpstreamProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamProxy for MockUpstreamProxy {
    fn fetch_blob(
        &self,
        mapping: RepositoryUpstreamMapping,
        upstream_name: String,
        digest: String,
    ) -> BoxFuture<'_, DomainResult<BlobFetch>> {
        let key = (mapping.path_prefix, upstream_name, digest);
        let entry = self.blobs.lock().unwrap().get(&key).cloned();
        Box::pin(async move {
            match entry {
                Some((body, declared, last_modified)) => {
                    use bytes::Bytes;
                    use futures::stream;
                    let stream =
                        stream::once(async move { Ok::<_, std::io::Error>(Bytes::from(body)) });
                    let boxed: BlobStream = Box::pin(stream);
                    Ok(BlobFetch {
                        stream: boxed,
                        declared_digest: declared,
                        last_modified,
                    })
                }
                None => Err(DomainError::Invariant(format!(
                    "upstream:not_found:mock blob {key:?}"
                ))),
            }
        })
    }

    fn fetch_manifest(
        &self,
        mapping: RepositoryUpstreamMapping,
        upstream_name: String,
        reference: String,
        _accept: Vec<String>,
    ) -> BoxFuture<'_, DomainResult<ManifestFetchOutcome>> {
        // The mock keys on (path_prefix, upstream_name, reference)
        // and ignores Accept — production tests don't currently
        // assert on Accept negotiation. Mocks accept the parameter
        // for signature conformance with the real adapter.
        //
        // Fixtures are still seeded as `ManifestFetch`
        // for back-compat with every test in the workspace; the mock
        // shape-converts to the new `ManifestFetchOutcome` here,
        // writing the body to a tempfile so consumers can stream it
        // (the OCI manifest pull-through opens `cache_handle.path`
        // directly; `manifest_body_bytes` was retired in favour of streaming).
        let injected = self.next_manifest_error.lock().unwrap().take();
        // One-shot "no cached body" outcome.
        // Consumed before the fixture lookup so it dominates.
        let no_cache_handle = {
            let mut guard = self.next_manifest_no_cache_handle.lock().unwrap();
            std::mem::replace(&mut *guard, false)
        };
        let key = (mapping.path_prefix, upstream_name, reference);
        let entry = self.manifests.lock().unwrap().get(&key).cloned();
        Box::pin(async move {
            if let Some(err) = injected {
                return Err(err);
            }
            if no_cache_handle {
                return Ok(ManifestFetchOutcome {
                    cache_handle: None,
                    bytes_read: 0,
                    media_type: None,
                    declared_digest: None,
                    last_modified: None,
                });
            }
            let fixture = entry.ok_or_else(|| {
                DomainError::Invariant(format!("upstream:not_found:mock manifest {key:?}"))
            })?;
            let bytes_read = fixture.bytes.len() as u64;
            let cache_handle = crate::project::cache_handle_from_bytes(
                &fixture.bytes,
                format!("mock-manifest:{key:?}"),
            )?;
            Ok(ManifestFetchOutcome {
                cache_handle: Some(cache_handle),
                bytes_read,
                media_type: Some(fixture.media_type),
                declared_digest: fixture.declared_digest,
                last_modified: fixture.last_modified,
            })
        })
    }

    fn fetch_metadata(
        &self,
        mapping: RepositoryUpstreamMapping,
        path: String,
        _accept: Vec<String>,
    ) -> BoxFuture<'_, DomainResult<MetadataFetchOutcome>> {
        // Fixtures are seeded as `Vec<u8>`; the mock
        // writes the body to a tempfile and returns the new
        // `MetadataFetchOutcome` shape. Tests calling
        // `metadata_body_bytes` against the outcome get the same bytes
        // back and the tempfile is cleaned up after.
        let injected = self.next_metadata_error.lock().unwrap().take();
        let key = (mapping.path_prefix, path);
        let entry = self.metadata.lock().unwrap().get(&key).cloned();
        Box::pin(async move {
            if let Some(err) = injected {
                return Err(err);
            }
            let body = entry.ok_or_else(|| {
                DomainError::Invariant(format!("upstream:not_found:mock metadata {key:?}"))
            })?;
            let bytes_read = body.len() as u64;
            let cache_handle =
                crate::project::cache_handle_from_bytes(&body, format!("mock-metadata:{key:?}"))?;
            Ok(MetadataFetchOutcome {
                cache_handle: Some(cache_handle),
                bytes_read,
                last_modified: None,
            })
        })
    }

    fn fetch_artifact(
        &self,
        mapping: RepositoryUpstreamMapping,
        path: String,
    ) -> BoxFuture<'_, DomainResult<ArtifactFetch>> {
        let injected = self.next_artifact_error.lock().unwrap().take();
        let key = (mapping.path_prefix, path);
        let entry = self.artifacts.lock().unwrap().get(&key).cloned();
        Box::pin(async move {
            if let Some(err) = injected {
                return Err(err);
            }
            let (body, last_modified) = entry.ok_or_else(|| {
                DomainError::Invariant(format!("upstream:not_found:mock artifact {key:?}"))
            })?;
            use bytes::Bytes;
            use futures::stream;
            let stream = stream::once(async move { Ok::<_, std::io::Error>(Bytes::from(body)) });
            Ok(ArtifactFetch {
                stream: Box::pin(stream) as BlobStream,
                last_modified,
            })
        })
    }

    fn fetch_referrers(
        &self,
        mapping: RepositoryUpstreamMapping,
        upstream_name: String,
        digest: String,
    ) -> BoxFuture<'_, DomainResult<Vec<ReferrerDescriptor>>> {
        // One-shot injected failure (drained on
        // consumption), mirroring the manifest/metadata/artifact slots.
        // When armed, `fetch_referrers` errors so the orchestrator's
        // referrer-discovery error arm is exercised.
        let injected = self.next_referrers_error.lock().unwrap().take();
        // Same key shape as `blobs` — (path_prefix, upstream_name,
        // digest). An unseeded key returns the empty "no referrers"
        // default, mirroring the production adapter's both-404 outcome
        // (rather than erroring like the manifest/blob lookups, since
        // "no upstream signature" is a normal, non-error result).
        let key = (mapping.path_prefix, upstream_name, digest);
        let entry = self
            .referrers
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .unwrap_or_default();
        Box::pin(async move {
            if let Some(err) = injected {
                return Err(err);
            }
            Ok(entry)
        })
    }
}

// ---------------------------------------------------------------------------
// MockUpstreamMetadataPort — in-memory mock for the
// application-layer `UpstreamMetadataPort`. Keyed on `(format, package)`.
// The default policy for an unseeded `format` is
// `UpstreamFetchError::UnsupportedFormat` — that mirrors the production
// impl's OCI / unknown-format short-circuit and lets
// downstream tests assert that short-circuit without seeding anything.
// ---------------------------------------------------------------------------

/// In-memory mock for
/// [`crate::ports::upstream_metadata::UpstreamMetadataPort`].
/// Tests seed `(format, package)` → response entries
/// via [`Self::insert_versions`]; `list_versions` returns the seeded
/// `Vec<String>` on a hit or the seeded [`UpstreamFetchError`] on a
/// configured error. Any call with an unseeded key collapses to
/// [`UpstreamFetchError::UnsupportedFormat`] — that matches the production
/// dispatch table's "format not in {npm, pypi, cargo}" path.
///
/// Mirrors the shape of every other test-support mock in this module:
/// state is held in `Mutex<HashMap<_, _>>`, the `new()`/`Default` impls
/// take no arguments, `insert_*` seed helpers are inherent methods on
/// the mock, and the trait `impl` returns `BoxFuture<'_, Result<_, _>>`
/// (the workspace convention — no `async_trait`). The mock can be
/// configured to return any [`UpstreamFetchError`] variant so the
/// discovery + self-service-prefetch use-case tests
/// can exercise the full taxonomy.
/// Seeded response on a `(format, package)` key inside
/// [`MockUpstreamMetadataPort`]. `Ok(_)` yields the version list verbatim;
/// `Err(_)` yields the [`UpstreamFetchError`] verbatim.
type MockUpstreamMetadataResponse = Result<Vec<String>, UpstreamFetchError>;

pub struct MockUpstreamMetadataPort {
    /// Keyed on `(format, package)`. Seeded `Ok(...)` returns the version
    /// list verbatim; seeded `Err(_)` returns the error verbatim.
    entries: Mutex<HashMap<(String, String), MockUpstreamMetadataResponse>>,
    /// Optional call-log for tests that want to assert dispatch
    /// happened with the expected arguments. Records `(format, package)`
    /// in call order.
    calls: Mutex<Vec<(String, String)>>,
}

impl MockUpstreamMetadataPort {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Seed a `(format, package)` response. `Ok(_)` yields the version
    /// list; `Err(_)` yields the error. Re-seeding the same key
    /// overwrites the previous entry.
    pub fn insert_versions(
        &self,
        format: &str,
        package: &str,
        response: MockUpstreamMetadataResponse,
    ) {
        self.entries
            .lock()
            .unwrap()
            .insert((format.to_string(), package.to_string()), response);
    }

    /// Snapshot of every `(format, package)` pair passed to
    /// `list_versions`, in call order. Used by use-case tests that
    /// want to assert the use case dispatched with the expected
    /// arguments.
    pub fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().unwrap().clone()
    }
}

impl Default for MockUpstreamMetadataPort {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::ports::upstream_metadata::UpstreamMetadataPort for MockUpstreamMetadataPort {
    fn list_versions<'a>(
        &'a self,
        format: &'a str,
        _mapping: &'a RepositoryUpstreamMapping,
        package: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, UpstreamFetchError>> {
        // Capture the call BEFORE the async block so the lookup keys
        // stay tied to the synchronous borrow.
        self.calls
            .lock()
            .unwrap()
            .push((format.to_string(), package.to_string()));
        let response = self
            .entries
            .lock()
            .unwrap()
            .get(&(format.to_string(), package.to_string()))
            .cloned();
        Box::pin(async move {
            // Unseeded `format` → production OCI / unknown-format
            // short-circuit. The default policy is critical for
            // tests that want to assert the OCI rejection without
            // having to seed the "negative" case.
            response.unwrap_or(Err(UpstreamFetchError::UnsupportedFormat))
        })
    }
}

#[cfg(test)]
mod upstream_metadata_mock_tests {
    //! Per-variant behavioural coverage for `MockUpstreamMetadataPort`.
    //!
    //! Every [`UpstreamFetchError`] variant must be configurable so
    //! The discovery / self-service-prefetch use-case tests can
    //! exercise the full taxonomy.

    use super::*;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    use uuid::Uuid;

    use crate::metrics::UpstreamFetchError;
    use crate::ports::upstream_metadata::UpstreamMetadataPort;

    fn mapping() -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path_prefix: String::new(),
            upstream_url: "https://upstream.example/".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn happy_path_returns_seeded_versions() {
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions("npm", "left-pad", Ok(vec!["1.0.0".into(), "1.1.0".into()]));
        let got = mock
            .list_versions("npm", &mapping(), "left-pad")
            .await
            .expect("seeded Ok response");
        assert_eq!(got, vec!["1.0.0".to_string(), "1.1.0".to_string()]);
    }

    #[tokio::test]
    async fn default_policy_returns_unsupported_format_for_unseeded_key() {
        let mock = MockUpstreamMetadataPort::new();
        let got = mock
            .list_versions("oci", &mapping(), "library/alpine")
            .await;
        assert_eq!(got, Err(UpstreamFetchError::UnsupportedFormat));
    }

    #[tokio::test]
    async fn seeded_not_found_propagates() {
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions("npm", "missing", Err(UpstreamFetchError::NotFound));
        let got = mock.list_versions("npm", &mapping(), "missing").await;
        assert_eq!(got, Err(UpstreamFetchError::NotFound));
    }

    #[tokio::test]
    async fn seeded_unauthorized_propagates() {
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions("npm", "p", Err(UpstreamFetchError::Unauthorized));
        let got = mock.list_versions("npm", &mapping(), "p").await;
        assert_eq!(got, Err(UpstreamFetchError::Unauthorized));
    }

    #[tokio::test]
    async fn seeded_rate_limited_propagates() {
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions("pypi", "p", Err(UpstreamFetchError::RateLimited));
        let got = mock.list_versions("pypi", &mapping(), "p").await;
        assert_eq!(got, Err(UpstreamFetchError::RateLimited));
    }

    #[tokio::test]
    async fn seeded_upstream_4xx_propagates() {
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions(
            "cargo",
            "serde",
            Err(UpstreamFetchError::Upstream4xx { status: 418 }),
        );
        let got = mock.list_versions("cargo", &mapping(), "serde").await;
        assert_eq!(got, Err(UpstreamFetchError::Upstream4xx { status: 418 }));
    }

    #[tokio::test]
    async fn seeded_upstream_5xx_propagates() {
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions(
            "npm",
            "p",
            Err(UpstreamFetchError::Upstream5xx { status: 503 }),
        );
        let got = mock.list_versions("npm", &mapping(), "p").await;
        assert_eq!(got, Err(UpstreamFetchError::Upstream5xx { status: 503 }));
    }

    #[tokio::test]
    async fn seeded_network_error_propagates() {
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions(
            "npm",
            "p",
            Err(UpstreamFetchError::NetworkError("dns".into())),
        );
        let got = mock.list_versions("npm", &mapping(), "p").await;
        assert_eq!(got, Err(UpstreamFetchError::NetworkError("dns".into())));
    }

    #[tokio::test]
    async fn seeded_timeout_propagates() {
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions("npm", "p", Err(UpstreamFetchError::Timeout));
        let got = mock.list_versions("npm", &mapping(), "p").await;
        assert_eq!(got, Err(UpstreamFetchError::Timeout));
    }

    #[tokio::test]
    async fn seeded_parse_error_propagates() {
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions(
            "npm",
            "p",
            Err(UpstreamFetchError::ParseError("packument".into())),
        );
        let got = mock.list_versions("npm", &mapping(), "p").await;
        assert_eq!(got, Err(UpstreamFetchError::ParseError("packument".into())),);
    }

    #[tokio::test]
    async fn seeded_unsupported_format_propagates() {
        // Explicit seed (vs. default-policy fallthrough) — also a
        // valid Err response. Exercising the explicit path locks the
        // mock's seed path against future refactors that might forget
        // to honour an explicit `Err(UnsupportedFormat)` seed.
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions("npm", "p", Err(UpstreamFetchError::UnsupportedFormat));
        let got = mock.list_versions("npm", &mapping(), "p").await;
        assert_eq!(got, Err(UpstreamFetchError::UnsupportedFormat));
    }

    #[tokio::test]
    async fn calls_records_dispatch_order() {
        let mock = MockUpstreamMetadataPort::new();
        mock.insert_versions("npm", "a", Ok(vec!["1".into()]));
        mock.insert_versions("pypi", "b", Ok(vec!["2".into()]));
        let _ = mock.list_versions("npm", &mapping(), "a").await;
        let _ = mock.list_versions("pypi", &mapping(), "b").await;
        let _ = mock.list_versions("oci", &mapping(), "c").await; // unsupported
        assert_eq!(
            mock.calls(),
            vec![
                ("npm".to_string(), "a".to_string()),
                ("pypi".to_string(), "b".to_string()),
                ("oci".to_string(), "c".to_string()),
            ],
        );
    }

    #[test]
    fn default_constructs_empty_mock() {
        let mock = MockUpstreamMetadataPort::default();
        assert!(mock.calls().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Tests for the content-reference / upstream-mapping mock ports. The
// proxy / pull-through use-case tests lean on these behaviours — a bug
// here will manifest as a confusing failure elsewhere, so pin the
// contracts here.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// MockScanFindingsRepository
// ---------------------------------------------------------------------------

/// Test mock for the [`ScanFindingsRepository`] outbound port.
///
/// Records every `insert_batch` call so tests can assert which rows
/// were persisted alongside a `ScanCompleted` event append. A mock
/// failure can be armed via [`fail_next_insert`].
#[allow(dead_code)]
pub struct MockScanFindingsRepository {
    inserted: Mutex<Vec<Vec<ScanFindingsRow>>>,
    next_error: Mutex<Option<DomainError>>,
}

#[allow(dead_code)]
impl MockScanFindingsRepository {
    pub fn new() -> Self {
        Self {
            inserted: Mutex::new(Vec::new()),
            next_error: Mutex::new(None),
        }
    }

    /// Snapshot of every batch passed to `insert_batch`, in call
    /// order. Each batch is the rows vec for one
    /// `record_scan_result` invocation.
    pub fn inserted_batches(&self) -> Vec<Vec<ScanFindingsRow>> {
        self.inserted.lock().unwrap().clone()
    }

    /// Total row count across every batch.
    pub fn total_inserted(&self) -> usize {
        self.inserted.lock().unwrap().iter().map(Vec::len).sum()
    }

    /// Arm the next `insert_batch` to return `Err(err)` instead of
    /// recording the rows. Cleared after the next call.
    pub fn fail_next_insert(&self, err: DomainError) {
        *self.next_error.lock().unwrap() = Some(err);
    }
}

impl Default for MockScanFindingsRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanFindingsRepository for MockScanFindingsRepository {
    fn insert_batch<'a>(&'a self, rows: &'a [ScanFindingsRow]) -> BoxFut<'a, DomainResult<()>> {
        if let Some(err) = self.next_error.lock().unwrap().take() {
            return Box::pin(async move { Err(err) });
        }
        self.inserted.lock().unwrap().push(rows.to_vec());
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// MockJobsRepository
// ---------------------------------------------------------------------------

/// Mock [`JobsRepository`] used by `hort-http-admin-tasks` handler tests
/// via `build_mock_ctx` in `hort-http-core::test_support`.
///
/// Records calls to `enqueue_task` and `delete_job`. Supports seeding:
/// - `enqueue_task` returns a configurable `Uuid` (default `Uuid::new_v4()`
///   per call, each time recording the call).
/// - `list_jobs` returns a seeded `Vec<JobRow>`.
/// - `get_job` returns a seeded `HashMap<Uuid, JobRow>`.
///
/// All other `JobsRepository` methods delegate to the trait defaults
/// (which return `Err(Invariant)`) to keep the mock minimal.
pub struct MockJobsRepository {
    enqueue_calls: Mutex<Vec<(String, serde_json::Value, Option<Uuid>)>>,
    /// Recorded `idempotency_key` arguments
    /// from `enqueue_task` calls (cloned per call; one entry per call
    /// in `enqueue_calls`, in lock-step). Handler tests assert that the
    /// destructive-kind path passes `Some(server-derived-key)` while
    /// the non-destructive path passes `None`.
    enqueue_idem_keys: Mutex<Vec<Option<hort_domain::types::IdempotencyKey>>>,
    /// When `Some`, the NEXT `enqueue_task`
    /// call returns `EnqueueOutcome::Duplicate { existing_job_id }`
    /// instead of `Enqueued`. One-shot, mirrors the `fail_next_enqueue`
    /// API shape.
    next_duplicate: Mutex<Option<Uuid>>,
    delete_calls: Mutex<Vec<Uuid>>,
    list_rows: Mutex<Vec<JobRow>>,
    get_rows: Mutex<HashMap<Uuid, JobRow>>,
    /// When `Some`, `enqueue_task` returns this error instead of Ok.
    enqueue_error: Mutex<Option<DomainError>>,
    /// Rows returned by `claim_pending_by_kinds`. Each call pops the
    /// front batch (worker dispatcher tests).
    claim_batches: Mutex<Vec<Vec<JobRow>>>,
    /// Recorded calls to `mark_completed`.
    mark_completed_calls: Mutex<Vec<Uuid>>,
    /// Recorded calls to `reschedule`.
    reschedule_calls: Mutex<Vec<(Uuid, String)>>,
    /// Recorded calls to `mark_failed`.
    mark_failed_calls: Mutex<Vec<(Uuid, String)>>,
    /// Seed map returned by
    /// `find_active_scan_for_artifact`. `(artifact_id) -> existing job_id`.
    /// Empty by default (the manual-rescan use case sees "no in-flight
    /// scan" and proceeds to enqueue).
    active_scans: Mutex<HashMap<Uuid, Uuid>>,
    /// Recorded calls to `enqueue_scan`.
    enqueue_scan_calls: Mutex<Vec<EnqueueScanCall>>,
    /// When `Some`, `enqueue_scan` returns this error instead of Ok.
    enqueue_scan_error: Mutex<Option<DomainError>>,
    /// Recorded rows passed to
    /// `enqueue_prefetch_batch`. Each call appends the whole batch
    /// (so the test can read how many cohorts the cascade ran).
    prefetch_batch_calls: Mutex<Vec<Vec<hort_domain::ports::jobs_repository::PrefetchEnqueueRow>>>,
    /// Set of `target_key`s already in-flight (the
    /// L3 partial unique index simulation). A row whose `target_key`
    /// is already in this set is dropped from the returned Uuid
    /// vector (mirrors `ON CONFLICT DO NOTHING`).
    prefetch_seen_keys: Mutex<std::collections::HashSet<String>>,
    /// When `Some`, `enqueue_prefetch_batch`
    /// returns this error on the next call (one-shot).
    prefetch_batch_error: Mutex<Option<DomainError>>,
    /// Recorded calls to
    /// `delete_terminal_prefetch_rows_older_than`. Each call appends
    /// the `Duration` argument.
    prefetch_retention_calls: Mutex<Vec<std::time::Duration>>,
    /// When `Some`, the retention sweep returns
    /// this row count instead of the seeded list.
    prefetch_retention_deleted_count: Mutex<Option<u64>>,
}

/// Recorded call to `enqueue_scan` — used by the manual-rescan use case
/// tests to assert the priority + trigger_source
/// the use case bound were the contracted values (priority=20,
/// trigger_source="manual").
#[derive(Debug, Clone)]
pub struct EnqueueScanCall {
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub content_hash: ContentHash,
    pub format: String,
    pub priority: i16,
    pub trigger_source: String,
}

impl Default for MockJobsRepository {
    fn default() -> Self {
        Self {
            enqueue_calls: Mutex::new(Vec::new()),
            enqueue_idem_keys: Mutex::new(Vec::new()),
            next_duplicate: Mutex::new(None),
            delete_calls: Mutex::new(Vec::new()),
            list_rows: Mutex::new(Vec::new()),
            get_rows: Mutex::new(HashMap::new()),
            enqueue_error: Mutex::new(None),
            claim_batches: Mutex::new(Vec::new()),
            mark_completed_calls: Mutex::new(Vec::new()),
            reschedule_calls: Mutex::new(Vec::new()),
            mark_failed_calls: Mutex::new(Vec::new()),
            active_scans: Mutex::new(HashMap::new()),
            enqueue_scan_calls: Mutex::new(Vec::new()),
            enqueue_scan_error: Mutex::new(None),
            prefetch_batch_calls: Mutex::new(Vec::new()),
            prefetch_seen_keys: Mutex::new(std::collections::HashSet::new()),
            prefetch_batch_error: Mutex::new(None),
            prefetch_retention_calls: Mutex::new(Vec::new()),
            prefetch_retention_deleted_count: Mutex::new(None),
        }
    }
}

impl MockJobsRepository {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed rows returned by `list_jobs`.
    pub fn seed_list(&self, rows: Vec<JobRow>) {
        *self.list_rows.lock().unwrap() = rows;
    }

    /// Seed a single row returned by `get_job` for a specific id.
    pub fn seed_get(&self, row: JobRow) {
        self.get_rows.lock().unwrap().insert(row.id, row);
    }

    /// Configure `enqueue_task` to return an error on the next call (one-shot).
    pub fn fail_next_enqueue(&self, err: DomainError) {
        *self.enqueue_error.lock().unwrap() = Some(err);
    }

    /// Configure `enqueue_task` to return
    /// `EnqueueOutcome::Duplicate { existing_job_id }` on the next call
    /// (one-shot). Used by handler tests that exercise the DB-layer
    /// dedup-hit shape without spinning up a real Postgres.
    pub fn seed_next_enqueue_duplicate(&self, existing_job_id: Uuid) {
        *self.next_duplicate.lock().unwrap() = Some(existing_job_id);
    }

    /// Recorded `(kind, params, actor_id)` tuples from `enqueue_task` calls.
    pub fn enqueue_calls(&self) -> Vec<(String, serde_json::Value, Option<Uuid>)> {
        self.enqueue_calls.lock().unwrap().clone()
    }

    /// Recorded `idempotency_key` arguments
    /// from `enqueue_task` calls, in lock-step with [`enqueue_calls`].
    /// Each entry is `Some(_)` when the caller passed a key (the
    /// destructive-kind path) or `None` for the non-destructive path.
    pub fn enqueue_idem_keys(&self) -> Vec<Option<hort_domain::types::IdempotencyKey>> {
        self.enqueue_idem_keys.lock().unwrap().clone()
    }

    /// Recorded job ids passed to `delete_job`.
    pub fn delete_calls(&self) -> Vec<Uuid> {
        self.delete_calls.lock().unwrap().clone()
    }

    /// Seed a batch that will be returned on the next `claim_pending_by_kinds` call.
    /// Multiple batches can be seeded; each call pops the front.
    pub fn seed_claim_batch(&self, rows: Vec<JobRow>) {
        self.claim_batches.lock().unwrap().push(rows);
    }

    /// Recorded job ids passed to `mark_completed`.
    pub fn mark_completed_calls(&self) -> Vec<Uuid> {
        self.mark_completed_calls.lock().unwrap().clone()
    }

    /// Recorded `(job_id, last_error)` pairs passed to `reschedule`.
    pub fn reschedule_calls(&self) -> Vec<(Uuid, String)> {
        self.reschedule_calls.lock().unwrap().clone()
    }

    /// Recorded `(job_id, last_error)` pairs passed to `mark_failed`.
    pub fn mark_failed_calls(&self) -> Vec<(Uuid, String)> {
        self.mark_failed_calls.lock().unwrap().clone()
    }

    /// Seed an in-flight scan job for an
    /// artifact so `find_active_scan_for_artifact(artifact_id)` returns
    /// `Ok(Some(existing_job_id))`. Used by `ManualRescanUseCase`
    /// conflict-detection tests.
    pub fn seed_active_scan(&self, artifact_id: Uuid, job_id: Uuid) {
        self.active_scans
            .lock()
            .unwrap()
            .insert(artifact_id, job_id);
    }

    /// Recorded `enqueue_scan` calls. Used to
    /// assert the manual-rescan use case bound the documented
    /// `priority=20` / `trigger_source="manual"` contract.
    pub fn enqueue_scan_calls(&self) -> Vec<EnqueueScanCall> {
        self.enqueue_scan_calls.lock().unwrap().clone()
    }

    /// Configure `enqueue_scan` to return an
    /// error on the next call (one-shot). Used to test the use case's
    /// error-propagation path when the underlying port surfaces a
    /// `Conflict` from the partial-unique-index race.
    pub fn fail_next_enqueue_scan(&self, err: DomainError) {
        *self.enqueue_scan_error.lock().unwrap() = Some(err);
    }

    /// Recorded `enqueue_prefetch_batch` calls.
    /// Each call appends the whole batch; the test reads
    /// `len() == 1` for a single-cohort cascade and inspects the
    /// `target_key`s of the first entry.
    pub fn prefetch_batch_calls(
        &self,
    ) -> Vec<Vec<hort_domain::ports::jobs_repository::PrefetchEnqueueRow>> {
        self.prefetch_batch_calls.lock().unwrap().clone()
    }

    /// Seed an already-in-flight target_key under
    /// `kind` so the L3-dedup partial unique index simulator drops
    /// it from the returned id vector (mirrors `ON CONFLICT DO
    /// NOTHING`). The mock keys the seen set as
    /// `"{kind}::{target_key}"` to match the per-kind disjoint
    /// partial unique indexes in production.
    pub fn seed_prefetch_inflight_target_key(
        &self,
        kind: impl Into<String>,
        key: impl Into<String>,
    ) {
        self.prefetch_seen_keys
            .lock()
            .unwrap()
            .insert(format!("{}::{}", kind.into(), key.into()));
    }

    /// Configure `enqueue_prefetch_batch` to return
    /// an error on the next call (one-shot).
    pub fn fail_next_prefetch_batch(&self, err: DomainError) {
        *self.prefetch_batch_error.lock().unwrap() = Some(err);
    }

    /// Recorded calls to
    /// `delete_terminal_prefetch_rows_older_than`. Each call appends
    /// the horizon argument the sweep ran with.
    pub fn prefetch_retention_calls(&self) -> Vec<std::time::Duration> {
        self.prefetch_retention_calls.lock().unwrap().clone()
    }

    /// Make `delete_terminal_prefetch_rows_older_than`
    /// return the configured row count on the next call. Default is 0.
    pub fn set_prefetch_retention_deleted_count(&self, count: u64) {
        *self.prefetch_retention_deleted_count.lock().unwrap() = Some(count);
    }
}

impl JobsRepository for MockJobsRepository {
    fn claim_scan_jobs<'a>(
        &'a self,
        _worker_id: &'a str,
        _batch_size: u32,
        _lock_duration: std::time::Duration,
    ) -> BoxFuture<'a, DomainResult<Vec<ScanJob>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn mark_completed<'a>(
        &'a self,
        job_id: Uuid,
        _result_summary: serde_json::Value,
    ) -> BoxFuture<'a, DomainResult<()>> {
        self.mark_completed_calls.lock().unwrap().push(job_id);
        Box::pin(async { Ok(()) })
    }

    fn reschedule<'a>(
        &'a self,
        job_id: Uuid,
        _backoff: std::time::Duration,
        last_error: &'a str,
    ) -> BoxFuture<'a, DomainResult<()>> {
        self.reschedule_calls
            .lock()
            .unwrap()
            .push((job_id, last_error.to_string()));
        Box::pin(async { Ok(()) })
    }

    fn mark_failed<'a>(
        &'a self,
        job_id: Uuid,
        last_error: &'a str,
    ) -> BoxFuture<'a, DomainResult<()>> {
        self.mark_failed_calls
            .lock()
            .unwrap()
            .push((job_id, last_error.to_string()));
        Box::pin(async { Ok(()) })
    }

    fn enqueue_scan<'a>(
        &'a self,
        artifact_id: Uuid,
        repository_id: Uuid,
        content_hash: &'a ContentHash,
        format: &'a str,
        priority: i16,
        trigger_source: &'a str,
    ) -> BoxFuture<'a, DomainResult<Uuid>> {
        self.enqueue_scan_calls
            .lock()
            .unwrap()
            .push(EnqueueScanCall {
                artifact_id,
                repository_id,
                content_hash: content_hash.clone(),
                format: format.to_string(),
                priority,
                trigger_source: trigger_source.to_string(),
            });
        let maybe_err = self.enqueue_scan_error.lock().unwrap().take();
        if let Some(err) = maybe_err {
            Box::pin(async move { Err(err) })
        } else {
            let id = Uuid::new_v4();
            Box::pin(async move { Ok(id) })
        }
    }

    fn find_active_scan_for_artifact<'a>(
        &'a self,
        artifact_id: Uuid,
    ) -> BoxFuture<'a, DomainResult<Option<Uuid>>> {
        let res = self.active_scans.lock().unwrap().get(&artifact_id).copied();
        Box::pin(async move { Ok(res) })
    }

    fn enqueue_task<'a>(
        &'a self,
        kind: &'a str,
        params: &'a serde_json::Value,
        actor_id: Option<Uuid>,
        _priority: i16,
        _trigger_source: &'a str,
        idempotency_key: Option<&'a hort_domain::types::IdempotencyKey>,
    ) -> BoxFuture<'a, DomainResult<hort_domain::ports::jobs_repository::EnqueueOutcome>> {
        self.enqueue_calls
            .lock()
            .unwrap()
            .push((kind.to_string(), params.clone(), actor_id));
        // Record the idempotency_key
        // verbatim (cloned, since the borrow does not outlive the call).
        self.enqueue_idem_keys
            .lock()
            .unwrap()
            .push(idempotency_key.cloned());
        let maybe_err = self.enqueue_error.lock().unwrap().take();
        let maybe_dup = self.next_duplicate.lock().unwrap().take();
        if let Some(err) = maybe_err {
            Box::pin(async move { Err(err) })
        } else if let Some(existing) = maybe_dup {
            Box::pin(async move {
                Ok(
                    hort_domain::ports::jobs_repository::EnqueueOutcome::Duplicate {
                        existing_job_id: existing,
                    },
                )
            })
        } else {
            let id = Uuid::new_v4();
            Box::pin(async move {
                Ok(hort_domain::ports::jobs_repository::EnqueueOutcome::Enqueued { job_id: id })
            })
        }
    }

    fn delete_job<'a>(&'a self, job_id: Uuid) -> BoxFuture<'a, DomainResult<()>> {
        self.delete_calls.lock().unwrap().push(job_id);
        Box::pin(async { Ok(()) })
    }

    fn list_jobs<'a>(
        &'a self,
        filter: ListJobsFilter,
        limit: u32,
        cursor: Option<Uuid>,
    ) -> BoxFuture<'a, DomainResult<ListJobsPage>> {
        let rows: Vec<JobRow> = {
            let all = self.list_rows.lock().unwrap();
            let display_limit = if limit == 0 { 50 } else { limit as usize };
            all.iter()
                .filter(|r| {
                    if let Some(ref k) = filter.kind {
                        if r.kind != *k {
                            return false;
                        }
                    }
                    if let Some(s) = filter.status {
                        if r.status != s {
                            return false;
                        }
                    }
                    if let Some(c) = cursor {
                        if r.id >= c {
                            return false;
                        }
                    }
                    true
                })
                .take(display_limit + 1)
                .cloned()
                .collect()
        };
        let display_limit = if limit == 0 { 50 } else { limit as usize };
        let has_more = rows.len() > display_limit;
        let items: Vec<JobRow> = rows.into_iter().take(display_limit).collect();
        let next_cursor = if has_more {
            items.last().map(|r| r.id)
        } else {
            None
        };
        Box::pin(async move { Ok(ListJobsPage { items, next_cursor }) })
    }

    fn get_job<'a>(&'a self, job_id: Uuid) -> BoxFuture<'a, DomainResult<Option<JobRow>>> {
        let row = self.get_rows.lock().unwrap().get(&job_id).cloned();
        Box::pin(async move { Ok(row) })
    }

    fn claim_pending_by_kinds<'a>(
        &'a self,
        _kinds: &'a [&'a str],
        _batch_size: u16,
        _worker_id: &'a str,
        _lock_duration: std::time::Duration,
    ) -> BoxFuture<'a, DomainResult<Vec<JobRow>>> {
        // Pop the front batch if any are seeded; return empty vec otherwise.
        let batch = self
            .claim_batches
            .lock()
            .unwrap()
            .first()
            .cloned()
            .unwrap_or_default();
        if !batch.is_empty() {
            self.claim_batches.lock().unwrap().remove(0);
        }
        Box::pin(async move { Ok(batch) })
    }

    fn enqueue_prefetch_batch<'a>(
        &'a self,
        rows: &'a [hort_domain::ports::jobs_repository::PrefetchEnqueueRow],
    ) -> BoxFuture<'a, DomainResult<Vec<Uuid>>> {
        // Record the batch verbatim.
        self.prefetch_batch_calls
            .lock()
            .unwrap()
            .push(rows.to_vec());
        // One-shot error injection.
        let maybe_err = self.prefetch_batch_error.lock().unwrap().take();
        if let Some(err) = maybe_err {
            return Box::pin(async move { Err(err) });
        }
        // L3-dedup simulation: the production schema's two partial
        // unique indexes (`jobs_prefetch_unique` for `kind =
        // 'prefetch'` and `jobs_prefetch_dependencies_unique` for
        // `kind = 'prefetch-dependencies'`) are disjoint — the same
        // `target_key` can be in-flight under both kinds at once.
        // The mock simulates that by namespacing the seen-set key
        // as `"{kind}::{target_key}"` so a `prefetch` row and a
        // `prefetch-dependencies` row with the same coordinate
        // both insert (mirrors production), while a re-walk of the
        // same `(kind, target_key)` is dedup'd.
        let mut ids: Vec<Uuid> = Vec::with_capacity(rows.len());
        {
            let mut seen = self.prefetch_seen_keys.lock().unwrap();
            for r in rows {
                let key = format!("{}::{}", r.kind, r.target_key);
                if seen.insert(key) {
                    ids.push(Uuid::new_v4());
                }
            }
        }
        Box::pin(async move { Ok(ids) })
    }

    fn delete_terminal_prefetch_rows_older_than<'a>(
        &'a self,
        horizon: std::time::Duration,
    ) -> BoxFuture<'a, DomainResult<u64>> {
        self.prefetch_retention_calls.lock().unwrap().push(horizon);
        let count = self
            .prefetch_retention_deleted_count
            .lock()
            .unwrap()
            .unwrap_or(0);
        Box::pin(async move { Ok(count) })
    }
}

// `JobStatus` needs `PartialEq` to compare inside `list_jobs` filter — it
// already derives it per the domain port definition, so no extra impl needed.

// ---------------------------------------------------------------------------
// test_job_row helper — shared across handler tests and dispatcher tests
// ---------------------------------------------------------------------------

/// Build a minimal [`JobRow`] fixture for tests.
///
/// `status` is `Running` (post-claim shape the dispatcher hands to handlers).
/// `attempts` is 1. All optional fields are `None`.
pub fn test_job_row(kind: &str) -> JobRow {
    use hort_domain::ports::jobs_repository::{JobStatus, KindFields};
    let now = Utc::now();
    JobRow {
        id: Uuid::new_v4(),
        kind: kind.to_string(),
        status: JobStatus::Running,
        params: Some(serde_json::Value::Null),
        actor_id: None,
        priority: 0,
        trigger_source: "test".to_string(),
        attempts: 1,
        created_at: now,
        updated_at: now,
        completed_at: None,
        last_error: None,
        result_summary: None,
        kind_fields: KindFields::Other,
    }
}

// ===========================================================================
// Mock implementations for OidcIssuerRepository +
// ServiceAccountRepository (used by ApplyConfigUseCase tests).
// ===========================================================================

/// In-memory mock for [`OidcIssuerRepository`]. Stores issuers by id;
/// reads are linear scans (test fixture sizes never exceed a handful).
pub struct MockOidcIssuerRepository {
    issuers: Mutex<HashMap<Uuid, hort_domain::entities::oidc_issuer::OidcIssuer>>,
}

impl Default for MockOidcIssuerRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl MockOidcIssuerRepository {
    pub fn new() -> Self {
        Self {
            issuers: Mutex::new(HashMap::new()),
        }
    }

    /// Synchronous test seeding (no async runtime needed). Inserts by
    /// the issuer's own id; callers control uniqueness. Used by handler
    /// tests that are already inside a tokio runtime and cannot
    /// `block_on` the async `upsert`.
    pub fn seed(&self, issuer: hort_domain::entities::oidc_issuer::OidcIssuer) {
        self.issuers.lock().unwrap().insert(issuer.id, issuer);
    }

    /// Test-only accessor: snapshot the current set, sorted by name.
    pub fn snapshot(&self) -> Vec<hort_domain::entities::oidc_issuer::OidcIssuer> {
        let mut items: Vec<_> = self.issuers.lock().unwrap().values().cloned().collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        items
    }
}

impl OidcIssuerRepository for MockOidcIssuerRepository {
    fn list(
        &self,
    ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::entities::oidc_issuer::OidcIssuer>>> {
        let items = self.snapshot();
        Box::pin(async move { Ok(items) })
    }

    fn get_by_name(
        &self,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<hort_domain::entities::oidc_issuer::OidcIssuer>>> {
        let name = name.to_string();
        let issuers = self.issuers.lock().unwrap();
        let result = issuers.values().find(|i| i.name == name).cloned();
        Box::pin(async move { Ok(result) })
    }

    fn get_by_issuer_url(
        &self,
        url: &str,
    ) -> BoxFuture<'_, DomainResult<Option<hort_domain::entities::oidc_issuer::OidcIssuer>>> {
        let url = url.to_string();
        let issuers = self.issuers.lock().unwrap();
        let result = issuers.values().find(|i| i.issuer_url == url).cloned();
        Box::pin(async move { Ok(result) })
    }

    fn upsert(
        &self,
        issuer: &hort_domain::entities::oidc_issuer::OidcIssuer,
    ) -> BoxFuture<'_, DomainResult<()>> {
        let mut issuers = self.issuers.lock().unwrap();
        // Upsert on name — the apply pipeline's create-path may have
        // minted a fresh UUID for a row whose name already exists, so
        // we reuse the existing id to match the Postgres adapter's
        // `ON CONFLICT (name) DO UPDATE` semantics.
        let existing_id = issuers
            .values()
            .find(|i| i.name == issuer.name)
            .map(|i| i.id);
        let id = existing_id.unwrap_or(issuer.id);
        let mut stored = issuer.clone();
        stored.id = id;
        issuers.insert(id, stored);
        Box::pin(async { Ok(()) })
    }

    fn delete_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<()>> {
        let mut issuers = self.issuers.lock().unwrap();
        if let Some(id) = issuers.values().find(|i| i.name == name).map(|i| i.id) {
            issuers.remove(&id);
        }
        Box::pin(async { Ok(()) })
    }
}

/// Mock [`ReplayGuardPort`] with a
/// canned outcome. Default reply is `FirstSeen` (the success path —
/// every existing federation handler test mints exactly once, so the
/// default keeps those green). `replayed()` / `unavailable()`
/// constructors drive the deny paths.
pub struct MockReplayGuardPort {
    outcome: Mutex<Result<ReplayClaim, ReplayGuardError>>,
    calls: Mutex<usize>,
}

impl Default for MockReplayGuardPort {
    fn default() -> Self {
        Self::first_seen()
    }
}

impl MockReplayGuardPort {
    /// Guard accepts (no prior sighting) — the success path.
    pub fn first_seen() -> Self {
        Self {
            outcome: Mutex::new(Ok(ReplayClaim::FirstSeen)),
            calls: Mutex::new(0),
        }
    }
    /// Guard reports a replay.
    pub fn replayed() -> Self {
        Self {
            outcome: Mutex::new(Ok(ReplayClaim::Replayed)),
            calls: Mutex::new(0),
        }
    }
    /// Guard is unreachable — drives the fail-CLOSED path.
    pub fn unavailable() -> Self {
        Self {
            outcome: Mutex::new(Err(ReplayGuardError::Unavailable("mock outage".into()))),
            calls: Mutex::new(0),
        }
    }
    /// Number of `claim` calls observed.
    pub fn call_count(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl ReplayGuardPort for MockReplayGuardPort {
    fn claim<'a>(
        &'a self,
        _key: &'a ReplayKey,
        _expires_at: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<ReplayClaim, ReplayGuardError>> {
        *self.calls.lock().unwrap() += 1;
        let out = self.outcome.lock().unwrap().clone();
        Box::pin(async move { out })
    }
}

/// In-memory mock for [`ServiceAccountRepository`]. Stores the full
/// aggregate; the test-side `upsert` follows the same name-as-identity
/// semantics as the Postgres adapter.
pub struct MockServiceAccountRepository {
    sas: Mutex<HashMap<Uuid, hort_domain::entities::service_account::ServiceAccount>>,
}

impl Default for MockServiceAccountRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl MockServiceAccountRepository {
    pub fn new() -> Self {
        Self {
            sas: Mutex::new(HashMap::new()),
        }
    }

    pub fn snapshot(&self) -> Vec<hort_domain::entities::service_account::ServiceAccount> {
        let mut items: Vec<_> = self.sas.lock().unwrap().values().cloned().collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        items
    }

    /// Synchronous test helper — pre-populate the mock without going
    /// through the async `upsert` path. Used by the
    /// rotation handler tests to seed a set of SAs before invoking
    /// the handler.
    pub fn insert(&self, sa: hort_domain::entities::service_account::ServiceAccount) {
        self.sas.lock().unwrap().insert(sa.id, sa);
    }
}

impl ServiceAccountRepository for MockServiceAccountRepository {
    fn list(
        &self,
    ) -> BoxFuture<'_, DomainResult<Vec<hort_domain::entities::service_account::ServiceAccount>>>
    {
        let items = self.snapshot();
        Box::pin(async move { Ok(items) })
    }

    fn get_by_name(
        &self,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<hort_domain::entities::service_account::ServiceAccount>>>
    {
        let name = name.to_string();
        let sas = self.sas.lock().unwrap();
        let result = sas.values().find(|s| s.name == name).cloned();
        Box::pin(async move { Ok(result) })
    }

    fn upsert(
        &self,
        sa: &hort_domain::entities::service_account::ServiceAccount,
    ) -> BoxFuture<'_, DomainResult<()>> {
        let mut sas = self.sas.lock().unwrap();
        let existing_id = sas.values().find(|s| s.name == sa.name).map(|s| s.id);
        let id = existing_id.unwrap_or(sa.id);
        let mut stored = sa.clone();
        stored.id = id;
        sas.insert(id, stored);
        Box::pin(async { Ok(()) })
    }

    fn delete_by_name(&self, name: &str) -> BoxFuture<'_, DomainResult<()>> {
        let mut sas = self.sas.lock().unwrap();
        if let Some(id) = sas.values().find(|s| s.name == name).map(|s| s.id) {
            sas.remove(&id);
        }
        Box::pin(async { Ok(()) })
    }
}

// ===========================================================================
// Mock implementation for KubernetesSecretWriter.
//
// Drives the `ServiceAccountRotationHandler` tests. Records every
// `upsert_managed` call so tests can assert ordering + format + labels.
// The plaintext PAT bytes from the spec are intentionally NOT stored on the
// mock — the spec is consumed by value and the buffer is zeroed when this
// function returns, matching the production wire shape. Tests assert on the
// non-secret metadata (format / token_id / last_rotated / sa name /
// registry host) instead.
// ===========================================================================

/// Recorded state from a past `upsert_managed` call. The plaintext PAT
/// is **not** stored — this struct is what the reconciler's audit-side
/// "what did we write" view should see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockSecretState {
    pub namespace: String,
    pub name: String,
    pub format: hort_domain::entities::service_account::SecretFormat,
    pub token_id: Uuid,
    pub service_account_name: String,
    pub last_rotated: DateTime<Utc>,
    pub registry_host: String,
}

/// In-memory mock for [`KubernetesSecretWriter`].
///
/// Stores upsert outcomes keyed by `(namespace, name)` and exposes
/// `read_managed` to project a [`ManagedSecret`] from the recorded
/// state — so a tick-then-tick test produces identical projected
/// `managed_by` / `last_rotated` to what a real k8s read would return.
///
/// `seed_existing` lets tests pre-populate state (covers the collision
/// and stale paths). Call counters expose idempotency assertions for
/// the "second tick is a no-op when fresh" test (the reconciler reads
/// first, decides freshness, and skips the upsert call entirely).
pub struct MockKubernetesSecretWriter {
    state: Arc<Mutex<HashMap<(String, String), MockSecretState>>>,
    read_call_count: Arc<AtomicUsize>,
    upsert_call_count: Arc<AtomicUsize>,
}

impl Default for MockKubernetesSecretWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl MockKubernetesSecretWriter {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            read_call_count: Arc::new(AtomicUsize::new(0)),
            upsert_call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Snapshot the recorded state, sorted by `(namespace, name)` so
    /// test assertions are order-stable.
    pub fn snapshot(&self) -> Vec<MockSecretState> {
        let mut items: Vec<_> = self.state.lock().unwrap().values().cloned().collect();
        items.sort_by(|a, b| {
            a.namespace
                .cmp(&b.namespace)
                .then_with(|| a.name.cmp(&b.name))
        });
        items
    }

    /// Pre-seed an existing recorded Secret. Used by tests covering
    /// the freshness + collision branches of the reconciler.
    pub fn seed_existing(&self, namespace: &str, name: &str, state: MockSecretState) {
        self.state
            .lock()
            .unwrap()
            .insert((namespace.to_string(), name.to_string()), state);
    }

    pub fn read_call_count(&self) -> usize {
        self.read_call_count.load(Ordering::SeqCst)
    }

    pub fn upsert_call_count(&self) -> usize {
        self.upsert_call_count.load(Ordering::SeqCst)
    }
}

impl KubernetesSecretWriter for MockKubernetesSecretWriter {
    fn read_managed<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, DomainResult<Option<ManagedSecret>>> {
        self.read_call_count.fetch_add(1, Ordering::SeqCst);
        let key = (namespace.to_string(), name.to_string());
        let state = self.state.lock().unwrap();
        let projected = state.get(&key).map(|s| ManagedSecret {
            managed_by: Some("hort-worker".into()),
            service_account: Some(s.service_account_name.clone()),
            last_rotated: Some(s.last_rotated),
            token_id: Some(s.token_id),
        });
        Box::pin(async move { Ok(projected) })
    }

    fn upsert_managed<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
        spec: ManagedSecretSpec,
    ) -> BoxFuture<'a, DomainResult<()>> {
        self.upsert_call_count.fetch_add(1, Ordering::SeqCst);
        let snapshot = MockSecretState {
            namespace: namespace.to_string(),
            name: name.to_string(),
            format: spec.format,
            token_id: spec.token_id,
            service_account_name: spec.service_account_name.clone(),
            last_rotated: spec.last_rotated,
            registry_host: spec.registry_host.clone(),
        };
        // Drop the spec → zero the plaintext. The mock retains only
        // the non-secret metadata in `snapshot`.
        drop(spec);
        self.state
            .lock()
            .unwrap()
            .insert((namespace.to_string(), name.to_string()), snapshot);
        Box::pin(async { Ok(()) })
    }
}

// ===========================================================================
// Mock implementation for FederatedJwtValidator.
//
// Drives the federation handler tests in
// `hort-http-core::handlers::exchange`. Stores a closed map keyed by the
// raw `subject_token` string (compact-serialisation JWT) and replays
// either a pre-registered `ValidatedClaims` (success path) or a
// pre-registered `FederationDenyReason` (deny path). The mock owns no
// crypto — every test calling `register_token` or `register_error`
// pins the validator's outcome explicitly.
// ===========================================================================

/// In-memory mock for
/// [`FederatedJwtValidator`](hort_domain::ports::federated_jwt_validator::FederatedJwtValidator).
///
/// Each token registered via [`Self::register_token`] / [`Self::register_error`]
/// produces a deterministic outcome on `validate()`. Unregistered tokens
/// surface as
/// [`FederationDenyReason::InvalidFormat`](hort_domain::ports::federated_jwt_validator::FederationDenyReason::InvalidFormat)
/// — the "no test setup, treat as garbage" default mirrors the
/// `MockIdentityProvider` precedent.
pub struct MockFederatedJwtValidator {
    outcomes: Mutex<
        HashMap<
            String,
            Result<
                hort_domain::ports::federated_jwt_validator::ValidatedClaims,
                hort_domain::ports::federated_jwt_validator::FederationDenyReason,
            >,
        >,
    >,
    /// Per-issuer-name
    /// pinned outcome for [`refresh_issuer`]. Default `Ok(())` (silent
    /// success) keeps pre-existing tests compiling unchanged; tests
    /// exercising the warm-up-failed path seed via
    /// [`Self::register_refresh_outcome`].
    refresh_outcomes: Mutex<
        HashMap<
            String,
            Result<(), hort_domain::ports::federated_jwt_validator::FederationDenyReason>,
        >,
    >,
    /// Invocation log for `refresh_issuer`. Apply-use-case
    /// tests assert that the warm-up was invoked with the expected
    /// issuer name regardless of outcome.
    refresh_calls: Mutex<Vec<String>>,
}

impl Default for MockFederatedJwtValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl MockFederatedJwtValidator {
    pub fn new() -> Self {
        Self {
            outcomes: Mutex::new(HashMap::new()),
            refresh_outcomes: Mutex::new(HashMap::new()),
            refresh_calls: Mutex::new(Vec::new()),
        }
    }

    /// Pin the validator to return [`Ok(claims)`] for the given raw
    /// `subject_token`. Replaces any prior registration for the same key.
    pub fn register_token(
        &self,
        token: impl Into<String>,
        claims: hort_domain::ports::federated_jwt_validator::ValidatedClaims,
    ) {
        self.outcomes
            .lock()
            .unwrap()
            .insert(token.into(), Ok(claims));
    }

    /// Pin the validator to return [`Err(reason)`] for the given raw
    /// `subject_token`.
    pub fn register_error(
        &self,
        token: impl Into<String>,
        reason: hort_domain::ports::federated_jwt_validator::FederationDenyReason,
    ) {
        self.outcomes
            .lock()
            .unwrap()
            .insert(token.into(), Err(reason));
    }

    /// Pin the outcome of `refresh_issuer` for an
    /// issuer matched by [`OidcIssuer.name`]. Unregistered names
    /// default to `Ok(())` (silent success) so existing tests
    /// continue unaffected.
    pub fn register_refresh_outcome(
        &self,
        issuer_name: impl Into<String>,
        outcome: Result<(), hort_domain::ports::federated_jwt_validator::FederationDenyReason>,
    ) {
        self.refresh_outcomes
            .lock()
            .unwrap()
            .insert(issuer_name.into(), outcome);
    }

    /// List every `OidcIssuer.name` `refresh_issuer`
    /// was invoked with, in call order. Apply-use-case tests use this
    /// to confirm the warm-up fired exactly once per create/update.
    pub fn refresh_calls(&self) -> Vec<String> {
        self.refresh_calls.lock().unwrap().clone()
    }
}

impl hort_domain::ports::federated_jwt_validator::FederatedJwtValidator
    for MockFederatedJwtValidator
{
    fn validate<'a>(
        &'a self,
        jwt: &'a str,
    ) -> BoxFuture<
        'a,
        Result<
            hort_domain::ports::federated_jwt_validator::ValidatedClaims,
            hort_domain::ports::federated_jwt_validator::FederationDenyReason,
        >,
    > {
        let key = jwt.to_string();
        let outcome = self
            .outcomes
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .unwrap_or(Err(
                hort_domain::ports::federated_jwt_validator::FederationDenyReason::InvalidFormat,
            ));
        Box::pin(async move { outcome })
    }

    fn refresh_issuer<'a>(
        &'a self,
        issuer: &'a hort_domain::entities::oidc_issuer::OidcIssuer,
    ) -> BoxFuture<'a, Result<(), hort_domain::ports::federated_jwt_validator::FederationDenyReason>>
    {
        let name = issuer.name.clone();
        self.refresh_calls.lock().unwrap().push(name.clone());
        let outcome = self
            .refresh_outcomes
            .lock()
            .unwrap()
            .get(&name)
            .cloned()
            .unwrap_or(Ok(()));
        Box::pin(async move { outcome })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::AsyncReadExt;

    const VALID_SHA256_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const VALID_SHA256_B: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    const VALID_SHA256_C: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    #[tokio::test]
    async fn mock_staging_stream_read_returns_appended_bytes() {
        let staging = MockStatefulUploadStagingPort::new();
        let session_id = Uuid::new_v4();

        // Two appends: the second must concatenate onto the first.
        let first: Box<dyn AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(b"hello ".to_vec()));
        staging.append(session_id, first).await.unwrap();
        let second: Box<dyn AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(b"world".to_vec()));
        staging.append(session_id, second).await.unwrap();

        let mut reader = staging.stream_read(session_id).await.unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello world");

        // A never-staged id must surface as `DomainError::NotFound` so
        // the use-case layer can distinguish "no session" from "empty
        // session". `Box<dyn AsyncRead>` doesn't implement `Debug`, so we
        // discard the success half of the `Result` to keep the panic
        // message formatter happy.
        let missing = staging
            .stream_read(Uuid::new_v4())
            .await
            .err()
            .expect("stream_read on unknown id must fail");
        match missing {
            DomainError::NotFound { entity, .. } => {
                assert_eq!(entity, "stateful_upload_staging");
            }
            other => panic!("expected DomainError::NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mock_staging_delete_is_idempotent() {
        let staging = MockStatefulUploadStagingPort::new();
        // Deleting a never-created id is OK — the port contract says
        // finalize and GC may race against each other.
        staging.delete(Uuid::new_v4()).await.unwrap();

        let session_id = Uuid::new_v4();
        let payload: Box<dyn AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(b"payload".to_vec()));
        staging.append(session_id, payload).await.unwrap();
        staging.delete(session_id).await.unwrap();
        // Second delete of the same id must also be OK.
        staging.delete(session_id).await.unwrap();
    }

    // ------------------------------------------------------------------
    // MockArtifactRepository — `package_version_status`
    // ------------------------------------------------------------------

    /// The mock mirrors the Pg adapter: matches `(repository_id, name)`,
    /// excludes soft-deleted rows, drops null-version rows, and returns
    /// raw `(version, quarantine_status)` pairs. This unit test pins
    /// each axis so the mock cannot silently drift from the adapter
    /// contract (the mock is the authority for `hort-app` use-case tests
    /// downstream of this port).
    #[tokio::test]
    async fn mock_package_version_status_filters_repo_name_deleted_and_null_version() {
        let mock = MockArtifactRepository::new();
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();

        // helper: clone-and-edit the shared fixture so each insert lands
        // a unique row.
        let make = |repo: Uuid,
                    name: &str,
                    version: Option<&str>,
                    status: QuarantineStatus,
                    is_deleted: bool| {
            let mut a = sample_artifact(status);
            a.id = Uuid::new_v4();
            a.repository_id = repo;
            a.name = name.into();
            a.name_as_published = name.into();
            a.version = version.map(str::to_owned);
            a.is_deleted = is_deleted;
            a
        };

        // In-scope rows under (repo_a, "leftpad"):
        mock.insert(make(
            repo_a,
            "leftpad",
            Some("1.0.0"),
            QuarantineStatus::None,
            false,
        ));
        mock.insert(make(
            repo_a,
            "leftpad",
            Some("1.1.0"),
            QuarantineStatus::Quarantined,
            false,
        ));
        mock.insert(make(
            repo_a,
            "leftpad",
            Some("1.2.0"),
            QuarantineStatus::Released,
            false,
        ));
        // Excluded: soft-deleted.
        mock.insert(make(
            repo_a,
            "leftpad",
            Some("9.9.0"),
            QuarantineStatus::Released,
            true,
        ));
        // Excluded: null version.
        mock.insert(make(
            repo_a,
            "leftpad",
            None,
            QuarantineStatus::Released,
            false,
        ));
        // Excluded: different name in same repo.
        mock.insert(make(
            repo_a,
            "other-pkg",
            Some("1.0.0"),
            QuarantineStatus::Released,
            false,
        ));
        // Excluded: same name in different repo.
        mock.insert(make(
            repo_b,
            "leftpad",
            Some("2.0.0"),
            QuarantineStatus::Released,
            false,
        ));

        let triples = mock
            .package_version_status(repo_a, "leftpad")
            .await
            .expect("mock returns Ok");
        // Third tuple element is `quarantine_until`
        // (sourced from `artifact.quarantine_deadline`). The fixture
        // helper above leaves `quarantine_deadline` at its
        // `sample_artifact`-default `None`, so the third element is
        // uniformly `None` here. Per-deadline coverage lives in the
        // DiscoveryUseCase test module.
        let pairs: Vec<(String, QuarantineStatus)> =
            triples.into_iter().map(|(v, s, _)| (v, s)).collect();
        assert_eq!(
            pairs,
            vec![
                ("1.0.0".to_string(), QuarantineStatus::None),
                ("1.1.0".to_string(), QuarantineStatus::Quarantined),
                ("1.2.0".to_string(), QuarantineStatus::Released),
            ]
        );
    }

    /// Unknown package → empty Vec, never an error.
    #[tokio::test]
    async fn mock_package_version_status_unknown_package_returns_empty() {
        let mock = MockArtifactRepository::new();
        let triples = mock
            .package_version_status(Uuid::new_v4(), "never-seen")
            .await
            .expect("mock returns Ok");
        assert!(triples.is_empty());
    }

    // ------------------------------------------------------------------
    // MockContentReferenceIndex contract tests. Mirrors the behaviours
    // asserted by the DB-gated integration tests in
    // `hort-adapters-postgres/src/pg_content_reference_repo.rs` so the
    // mock cannot silently drift from the adapter.
    // ------------------------------------------------------------------

    fn sample_reference(
        repo: Uuid,
        source: Uuid,
        target_hex: &str,
        kind: &str,
        metadata: serde_json::Value,
    ) -> ContentReference {
        ContentReference {
            source_artifact_id: source,
            target_content_hash: target_hex
                .parse()
                .expect("valid SHA-256 hex in test fixture"),
            kind: kind.into(),
            metadata,
            repository_id: repo,
            recorded_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn mock_references_insert_then_find_roundtrip() {
        let idx = MockContentReferenceIndex::new();
        let repo = Uuid::new_v4();
        let source = Uuid::new_v4();
        let target: ContentHash = VALID_SHA256_A.parse().unwrap();

        idx.insert(sample_reference(
            repo,
            source,
            VALID_SHA256_A,
            "oci_subject",
            serde_json::json!({"artifact_type": "application/vnd.x"}),
        ))
        .await
        .unwrap();

        let found = idx.find_by_target(repo, &target, None).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].source_artifact_id, source);
        assert_eq!(
            found[0].metadata,
            serde_json::json!({"artifact_type": "application/vnd.x"})
        );

        // Unknown target → empty, not error.
        let unknown: ContentHash = VALID_SHA256_B.parse().unwrap();
        let empty = idx.find_by_target(repo, &unknown, None).await.unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn mock_references_kind_filter_narrows() {
        let idx = MockContentReferenceIndex::new();
        let repo = Uuid::new_v4();
        let target: ContentHash = VALID_SHA256_B.parse().unwrap();
        let s_oci = Uuid::new_v4();
        let s_sbom = Uuid::new_v4();

        idx.insert(sample_reference(
            repo,
            s_oci,
            VALID_SHA256_B,
            "oci_subject",
            serde_json::Value::Null,
        ))
        .await
        .unwrap();
        idx.insert(sample_reference(
            repo,
            s_sbom,
            VALID_SHA256_B,
            "sbom_attachment",
            serde_json::Value::Null,
        ))
        .await
        .unwrap();

        let oci_only = idx
            .find_by_target(repo, &target, Some("oci_subject"))
            .await
            .unwrap();
        assert_eq!(oci_only.len(), 1);
        assert_eq!(oci_only[0].source_artifact_id, s_oci);

        // None filter → both rows.
        let all = idx.find_by_target(repo, &target, None).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn mock_references_delete_by_source_removes_entry() {
        let idx = MockContentReferenceIndex::new();
        let repo = Uuid::new_v4();
        let source = Uuid::new_v4();
        let target: ContentHash = VALID_SHA256_C.parse().unwrap();

        idx.insert(sample_reference(
            repo,
            source,
            VALID_SHA256_C,
            "oci_subject",
            serde_json::Value::Null,
        ))
        .await
        .unwrap();
        assert_eq!(idx.entry_count(), 1);

        idx.delete_by_source(source).await.unwrap();
        let after = idx.find_by_target(repo, &target, None).await.unwrap();
        assert!(after.is_empty());
        assert_eq!(idx.entry_count(), 0);

        // Idempotent — second delete of the same id, and delete of a
        // never-existing id, both succeed.
        idx.delete_by_source(source).await.unwrap();
        idx.delete_by_source(Uuid::new_v4()).await.unwrap();
    }

    #[tokio::test]
    async fn mock_references_find_on_empty_returns_empty_vec() {
        // `find_by_target` on an index with zero entries must be
        // `Ok(vec![])`, not `Err(NotFound)` — matches the adapter
        // contract documented on the port.
        let idx = MockContentReferenceIndex::new();
        let target: ContentHash = VALID_SHA256_A.parse().unwrap();
        let out = idx
            .find_by_target(Uuid::new_v4(), &target, None)
            .await
            .expect("find_by_target on empty index must be Ok");
        assert!(out.is_empty());

        let out_filtered = idx
            .find_by_target(Uuid::new_v4(), &target, Some("oci_subject"))
            .await
            .expect("filtered find_by_target on empty index must be Ok");
        assert!(out_filtered.is_empty());
    }

    // ------------------------------------------------------------------
    // MockApiTokenRepository::fail_next_insert
    // ------------------------------------------------------------------

    /// Sole direct-unit-test of the [`MockApiTokenRepository::fail_next_insert`]
    /// hook. The hook is a one-shot fail-injection slot mirroring ten
    /// existing `fail_next_*` precedents in this file (closest in shape:
    /// `MockRefRegistry::fail_next_insert`). The hook exists so the
    /// `crates/hort-http-core` exchange-handler tests can drive the
    /// genuine `infrastructure_error` exit on `/api/v1/auth/exchange`
    /// without trait-wrapping `ApiTokenUseCase` (declined per the
    /// architecture rule "outbound ports are traits, use cases are
    /// concrete"). This test pins the contract:
    /// 1. Unarmed, `insert` succeeds and appends to `inserted()`.
    /// 2. After `fail_next_insert(err)`, the next `insert` returns
    ///    `Err(_)` AND does NOT append (so failure-injection tests can
    ///    assert the row was NOT persisted).
    /// 3. The slot is one-shot: a follow-up `insert` succeeds again
    ///    and appends normally.
    #[tokio::test]
    async fn mock_api_token_repository_fail_next_insert_arms_once_then_resets() {
        use hort_domain::entities::api_token::{ApiToken, TokenKind};
        use hort_domain::ports::api_token_repository::ApiTokenRepository;

        let mock = MockApiTokenRepository::new();

        let make_token = || ApiToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "test".to_string(),
            description: None,
            kind: TokenKind::Pat,
            token_hash: "hash".to_string(),
            token_prefix: "prefix".to_string(),
            declared_permissions: Vec::new(),
            repository_ids: None,
            expires_at: None,
            revoked_at: None,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            created_by_user_id: Uuid::new_v4(),
            created_at: Utc::now(),
        };

        // (1) Unarmed → Ok, row persisted.
        let token_a = make_token();
        mock.insert(&token_a)
            .await
            .expect("unarmed insert must succeed");
        assert_eq!(
            mock.inserted().len(),
            1,
            "unarmed insert must append to inserted()"
        );

        // (2) Armed → Err, row NOT persisted.
        mock.fail_next_insert(DomainError::Invariant("test".into()));
        let token_b = make_token();
        let err = mock
            .insert(&token_b)
            .await
            .expect_err("armed insert must return Err");
        match err {
            DomainError::Invariant(msg) => assert_eq!(msg, "test"),
            other => panic!("expected DomainError::Invariant, got {other:?}"),
        }
        assert_eq!(
            mock.inserted().len(),
            1,
            "armed insert must NOT append — inserted() unchanged"
        );

        // (3) One-shot reset → next insert succeeds and appends.
        let token_c = make_token();
        mock.insert(&token_c)
            .await
            .expect("post-fire insert must succeed (slot is one-shot)");
        assert_eq!(
            mock.inserted().len(),
            2,
            "post-fire insert must append again"
        );
    }

    // -- MockStoragePort::fail_next_get_truncated (CAS serve-path) -----------

    /// Direct-unit test of the [`MockStoragePort::fail_next_get_truncated`]
    /// hook + the [`TruncatingReader`] it installs. Mirrors the one-shot,
    /// consumed-on-use posture asserted for the other `fail_next_*`
    /// precedents (closest in shape:
    /// `mock_api_token_repository_fail_next_insert_arms_once_then_resets`).
    ///
    /// Contract under test:
    /// 1. Unarmed `get` returns the stored content cleanly.
    /// 2. After `fail_next_get_truncated(hash, prefix)`, the next `get`
    ///    for that hash returns a reader that delivers exactly `prefix`
    ///    and then yields `io::ErrorKind::InvalidData` at EOF — the
    ///    `VerifyingReader` tampered-blob shape.
    /// 3. The slot is one-shot: a subsequent `get` for the same hash
    ///    falls through to the normal stored content.
    /// 4. Re-polling the errored reader keeps yielding `InvalidData`
    ///    (never a spurious clean EOF) — the defensive branch.
    #[tokio::test]
    async fn mock_storage_fail_next_get_truncated_arms_once_then_resets() {
        let mock = MockStoragePort::new();
        let hash: ContentHash = VALID_SHA256_A.parse().unwrap();
        mock.insert_content(hash.clone(), b"the full clean content".to_vec());

        // (1) Unarmed → stored content, clean read-to-end.
        let mut r = mock.get(&hash).await.expect("unarmed get must succeed");
        let mut buf = Vec::new();
        r.read_to_end(&mut buf)
            .await
            .expect("unarmed read must be clean");
        assert_eq!(&buf, b"the full clean content");

        // (2) Armed → prefix then InvalidData at EOF.
        mock.fail_next_get_truncated(hash.clone(), b"PARTIAL!".to_vec());
        let mut r = mock.get(&hash).await.expect("get itself still resolves Ok");
        // Read the prefix in full first — those bytes flow normally.
        let mut prefix = [0u8; 8];
        r.read_exact(&mut prefix)
            .await
            .expect("the valid prefix must read cleanly");
        assert_eq!(&prefix, b"PARTIAL!");
        // The next read hits the simulated EOF integrity failure.
        let mut sink = Vec::new();
        let err = r
            .read_to_end(&mut sink)
            .await
            .expect_err("EOF must yield an integrity io::Error, not clean EOF");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // (4) Defensive: re-polling the errored reader stays errored.
        let err2 = r
            .read_to_end(&mut sink)
            .await
            .expect_err("re-poll after error must stay errored");
        assert_eq!(err2.kind(), std::io::ErrorKind::InvalidData);

        // (3) One-shot reset → next get returns normal stored content.
        let mut r = mock
            .get(&hash)
            .await
            .expect("post-fire get must resolve Ok");
        let mut buf = Vec::new();
        r.read_to_end(&mut buf)
            .await
            .expect("post-fire read must be clean (slot is one-shot)");
        assert_eq!(&buf, b"the full clean content");
    }

    /// Empty-prefix variant: an armed reader with a zero-length prefix
    /// errors on the very first poll (no bytes ever flow). Guards the
    /// `buf.filled().len() == before` EOF branch when the prefix cursor
    /// is empty from the start.
    #[tokio::test]
    async fn mock_storage_fail_next_get_truncated_empty_prefix_errors_immediately() {
        let mock = MockStoragePort::new();
        let hash: ContentHash = VALID_SHA256_B.parse().unwrap();
        mock.fail_next_get_truncated(hash.clone(), Vec::new());
        let mut r = mock.get(&hash).await.expect("get resolves Ok");
        let mut sink = Vec::new();
        let err = r
            .read_to_end(&mut sink)
            .await
            .expect_err("empty-prefix armed reader must error immediately");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(sink.is_empty(), "no bytes must flow for an empty prefix");
    }

    // -- MockKubernetesSecretWriter -------------------------

    fn make_spec(
        format: hort_domain::entities::service_account::SecretFormat,
    ) -> ManagedSecretSpec {
        ManagedSecretSpec {
            format,
            token_value: zeroize::Zeroizing::new("hort_svc_secret".into()),
            token_id: Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap(),
            service_account_name: "ci-pypi-pusher".into(),
            last_rotated: DateTime::parse_from_rfc3339("2026-05-13T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            registry_host: "registry.example".into(),
        }
    }

    #[tokio::test]
    async fn mock_k8s_writer_read_missing_returns_none() {
        let writer = MockKubernetesSecretWriter::new();
        assert_eq!(writer.read_call_count(), 0);
        let got = writer.read_managed("ci", "hort-token").await.unwrap();
        assert!(got.is_none());
        assert_eq!(writer.read_call_count(), 1);
    }

    #[tokio::test]
    async fn mock_k8s_writer_upsert_then_read_round_trip() {
        let writer = MockKubernetesSecretWriter::new();
        let spec =
            make_spec(hort_domain::entities::service_account::SecretFormat::Dockerconfigjson);
        let token_id = spec.token_id;
        let last_rotated = spec.last_rotated;
        writer
            .upsert_managed("ci", "hort-token", spec)
            .await
            .unwrap();
        let got = writer
            .read_managed("ci", "hort-token")
            .await
            .unwrap()
            .expect("Some after upsert");
        assert_eq!(got.managed_by.as_deref(), Some("hort-worker"));
        assert_eq!(got.service_account.as_deref(), Some("ci-pypi-pusher"));
        assert_eq!(got.token_id, Some(token_id));
        assert_eq!(got.last_rotated, Some(last_rotated));
    }

    #[tokio::test]
    async fn mock_k8s_writer_snapshot_is_sorted_by_ns_then_name() {
        let writer = MockKubernetesSecretWriter::new();
        let mk = |sa: &str| {
            let mut spec = make_spec(hort_domain::entities::service_account::SecretFormat::Opaque);
            spec.service_account_name = sa.into();
            spec
        };
        writer.upsert_managed("ns-z", "z", mk("z")).await.unwrap();
        writer.upsert_managed("ns-a", "b", mk("ab")).await.unwrap();
        writer.upsert_managed("ns-a", "a", mk("aa")).await.unwrap();
        let snap = writer.snapshot();
        let keys: Vec<(String, String)> = snap
            .iter()
            .map(|s| (s.namespace.clone(), s.name.clone()))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("ns-a".into(), "a".into()),
                ("ns-a".into(), "b".into()),
                ("ns-z".into(), "z".into()),
            ]
        );
        assert_eq!(writer.upsert_call_count(), 3);
    }

    #[tokio::test]
    async fn mock_k8s_writer_seed_existing_drives_read_path() {
        // Tests that exercise the freshness check will
        // pre-seed via this surface rather than chaining upserts.
        let writer = MockKubernetesSecretWriter::new();
        let state = MockSecretState {
            namespace: "ci".into(),
            name: "hort-token".into(),
            format: hort_domain::entities::service_account::SecretFormat::Dockerconfigjson,
            token_id: Uuid::nil(),
            service_account_name: "ci-pypi-pusher".into(),
            last_rotated: DateTime::parse_from_rfc3339("2026-05-13T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            registry_host: "registry.example".into(),
        };
        writer.seed_existing("ci", "hort-token", state.clone());
        let got = writer
            .read_managed("ci", "hort-token")
            .await
            .unwrap()
            .expect("Some after seed");
        assert_eq!(got.service_account.as_deref(), Some("ci-pypi-pusher"));
        assert_eq!(got.token_id, Some(state.token_id));
        // Seeding does NOT count as an upsert call.
        assert_eq!(writer.upsert_call_count(), 0);
    }

    /// `MockUpstreamProxy::fetch_referrers`
    /// returns the seeded descriptors through `Arc<dyn UpstreamProxy>`
    /// (the shape the provenance orchestration use case consumes), and
    /// an unseeded key inherits the empty "no referrers" default.
    #[tokio::test]
    async fn mock_upstream_proxy_fetch_referrers_returns_seeded_descriptors() {
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::ports::repository_upstream_mapping_repository::UpstreamAuth;

        let referrers_mapping = |path_prefix: &str| {
            let now = Utc::now();
            RepositoryUpstreamMapping {
                id: Uuid::new_v4(),
                repository_id: Uuid::new_v4(),
                path_prefix: path_prefix.into(),
                upstream_url: "https://registry.example/".into(),
                upstream_name_prefix: None,
                upstream_auth: UpstreamAuth::Anonymous,
                secret_ref: None,
                managed_by: ManagedBy::Local,
                managed_by_digest: None,
                insecure_upstream_url: false,
                trust_upstream_publish_time: false,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
                created_at: now,
                updated_at: now,
            }
        };

        let proxy = MockUpstreamProxy::new();
        let seeded = vec![ReferrerDescriptor {
            digest: "sha256:sig".into(),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            artifact_type: Some("application/vnd.dev.sigstore.bundle.v0.3+json".into()),
        }];
        proxy.insert_referrers("docker", "library/nginx", "sha256:abc", seeded.clone());

        let dyn_proxy: Arc<dyn UpstreamProxy> = Arc::new(proxy);
        let out = dyn_proxy
            .fetch_referrers(
                referrers_mapping("docker"),
                "library/nginx".into(),
                "sha256:abc".into(),
            )
            .await
            .expect("seeded fetch_referrers");
        assert_eq!(out, seeded);

        // Unseeded key → empty (inherits the "no referrers" default).
        let empty = dyn_proxy
            .fetch_referrers(
                referrers_mapping("docker"),
                "library/other".into(),
                "sha256:def".into(),
            )
            .await
            .expect("unseeded fetch_referrers");
        assert!(empty.is_empty());
    }
}
