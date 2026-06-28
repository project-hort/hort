//! Shared mock [`AppContext`] construction for router / handler tests.
//!
//! Gated behind the `test-support` Cargo feature. Downstream test sites
//! (`hort-server` router tests, every `hort-http-<format>` crate's test
//! module) pull this in via
//! `[dev-dependencies] hort-http-core = { ..., features = ["test-support"] }`
//! and call [`build_mock_ctx`] to get a fully-wired disabled-auth
//! [`AppContext`] backed by the `hort-app::use_cases::test_support` mocks.
//! The returned [`MockPorts`] struct exposes concrete `Arc<MockXxx>`
//! handles so callers can seed test fixtures (repos, artifacts, storage
//! content, ephemeral entries, …) after construction.
//!
//! Replaces the ~100-line AppContext wiring that would otherwise be
//! duplicated across every test module in the inbound-HTTP crates
//! (ADR 0008).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use metrics_exporter_prometheus::PrometheusHandle;

use hort_adapters_ephemeral_memory::{InMemoryEphemeralStore, MeteredEphemeralStore};
use hort_app::event_store_publisher::{wrap_for_test, EventStorePublisher};
use hort_app::pull_dedup::{PullDedup, PullDedupConfig};
use hort_app::use_cases::api_token_use_case::{ApiTokenIssuanceConfig, ApiTokenUseCase};
use hort_app::use_cases::artifact_group_use_case::ArtifactGroupUseCase;
use hort_app::use_cases::artifact_use_case::ArtifactUseCase;
use hort_app::use_cases::content_reference::ContentReferenceUseCase;
// Curator decision authority. Wired into
// `AppContext.curation_use_case` so the HTTP decision handlers
// (`/api/v1/admin/curation/...`) can drive `waive` / `block` through the
// shared harness. The use case's three list ports are backed by the
// recording mocks ([`MockCurationQueueRepository`] etc.) defined below.
use hort_app::use_cases::curation_use_case::CurationUseCase;
// Repo-keyed discovery use case. Wired into the
// mock `AppContext` so the `hort-http-discovery` handler tests can drive
// `GET /api/v1/repositories/:repo_key/discovery/versions/:package` through
// the shared harness.
use hort_app::use_cases::discovery_use_case::DiscoveryUseCase;
use hort_app::use_cases::effective_permissions_use_case::EffectivePermissionsUseCase;
use hort_app::use_cases::ingest_use_case::IngestUseCase;
use hort_app::use_cases::manual_rescan_use_case::ManualRescanUseCase;
use hort_app::use_cases::patch_candidate_use_case::PatchCandidateUseCase;
use hort_app::use_cases::scanner_worker_query_use_case::ScannerWorkerQueryUseCase;
// `PolicyUseCase` wired into the mock
// `AppContext` so the HTTP exclusion write endpoints
// (`/api/v1/admin/policies/:policy_id/exclusions[/:cve_id]`) drive the
// same use case the production composition root threads.
use hort_app::use_cases::policy_use_case::PolicyUseCase;
// Prefetch planner; wired into the mock
// `AppContext` so format-crate tests can drive the trigger path.
use hort_app::use_cases::prefetch_use_case::PrefetchUseCase;
use hort_app::use_cases::promotion_use_case::PromotionUseCase;
use hort_app::use_cases::quarantine_use_case::QuarantineUseCase;
use hort_app::use_cases::rbac_resolve_use_case::RbacResolveUseCase;
use hort_app::use_cases::ref_use_case::RefUseCase;
use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
use hort_app::use_cases::repository_use_case::RepositoryUseCase;
use hort_app::use_cases::security_score_use_case::SecurityScoreUseCase;
use hort_app::use_cases::virtual_resolution::VirtualResolutionUseCase;
// Repo-keyed self-service prefetch use case.
// Wired into the mock `AppContext` so the `hort-http-discovery` handler
// tests can drive `POST /api/v1/repositories/:repo_key/prefetch` through
// the shared harness.
use hort_app::use_cases::self_service_prefetch_use_case::SelfServicePrefetchUseCase;
use hort_app::use_cases::subscription_use_case::{SubscriptionUseCase, SubscriptionUseCaseConfig};
use hort_app::use_cases::task_use_case::TaskUseCase;
use hort_app::use_cases::test_support::{
    MockApiTokenRepository, MockArtifactGroupLifecyclePort, MockArtifactGroupRepository,
    MockArtifactLifecycle, MockArtifactMetadataRepository, MockArtifactRepository,
    MockClaimMappingRepository, MockContentReferenceIndex, MockCurationRuleRepository,
    MockEventStore, MockJobsRepository, MockPermissionGrantRepository,
    MockPolicyProjectionRepository, MockRefLifecyclePort, MockRefRegistryPort,
    MockRepoSecurityScoreRepository, MockRepositoryRepository,
    MockRepositoryUpstreamMappingRepository, MockStatefulUploadStagingPort, MockStoragePort,
    MockUpstreamMetadataPort, MockUpstreamProxy, MockUpstreamResolver, MockUserRepository,
};
use hort_app::use_cases::user_use_case::UserUseCase;
// PEP 658 `.metadata` read-path use case.
use hort_app::use_cases::wheel_metadata_use_case::WheelMetadataUseCase;

use hort_domain::entities::subscription::{
    SsrfBlockReason, Subscription, SubscriptionFailure, SubscriptionId, SubscriptionState,
};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::curation_decisions_repository::{
    CurationDecisionEntry, CurationDecisionFilter, CurationDecisionsRepository,
};
use hort_domain::ports::curation_exclusions_repository::{
    CurationExclusionEntry, CurationExclusionFilter, CurationExclusionsRepository,
};
use hort_domain::ports::curation_queue_repository::{
    CurationQueueEntry, CurationQueueFilter, CurationQueueRepository,
};
use hort_domain::ports::event_store::EventStore;
use hort_domain::ports::metadata_mirror_store::MetadataMirrorStore;
use hort_domain::ports::patch_candidate_repository::{
    PatchCandidate, PatchCandidateFilter, PatchCandidateRepository,
};
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::scanner_registry_repository::{
    ScannerRegistryEntry, ScannerRegistryRepository,
};
use hort_domain::ports::storage::StoragePort;
use hort_domain::ports::subscription_repository::SubscriptionRepository;
use hort_domain::ports::webhook_target_guard::WebhookTargetGuard;
use hort_domain::ports::BoxFuture;
use hort_domain::types::{Page, PageRequest};
use uuid::Uuid;

use crate::context::{AppContext, AuthContext};
use crate::middleware::rate_limit::RateLimitConfig;
use crate::middleware::trust::TrustConfig;
use crate::url_resolver::UrlResolver;

/// Handler-layer mock for
/// [`PatchCandidateRepository`].
///
/// Lives here (not in `hort-app::use_cases::test_support`) because it is
/// only consumed by handler tests in `hort-http-core::handlers::admin`
/// and by downstream inbound-HTTP crates pulling
/// `hort-http-core/test-support` in dev-deps. The use-case layer has its
/// own inline private mock in
/// `crates/hort-app/src/use_cases/patch_candidate_use_case.rs`.
///
/// Recorded `list_candidates(filter)` calls are returned by [`Self::calls`];
/// the seeded rows are returned in insertion order, clamped at
/// `filter.limit` items.
pub struct MockPatchCandidateRepository {
    calls: Mutex<Vec<PatchCandidateFilter>>,
    rows: Mutex<Vec<PatchCandidate>>,
}

impl Default for MockPatchCandidateRepository {
    fn default() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            rows: Mutex::new(Vec::new()),
        }
    }
}

impl MockPatchCandidateRepository {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the rows returned by the next `list_candidates` call.
    /// Insertion order is preserved (the SQL adapter's `ORDER BY` is
    /// deterministic; tests rely on that).
    pub fn seed(&self, rows: Vec<PatchCandidate>) {
        *self.rows.lock().unwrap() = rows;
    }

    /// Recorded `list_candidates` calls (one entry per invocation, in
    /// call order). Tests assert on this to prove the use case was —
    /// or was not — reached.
    pub fn calls(&self) -> Vec<PatchCandidateFilter> {
        self.calls.lock().unwrap().clone()
    }
}

impl PatchCandidateRepository for MockPatchCandidateRepository {
    fn list_candidates<'a>(
        &'a self,
        filter: PatchCandidateFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<PatchCandidate>>> {
        Box::pin(async move {
            let limit = filter.limit as usize;
            self.calls.lock().unwrap().push(filter);
            let rows = self.rows.lock().unwrap().clone();
            // Clamp on the seeded order — mirrors the adapter's
            // `LIMIT $n` semantics so handler tests can assert that
            // `limit` is honoured end-to-end.
            Ok(rows.into_iter().take(limit).collect())
        })
    }
}

/// Handler-layer mock for [`ScannerRegistryRepository`].
///
/// Lives here (not in `hort-app::use_cases::test_support`) because it is
/// only consumed by handler tests in `hort-http-core::handlers::admin` and
/// downstream inbound-HTTP crates pulling `hort-http-core/test-support`.
/// The use-case layer has its own inline private mock in
/// `crates/hort-app/src/use_cases/scanner_worker_query_use_case.rs`.
///
/// `list_all` returns the seeded rows in insertion order; the write methods
/// are no-ops (the admin read path never calls them).
pub struct MockScannerRegistryRepository {
    rows: Mutex<Vec<ScannerRegistryEntry>>,
}

impl Default for MockScannerRegistryRepository {
    fn default() -> Self {
        Self {
            rows: Mutex::new(Vec::new()),
        }
    }
}

impl MockScannerRegistryRepository {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the rows returned by the next `list_all` call.
    pub fn seed(&self, rows: Vec<ScannerRegistryEntry>) {
        *self.rows.lock().unwrap() = rows;
    }
}

impl ScannerRegistryRepository for MockScannerRegistryRepository {
    fn upsert_self<'a>(
        &'a self,
        _worker_id: &'a str,
        _backends: Vec<String>,
    ) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }
    fn refresh_heartbeat<'a>(&'a self, _worker_id: &'a str) -> BoxFuture<'a, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }
    fn list_all<'a>(&'a self) -> BoxFuture<'a, DomainResult<Vec<ScannerRegistryEntry>>> {
        Box::pin(async move { Ok(self.rows.lock().unwrap().clone()) })
    }
    fn prune_stale<'a>(
        &'a self,
        _older_than: std::time::Duration,
    ) -> BoxFuture<'a, DomainResult<u64>> {
        Box::pin(async { Ok(0) })
    }
}

// ---------------------------------------------------------------------------
// Recording curation list-port mocks
//
// The decision-endpoint handlers only call `waive` / `block`, but
// [`CurationUseCase`]'s three list ports are recording mocks — handler
// tests for `GET /api/v1/admin/curation/{queue,decisions,exclusions}`
// seed a result Vec and assert the filter the use case forwards to the
// port.
//
// Shape mirrors the use-case-layer mocks in
// `hort-app::use_cases::curation_use_case::tests` (`Mutex<Option<…>>` +
// `Mutex<Result<…, …>>`) so the same mental model carries across the
// two surfaces. The handles are exposed via [`MockPorts`] so tests do
// `mocks.curation_queue.set_result(...)` then drive the handler.
// ---------------------------------------------------------------------------

/// Recording mock for [`CurationQueueRepository`].
///
/// `set_result` seeds the next call's return value; `recorded_filters`
/// returns every filter the use case forwarded (Vec, FIFO). The default
/// result is `Ok(Vec::new())` — handlers that don't seed a result still
/// observe the empty-list happy path.
pub struct MockCurationQueueRepository {
    recorded: Mutex<Vec<CurationQueueFilter>>,
    result: Mutex<DomainResult<Vec<CurationQueueEntry>>>,
}

impl Default for MockCurationQueueRepository {
    fn default() -> Self {
        Self {
            recorded: Mutex::new(Vec::new()),
            result: Mutex::new(Ok(Vec::new())),
        }
    }
}

impl MockCurationQueueRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_result(&self, result: DomainResult<Vec<CurationQueueEntry>>) {
        *self.result.lock().unwrap() = result;
    }

    pub fn recorded_filters(&self) -> Vec<CurationQueueFilter> {
        self.recorded.lock().unwrap().clone()
    }
}

impl CurationQueueRepository for MockCurationQueueRepository {
    fn list_queue<'a>(
        &'a self,
        filter: CurationQueueFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<CurationQueueEntry>>> {
        self.recorded.lock().unwrap().push(filter);
        let result = match &*self.result.lock().unwrap() {
            Ok(v) => Ok(v.clone()),
            Err(e) => Err(e.clone()),
        };
        Box::pin(async move { result })
    }
}

/// Recording mock for [`CurationDecisionsRepository`].
/// Mirrors [`MockCurationQueueRepository`].
pub struct MockCurationDecisionsRepository {
    recorded: Mutex<Vec<CurationDecisionFilter>>,
    result: Mutex<DomainResult<Vec<CurationDecisionEntry>>>,
}

impl Default for MockCurationDecisionsRepository {
    fn default() -> Self {
        Self {
            recorded: Mutex::new(Vec::new()),
            result: Mutex::new(Ok(Vec::new())),
        }
    }
}

impl MockCurationDecisionsRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_result(&self, result: DomainResult<Vec<CurationDecisionEntry>>) {
        *self.result.lock().unwrap() = result;
    }

    pub fn recorded_filters(&self) -> Vec<CurationDecisionFilter> {
        self.recorded.lock().unwrap().clone()
    }
}

impl CurationDecisionsRepository for MockCurationDecisionsRepository {
    fn list_decisions<'a>(
        &'a self,
        filter: CurationDecisionFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<CurationDecisionEntry>>> {
        self.recorded.lock().unwrap().push(filter);
        let result = match &*self.result.lock().unwrap() {
            Ok(v) => Ok(v.clone()),
            Err(e) => Err(e.clone()),
        };
        Box::pin(async move { result })
    }
}

/// Recording mock for [`CurationExclusionsRepository`].
/// Mirrors [`MockCurationQueueRepository`].
pub struct MockCurationExclusionsRepository {
    recorded: Mutex<Vec<CurationExclusionFilter>>,
    result: Mutex<DomainResult<Vec<CurationExclusionEntry>>>,
}

impl Default for MockCurationExclusionsRepository {
    fn default() -> Self {
        Self {
            recorded: Mutex::new(Vec::new()),
            result: Mutex::new(Ok(Vec::new())),
        }
    }
}

impl MockCurationExclusionsRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_result(&self, result: DomainResult<Vec<CurationExclusionEntry>>) {
        *self.result.lock().unwrap() = result;
    }

    pub fn recorded_filters(&self) -> Vec<CurationExclusionFilter> {
        self.recorded.lock().unwrap().clone()
    }
}

impl CurationExclusionsRepository for MockCurationExclusionsRepository {
    fn list_exclusions<'a>(
        &'a self,
        filter: CurationExclusionFilter,
    ) -> BoxFuture<'a, DomainResult<Vec<CurationExclusionEntry>>> {
        self.recorded.lock().unwrap().push(filter);
        let result = match &*self.result.lock().unwrap() {
            Ok(v) => Ok(v.clone()),
            Err(e) => Err(e.clone()),
        };
        Box::pin(async move { result })
    }
}

// ---------------------------------------------------------------------------
// MockSubscriptionRepository / MockWebhookTargetGuard
//
// Inlined here (not imported from `hort-app::use_cases::test_support`)
// because the use-case-layer's mocks live inside the `#[cfg(test)]`
// inline `mod tests` of `subscription_use_case.rs` — they are not
// `pub` and therefore not reusable across crates, so the cleanest
// move is to keep one canonical pair here. The use-case tests keep their
// private copies — different test surfaces, different shapes, no
// shared invariant to break.
// ---------------------------------------------------------------------------

/// Handler-layer mock for
/// [`SubscriptionRepository`]. In-memory `HashMap` over
/// `SubscriptionId`; `find_by_name` collation matches the Postgres
/// adapter's `(owner_user_id, name)` unique key.
pub struct MockSubscriptionRepository {
    items: Mutex<HashMap<SubscriptionId, Subscription>>,
}

impl Default for MockSubscriptionRepository {
    fn default() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
        }
    }
}

impl MockSubscriptionRepository {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a row directly (bypasses the create-side audit event).
    /// Tests asserting GET / PATCH / DELETE shapes use this to set up
    /// the row without driving the full create flow.
    pub fn seed(&self, sub: Subscription) {
        self.items.lock().unwrap().insert(sub.id, sub);
    }

    /// Number of seeded / created rows currently in the mock.
    pub fn count(&self) -> usize {
        self.items.lock().unwrap().len()
    }

    /// Synchronous list of subscriptions for `owner` — convenience for
    /// tests that need to inspect / mutate the seeded state without
    /// going through the async port (which would force the test to
    /// run inside a future).
    pub fn list_for_owner_blocking(&self, owner: Uuid) -> Vec<Subscription> {
        self.items
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.owner_user_id == owner)
            .cloned()
            .collect()
    }
}

impl SubscriptionRepository for MockSubscriptionRepository {
    fn create(&self, s: &Subscription) -> BoxFuture<'_, DomainResult<()>> {
        // Mirror the Postgres adapter's `(owner_user_id, name)` unique
        // collation — duplicates surface as `DomainError::Conflict`,
        // which the use case maps to `DuplicateName`.
        let mut items = self.items.lock().unwrap();
        if items
            .values()
            .any(|existing| existing.owner_user_id == s.owner_user_id && existing.name == s.name)
        {
            return Box::pin(async {
                Err(DomainError::Conflict(
                    "duplicate (owner, name) on subscriptions row".into(),
                ))
            });
        }
        items.insert(s.id, s.clone());
        Box::pin(async { Ok(()) })
    }

    fn find_by_id(&self, id: SubscriptionId) -> BoxFuture<'_, DomainResult<Subscription>> {
        let result = self.items.lock().unwrap().get(&id).cloned();
        Box::pin(async move {
            result.ok_or(DomainError::NotFound {
                entity: "Subscription",
                id: id.0.to_string(),
            })
        })
    }

    fn find_by_name(
        &self,
        owner: Uuid,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<Subscription>>> {
        let needle = name.to_string();
        let result = self
            .items
            .lock()
            .unwrap()
            .values()
            .find(|s| s.owner_user_id == owner && s.name == needle)
            .cloned();
        Box::pin(async move { Ok(result) })
    }

    fn list_for_owner(
        &self,
        owner: Uuid,
        page: PageRequest,
    ) -> BoxFuture<'_, DomainResult<Page<Subscription>>> {
        let all: Vec<Subscription> = self
            .items
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.owner_user_id == owner)
            .cloned()
            .collect();
        let total = all.len() as u64;
        let start = (page.offset as usize).min(all.len());
        let end = ((page.offset + page.limit) as usize).min(all.len());
        let items = all[start..end].to_vec();
        Box::pin(async move { Ok(Page { items, total }) })
    }

    fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<Subscription>>> {
        let items: Vec<Subscription> = self
            .items
            .lock()
            .unwrap()
            .values()
            .filter(|s| matches!(s.state, SubscriptionState::Active))
            .cloned()
            .collect();
        Box::pin(async move { Ok(items) })
    }

    fn update(&self, s: &Subscription) -> BoxFuture<'_, DomainResult<()>> {
        self.items.lock().unwrap().insert(s.id, s.clone());
        Box::pin(async { Ok(()) })
    }

    fn delete(&self, id: SubscriptionId) -> BoxFuture<'_, DomainResult<()>> {
        self.items.lock().unwrap().remove(&id);
        Box::pin(async { Ok(()) })
    }

    fn update_last_delivered(
        &self,
        id: SubscriptionId,
        position: u64,
        last_failure: Option<&SubscriptionFailure>,
    ) -> BoxFuture<'_, DomainResult<()>> {
        let lf = last_failure.cloned();
        let mut items = self.items.lock().unwrap();
        if let Some(s) = items.get_mut(&id) {
            s.last_delivered_position = Some(position);
            s.last_failure = lf;
        }
        Box::pin(async { Ok(()) })
    }
}

/// Handler-layer mock for
/// [`WebhookTargetGuard`]. Default constructor allows every URL; tests
/// asserting the SSRF reject path build via [`Self::deny`].
pub struct MockWebhookTargetGuard {
    result: Mutex<Result<(), SsrfBlockReason>>,
}

impl Default for MockWebhookTargetGuard {
    fn default() -> Self {
        Self::allow()
    }
}

impl MockWebhookTargetGuard {
    /// Guard that accepts every URL. The default used by `build_mock_ctx`.
    pub fn allow() -> Self {
        Self {
            result: Mutex::new(Ok(())),
        }
    }

    /// Guard that rejects every URL with the supplied reason. Tests
    /// asserting the `WebhookTargetNotRoutable` reject path build via
    /// this constructor.
    pub fn deny(reason: SsrfBlockReason) -> Self {
        Self {
            result: Mutex::new(Err(reason)),
        }
    }
}

impl WebhookTargetGuard for MockWebhookTargetGuard {
    fn check<'a>(&'a self, _url: &'a url::Url) -> BoxFuture<'a, Result<(), SsrfBlockReason>> {
        let r = *self.result.lock().unwrap();
        Box::pin(async move { r })
    }
}

/// `TrustConfig` with **no** pinned `public_base_url` and no trusted
/// proxies — used by handler tests that need the trust layer to fall
/// back to `Host` + `https` for untrusted peers. Distinct from
/// [`TrustConfig::default()`], which pins
/// `http://hort-server:8080` to match production docker-compose.
pub fn trust_config_untrusted_peer_fallback() -> TrustConfig {
    TrustConfig::new(
        None,
        Vec::new(),
        url::Url::parse("http://0.0.0.0:8080/").expect("valid test bind-address fallback URL"),
    )
}

/// In-memory [`MetadataMirrorStore`] mock for the raw
/// upstream-metadata mirror slot on [`AppContext::metadata_mirror`].
///
/// A logical-keyed `Mutex<HashMap<String, Vec<u8>>>`: `put` overwrites,
/// `get` streams back (or `None`), `delete` is idempotent. Tests that need
/// to assert mirror writes hold the same `Arc<MockMetadataMirror>` and
/// inspect it via [`MockMetadataMirror::get`] / [`MockMetadataMirror::keys`].
#[derive(Default)]
pub struct MockMetadataMirror {
    data: Mutex<HashMap<String, Vec<u8>>>,
}

impl MockMetadataMirror {
    /// All keys currently held, for test assertions.
    pub fn keys(&self) -> Vec<String> {
        self.data.lock().unwrap().keys().cloned().collect()
    }
}

/// Read a mirror key's bytes back through the
/// [`MetadataMirrorStore::get`] trait method (the mock has no sync byte
/// accessor beyond [`MockMetadataMirror::keys`]).
///
/// Hoisted here from the byte-identical `read_mirror` test helpers the npm /
/// cargo / pypi proxy-cache test modules each carried. Returns `None` when the
/// key is absent; otherwise the full body buffered into a `Vec<u8>`.
pub async fn read_mirror(mocks: &MockPorts, key: &str) -> Option<Vec<u8>> {
    let mut reader = mocks.metadata_mirror.get(key).await.unwrap()?;
    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
        .await
        .unwrap();
    Some(buf)
}

impl MetadataMirrorStore for MockMetadataMirror {
    fn put(
        &self,
        key: &str,
        mut body: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<()>> {
        let key = key.to_string();
        Box::pin(async move {
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut body, &mut buf)
                .await
                .map_err(|e| DomainError::Invariant(format!("mock mirror read: {e}")))?;
            self.data.lock().unwrap().insert(key, buf);
            Ok(())
        })
    }

    fn get(
        &self,
        key: &str,
    ) -> BoxFuture<'_, DomainResult<Option<Box<dyn tokio::io::AsyncRead + Send + Unpin>>>> {
        let value = self.data.lock().unwrap().get(key).cloned();
        Box::pin(async move {
            Ok(value.map(|v| {
                Box::new(std::io::Cursor::new(v)) as Box<dyn tokio::io::AsyncRead + Send + Unpin>
            }))
        })
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
        self.data.lock().unwrap().remove(key);
        Box::pin(async move { Ok(()) })
    }
}

/// Handles to every mock port wired into the [`AppContext`] returned by
/// [`build_mock_ctx`].
///
/// Each field is a concrete `Arc<Mock…>`, not a trait object, so test code
/// can call the mock's seeding methods (`insert`, `insert_content`, …)
/// directly without downcasting. The same `Arc` is also stored inside the
/// returned `AppContext` behind a `dyn Port` coercion, so seeds made on
/// the mock are visible to handlers driven through the context.
pub struct MockPorts {
    pub artifacts: Arc<MockArtifactRepository>,
    pub repositories: Arc<MockRepositoryRepository>,
    pub storage: Arc<MockStoragePort>,
    pub events: Arc<MockEventStore>,
    pub lifecycle: Arc<MockArtifactLifecycle>,
    pub users: Arc<MockUserRepository>,
    pub artifact_metadata: Arc<MockArtifactMetadataRepository>,
    pub artifact_groups: Arc<MockArtifactGroupRepository>,
    pub artifact_group_lifecycle: Arc<MockArtifactGroupLifecyclePort>,
    pub refs: Arc<MockRefRegistryPort>,
    pub ref_lifecycle: Arc<MockRefLifecyclePort>,
    /// Handle to the **evictable** in-memory
    /// [`EphemeralStore`](hort_domain::ports::ephemeral_store::EphemeralStore)
    /// wired into the mock [`AppContext`]. Routed to cache consumers
    /// (Cargo / PyPI / npm caches, pull-through dedup). Distinct from
    /// [`Self::ephemeral_durable`] — a write here is invisible from
    /// the durable handle and vice versa. This matches what
    /// production multi-Redis would do, preserving the
    /// keyspace-isolation invariant in tests by mechanical default.
    pub ephemeral_evictable: Arc<MeteredEphemeralStore<InMemoryEphemeralStore>>,
    /// Handle to the **durable** in-memory
    /// [`EphemeralStore`](hort_domain::ports::ephemeral_store::EphemeralStore)
    /// wired into the mock [`AppContext`]. Routed to durable consumers
    /// (auth lockout, PAT lockout, OCI upload session records, OCI
    /// session-count caps, auth-event throttle). Distinct from
    /// [`Self::ephemeral_evictable`] — see that field's doc.
    pub ephemeral_durable: Arc<MeteredEphemeralStore<InMemoryEphemeralStore>>,
    /// In-memory raw-metadata mirror wired into
    /// [`AppContext::metadata_mirror`]. The same `Arc` is held on the
    /// context (pointer-equal); tests asserting that a fetch path mirrored
    /// the raw upstream body inspect it via [`MockMetadataMirror::keys`] /
    /// [`MockMetadataMirror::get`].
    pub metadata_mirror: Arc<MockMetadataMirror>,
    /// `PullDedup` service constructed over the
    /// in-memory `ephemeral_evictable` store with
    /// [`PullDedupConfig::defaults()`]. Same `Arc` is held on
    /// `AppContext.pull_dedup` (pointer-equal — see the `Arc::ptr_eq`
    /// assertion in this module's tests). Choosing the real service
    /// over a mock matches the harness-wide mock pattern: tests pass
    /// on memory ⇒ tests pass on Redis. Tests asserting follower /
    /// leader Layer-B coordination drive both the `coalesce_*` API
    /// through `ctx.pull_dedup` AND inspect the underlying ephemeral
    /// state via `ephemeral_evictable` directly.
    pub pull_dedup: Arc<PullDedup>,
    /// Format-agnostic staging port. Tests
    /// that need Maven / LFS staging reach through the same handle.
    pub stateful_upload_staging: Arc<MockStatefulUploadStagingPort>,
    /// Content-reference projection mock.
    /// Tests seeding cross-artifact references drive this handle.
    pub content_references: Arc<MockContentReferenceIndex>,
    /// In-memory upstream-mapping CRUD mock.
    /// Tests seeding multi-upstream OCI mirrors drive this handle.
    pub repository_upstream_mappings: Arc<MockRepositoryUpstreamMappingRepository>,
    /// In-memory upstream resolver mock.
    /// Tests asserting longest-prefix routing through the live
    /// pull-through path drive this handle (insert mappings, then
    /// the OCI handler hits the resolver).
    pub upstream_resolver: Arc<MockUpstreamResolver>,
    /// In-memory upstream proxy mock.
    /// Tests preload blob/manifest payloads keyed by (path_prefix,
    /// upstream_name, ref) and assert the OCI pull path threads
    /// the mapping + name through correctly.
    pub upstream_proxy: Arc<MockUpstreamProxy>,
    /// `policy_projections` /
    /// `exclusion_projections` mock. Wired into
    /// `QuarantineUseCase` so handler tests can seed a
    /// repo-scoped or global policy + exclusions and observe the
    /// scan-result evaluation path. Empty by default — tests that
    /// don't touch policy enforcement see the `DefaultPolicy`
    /// "block on critical only" semantics.
    pub policy_projections: Arc<MockPolicyProjectionRepository>,
    /// `curation_rules` mock. Wired into
    /// `IngestUseCase` so handler tests can seed `Block` / `Warn`
    /// rules per repository and observe the pre-storage curation
    /// gate. Empty by default — tests that don't touch curation
    /// see the fast-path Allow.
    pub curation_rules: Arc<MockCurationRuleRepository>,
    /// Native API token repository mock
    /// wired into `ApiTokenUseCase`. Tests asserting issuance /
    /// revocation / listing read the recorded calls off this
    /// handle.
    pub api_tokens: Arc<MockApiTokenRepository>,
    /// `repo_security_scores` projection mock
    /// wired into `SecurityScoreUseCase`. Tests asserting the
    /// `/security-score` REST surface seed rows via this handle.
    pub security_scores: Arc<MockRepoSecurityScoreRepository>,
    /// `jobs` table mock wired into
    /// `TaskUseCase`. Tests asserting the `/api/v1/admin/tasks/*`
    /// REST surface seed rows and read enqueue calls via this handle.
    pub jobs: Arc<MockJobsRepository>,
    /// `patch_candidates` mock wired into
    /// `PatchCandidateUseCase`. Tests asserting the
    /// `GET /admin/quarantine/patch-candidates` surface seed rows via
    /// `seed(...)` and read recorded filters via `calls()`.
    pub patch_candidates: Arc<MockPatchCandidateRepository>,
    /// `scanner_registry` mock wired into
    /// `ScannerWorkerQueryUseCase`. Tests asserting the
    /// `GET /admin/workers` surface seed rows via `seed(...)`.
    pub scanner_workers: Arc<MockScannerRegistryRepository>,
    /// `PermissionGrantRepository` mock wired
    /// into `EffectivePermissionsUseCase` AND
    /// `RbacResolveUseCase`. Tests asserting
    /// `GET /admin/users/:user_id/effective-permissions` and
    /// `POST /admin/rbac/resolve` seed the grant set via `seed(...)`.
    pub permission_grants: Arc<MockPermissionGrantRepository>,
    /// `ClaimMappingRepository` mock wired into
    /// `RbacResolveUseCase`. Tests asserting `POST /admin/rbac/resolve`
    /// seed the group→claim mappings via `seed(...)`.
    pub claim_mappings: Arc<MockClaimMappingRepository>,
    /// In-memory `SubscriptionRepository` mock
    /// wired into `SubscriptionUseCase`. Tests driving the
    /// `/api/v1/subscriptions` surface seed rows via `seed(...)`.
    pub subscriptions: Arc<MockSubscriptionRepository>,
    /// `WebhookTargetGuard` mock wired into
    /// `SubscriptionUseCase`. Defaults to "allow every URL" (allow);
    /// tests asserting the SSRF reject path rebuild the context via a
    /// custom guard.
    pub webhook_guard: Arc<MockWebhookTargetGuard>,
    /// Recording mock for the curation-queue
    /// list port. Same `Arc` wired into `CurationUseCase`; tests drive
    /// `GET /api/v1/admin/curation/queue` then assert the filter the
    /// use case forwarded via [`MockCurationQueueRepository::recorded_filters`].
    pub curation_queue: Arc<MockCurationQueueRepository>,
    /// Recording mock for the curation-decisions
    /// list port. Tests seed events via
    /// [`MockCurationDecisionsRepository::set_result`] then drive
    /// `GET /api/v1/admin/curation/decisions`.
    pub curation_decisions: Arc<MockCurationDecisionsRepository>,
    /// Recording mock for the active-exclusions
    /// list port. Tests seed exclusion rows then drive
    /// `GET /api/v1/admin/curation/exclusions`.
    pub curation_exclusions: Arc<MockCurationExclusionsRepository>,
    /// In-memory mock for
    /// [`hort_app::ports::upstream_metadata::UpstreamMetadataPort`] wired
    /// into both `DiscoveryUseCase` and `SelfServicePrefetchUseCase`.
    /// Tests driving the `GET /discovery/...` + `POST /prefetch`
    /// endpoints seed per-`(format, package)` version lists via
    /// `mocks.upstream_metadata.insert_versions(...)`.
    pub upstream_metadata: Arc<MockUpstreamMetadataPort>,
}

/// Seed a permissive global `ScanPolicyProjection`
/// (`quarantine_duration_secs = 0`) onto the supplied projections
/// mock so existing HTTP-handler tests, which pre-date the
/// quarantine-by-default flip, keep their pre-flip baseline:
/// pull-through cache-miss ingests do NOT auto-quarantine and
/// `download_proxy_cache_miss` tests still return 200. Tests that
/// exercise the Default-policy fire or operator-strict quarantine
/// against the HTTP layer must clear / overwrite this seed via the
/// `policy_projections` handle on [`MockPorts`].
///
/// Mirrors the inline `seed_permissive_global_policy` helper in
/// `hort-app::use_cases::ingest_use_case::tests` (the unit-test
/// harness wires the same pre-seed for the same reason).
///
/// **Known blind spot.** This fixture
/// silently overrides the production default-policy posture; a NEW
/// HTTP-handler test that intends to assert default-policy quarantine
/// will not trip it unless it explicitly clears or replaces the seed.
/// HTTP-layer default-fire assertions are NOT the right surface —
/// prefer `hort-app::use_cases::ingest_use_case::tests` with
/// `make_scan_gated_use_case`, which deliberately seeds nothing. A
/// future inversion ("quarantine-by-default in fixtures, test opts
/// in to permissive") would close the blind spot but has not been
/// adopted.
pub fn seed_permissive_global_policy_for_tests(projections: &MockPolicyProjectionRepository) {
    use chrono::Utc;
    use hort_domain::entities::scan_policy::{
        NegligibleAction, ProvenanceMode, ScanPolicyProjection, SeverityThreshold,
    };
    use hort_domain::events::PolicyScope;
    let now = Utc::now();
    projections.insert(ScanPolicyProjection {
        policy_id: Uuid::from_u128(0x0046_0002_0000_0000_0000_0000_0000_0002),
        name: "permissive-http-test-default".to_string(),
        scope: PolicyScope::Global,
        severity_threshold: SeverityThreshold::Critical,
        quarantine_duration_secs: 0, // permissive — no quarantine on ingest
        require_approval: false,
        provenance_mode: ProvenanceMode::VerifyIfPresent,
        provenance_backends: vec!["cosign".to_string()],
        provenance_identities: Vec::new(),
        max_artifact_age_secs: None,
        license_policy: serde_json::Value::Null,
        archived: false,
        scan_backends: vec!["trivy".to_string()],
        rescan_interval_hours: 24,
        negligible_action: NegligibleAction::Ignore,
        stream_version: 0,
        created_at: now,
        updated_at: now,
    });
}

/// Build a fully-wired disabled-auth [`AppContext`] backed by in-memory
/// mocks, with `include_repository_label = true`.
///
/// The returned [`MockPorts`] exposes handles to every mock so tests can
/// seed fixtures before exercising the router. Defaults applied:
///
/// - `auth: AuthContext::Disabled`
/// - `trust_config: TrustConfig::default()` — tests that need a pinned
///   public URL should rebuild the trust-sensitive fields after calling
///   this helper via [`with_trust_config`]
/// - `rate_limit_config: RateLimitConfig::default()`
/// - `publish_body_limit_bytes: None`
/// - `include_repository_label: true`
///
/// Use [`with_auth`] to flip to `AuthContext::Enabled` without
/// reconstructing every port. Use [`build_mock_ctx_with_label_flag`]
/// when a test needs to exercise the `_all`-sentinel branch.
pub fn build_mock_ctx(handle: PrometheusHandle) -> (Arc<AppContext>, MockPorts) {
    build_mock_ctx_with_label_flag(handle, true)
}

/// Variant of [`build_mock_ctx`] that threads `include_repository_label`
/// through every use-case constructor so pypi/cargo/npm emission tests
/// can exercise both the real-label and `_all`-sentinel branches.
pub fn build_mock_ctx_with_label_flag(
    handle: PrometheusHandle,
    include_repository_label: bool,
) -> (Arc<AppContext>, MockPorts) {
    let artifacts = Arc::new(MockArtifactRepository::new());
    let repositories = Arc::new(MockRepositoryRepository::new());
    let events = Arc::new(MockEventStore::new());
    // Every use case (and AppContext.event_store)
    // takes `Arc<EventStorePublisher>`. The mock test harness wraps
    // the same underlying `MockEventStore` in a no-broadcast publisher;
    // both shapes share storage via the inner `Arc`, so test seeding +
    // assertions on `events.appended_batches()` continue to work
    // verbatim.
    let event_publisher = wrap_for_test(events.clone());
    let storage = Arc::new(MockStoragePort::new());
    // In-memory raw-metadata mirror for
    // `AppContext::metadata_mirror`.
    let metadata_mirror = Arc::new(MockMetadataMirror::default());
    let users = Arc::new(MockUserRepository::new());
    let artifact_metadata = Arc::new(MockArtifactMetadataRepository::new());
    // Wire the lifecycle through the metadata repo so a
    // `commit_transition(metadata: Some(_))` call lands in
    // `MockArtifactMetadataRepository` — same as the real Postgres
    // adapter's atomic artifact + metadata write. Without this,
    // pull-through ingest tests that read back the persisted
    // `oci_media_type` see only the no-metadata-row default.
    let lifecycle = Arc::new(
        MockArtifactLifecycle::new(artifacts.clone()).with_metadata_repo(artifact_metadata.clone()),
    );

    let jobs = Arc::new(MockJobsRepository::new());
    let repository_use_case = Arc::new(RepositoryUseCase::new(repositories.clone()));
    // `RepositoryAccessUseCase` for handler-side
    // visibility / authz checks. Mock harness defaults to
    // `RbacAccess::Disabled` (admit-everything) so existing tests that
    // never opt into RBAC keep working unchanged. Tests that need
    // enabled-RBAC semantics rebuild via [`with_repository_access`].
    let repository_access_use_case = Arc::new(RepositoryAccessUseCase::new(
        repositories.clone(),
        RbacAccess::Disabled,
        include_repository_label,
    ));
    let artifact_use_case = Arc::new(
        ArtifactUseCase::new(
            artifacts.clone(),
            storage.clone(),
            repositories.clone(),
            include_repository_label,
        )
        .with_repository_access(repository_access_use_case.clone())
        .with_artifact_metadata(artifact_metadata.clone())
        // Wire the opt-in download-audit
        // gate to the same no-broadcast publisher every other use case
        // shares so format-crate tests can assert the captured
        // `ArtifactDownloaded` batch on `MockPorts.events`. Mirrors the
        // production composition wiring; no-op unless the served repo
        // sets `download_audit_enabled = true`.
        .with_audit_events(event_publisher.clone()),
    );
    let artifact_groups = Arc::new(MockArtifactGroupRepository::new());
    let artifact_group_lifecycle =
        Arc::new(MockArtifactGroupLifecyclePort::new(artifact_groups.clone()));
    let artifact_group_use_case = Arc::new(ArtifactGroupUseCase::new(
        artifact_groups.clone(),
        artifact_group_lifecycle.clone(),
        include_repository_label,
    ));
    let curation_rules = Arc::new(MockCurationRuleRepository::new());
    // Hoisted ahead of IngestUseCase so the same Arc
    // threads into both `IngestUseCase::new` (refcount writes) and
    // `ContentReferenceUseCase::new` (below).
    let content_references = Arc::new(MockContentReferenceIndex::new());
    // Same `policy_projections` Arc threads into
    // both `IngestUseCase::new` (ingest-time scan auto-enqueue) and
    // `QuarantineUseCase::new` below. Hoisted ahead of ingest for the
    // same reason `content_references` is hoisted.
    //
    // Seed a permissive global ScanPolicy so existing
    // HTTP-handler tests, which pre-date the quarantine-by-default
    // flip, keep their pre-flip baseline (no quarantine on
    // pull-through-cache-miss ingests; `download_proxy_cache_miss`
    // tests still return 200). Tests that exercise the Default-policy
    // fire or operator-strict quarantine must clear / overwrite this
    // seed.
    let policy_projections = Arc::new(MockPolicyProjectionRepository::new());
    seed_permissive_global_policy_for_tests(&policy_projections);
    let ingest_use_case = Arc::new(IngestUseCase::new(
        storage.clone(),
        lifecycle.clone(),
        artifacts.clone(),
        repositories.clone(),
        event_publisher.clone(),
        curation_rules.clone(),
        artifact_group_use_case.clone(),
        include_repository_label,
        HashMap::new(),
        0,
        content_references.clone(),
        policy_projections.clone(),
        jobs.clone(),
    ));
    let user_use_case = Arc::new(UserUseCase::new(users.clone()));
    // `ApiTokenUseCase` for the native
    // token issuance / revocation / listing surface. Defaults to
    // both feature flags off (`HORT_TOKEN_ALLOW_ADMIN=false`,
    // `HORT_TOKEN_ALLOW_UNBOUNDED_SVC=false`); handler tests that
    // need the gated branches rebuild via [`with_api_token_config`].
    let api_tokens = Arc::new(MockApiTokenRepository::new());
    // Empty evaluator wrapped in `ArcSwap` to
    // match the production wiring: handler tests don't drive the
    // cap-vs-authority gate (admin-bearing principals short-circuit
    // through the evaluator's role check); tests that DO drive it
    // rebuild via the same `with_auth` flow below to seed grants.
    let api_token_rbac = Arc::new(arc_swap::ArcSwap::from_pointee(
        hort_app::rbac::RbacEvaluator::new(Vec::new()),
    ));
    let api_token_use_case = Arc::new(ApiTokenUseCase::new(
        api_tokens.clone(),
        users.clone(),
        event_publisher.clone(),
        api_token_rbac,
        ApiTokenIssuanceConfig::default(),
    ));
    // `policy_projections` was hoisted earlier (above
    // `IngestUseCase::new`) so the same Arc is shared between ingest
    // and quarantine. See the comment there.
    // `QuarantineUseCase::new` is the
    // sole constructor and takes the storage port unconditionally.
    // Even handler tests that don't drive the scan-result path must
    // wire a storage mock for it; cheap allocation, no behaviour
    // change for the non-scan paths.
    //
    // Per-finding-row persistence rides through the lifecycle
    // port; no separate ScanFindingsRepository handle on the use case.
    let quarantine_use_case = Arc::new(QuarantineUseCase::new(
        artifacts.clone(),
        event_publisher.clone(),
        lifecycle.clone(),
        repositories.clone(),
        policy_projections.clone(),
        // Reject paths sweep
        // `content_references` rows for the rejected source — same
        // refcount mock used by the ingest write path above.
        content_references.clone(),
        storage.clone(),
    ));
    let promotion_use_case = Arc::new(PromotionUseCase::new(
        artifacts.clone(),
        repositories.clone(),
        event_publisher.clone(),
        lifecycle.clone(),
        policy_projections.clone(),
    ));

    let refs = Arc::new(MockRefRegistryPort::new());
    let ref_lifecycle = Arc::new(MockRefLifecyclePort::new(refs.clone()));
    let ref_use_case = Arc::new(RefUseCase::new(
        refs.clone(),
        ref_lifecycle.clone(),
        include_repository_label,
    ));

    let stateful_upload_staging = Arc::new(MockStatefulUploadStagingPort::new());
    // `repo_security_scores` projection mock
    // backing the `SecurityScoreUseCase`. Same `Arc` is exposed via
    // `MockPorts.security_scores` so handler tests can seed rows
    // directly without going through the use case.
    let security_scores = Arc::new(MockRepoSecurityScoreRepository::new());
    let security_score_use_case = Arc::new(SecurityScoreUseCase::new(
        security_scores.clone(),
        repositories.clone(),
        repository_access_use_case.clone(),
    ));
    // `ContentReferenceUseCase` composed over the
    // mock index + the access use case. Tests that need enabled-RBAC
    // semantics rebuild via [`with_repository_access`] (which also
    // rebuilds this use case) so the access policy stays consistent
    // across both surfaces.
    let content_reference_use_case = Arc::new(ContentReferenceUseCase::new(
        content_references.clone(),
        repository_access_use_case.clone(),
    ));
    let repository_upstream_mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());
    let upstream_resolver = Arc::new(MockUpstreamResolver::new());
    let upstream_proxy = Arc::new(MockUpstreamProxy::new());

    // Two distinct in-memory `EphemeralStore`
    // instances behind the production metrics wrapper, one per class
    // slot. Default behaviour preserves the keyspace-
    // isolation invariant: a write to `ephemeral_evictable` is invisible
    // from `ephemeral_durable` and vice versa. The "tests pass on
    // memory ⇒ tests pass on Redis" property holds by
    // mechanical default rather than per-test opt-in. Tests that
    // genuinely need the slots aliased call
    // [`build_mock_ctx_aliased_ephemeral`] instead.
    let ephemeral_evictable = Arc::new(MeteredEphemeralStore::new(
        Arc::new(InMemoryEphemeralStore::new()),
        hort_app::ephemeral_keyspace::EphemeralKeyspaceClass::Evictable,
    ));
    let ephemeral_durable = Arc::new(MeteredEphemeralStore::new(
        Arc::new(InMemoryEphemeralStore::new()),
        hort_app::ephemeral_keyspace::EphemeralKeyspaceClass::Durable,
    ));

    // Real `PullDedup` over the in-memory
    // `ephemeral_evictable` store. Matching the harness-wide pattern, tests
    // get the production service composition (not a mock) so behaviour
    // assertions on coalescing semantics carry through to Redis. The
    // `pull_dedup` Arc handed to `MockPorts` is the SAME Arc threaded
    // onto `AppContext.pull_dedup` (the no-double-construction
    // assertion in this module's tests pins the pointer-equality).
    let pull_dedup = Arc::new(PullDedup::new(
        ephemeral_evictable.clone(),
        PullDedupConfig::defaults(),
    ));

    // `TaskUseCase` wired with the mock jobs port
    // and mock event store. The default RBAC evaluator in mock contexts
    // is empty (deny-everything); handler tests that need to exercise the
    // RBAC-permit path build their own `CallerPrincipal` with the matching
    // role and use `AuthContext::Disabled` (which bypasses the middleware
    // guard) OR rebuild via `with_task_use_case`.
    let task_use_case = Arc::new(TaskUseCase::new(
        jobs.clone(),
        event_publisher.clone(),
        Arc::new(arc_swap::ArcSwap::from_pointee(
            hort_app::rbac::RbacEvaluator::new(Vec::new()),
        )),
    ));

    // `ManualRescanUseCase` for the
    // `POST /api/v1/artifacts/:id/rescan` endpoint. Wired with the
    // same mock artifact + jobs ports used elsewhere in the harness;
    // shares the same `RepositoryAccessUseCase` so the
    // anti-enumeration semantics observed by the security-score
    // surface apply uniformly here.
    let manual_rescan_use_case = Arc::new(ManualRescanUseCase::new(
        artifacts.clone(),
        jobs.clone(),
        repository_access_use_case.clone(),
    ));

    // `PatchCandidateUseCase` for the admin
    // patch-candidate read surface. Wired with the mock repository
    // exposed on `MockPorts.patch_candidates` so handler tests seed
    // rows via `mocks.patch_candidates.seed(...)` and assert the
    // recorded filter via `mocks.patch_candidates.calls()`.
    let patch_candidates = Arc::new(MockPatchCandidateRepository::new());
    let patch_candidate_use_case = Arc::new(PatchCandidateUseCase::new(
        patch_candidates.clone() as Arc<dyn PatchCandidateRepository>
    ));

    // `ScannerWorkerQueryUseCase` for the admin worker-list surface
    // (`GET /admin/workers`). Wired with the mock registry exposed on
    // `MockPorts.scanner_workers` so handler tests seed rows via
    // `mocks.scanner_workers.seed(...)`.
    let scanner_workers = Arc::new(MockScannerRegistryRepository::new());
    let scanner_worker_query_use_case = Arc::new(ScannerWorkerQueryUseCase::new(
        scanner_workers.clone() as Arc<dyn ScannerRegistryRepository>,
    ));

    // `PrefetchUseCase` planner. Zero-cost unit
    // struct; the `Arc` mirrors the rest of the use-case surface.
    let prefetch_use_case = Arc::new(PrefetchUseCase::new());

    // `EffectivePermissionsUseCase` for the
    // admin effective-permissions read surface. Wired with the in-memory
    // user mock (shared with `user_use_case`) + a dedicated grant mock
    // exposed on `MockPorts.permission_grants` so handler tests seed
    // grants via `mocks.permission_grants.seed(...)`.
    let permission_grants = Arc::new(MockPermissionGrantRepository::new());
    let effective_permissions_use_case = Arc::new(EffectivePermissionsUseCase::new(
        users.clone(),
        permission_grants.clone(),
    ));

    // `RbacResolveUseCase` for the admin what-if
    // resolver (`POST /api/v1/admin/rbac/resolve`). Wired with a dedicated
    // `claim_mappings` mock (exposed on `MockPorts.claim_mappings` so tests
    // seed group→claim mappings via `mocks.claim_mappings.seed(...)`) and
    // the SAME `permission_grants` grant mock the effective-permissions use
    // case reads, so a handler test can seed one grant set and exercise both
    // admin surfaces.
    let claim_mappings = Arc::new(MockClaimMappingRepository::new());
    let rbac_resolve_use_case = Arc::new(RbacResolveUseCase::new(
        claim_mappings.clone(),
        permission_grants.clone(),
    ));

    // Subscription CRUD use case. Wired against
    // the in-memory `MockSubscriptionRepository` + `MockWebhookTargetGuard`
    // declared above. The default config has both `allow_plaintext_webhooks`
    // and `allow_nonroutable_webhook_targets = false` (production secure
    // defaults); tests asserting the plaintext / nonroutable opt-in
    // branches rebuild the context with a custom config.
    let subscriptions = Arc::new(MockSubscriptionRepository::new());
    let webhook_guard = Arc::new(MockWebhookTargetGuard::default());
    let subscription_rbac = Arc::new(arc_swap::ArcSwap::from_pointee(
        hort_app::rbac::RbacEvaluator::new(Vec::new()),
    ));
    let subscription_use_case = Arc::new(SubscriptionUseCase::new(
        subscriptions.clone(),
        users.clone(),
        event_publisher.clone(),
        subscription_rbac,
        repositories.clone(),
        webhook_guard.clone(),
        SubscriptionUseCaseConfig::default(),
    ));

    // `CurationUseCase` wired
    // with the same ports the production composition root threads
    // (events, artifacts, lifecycle, policy projections). The three
    // `list_*` ports are recording mocks — the GET handlers under
    // `/api/v1/admin/curation/` exercise them; tests seed results +
    // assert filters via the
    // `mocks.curation_{queue,decisions,exclusions}` handles.
    let curation_queue = Arc::new(MockCurationQueueRepository::new());
    let curation_decisions = Arc::new(MockCurationDecisionsRepository::new());
    let curation_exclusions = Arc::new(MockCurationExclusionsRepository::new());
    let curation_use_case = Arc::new(CurationUseCase::new(
        event_publisher.clone(),
        artifacts.clone(),
        lifecycle.clone(),
        policy_projections.clone(),
        curation_queue.clone(),
        curation_decisions.clone(),
        curation_exclusions.clone(),
        // Mirror the production composition
        // root: thread the shared `RepositoryAccessUseCase` so the
        // curation emission sites can resolve repository keys for the
        // `hort_curation_decisions_total{repository}` label.
        repository_access_use_case.clone(),
    ));

    // `PolicyUseCase` wired with the same ports
    // the production composition root threads (event_publisher,
    // policy_projections, artifacts, lifecycle, storage). The
    // exclusion-write HTTP handlers under
    // `/api/v1/admin/policies/:policy_id/exclusions[/:cve_id]` drive
    // `add_exclusion` / `remove_exclusion` on this use case.
    let policy_use_case = Arc::new(PolicyUseCase::new(
        event_publisher.clone(),
        policy_projections.clone(),
        artifacts.clone(),
        lifecycle.clone(),
        storage.clone(),
        // Mirror the production composition: thread
        // the same `RepositoryAccessUseCase` so the curator-path
        // exclusion metric resolves `PolicyScope::Repository(id)` to
        // the repo key.
        repository_access_use_case.clone(),
        // ADR 0041 invariant #6 (c): the re-evaluation pass's
        // active-curation precondition reads live curation rules.
        curation_rules.clone(),
        // ADR 0041 Item 3: the exclusion-write handlers enqueue the
        // async `policy-reevaluation` task; share the mock jobs repo so
        // tests can assert the enqueue.
        jobs.clone(),
    ));

    // `WheelMetadataUseCase` composed over the
    // shared `ArtifactUseCase` (visibility-gate + status hydration),
    // the in-memory `MockContentReferenceIndex` (wheel_metadata PK
    // lookup), and the shared mock storage. Mirrors the production
    // composition root one-liner.
    let wheel_metadata_use_case = Arc::new(WheelMetadataUseCase::new(
        artifact_use_case.clone(),
        content_references.clone(),
        storage.clone(),
    ));

    // Discovery + self-service prefetch
    // use cases. Both consume the `UpstreamMetadataPort`;
    // the mock here is exposed on `MockPorts.upstream_metadata`
    // so handler tests seed per-(format, package) version lists. The
    // RBAC evaluator for these two use cases is wired from the same
    // production-composition pattern: an empty evaluator by default;
    // tests that exercise the token-kind / permission-denied gates
    // either flip `AuthContext::Disabled → Enabled` via `with_auth` and
    // supply grants, or pre-seed the underlying repositories.
    let upstream_metadata = Arc::new(MockUpstreamMetadataPort::new());
    let discovery_rbac = Arc::new(arc_swap::ArcSwap::from_pointee(
        hort_app::rbac::RbacEvaluator::new(Vec::new()),
    ));
    let discovery_use_case = Arc::new(DiscoveryUseCase::new(
        repositories.clone(),
        artifacts.clone(),
        repository_upstream_mappings.clone(),
        upstream_metadata.clone(),
        discovery_rbac.clone(),
        policy_projections.clone(),
    ));
    let self_service_prefetch_use_case = Arc::new(SelfServicePrefetchUseCase::new(
        repositories.clone(),
        artifacts.clone(),
        repository_upstream_mappings.clone(),
        upstream_metadata.clone(),
        jobs.clone(),
        discovery_rbac.clone(),
    ));

    let virtual_resolution_use_case = Arc::new(VirtualResolutionUseCase::new(
        repositories.clone(),
        repository_access_use_case.clone(),
    ));

    let mut ctx_inner = AppContext {
        repository_use_case,
        artifact_use_case,
        repository_access_use_case,
        virtual_resolution_use_case,
        content_reference_use_case,
        ingest_use_case,
        user_use_case,
        api_token_use_case,
        quarantine_use_case,
        promotion_use_case,
        ref_use_case,
        // See field doc.
        security_score_use_case,
        // See field doc.
        task_use_case,
        // See field doc.
        manual_rescan_use_case,
        // See field doc.
        patch_candidate_use_case,
        // See field doc.
        scanner_worker_query_use_case,
        // See field doc.
        prefetch_use_case,
        // See field doc.
        effective_permissions_use_case,
        // See field doc.
        rbac_resolve_use_case,
        // See field doc.
        subscription_use_case,
        // See field doc.
        curation_use_case,
        // See field doc.
        policy_use_case,
        // See field doc.
        wheel_metadata_use_case,
        // The discovery + self-service
        // prefetch use case slots default to `None` (see
        // `AppContext::with_discovery_use_cases` docs). They are
        // populated below via the same helper the production
        // composition root invokes at boot time.
        discovery_use_case: None,
        self_service_prefetch_use_case: None,
        storage: storage.clone(),
        artifacts: artifacts.clone(),
        repositories: repositories.clone(),
        refs: refs.clone(),
        ref_lifecycle: ref_lifecycle.clone(),
        artifact_group_use_case,
        artifact_groups: artifact_groups.clone(),
        artifact_group_lifecycle: artifact_group_lifecycle.clone(),
        artifact_metadata: artifact_metadata.clone(),
        // See field doc.
        security_scores: security_scores.clone(),
        // Same `MockJobsRepository` shared with
        // `task_use_case` and `manual_rescan_use_case`.
        jobs: jobs.clone(),
        ephemeral_evictable: ephemeral_evictable.clone(),
        // In-memory raw-metadata mirror.
        metadata_mirror: metadata_mirror.clone(),
        pull_dedup: pull_dedup.clone(),
        ephemeral_durable: ephemeral_durable.clone(),
        event_store: event_publisher.clone(),
        // Federation validator. Mock contexts leave
        // it unset; the federation handler tests wire a
        // mock directly when exercising the federation path.
        federated_jwt_validator: None,
        // ServiceAccountRepository for the federation
        // branch's SA-resolution. Mock contexts leave it unset; the
        // federation handler tests wire a `MockServiceAccountRepository`
        // through a `with_federation_ports` helper.
        service_accounts: None,
        // OidcIssuerRepository for
        // resolving the matched issuer's `require_jti`. Mock contexts
        // leave it unset; the federation handler tests wire a mock via
        // `with_federation_ports`.
        oidc_issuers: None,
        // K8s Secret writer for the fallback-PAT
        // rotation reconciler. Mock contexts leave it unset; the
        // rotation-reconciler tests wire the mock writer directly
        // when exercising the rotation handler.
        k8s_secret_writer: None,
        stateful_upload_staging: stateful_upload_staging.clone(),
        content_references: content_references.clone(),
        repository_upstream_mappings: repository_upstream_mappings.clone(),
        upstream_resolver: upstream_resolver.clone(),
        upstream_proxy: upstream_proxy.clone(),
        policy_projections: policy_projections.clone(),
        curation_rules: curation_rules.clone(),
        metrics_handle: handle,
        include_repository_label,
        // Default `true` mirrors the production
        // operator posture (per-SA breakdown until cardinality
        // pressure warrants flipping the toggle). Tests that need
        // to exercise the `_all`-sentinel branch construct the
        // context manually.
        include_service_account_label: true,
        url_resolver: UrlResolver,
        trust_config: TrustConfig::default(),
        rate_limit_config: RateLimitConfig::default(),
        concurrency_limit_config: crate::middleware::load_shed::ConcurrencyLimitConfig::default(),
        http_timeout_config: crate::middleware::request_timeout::HttpTimeoutConfig::defaults(),
        publish_body_limit_bytes: None,
        // Test default mirrors the production env-var
        // default (2 MiB). Tests that need to trip the projector cap
        // override this via `with_*` in the per-test wiring.
        upstream_projector_version_object_max_bytes: 2 * 1024 * 1024,
        auth: AuthContext::Disabled,
        // Default to None in all mock contexts.
        // Tests that need to exercise extra-CA behaviour supply it directly.
        extra_trust_anchors: None,
        // Native-API-token cache. Mock
        // contexts default to `None` because the auth-middleware
        // tests don't drive PAT validation through the harness; the
        // validator is wired in `AuthContext::Enabled.authenticate`
        // directly when those tests need it.
        pat_cache: None,
        // Operator opt-in defaults to `false`; the
        // plaintext-PAT-refusal branch is reached by the
        // dedicated tests that flip this slot via `with_pat_over_http_allowed`.
        pat_over_http_allowed: false,
        // OCI `/v2/auth` slots default to None for
        // mock contexts. Tests that need to exercise the Bearer
        // challenge / mint path explicitly construct + thread the
        // signing key + use case via dedicated overrides.
        oci_token_exchange: None,
        oci_signing_key: None,
        oci_public_base_url: None,
        // `client_config` defaults to None in the
        // mock harness; the `well_known` handler tests construct their
        // own `Arc<AppContext>` with `client_config = Some(_)` to
        // exercise the served-document path.
        client_config: None,
    };
    // Populate the discovery + self-service
    // prefetch use case slots via the production-shaped helper. Same code
    // path the composition root invokes at boot.
    ctx_inner.with_discovery_use_cases(
        discovery_use_case.clone(),
        self_service_prefetch_use_case.clone(),
    );
    let ctx = Arc::new(ctx_inner);

    let mocks = MockPorts {
        artifacts,
        repositories,
        storage,
        events,
        lifecycle,
        users,
        artifact_metadata,
        artifact_groups,
        artifact_group_lifecycle,
        refs,
        ref_lifecycle,
        ephemeral_evictable,
        metadata_mirror,
        pull_dedup,
        ephemeral_durable,
        stateful_upload_staging,
        content_references,
        repository_upstream_mappings,
        upstream_resolver,
        upstream_proxy,
        policy_projections,
        curation_rules,
        api_tokens,
        security_scores,
        jobs,
        patch_candidates,
        scanner_workers,
        permission_grants,
        claim_mappings,
        subscriptions,
        webhook_guard,
        curation_queue,
        curation_decisions,
        curation_exclusions,
        upstream_metadata,
    };

    (ctx, mocks)
}

/// Opt-in helper that aliases both
/// `ephemeral_evictable` and `ephemeral_durable` slots (both on the
/// returned `AppContext` AND on both `MockPorts` handles) onto the
/// SAME `Arc<MeteredEphemeralStore<InMemoryEphemeralStore>>`.
///
/// **Use only when a test explicitly needs cross-class observability** —
/// for example, a regression test that wants to assert behaviour by
/// reading state through either handle interchangeably. Production
/// wiring constructs two distinct stores; the default
/// [`build_mock_ctx`] mirrors that. Calling THIS helper is a deliberate
/// signal that the test understands it is observing a single physical
/// store under two metric labels.
///
/// The single shared store is constructed with
/// [`EphemeralKeyspaceClass::Durable`](hort_app::ephemeral_keyspace::EphemeralKeyspaceClass::Durable)
/// — arbitrary; the metric label is purely cosmetic for tests that
/// reach for this helper.
pub fn build_mock_ctx_aliased_ephemeral(handle: PrometheusHandle) -> (Arc<AppContext>, MockPorts) {
    let (base, mut mocks) = build_mock_ctx_with_label_flag(handle, true);
    let aliased = Arc::new(MeteredEphemeralStore::new(
        Arc::new(InMemoryEphemeralStore::new()),
        hort_app::ephemeral_keyspace::EphemeralKeyspaceClass::Durable,
    ));
    mocks.ephemeral_evictable = aliased.clone();
    mocks.ephemeral_durable = aliased.clone();
    let ctx = rebuild(&base, |ctx| {
        ctx.ephemeral_evictable = aliased.clone();
        ctx.ephemeral_durable = aliased.clone();
    });
    (ctx, mocks)
}

/// Clone every field of `base` into a new [`AppContext`]. The callback
/// receives the fresh struct before it's wrapped in an `Arc`, so tests
/// can override one or two fields (e.g. `auth`, `trust_config`,
/// `publish_body_limit_bytes`) without duplicating the ~25-field clone
/// boilerplate.
fn rebuild(base: &Arc<AppContext>, mutate: impl FnOnce(&mut AppContext)) -> Arc<AppContext> {
    let mut next = AppContext {
        repository_use_case: base.repository_use_case.clone(),
        artifact_use_case: base.artifact_use_case.clone(),
        repository_access_use_case: base.repository_access_use_case.clone(),
        virtual_resolution_use_case: base.virtual_resolution_use_case.clone(),
        content_reference_use_case: base.content_reference_use_case.clone(),
        ingest_use_case: base.ingest_use_case.clone(),
        user_use_case: base.user_use_case.clone(),
        api_token_use_case: base.api_token_use_case.clone(),
        quarantine_use_case: base.quarantine_use_case.clone(),
        promotion_use_case: base.promotion_use_case.clone(),
        ref_use_case: base.ref_use_case.clone(),
        // Carry forward from base; tests
        // that need to swap the use case rebuild via a dedicated
        // helper if needed in future. The default mock-built
        // version reads from `MockPorts.security_scores`.
        security_score_use_case: base.security_score_use_case.clone(),
        // Carry forward the same `Arc<TaskUseCase>`.
        // Tests that need a different RBAC evaluator wired into the use
        // case use `with_task_use_case`.
        task_use_case: base.task_use_case.clone(),
        // Carry forward the same
        // `Arc<ManualRescanUseCase>`. Tests that swap the access policy
        // via `with_repository_access` rebuild this use case in the
        // helper itself so the cloned access propagates.
        manual_rescan_use_case: base.manual_rescan_use_case.clone(),
        // Carry forward. The patch-candidate
        // surface is admin-only and does not consume
        // `RepositoryAccessUseCase`, so no `with_*` helper rebuild is
        // needed when the access policy flips.
        patch_candidate_use_case: base.patch_candidate_use_case.clone(),
        // Carry forward. The worker-list surface is admin-only and does
        // not consume `RepositoryAccessUseCase`, so no rebuild is needed.
        scanner_worker_query_use_case: base.scanner_worker_query_use_case.clone(),
        // Carry forward. The prefetch planner is
        // a stateless unit struct; rebuilding would yield the identical
        // instance, but threading the existing `Arc` keeps pointer
        // identity consistent across `with_*` helpers.
        prefetch_use_case: base.prefetch_use_case.clone(),
        // Carry forward. The effective-permissions
        // surface is admin-only and does not consume
        // `RepositoryAccessUseCase`, so no `with_*` helper rebuild is
        // needed when the access policy flips.
        effective_permissions_use_case: base.effective_permissions_use_case.clone(),
        // Carry forward. The what-if resolver is
        // admin-only and does not consume `RepositoryAccessUseCase`, so no
        // `with_*` helper rebuild is needed when the access policy flips.
        rbac_resolve_use_case: base.rbac_resolve_use_case.clone(),
        // Carry forward the same use case Arc;
        // tests that swap the RBAC evaluator or webhook guard
        // reconstruct the harness from scratch via `build_mock_ctx`
        // rather than mutating in place.
        subscription_use_case: base.subscription_use_case.clone(),
        // Carry forward the same
        // `Arc<CurationUseCase>`. The curation surface is admin-only
        // (gated by `CurateOrAdminPrincipal`) and does NOT consume
        // `RepositoryAccessUseCase`; no `with_*` helper rebuild is
        // needed when the access policy flips.
        curation_use_case: base.curation_use_case.clone(),
        // Carry forward the same
        // `Arc<PolicyUseCase>`. The HTTP exclusion write endpoints
        // mount under `/api/v1/admin/policies/:policy_id/exclusions`
        // gated by `CurateOrAdminPrincipal`; the use case is
        // permission-neutral so no `with_*` helper rebuild is required
        // when access policy flips.
        policy_use_case: base.policy_use_case.clone(),
        // Carry forward. The wheel-metadata
        // surface composes the shared `ArtifactUseCase` (which a
        // `with_repository_access` rebuild already swaps in the
        // helper itself), so a passive carry-forward keeps pointer
        // identity correct without per-helper rebuild logic.
        wheel_metadata_use_case: base.wheel_metadata_use_case.clone(),
        // Carry forward the discovery +
        // self-service prefetch use case `Option<Arc<_>>` slots. Same
        // pointer-identity preservation as every other use case here;
        // `with_auth` / `with_pat_cache` / … callers see the same
        // instances. Tests that need fresh use-case wiring rebuild via
        // `build_mock_ctx` from scratch.
        discovery_use_case: base.discovery_use_case.clone(),
        self_service_prefetch_use_case: base.self_service_prefetch_use_case.clone(),
        storage: base.storage.clone(),
        artifacts: base.artifacts.clone(),
        repositories: base.repositories.clone(),
        refs: base.refs.clone(),
        ref_lifecycle: base.ref_lifecycle.clone(),
        artifact_group_use_case: base.artifact_group_use_case.clone(),
        artifact_groups: base.artifact_groups.clone(),
        artifact_group_lifecycle: base.artifact_group_lifecycle.clone(),
        artifact_metadata: base.artifact_metadata.clone(),
        // Carry forward.
        security_scores: base.security_scores.clone(),
        // Carry forward the shared jobs port.
        jobs: base.jobs.clone(),
        ephemeral_evictable: base.ephemeral_evictable.clone(),
        // Carry forward the raw-metadata mirror.
        metadata_mirror: base.metadata_mirror.clone(),
        // Carry forward the same `Arc<PullDedup>`.
        // The service is constructed once in `build_mock_ctx_with_label_flag`
        // and shared across every `with_*` rebuild; tests that need to
        // override behaviour seed the underlying `ephemeral_evictable`
        // store rather than re-constructing the service.
        pull_dedup: base.pull_dedup.clone(),
        ephemeral_durable: base.ephemeral_durable.clone(),
        event_store: base.event_store.clone(),
        // Carry forward; tests that need to drive the
        // federation handler supply a mock through the
        // `with_federation_ports` helper.
        federated_jwt_validator: base.federated_jwt_validator.clone(),
        // Carry forward the optional SA repo. Tests
        // exercising the federation handler wire both this and the
        // validator via `with_federation_ports`.
        service_accounts: base.service_accounts.clone(),
        // Carry forward the optional
        // OidcIssuerRepository (federation handler resolves
        // `require_jti` from it).
        oidc_issuers: base.oidc_issuers.clone(),
        // Carry forward the optional k8s Secret writer.
        // The rotation-reconciler tests construct their own context with
        // `k8s_secret_writer = Some(_)` to drive the rotation path.
        k8s_secret_writer: base.k8s_secret_writer.clone(),
        stateful_upload_staging: base.stateful_upload_staging.clone(),
        content_references: base.content_references.clone(),
        repository_upstream_mappings: base.repository_upstream_mappings.clone(),
        upstream_resolver: base.upstream_resolver.clone(),
        upstream_proxy: base.upstream_proxy.clone(),
        policy_projections: base.policy_projections.clone(),
        curation_rules: base.curation_rules.clone(),
        metrics_handle: base.metrics_handle.clone(),
        include_repository_label: base.include_repository_label,
        include_service_account_label: base.include_service_account_label,
        url_resolver: base.url_resolver,
        trust_config: base.trust_config.clone(),
        rate_limit_config: base.rate_limit_config,
        concurrency_limit_config: base.concurrency_limit_config,
        http_timeout_config: base.http_timeout_config,
        publish_body_limit_bytes: base.publish_body_limit_bytes,
        upstream_projector_version_object_max_bytes: base
            .upstream_projector_version_object_max_bytes,
        auth: AuthContext::Disabled,
        // Carry forward from base; callers that need
        // to test with extra anchors override this field in the mutate closure.
        extra_trust_anchors: base.extra_trust_anchors.clone(),
        // Carry forward from base; tests that need to
        // exercise the PAT-over-HTTP branch override via
        // [`with_pat_over_http_allowed`] / [`with_pat_cache`].
        pat_cache: base.pat_cache.clone(),
        pat_over_http_allowed: base.pat_over_http_allowed,
        // OCI token-exchange slots carry forward.
        oci_token_exchange: base.oci_token_exchange.clone(),
        oci_signing_key: base.oci_signing_key.clone(),
        oci_public_base_url: base.oci_public_base_url.clone(),
        // Carry forward from base; tests that need
        // to exercise the discovery handler override directly.
        client_config: base.client_config.clone(),
    };
    // Preserve the incoming auth unless the caller overrides it. Cloning
    // AuthContext::Enabled's `Arc<ArcSwap<_>>` is cheap; cloning the
    // use-case Arc equally so.
    match &base.auth {
        AuthContext::Disabled => next.auth = AuthContext::Disabled,
        AuthContext::Enabled {
            authenticate,
            rbac,
            issuer_url,
        } => {
            next.auth = AuthContext::Enabled {
                authenticate: authenticate.clone(),
                rbac: rbac.clone(),
                issuer_url: issuer_url.clone(),
            };
        }
        AuthContext::BearerOnly { authenticate, rbac } => {
            next.auth = AuthContext::BearerOnly {
                authenticate: authenticate.clone(),
                rbac: rbac.clone(),
            };
        }
    }
    mutate(&mut next);
    Arc::new(next)
}

/// Build a new [`AppContext`] copying every field from `base` except
/// `auth`, which becomes `new_auth`.
///
/// Use to flip a disabled-auth context to `AuthContext::Enabled` (or vice
/// versa) without re-wiring every port.
pub fn with_auth(base: &Arc<AppContext>, new_auth: AuthContext) -> Arc<AppContext> {
    rebuild(base, |ctx| ctx.auth = new_auth)
}

/// Replace the wired [`ApiTokenUseCase`] on an
/// existing context. Used by handler tests that need the use case
/// rebuilt with a SPECIFIC `RbacEvaluator` so cap-vs-authority checks
/// observe the seeded grants. The default use case from
/// [`build_mock_ctx`] holds an empty evaluator.
pub fn with_api_token_use_case(
    base: &Arc<AppContext>,
    new_uc: Arc<ApiTokenUseCase>,
) -> Arc<AppContext> {
    rebuild(base, |ctx| ctx.api_token_use_case = new_uc)
}

/// Replace the wired [`SubscriptionUseCase`] on
/// an existing context. Used by handler tests that need the use case
/// rebuilt with a SPECIFIC `RbacEvaluator` so admin-scope checks
/// observe the seeded grants. Same pattern as
/// [`with_api_token_use_case`].
pub fn with_subscription_use_case(
    base: &Arc<AppContext>,
    new_uc: Arc<SubscriptionUseCase>,
) -> Arc<AppContext> {
    rebuild(base, |ctx| ctx.subscription_use_case = new_uc)
}

/// Wire the federation-branch ports (the
/// `FederatedJwtValidator` and the `ServiceAccountRepository`) onto an
/// existing mock context. Used by the federation handler tests in
/// `handlers::exchange` to drive the `subject_token_type = jwt` path.
///
/// Mock contexts default both slots to `None` (the access_token-path
/// tests do not need them); this helper is the canonical override.
pub fn with_federation_ports(
    base: &Arc<AppContext>,
    validator: Arc<dyn hort_domain::ports::federated_jwt_validator::FederatedJwtValidator>,
    service_accounts: Arc<
        dyn hort_domain::ports::service_account_repository::ServiceAccountRepository,
    >,
) -> Arc<AppContext> {
    rebuild(base, |ctx| {
        ctx.federated_jwt_validator = Some(validator);
        ctx.service_accounts = Some(service_accounts);
    })
}

/// Wire the `OidcIssuerRepository`
/// the federation handler uses to resolve the matched issuer's
/// `require_jti` flag. Defaults to `None` on mock contexts; the
/// federation handler treats a `None` slot as a composition bug and
/// fails CLOSED, so the replay-path handler tests wire this.
pub fn with_oidc_issuer_repo(
    base: &Arc<AppContext>,
    oidc_issuers: Arc<dyn hort_domain::ports::oidc_issuer_repository::OidcIssuerRepository>,
) -> Arc<AppContext> {
    rebuild(base, |ctx| {
        ctx.oidc_issuers = Some(oidc_issuers);
    })
}

/// Flip `pat_over_http_allowed` on a mock
/// context. Used by the plaintext-PAT-refusal middleware tests to
/// drive both branches without rebuilding every port.
pub fn with_pat_over_http_allowed(base: &Arc<AppContext>, allowed: bool) -> Arc<AppContext> {
    rebuild(base, |ctx| ctx.pat_over_http_allowed = allowed)
}

/// Wire the OCI signing-key handle on a mock
/// context. Used by the `/v2/*` challenge-middleware tests to drive
/// both branches (Bearer when wired, Basic when not).
pub fn with_oci_signing_key(
    base: &Arc<AppContext>,
    key: Option<Arc<hort_app::oci_token_signing::OciTokenSigningKey>>,
) -> Arc<AppContext> {
    rebuild(base, |ctx| ctx.oci_signing_key = key)
}

/// Wire the OCI token-exchange use case on a
/// mock context. Pairs with [`with_oci_signing_key`] for tests that
/// drive `/v2/auth` end-to-end.
pub fn with_oci_token_exchange(
    base: &Arc<AppContext>,
    uc: Option<Arc<hort_app::use_cases::oci_token_exchange_use_case::OciTokenExchangeUseCase>>,
) -> Arc<AppContext> {
    rebuild(base, |ctx| ctx.oci_token_exchange = uc)
}

/// Set the public base URL used to render the
/// `realm=…/v2/auth` value in the Bearer challenge.
pub fn with_oci_public_base_url(base: &Arc<AppContext>, url: Option<String>) -> Arc<AppContext> {
    rebuild(base, |ctx| ctx.oci_public_base_url = url)
}

/// Set the pre-rendered client-bootstrap
/// config used by `GET /.well-known/hort-client-config`. Tests pass
/// `Some(_)` to exercise the served-document path; `None` simulates
/// the composition-bug guard branch (route mounted with the field
/// unpopulated).
pub fn with_client_config(
    base: &Arc<AppContext>,
    cfg: Option<crate::handlers::well_known::ClientBootstrapConfig>,
) -> Arc<AppContext> {
    rebuild(base, |ctx| ctx.client_config = cfg)
}

/// Build a new [`AppContext`] copying every field from `base` except
/// `trust_config`, which becomes `new_trust_config`. Used by handler
/// tests that need a specific trust profile — e.g. the cargo
/// `config.json` tests that assert host-header fallback behaviour and
/// therefore need `trust_config_untrusted_peer_fallback()` rather than
/// the pinned-URL `TrustConfig::default()`.
pub fn with_trust_config(base: &Arc<AppContext>, new_trust_config: TrustConfig) -> Arc<AppContext> {
    rebuild(base, |ctx| ctx.trust_config = new_trust_config)
}

/// Replace the wired
/// [`RepositoryAccessUseCase`] on an existing context. Used by handler
/// tests that need enabled-RBAC semantics (e.g. anonymous-on-private
/// regression tests) where the default [`RbacAccess::Disabled`]
/// admit-everything policy would mask the visibility check the test is
/// asserting.
///
/// The returned context's `artifact_use_case` is rebuilt to consume
/// the new access use case via
/// [`ArtifactUseCase::with_repository_access`] so
/// `find_visible_*` calls observe the same RBAC state. The
/// `artifact_metadata` wiring is preserved.
pub fn with_repository_access(
    base: &Arc<AppContext>,
    new_access: Arc<RepositoryAccessUseCase>,
) -> Arc<AppContext> {
    rebuild(base, |ctx| {
        ctx.repository_access_use_case = new_access.clone();
        ctx.artifact_use_case = Arc::new(
            ArtifactUseCase::new(
                ctx.artifacts.clone(),
                ctx.storage.clone(),
                ctx.repositories.clone(),
                ctx.include_repository_label,
            )
            .with_repository_access(new_access.clone())
            .with_artifact_metadata(ctx.artifact_metadata.clone()),
        );
        // Keep the content-reference use case in
        // sync with the new access policy. The OCI anonymous-on-private
        // referrers regression test relies on the visibility check
        // composed inside `find_by_visible_target`; if we left the old
        // (Disabled) access wired here, the test would route through a
        // permissive composition and silently regress.
        ctx.content_reference_use_case = Arc::new(ContentReferenceUseCase::new(
            ctx.content_references.clone(),
            new_access.clone(),
        ));
        // Same invariant for the security-score
        // use case. The use case composes a `RepositoryAccessUseCase`
        // for both `find_for_repo` and `list_with_access`; without this
        // rebuild, an anonymous-on-private regression test would route
        // through the original Disabled access and silently regress.
        ctx.security_score_use_case = Arc::new(SecurityScoreUseCase::new(
            ctx.security_scores.clone(),
            ctx.repositories.clone(),
            new_access.clone(),
        ));
        // Same invariant for the manual rescan
        // use case. The Write-arm enforcement and the anti-enumeration
        // collapse both consume the access policy; without rebuilding
        // here the new access value would not propagate and the
        // 404/403 handler tests would route through the original
        // Disabled access (silent regression).
        ctx.manual_rescan_use_case = Arc::new(ManualRescanUseCase::new(
            ctx.artifacts.clone(),
            ctx.jobs.clone(),
            new_access,
        ));
        // Same invariant for the wheel-metadata
        // use case. The use case composes the freshly-rebuilt
        // `ArtifactUseCase` (via `find_visible_by_path` for the
        // anti-enumeration hop); without rebuilding here the new
        // access would not propagate into the metadata serve path and
        // the anonymous-on-private metadata regression test (in the
        // pypi handler crate) would route through the original
        // Disabled access (silent regression).
        ctx.wheel_metadata_use_case = Arc::new(WheelMetadataUseCase::new(
            ctx.artifact_use_case.clone(),
            ctx.content_references.clone(),
            ctx.storage.clone(),
        ));
    })
}

/// Replace the wired [`TaskUseCase`] on an
/// existing context. Used by handler tests that need the use case
/// rebuilt with a specific `RbacEvaluator` so RBAC-permit assertions
/// on the invoke path work correctly (the default `build_mock_ctx`
/// wires an empty deny-all evaluator).
/// Rebuild the `AppContext` with freshly-wired
/// discovery + self-service prefetch use cases. Mirrors
/// [`with_task_use_case`] in shape; handler tests asserting the gate
/// matrix (token-kind / RBAC) need to inject a custom RBAC evaluator,
/// which requires rebuilding both use cases (they share the evaluator
/// via an internal `ArcSwap`).
///
/// Pass the same use case `Arc`s the test wired against the desired
/// evaluator. The resulting `AppContext` retains pointer identity for
/// every other field (auth, trust, ports, …) so subsequent `with_*`
/// callers see consistent state.
pub fn with_discovery_use_cases(
    base: &Arc<AppContext>,
    discovery: Arc<DiscoveryUseCase>,
    self_service_prefetch: Arc<SelfServicePrefetchUseCase>,
) -> Arc<AppContext> {
    rebuild(base, |ctx| {
        ctx.with_discovery_use_cases(discovery, self_service_prefetch);
    })
}

pub fn with_task_use_case(base: &Arc<AppContext>, new_uc: Arc<TaskUseCase>) -> Arc<AppContext> {
    rebuild(base, |ctx| ctx.task_use_case = new_uc)
}

/// Swap the wired
/// [`EventStore`] handle on a mock context. Used by the `/readyz`
/// handler test that drives the unhealthy branch by injecting a
/// failing event-store stub. The default mock (`MockEventStore`) is
/// always healthy.
pub fn with_event_store(base: &Arc<AppContext>, store: Arc<dyn EventStore>) -> Arc<AppContext> {
    let publisher = Arc::new(EventStorePublisher::without_broadcast(store));
    rebuild(base, |ctx| ctx.event_store = publisher)
}

/// Swap the
/// [`AppContext::repositories`] slot on a mock context. Used by the
/// `authz::extractors` tests that pass a custom `Arc<dyn
/// RepositoryRepository>` (e.g. a `SpyRepoRepo` that counts
/// `find_by_key` invocations) so the extractor under test reads from
/// the spy directly via `state.repositories.find_by_key(...)`.
///
/// The composed use cases retain their original wiring: extractor
/// tests never exercise them (the extractor reads
/// `state.repositories` directly, the `authorize` predicate consults
/// `state.auth`, and no test-asserted code path goes through
/// `RepositoryUseCase` / `RepositoryAccessUseCase`). Tests that DO
/// drive use cases through a custom repo should reach for a richer
/// helper or the `with_repository_access` chain instead.
pub fn with_repositories(
    base: &Arc<AppContext>,
    repos: Arc<dyn RepositoryRepository>,
) -> Arc<AppContext> {
    rebuild(base, |ctx| ctx.repositories = repos)
}

/// Swap the wired
/// [`StoragePort`] on a mock context AND rebuild the two use cases
/// that consume storage on their hot path:
/// [`ArtifactUseCase`] (download) and [`IngestUseCase`] (publish).
/// Used by the pypi end-to-end metrics test which drives a real
/// [`hort_adapters_storage::FilesystemStorage`] adapter so the
/// `backend="filesystem"` storage-operations counter actually fires
/// (the default `MockStoragePort` does not emit those metrics).
///
/// The `mocks` argument supplies the
/// [`hort_app::use_cases::test_support::MockArtifactLifecycle`] handle
/// that `IngestUseCase::new` requires; it is not reachable from
/// [`AppContext`] directly because the lifecycle port is owned by
/// the use cases, not held in a free slot.
pub fn with_storage(
    base: &Arc<AppContext>,
    mocks: &MockPorts,
    storage: Arc<dyn StoragePort>,
) -> Arc<AppContext> {
    rebuild(base, |ctx| {
        ctx.storage = storage.clone();
        // Rebuild ArtifactUseCase so download() reads from the new
        // storage adapter. Mirror the composition shape used in
        // `build_mock_ctx_with_label_flag` — `with_repository_access`
        // and `with_artifact_metadata` carry forward.
        ctx.artifact_use_case = Arc::new(
            ArtifactUseCase::new(
                ctx.artifacts.clone(),
                storage.clone(),
                ctx.repositories.clone(),
                ctx.include_repository_label,
            )
            .with_repository_access(ctx.repository_access_use_case.clone())
            .with_artifact_metadata(ctx.artifact_metadata.clone()),
        );
        // Rebuild IngestUseCase so publish() writes to the new
        // storage adapter. All other dependencies thread through from
        // the existing context / mocks.
        ctx.ingest_use_case = Arc::new(IngestUseCase::new(
            storage,
            mocks.lifecycle.clone(),
            ctx.artifacts.clone(),
            ctx.repositories.clone(),
            ctx.event_store.clone(),
            ctx.curation_rules.clone(),
            ctx.artifact_group_use_case.clone(),
            ctx.include_repository_label,
            HashMap::new(),
            0,
            ctx.content_references.clone(),
            // Thread the same policy_projections +
            // jobs Arcs that the initial IngestUseCase build received,
            // so any policy seeded by the test (or any enqueue
            // assertion) keeps pointing at the live mocks.
            ctx.policy_projections.clone(),
            ctx.jobs.clone(),
        ));
    })
}

#[cfg(test)]
mod guard_tests {
    //! Regression guard.
    //!
    //! Asserts that `Arc::new(AppContext { ... })` does not appear in
    //! any production OR test code outside this file (the canonical
    //! mock-context construction site). Without this guard, the next
    //! field added to [`AppContext`] would silently trigger an inline
    //! fixture re-introduction somewhere else and the "Duplicated
    //! `AppContext` wiring" anti-pattern would creep back in. New
    //! test fixtures must compose [`build_mock_ctx`] + the `with_*`
    //! helper family instead.

    use std::path::PathBuf;
    use std::process::Command;

    /// Walk up from `CARGO_MANIFEST_DIR` (the crate root) to the
    /// workspace root. `Cargo.lock` lives at the workspace root and
    /// not in individual crates, so it serves as the marker.
    fn workspace_root() -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        loop {
            if dir.join("Cargo.lock").exists() {
                return dir;
            }
            if !dir.pop() {
                panic!(
                    "could not locate workspace root from CARGO_MANIFEST_DIR={:?}",
                    env!("CARGO_MANIFEST_DIR")
                );
            }
        }
    }

    #[test]
    fn no_hand_rolled_appcontext_outside_test_support() {
        let root = workspace_root();
        // Recursive grep across `crates/` only — all workspace code
        // lives under `crates/`.
        let output = Command::new("grep")
            .args([
                "-rn",
                "--include=*.rs",
                r"Arc::new(AppContext\s*{",
                "crates/",
            ])
            .current_dir(&root)
            .output()
            .expect("`grep` must be available in the test environment");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Only this file is allowed to mention the literal — the
        // canonical construction site for the mock harness. Add
        // further allow-listed paths here only with a comment naming
        // the deliberate exception.
        let allowed_substrings = ["hort-http-core/src/test_support.rs"];

        let unallowed: Vec<&str> = stdout
            .lines()
            .filter(|line| !line.is_empty())
            .filter(|line| !allowed_substrings.iter().any(|s| line.contains(s)))
            .collect();

        assert!(
            unallowed.is_empty(),
            "found `Arc::new(AppContext {{ ... }})` outside test_support.rs:\n{}\n\
             (stderr: {})\n\
             Use `hort_http_core::test_support::build_mock_ctx` + the `with_*` helpers \
             instead.",
            unallowed.join("\n"),
            stderr
        );
    }
}

#[cfg(test)]
mod pull_dedup_wiring_tests {
    //! The `AppContext.pull_dedup` slot must be
    //! populated by `build_mock_ctx` (and, by mechanical mirror, by
    //! `composition::build_app_context`) AND must be the SAME `Arc` as
    //! the one exposed on `MockPorts.pull_dedup` — no double
    //! construction. Pointer-equality is the cheapest possible
    //! assertion that "tests pass on memory" preserves "tests pass on
    //! Redis": both sides observe the same `EphemeralStore`-backed
    //! coordination state.
    //!
    //! The composition root in `hort-server::composition::build_app_context`
    //! follows the same shape (single `Arc::new(PullDedup::new(...))`
    //! threaded into `AppContextParts`); a hand-rolled production-side
    //! `Arc::ptr_eq` test would require constructing a full
    //! `BuildAppContextOutput`, which currently has no harness in
    //! `crates/hort-server/src/composition.rs::tests` (the existing tests
    //! cover helpers — `resolve_redis_url`, `build_ephemeral_stores`,
    //! `read_extra_ca_bundle`, `derive_oci_token_endpoint_strings`,
    //! `emit_pat_over_http_signal` — not full-context assembly).
    //! Adding such a harness would require an in-process Postgres
    //! fixture and is out of scope for this item; the mock-side check
    //! here pins the `AppContextParts → AppContext::new → ctx`
    //! identity transform that production also runs through.

    use super::*;
    use metrics_exporter_prometheus::PrometheusBuilder;

    /// Cross-check: the `Arc<PullDedup>` on `MockPorts.pull_dedup` is
    /// pointer-equal to the one on `ctx.pull_dedup`. Trips on any
    /// future refactor that re-constructs the service in either path.
    #[tokio::test]
    async fn ctx_and_mockports_share_same_pull_dedup_arc() {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);
        assert!(
            Arc::ptr_eq(&ctx.pull_dedup, &mocks.pull_dedup),
            "ctx.pull_dedup and mocks.pull_dedup must reference the same Arc \
             (no double construction)"
        );
    }

    /// Cross-check: the `Arc<PullDedup>` carried over a `with_*`
    /// rebuild remains pointer-equal to the original. Confirms
    /// `rebuild` threads the field unchanged (acceptance line: "every
    /// `with_*` builder threads the field through").
    #[tokio::test]
    async fn pull_dedup_arc_survives_with_trust_config_rebuild() {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (base, _mocks) = build_mock_ctx(handle);
        let original = base.pull_dedup.clone();
        let rebuilt = with_trust_config(&base, trust_config_untrusted_peer_fallback());
        assert!(
            Arc::ptr_eq(&original, &rebuilt.pull_dedup),
            "pull_dedup must survive a with_trust_config rebuild as the same Arc"
        );
    }

    /// The `AppContext.metadata_mirror` slot must be
    /// populated by `build_mock_ctx` so the per-format fetch
    /// paths can drive `ctx.metadata_mirror.as_ref()`. The `pub` field
    /// resolves through the [`MetadataMirrorStore`] trait object.
    #[tokio::test]
    async fn build_mock_ctx_has_metadata_mirror() {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, _mocks) = build_mock_ctx(handle);
        let _: &Arc<dyn MetadataMirrorStore> = &ctx.metadata_mirror;
    }
}
