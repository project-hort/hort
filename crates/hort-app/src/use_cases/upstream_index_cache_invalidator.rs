//! Application-layer adapter for the
//! [`UpstreamIndexCacheInvalidator`](hort_domain::ports::upstream_index_cache_invalidator::UpstreamIndexCacheInvalidator)
//! domain port.
//!
//! See the port contract:
//! `crates/hort-domain/src/ports/upstream_index_cache_invalidator.rs`.
//!
//! # Why this lives in `hort-app` (not `hort-adapters-postgres`)
//!
//! `hort-adapters-postgres` has zero
//! `EphemeralStore` consumers and the implementation here is
//! application-layer orchestration over domain ports (DB-reads via
//! `RepositoryRepository` + `RepositoryUpstreamMappingRepository`,
//! cache writes via `EphemeralStore`). [`PatCache`](crate::use_cases::pat_cache::PatCache)
//! is the production precedent for a domain-port-composed invalidator
//! in `hort-app`.
//!
//! # Per-format cache key shapes
//!
//! | Format | Cache key | Source |
//! |---|---|---|
//! | **npm** | `npm_packument_proj:{mapping.id}:{url_encoded_raw_name}` | `crates/hort-http-npm/src/packument.rs` |
//! | **PyPI** | `pypi_simple_proj:{mapping.id}:{normalized_name}` (× 1 — format-independent) | `crates/hort-http-pypi/src/simple_index.rs` |
//! | **cargo** | `cargo_index_proj:{mapping.id}:{index_path_for(crate_name)}` (lowercased + sharded) | `crates/hort-http-cargo/src/index_cache.rs` |
//!
//! The PyPI serve cache is ONE
//! format-INDEPENDENT projection row (`pypi_simple_proj:{...}`), not two
//! per-format raw-body rows, so the
//! invalidator deletes a SINGLE key per mapping. The raw
//! body lives in the `MetadataMirrorStore` (overwrite-on-refresh;
//! lifecycle rides the retention pipeline), so it is not an
//! EphemeralStore key
//! this invalidator owns. The cargo `cargo_index_config:` family
//! (per-mapping config, not per-package) is **skipped** — invalidating it
//! on `ArtifactRejected` would force every operator to re-read the entire
//! upstream config on the next request for that mapping.
//!
//! Aliased formats (Yarn → npm, Poetry/Conda → PyPI, etc.) route per
//! the underlying family. Formats with no upstream-index cache today
//! (OCI/Docker, Maven, Helm, RPM, Debian, …) yield zero evictions
//! (no-op) — if a future format adds an `EphemeralStore`-backed
//! upstream cache, it joins this dispatcher.
//!
//! # Best-effort, not load-bearing
//!
//! Invalidation failure must NOT roll back the caller's
//! event-store append. The `NonServableStatusFilter` on the
//! next index-build is the load-bearing close on the index-build path;
//! this adapter is defense-in-depth cache hygiene that shortens the
//! freshness-of-revocation-signal window from `TTL` to "immediate OR
//! next index build, whichever fires first".

use std::sync::Arc;

use uuid::Uuid;

use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::DomainResult;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;
use hort_domain::ports::upstream_index_cache_invalidator::UpstreamIndexCacheInvalidator;
use hort_domain::ports::BoxFuture;

/// Application-layer adapter for the
/// [`UpstreamIndexCacheInvalidator`] domain port. See module-level
/// docs for the per-format key shapes + best-effort contract.
pub struct AppUpstreamIndexCacheInvalidator {
    repositories: Arc<dyn RepositoryRepository>,
    upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
    /// The **evictable** ephemeral store (`ctx.ephemeral_evictable`).
    /// All three target keyspaces (`npm_packument_proj:`, `pypi_simple_proj:`,
    /// `cargo_index_proj:`) are classified `Evictable` in
    /// [`KEYSPACE_REGISTRY`](crate::ephemeral_keyspace::KEYSPACE_REGISTRY);
    /// the durable store does not hold these keys.
    ephemeral_evictable: Arc<dyn EphemeralStore>,
}

impl AppUpstreamIndexCacheInvalidator {
    pub fn new(
        repositories: Arc<dyn RepositoryRepository>,
        upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
        ephemeral_evictable: Arc<dyn EphemeralStore>,
    ) -> Self {
        Self {
            repositories,
            upstream_mappings,
            ephemeral_evictable,
        }
    }
}

impl UpstreamIndexCacheInvalidator for AppUpstreamIndexCacheInvalidator {
    fn invalidate_for_package(
        &self,
        repository_id: Uuid,
        package_raw_name: &str,
    ) -> BoxFuture<'_, DomainResult<u32>> {
        let package = package_raw_name.to_owned();
        Box::pin(async move {
            let repo = self.repositories.find_by_id(repository_id).await?;
            let mappings = self
                .upstream_mappings
                .list_for_repository(repository_id)
                .await?;
            if mappings.is_empty() {
                return Ok(0);
            }

            // Per-format key derivation. Aliased families route per
            // their underlying format (spec §4 — the comment table
            // in the module docs); unsupported formats yield no keys
            // and the loop is a no-op.
            let keys: Vec<String> = mappings
                .iter()
                .flat_map(|m| derive_cache_keys(&repo.format, m.id, &package))
                .collect();
            if keys.is_empty() {
                return Ok(0);
            }

            let mut evicted: u32 = 0;
            for key in &keys {
                self.ephemeral_evictable.delete(key).await?;
                evicted += 1;
            }
            Ok(evicted)
        })
    }
}

// ---------------------------------------------------------------------------
// Per-format key derivation (pure functions — easy to unit-test
// individually, and the dispatcher in `derive_cache_keys` routes by
// `RepositoryFormat`)
// ---------------------------------------------------------------------------

/// URL-encode an npm package name for the registry path.
///
/// `/` → `%2f` (lowercase) per the npm registry convention —
/// **bit-for-bit** identical to
/// `crates/hort-http-npm/src/packument.rs::url_encode_npm_name`. Kept
/// inline here rather than pulled from `hort-http-npm` because `hort-app`
/// must not depend on a format-handler crate (hexagonal dep graph —
/// `hort-app` is below the inbound-HTTP layer).
fn url_encode_npm_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    for c in name.chars() {
        match c {
            '/' => out.push_str("%2f"),
            _ => out.push(c),
        }
    }
    out
}

/// PEP 503 §4 — lowercase, collapse runs of `-_.` to a single `-`.
///
/// **Bit-for-bit** identical to
/// `crates/hort-formats/src/pypi.rs::PyPiFormatHandler::normalize_name`.
/// Inlined here for the same hexagonal-layering reason as
/// [`url_encode_npm_name`] — `hort-app` cannot depend on `hort-formats`.
/// Any divergence between the two would surface as a cache-key miss
/// here that leaves the upstream advertisement live until TTL; the
/// integration test (`packument_cache_invalidated_on_reject`)
/// is the regression guard against drift.
fn normalize_pep503(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    let mut in_separator_run = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !in_separator_run && !result.is_empty() {
                result.push('-');
                in_separator_run = true;
            }
        } else {
            in_separator_run = false;
            result.extend(c.to_lowercase());
        }
    }
    if result.ends_with('-') {
        result.pop();
    }
    result
}

/// Build the sparse-index path for a crate name per RFC 2789 — the
/// same shape `hort-http-cargo` consumes via `hort_formats::cargo::index_path_for`.
///
/// **Bit-for-bit** identical to `hort_formats::cargo::index_path_for`,
/// inlined for the hexagonal-layering reason explained on
/// [`url_encode_npm_name`].
fn cargo_index_path_for(crate_name: &str) -> String {
    let lower = crate_name.to_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    let prefix = match chars.len() {
        // The production helper panics on empty input (caller is
        // expected to have validated upstream). The cache invalidator
        // is called from a post-commit hook with an artifact name that
        // already round-tripped through ingest, so empty is
        // practically unreachable — but a panic here would surface as
        // a `warn!`-and-drop at the call site, the wrong end of a
        // best-effort guarantee. Return the empty path; the resulting
        // key (`cargo_index_proj:{mapping.id}:`) cannot collide with any
        // real cache row and the delete is a benign no-op.
        0 => return String::new(),
        1 => "1".to_string(),
        2 => "2".to_string(),
        3 => format!("3/{}", chars[0]),
        _ => {
            let aa: String = chars[..2].iter().collect();
            let bb: String = chars[2..4].iter().collect();
            format!("{aa}/{bb}")
        }
    };
    format!("{prefix}/{lower}")
}

/// Dispatch per repository format. Returns the set of cache keys that
/// the invalidator should delete for `(mapping_id, package_raw_name)`.
/// An empty result means the format has no `EphemeralStore`-backed
/// upstream index cache today; the call is a no-op.
fn derive_cache_keys(
    format: &RepositoryFormat,
    mapping_id: Uuid,
    package_raw_name: &str,
) -> Vec<String> {
    match format {
        // npm and aliased npm-based families share the packument
        // cache. `hort-http-npm` is the sole writer; the Redis entry is
        // the small projection (`npm_packument_proj:`), not the raw body
        // (`npm_packument_raw:`) — the
        // invalidator deletes the projection cache. The raw body lives in
        // the `MetadataMirrorStore` (overwrite-on-refresh; lifecycle
        // rides the retention pipeline), so it is not an EphemeralStore
        // key this invalidator owns.
        RepositoryFormat::Npm
        | RepositoryFormat::Yarn
        | RepositoryFormat::Bower
        | RepositoryFormat::Pnpm => {
            let encoded = url_encode_npm_name(package_raw_name);
            vec![format!("npm_packument_proj:{mapping_id}:{encoded}")]
        }
        // PyPI and aliased PyPI-based families share the simple-index
        // cache. The cache is
        // ONE format-INDEPENDENT projection row (`pypi_simple_proj:{...}`),
        // not two per-format raw-body rows;
        // both serve arms project to the SAME `PypiSimpleIndexProjection`,
        // so the invalidator deletes a SINGLE key. The raw body lives
        // in the `MetadataMirrorStore`, not an EphemeralStore key this
        // invalidator owns.
        RepositoryFormat::Pypi | RepositoryFormat::Poetry | RepositoryFormat::Conda => {
            let normalized = normalize_pep503(package_raw_name);
            vec![format!("pypi_simple_proj:{mapping_id}:{normalized}")]
        }
        // Cargo — the Redis entry is the small projection
        // (`cargo_index_proj:`), not the raw
        // NDJSON body (`cargo_index:`); the invalidator deletes the
        // projection cache. The raw body lives in the `MetadataMirrorStore`
        // (overwrite-on-refresh; lifecycle rides the retention pipeline),
        // so it is not an EphemeralStore key this invalidator owns.
        // `cargo_index_config:` is intentionally NOT included (per-mapping
        // config, not per-package; invalidating it would force a re-read of
        // the entire upstream config on every `ArtifactRejected`).
        RepositoryFormat::Cargo => {
            let path = cargo_index_path_for(package_raw_name);
            vec![format!("cargo_index_proj:{mapping_id}:{path}")]
        }
        // Formats with no upstream-index `EphemeralStore` cache today
        // (OCI/Docker, Maven, Gradle, Helm, RPM, Debian, NuGet, …) —
        // no-op. A future format that adds such a cache joins the
        // dispatcher above.
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Post-commit hook helper — extracted because the three emitter sites
// (CurationUseCase::block_one, QuarantineUseCase::record_scan_result
// Reject branch, ApplyConfigUseCase::commit_retroactive_block) cross
// the 3-blocks duplication threshold (CLAUDE.md). See spec §5.
// ---------------------------------------------------------------------------

/// Best-effort post-commit cache-invalidation hook. Called by each
/// `ArtifactRejected` emitter **after** its `commit_*` returns
/// `Ok(_)`. Logs `tracing::debug!` on success (per spec §5 — defense-
/// in-depth, not security-relevant) and `tracing::warn!` on failure.
/// Returns `()` — the caller never propagates this error (the event-
/// store append already committed).
pub(crate) async fn invalidate_after_reject(
    invalidator: &Arc<dyn UpstreamIndexCacheInvalidator>,
    artifact_id: Uuid,
    repository_id: Uuid,
    package_name: &str,
) {
    match invalidator
        .invalidate_for_package(repository_id, package_name)
        .await
    {
        Ok(keys_evicted) => {
            tracing::debug!(
                artifact_id = %artifact_id,
                repository_id = %repository_id,
                package = %package_name,
                keys_evicted,
                "upstream index cache invalidated post-ArtifactRejected"
            );
        }
        Err(e) => {
            tracing::warn!(
                artifact_id = %artifact_id,
                repository_id = %repository_id,
                package = %package_name,
                error = %e,
                "upstream index cache invalidation failed post-ArtifactRejected; falling back to TTL freshness"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use bytes::Bytes;
    use chrono::Utc;

    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::Repository;
    use hort_domain::error::{DomainError, DomainResult};
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };

    use super::*;
    use crate::use_cases::test_support::{
        sample_repository, MockRepositoryRepository, MockRepositoryUpstreamMappingRepository,
    };

    // -----------------------------------------------------------------
    // Tiny in-memory EphemeralStore — minimal surface the invalidator
    // needs (`get` + `put` + `delete`). The other trait methods are
    // not exercised by the tests; we panic on call to surface any
    // accidental use clearly.
    // -----------------------------------------------------------------

    struct TestEphemeralStore {
        entries: Mutex<std::collections::HashMap<String, Bytes>>,
        fail_next_delete: Mutex<Option<DomainError>>,
        delete_calls: Mutex<u32>,
    }

    impl TestEphemeralStore {
        fn new() -> Self {
            Self {
                entries: Mutex::new(std::collections::HashMap::new()),
                fail_next_delete: Mutex::new(None),
                delete_calls: Mutex::new(0),
            }
        }

        fn seed(&self, key: &str, value: &[u8]) {
            self.entries
                .lock()
                .unwrap()
                .insert(key.to_owned(), Bytes::copy_from_slice(value));
        }

        fn has(&self, key: &str) -> bool {
            self.entries.lock().unwrap().contains_key(key)
        }

        fn fail_next(&self, e: DomainError) {
            *self.fail_next_delete.lock().unwrap() = Some(e);
        }

        fn delete_call_count(&self) -> u32 {
            *self.delete_calls.lock().unwrap()
        }
    }

    impl EphemeralStore for TestEphemeralStore {
        fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            let v = self.entries.lock().unwrap().get(key).cloned();
            Box::pin(async move { Ok(v) })
        }

        fn put(&self, key: &str, value: Bytes, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            self.entries.lock().unwrap().insert(key.to_owned(), value);
            Box::pin(async { Ok(()) })
        }

        fn put_if_absent(
            &self,
            _key: &str,
            _value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            unimplemented!("TestEphemeralStore::put_if_absent not exercised by this invalidator")
        }

        fn compare_and_swap(
            &self,
            _key: &str,
            _expected_version: u64,
            _new_value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            unimplemented!("TestEphemeralStore::compare_and_swap not exercised by this invalidator")
        }

        fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
            *self.delete_calls.lock().unwrap() += 1;
            if let Some(e) = self.fail_next_delete.lock().unwrap().take() {
                return Box::pin(async move { Err(e) });
            }
            self.entries.lock().unwrap().remove(key);
            Box::pin(async { Ok(()) })
        }

        fn extend_ttl(&self, _key: &str, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            unimplemented!("TestEphemeralStore::extend_ttl not exercised by this invalidator")
        }

        // `try_increment_counter` has a default impl on the trait —
        // we deliberately do NOT override it: this invalidator never
        // touches a counter keyspace.
    }

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    fn make_repo(format: RepositoryFormat) -> Repository {
        let mut r = sample_repository();
        r.format = format;
        r
    }

    fn make_mapping(repo_id: Uuid) -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo_id,
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

    fn build_invalidator(
        repo: Repository,
        mappings: Vec<RepositoryUpstreamMapping>,
        eph: Arc<TestEphemeralStore>,
    ) -> AppUpstreamIndexCacheInvalidator {
        let repos = MockRepositoryRepository::new();
        repos.insert(repo);
        let upstreams = MockRepositoryUpstreamMappingRepository::new();
        for m in mappings {
            // Use `upsert` so insertion mirrors the production
            // adapter's semantics (path_prefix == "" is the catch-all;
            // multiple non-empty prefixes coexist).
            futures::executor::block_on(upstreams.upsert(m)).expect("mock upsert never errors");
        }
        AppUpstreamIndexCacheInvalidator::new(Arc::new(repos), Arc::new(upstreams), eph)
    }

    // -----------------------------------------------------------------
    // Tests (spec §7)
    // -----------------------------------------------------------------

    /// Spec §7 case 1 — two npm mappings, same package. Both cache
    /// rows evicted in one call. Unrelated-package row survives.
    #[tokio::test]
    async fn invalidates_npm_packument_for_two_mappings() {
        let repo = make_repo(RepositoryFormat::Npm);
        let m1 = make_mapping(repo.id);
        let mut m2 = make_mapping(repo.id);
        m2.path_prefix = "@scope/".into();
        let eph = Arc::new(TestEphemeralStore::new());
        eph.seed(&format!("npm_packument_proj:{}:lodash", m1.id), b"{}");
        eph.seed(&format!("npm_packument_proj:{}:lodash", m2.id), b"{}");
        eph.seed(&format!("npm_packument_proj:{}:react", m1.id), b"{}");
        let inv = build_invalidator(repo.clone(), vec![m1.clone(), m2.clone()], eph.clone());

        let evicted = inv
            .invalidate_for_package(repo.id, "lodash")
            .await
            .expect("invalidate must succeed");

        assert_eq!(evicted, 2, "exactly two npm cache rows must be evicted");
        assert!(!eph.has(&format!("npm_packument_proj:{}:lodash", m1.id)));
        assert!(!eph.has(&format!("npm_packument_proj:{}:lodash", m2.id)));
        assert!(
            eph.has(&format!("npm_packument_proj:{}:react", m1.id)),
            "unrelated package must survive"
        );
    }

    /// PyPI invalidates the SINGLE
    /// unified, format-INDEPENDENT projection key (not two per-format
    /// raw-body rows).
    #[tokio::test]
    async fn invalidates_pypi_simple_unified_projection_key() {
        let repo = make_repo(RepositoryFormat::Pypi);
        let m = make_mapping(repo.id);
        let eph = Arc::new(TestEphemeralStore::new());
        eph.seed(&format!("pypi_simple_proj:{}:requests", m.id), b"{}");
        eph.seed(&format!("pypi_simple_proj:{}:flask", m.id), b"{}");
        let inv = build_invalidator(repo.clone(), vec![m.clone()], eph.clone());

        let evicted = inv
            .invalidate_for_package(repo.id, "requests")
            .await
            .expect("invalidate must succeed");

        assert_eq!(
            evicted, 1,
            "PyPI must evict the single unified projection cache entry per mapping"
        );
        assert!(!eph.has(&format!("pypi_simple_proj:{}:requests", m.id)));
        assert!(
            eph.has(&format!("pypi_simple_proj:{}:flask", m.id)),
            "unrelated package must survive"
        );
    }

    /// Spec §7 case 3 — cargo invalidates the per-crate key but
    /// preserves the per-mapping `cargo_index_config:` row (sibling
    /// keyspace; per-mapping config, not per-package).
    #[tokio::test]
    async fn invalidates_cargo_index_skipping_config_key() {
        let repo = make_repo(RepositoryFormat::Cargo);
        let m = make_mapping(repo.id);
        let eph = Arc::new(TestEphemeralStore::new());
        // For "serde", the cargo sparse-index path is "se/rd/serde"
        // (chars 0..2 then chars 2..4 then full lowercase).
        eph.seed(&format!("cargo_index_proj:{}:se/rd/serde", m.id), b"{}");
        eph.seed(&format!("cargo_index_config:{}", m.id), b"{}");
        let inv = build_invalidator(repo.clone(), vec![m.clone()], eph.clone());

        let evicted = inv
            .invalidate_for_package(repo.id, "serde")
            .await
            .expect("invalidate must succeed");

        assert_eq!(
            evicted, 1,
            "exactly one cargo cache row evicted; cargo_index_config: is per-mapping not per-crate"
        );
        assert!(!eph.has(&format!("cargo_index_proj:{}:se/rd/serde", m.id)));
        assert!(
            eph.has(&format!("cargo_index_config:{}", m.id)),
            "per-mapping cargo_index_config: must survive — this is the regression \
             guard against accidentally widening the invalidation to per-mapping config"
        );
    }

    /// Spec §7 case 4 — PyPI key derivation uses PEP 503 normalised
    /// form so cache-row identity follows the writer's key shape. The
    /// invalidator receives a raw name and normalises internally.
    #[tokio::test]
    async fn invalidates_pep503_normalised_pypi_name() {
        let repo = make_repo(RepositoryFormat::Pypi);
        let m = make_mapping(repo.id);
        let eph = Arc::new(TestEphemeralStore::new());
        // The cache writer normalises `Some.Package` → `some-package`
        // (one unified, format-independent key).
        eph.seed(&format!("pypi_simple_proj:{}:some-package", m.id), b"{}");
        let inv = build_invalidator(repo.clone(), vec![m.clone()], eph.clone());

        // Invoke with the **un-normalised** raw name as seen on the
        // wire (mixed case, dots) — the invalidator MUST normalise.
        let evicted = inv
            .invalidate_for_package(repo.id, "Some.Package")
            .await
            .expect("invalidate must succeed");

        assert_eq!(evicted, 1);
        assert!(!eph.has(&format!("pypi_simple_proj:{}:some-package", m.id)));
    }

    /// Spec §7 case 5 — a repo with no upstream mappings yields
    /// `Ok(0)` and emits zero `EphemeralStore::delete` calls. The
    /// delete-call counter pins the no-op contract.
    #[tokio::test]
    async fn repository_with_no_mappings_returns_zero() {
        let repo = make_repo(RepositoryFormat::Npm);
        let eph = Arc::new(TestEphemeralStore::new());
        // Seed something unrelated so a buggy "delete everything" arm
        // would surface as a non-zero call count.
        eph.seed("npm_packument_proj:<some-mapping>:lodash", b"{}");
        let inv = build_invalidator(repo.clone(), Vec::new(), eph.clone());

        let evicted = inv
            .invalidate_for_package(repo.id, "lodash")
            .await
            .expect("invalidate must succeed");

        assert_eq!(evicted, 0);
        assert_eq!(
            eph.delete_call_count(),
            0,
            "no upstream mappings means no EphemeralStore::delete calls"
        );
    }

    /// Spec §7 case 6 — when `EphemeralStore::delete` errors, the
    /// invalidator propagates `Err`. The caller logs `warn!` and does
    /// not roll back the event-store append (that is the contract of
    /// `invalidate_after_reject` — covered by the integration test).
    #[tokio::test]
    async fn ephemeral_store_error_propagates_to_caller() {
        let repo = make_repo(RepositoryFormat::Npm);
        let m = make_mapping(repo.id);
        let eph = Arc::new(TestEphemeralStore::new());
        eph.fail_next(DomainError::Invariant("simulated Redis outage".into()));
        let inv = build_invalidator(repo.clone(), vec![m], eph.clone());

        let err = inv
            .invalidate_for_package(repo.id, "lodash")
            .await
            .expect_err("invalidate must propagate the Ephemeral store error");
        assert!(
            err.to_string().contains("simulated Redis outage"),
            "the underlying error must be surfaced to the caller (got: {err})"
        );
    }

    /// Defence-in-depth — a format with no `EphemeralStore`-backed
    /// upstream cache today (OCI/Docker) returns `Ok(0)` even when
    /// upstream mappings exist. A no-op rather than an error keeps
    /// the call site one-line and surfaces no spurious `warn!`.
    #[tokio::test]
    async fn oci_format_yields_no_keys() {
        let repo = make_repo(RepositoryFormat::Oci);
        let m = make_mapping(repo.id);
        let eph = Arc::new(TestEphemeralStore::new());
        let inv = build_invalidator(repo.clone(), vec![m], eph.clone());

        let evicted = inv
            .invalidate_for_package(repo.id, "library/alpine")
            .await
            .expect("invalidate must succeed");

        assert_eq!(evicted, 0);
        assert_eq!(eph.delete_call_count(), 0);
    }

    /// Defence-in-depth — `invalidate_after_reject` is the post-commit
    /// hook helper called by the three emitter sites. The contract is
    /// "log and continue; never propagate". Exercise the success path
    /// here; the failure path is exercised indirectly via the unit
    /// tests on the underlying adapter (which return `Err`) plus the
    /// integration test.
    #[tokio::test]
    async fn invalidate_after_reject_helper_smoke_success() {
        let repo = make_repo(RepositoryFormat::Npm);
        let m = make_mapping(repo.id);
        let eph = Arc::new(TestEphemeralStore::new());
        eph.seed(&format!("npm_packument_proj:{}:lodash", m.id), b"{}");
        let inv: Arc<dyn UpstreamIndexCacheInvalidator> = Arc::new(build_invalidator(
            repo.clone(),
            vec![m.clone()],
            eph.clone(),
        ));

        // The helper returns `()` and never panics — covers the
        // tracing::debug! success branch.
        invalidate_after_reject(&inv, Uuid::new_v4(), repo.id, "lodash").await;
        assert!(!eph.has(&format!("npm_packument_proj:{}:lodash", m.id)));
    }

    /// Defence-in-depth — `invalidate_after_reject` on the failure
    /// branch logs `warn!` and returns; it does NOT panic or propagate.
    /// This is the contract that lets the three emitter sites call it
    /// as a fire-and-forget hook.
    #[tokio::test]
    async fn invalidate_after_reject_helper_smoke_failure_is_swallowed() {
        let repo = make_repo(RepositoryFormat::Npm);
        let m = make_mapping(repo.id);
        let eph = Arc::new(TestEphemeralStore::new());
        eph.fail_next(DomainError::Invariant("simulated outage".into()));
        let inv: Arc<dyn UpstreamIndexCacheInvalidator> =
            Arc::new(build_invalidator(repo.clone(), vec![m], eph));

        // No `.expect()` / `?` — the helper must absorb the failure.
        invalidate_after_reject(&inv, Uuid::new_v4(), repo.id, "lodash").await;
    }

    // -----------------------------------------------------------------
    // Pure-function tests for the key-derivation helpers — proves the
    // bit-for-bit equivalence with the production cache writers.
    // -----------------------------------------------------------------

    #[test]
    fn url_encode_npm_name_matches_production() {
        // Mirror `crates/hort-http-npm/src/packument.rs::url_encode_npm_name`.
        assert_eq!(url_encode_npm_name("express"), "express");
        assert_eq!(url_encode_npm_name("@types/node"), "@types%2fnode");
    }

    #[test]
    fn normalize_pep503_matches_production() {
        // Mirror `crates/hort-formats/src/pypi.rs::PyPiFormatHandler::normalize_name`.
        assert_eq!(normalize_pep503("Foo"), "foo");
        assert_eq!(normalize_pep503("Some-Package"), "some-package");
        assert_eq!(normalize_pep503("Some.Package"), "some-package");
        assert_eq!(normalize_pep503("Some_Package"), "some-package");
        assert_eq!(normalize_pep503("foo___bar"), "foo-bar");
        assert_eq!(normalize_pep503("Foo-_-Bar"), "foo-bar");
    }

    #[test]
    fn cargo_index_path_for_matches_production() {
        // Mirror `hort_formats::cargo::index_path_for` shape (lower +
        // sharded; len(1)→"1", len(2)→"2", len(3)→"3/<c0>",
        // otherwise→"<c0c1>/<c2c3>").
        assert_eq!(cargo_index_path_for("a"), "1/a");
        assert_eq!(cargo_index_path_for("ab"), "2/ab");
        assert_eq!(cargo_index_path_for("abc"), "3/a/abc");
        assert_eq!(cargo_index_path_for("serde"), "se/rd/serde");
        assert_eq!(cargo_index_path_for("Serde"), "se/rd/serde");
    }

    #[test]
    fn derive_cache_keys_npm_returns_single_key() {
        let mapping_id = Uuid::new_v4();
        let keys = derive_cache_keys(&RepositoryFormat::Npm, mapping_id, "express");
        assert_eq!(
            keys,
            vec![format!("npm_packument_proj:{mapping_id}:express")]
        );
    }

    #[test]
    fn derive_cache_keys_pypi_returns_single_unified_key() {
        // The PyPI serve cache is one
        // format-INDEPENDENT projection key (not two per-format rows).
        let mapping_id = Uuid::new_v4();
        let keys = derive_cache_keys(&RepositoryFormat::Pypi, mapping_id, "requests");
        assert_eq!(
            keys,
            vec![format!("pypi_simple_proj:{mapping_id}:requests")]
        );
    }

    #[test]
    fn derive_cache_keys_cargo_returns_single_key_no_config() {
        let mapping_id = Uuid::new_v4();
        let keys = derive_cache_keys(&RepositoryFormat::Cargo, mapping_id, "serde");
        assert_eq!(
            keys,
            vec![format!("cargo_index_proj:{mapping_id}:se/rd/serde")]
        );
        // Critical — no `cargo_index_config:` row in the output.
        assert!(
            !keys.iter().any(|k| k.starts_with("cargo_index_config:")),
            "derive_cache_keys must never produce a cargo_index_config: key"
        );
    }

    #[test]
    fn derive_cache_keys_unsupported_format_is_empty() {
        let mapping_id = Uuid::new_v4();
        // OCI, Maven, Helm, RPM, Debian — no EphemeralStore-backed
        // upstream cache today.
        for fmt in [
            RepositoryFormat::Oci,
            RepositoryFormat::Maven,
            RepositoryFormat::Helm,
            RepositoryFormat::Rpm,
            RepositoryFormat::Debian,
            RepositoryFormat::Generic,
        ] {
            assert!(
                derive_cache_keys(&fmt, mapping_id, "any").is_empty(),
                "format {fmt:?} must yield no keys (no upstream cache today)"
            );
        }
    }

    #[test]
    fn derive_cache_keys_npm_aliases_route_to_npm() {
        let mapping_id = Uuid::new_v4();
        for fmt in [
            RepositoryFormat::Yarn,
            RepositoryFormat::Bower,
            RepositoryFormat::Pnpm,
        ] {
            let keys = derive_cache_keys(&fmt, mapping_id, "express");
            assert_eq!(
                keys,
                vec![format!("npm_packument_proj:{mapping_id}:express")],
                "{fmt:?} must route to the npm packument key shape"
            );
        }
    }

    #[test]
    fn derive_cache_keys_pypi_aliases_route_to_pypi() {
        let mapping_id = Uuid::new_v4();
        for fmt in [RepositoryFormat::Poetry, RepositoryFormat::Conda] {
            let keys = derive_cache_keys(&fmt, mapping_id, "requests");
            // One unified key.
            assert_eq!(
                keys,
                vec![format!("pypi_simple_proj:{mapping_id}:requests")]
            );
        }
    }
}
