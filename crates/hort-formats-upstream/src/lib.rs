//! `UpstreamMetadataPort` composition adapter.
//!
//! This is the ONLY production crate other than `hort-server` that imports
//! multiple `hort-http-<format>` inbound crates as a normal dep. The
//! dispatch table on `format` ("npm" / "pypi" / "cargo") is the
//! composition seam — each format branch composes:
//!
//! 1. the per-format `fetch_raw_with_cache` helper (in
//!    `hort-http-<format>`), which owns the cache + dedup + upstream
//!    proxy fetch + URL composition for that format's wire shape, with
//!    2. the per-format `FormatHandler::extract_upstream_versions`
//!    parser (in `hort-formats`), which extracts the upstream-advertised
//!    version set from the raw bytes the helper returned.
//!
//! See `docs/architecture/explanation/format-handlers.md` and
//! `docs/architecture/explanation/prefetch-pipeline.md` for the design
//! rationale.
//!
//! # Cycle-avoidance discipline
//!
//! [`UpstreamMetadataAdapter`] holds `Arc<dyn UpstreamResolver>` +
//! `Arc<dyn EphemeralStore>` + `Arc<dyn UpstreamProxy>` +
//! `Arc<PullDedup>` — **never** `Arc<AppContext>`. The composition root
//! wires `AppContext` to hold `Arc<dyn UpstreamMetadataPort>`, so holding
//! `AppContext` here would close a construction cycle. The composition
//! root passes the same `Arc`s to both this adapter's constructor and
//! into `AppContext::builder()` — "shared dependency, two consumers".
//!
//! # Dispatch table
//!
//! | `format` | fetch                                                | parser                                                      |
//! |----------|------------------------------------------------------|-------------------------------------------------------------|
//! | `"npm"`  | [`hort_http_npm::packument::fetch_raw_with_cache`]     | [`hort_formats::npm::NpmFormatHandler::extract_upstream_versions`]   |
//! | `"pypi"` | [`hort_http_pypi::simple_index::fetch_raw_with_cache`] | [`hort_formats::pypi::PyPiFormatHandler::extract_upstream_versions`] |
//! | `"cargo"`| [`hort_http_cargo::index_cache::fetch_raw_with_cache`] | [`hort_formats::cargo::CargoFormatHandler::extract_upstream_versions`]|
//! | `"oci"`  | rejected → [`UpstreamFetchError::UnsupportedFormat`] | n/a                                                         |
//! | other    | rejected → [`UpstreamFetchError::UnsupportedFormat`] | n/a                                                         |
//!
//! # Error mapping
//!
//! The per-format helpers currently classify upstream failures into
//! three coarse variants (`NoUpstream`, `UpstreamUnavailable`,
//! `Internal`). The adapter maps them to the closest [`UpstreamFetchError`]
//! variant:
//!
//! - `NoUpstream` → [`UpstreamFetchError::NotFound`]: the repo has no
//!   upstream mapping configured, so from the discovery / prefetch
//!   use-case's perspective the package is "not found upstream".
//!   Mirrors the helper's own wire mapping (the per-format inbound
//!   handler returns 404 for `NoUpstream`).
//! - `UpstreamUnavailable` → [`UpstreamFetchError::NetworkError`] with
//!   a constant `"upstream fetch failed"` label. The sanitisation
//!   contract (no URLs, hosts, package names, response bytes) is
//!   honored by construction — the label is hard-coded.
//! - `Internal` → [`UpstreamFetchError::ParseError`] with a constant
//!   `"envelope encode/decode"` label.
//!
//! Parse-side failures from
//! [`FormatHandler::extract_upstream_versions`] (which can return
//! [`DomainError::Validation`] when the upstream body exceeds the
//! per-format byte cap) map to [`UpstreamFetchError::ParseError`] with
//! a constant `"parser body too large"` or `"parser malformed"` label.
//!
//! **Future work — finer-grained classification.** The eight typed
//! variants of [`UpstreamFetchError`] (`Unauthorized`, `RateLimited`,
//! `Upstream4xx`, `Upstream5xx`, `Timeout` …) align 1:1 with the
//! upstream-fetch subset of [`UpstreamErrorKind`], but the existing
//! per-format helpers collapse all upstream-side failures into
//! `UpstreamUnavailable`. Surfacing the rich kinds requires either
//! (a) widening the helpers' error enum to carry an
//! `Option<UpstreamErrorKind>`, or (b) a domain-layer helper that
//! parses the `upstream:<kind>:<detail>` sentinel encoded by
//! `hort-adapters-upstream-http` (the only existing
//! `UpstreamProxy` impl). Both are out of scope in the current release —
//! the upstream-metadata adapter calls out behaviour-preserving
//! signature refactor only.
//!
//! # `upstream_name_prefix` invariant
//!
//! `mapping.upstream_name_prefix` is OCI-effective-only per the
//! `RepositoryUpstreamMapping` doc (see
//! `docs/architecture/how-to/declare-gitops-config.md`). The npm /
//! pypi / cargo branches MUST NOT consume the field. The OCI branch
//! never reaches URL composition — the dispatch table rejects OCI
//! upstream of any composer. A unit test
//! (`upstream_name_prefix_is_inert_*`) asserts that for each of the
//! three non-OCI branches, `mapping.upstream_name_prefix = Some("foo")`
//! produces byte-identical version output as `None`.
//!
//! [`UpstreamErrorKind`]: hort_app::metrics::UpstreamErrorKind
//! [`DomainError::Validation`]: hort_domain::error::DomainError::Validation

use std::sync::Arc;

use hort_app::metrics::UpstreamFetchError;
use hort_app::ports::upstream_metadata::UpstreamMetadataPort;
use hort_app::pull_dedup::PullDedup;
use hort_domain::entities::repository::Repository;
use hort_domain::entities::repository::RepositoryType;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping;
use hort_domain::ports::upstream_proxy::UpstreamProxy;
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_domain::ports::BoxFuture;
// No dispatcher calls `FormatHandler::extract_upstream_versions` any more:
// every per-format helper returns the typed projection and each `dispatch_*`
// reads the version list off it directly (npm/cargo via the typed `version`
// field, pypi via `pypi_extract_version_from_filename` over the projection's
// `files[]`). The `FormatHandler` trait + `PyPiFormatHandler` are now only
// referenced from the test module (`normalize_name` /
// `metadata_expected_max_bytes`), so their imports moved there.
use hort_http_cargo::index_cache as cargo_helpers;
use hort_http_npm::packument as npm_helpers;
use hort_http_pypi::simple_index as pypi_helpers;

/// Wire format key for npm.
const FORMAT_NPM: &str = "npm";
/// Wire format key for PyPI.
const FORMAT_PYPI: &str = "pypi";
/// Wire format key for Cargo.
const FORMAT_CARGO: &str = "cargo";
/// Wire format key for OCI (upstream metadata not supported).
const FORMAT_OCI: &str = "oci";

/// Default per-version-object projector cap
/// (`HORT_UPSTREAM_PROJECTOR_VERSION_OBJECT_MAX_SIZE` default 2 MiB). The
/// discovery seam (version-listing only) is not on the configurable
/// serve path that threads `AppContext.
/// upstream_projector_version_object_max_bytes`, so it uses the default —
/// the per-version cap is a parse-bomb DoS guard, not a correctness knob,
/// and version-listing reads only the `versions{}` keys.
const UPSTREAM_PROJECTOR_VERSION_OBJECT_DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024;

/// Composition adapter implementing [`UpstreamMetadataPort`].
///
/// See the crate-level docs for the dispatch table, error mapping,
/// and cycle-avoidance discipline.
#[derive(Clone)]
pub struct UpstreamMetadataAdapter {
    resolver: Arc<dyn UpstreamResolver>,
    cache: Arc<dyn EphemeralStore>,
    upstream_proxy: Arc<dyn UpstreamProxy>,
    pull_dedup: Arc<PullDedup>,
}

impl UpstreamMetadataAdapter {
    /// Construct a new adapter holding the shared resolver + cache +
    /// proxy + dedup `Arc`s.
    ///
    /// The composition root passes the same `Arc`s — by `Arc::clone` —
    /// to BOTH this constructor AND `AppContext::builder()`, so the adapter
    /// does not reach into a constructed `AppContext` (no construction
    /// cycle). See the crate-level docs for the rationale.
    pub fn new(
        resolver: Arc<dyn UpstreamResolver>,
        cache: Arc<dyn EphemeralStore>,
        upstream_proxy: Arc<dyn UpstreamProxy>,
        pull_dedup: Arc<PullDedup>,
    ) -> Self {
        Self {
            resolver,
            cache,
            upstream_proxy,
            pull_dedup,
        }
    }

    /// Build a synthetic `Repository` for the dispatch helpers. The
    /// per-format `fetch_raw_with_cache` helpers all take a `&Repository`
    /// reference; the only fields they read off it are `repo.id` (for
    /// the resolver) and `repo.key` (for tracing). The `mapping` parameter
    /// provides `repository_id` — we use that as `repo.id` so the
    /// resolver mock keying lines up. Other fields are filled with safe
    /// defaults; the helpers never inspect them.
    fn synthetic_repo(mapping: &RepositoryUpstreamMapping) -> Repository {
        use chrono::Utc;
        use hort_domain::entities::repository::{
            IndexMode, PrefetchPolicy, ReplicationPriority, RepositoryFormat,
        };
        let now = Utc::now();
        Repository {
            id: mapping.repository_id,
            key: format!("upstream-metadata:{}", mapping.repository_id),
            name: "upstream-metadata-synth".into(),
            description: None,
            format: RepositoryFormat::Generic,
            repo_type: RepositoryType::Proxy,
            storage_backend: "synth".into(),
            storage_path: "/synth".into(),
            upstream_url: Some(mapping.upstream_url.clone()),
            index_upstream_url: None,
            is_public: true,
            download_audit_enabled: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion: None,
            curation_rule_names: Vec::new(),
            index_mode: IndexMode::IncludePending,
            prefetch_policy: PrefetchPolicy::default(),
            created_at: now,
            updated_at: now,
            managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
            managed_by_digest: None,
        }
    }

    /// Dispatch a single format string to the appropriate
    /// fetch + parse pair. Extracted from [`Self::list_versions`] so the
    /// dispatch can be unit-tested in isolation. Returns the typed
    /// [`UpstreamFetchError`] for any branch — the consuming use case
    /// classifies once at the metric site.
    async fn dispatch(
        &self,
        format: &str,
        mapping: &RepositoryUpstreamMapping,
        package: &str,
    ) -> Result<Vec<String>, UpstreamFetchError> {
        match format {
            FORMAT_NPM => self.dispatch_npm(mapping, package).await,
            FORMAT_PYPI => self.dispatch_pypi(mapping, package).await,
            FORMAT_CARGO => self.dispatch_cargo(mapping, package).await,
            FORMAT_OCI => {
                // Discovery + prefetch are not supported for OCI.
                tracing::debug!(
                    format = %format,
                    "upstream metadata: OCI is rejected upstream of URL composition",
                );
                Err(UpstreamFetchError::UnsupportedFormat)
            }
            _ => {
                tracing::debug!(
                    format = %format,
                    "upstream metadata: unrecognised format",
                );
                Err(UpstreamFetchError::UnsupportedFormat)
            }
        }
    }

    async fn dispatch_npm(
        &self,
        mapping: &RepositoryUpstreamMapping,
        package: &str,
    ) -> Result<Vec<String>, UpstreamFetchError> {
        let repo = Self::synthetic_repo(mapping);
        // The npm helper streams the body through the projector and returns
        // the small `NpmProjection`. The discovery seam is version-listing
        // only: it does NOT serve, so it passes `mirror = None` (no
        // stale-while-error need, and it holds no mirror) and the default
        // per-version-object cap (2 MiB). The version list is the
        // projection's `versions[].version`.
        match npm_helpers::fetch_raw_with_cache(
            self.resolver.as_ref(),
            self.cache.as_ref(),
            self.upstream_proxy.as_ref(),
            self.pull_dedup.as_ref(),
            None,
            UPSTREAM_PROJECTOR_VERSION_OBJECT_DEFAULT_MAX_BYTES,
            &repo,
            package,
        )
        .await
        {
            Ok(projection) => {
                let versions: Vec<String> =
                    projection.versions.into_iter().map(|v| v.version).collect();
                Ok(versions)
            }
            Err(e) => Err(map_npm_helper_error(&e)),
        }
    }

    async fn dispatch_pypi(
        &self,
        mapping: &RepositoryUpstreamMapping,
        package: &str,
    ) -> Result<Vec<String>, UpstreamFetchError> {
        let repo = Self::synthetic_repo(mapping);
        // The composition seam fetches the HTML simple-index for the
        // upstream-advertised version list — it is the universal-fallback
        // shape (every PEP 503 mirror serves HTML; PEP 691 JSON is an
        // upgrade). HTML is the conservative choice for an upstream we
        // don't have prior knowledge of.
        //
        // The pypi helper streams the body through the format-appropriate
        // projector and returns the small `PypiSimpleIndexProjection` (the
        // raw body went to the mirror on the serve path). This
        // low-frequency discovery seam passes `mirror = None` (it does not
        // serve, so it has no mirror and no stale-while-error need) and the
        // default per-value-object cap (2 MiB), then derives the version
        // list directly from the projection's `files[]` filenames — so the
        // seam no longer caches the raw body either (the spec's "raw leaves
        // Redis" invariant covers pypi wholesale, not just serve). A
        // filename that yields no PEP 440 version is dropped (the same
        // skip-unparseable policy the retired `extract_upstream_versions`
        // had).
        match pypi_helpers::fetch_raw_with_cache(
            self.resolver.as_ref(),
            self.cache.as_ref(),
            self.upstream_proxy.as_ref(),
            self.pull_dedup.as_ref(),
            None,
            UPSTREAM_PROJECTOR_VERSION_OBJECT_DEFAULT_MAX_BYTES,
            &repo,
            package,
            pypi_helpers::SimpleIndexFormat::Html,
        )
        .await
        {
            Ok(projection) => {
                let versions: Vec<String> = projection
                    .files
                    .into_iter()
                    .filter_map(|f| {
                        f.filename
                            .or_else(|| {
                                f.url
                                    .as_deref()
                                    .and_then(|u| u.rsplit('/').next().map(str::to_string))
                            })
                            .and_then(|fname| {
                                hort_formats::pypi::pypi_extract_version_from_filename(&fname)
                            })
                    })
                    .collect();
                Ok(versions)
            }
            Err(e) => Err(map_pypi_helper_error(&e)),
        }
    }

    async fn dispatch_cargo(
        &self,
        mapping: &RepositoryUpstreamMapping,
        package: &str,
    ) -> Result<Vec<String>, UpstreamFetchError> {
        let repo = Self::synthetic_repo(mapping);
        // The cargo helper returns the streamed PROJECTION
        // (`Vec<CargoVersionLine>`); the raw body went to the mirror on the
        // serve path. This low-frequency discovery seam passes
        // `mirror = None` (it does not serve, so it has no mirror and no
        // stale-while-error need) and derives the version list directly
        // from the projection — so the seam no longer caches the raw body
        // either (the spec's "raw leaves Redis" invariant covers cargo
        // wholesale, not just serve).
        match cargo_helpers::fetch_raw_with_cache(
            self.resolver.as_ref(),
            self.cache.as_ref(),
            self.upstream_proxy.as_ref(),
            self.pull_dedup.as_ref(),
            None,
            &repo,
            package,
        )
        .await
        {
            Ok(projection) => {
                let versions = projection.into_iter().map(|l| l.vers).collect();
                Ok(versions)
            }
            Err(e) => Err(map_cargo_helper_error(&e)),
        }
    }
}

impl UpstreamMetadataPort for UpstreamMetadataAdapter {
    fn list_versions<'a>(
        &'a self,
        format: &'a str,
        mapping: &'a RepositoryUpstreamMapping,
        package: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, UpstreamFetchError>> {
        Box::pin(async move {
            let result = self.dispatch(format, mapping, package).await;
            match &result {
                Ok(versions) => {
                    tracing::debug!(
                        format = %format,
                        version_count = versions.len(),
                        "upstream metadata fetch succeeded",
                    );
                }
                Err(UpstreamFetchError::UnsupportedFormat) => {
                    // Not warn — this is the expected unsupported-format
                    // reject path, logged at debug in the dispatch helper.
                }
                Err(other) => {
                    tracing::warn!(
                        format = %format,
                        error = ?other,
                        "upstream metadata fetch failed",
                    );
                }
            }
            result
        })
    }
}

// `map_parse_result` was retired. It mapped a
// `FormatHandler::extract_upstream_versions(&raw_body)` parse result to the
// `UpstreamFetchError` taxonomy, but all three discovery-seam dispatchers
// (npm / cargo / pypi) now derive their version list directly from the typed
// projection the per-format helper returns (the raw body went to the mirror,
// never re-parsed here). With pypi migrated, the last caller is gone, so the
// helper + its tests were removed rather than left as dead surface.

/// Map the npm helper's coarse [`npm_helpers::PackumentFetchError`] to
/// the typed [`UpstreamFetchError`] taxonomy. See the crate-level docs
/// for the per-variant rationale.
fn map_npm_helper_error(e: &npm_helpers::PackumentFetchError) -> UpstreamFetchError {
    use npm_helpers::PackumentFetchError;
    match e {
        PackumentFetchError::NoUpstream => UpstreamFetchError::NotFound,
        PackumentFetchError::UpstreamUnavailable => {
            UpstreamFetchError::NetworkError("upstream fetch failed".into())
        }
        // The storage backstop is an artifact-fetch concern; the discovery /
        // self-service-prefetch path folds it to a network-class failure
        // (sanitised constant — no bytes/URLs), consistent with
        // `DiscoveryResult`/`PrefetchSelfServiceResult` collapsing the
        // `*TooLarge` kinds to `NetworkError`.
        PackumentFetchError::UpstreamBodyTooLarge { .. } => {
            UpstreamFetchError::NetworkError("upstream body too large".into())
        }
        // A malformed body or per-version-object cap trip is a parse-class
        // failure (NOT network); map to `ParseError` (sanitised constant —
        // no body/URL fragments).
        PackumentFetchError::MetadataMalformed { .. } => {
            UpstreamFetchError::ParseError("npm upstream packument malformed".into())
        }
        // A package name that fails `validate_npm_name` on the proxy-GET path
        // (INJ-3 serve-path validation) is a parse/validation-class failure;
        // map to `ParseError` with a sanitised constant (no name fragments).
        PackumentFetchError::InvalidName { .. } => {
            UpstreamFetchError::ParseError("npm package name invalid".into())
        }
        PackumentFetchError::VersionObjectTooLarge { .. } => {
            UpstreamFetchError::ParseError("npm upstream version object too large".into())
        }
        PackumentFetchError::Internal(_) => {
            // Sanitised — the helper's `Internal` carries an envelope-
            // encode/decode message that may have base64 fragments;
            // collapse to a constant label.
            UpstreamFetchError::ParseError("npm envelope encode/decode".into())
        }
    }
}

/// Map the pypi helper's coarse `IndexFetchError` to the typed
/// [`UpstreamFetchError`] taxonomy.
fn map_pypi_helper_error(e: &pypi_helpers::IndexFetchError) -> UpstreamFetchError {
    use pypi_helpers::IndexFetchError;
    match e {
        IndexFetchError::NoUpstream => UpstreamFetchError::NotFound,
        IndexFetchError::UpstreamUnavailable => {
            UpstreamFetchError::NetworkError("upstream fetch failed".into())
        }
        // Storage-backstop trip folds to a network-class failure on the
        // discovery path (same rationale as `map_npm_helper_error`).
        IndexFetchError::UpstreamBodyTooLarge { .. } => {
            UpstreamFetchError::NetworkError("upstream body too large".into())
        }
        // A malformed simple-index body is a parse-class failure (NOT
        // network); map to `ParseError` (sanitised constant — no body/URL
        // fragments).
        IndexFetchError::MetadataMalformed { .. } => {
            UpstreamFetchError::ParseError("pypi upstream simple-index malformed".into())
        }
        // A per-file-object cap trip is a parse-class failure (mirrors
        // npm's `VersionObjectTooLarge`).
        IndexFetchError::VersionObjectTooLarge { .. } => {
            UpstreamFetchError::ParseError("pypi upstream version object too large".into())
        }
        IndexFetchError::Internal(_) => {
            UpstreamFetchError::ParseError("pypi envelope encode/decode".into())
        }
    }
}

/// Map the cargo helper's coarse `IndexFetchError` to the typed
/// [`UpstreamFetchError`] taxonomy.
fn map_cargo_helper_error(e: &cargo_helpers::IndexFetchError) -> UpstreamFetchError {
    use cargo_helpers::IndexFetchError;
    match e {
        IndexFetchError::NoUpstream => UpstreamFetchError::NotFound,
        IndexFetchError::UpstreamUnavailable => {
            UpstreamFetchError::NetworkError("upstream fetch failed".into())
        }
        // A malformed sparse-index line is a parse-class failure (NOT
        // network); map to `ParseError` (sanitised constant — no body/URL
        // fragments).
        IndexFetchError::MetadataMalformed { .. } => {
            UpstreamFetchError::ParseError("cargo upstream sparse-index malformed".into())
        }
        IndexFetchError::Internal(_) => {
            UpstreamFetchError::ParseError("cargo envelope encode/decode".into())
        }
    }
}

// ---------------------------------------------------------------------------
// `PackumentFetchError` / `IndexFetchError` re-exports are NOT done; the
// helpers' coarse errors are deliberately internal to the per-format
// crates. The adapter consumes them through the per-format `pub` paths
// (e.g. `hort_http_npm::packument::PackumentFetchError`). If a future
// caller needs to discriminate the coarse helper errors, they should
// depend on the per-format crate directly — not on `hort-formats-upstream`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Unit tests for the dispatch table + error mapping.
    //!
    //! Coverage spans:
    //! - The dispatch table on `format`: happy path for each of npm /
    //!   pypi / cargo; OCI rejection; unknown-format rejection.
    //! - The error mapping: `NoUpstream` → `NotFound`,
    //!   `UpstreamUnavailable` → `NetworkError`, `Internal` →
    //!   `ParseError`. Each mapping has a dedicated unit test against
    //!   the small `map_*_helper_error` functions so the dispatch tests
    //!   only need to cover ONE error branch per format end-to-end
    //!   (the rest is exercised at the unit level).
    //! - The parse-side error mapping: a fixture body large enough to
    //!   trip the per-format byte cap drives
    //!   `extract_upstream_versions` into `DomainError::Validation`;
    //!   the adapter maps to `ParseError`.
    //! - The `upstream_name_prefix` invariant: `mapping.upstream_name_prefix
    //!   = Some("foo")` produces byte-identical version output as `None`
    //!   for each of the three non-OCI branches.

    use super::*;
    use chrono::Utc;
    use hort_domain::entities::managed_by::ManagedBy;
    // `FormatHandler` (`normalize_name` / `metadata_expected_max_bytes`) +
    // `NpmFormatHandler` / `PyPiFormatHandler` are now used only by tests
    // (every dispatcher derives versions from the typed projection); the
    // crate-level production `use`s were removed to avoid unused imports.
    use hort_domain::ports::format_handler::FormatHandler;
    use hort_domain::ports::repository_upstream_mapping_repository::UpstreamAuth;
    use hort_formats::npm::NpmFormatHandler;
    use hort_formats::pypi::PyPiFormatHandler;
    use uuid::Uuid;

    use hort_app::use_cases::test_support::{MockUpstreamProxy, MockUpstreamResolver};
    use hort_http_core::test_support::build_mock_ctx;
    use metrics_exporter_prometheus::PrometheusBuilder;

    /// Build a [`RepositoryUpstreamMapping`] for the given format
    /// (controls the simulated upstream URL only; the helpers ignore
    /// `format` themselves). `upstream_name_prefix` is the discriminator
    /// for the `upstream_name_prefix` invariant test.
    fn make_mapping(
        repo_id: Uuid,
        upstream_name_prefix: Option<String>,
    ) -> RepositoryUpstreamMapping {
        let now = Utc::now();
        RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            path_prefix: "".into(),
            upstream_url: "https://upstream.example".into(),
            upstream_name_prefix,
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

    /// Build an adapter wired to the same in-memory ports the
    /// `build_mock_ctx` harness uses. We don't actually need the
    /// constructed `AppContext` (the adapter never holds it) — we just
    /// reuse the harness's pre-wired ports so test setup is one line.
    /// Returns the adapter + a handle to the seedable mocks.
    fn build_adapter() -> (
        UpstreamMetadataAdapter,
        Arc<MockUpstreamResolver>,
        Arc<MockUpstreamProxy>,
    ) {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(metrics);

        // `AppContext` already holds the resolver / cache / upstream
        // proxy / pull-dedup we need; we take the same `Arc`s ("shared
        // dependency, two consumers" pattern. At runtime the composition
        // root passes these `Arc`s into both sides; here we mimic that by
        // reading from the test ctx.
        let resolver: Arc<dyn UpstreamResolver> = ctx.upstream_resolver.clone();
        let cache: Arc<dyn EphemeralStore> = ctx.ephemeral_evictable.clone();
        let upstream_proxy: Arc<dyn UpstreamProxy> = ctx.upstream_proxy.clone();
        let pull_dedup: Arc<PullDedup> = ctx.pull_dedup.clone();

        let adapter = UpstreamMetadataAdapter::new(resolver, cache, upstream_proxy, pull_dedup);
        // We also need typed handles to the mocks for seeding — the
        // `MockPorts` fields carry the concrete mock type already.
        (
            adapter,
            mocks.upstream_resolver.clone(),
            mocks.upstream_proxy.clone(),
        )
    }

    /// Seed `(resolver, upstream_proxy)` so the npm helper succeeds for
    /// `(repo_id, package)` with the given body.
    fn seed_npm(
        resolver: &MockUpstreamResolver,
        proxy: &MockUpstreamProxy,
        mapping: &RepositoryUpstreamMapping,
        package: &str,
        body: Vec<u8>,
    ) {
        resolver.insert(mapping.clone());
        // The npm helper builds path `/<encoded_name>` and passes it to
        // `fetch_metadata(mapping, path, vec![])`. The mock keys the
        // metadata table on `(path_prefix, path)` → bytes.
        proxy.insert_metadata("", &format!("/{package}"), body);
    }

    /// Seed `(resolver, upstream_proxy)` so the pypi helper succeeds for
    /// `(repo_id, package)` with the given body.
    fn seed_pypi(
        resolver: &MockUpstreamResolver,
        proxy: &MockUpstreamProxy,
        mapping: &RepositoryUpstreamMapping,
        package: &str,
        body: Vec<u8>,
    ) {
        resolver.insert(mapping.clone());
        // The PyPI helper normalises and uses `/simple/{normalized}/`.
        // The mock test bodies use already-normalised names; we
        // pre-normalise here to keep the seeding ergonomic.
        let normalized = PyPiFormatHandler.normalize_name(package);
        proxy.insert_metadata("", &format!("/simple/{normalized}/"), body);
    }

    /// Seed `(resolver, upstream_proxy)` so the cargo helper succeeds for
    /// `(repo_id, crate_name)` with the given body.
    fn seed_cargo(
        resolver: &MockUpstreamResolver,
        proxy: &MockUpstreamProxy,
        mapping: &RepositoryUpstreamMapping,
        crate_name: &str,
        body: Vec<u8>,
    ) {
        resolver.insert(mapping.clone());
        let path = hort_formats::cargo::index_path_for(crate_name);
        proxy.insert_metadata("", &format!("/{path}"), body);
    }

    // -----------------------------------------------------------------
    // Dispatch table — happy path per format
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn dispatch_npm_returns_parsed_version_set() {
        let (adapter, resolver, proxy) = build_adapter();
        let repo_id = Uuid::new_v4();
        let mapping = make_mapping(repo_id, None);
        let body = br#"{"name":"left-pad","versions":{"1.0.0":{},"1.1.0":{}}}"#.to_vec();
        seed_npm(&resolver, &proxy, &mapping, "left-pad", body);

        let mut got = adapter
            .list_versions("npm", &mapping, "left-pad")
            .await
            .expect("npm happy path must return Ok");
        got.sort();
        assert_eq!(got, vec!["1.0.0".to_string(), "1.1.0".to_string()]);
    }

    #[tokio::test]
    async fn dispatch_pypi_returns_parsed_version_set() {
        let (adapter, resolver, proxy) = build_adapter();
        let repo_id = Uuid::new_v4();
        let mapping = make_mapping(repo_id, None);
        // `dispatch_pypi` fetches the PEP 503 HTML simple-index and derives
        // versions from the projection's `files[]` filenames (via
        // `pypi_extract_version_from_filename`), not from a `versions[]`
        // array. Seed an HTML index whose anchors encode the two versions.
        let body = br#"<!DOCTYPE html><html><body>
            <a href="https://files.pythonhosted.org/x/requests-1.0.0-py3-none-any.whl#sha256=aa">requests-1.0.0-py3-none-any.whl</a>
            <a href="https://files.pythonhosted.org/x/requests-1.1.0.tar.gz#sha256=bb">requests-1.1.0.tar.gz</a>
            </body></html>"#.to_vec();
        seed_pypi(&resolver, &proxy, &mapping, "requests", body);

        let mut got = adapter
            .list_versions("pypi", &mapping, "requests")
            .await
            .expect("pypi happy path must return Ok");
        got.sort();
        assert_eq!(got, vec!["1.0.0".to_string(), "1.1.0".to_string()]);
    }

    #[tokio::test]
    async fn dispatch_cargo_returns_parsed_version_set() {
        let (adapter, resolver, proxy) = build_adapter();
        let repo_id = Uuid::new_v4();
        let mapping = make_mapping(repo_id, None);
        // NDJSON: one JSON object per line, each with a `vers` field.
        let body = b"{\"vers\":\"0.1.0\"}\n{\"vers\":\"0.2.0\"}\n".to_vec();
        seed_cargo(&resolver, &proxy, &mapping, "serde", body);

        let mut got = adapter
            .list_versions("cargo", &mapping, "serde")
            .await
            .expect("cargo happy path must return Ok");
        got.sort();
        assert_eq!(got, vec!["0.1.0".to_string(), "0.2.0".to_string()]);
    }

    // -----------------------------------------------------------------
    // Dispatch table — rejection paths (OCI + unknown format)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn dispatch_oci_returns_unsupported_format() {
        let (adapter, _, _) = build_adapter();
        let mapping = make_mapping(Uuid::new_v4(), None);

        let got = adapter
            .list_versions("oci", &mapping, "library/alpine")
            .await;
        assert_eq!(got, Err(UpstreamFetchError::UnsupportedFormat));
    }

    #[tokio::test]
    async fn dispatch_unknown_format_returns_unsupported_format() {
        let (adapter, _, _) = build_adapter();
        let mapping = make_mapping(Uuid::new_v4(), None);

        let got = adapter.list_versions("not-a-format", &mapping, "x").await;
        assert_eq!(got, Err(UpstreamFetchError::UnsupportedFormat));
    }

    #[tokio::test]
    async fn dispatch_empty_format_returns_unsupported_format() {
        let (adapter, _, _) = build_adapter();
        let mapping = make_mapping(Uuid::new_v4(), None);

        let got = adapter.list_versions("", &mapping, "x").await;
        assert_eq!(got, Err(UpstreamFetchError::UnsupportedFormat));
    }

    // -----------------------------------------------------------------
    // Error mapping — coarse helper-error variants (per-variant)
    // -----------------------------------------------------------------

    #[test]
    fn map_npm_helper_error_no_upstream_to_not_found() {
        let mapped = map_npm_helper_error(&npm_helpers::PackumentFetchError::NoUpstream);
        assert_eq!(mapped, UpstreamFetchError::NotFound);
    }

    #[test]
    fn map_npm_helper_error_unavailable_to_network_error_sanitised() {
        let mapped = map_npm_helper_error(&npm_helpers::PackumentFetchError::UpstreamUnavailable);
        match mapped {
            UpstreamFetchError::NetworkError(s) => {
                // Sanitisation contract — no URLs / hosts / package names.
                assert!(!s.contains("://"), "label must not contain a URL");
                assert!(
                    !s.contains("upstream.example"),
                    "label must not contain hostname"
                );
                // The label is a constant by construction; pin the exact text.
                assert_eq!(s, "upstream fetch failed");
            }
            other => panic!("expected NetworkError, got {other:?}"),
        }
    }

    #[test]
    fn map_npm_helper_error_internal_to_parse_error_sanitised() {
        let mapped = map_npm_helper_error(&npm_helpers::PackumentFetchError::Internal(
            // Carries upstream bytes (a base64 fragment) — the mapping
            // must NOT propagate this.
            "raw payload base64: AAAA".into(),
        ));
        match mapped {
            UpstreamFetchError::ParseError(s) => {
                assert!(!s.contains("AAAA"), "must not carry upstream bytes");
                assert_eq!(s, "npm envelope encode/decode");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn map_pypi_helper_error_no_upstream_to_not_found() {
        let mapped = map_pypi_helper_error(&pypi_helpers::IndexFetchError::NoUpstream);
        assert_eq!(mapped, UpstreamFetchError::NotFound);
    }

    #[test]
    fn map_pypi_helper_error_unavailable_to_network_error() {
        let mapped = map_pypi_helper_error(&pypi_helpers::IndexFetchError::UpstreamUnavailable);
        assert!(matches!(mapped, UpstreamFetchError::NetworkError(_)));
    }

    #[test]
    fn map_pypi_helper_error_internal_to_parse_error() {
        let mapped = map_pypi_helper_error(&pypi_helpers::IndexFetchError::Internal("x".into()));
        assert!(matches!(mapped, UpstreamFetchError::ParseError(_)));
    }

    #[test]
    fn map_cargo_helper_error_no_upstream_to_not_found() {
        let mapped = map_cargo_helper_error(&cargo_helpers::IndexFetchError::NoUpstream);
        assert_eq!(mapped, UpstreamFetchError::NotFound);
    }

    #[test]
    fn map_cargo_helper_error_unavailable_to_network_error() {
        let mapped = map_cargo_helper_error(&cargo_helpers::IndexFetchError::UpstreamUnavailable);
        assert!(matches!(mapped, UpstreamFetchError::NetworkError(_)));
    }

    #[test]
    fn map_cargo_helper_error_internal_to_parse_error() {
        let mapped = map_cargo_helper_error(&cargo_helpers::IndexFetchError::Internal("x".into()));
        assert!(matches!(mapped, UpstreamFetchError::ParseError(_)));
    }

    // -----------------------------------------------------------------
    // End-to-end error mapping through the dispatch table (one per
    // format to pin the dispatch → mapping wiring)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn dispatch_npm_no_mapping_returns_not_found() {
        let (adapter, _, _) = build_adapter();
        // No resolver insert → helper returns NoUpstream → adapter
        // maps to NotFound.
        let mapping = make_mapping(Uuid::new_v4(), None);

        let got = adapter.list_versions("npm", &mapping, "left-pad").await;
        assert_eq!(got, Err(UpstreamFetchError::NotFound));
    }

    #[tokio::test]
    async fn dispatch_pypi_no_mapping_returns_not_found() {
        let (adapter, _, _) = build_adapter();
        let mapping = make_mapping(Uuid::new_v4(), None);

        let got = adapter.list_versions("pypi", &mapping, "requests").await;
        assert_eq!(got, Err(UpstreamFetchError::NotFound));
    }

    #[tokio::test]
    async fn dispatch_cargo_no_mapping_returns_not_found() {
        let (adapter, _, _) = build_adapter();
        let mapping = make_mapping(Uuid::new_v4(), None);

        let got = adapter.list_versions("cargo", &mapping, "serde").await;
        assert_eq!(got, Err(UpstreamFetchError::NotFound));
    }

    #[tokio::test]
    async fn dispatch_npm_upstream_5xx_returns_network_error() {
        let (adapter, resolver, proxy) = build_adapter();
        let mapping = make_mapping(Uuid::new_v4(), None);
        resolver.insert(mapping.clone());
        // No seeded metadata for `/express` AND a failure injected →
        // upstream-proxy mock returns DomainError → helper's
        // UpstreamUnavailable → adapter's NetworkError.
        proxy.fail_next_metadata_with(hort_domain::error::DomainError::Invariant(
            "upstream:upstream_5xx:simulated".into(),
        ));

        let got = adapter.list_versions("npm", &mapping, "express").await;
        assert!(matches!(got, Err(UpstreamFetchError::NetworkError(_))));
    }

    // -----------------------------------------------------------------
    // Parse-side error mapping (ParseError variant)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn dispatch_npm_malformed_body_returns_parse_error() {
        let (adapter, resolver, proxy) = build_adapter();
        let mapping = make_mapping(Uuid::new_v4(), None);
        // The npm helper streams the body through the projector
        // (`fetch_and_project`/`project_cached`). A body that is not valid
        // JSON fails the projection (fail-closed) and maps to `ParseError`
        // — NOT the network bucket. A large non-JSON blob doubles as the
        // cap / over-size case.
        let max = NpmFormatHandler.metadata_expected_max_bytes();
        let body = vec![b'a'; max + 1];
        seed_npm(&resolver, &proxy, &mapping, "left-pad", body);

        let got = adapter.list_versions("npm", &mapping, "left-pad").await;
        match got {
            Err(UpstreamFetchError::ParseError(s)) => {
                // Sanitisation contract — the label MUST NOT carry
                // upstream content (URL, host, package name, payload
                // bytes). The constant label is the stage label by
                // construction; assert it does NOT contain the package
                // name `"left-pad"` or any upstream URL fragment.
                assert!(!s.contains("left-pad"), "must not carry package name");
                assert!(!s.contains("://"), "must not carry URL fragment");
                assert!(!s.contains("upstream.example"), "must not carry hostname");
                assert_eq!(s, "npm upstream packument malformed");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_pypi_malformed_body_returns_parse_error() {
        let (adapter, resolver, proxy) = build_adapter();
        let mapping = make_mapping(Uuid::new_v4(), None);
        // The pypi helper streams the HTML simple-index body through the
        // `HtmlSimpleIndexProjector`. A non-UTF-8 body fails the projection
        // (fail-closed) and maps to `ParseError` — NOT the network bucket.
        let body = vec![0xff, 0xfe, 0x00, 0x01];
        seed_pypi(&resolver, &proxy, &mapping, "requests", body);

        let got = adapter.list_versions("pypi", &mapping, "requests").await;
        match got {
            Err(UpstreamFetchError::ParseError(s)) => {
                // Sanitisation contract — the label MUST NOT carry upstream
                // content (package name / URL / host).
                assert!(!s.contains("requests"), "must not carry package name");
                assert!(!s.contains("://"), "must not carry URL fragment");
                assert!(!s.contains("upstream.example"), "must not carry hostname");
                assert_eq!(s, "pypi upstream simple-index malformed");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    // The `map_parse_result_*` tests were removed with the
    // `map_parse_result` helper they covered (no production caller remains;
    // all three dispatchers derive versions from the typed projection).

    // -----------------------------------------------------------------
    // `upstream_name_prefix` invariant — MUST NOT influence npm / pypi /
    // cargo URL composition (the field is OCI-effective-only).
    // See `docs/architecture/how-to/declare-gitops-config.md`.
    // -----------------------------------------------------------------

    /// Helper: run the npm dispatch twice — once with
    /// `upstream_name_prefix = None`, once with `Some("foo")` — and
    /// assert byte-identical version output. Both runs hit the same
    /// upstream seed (keyed on the request path); if the field were
    /// being consumed, the second run would build a different URL and
    /// the seed would miss.
    #[tokio::test]
    async fn upstream_name_prefix_is_inert_npm() {
        let (adapter, resolver, proxy) = build_adapter();
        // Same repo_id across both mappings so the helper resolves to
        // the same row regardless of prefix.
        let repo_id = Uuid::new_v4();
        let mapping_none = make_mapping(repo_id, None);
        let body = br#"{"versions":{"1.0.0":{}}}"#.to_vec();
        seed_npm(&resolver, &proxy, &mapping_none, "left-pad", body);

        let got_none = adapter
            .list_versions("npm", &mapping_none, "left-pad")
            .await
            .expect("npm with prefix=None must succeed");

        // Reseat the mapping with a non-None prefix; the resolver mock
        // keeps the SAME `mapping.id` rowing so the helper still
        // resolves. The test asserts that the (non-OCI) dispatch
        // branch produces the same URL the seed is on, irrespective of
        // `upstream_name_prefix`.
        let mut mapping_some = mapping_none.clone();
        mapping_some.upstream_name_prefix = Some("foo".into());
        // Re-insert with the same id so the resolver's longest-prefix
        // lookup returns the new row.
        resolver.insert(mapping_some.clone());

        let got_some = adapter
            .list_versions("npm", &mapping_some, "left-pad")
            .await
            .expect("npm with prefix=Some(\"foo\") must produce IDENTICAL output");

        assert_eq!(
            got_none, got_some,
            "upstream_name_prefix is OCI-effective-only: npm versions must be identical"
        );
    }

    #[tokio::test]
    async fn upstream_name_prefix_is_inert_pypi() {
        let (adapter, resolver, proxy) = build_adapter();
        let repo_id = Uuid::new_v4();
        let mapping_none = make_mapping(repo_id, None);
        let body = br#"{"versions":["1.0.0"]}"#.to_vec();
        seed_pypi(&resolver, &proxy, &mapping_none, "requests", body);

        let got_none = adapter
            .list_versions("pypi", &mapping_none, "requests")
            .await
            .expect("pypi with prefix=None must succeed");

        let mut mapping_some = mapping_none.clone();
        mapping_some.upstream_name_prefix = Some("foo".into());
        resolver.insert(mapping_some.clone());

        let got_some = adapter
            .list_versions("pypi", &mapping_some, "requests")
            .await
            .expect("pypi with prefix=Some(\"foo\") must produce IDENTICAL output");

        assert_eq!(
            got_none, got_some,
            "upstream_name_prefix is OCI-effective-only: pypi versions must be identical"
        );
    }

    #[tokio::test]
    async fn upstream_name_prefix_is_inert_cargo() {
        let (adapter, resolver, proxy) = build_adapter();
        let repo_id = Uuid::new_v4();
        let mapping_none = make_mapping(repo_id, None);
        let body = b"{\"vers\":\"0.1.0\"}\n".to_vec();
        seed_cargo(&resolver, &proxy, &mapping_none, "serde", body);

        let got_none = adapter
            .list_versions("cargo", &mapping_none, "serde")
            .await
            .expect("cargo with prefix=None must succeed");

        let mut mapping_some = mapping_none.clone();
        mapping_some.upstream_name_prefix = Some("foo".into());
        resolver.insert(mapping_some.clone());

        let got_some = adapter
            .list_versions("cargo", &mapping_some, "serde")
            .await
            .expect("cargo with prefix=Some(\"foo\") must produce IDENTICAL output");

        assert_eq!(
            got_none, got_some,
            "upstream_name_prefix is OCI-effective-only: cargo versions must be identical"
        );
    }

    // -----------------------------------------------------------------
    // Adapter constructor — pins that the four `Arc<_>` fields are
    // accepted in the expected order. A future shuffle of the field
    // order is a compile-time break here.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn adapter_new_accepts_four_arcs_in_expected_order() {
        // We don't need the adapter to do anything — we just need it to
        // construct, holding the four Arcs the adapter expects.
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, _mocks) = build_mock_ctx(metrics);
        let resolver: Arc<dyn UpstreamResolver> = ctx.upstream_resolver.clone();
        let cache: Arc<dyn EphemeralStore> = ctx.ephemeral_evictable.clone();
        let upstream_proxy: Arc<dyn UpstreamProxy> = ctx.upstream_proxy.clone();
        let pull_dedup: Arc<PullDedup> = ctx.pull_dedup.clone();

        let adapter = UpstreamMetadataAdapter::new(resolver, cache, upstream_proxy, pull_dedup);

        // `Clone` is part of the public surface — the composition root
        // hands out `Arc<dyn UpstreamMetadataPort>` clones.
        let _cloned = adapter.clone();
    }

    // -----------------------------------------------------------------
    // Compile-time pin — the adapter MUST implement `UpstreamMetadataPort`
    // and be holdable as `Arc<dyn UpstreamMetadataPort>`. A future change
    // that breaks dyn-compatibility surfaces here at test build time, not
    // at the composition root.
    // -----------------------------------------------------------------

    #[test]
    fn adapter_is_dyn_upstream_metadata_port() {
        // Type-level dyn-compatibility check — no runtime work needed.
        // A future change that breaks dyn-compatibility surfaces here
        // at test build time, not at the composition root.
        fn _hold(a: Arc<UpstreamMetadataAdapter>) -> Arc<dyn UpstreamMetadataPort> {
            a
        }
        let _: fn(Arc<UpstreamMetadataAdapter>) -> Arc<dyn UpstreamMetadataPort> = _hold;
    }
}
