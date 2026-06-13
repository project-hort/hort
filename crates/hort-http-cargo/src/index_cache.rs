//! Cargo sparse-index pull-through cache (see ADR 0006).
//!
//! Adds Remote (`RepositoryType::Proxy`) repository support to the
//! sparse-index routes:
//!
//! 1. Cache check — read `cargo_index_proj:{mapping.id}:{prefix}/{name}`
//!    via [`EphemeralStore::get`](hort_domain::ports::ephemeral_store::EphemeralStore).
//!    Hit + within fresh window: return the cached **projection** (no
//!    re-parse); the unified pipeline renders it.
//! 2. Stale or miss → call [`UpstreamProxy::fetch_metadata`](
//!    hort_domain::ports::upstream_proxy::UpstreamProxy). On success the
//!    body streams through the [`CargoSparseIndexProjector`] (validate-
//!    before-commit) and into the
//!    [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store);
//!    the small projection is cached and served fresh. On failure, if a
//!    stale projection exists serve it; else re-project from the raw
//!    mirror (`stale-while-error` / air-gapped); else surface
//!    `UpstreamUnavailable` for the caller to wire-map to 502.
//!
//! # Cache contract (ADR 0026)
//!
//! The cargo proxy caches the small **projection** (`Vec<CargoVersionLine>`)
//! in Redis; the raw NDJSON body streams into the logical-keyed
//! [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store)
//! under `mirror_key("cargo", mapping_id, index_path_for(name))` (a
//! separate keyspace from artifact CAS). Serve renders the cached
//! projection with no re-parse; the raw mirror is the stale-while-error /
//! air-gapped fallback.
//!
//! [`crate::upstream_pull::try_upstream_crate_pull`] reads the same
//! cached projection: the `cksum` it carries is Cargo's verbatim
//! upstream checksum (ADR 0006) — exactly what the verified-ingest path
//! needs.
//!
//! # Cache key
//!
//! `cargo_index_proj:{mapping.id}:{prefix/name}` — the `_proj` suffix
//! versions the key for the amendment (a rolling deploy never has new
//! code read a pre-amendment `cargo_index:` entry whose payload is a
//! base64-JSON raw-body envelope, not a serialized projection). The
//! **mapping id** is the invalidation axis (Item 3 reasoning): an
//! upstream URL change rotates the mapping, which is exactly when stale
//! upstream-derived bytes should die. A repo rename keeps the mapping
//! intact and shouldn't churn the cache. `prefix/name` is the exact path
//! passed to `fetch_metadata` (with no leading slash) so the fetch leg
//! and cache leg key on identical strings, and matches the mirror key's
//! package segment.
//!
//! # Envelope encoding
//!
//! Compact binary frame `[version u8 = 1][fetched_at_ms i64 BE][
//! serde_json(Vec<CargoVersionLine>)]` (see [`CachedCargoProjection`]).
//! The payload is the serialized projection, not the raw body.
//!
//! # TTLs
//!
//! Per-crate sparse index: fresh window 60 s, backend window 1 h. The
//! backend window is the stale-while-error survival horizon — long
//! enough to ride a typical upstream outage, short enough that operators
//! re-bootstrapping a proxy don't carry yesterday's index forever.
//!
//! A per-repo TTL override would need a `repository_config`
//! accessor that does not yet exist, and inventing a new outbound port
//! for a nice-to-have is out of scope. Accept the global window until
//! such an accessor lands for another reason; do not add a port solely
//! for this.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;

use hort_app::error::AppError;
use hort_app::pull_dedup::{DedupKey, PullDedup};
// `CargoSemverOrdering` is a type alias on `NpmSemverOrdering` (cargo
// reuses the npm semver ordering helper); the unit-struct value used at
// instantiation is `NpmSemverOrdering`. The alias is still useful at
// the *type* level (e.g. function signatures that document the format
// intent), but the value-context constructor is the underlying struct.
use hort_app::use_cases::index_serve_filter::{CargoSemverOrdering, NpmSemverOrdering};
// Prefetch trigger planner. Called from `ProxyCargoSource::fetch` after
// the fetch; the use case decides which versions to pull-through-prefetch
// and emits the planning metrics. The format crate then spawns the
// per-version pull (`try_upstream_crate_pull`) per planned version;
// `PullDedup` inside the spawn handles concurrent dedup.
use hort_app::use_cases::prefetch_use_case::PrefetchPlan;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::{PrefetchTrigger, Repository};
use hort_domain::error::DomainError;
use hort_domain::ports::ephemeral_store::EphemeralStore;
// The raw upstream NDJSON streams into the logical-keyed mirror; only
// the small projection lands in Redis (ADR 0026).
use hort_domain::ports::metadata_mirror_store::{mirror_key, MetadataMirrorStore};
use hort_domain::ports::upstream_proxy::{MetadataProjector, UpstreamProxy};
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_formats::cargo::projection::{CargoSparseIndexProjector, CargoVersionLine};
use hort_http_core::cache_envelope::CachedProjection;
use hort_http_core::context::AppContext;

/// Fresh-window TTL — within this window since `fetched_at`, the
/// cache entry is served without an upstream round-trip.
pub const CARGO_INDEX_FRESH_TTL: Duration = Duration::from_secs(60);

/// Backend-storage TTL — past this the entry expires entirely and a
/// follow-on miss forces a fresh upstream fetch. Must be `>` the fresh
/// window or `stale-while-error` has nothing to fall back on.
pub const CARGO_INDEX_STALE_TTL: Duration = Duration::from_secs(60 * 60);

/// Cached upstream sparse-index **projection** (see ADR 0026).
///
/// The cargo proxy caches the small projection (`Vec<CargoVersionLine>`)
/// in Redis and streams the raw body into the
/// [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store) —
/// serve renders the cached projection with no re-parse; the raw mirror
/// is the stale-while-error / air-gapped fallback.
///
/// This is the shared generic
/// [`CachedProjection<Vec<CargoVersionLine>>`](hort_http_core::cache_envelope::CachedProjection).
/// Wire frame:
///
///   ```text
///   [ version u8 = 1 ][ fetched_at_millis i64 BE ][ serde_json(Vec<CargoVersionLine>) ]
///   ```
///
/// The projection carries `cksum` per version (Cargo's verbatim upstream
/// checksum, ADR 0006), so the tarball-pull orchestrator
/// ([`crate::upstream_pull`]) recovers the genuine checksum from the
/// cached projection — no raw body required.
pub(crate) type CachedCargoProjection = CachedProjection<Vec<CargoVersionLine>>;

/// Discriminated failure modes for [`fetch_raw_with_cache`]. Wire mapping
/// (HTTP status + envelope body) is performed by the caller in
/// `lib.rs` / `serve.rs`:
///
/// - `NoUpstream` → 404 (cargo's "crate doesn't exist" semantic for a
///   Proxy repo with no upstream mapping).
/// - `UpstreamUnavailable` → 502 (the only fail leg with no cache to
///   fall back on; emitted only when the cache also missed).
/// - `MetadataMalformed` → 502/`parse_error` — a malformed upstream body
///   is a content fault, NOT an outage; it must NOT land in the
///   `UpstreamUnavailable` network bucket.
/// - `Internal` → 500 (cache infrastructure failures that aren't
///   upstream-attributable).
///
/// `pub` visibility exists for the `hort-formats-upstream` composition
/// seam only — do not pattern-match from outside `hort-http-cargo`
/// in-crate code OR `hort-formats-upstream`. A fourth caller breaks the
/// dep-graph rationale (ADR 0008).
#[derive(Debug, thiserror::Error)]
pub enum IndexFetchError {
    #[error("no upstream mapping configured")]
    NoUpstream,
    #[error("upstream unavailable")]
    UpstreamUnavailable,
    /// The upstream sparse-index failed to parse / project (a malformed
    /// NDJSON line). Fail-closed: nothing was cached or mirrored.
    /// Surfaces as `parse_error` (a 4xx/502 parse-class), NEVER the
    /// `UpstreamUnavailable` network bucket — a malformed body is a
    /// content fault, not an outage.
    #[error("upstream sparse-index malformed: {cause}")]
    MetadataMalformed { cause: String },
    #[error("internal: {0}")]
    Internal(String),
}

/// Pull-through fetch of the upstream Cargo sparse-index as a streamed
/// **projection**, with `EphemeralStore`-backed caching of the
/// projection and the raw body streamed into the
/// [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store).
///
/// On a cache miss/stale the upstream body streams (no full-body `Vec`)
/// through [`CargoSparseIndexProjector`] into a small
/// `Vec<CargoVersionLine>`; the raw body streams into the mirror under
/// `mirror_key("cargo", mapping_id, path)` (valid bodies only —
/// validate-before-commit); the projection is cached in Redis under the
/// `cargo_index_proj:` prefix. Serve renders the cached projection with
/// no re-parse; the raw mirror is the stale-while-error / air-gapped
/// fallback (ADR 0026).
///
/// `mirror` is `Option` so the low-frequency `hort-formats-upstream`
/// discovery seam (version-listing only) can pass `None` — it does not
/// serve, so it has no mirror and no stale-while-error need. In-crate
/// serve / tarball-pull callers pass
/// `Some(ctx.metadata_mirror.as_ref())`.
///
/// The projection carries each version's verbatim `cksum` (Cargo's
/// upstream checksum, ADR 0006), so
/// [`crate::upstream_pull::try_upstream_crate_pull`] recovers it from
/// the cached projection — its reader/writer contract rides the
/// projection cache.
///
/// # Composition-seam visibility
///
/// `pub` visibility exists for the `hort-formats-upstream` composition
/// seam only — do not call from outside `hort-http-cargo` in-crate code
/// OR `hort-formats-upstream`. A fourth caller breaks the dep-graph
/// rationale (ADR 0008). See
/// `docs/architecture/how-to/add-a-format-handler.md` for the
/// supported integration points.
///
/// The helper takes explicit `&dyn UpstreamResolver` + `&dyn
/// EphemeralStore` + `&dyn UpstreamProxy` + `&PullDedup` (+ the optional
/// mirror) deps rather than `&Arc<AppContext>` because
/// `hort-formats-upstream`'s adapter cannot hold `Arc<AppContext>` (a
/// construction cycle).
#[tracing::instrument(
    skip(resolver, cache, upstream_proxy, pull_dedup, mirror),
    fields(repo_key = %repo.key, crate_name)
)]
pub async fn fetch_raw_with_cache(
    resolver: &dyn UpstreamResolver,
    cache: &dyn EphemeralStore,
    upstream_proxy: &dyn UpstreamProxy,
    pull_dedup: &PullDedup,
    mirror: Option<&dyn MetadataMirrorStore>,
    repo: &Repository,
    crate_name: &str,
) -> Result<Vec<CargoVersionLine>, IndexFetchError> {
    let Some((mapping, _stripped)) = resolver.resolve(repo.id, "") else {
        tracing::warn!("Cargo proxy repository has no upstream mapping configured");
        return Err(IndexFetchError::NoUpstream);
    };

    // The path the upstream sees AND the suffix of the cache key.
    // `index_path_for` already lowercases — same shape Item 3 uses for
    // `upstream_checksum_metadata_path`, so a Proxy serving `Foo` and
    // `foo` collapses to a single cache row.
    let path = hort_formats::cargo::index_path_for(crate_name);
    // `cargo_index_proj:` prefix: the entry holds the small PROJECTION,
    // not the raw body. The prefix versions the key so a rolling deploy
    // never reads a stale base64-JSON raw-body envelope.
    let key = format!("cargo_index_proj:{}:{}", mapping.id, path);
    // The raw body's home is the logical-keyed mirror (separate keyspace
    // from artifact CAS). The `path` package segment matches the Redis
    // cache key's segment so prefetch / serve / tarball-pull all compute
    // the same mirror key for the same crate.
    let mkey = mirror_key("cargo", &mapping.id.to_string(), &path);

    let cached_raw = cache
        .get(&key)
        .await
        .map_err(|e| IndexFetchError::Internal(e.to_string()))?;

    // Decode the cached projection if present. A decode failure is
    // treated as a miss + warn: cache poisoning (e.g. a pre-amendment
    // base64-JSON envelope on a rolling deploy) shouldn't wedge a Proxy;
    // the cold-cache event resolves naturally via the upstream fetch.
    let stale_entry: Option<CachedCargoProjection> =
        cached_raw.and_then(|raw| match CachedCargoProjection::decode(&raw) {
            Some(env) => Some(env),
            None => {
                tracing::warn!(
                    bytes = raw.len(),
                    "Cargo index projection cache entry decode failed; treating as miss \
                     (rolling-deploy from a pre-amendment raw-body envelope is the expected cause)"
                );
                None
            }
        });

    // Fresh-cache hit: return the cached projection immediately, no
    // upstream call, no re-parse.
    let now = Utc::now();
    if let Some(env) = stale_entry.as_ref() {
        if env.is_fresh(now, CARGO_INDEX_FRESH_TTL) {
            return Ok(env.projection.clone());
        }
    }

    // Either fully missing or stale — try upstream. Wrap the fetch in
    // `PullDedup::coalesce_metadata` so N parallel index misses for the
    // same crate produce ≤ 1 upstream call. The closure streams the body
    // through the projector + mirror (`fetch_and_project`) and returns
    // the SERIALIZED projection bytes so followers receive the small
    // projection (not the raw NDJSON body) — keeping the dedup window's
    // payload bounded by the projection size.
    let upstream_path = format!("/{path}");
    let dedup_key = DedupKey::metadata("cargo", repo.id, &upstream_path);
    let mapping_for_closure = mapping.clone();
    let upstream_path_for_closure = upstream_path.clone();
    let mkey_for_closure = mkey.clone();
    let coalesce_result = pull_dedup
        .coalesce_metadata(dedup_key, move || async move {
            let outcome = upstream_proxy
                .fetch_metadata(mapping_for_closure, upstream_path_for_closure, Vec::new())
                .await
                .map_err(AppError::from)?;
            let handle = outcome.cache_handle.as_ref().ok_or_else(|| {
                AppError::from(DomainError::Invariant(
                    "cargo fetch_metadata returned no cache_handle".to_string(),
                ))
            })?;
            // PASS 1 validate/project (a malformed NDJSON line ⇒ Err,
            // nothing committed — the cargo projector is fail-closed,
            // Task 5); PASS 2 streams the raw body into the mirror (valid
            // only) iff a mirror was supplied. No full-body Vec.
            let projection = match mirror {
                Some(m) => hort_app::project::fetch_and_project(
                    handle,
                    CargoSparseIndexProjector::new(),
                    m,
                    &mkey_for_closure,
                )
                .await
                .map_err(AppError::from)?,
                None => hort_app::project::project_cached(handle, CargoSparseIndexProjector::new())
                    .await
                    .map_err(AppError::from)?,
            };
            // Best-effort tempfile cleanup (the consumer owns the
            // lifecycle, mirroring the retired `metadata_body_bytes`).
            if let Err(e) = tokio::fs::remove_file(&handle.path).await {
                tracing::debug!(
                    path = %handle.path.display(),
                    error = %e,
                    "cargo index tempfile cleanup failed (non-fatal)"
                );
            }
            // Followers receive the serialized projection (small).
            let json = serde_json::to_vec(&projection).map_err(|e| {
                AppError::from(DomainError::Invariant(format!(
                    "cargo projection serialize: {e}"
                )))
            })?;
            Ok(Bytes::from(json))
        })
        .await;
    match coalesce_result {
        Ok(json) => {
            // Deserialize the projection the coalesce produced (leader's
            // own projection, or a follower's copy of the leader's).
            let projection: Vec<CargoVersionLine> = serde_json::from_slice(&json).map_err(|e| {
                IndexFetchError::Internal(format!("cargo projection deserialize: {e}"))
            })?;
            // Cache the small projection (not the raw body). Cache-write
            // failures are non-fatal (we already have the projection to
            // return).
            let entry = CachedCargoProjection::from_projection(projection.clone());
            if let Err(e) = cache.put(&key, entry.encode(), CARGO_INDEX_STALE_TTL).await {
                tracing::warn!(error = %e, "Cargo index projection cache write failed (non-fatal)");
            }
            tracing::info!(
                versions = projection.len(),
                "Cargo sparse-index upstream fetch succeeded; cached projection, raw to mirror",
            );
            Ok(projection)
        }
        Err(e) => {
            // Classify BEFORE the stale fallback. A malformed body is a
            // PARSE failure, not an outage: it must surface as
            // `parse_error`, fail-closed (nothing cached), and must NOT
            // be masked by serving a stale projection (stale-while-error
            // is for genuine upstream unavailability only). The cargo
            // projector raises `DomainError::Validation` on a malformed
            // NDJSON line, which `fetch_and_project` propagates; followers
            // see the leader's wrapped error (not `Validation`) and fall
            // through to `UpstreamUnavailable` — leader-only
            // discrimination (see `PullDedup` §coalesce contract).
            if let AppError::Domain(DomainError::Validation(msg)) = &e {
                tracing::warn!(cause = %msg, "cargo upstream sparse-index malformed (parse_error)");
                return Err(IndexFetchError::MetadataMalformed { cause: msg.clone() });
            }
            tracing::warn!(error = %e, "Cargo upstream sparse-index fetch failed");
            // Stale-while-error: prefer a stale projection over a 502.
            if let Some(env) = stale_entry {
                tracing::warn!(
                    stale_age_secs = now.signed_duration_since(env.fetched_at).num_seconds(),
                    "Cargo upstream fetch failed; serving stale projection cache entry",
                );
                return Ok(env.projection);
            }
            // No stale projection in Redis — re-project from the raw
            // mirror if present (replaces the pre-amendment stale-Redis-
            // raw fallback). The mirror is the air-gapped / outage
            // source; re-projecting avoids an upstream re-fetch.
            if let Some(m) = mirror {
                if let Ok(Some(reader)) = m.get(&mkey).await {
                    match project_from_mirror(reader).await {
                        Ok(projection) => {
                            tracing::info!(
                                versions = projection.len(),
                                "Cargo upstream fetch failed; re-projected stale body from mirror",
                            );
                            return Ok(projection);
                        }
                        Err(perr) => {
                            tracing::warn!(
                                error = %perr,
                                "cargo mirror re-projection failed; falling through to upstream error",
                            );
                        }
                    }
                }
            }
            Err(IndexFetchError::UpstreamUnavailable)
        }
    }
}

/// Re-project a raw sparse-index body from the metadata mirror through
/// the streaming projector. Used **only** on the stale-while-error /
/// air-gapped fallback path (§4) — off the hot serve path, which never
/// reads the mirror (it renders the cached projection). The mirror
/// reader is read into a buffer here and projected via `Cursor`: the
/// sync `MetadataProjector` (`R: std::io::Read`) cannot take an
/// `AsyncRead` directly, and `tokio-util`'s `SyncIoBridge` needs the
/// `io-util` feature (not enabled workspace-wide). A transient buffer on
/// this cold outage path is acceptable — it mirrors what the
/// pre-amendment stale fallback already held; the hot-path memory bound
/// (the point of the amendment) is unaffected.
async fn project_from_mirror(
    mut reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
) -> Result<Vec<CargoVersionLine>, DomainError> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .await
        .map_err(|e| DomainError::Invariant(format!("cargo mirror read: {e}")))?;
    tokio::task::spawn_blocking(move || {
        CargoSparseIndexProjector::new().project(std::io::Cursor::new(buf))
    })
    .await
    .map_err(|e| DomainError::Invariant(format!("cargo mirror re-projection task panicked: {e}")))?
}

// ---------------------------------------------------------------------------
// Prefetch trigger wiring (see docs/architecture/explanation/prefetch-pipeline.md)
// ---------------------------------------------------------------------------

// The legacy `apply_quarantine_filter` and `apply_filter_and_fire_prefetch`
// helpers were removed when the unified Source → Filter → Builder pipeline
// absorbed the filter step via `NonServableStatusFilter` + `IndexModeFilter`
// post-source. The prefetch trigger (`fire_prefetch_trigger_cargo`, below)
// fires from `ProxyCargoSource::fetch` after the fetch.

/// Best-effort prefetch trigger for a Cargo sparse-index serve.
///
/// Consumes the already-computed projection (the consumer projected the
/// body once via `fetch_raw_with_cache`; re-projecting a synthetic body
/// here would be wasteful and re-introduce a parse). The shared
/// `fire_hot_path_trigger` parser closure has a fixed
/// `FnOnce(&[u8]) -> (Vec<String>, Option<String>)` shape, so we
/// pre-compute the version list from the projection and hand it back
/// from a closure that ignores the (empty) body argument.
///
/// **`OnDistTagMove` semantics for cargo.** Cargo's sparse-index has no
/// native `dist-tags`; the analogue is the upstream's newest version (the
/// implicit "latest" any unconstrained `cargo install` resolves to). The
/// helper synthesises this via `max_by(CargoSemverOrdering)` over the
/// parsed version set when the parser returns `None` for the second tuple
/// element — exactly the shape cargo needs.
pub(crate) fn fire_prefetch_trigger_cargo(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    crate_name: &str,
    projection: &[CargoVersionLine],
    pkg_status: &[(String, QuarantineStatus)],
) {
    let ordering: CargoSemverOrdering = NpmSemverOrdering;
    let versions: Vec<String> = projection.iter().map(|l| l.vers.clone()).collect();
    hort_app::use_cases::prefetch_trigger::fire_hot_path_trigger(
        ctx,
        &ctx.prefetch_use_case,
        repo,
        crate_name,
        &[],
        pkg_status,
        &ordering,
        "cargo",
        move |_body: &[u8]| (versions, None),
        spawn_prefetch_for_versions,
    );
}

// The standalone `parse_ndjson_for_versions` helper was retired:
// `fire_prefetch_trigger_cargo` now receives the already-computed
// projection and passes its version list into the shared trigger
// directly, so there is no second projection pass.

/// Spawn one background [`try_upstream_crate_pull`] per planned
/// version. Each spawn rides through the `PullDedup` inside the pull
/// function, so concurrent prefetches (e.g. the same version being
/// warmed by both `OnIndexFetch` and a racing client pull) collapse to
/// a single upstream fetch.
///
/// `tokio::spawn` is the deliberate choice for the hot-path triggers
/// (a DB-backed job row per serve is exactly the churn the prefetch
/// design warns against). The `scheduled` trigger is the DB-backed
/// path.
fn spawn_prefetch_for_versions(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    crate_name: &str,
    plan: PrefetchPlan,
    trigger: PrefetchTrigger,
) {
    if plan.is_empty() {
        return;
    }
    for version in plan.versions {
        let ctx = ctx.clone();
        let repo = repo.clone();
        let crate_name = crate_name.to_string();
        let trigger_str = trigger.to_string();
        tokio::spawn(async move {
            match crate::upstream_pull::try_upstream_crate_pull(&ctx, &repo, &crate_name, &version)
                .await
            {
                Ok(_) => {
                    tracing::info!(
                        format = "cargo",
                        repository_key = %repo.key,
                        crate_name = %crate_name,
                        version = %version,
                        trigger = %trigger_str,
                        "prefetch pull-through succeeded",
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        format = "cargo",
                        repository_key = %repo.key,
                        crate_name = %crate_name,
                        version = %version,
                        trigger = %trigger_str,
                        error = ?e,
                        "prefetch pull-through failed (non-fatal)",
                    );
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// The cache holds the small PROJECTION (`Vec<CargoVersionLine>`, not the raw
// NDJSON body) and the raw body streams into the mirror. The tests below
// pin: (a) the projection-frame round-trip + rolling-deploy decode rejection;
// (b) cache miss → projection cached + raw mirrored; (c) a malformed upstream
// NDJSON line fails closed and maps to `parse_error` (NOT the network bucket);
// (d) fresh-hit serves the cached projection with no upstream call;
// (e) stale-while-error serves a stale projection / re-projects from the
// mirror.

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use uuid::Uuid;

    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{RepositoryFormat, RepositoryType};
    use hort_domain::ports::ephemeral_store::EphemeralStore;
    use hort_domain::ports::metadata_mirror_store::MetadataMirrorStore as _;
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    // The frame version byte lives on the shared generic envelope;
    // `read_mirror` is the shared helper in
    // `hort_http_core::test_support` (the npm / cargo / pypi copies
    // are byte-identical).
    use hort_http_core::cache_envelope::CACHE_FORMAT_VERSION;
    use hort_http_core::test_support::{build_mock_ctx, read_mirror, MockPorts};

    use hort_app::use_cases::test_support::sample_repository;

    use super::*;

    fn handle() -> metrics_exporter_prometheus::PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    fn proxy_cargo_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Cargo;
        r.repo_type = RepositoryType::Proxy;
        r
    }

    fn seed_mapping(mocks: &MockPorts, repo_id: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        let now = Utc::now();
        mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
            id,
            repository_id: repo_id,
            path_prefix: String::new(),
            upstream_url: "https://crates.io".into(),
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
        });
        id
    }

    /// One-line NDJSON entry whose `cksum` is `cksum`.
    fn ndjson_entry(name: &str, version: &str, cksum: &str) -> Vec<u8> {
        format!(
            r#"{{"name":"{name}","vers":"{version}","deps":[],"cksum":"{cksum}","features":{{}},"yanked":false}}"#
        )
        .into_bytes()
    }

    fn sample_projection() -> Vec<CargoVersionLine> {
        CargoSparseIndexProjector::new()
            .project(std::io::Cursor::new(ndjson_entry(
                "serde", "1.0.0", "abc123",
            )))
            .expect("sample body must project")
    }

    #[test]
    fn cached_projection_frame_round_trips() {
        let p = sample_projection();
        let entry = CachedCargoProjection::from_projection(p);
        let encoded = entry.encode();
        let decoded = CachedCargoProjection::decode(&encoded).expect("decode");
        assert_eq!(decoded.projection.len(), 1);
        assert_eq!(decoded.projection[0].vers, "1.0.0");
        // `cksum` is Cargo's verbatim upstream checksum (ADR 0006)
        // and MUST round-trip through the cache frame unchanged.
        assert_eq!(decoded.projection[0].cksum, "abc123");
        assert_eq!(
            decoded.fetched_at.timestamp_millis(),
            entry.fetched_at.timestamp_millis()
        );
    }

    #[test]
    fn cached_projection_decode_rejects_pre_amendment_and_short_frames() {
        // Pre-amendment base64-JSON `IndexEnvelope`: first byte `{` ≠
        // version 1 → decode `None` (rolling-deploy cold-cache).
        let legacy = br#"{"body":"abc","fetched_at":"2024-01-01T00:00:00Z"}"#;
        assert!(CachedCargoProjection::decode(legacy).is_none());

        // A valid header byte but a payload that cannot be a
        // `Vec<CargoVersionLine>` (a JSON object, not an array) → None.
        let mut bad_payload = vec![CACHE_FORMAT_VERSION];
        bad_payload.extend_from_slice(&0i64.to_be_bytes());
        bad_payload.extend_from_slice(br#"{"not":"an array"}"#);
        assert!(CachedCargoProjection::decode(&bad_payload).is_none());

        // Too-short input (< 9-byte header) collapses to a miss.
        assert!(CachedCargoProjection::decode(&[]).is_none());
        assert!(CachedCargoProjection::decode(&[1, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    /// (a) Cache miss + valid upstream → the PROJECTION is returned and
    /// cached (NOT the raw body), AND the raw body is mirrored under
    /// `mirror_key("cargo", mapping_id, path)`.
    #[tokio::test]
    async fn fetch_caches_projection_and_mirrors_raw_not_redis_raw() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        let upstream = ndjson_entry("serde", "1.0.0", "deadbeef");
        let path = hort_formats::cargo::index_path_for("serde");
        mocks
            .upstream_proxy
            .insert_metadata("", &format!("/{path}"), upstream.clone());

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            &repo,
            "serde",
        )
        .await
        .expect("fetch must succeed on upstream-200");
        assert_eq!(projection.len(), 1);
        assert_eq!(projection[0].vers, "1.0.0");
        assert_eq!(projection[0].cksum, "deadbeef");

        // Redis holds the PROJECTION frame (decodes as CachedCargoProjection,
        // NOT the raw body).
        let cache_key = format!("cargo_index_proj:{mapping_id}:{path}");
        let cached = mocks
            .ephemeral_evictable
            .get(&cache_key)
            .await
            .unwrap()
            .expect("projection cache must be populated");
        let env = CachedCargoProjection::decode(&cached).expect("projection frame decode");
        assert_eq!(env.projection[0].cksum, "deadbeef");

        // The mirror holds the RAW body under the format-scoped key.
        let mkey = mirror_key("cargo", &mapping_id.to_string(), &path);
        assert!(
            mocks.metadata_mirror.keys().contains(&mkey),
            "mirror must hold the raw body under {mkey}; got {:?}",
            mocks.metadata_mirror.keys()
        );
        let raw = read_mirror(&mocks, &mkey)
            .await
            .expect("mirror raw must be present");
        assert_eq!(raw, upstream, "mirror must hold the verbatim raw body");
    }

    /// (b) A malformed upstream NDJSON line fails closed: rejects with a
    /// parse-class error (MetadataMalformed — maps to `parse_error`, NOT
    /// the `UpstreamUnavailable` network bucket), and neither Redis nor
    /// the mirror is written.
    #[tokio::test]
    async fn malformed_upstream_maps_to_parse_error_not_network_error() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // line1 ok, line2 malformed → the cargo projector fails closed
        // (Task 5 reject-on-invalid).
        let body =
            b"{\"name\":\"serde\",\"vers\":\"1.0.0\",\"cksum\":\"x\"}\nnot json at all\n".to_vec();
        let path = hort_formats::cargo::index_path_for("serde");
        mocks
            .upstream_proxy
            .insert_metadata("", &format!("/{path}"), body);

        let err = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            &repo,
            "serde",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, IndexFetchError::MetadataMalformed { .. }),
            "malformed body must be parse-class, NOT network/unavailable; got {err:?}"
        );

        // Fail-closed: nothing cached, nothing mirrored.
        let cache_key = format!("cargo_index_proj:{mapping_id}:{path}");
        assert!(
            mocks
                .ephemeral_evictable
                .get(&cache_key)
                .await
                .unwrap()
                .is_none(),
            "a malformed body must NOT write the projection cache"
        );
        assert!(
            mocks.metadata_mirror.keys().is_empty(),
            "a malformed body must NOT write the mirror (validate-before-commit)"
        );
    }

    /// Cache miss + upstream 5xx with no stale fallback → UpstreamUnavailable
    /// (the genuine-outage bucket, distinct from the parse_error class above).
    #[tokio::test]
    async fn fetch_miss_upstream_error_returns_unavailable() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);
        // No metadata seeded → mock fetch_metadata returns an error.

        let err = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            &repo,
            "serde",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, IndexFetchError::UpstreamUnavailable),
            "expected UpstreamUnavailable, got {err:?}"
        );
    }

    /// (d) Fresh projection-cache hit → returns the cached projection,
    /// no upstream call, no mirror read. The seeded upstream is different
    /// so a broken fresh-check surfaces as a mismatch.
    #[tokio::test]
    async fn fetch_fresh_hit_serves_cached_projection_no_upstream_call() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        let path = hort_formats::cargo::index_path_for("serde");
        let entry = CachedCargoProjection::from_projection(sample_projection());
        let key = format!("cargo_index_proj:{mapping_id}:{path}");
        mocks
            .ephemeral_evictable
            .put(&key, entry.encode(), CARGO_INDEX_STALE_TTL)
            .await
            .unwrap();

        // Seed a DIFFERENT upstream — would-be evidence of an unwanted call.
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("/{path}"),
            ndjson_entry("serde", "7.7.7", "zzz"),
        );

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            &repo,
            "serde",
        )
        .await
        .unwrap();
        // The fresh cached projection (1.0.0), not the upstream (7.7.7).
        assert_eq!(projection[0].vers, "1.0.0");
        // Fresh hit reads neither upstream nor the mirror.
        assert!(
            mocks.metadata_mirror.keys().is_empty(),
            "fresh hit must not touch the mirror"
        );
    }

    /// Stale projection in Redis + upstream down → serve the stale
    /// projection (stale-while-error), no error.
    #[tokio::test]
    async fn fetch_stale_projection_served_on_upstream_error() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // Seed a STALE projection (fetched_at far in the past so it is
        // outside the fresh window but the frame is decodable).
        let path = hort_formats::cargo::index_path_for("serde");
        let mut entry = CachedCargoProjection::from_projection(sample_projection());
        entry.fetched_at = Utc::now() - chrono::Duration::seconds(120);
        let key = format!("cargo_index_proj:{mapping_id}:{path}");
        mocks
            .ephemeral_evictable
            .put(&key, entry.encode(), CARGO_INDEX_STALE_TTL)
            .await
            .unwrap();

        // Upstream is down (no metadata seeded → fetch_metadata errors).

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            &repo,
            "serde",
        )
        .await
        .expect("stale projection must be served on upstream error");
        assert_eq!(projection[0].vers, "1.0.0");
    }

    /// No stale projection in Redis + upstream down + mirror present →
    /// re-project from the mirror and serve (air-gapped / outage path).
    #[tokio::test]
    async fn fetch_reprojects_from_mirror_when_redis_empty_and_upstream_down() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // Seed only the mirror (no Redis projection).
        let path = hort_formats::cargo::index_path_for("serde");
        let raw = ndjson_entry("serde", "9.9.9", "feedface");
        let mkey = mirror_key("cargo", &mapping_id.to_string(), &path);
        mocks
            .metadata_mirror
            .put(&mkey, Box::new(std::io::Cursor::new(raw)))
            .await
            .unwrap();

        // Upstream is down (no metadata seeded → fetch_metadata errors).

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            &repo,
            "serde",
        )
        .await
        .expect("mirror re-projection must serve on upstream error");
        assert_eq!(projection[0].vers, "9.9.9");
        assert_eq!(projection[0].cksum, "feedface");
    }

    /// No upstream mapping → NoUpstream.
    #[tokio::test]
    async fn fetch_no_mapping_returns_no_upstream() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());

        let err = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            &repo,
            "serde",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IndexFetchError::NoUpstream));
    }
}
