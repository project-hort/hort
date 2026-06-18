//! npm packument pull-through cache (upstream pull-through).
//!
//! Adds Proxy (`RepositoryType::Proxy`) repository support to the
//! `GET /{repo_key}/{pkg}` and `GET /{repo_key}/@{scope}/{name}` routes:
//!
//! 1. Cache check — read
//!    `npm_packument_proj:{mapping.id}:{url_encoded_name}` via
//!    [`EphemeralStore::get`](hort_domain::ports::ephemeral_store::EphemeralStore).
//!    Hit + within fresh window: return the cached **projection** (no
//!    re-parse); serve renders it through the Source → Filter → Builder
//!    pipeline.
//! 2. Stale or miss → call
//!    [`UpstreamProxy::fetch_metadata`](hort_domain::ports::upstream_proxy::UpstreamProxy)
//!    with no Accept header (npm's registry serves `application/json`
//!    unconditionally). On success the body streams through the
//!    [`NpmPackumentProjector`] (validate-before-commit) and into the
//!    [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store);
//!    the small projection is cached and served fresh. On failure, if a
//!    stale projection exists serve it; else re-project from the raw
//!    mirror (`stale-while-error` / air-gapped); else surface
//!    `UpstreamUnavailable` for the caller to wire-map to 502.
//!
//! # Cache contract (ADR 0026 §3/§5)
//!
//! The ephemeral store holds the small **projection** (versions +
//! `dist.tarball`/`dist.integrity`/`time`, `dist-tags.latest`) — NOT the
//! raw body. The raw body streams into the logical-keyed
//! [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store)
//! under `mirror_key("npm", mapping_id, url_encoded_name)` (a separate
//! keyspace from artifact CAS). This removes the pre-amendment multi-MB
//! big-key from Redis (`@types/node` ~50 MiB) and the per-serve re-parse.
//! [`crate::upstream_pull::try_upstream_tarball_pull`] reads the same
//! cached projection — the `versions[].tarball` it carries is the
//! genuine upstream `dist.tarball` (captured verbatim by the projector
//! before any rewrite, which the builder applies per-request at serve
//! time), and `versions[].integrity` is the verbatim `dist.integrity`
//! SRI used for SHA-512 verification (ADR 0006 upstream verification invariants).
//!
//! # Cache key
//!
//! `npm_packument_proj:{mapping.id}:{url_encoded_name}` — the `_proj`
//! prefix versions the key for the amendment (a rolling deploy never has
//! new code read a pre-amendment `npm_packument_raw:` entry that holds
//! the raw body, not a serialized projection).
//! The **mapping id** is the invalidation axis: an upstream URL change
//! rotates the mapping, which is exactly when stale upstream-derived
//! bytes should die. The
//! URL-encoded name is what actually appears on the wire (`@types%2fnode`
//! for scoped packages), so scoped vs unscoped packages cannot collide.
//!
//! # Envelope encoding
//!
//! Compact binary frame `[version u8 = 1][fetched_at_ms i64 BE][
//! serde_json(NpmProjection)]` (see [`CachedNpmProjection`]). The payload
//! is the serialized projection, not the raw body.
//!
//! # TTLs
//!
//! Per-package packument: fresh window 60 s, backend window 1 h. The
//! backend window is the stale-while-error survival horizon — long
//! enough to ride a typical upstream outage, short enough that operators
//! re-bootstrapping a proxy don't carry yesterday's metadata forever.
//!
//! # URL rewriting
//!
//! Upstream npm returns absolute URLs to `https://registry.npmjs.org`
//! (or whichever upstream is configured) in `versions[].dist.tarball`.
//! Each tarball URL is rewritten to
//! `{base_url}/npm/{repo_key}/{pkg_name}/-/{filename}` at **serve time**
//! — the cache holds the raw upstream URL (see "Cache contract" above).
//! `dist.integrity` and `dist.shasum` are left **verbatim** — clients
//! verify the tarball against `dist.integrity` (SHA-512 SRI) downstream
//! of this handler, so any mutation here would defeat verification. The
//! `pkg_name` segment used in the rewritten URL is the per-version
//! `name` field (preferring it over the request parameter so scoped
//! packages emit the canonical `@scope/pkg/-/{filename}` form, matching
//! public-registry convention and the existing local-CAS handler in
//! `serve_packument`).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;

use hort_app::error::AppError;
use hort_app::pull_dedup::{DedupKey, PullDedup};
use hort_app::use_cases::index_serve_filter::NpmSemverOrdering;
// Prefetch trigger planner — called from the proxy source after the
// raw-body fetch (`ProxyNpmSource::fetch`); the use case emits the
// planning metrics and returns the version list this site then spawns
// per-version `try_upstream_tarball_pull` for.
use hort_app::use_cases::prefetch_use_case::PrefetchPlan;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::{PrefetchTrigger, Repository};
// The typed storage-backstop error is carried through to the consumer
// so a tripped cap surfaces the honest 502 instead of the generic
// "upstream unavailable" envelope.
use hort_domain::error::{DomainError, FetchClass};
use hort_domain::ports::ephemeral_store::EphemeralStore;
// The raw upstream body streams into the logical-keyed mirror; only the
// small projection lands in Redis.
use hort_domain::ports::metadata_mirror_store::{mirror_key, MetadataMirrorStore};
use hort_domain::ports::upstream_proxy::{MetadataProjector, UpstreamProxy};
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_formats::npm::projection::{NpmPackumentProjector, NpmProjection};
use hort_http_core::cache_envelope::CachedProjection;
use hort_http_core::context::AppContext;

/// Fresh-window TTL — within this window since `fetched_at`, the
/// cache entry is served without an upstream round-trip.
pub const NPM_PACKUMENT_FRESH_TTL: Duration = Duration::from_secs(60);

/// Backend-storage TTL — past this the entry expires entirely and a
/// follow-on miss forces a fresh upstream fetch. Must be `>` the fresh
/// window or `stale-while-error` has nothing to fall back on.
pub const NPM_PACKUMENT_STALE_TTL: Duration = Duration::from_secs(60 * 60);

/// Cached upstream packument **projection** (ADR 0026 §3/§5.4).
///
/// The npm proxy caches the *projection* in Redis, not the raw packument
/// body. Multi-MB packuments (`@types/node` ~50 MiB) are streamed into
/// the [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store)
/// and only the small [`NpmProjection`] lands here — serve renders it
/// with no re-parse, and the raw mirror is the stale-while-error /
/// air-gapped fallback.
///
/// This is the shared generic
/// [`CachedProjection<NpmProjection>`](hort_http_core::cache_envelope::CachedProjection)
/// (the per-format `CachedNpmProjection` struct + its byte-identical
/// `encode`/`decode`/`is_fresh` bodies were collapsed into the generic).
/// Wire frame:
///
///   ```text
///   [ version u8 = 1 ][ fetched_at_millis i64 BE ][ serde_json(NpmProjection) ]
///   ```
///
/// The projection carries `versions[].tarball` (the genuine upstream
/// `dist.tarball`, pre-rewrite) and `versions[].integrity` (the verbatim
/// `dist.integrity` SRI) so the tarball-pull orchestrator
/// ([`crate::upstream_pull`]) recovers the real upstream URL and checksum
/// from the cached projection — no raw body required (ADR 0006).
pub(crate) type CachedNpmProjection = CachedProjection<NpmProjection>;

/// Discriminated failure modes for [`fetch_with_cache`]. Wire mapping
/// (HTTP status + envelope body) is performed by the caller in
/// `lib.rs`:
///
/// - `NoUpstream` → 404 (npm's "package doesn't exist" semantic for a
///   Proxy repo with no upstream mapping configured — mirrors
///   Cargo / PyPI).
/// - `UpstreamUnavailable` → 502 (the only fail leg with no cache to
///   fall back on; emitted only when the cache also missed).
/// - `Internal` → 500 (envelope encode/decode infrastructure failures
///   that aren't upstream-attributable).
///
/// `pub` visibility exists for the `hort-formats-upstream` composition
/// seam only — do not pattern-match from outside `hort-http-npm` in-crate
/// code OR `hort-formats-upstream`. A fourth caller breaks the dep-graph
/// rationale behind the explicit-deps seam design.
#[derive(Debug, thiserror::Error)]
pub enum PackumentFetchError {
    #[error("no upstream mapping configured")]
    NoUpstream,
    /// The requested package name failed `validate_npm_name` (serve-path
    /// parity, INJ-3): a `..` / `..%2f`-shaped name that the bare
    /// `normalize_name` URL-decode would otherwise pass through into the
    /// Redis cache key / mirror key / composed upstream URL. Fail-closed
    /// BEFORE any key construction. Carries the validator's message;
    /// consumers surface it as `Validation` → 400 (a client fault, NOT
    /// the `UpstreamUnavailable` network bucket).
    #[error("invalid package name: {cause}")]
    InvalidName { cause: String },
    #[error("upstream unavailable")]
    UpstreamUnavailable,
    /// The upstream metadata body exceeded the configured storage backstop.
    /// Carried verbatim from the adapter's typed
    /// [`DomainError::UpstreamBodyTooLarge`] so the consumer surfaces the
    /// honest 502 (`bytes_read` + `cap`) rather than folding into the
    /// generic [`Self::UpstreamUnavailable`] envelope.
    #[error("upstream {fetch_class} body too large: read {bytes_read} bytes, cap {cap}")]
    UpstreamBodyTooLarge {
        fetch_class: FetchClass,
        bytes_read: u64,
        cap: u64,
    },
    /// The upstream packument failed to parse / project (malformed JSON).
    /// Fail-closed: nothing was cached or mirrored. Surfaces as
    /// `parse_error` (a 4xx), NEVER the `network_error` /
    /// `UpstreamUnavailable` bucket — a malformed body is a content fault,
    /// not an outage.
    #[error("upstream packument malformed: {cause}")]
    MetadataMalformed { cause: String },
    /// A single version object exceeded the per-version-object cap.
    /// Fail-closed (nothing cached); the consumer emits
    /// `version_object_too_large`. Distinct from `MetadataMalformed`
    /// only for the metric.
    #[error("upstream version object too large: {cause}")]
    VersionObjectTooLarge { cause: String },
    #[error("internal: {0}")]
    Internal(String),
}

/// URL-encode an npm package name for the registry path.
///
/// `/` → `%2f` (lowercase) per the npm registry convention (matches
/// `NpmFormatHandler::upstream_checksum_metadata_path` in `hort-formats`).
/// `@` is **not** encoded so scoped names appear as `@scope%2fpkg`.
/// Every other character is passed through verbatim — npm's package-
/// name grammar is a small ASCII subset.
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

/// Pull-through fetch of the upstream packument as a streamed
/// **projection**, with `EphemeralStore`-backed caching of the
/// projection and the raw body streamed into the
/// [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store).
///
/// On a cache miss/stale the upstream body streams (no full-body `Vec`)
/// through [`NpmPackumentProjector`] into a small [`NpmProjection`]; the
/// raw body streams into the mirror under
/// `mirror_key("npm", mapping_id, encoded)` (PASS 2 of
/// [`hort_app::project::fetch_and_project`], valid bodies only —
/// validate-before-commit); the projection is cached in Redis under the
/// `npm_packument_proj:` prefix. Serve renders the cached projection with
/// no re-parse; the raw mirror is the stale-while-error / air-gapped
/// fallback (ADR 0026).
///
/// `mirror` is `Option` so the low-frequency discovery seam
/// (`hort-formats-upstream`, version-listing only) can pass `None` — it
/// does not serve, so it has no mirror and no stale-while-error need.
/// In-crate serve / tarball-pull callers pass
/// `Some(ctx.metadata_mirror.as_ref())`. `per_version_object_max_bytes`
/// is the projector cap (`AppContext.
/// upstream_projector_version_object_max_bytes`, default 2 MiB).
///
/// `pkg_name` is the protocol-form name (`express` or `@types/node`).
///
/// The projection carries the genuine upstream `dist.tarball` URL +
/// verbatim `dist.integrity` SRI per version (ADR 0006), so
/// [`crate::upstream_pull::try_upstream_tarball_pull`] recovers them
/// from the cached projection.
///
/// # Composition-seam helper
///
/// `pub` visibility exists for the `hort-formats-upstream` composition
/// seam only — do not call from outside `hort-http-npm` in-crate code
/// OR `hort-formats-upstream`. A fourth caller breaks the dep-graph
/// rationale behind the explicit-deps seam design. See
/// `docs/architecture/how-to/add-a-format-handler.md` for the
/// supported integration points.
///
/// The helper takes explicit `&dyn UpstreamResolver` + `&dyn
/// EphemeralStore` + `&dyn UpstreamProxy` + `&PullDedup` (+ the
/// optional mirror + projector cap) deps rather than `&Arc<AppContext>`
/// because `hort-formats-upstream`'s adapter cannot hold
/// `Arc<AppContext>` (constructing `AppContext` to hold `Arc<dyn
/// UpstreamMetadataPort>` would be a construction cycle).
// Eight args is over clippy's default 7; wrapping them in a record type
// would just push a per-call-site construction burden onto the three
// callers.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(resolver, cache, upstream_proxy, pull_dedup, mirror), fields(repo_key = %repo.key, pkg = %pkg_name))]
pub async fn fetch_raw_with_cache(
    resolver: &dyn UpstreamResolver,
    cache: &dyn EphemeralStore,
    upstream_proxy: &dyn UpstreamProxy,
    pull_dedup: &PullDedup,
    mirror: Option<&dyn MetadataMirrorStore>,
    per_version_object_max_bytes: u64,
    repo: &Repository,
    pkg_name: &str,
) -> Result<NpmProjection, PackumentFetchError> {
    let Some((mapping, _stripped)) = resolver.resolve(repo.id, "") else {
        tracing::warn!("npm proxy repository has no upstream mapping configured");
        return Err(PackumentFetchError::NoUpstream);
    };

    // ---- Package-name validation (serve-path parity, INJ-3) ----------
    // The publish path validates the npm name via `validate_npm_name`
    // before any storage write; the proxy-GET serve path historically
    // only ran the bare `normalize_name` URL-decode, so a `..` / `..%2f`
    // -shaped name would flow unvalidated into the Redis cache key, the
    // mirror key, AND the composed upstream URL below. There is no
    // filesystem escape (CAS + `reject_traversal` backstop), but the
    // cache key / mirror key / upstream path would be polluted. Reject
    // here, BEFORE any key / upstream-URL construction, returning the
    // SAME `npm.name` `DomainError::Validation` the publish path emits
    // (consumers map it to 400 — a client fault, not an outage).
    if let Err(e) = hort_formats::npm::validate_npm_name(pkg_name) {
        tracing::warn!("npm proxy package name failed validation; refusing to construct keys");
        return Err(PackumentFetchError::InvalidName {
            cause: e.to_string(),
        });
    }

    // The cache key uses the URL-encoded form so scoped (`@types%2fnode`)
    // and unscoped names occupy distinct cache rows even when the un-
    // encoded scoped name (`@types/node`) is what the request URL carried.
    let encoded = url_encode_npm_name(pkg_name);
    // `npm_packument_proj:` prefix: the entry holds the small PROJECTION,
    // not the raw body. The prefix is versioned so a rolling deploy never
    // has new code read a legacy `npm_packument_raw:` entry (its payload
    // is the raw body, not a `serde_json(NpmProjection)` — `decode` would
    // treat it as a miss anyway, but a fresh prefix is cleaner).
    let key = format!("npm_packument_proj:{}:{}", mapping.id, encoded);
    // The raw body's home is the logical-keyed mirror (separate keyspace
    // from artifact CAS). The `encoded` package segment matches the
    // Redis cache key's segment so prefetch / serve / tarball-pull all
    // compute the same mirror key for the same package.
    let mkey = mirror_key("npm", &mapping.id.to_string(), &encoded);

    let cached_raw = cache
        .get(&key)
        .await
        .map_err(|e| PackumentFetchError::Internal(e.to_string()))?;

    // Decode the cached projection if present. A decode failure is
    // treated as a miss + warn: cache poisoning (e.g. a pre-amendment
    // raw-body frame on a rolling deploy) shouldn't wedge a Proxy; the
    // cold-cache event resolves naturally via the upstream fetch below.
    let stale_entry: Option<CachedNpmProjection> =
        cached_raw.and_then(|raw| match CachedNpmProjection::decode(&raw) {
            Some(env) => Some(env),
            None => {
                tracing::warn!(
                    bytes = raw.len(),
                    "npm packument projection cache entry decode failed; treating as miss \
                     (rolling-deploy from a pre-amendment raw-body frame is the expected cause)"
                );
                None
            }
        });

    // Fresh-cache hit: return the cached projection immediately, no
    // upstream call, no re-parse.
    let now = Utc::now();
    if let Some(env) = stale_entry.as_ref() {
        if env.is_fresh(now, NPM_PACKUMENT_FRESH_TTL) {
            return Ok(env.projection.clone());
        }
    }

    // Either fully missing or stale — try upstream. Wrap the fetch in
    // `PullDedup::coalesce_metadata` so N parallel packument misses for
    // the same package produce ≤ 1 upstream call. The closure streams the
    // body through the projector + mirror (`fetch_and_project`) and
    // returns the SERIALIZED projection bytes so followers receive the
    // small projection (not the multi-MB raw body) — keeping the dedup
    // window's payload bounded by the projection size.
    let upstream_path = format!("/{encoded}");
    let dedup_key = DedupKey::metadata("npm", repo.id, &upstream_path);
    let mapping_for_closure = mapping.clone();
    let upstream_path_for_closure = upstream_path.clone();
    let mkey_for_closure = mkey.clone();
    // Grab the per-version-object cap-trip flag before the projector is
    // moved into the closure, so the leader can tell a cap trip apart from
    // a generic malformed-JSON parse failure after the coalesce returns
    // `Err` (followers don't run the closure — their flag stays false and
    // they surface the leader's wrapped error, matching the
    // leader-only-discrimination contract).
    let projector = NpmPackumentProjector::new(per_version_object_max_bytes);
    let cap_flag = projector.cap_trip_flag();
    let coalesce_result = pull_dedup
        .coalesce_metadata(dedup_key, move || async move {
            let outcome = upstream_proxy
                .fetch_metadata(mapping_for_closure, upstream_path_for_closure, vec![])
                .await
                .map_err(AppError::from)?;
            let handle = outcome.cache_handle.as_ref().ok_or_else(|| {
                AppError::from(DomainError::Invariant(
                    "npm fetch_metadata returned no cache_handle".to_string(),
                ))
            })?;
            // PASS 1 validate/project (malformed / cap-trip ⇒ Err,
            // nothing committed); PASS 2 streams the raw body into the
            // mirror (valid only) iff a mirror was supplied. No full-body
            // Vec.
            let projection = match mirror {
                Some(m) => {
                    hort_app::project::fetch_and_project(handle, projector, m, &mkey_for_closure)
                        .await
                        .map_err(AppError::from)?
                }
                None => hort_app::project::project_cached(handle, projector)
                    .await
                    .map_err(AppError::from)?,
            };
            // Best-effort tempfile cleanup (the consumer owns the
            // lifecycle, mirroring the retired `metadata_body_bytes`).
            if let Err(e) = tokio::fs::remove_file(&handle.path).await {
                tracing::debug!(
                    path = %handle.path.display(),
                    error = %e,
                    "npm packument tempfile cleanup failed (non-fatal)"
                );
            }
            // Followers receive the serialized projection (small).
            let json = serde_json::to_vec(&projection).map_err(|e| {
                AppError::from(DomainError::Invariant(format!(
                    "npm projection serialize: {e}"
                )))
            })?;
            Ok(Bytes::from(json))
        })
        .await;
    match coalesce_result {
        Ok(json) => {
            // Deserialize the projection the coalesce produced (leader's
            // own projection, or a follower's copy of the leader's).
            let projection: NpmProjection = serde_json::from_slice(&json).map_err(|e| {
                PackumentFetchError::Internal(format!("npm projection deserialize: {e}"))
            })?;
            // Cache the small projection (not the raw body). Cache-write
            // failures are non-fatal (we already have the projection to
            // return).
            let entry = CachedNpmProjection::from_projection(projection.clone());
            if let Err(e) = cache
                .put(&key, entry.encode(), NPM_PACKUMENT_STALE_TTL)
                .await
            {
                tracing::warn!(error = %e, "npm packument projection cache write failed (non-fatal)");
            }
            tracing::info!(
                versions = projection.versions.len(),
                "npm packument upstream fetch succeeded; cached projection, raw to mirror",
            );
            Ok(projection)
        }
        Err(e) => {
            // Classify BEFORE the stale fallback. A malformed body or
            // per-version-object cap trip is a PARSE failure, not an
            // outage: it must surface as `parse_error` (4xx), fail-closed
            // (nothing cached), and must NOT be masked by serving a stale
            // projection (stale-while-error is for genuine upstream
            // unavailability only).
            if let AppError::Domain(DomainError::Validation(msg)) = &e {
                // The leader's projector tells a cap trip apart from a
                // generic malformed-JSON parse error. Followers see the
                // leader's wrapped error (not `Validation`) and fall
                // through to `UpstreamUnavailable` — leader-only
                // discrimination.
                if cap_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    tracing::warn!(cause = %msg, "npm upstream per-version-object cap tripped (I-6)");
                    return Err(PackumentFetchError::VersionObjectTooLarge { cause: msg.clone() });
                }
                tracing::warn!(cause = %msg, "npm upstream packument malformed (parse_error)");
                return Err(PackumentFetchError::MetadataMalformed { cause: msg.clone() });
            }
            tracing::warn!(error = %e, "npm upstream packument fetch failed");
            // Stale-while-error: prefer a stale projection over a 502.
            if let Some(env) = stale_entry {
                tracing::info!(
                    stale_age_secs = now.signed_duration_since(env.fetched_at).num_seconds(),
                    "npm upstream fetch failed; serving stale projection cache entry",
                );
                return Ok(env.projection);
            }
            // No stale projection in Redis — re-project from the raw
            // mirror if present (replaces the pre-amendment stale-Redis-
            // raw fallback). The mirror is the air-gapped / outage
            // source; re-projecting avoids an upstream re-fetch.
            if let Some(m) = mirror {
                if let Ok(Some(reader)) = m.get(&mkey).await {
                    match project_from_mirror(reader, per_version_object_max_bytes).await {
                        Ok(projection) => {
                            tracing::info!(
                                versions = projection.versions.len(),
                                "npm upstream fetch failed; re-projected stale body from mirror",
                            );
                            return Ok(projection);
                        }
                        Err(perr) => {
                            tracing::warn!(
                                error = %perr,
                                "npm mirror re-projection failed; falling through to upstream error",
                            );
                        }
                    }
                }
            }
            // No stale fallback: preserve the honest storage-backstop
            // classification rather than folding it into the generic
            // "upstream unavailable" envelope. Stale-while-error still
            // wins above (availability); this only fires on a cold cache,
            // which is exactly when the operator needs the
            // `bytes_read`/`cap` signal to size the knob.
            if let AppError::Domain(DomainError::UpstreamBodyTooLarge {
                fetch_class,
                bytes_read,
                cap,
            }) = e
            {
                return Err(PackumentFetchError::UpstreamBodyTooLarge {
                    fetch_class,
                    bytes_read,
                    cap,
                });
            }
            Err(PackumentFetchError::UpstreamUnavailable)
        }
    }
}

/// Re-project a raw packument body from the metadata mirror through the
/// streaming projector. Used **only** on the stale-while-error /
/// air-gapped fallback path — off the hot serve path, which never
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
    per_version_object_max_bytes: u64,
) -> Result<NpmProjection, DomainError> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .await
        .map_err(|e| DomainError::Invariant(format!("npm mirror read: {e}")))?;
    tokio::task::spawn_blocking(move || {
        NpmPackumentProjector::new(per_version_object_max_bytes).project(std::io::Cursor::new(buf))
    })
    .await
    .map_err(|e| DomainError::Invariant(format!("npm mirror re-projection task panicked: {e}")))?
}

// `fn rewrite_packument`, `fn serve_rewritten`, `fn truncate_for_log`,
// `enum RewriteError`, and `fn serve_proxy_packument` were deleted when
// the unified Source → Filter → Builder pipeline replaced them:
// `NonServableStatusFilter` + `IndexModeFilter` + `NpmIndexBuilder`
// apply those transformations post-source. Self-name validation +
// `dist.tarball` rewriting now happen inside `ProxyNpmSource::fetch`
// (per-version) as part of constructing each `VersionEntry`.

// ---------------------------------------------------------------------------
// Prefetch trigger wiring
// ---------------------------------------------------------------------------

/// Best-effort prefetch trigger for an npm packument serve.
///
/// Delegates the canonical five-step sequence to
/// [`fire_hot_path_trigger`]. This function provides the two
/// npm-specific closures:
///
/// - **parser**: packument JSON body → (`versions{}` keys,
///   `Some(dist-tags.latest)` — npm protocol carries an explicit
///   `latest` tag the planner respects verbatim).
/// - **spawner**: the existing [`spawn_prefetch_pulls_npm`] loop.
///
/// The five-step sequence (enabled-escape, parse,
/// `plan(OnIndexFetch)` + spawn, latest-divergence check,
/// `plan(OnDistTagMove)` + spawn) lives in the shared helper's
/// module (`hort_app::use_cases::prefetch_trigger`); see that module
/// for the canonical contract.
///
/// **Filename construction.** npm tarball filenames are universally
/// `{basename}-{version}.tgz` where `basename` is the package name
/// with any `@scope/` prefix stripped (the npm registry serves
/// scoped packages from `@scope/pkg/-/pkg-1.0.0.tgz`). The pull
/// function's defence-in-depth filename check (`extract_upstream_tarball_url`
/// → `actual_basename != filename` arm in `upstream_pull.rs`) catches
/// any deviation between this guess and the upstream-supplied
/// `dist.tarball` URL, so an unusual upstream that uses a different
/// shape fails closed (WARN) rather than poisoning hort with mis-named
/// CAS rows.
pub(crate) fn fire_prefetch_trigger_npm(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    pkg_name: &str,
    projection: &NpmProjection,
    pkg_status: &[(String, QuarantineStatus)],
) {
    // The trigger consumes the already-computed projection (the consumer
    // projected the body once; re-projecting a synthetic body here would
    // be wasteful and re-introduce a parse). The shared
    // `fire_hot_path_trigger` parser closure has a fixed
    // `FnOnce(&[u8]) -> (Vec<String>, Option<String>)` shape (it serves
    // every format and is not in this task's scope to change), so we
    // pre-compute the tuple from the projection and hand it back from a
    // closure that ignores the (empty) body argument.
    let versions: Vec<String> = projection
        .versions
        .iter()
        .map(|v| v.version.clone())
        .collect();
    let latest = projection.dist_tag_latest.clone();
    hort_app::use_cases::prefetch_trigger::fire_hot_path_trigger(
        ctx,
        &ctx.prefetch_use_case,
        repo,
        pkg_name,
        &[],
        pkg_status,
        &NpmSemverOrdering,
        "npm",
        move |_body: &[u8]| (versions, latest),
        spawn_prefetch_pulls_npm,
    );
}

// The standalone `parse_packument_versions` helper was retired:
// `fire_prefetch_trigger_npm` now receives the already-computed
// `NpmProjection` and passes its version list / `dist-tags.latest` into
// the shared trigger directly, so there is no second projection pass.

/// Spawn one background pull per planned version. See
/// [`fire_prefetch_trigger_npm`] for the design rationale.
///
/// Takes the borrowed inputs (matches the clippy
/// `needless_pass_by_value` rule); the per-spawn closure clones
/// what it needs.
fn spawn_prefetch_pulls_npm(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    pkg_name: &str,
    plan: PrefetchPlan,
    trigger: PrefetchTrigger,
) {
    if plan.is_empty() {
        return;
    }
    // Tarball filename construction: strip any `@scope/` prefix from
    // the package name to obtain the basename, then format as
    // `{basename}-{version}.tgz`. Matches the npm registry's path
    // convention (`/scope%2fpkg/-/pkg-1.0.0.tgz`) and the validation
    // the pull function applies via `extract_upstream_tarball_url`.
    let basename = pkg_name.rsplit('/').next().unwrap_or(pkg_name).to_string();
    for version in plan.versions {
        let ctx = ctx.clone();
        let repo = repo.clone();
        let pkg_name = pkg_name.to_string();
        let filename = format!("{basename}-{version}.tgz");
        let trigger_str = trigger.to_string();
        tokio::spawn(async move {
            match crate::upstream_pull::try_upstream_tarball_pull(
                &ctx, &repo, &pkg_name, &version, &filename,
            )
            .await
            {
                Ok(_) => {
                    tracing::info!(
                        format = "npm",
                        repository_key = %repo.key,
                        package = %pkg_name,
                        version = %version,
                        trigger = %trigger_str,
                        "npm prefetch pull-through succeeded",
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        format = "npm",
                        repository_key = %repo.key,
                        package = %pkg_name,
                        version = %version,
                        trigger = %trigger_str,
                        error = ?e,
                        "npm prefetch pull-through failed (non-fatal)",
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
// The tests below pin: (a) the projection-frame round-trip + rolling-
// deploy decode rejection; (b) cache miss → projection cached + raw
// mirrored; (c) a malformed upstream body fails closed and maps to
// `parse_error` (NOT the network bucket); (d) fresh-hit serves the
// cached projection with no upstream call. The end-to-end tarball
// URL + SRI reader/writer contract lives in `upstream_pull::tests`;
// serve rendering in `serve::tests`.

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use uuid::Uuid;

    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{IndexMode, RepositoryFormat, RepositoryType};
    use hort_domain::ports::ephemeral_store::EphemeralStore;
    use hort_domain::ports::metadata_mirror_store::MetadataMirrorStore as _;
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    use hort_formats::npm::projection::NpmVersionEntry;
    // The frame version byte lives on the shared generic envelope in
    // `hort_http_core::cache_envelope`.
    use hort_http_core::cache_envelope::CACHE_FORMAT_VERSION;
    // `read_mirror` is the shared helper in `hort_http_core::test_support`
    // (the npm / cargo / pypi copies were byte-identical).
    use hort_http_core::test_support::{build_mock_ctx, read_mirror, MockPorts};

    use super::*;

    fn sample_projection() -> NpmProjection {
        NpmProjection {
            dist_tag_latest: Some("1.2.3".to_string()),
            versions: vec![NpmVersionEntry {
                version: "1.2.3".to_string(),
                name_as_published: Some("express".to_string()),
                tarball: Some("https://registry.npmjs.org/express/-/express-1.2.3.tgz".to_string()),
                integrity: Some("sha512-abc".to_string()),
                shasum: Some("deadbeef".to_string()),
                published_at: None,
            }],
        }
    }

    #[test]
    fn cached_projection_frame_round_trips() {
        let p = sample_projection();
        let entry = CachedNpmProjection::from_projection(p);
        let encoded = entry.encode();
        let decoded = CachedNpmProjection::decode(&encoded).expect("decode");
        assert_eq!(decoded.projection.dist_tag_latest.as_deref(), Some("1.2.3"));
        assert_eq!(decoded.projection.versions.len(), 1);
        assert_eq!(
            decoded.projection.versions[0].tarball.as_deref(),
            Some("https://registry.npmjs.org/express/-/express-1.2.3.tgz")
        );
        assert_eq!(
            decoded.projection.versions[0].integrity.as_deref(),
            Some("sha512-abc")
        );
        // fetched_at preserved to millisecond precision.
        assert_eq!(
            decoded.fetched_at.timestamp_millis(),
            entry.fetched_at.timestamp_millis()
        );
    }

    #[test]
    fn cached_projection_decode_rejects_pre_amendment_and_short_frames() {
        // A pre-amendment raw-body frame: version byte 1, header OK, but
        // the payload is the raw packument body, not a serde_json
        // projection → decode `None` (rolling-deploy cold-cache).
        let mut raw_frame = vec![CACHE_FORMAT_VERSION];
        raw_frame.extend_from_slice(&0i64.to_be_bytes());
        raw_frame.extend_from_slice(br#"{"name":"express","versions":{}}"#);
        // The payload IS valid JSON but not an `NpmProjection` shape...
        // `NpmProjection` has `Default` for missing fields, so a bare
        // object actually deserializes to an empty projection. Use a
        // payload that cannot be an `NpmProjection` (a JSON array).
        let mut bad_payload = vec![CACHE_FORMAT_VERSION];
        bad_payload.extend_from_slice(&0i64.to_be_bytes());
        bad_payload.extend_from_slice(b"[1,2,3]");
        assert!(CachedNpmProjection::decode(&bad_payload).is_none());

        // Legacy base64-JSON envelope: first byte `{` ≠ version 1.
        let legacy = br#"{"body":"abc","fetched_at":"2024-01-01T00:00:00Z"}"#;
        assert!(CachedNpmProjection::decode(legacy).is_none());

        // Too-short input (< 9-byte header) collapses to a miss.
        assert!(CachedNpmProjection::decode(&[]).is_none());
        assert!(CachedNpmProjection::decode(&[1, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    fn proxy_npm_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Npm;
        r.repo_type = RepositoryType::Proxy;
        r.upstream_url = Some("https://registry.npmjs.org".into());
        r.index_mode = IndexMode::IncludePending;
        r
    }

    fn seed_mapping(mocks: &MockPorts, repo_id: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        let now = Utc::now();
        mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
            id,
            repository_id: repo_id,
            path_prefix: "".into(),
            upstream_url: "https://registry.npmjs.org".into(),
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

    fn cap() -> u64 {
        2 * 1024 * 1024
    }

    /// (a) Cache miss + valid upstream → the PROJECTION is returned and
    /// cached (NOT the raw body), AND the raw body is mirrored under
    /// `mirror_key("npm", mapping_id, encoded)`.
    #[tokio::test]
    async fn fetch_caches_projection_and_mirrors_raw_not_redis_raw() {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(metrics);
        let repo = proxy_npm_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        let upstream = br#"{"name":"express","dist-tags":{"latest":"1.0.0"},
            "versions":{"1.0.0":{"name":"express","dist":{
            "tarball":"https://registry.npmjs.org/express/-/express-1.0.0.tgz",
            "integrity":"sha512-xyz"}}}}"#;
        mocks
            .upstream_proxy
            .insert_metadata("", "/express", upstream.to_vec());

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "express",
        )
        .await
        .expect("fetch must succeed on upstream-200");
        assert_eq!(projection.dist_tag_latest.as_deref(), Some("1.0.0"));
        assert_eq!(projection.versions.len(), 1);

        // Redis holds the PROJECTION frame (decodes as CachedNpmProjection,
        // NOT the raw body).
        let cache_key = format!("npm_packument_proj:{mapping_id}:express");
        let cached = mocks
            .ephemeral_evictable
            .get(&cache_key)
            .await
            .unwrap()
            .expect("projection cache must be populated");
        let env = CachedNpmProjection::decode(&cached).expect("projection frame decode");
        assert_eq!(
            env.projection.versions[0].tarball.as_deref(),
            Some("https://registry.npmjs.org/express/-/express-1.0.0.tgz")
        );

        // The mirror holds the RAW body under the format-scoped key.
        let mkey = mirror_key("npm", &mapping_id.to_string(), "express");
        assert!(
            mocks.metadata_mirror.keys().contains(&mkey),
            "mirror must hold the raw body under {mkey}; got {:?}",
            mocks.metadata_mirror.keys()
        );
        let raw = read_mirror(&mocks, &mkey)
            .await
            .expect("mirror raw must be present");
        assert_eq!(raw, upstream, "mirror must hold the verbatim raw body");

        // The Redis value is NOT the raw body (it's smaller / a frame).
        assert!(
            CachedNpmProjection::decode(&cached).is_some(),
            "Redis value must be a projection frame, not the raw body"
        );
    }

    /// (b) A malformed upstream body fails closed: rejects with a
    /// parse-class error (MetadataMalformed — maps to `parse_error` /
    /// 4xx, NOT the `network_error` / `UpstreamUnavailable` bucket), and
    /// neither Redis nor the mirror is written.
    #[tokio::test]
    async fn malformed_upstream_maps_to_parse_error_not_network_error() {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(metrics);
        let repo = proxy_npm_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // Not valid JSON → the projector fails closed.
        mocks
            .upstream_proxy
            .insert_metadata("", "/express", b"{ this is not json".to_vec());

        let err = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "express",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, PackumentFetchError::MetadataMalformed { .. }),
            "malformed body must be parse-class, NOT network/unavailable; got {err:?}"
        );

        // Fail-closed: nothing cached, nothing mirrored.
        let cache_key = format!("npm_packument_proj:{mapping_id}:express");
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
    async fn fetch_miss_upstream_5xx_returns_unavailable() {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(metrics);
        let repo = proxy_npm_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);
        mocks
            .upstream_proxy
            .fail_next_metadata_with(DomainError::Invariant(
                "upstream:transport_error:simulated".into(),
            ));

        let err = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "express",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PackumentFetchError::UpstreamUnavailable));
    }

    /// Cache miss + storage-backstop trip with no stale fallback preserves
    /// the typed `UpstreamBodyTooLarge`.
    #[tokio::test]
    async fn fetch_storage_backstop_trip_preserves_typed_error() {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(metrics);
        let repo = proxy_npm_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);
        mocks
            .upstream_proxy
            .fail_next_metadata_with(DomainError::UpstreamBodyTooLarge {
                fetch_class: FetchClass::Metadata,
                bytes_read: 99,
                cap: 10,
            });

        let err = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "express",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                PackumentFetchError::UpstreamBodyTooLarge {
                    bytes_read: 99,
                    cap: 10,
                    ..
                }
            ),
            "storage-backstop trip must preserve the typed error, got {err:?}"
        );
    }

    /// Stale projection in Redis + upstream down → serve the stale
    /// projection (stale-while-error), no error.
    #[tokio::test]
    async fn fetch_stale_projection_served_on_upstream_error() {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(metrics);
        let repo = proxy_npm_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // Seed a STALE projection (fetched_at far in the past so it is
        // outside the fresh window but the frame is decodable).
        let mut entry = CachedNpmProjection::from_projection(sample_projection());
        entry.fetched_at = Utc::now() - chrono::Duration::seconds(120);
        let key = format!("npm_packument_proj:{mapping_id}:express");
        mocks
            .ephemeral_evictable
            .put(&key, entry.encode(), NPM_PACKUMENT_STALE_TTL)
            .await
            .unwrap();

        // Upstream is down.
        mocks
            .upstream_proxy
            .fail_next_metadata_with(DomainError::Invariant("upstream:down".into()));

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "express",
        )
        .await
        .expect("stale projection must be served on upstream error");
        assert_eq!(projection.dist_tag_latest.as_deref(), Some("1.2.3"));
    }

    /// No stale projection in Redis + upstream down + mirror present →
    /// re-project from the mirror and serve (air-gapped / outage path).
    #[tokio::test]
    async fn fetch_reprojects_from_mirror_when_redis_empty_and_upstream_down() {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(metrics);
        let repo = proxy_npm_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // Seed only the mirror (no Redis projection).
        let raw = br#"{"dist-tags":{"latest":"9.9.9"},
            "versions":{"9.9.9":{"name":"express","dist":{
            "tarball":"https://registry.npmjs.org/express/-/express-9.9.9.tgz",
            "integrity":"sha512-zzz"}}}}"#;
        let mkey = mirror_key("npm", &mapping_id.to_string(), "express");
        mocks
            .metadata_mirror
            .put(&mkey, Box::new(std::io::Cursor::new(raw.to_vec())))
            .await
            .unwrap();

        // Upstream is down.
        mocks
            .upstream_proxy
            .fail_next_metadata_with(DomainError::Invariant("upstream:down".into()));

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "express",
        )
        .await
        .expect("mirror re-projection must serve on upstream error");
        assert_eq!(projection.dist_tag_latest.as_deref(), Some("9.9.9"));
    }

    /// No upstream mapping → NoUpstream.
    #[tokio::test]
    async fn fetch_no_mapping_returns_no_upstream() {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(metrics);
        let repo = proxy_npm_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());

        let err = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "express",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PackumentFetchError::NoUpstream));
    }

    /// Serve-path package-name validation (INJ-3). A traversal-shaped
    /// proxy-GET name (`..`, `..%2f`, `../etc`) must be rejected by
    /// `validate_npm_name` BEFORE any cache-key / mirror-key /
    /// upstream-URL construction — surfaced as `InvalidName`, NOT
    /// lowercase-normalised onward. The mapping is seeded so the request
    /// reaches the validation gate (which sits after the mapping
    /// resolve) rather than short-circuiting on `NoUpstream`. A tripwire
    /// one-shot upstream failure proves `fetch_metadata` is never called
    /// (the reject fires before any upstream leg).
    #[tokio::test]
    async fn fetch_rejects_traversal_name_before_key_construction() {
        for bad in ["..", "..%2f", "../etc", "..%2fetc"] {
            let metrics = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(metrics);
            let repo = proxy_npm_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            // Tripwire: if validation were bypassed, the fetch would call
            // upstream and consume this one-shot failure.
            mocks
                .upstream_proxy
                .fail_next_metadata_with(DomainError::Invariant(
                    "MARKER:fetch_metadata_must_not_be_called".into(),
                ));

            let err = fetch_raw_with_cache(
                ctx.upstream_resolver.as_ref(),
                ctx.ephemeral_evictable.as_ref(),
                ctx.upstream_proxy.as_ref(),
                ctx.pull_dedup.as_ref(),
                Some(ctx.metadata_mirror.as_ref()),
                cap(),
                &repo,
                bad,
            )
            .await
            .unwrap_err();

            assert!(
                matches!(err, PackumentFetchError::InvalidName { .. }),
                "traversal name {bad:?} must reject with InvalidName, got {err:?}"
            );
        }
    }

    /// The validation gate must not regress the happy path: a normal
    /// package name flows past validation into the cache/upstream
    /// pipeline. A fresh cache hit lets us assert the gate is permissive
    /// without seeding an upstream.
    #[tokio::test]
    async fn fetch_accepts_valid_name_past_validation_gate() {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(metrics);
        let repo = proxy_npm_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        let entry = CachedNpmProjection::from_projection(sample_projection());
        let key = format!("npm_packument_proj:{mapping_id}:express");
        mocks
            .ephemeral_evictable
            .put(&key, entry.encode(), NPM_PACKUMENT_STALE_TTL)
            .await
            .unwrap();

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "express",
        )
        .await
        .expect("valid name must pass the validation gate");
        assert_eq!(projection.dist_tag_latest.as_deref(), Some("1.2.3"));
    }

    /// (d) Fresh projection-cache hit → returns the cached projection,
    /// no upstream call, no mirror read. The seeded upstream is different
    /// so a broken fresh-check surfaces as a mismatch.
    #[tokio::test]
    async fn fetch_fresh_hit_serves_cached_projection_no_upstream_call() {
        let metrics = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(metrics);
        let repo = proxy_npm_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        let entry = CachedNpmProjection::from_projection(sample_projection());
        let key = format!("npm_packument_proj:{mapping_id}:express");
        mocks
            .ephemeral_evictable
            .put(&key, entry.encode(), NPM_PACKUMENT_STALE_TTL)
            .await
            .unwrap();

        // Seed a DIFFERENT upstream — would-be evidence of an unwanted call.
        mocks.upstream_proxy.insert_metadata(
            "",
            "/express",
            br#"{"versions":{"7.7.7":{}}}"#.to_vec(),
        );

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "express",
        )
        .await
        .unwrap();
        // The fresh cached projection (1.2.3), not the upstream (7.7.7).
        assert_eq!(projection.dist_tag_latest.as_deref(), Some("1.2.3"));
        // Fresh hit reads neither upstream nor the mirror.
        assert!(
            mocks.metadata_mirror.keys().is_empty(),
            "fresh hit must not touch the mirror"
        );
    }
}
