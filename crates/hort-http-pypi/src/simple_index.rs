//! PyPI simple-index pull-through cache.
//!
//! Adds Remote (`RepositoryType::Proxy`) repository support to the
//! PEP 503 (`text/html`) and PEP 691 (`application/vnd.pypi.simple.v1+json`)
//! `/simple/{name}/` routes:
//!
//! 1. Cache check — read `pypi_simple_proj:{mapping.id}:{normalized_name}`
//!    via [`EphemeralStore::get`](hort_domain::ports::ephemeral_store::EphemeralStore).
//!    Hit + within fresh window: return the cached **projection** (no
//!    re-parse); the unified pipeline re-renders HTML or JSON from it.
//! 2. Stale or miss → call [`UpstreamProxy::fetch_metadata`](
//!    hort_domain::ports::upstream_proxy::UpstreamProxy) with a format-
//!    specific Accept header. On success the body streams through the
//!    format-appropriate projector (JSON via
//!    [`PypiSimpleIndexProjector`], HTML via
//!    [`HtmlSimpleIndexProjector`]) into a small
//!    [`PypiSimpleIndexProjection`], and the raw body streams into the
//!    [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store);
//!    the projection is cached and served fresh. On failure, if a stale
//!    projection exists serve it; else re-project from the raw mirror
//!    (`stale-while-error` / air-gapped); else surface
//!    `UpstreamUnavailable` for the caller to wire-map to 502.
//!
//! # Cache contract (ADR 0026)
//!
//! The PyPI proxy caches only the small **projection** (not the raw body)
//! in Redis. The raw body streams into the logical-keyed mirror. BOTH
//! serve arms (PEP 503 HTML, PEP 691 JSON) project to the SAME
//! representation-independent [`PypiSimpleIndexProjection`], so the serve
//! cache is unified to ONE format-INDEPENDENT key. Serve re-renders HTML
//! or JSON from the cached projection (no re-parse).
//!
//! # Cache key
//!
//! `pypi_simple_proj:{mapping.id}:{normalized_name}` — the `_proj` prefix
//! versions the key for the amendment (a rolling deploy never has new
//! code read a pre-amendment `pypi_simple:{...}:{html|json}` base64-JSON
//! raw-body envelope). The **mapping id** is the invalidation axis: an
//! upstream URL change rotates the mapping, which is exactly when stale
//! upstream-derived bytes should die. The key is format-INDEPENDENT —
//! HTML and JSON share one projection row (the projection is
//! representation-agnostic).
//!
//! # Mirror key
//!
//! `mirror_key("pypi", mapping_id, "{normalized}#{fmt}")` — FORMAT-DISTINCT
//! (the HTML and JSON raw bodies differ; stale-while-error re-projection
//! reads the mirror and applies the projector matching the stored body).
//!
//! # TTLs
//!
//! Per-package simple index: fresh window 60 s, backend window 1 h. The
//! backend window is the stale-while-error survival horizon — long
//! enough to ride a typical upstream outage, short enough that operators
//! re-bootstrapping a proxy don't carry yesterday's index forever.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;

use hort_app::error::AppError;
use hort_app::pull_dedup::{DedupKey, PullDedup};
use hort_app::use_cases::index_serve_filter::Pep440Ordering;
// Prefetch trigger planner. Called from `ProxyPypiSource::fetch` after
// the raw-body fetch; the use case emits the planning metrics and
// returns the version list this site then spawns per-version
// `try_upstream_file_pull` fan-out for.
use hort_app::use_cases::prefetch_use_case::PrefetchPlan;
use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::entities::repository::{PrefetchTrigger, Repository};
use hort_domain::error::{DomainError, DomainResult, FetchClass};
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::metadata_mirror_store::{mirror_key, MetadataMirrorStore};
use hort_domain::ports::upstream_proxy::{MetadataProjector, UpstreamProxy};
use hort_domain::ports::upstream_resolver::UpstreamResolver;
use hort_formats::pypi::projection::{
    PypiSimpleIndexProjection, PypiSimpleIndexProjector, PypiVersionJsonProjection,
    PypiVersionJsonProjector,
};
use hort_formats::pypi::PyPiFormatHandler;
use hort_http_core::cache_envelope::CachedProjection;
use hort_http_core::context::AppContext;

use crate::html_projection::HtmlSimpleIndexProjector;

/// Fresh-window TTL — within this window since `fetched_at`, the
/// cache entry is served without an upstream round-trip.
pub const PYPI_SIMPLE_FRESH_TTL: Duration = Duration::from_secs(60);

/// Backend-storage TTL — past this the entry expires entirely and a
/// follow-on miss forces a fresh upstream fetch. Must be `>` the fresh
/// window or `stale-while-error` has nothing to fall back on.
pub const PYPI_SIMPLE_STALE_TTL: Duration = Duration::from_secs(60 * 60);

/// PEP 691 v1+json content type. Substring matched against `Accept`
/// values; anything else is treated as HTML (PEP 503 default — local-
/// repo handler does the same).
const PEP691_JSON_TYPE: &str = "application/vnd.pypi.simple.v1+json";

/// PEP 691 v1+html content type. Forwarded alongside `text/html` so
/// upstream mirrors that opt into the new content-type can serve the
/// cleaner v1+html shape, but the response is still HTML either way.
const PEP691_HTML_TYPE: &str = "application/vnd.pypi.simple.v1+html";

/// Cached negotiation result. `Html` covers PEP 503 (`text/html`) and
/// PEP 691 v1+html — both serialise as HTML; the cache is keyed on this
/// enum's `as_str()` so they share an entry.
///
/// `pub` visibility exists for the `hort-formats-upstream` composition
/// seam only — do not consume from outside `hort-http-pypi` in-crate
/// code OR `hort-formats-upstream`. A fourth caller breaks the dep-graph
/// rationale behind the composition seam (see
/// `docs/architecture/how-to/add-a-format-handler.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimpleIndexFormat {
    Html,
    Json,
}

impl SimpleIndexFormat {
    /// Cache-key suffix and content negotiation discriminator.
    fn as_str(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Json => "json",
        }
    }

    /// Inspect an `Accept` header value for the PEP 691 v1+json content
    /// type. **HTML is the default fallback** when the client sends no
    /// `Accept` header or one we don't recognise — matches the existing
    /// local-repo handler's behaviour (`wants_pep691_json` in `lib.rs`).
    /// Returning 406 here would regress local repos; the per-spec 406
    /// path lives at the protocol-spec layer, not the cache layer.
    pub(crate) fn from_accept(accept: Option<&str>) -> Self {
        match accept {
            Some(s) if s.contains(PEP691_JSON_TYPE) => Self::Json,
            _ => Self::Html,
        }
    }

    /// Accept-header values forwarded to upstream. Both branches
    /// include the v1 PEP 691 content types so a mirror that supports
    /// them can negotiate up; `text/html` stays in the HTML branch as
    /// the universal fallback.
    fn upstream_accept(self) -> Vec<String> {
        match self {
            Self::Html => vec![PEP691_HTML_TYPE.into(), "text/html".into()],
            Self::Json => vec![PEP691_JSON_TYPE.into()],
        }
    }

    // `response_content_type` was deleted: the unified
    // `serve::serve_simple_index_unified` handler emits the per-format
    // `Content-Type` inline (it pinned
    // `application/vnd.pypi.simple.v1+json` / `text/html; charset=utf-8`
    // via a literal `match`).
}

/// Cached upstream simple-index **projection** (ADR 0026).
///
/// The PyPI proxy caches only the small [`PypiSimpleIndexProjection`]
/// here; the raw body streams into the logical-keyed
/// [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store).
/// BOTH the PEP 503 HTML arm (projected via the regex
/// [`HtmlSimpleIndexProjector`]) and the PEP 691 JSON arm (projected via
/// [`PypiSimpleIndexProjector`]) produce the SAME representation-
/// independent projection, so the serve cache is unified to ONE
/// format-independent key (`pypi_simple_proj:{mapping.id}:{normalized}`).
/// Serve re-renders HTML or JSON from the cached projection with no
/// re-parse; the raw mirror (format-distinct key) is the
/// stale-while-error / air-gapped fallback.
///
/// The shared generic
/// [`CachedProjection<PypiSimpleIndexProjection>`](hort_http_core::cache_envelope::CachedProjection)
/// superseded the per-format `CachedPypiProjection` struct (whose
/// `encode`/`decode`/`is_fresh` bodies were byte-identical).
/// Wire frame (unchanged, byte-identical):
///
///   ```text
///   [ version u8 = 1 ][ fetched_at_millis i64 BE ][ serde_json(PypiSimpleIndexProjection) ]
///   ```
pub(crate) type CachedPypiProjection = CachedProjection<PypiSimpleIndexProjection>;

/// Discriminated failure modes for [`fetch_with_cache`]. Wire mapping
/// (HTTP status + envelope body) is performed by the caller in
/// `lib.rs::simple_project`:
///
/// - `NoUpstream` → 404 (PyPI's "package doesn't exist" semantic for a
///   Proxy repo with no upstream mapping configured — mirrors Cargo).
/// - `UpstreamUnavailable` → 502 (the only fail leg with no cache to
///   fall back on; emitted only when the cache also missed).
/// - `Internal` → 500 (envelope encode/decode infrastructure failures
///   that aren't upstream-attributable).
///
/// `pub` visibility exists for the `hort-formats-upstream` composition
/// seam only — do not pattern-match from outside `hort-http-pypi`
/// in-crate code OR `hort-formats-upstream`. A fourth caller breaks the
/// dep-graph rationale behind the composition seam (see
/// `docs/architecture/how-to/add-a-format-handler.md`).
#[derive(Debug, thiserror::Error)]
pub enum IndexFetchError {
    #[error("no upstream mapping configured")]
    NoUpstream,
    #[error("upstream unavailable")]
    UpstreamUnavailable,
    /// Upstream metadata body exceeded the configured storage backstop;
    /// carried verbatim from the adapter so the consumer surfaces the
    /// honest 502 (`bytes_read` + `cap`) instead of folding into
    /// [`Self::UpstreamUnavailable`].
    #[error("upstream {fetch_class} body too large: read {bytes_read} bytes, cap {cap}")]
    UpstreamBodyTooLarge {
        fetch_class: FetchClass,
        bytes_read: u64,
        cap: u64,
    },
    /// The upstream simple-index failed to parse / project (a malformed
    /// HTML/JSON body). Fail-closed: nothing was cached or mirrored.
    /// Surfaces as `parse_error` (a 4xx via the `Validation` → 400
    /// mapping), NEVER the `UpstreamUnavailable` network bucket — a
    /// malformed body is a content fault, not an outage.
    #[error("upstream simple-index malformed: {cause}")]
    MetadataMalformed { cause: String },
    /// A single per-file object in the PEP 691 JSON simple-index exceeded
    /// the per-value object cap. Fail-closed (nothing cached); the
    /// consumer emits `version_object_too_large`. Distinct from
    /// [`Self::MetadataMalformed`] only for the metric — both map to
    /// `Validation` → 400. The discrimination is driven by the projector's
    /// typed `cap_trip_flag` (leader-only — followers see the leader's
    /// wrapped error and fall through to `UpstreamUnavailable`), NOT a
    /// brittle error-string substring match. Only the JSON arm raises this;
    /// the HTML projector has no per-file-object cap concept (an over-cap
    /// HTML body trips the whole-body plausibility bound instead).
    #[error("upstream version object too large: {cause}")]
    VersionObjectTooLarge { cause: String },
    #[error("internal: {0}")]
    Internal(String),
}

// `HREF_RE` (per-anchor href URL rewriter regex) and `METADATA_URL_RE`
// (PEP 658 data-dist-info-metadata rewriter regex) were deleted along
// with the legacy `rewrite_html` / `rewrite_metadata_attr` functions.
// The unified `PypiHtmlIndexBuilder` constructs URLs from
// `PypiVersionFile::filename` instead of regex-rewriting upstream HTML.
//
// `FULL_ANCHOR_RE` + the `pypi_extract_href_attr` /
// `pypi_filename_from_href` HTML-attribute helpers were retired: the
// prefetch trigger now derives its version set from the cached
// `PypiSimpleIndexProjection` (via `versions_from_projection`), not from
// a raw HTML/JSON body. The HTML anchor regex lives only in
// `crate::html_projection` now (the serve HTML projector).

/// Pull-through fetch of the upstream simple-index as a streamed
/// **projection**, with `EphemeralStore`-backed caching of the
/// projection and the raw body streamed into the
/// [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store).
///
/// On a cache miss/stale the upstream body streams (no full-body `Vec`)
/// through the format-appropriate projector — [`PypiSimpleIndexProjector`]
/// (JSON) or [`HtmlSimpleIndexProjector`] (HTML, buffered regex; PyPI
/// simple-index bodies are ~110 KB so a streaming HTML parser is not
/// warranted) — into a small [`PypiSimpleIndexProjection`]; the raw body
/// streams into the mirror (PASS 2 of
/// [`hort_app::project::fetch_and_project`], valid bodies only —
/// validate-before-commit); the projection is cached in Redis under the
/// format-INDEPENDENT `pypi_simple_proj:` prefix.
///
/// Both arms produce the SAME representation-independent projection, so
/// the serve cache is unified to ONE key
/// (`pypi_simple_proj:{mapping.id}:{normalized}`). A fresh hit in EITHER
/// format renders from the cached projection with no upstream call and
/// no re-parse. The raw mirror is keyed FORMAT-DISTINCTLY
/// (`mirror_key("pypi", mapping_id, "{normalized}#{fmt}")`) because the
/// HTML and JSON raw bodies differ and stale-while-error re-projection
/// must use the matching projector.
///
/// `mirror` is `Option` so the discovery seam (`hort-formats-upstream`,
/// version-listing only) can pass `None` — it does not serve, so it has
/// no mirror and no stale-while-error need. In-crate serve callers pass
/// `Some(ctx.metadata_mirror.as_ref())`.
/// `per_value_object_max_bytes` is the projector per-object cap.
///
/// `format` selects HTML vs JSON; **the same upstream URL** is fetched
/// for both (the upstream content-negotiates on `Accept`).
///
/// `pub` visibility exists for the `hort-formats-upstream` composition
/// seam only — do not call from outside `hort-http-pypi` in-crate code
/// OR `hort-formats-upstream`. See
/// `docs/architecture/how-to/add-a-format-handler.md` for the
/// supported integration points.
///
/// The helper takes explicit `&dyn UpstreamResolver` + `&dyn
/// EphemeralStore` + `&dyn UpstreamProxy` + `&PullDedup` (+ the optional
/// mirror + projector cap) deps rather than `&Arc<AppContext>` because
/// `hort-formats-upstream`'s adapter cannot hold `Arc<AppContext>`
/// (wiring `AppContext` to hold `Arc<dyn UpstreamMetadataPort>` would be
/// a construction cycle).
///
/// Dedup/coalescing URL-key for the simple index. Includes the negotiated
/// PEP 503/691 format so HTML and JSON do **not** coalesce — they parse
/// differently, and a cross-format follower would receive an empty index.
/// The `#<fmt>` fragment is key-only; the actual upstream fetch uses the
/// bare `/simple/<name>/` path.
fn simple_index_dedup_key_url(normalized_project: &str, format: SimpleIndexFormat) -> String {
    format!("/simple/{normalized_project}/#{}", format.as_str())
}

/// Format-distinct mirror-key package segment. The HTML and JSON raw
/// bodies differ; the stale-while-error re-projection reads the mirror
/// and MUST apply the projector matching the body it stored, so the
/// mirror key carries the format suffix even though the projection cache
/// key does not.
fn simple_index_mirror_package(normalized_project: &str, format: SimpleIndexFormat) -> String {
    format!("{normalized_project}#{}", format.as_str())
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    skip(resolver, cache, upstream_proxy, pull_dedup, mirror),
    fields(repo_key = %repo.key, project, format = ?format)
)]
pub async fn fetch_raw_with_cache(
    resolver: &dyn UpstreamResolver,
    cache: &dyn EphemeralStore,
    upstream_proxy: &dyn UpstreamProxy,
    pull_dedup: &PullDedup,
    mirror: Option<&dyn MetadataMirrorStore>,
    per_value_object_max_bytes: u64,
    repo: &Repository,
    project: &str,
    format: SimpleIndexFormat,
) -> Result<PypiSimpleIndexProjection, IndexFetchError> {
    let Some((mapping, _stripped)) = resolver.resolve(repo.id, "") else {
        tracing::warn!("PyPI proxy repository has no upstream mapping configured");
        return Err(IndexFetchError::NoUpstream);
    };

    // Normalise the project name once — both the upstream path and the
    // cache key key on PEP 503's normalised form so `Foo`, `foo`, and
    // `f-o-o` collapse to a single cache row.
    let normalized = PyPiFormatHandler.normalize_name(project);
    // `pypi_simple_proj:` prefix: the entry holds the small PROJECTION,
    // not the raw body, and is FORMAT-INDEPENDENT (both arms produce the
    // same projection). The `_proj` suffix versions the key so a rolling
    // deploy never has new code read a legacy `pypi_simple:{...}:{html|json}`
    // base64-JSON raw-body envelope.
    let key = format!("pypi_simple_proj:{}:{}", mapping.id, normalized);
    // The raw body's home is the logical-keyed mirror (separate keyspace
    // from artifact CAS), keyed FORMAT-DISTINCTLY (HTML/JSON bodies differ).
    let mkey = mirror_key(
        "pypi",
        &mapping.id.to_string(),
        &simple_index_mirror_package(&normalized, format),
    );

    let cached_raw = cache
        .get(&key)
        .await
        .map_err(|e| IndexFetchError::Internal(e.to_string()))?;

    // Decode the cached projection if present. A decode failure is
    // treated as a miss + warn: cache poisoning (e.g. a pre-amendment
    // base64-JSON envelope on a rolling deploy) shouldn't wedge a Proxy.
    let stale_entry: Option<CachedPypiProjection> =
        cached_raw.and_then(|raw| match CachedPypiProjection::decode(&raw) {
            Some(env) => Some(env),
            None => {
                tracing::warn!(
                    bytes = raw.len(),
                    "PyPI simple-index projection cache entry decode failed; treating as miss \
                     (rolling-deploy from a pre-amendment raw-body envelope is the expected cause)"
                );
                None
            }
        });

    // Fresh-cache hit: return the cached projection immediately, no
    // upstream call, no re-parse.
    let now = Utc::now();
    if let Some(env) = stale_entry.as_ref() {
        if env.is_fresh(now, PYPI_SIMPLE_FRESH_TTL) {
            return Ok(env.projection.clone());
        }
    }

    // Either fully missing or stale — try upstream. Wrap the fetch in
    // `PullDedup::coalesce_metadata` so N parallel simple-index misses
    // for the same project produce ≤ 1 upstream call. The closure streams
    // the body through the projector + mirror (`fetch_and_project`) and
    // returns the SERIALIZED projection so followers receive the small
    // projection (not the raw body) — and the dedup/coalescing key MUST
    // include the negotiated format (HTML/JSON parse differently).
    let upstream_path = format!("/simple/{normalized}/");
    let dedup_key = DedupKey::metadata(
        "pypi",
        repo.id,
        &simple_index_dedup_key_url(&normalized, format),
    );
    let mapping_for_closure = mapping.clone();
    let upstream_path_for_closure = upstream_path.clone();
    let upstream_accept = format.upstream_accept();
    let mkey_for_closure = mkey.clone();
    // Build the JSON projector OUTSIDE the closure (for the JSON arm only)
    // and grab its `cap_trip_flag` BEFORE the coalesce, so on a leader
    // `Validation` error we can tell a per-file-object cap trip apart from
    // a generic malformed-JSON parse failure WITHOUT a brittle error-string
    // match. The HTML projector has no per-file-object cap concept, so the
    // HTML arm carries no flag (an over-cap HTML body trips the whole-body
    // bound and surfaces as `MetadataMalformed`). Followers don't run the
    // closure — their (unset) flag is never read; they surface the leader's
    // wrapped error and fall through to `UpstreamUnavailable`.
    let json_projector = match format {
        SimpleIndexFormat::Json => Some(PypiSimpleIndexProjector::new(per_value_object_max_bytes)),
        SimpleIndexFormat::Html => None,
    };
    let cap_flag = json_projector
        .as_ref()
        .map(PypiSimpleIndexProjector::cap_trip_flag);
    let coalesce_result = pull_dedup
        .coalesce_metadata(dedup_key, move || async move {
            let outcome = upstream_proxy
                .fetch_metadata(
                    mapping_for_closure,
                    upstream_path_for_closure,
                    upstream_accept,
                )
                .await
                .map_err(AppError::from)?;
            let handle = outcome.cache_handle.as_ref().ok_or_else(|| {
                AppError::from(DomainError::Invariant(
                    "pypi fetch_metadata returned no cache_handle".to_string(),
                ))
            })?;
            // PASS 1 validate/project (a malformed body / cap-trip ⇒ Err,
            // nothing committed — fail-closed); PASS 2 streams the raw
            // body into the mirror (valid only) iff a mirror was supplied.
            // The projector is format-appropriate: JSON arm streams via the
            // pre-built `PypiSimpleIndexProjector` (whose cap flag the caller
            // holds); HTML arm via the buffered-regex `HtmlSimpleIndexProjector`
            // (bodies are ~110 KB). Both yield the SAME
            // `PypiSimpleIndexProjection`.
            let projection = project_body(handle, json_projector, mirror, &mkey_for_closure)
                .await
                .map_err(AppError::from)?;
            // Best-effort tempfile cleanup (the consumer owns the
            // lifecycle, mirroring the retired `metadata_body_bytes`).
            if let Err(e) = tokio::fs::remove_file(&handle.path).await {
                tracing::debug!(
                    path = %handle.path.display(),
                    error = %e,
                    "pypi simple-index tempfile cleanup failed (non-fatal)"
                );
            }
            // Followers receive the serialized projection (small).
            let json = serde_json::to_vec(&projection).map_err(|e| {
                AppError::from(DomainError::Invariant(format!(
                    "pypi projection serialize: {e}"
                )))
            })?;
            Ok(Bytes::from(json))
        })
        .await;
    match coalesce_result {
        Ok(json) => {
            // Deserialize the projection the coalesce produced (leader's
            // own projection, or a follower's copy of the leader's).
            let projection: PypiSimpleIndexProjection =
                serde_json::from_slice(&json).map_err(|e| {
                    IndexFetchError::Internal(format!("pypi projection deserialize: {e}"))
                })?;
            // Cache the small projection (not the raw body). Cache-write
            // failures are non-fatal (we already have the projection to
            // return).
            let entry = CachedPypiProjection::from_projection(projection.clone());
            if let Err(e) = cache.put(&key, entry.encode(), PYPI_SIMPLE_STALE_TTL).await {
                tracing::warn!(error = %e, "PyPI simple-index projection cache write failed (non-fatal)");
            }
            tracing::info!(
                files = projection.files.len(),
                "PyPI simple-index upstream fetch succeeded; cached projection, raw to mirror",
            );
            Ok(projection)
        }
        Err(e) => {
            // Classify BEFORE the stale fallback. A malformed body /
            // per-file-object cap trip is a PARSE failure, not an outage:
            // it must surface as `parse_error`, fail-closed (nothing
            // cached), and must NOT be masked by serving a stale projection
            // (stale-while-error is for genuine upstream unavailability
            // only). The projectors raise `DomainError::Validation` on a
            // malformed/over-cap body; followers see the leader's wrapped
            // error (not `Validation`) and fall through to
            // `UpstreamUnavailable`.
            if let AppError::Domain(DomainError::Validation(msg)) = &e {
                // The leader's JSON projector tells a per-file-object cap
                // trip apart from a generic malformed body via the typed
                // `cap_trip_flag` — NOT a brittle `msg.contains(...)`
                // substring match. HTML carries no flag, so an HTML
                // `Validation` always classifies as malformed.
                let cap_tripped = cap_flag
                    .as_ref()
                    .map(|f| f.load(std::sync::atomic::Ordering::Relaxed))
                    .unwrap_or(false);
                if cap_tripped {
                    tracing::warn!(cause = %msg, "pypi upstream per-file-object cap tripped");
                    return Err(IndexFetchError::VersionObjectTooLarge { cause: msg.clone() });
                }
                tracing::warn!(cause = %msg, "pypi upstream simple-index malformed (parse_error)");
                return Err(IndexFetchError::MetadataMalformed { cause: msg.clone() });
            }
            tracing::warn!(error = %e, "PyPI upstream simple-index fetch failed");
            // Stale-while-error: prefer a stale projection over a 502.
            if let Some(env) = stale_entry {
                tracing::warn!(
                    stale_age_secs = now.signed_duration_since(env.fetched_at).num_seconds(),
                    "PyPI upstream fetch failed; serving stale projection cache entry",
                );
                return Ok(env.projection);
            }
            // No stale projection in Redis — re-project from the raw
            // mirror if present (replaces the pre-amendment stale-Redis-
            // raw fallback). The mirror is the air-gapped / outage source;
            // re-projecting avoids an upstream re-fetch. The mirror key is
            // format-distinct, so the matching projector is applied.
            if let Some(m) = mirror {
                if let Ok(Some(reader)) = m.get(&mkey).await {
                    match project_from_mirror(reader, format, per_value_object_max_bytes).await {
                        Ok(projection) => {
                            tracing::info!(
                                files = projection.files.len(),
                                "PyPI upstream fetch failed; re-projected stale body from mirror",
                            );
                            return Ok(projection);
                        }
                        Err(perr) => {
                            tracing::warn!(
                                error = %perr,
                                "pypi mirror re-projection failed; falling through to upstream error",
                            );
                        }
                    }
                }
            }
            // No stale fallback: preserve the honest storage-backstop
            // classification instead of folding into the generic "upstream
            // unavailable" envelope.
            if let AppError::Domain(DomainError::UpstreamBodyTooLarge {
                fetch_class,
                bytes_read,
                cap,
            }) = e
            {
                return Err(IndexFetchError::UpstreamBodyTooLarge {
                    fetch_class,
                    bytes_read,
                    cap,
                });
            }
            Err(IndexFetchError::UpstreamUnavailable)
        }
    }
}

/// Stream the cached upstream body through the format-appropriate
/// projector, optionally mirroring the raw body (PASS 2). The JSON arm
/// receives a PRE-BUILT [`PypiSimpleIndexProjector`] (`Some`) whose
/// `cap_trip_flag` the caller holds so a per-file-object cap trip is
/// discriminated from a generic parse error after the coalesce; the HTML
/// arm (`None`) builds its [`HtmlSimpleIndexProjector`] internally (it has
/// no per-file-object cap concept). Both yield a
/// [`PypiSimpleIndexProjection`]. When `mirror` is `Some`, drives
/// [`hort_app::project::fetch_and_project`] (validate-before-commit — a
/// malformed body never reaches the mirror); when `None`, drives
/// [`hort_app::project::project_cached`] (discovery seam — no mirror, no
/// stale need).
async fn project_body(
    handle: &hort_domain::ports::upstream_proxy::CachedBodyHandle,
    json_projector: Option<PypiSimpleIndexProjector>,
    mirror: Option<&dyn MetadataMirrorStore>,
    mkey: &str,
) -> DomainResult<PypiSimpleIndexProjection> {
    match (json_projector, mirror) {
        (Some(projector), Some(m)) => {
            hort_app::project::fetch_and_project(handle, projector, m, mkey).await
        }
        (Some(projector), None) => hort_app::project::project_cached(handle, projector).await,
        (None, Some(m)) => {
            hort_app::project::fetch_and_project(
                handle,
                HtmlSimpleIndexProjector::with_default_cap(),
                m,
                mkey,
            )
            .await
        }
        (None, None) => {
            hort_app::project::project_cached(handle, HtmlSimpleIndexProjector::with_default_cap())
                .await
        }
    }
}

/// Re-project a raw simple-index body from the metadata mirror through
/// the format-appropriate streaming projector. Used **only** on the
/// stale-while-error / air-gapped fallback path — off the hot serve
/// path, which never reads the mirror (it renders the cached
/// projection). The mirror reader is read into a buffer here and
/// projected via `Cursor`: the sync `MetadataProjector`
/// (`R: std::io::Read`) cannot take an `AsyncRead` directly, and
/// `tokio-util`'s `SyncIoBridge` needs the `io-util` feature (not enabled
/// workspace-wide). A transient buffer on this cold outage path is
/// acceptable — PyPI simple-index bodies are ~110 KB.
async fn project_from_mirror(
    mut reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    format: SimpleIndexFormat,
    per_value_object_max_bytes: u64,
) -> DomainResult<PypiSimpleIndexProjection> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .await
        .map_err(|e| DomainError::Invariant(format!("pypi mirror read: {e}")))?;
    tokio::task::spawn_blocking(move || match format {
        SimpleIndexFormat::Json => PypiSimpleIndexProjector::new(per_value_object_max_bytes)
            .project(std::io::Cursor::new(buf)),
        SimpleIndexFormat::Html => {
            HtmlSimpleIndexProjector::with_default_cap().project(std::io::Cursor::new(buf))
        }
    })
    .await
    .map_err(|e| DomainError::Invariant(format!("pypi mirror re-projection task panicked: {e}")))?
}

// ---------------------------------------------------------------------------
// Prefetch trigger wiring
// ---------------------------------------------------------------------------

/// Best-effort prefetch trigger for a PyPI simple-index serve.
///
/// Parses the upstream PEP 503 HTML / PEP 691 JSON simple index for
/// its version set (mirroring the Item-4 quarantine filter's
/// per-version extraction), then calls
/// [`PrefetchUseCase::plan`](hort_app::use_cases::prefetch_use_case::PrefetchUseCase::plan)
/// once for `OnIndexFetch` and (when applicable) once for
/// `OnDistTagMove`. For each planned version, spawns a background
/// task that fetches the per-version JSON manifest
/// (`/pypi/{name}/{version}/json`) and drives a
/// [`crate::upstream_pull::try_upstream_file_pull`] per distribution
/// file (sdist + N wheels). The quarantine window elapses *off* the
/// next build's critical path. The trigger never blocks the serve.
///
/// **Filename-keyed pull rationale.** Unlike npm / cargo where one
/// version maps to a single tarball, a PyPI version typically
/// publishes a sdist and several platform-arch wheels. The mapping
/// "warm version V" → its concrete pull set requires the per-version
/// JSON manifest first. `PullDedup` single-flights each per-file
/// pull, so a racing client `pip install` collapses to the same
/// in-flight fetch the prefetch started.
///
/// **`OnDistTagMove` semantics for PyPI.** PyPI has no native
/// `dist-tags`; the analogue is the bare `pip install <project>`
/// resolution target — the newest served version per
/// [`Pep440Ordering`]. When hort's latest-held differs from upstream's
/// newest, a tag move has effectively occurred (the next
/// `pip install` will pick a version hort has not seen). The planner's
/// `OnDistTagMove` branch handles this once we pass it the same
/// inputs as `OnIndexFetch` with the trigger discriminator changed;
/// both routes share `PullDedup`, so an enabled-both operator does
/// not double-pull.
///
/// **Spawn vs DB job row.** Hot-path triggers (every simple-index
/// serve fires this) deliberately spawn — the per-serve `jobs` row
/// churn is the cost the planner is sized to avoid. The scheduled
/// trigger is the DB-backed path.
pub(crate) fn fire_prefetch_trigger_pypi(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    project_name: &str,
    normalized_name: &str,
    projection: &PypiSimpleIndexProjection,
    pkg_status: &[(String, QuarantineStatus)],
) {
    // Consume the shared `fire_hot_path_trigger` helper. Per-format
    // variation collapses to a parser closure (PyPI has no native
    // `dist-tags.latest`, so `None` triggers the helper's
    // synthesis-by-Pep440Ordering branch) + a spawner closure
    // (`spawn_prefetch_pulls_pypi`).
    //
    // The trigger consumes the already-computed projection (the consumer
    // projected the body once via `fetch_raw_with_cache`; re-projecting a
    // synthetic body here would be wasteful and re-introduce a parse). The
    // shared `fire_hot_path_trigger` parser closure has a fixed
    // `FnOnce(&[u8]) -> (Vec<String>, Option<String>)` shape, so we
    // pre-compute the version list from the projection's `files[]`
    // filenames and hand it back from a closure that ignores the (empty)
    // body argument.
    let project_name_owned = project_name.to_string();
    let versions = versions_from_projection(projection, normalized_name);
    hort_app::use_cases::prefetch_trigger::fire_hot_path_trigger(
        ctx,
        &ctx.prefetch_use_case,
        repo,
        normalized_name,
        &[],
        pkg_status,
        &Pep440Ordering,
        "pypi",
        move |_body: &[u8]| (versions, None),
        move |ctx, repo, _normalized, plan, trigger| {
            // The spawner emits per-version pulls keyed on
            // `project_name` (the raw request form — pull URLs are
            // built against the upstream's path shape there).
            spawn_prefetch_pulls_pypi(ctx, repo, &project_name_owned, plan, trigger);
        },
    );
}

/// Derive the upstream version set from a cached
/// [`PypiSimpleIndexProjection`] by extracting a PEP 440 version from each
/// `files[]` entry's filename (falling back to the URL basename when the
/// explicit filename is absent). The projection is format-INDEPENDENT,
/// so this single path serves both the HTML and JSON arms.
fn versions_from_projection(
    projection: &PypiSimpleIndexProjection,
    normalized_project: &str,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for f in &projection.files {
        let filename = f.filename.clone().or_else(|| {
            f.url
                .as_ref()
                .and_then(|u| u.rsplit('/').next().map(str::to_string))
        });
        if let Some(fname) = filename {
            if let Some(v) = pypi_extract_version_from_filename(&fname, normalized_project) {
                out.push(v);
            }
        }
    }
    out
}

/// Best-effort PEP 440 version extractor for a PyPI distribution
/// filename. Handles wheels (`.whl`) and sdists. Used by the
/// prefetch-trigger version-set parser to derive the per-anchor
/// version key from a PEP 503 / 691 simple-index entry.
fn pypi_extract_version_from_filename(filename: &str, _normalized_project: &str) -> Option<String> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let mut parts = stem.split('-');
        let _name = parts.next()?;
        let version = parts.next()?;
        if version.is_empty() {
            return None;
        }
        return Some(version.to_string());
    }
    for ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".egg"] {
        if let Some(stem) = filename.strip_suffix(ext) {
            let (_, version) = stem.rsplit_once('-')?;
            if version.is_empty() {
                return None;
            }
            return Some(version.to_string());
        }
    }
    None
}

/// Spawn one background task per planned version. Each task fetches
/// the per-version JSON manifest, enumerates distribution filenames
/// from `urls[]`, and drives a
/// [`crate::upstream_pull::try_upstream_file_pull`] per filename
/// (sdist + N wheels). Each per-file pull rides through `PullDedup`
/// inside `try_upstream_file_pull`, so concurrent prefetches (e.g. the
/// same file being warmed by both `OnIndexFetch` and a racing
/// `pip install`) collapse to a single upstream fetch.
///
/// `tokio::spawn` per VERSION (not per FILE) — the per-version JSON
/// fetch is the work the version owns; the per-file pulls inside the
/// spawn are then awaited sequentially. A future tuning may parallel-
/// dispatch the per-file pulls inside the version task, but the
/// per-version spawn cardinality matches npm / cargo's per-version
/// cardinality, which is the design unit operators tune around
/// (depth-N).
fn spawn_prefetch_pulls_pypi(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    project_name: &str,
    plan: PrefetchPlan,
    trigger: PrefetchTrigger,
) {
    if plan.is_empty() {
        return;
    }
    for version in plan.versions {
        let ctx = ctx.clone();
        let repo = repo.clone();
        let project_name = project_name.to_string();
        let trigger_str = trigger.to_string();
        tokio::spawn(async move {
            prefetch_pypi_version(&ctx, &repo, &project_name, &version, &trigger_str).await;
        });
    }
}

/// Per-version PyPI prefetch task body (extracted from the spawn
/// closure so unit tests can drive it without a runtime). Fetches the
/// per-version JSON, enumerates filenames, and pulls each through
/// `try_upstream_file_pull`. Every failure mode is non-fatal — the
/// trigger is best-effort by design (a prefetch failure must never
/// affect the serve that fired it).
async fn prefetch_pypi_version(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    project_name: &str,
    version: &str,
    trigger_str: &str,
) {
    // 1. Resolve mapping (same path the orchestrator takes).
    let Some((mapping, _)) = ctx.upstream_resolver.resolve(repo.id, "") else {
        tracing::warn!(
            format = "pypi",
            repository_key = %repo.key,
            package = %project_name,
            version = %version,
            trigger = %trigger_str,
            "prefetch skipped: no upstream mapping",
        );
        return;
    };

    // 2. Fetch the per-version JSON manifest. Route through the shared
    //    `PullDedup` so a racing client pull for the same JSON path
    //    coalesces with this fetch.
    let normalized = PyPiFormatHandler.normalize_name(project_name);
    let metadata_path = format!("/pypi/{normalized}/{version}/json");
    let dedup_key = DedupKey::metadata("pypi", repo.id, &metadata_path);
    let upstream_proxy = ctx.upstream_proxy.clone();
    let mapping_for_closure = mapping.clone();
    let path_for_closure = metadata_path.clone();
    let cap = ctx.upstream_projector_version_object_max_bytes;
    // Stream the per-version JSON through the `PypiVersionJsonProjector`
    // (no full-body `Vec`); the closure returns the SERIALIZED projection
    // so followers receive the small projection, not the raw per-version
    // JSON body. The prefetch is best-effort and does not serve, so it
    // passes no mirror (`project_cached`).
    let projection = match ctx
        .pull_dedup
        .coalesce_metadata(dedup_key, move || async move {
            let outcome = upstream_proxy
                .fetch_metadata(
                    mapping_for_closure,
                    path_for_closure,
                    vec!["application/json".into()],
                )
                .await
                .map_err(AppError::from)?;
            let handle = outcome.cache_handle.as_ref().ok_or_else(|| {
                AppError::from(DomainError::Invariant(
                    "pypi per-version fetch_metadata returned no cache_handle".to_string(),
                ))
            })?;
            let projection =
                hort_app::project::project_cached(handle, PypiVersionJsonProjector::new(cap))
                    .await
                    .map_err(AppError::from)?;
            // Best-effort tempfile cleanup (the consumer owns the lifecycle).
            if let Err(e) = tokio::fs::remove_file(&handle.path).await {
                tracing::debug!(
                    path = %handle.path.display(),
                    error = %e,
                    "pypi per-version JSON tempfile cleanup failed (non-fatal)"
                );
            }
            let json = serde_json::to_vec(&projection).map_err(|e| {
                AppError::from(DomainError::Invariant(format!(
                    "pypi per-version projection serialize: {e}"
                )))
            })?;
            Ok(Bytes::from(json))
        })
        .await
    {
        Ok(json) => match serde_json::from_slice::<PypiVersionJsonProjection>(&json) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    format = "pypi",
                    repository_key = %repo.key,
                    package = %project_name,
                    version = %version,
                    trigger = %trigger_str,
                    error = %e,
                    "prefetch per-version projection deserialize failed (non-fatal)",
                );
                return;
            }
        },
        Err(e) => {
            tracing::warn!(
                format = "pypi",
                repository_key = %repo.key,
                package = %project_name,
                version = %version,
                trigger = %trigger_str,
                error = ?e,
                "prefetch per-version JSON fetch failed (non-fatal)",
            );
            return;
        }
    };

    // 3. Enumerate distribution filenames from the projection's `urls[]`.
    let filenames: Vec<String> = projection
        .files
        .iter()
        .filter_map(|f| f.filename.clone())
        .collect();
    if filenames.is_empty() {
        tracing::warn!(
            format = "pypi",
            repository_key = %repo.key,
            package = %project_name,
            version = %version,
            trigger = %trigger_str,
            "prefetch found no filenames in per-version JSON (non-fatal)",
        );
        return;
    }

    // 4. Drive `try_upstream_file_pull` per filename. `PullDedup` inside
    //    the pull function single-flights against a concurrent client pull
    //    of the same file. Failures are per-filename and logged; a single
    //    failing wheel does not block the sister wheels.
    for filename in filenames {
        match crate::upstream_pull::try_upstream_file_pull(ctx, repo, project_name, &filename).await
        {
            Ok(_) => {
                tracing::info!(
                    format = "pypi",
                    repository_key = %repo.key,
                    package = %project_name,
                    version = %version,
                    filename = %filename,
                    trigger = %trigger_str,
                    "prefetch pull-through succeeded",
                );
            }
            Err(e) => {
                tracing::warn!(
                    format = "pypi",
                    repository_key = %repo.key,
                    package = %project_name,
                    version = %version,
                    filename = %filename,
                    trigger = %trigger_str,
                    error = ?e,
                    "prefetch pull-through failed (non-fatal)",
                );
            }
        }
    }
}

// `parse_pypi_version_filenames` (the raw-body `serde_json::Value` walk
// over `urls[]`) was retired: the prefetch per-version JSON now streams
// through `PypiVersionJsonProjector`, and the filename list comes off the
// projection's `files[].filename`.

#[cfg(test)]
mod tests {
    use super::*;

    /// Alpha-walk finding (runbook §7.2): the PEP 503 (HTML) and PEP 691
    /// (JSON) simple-index representations MUST NOT share a dedup/coalescing
    /// key. Before this guard the key omitted the format, so a follower of an
    /// in-flight fetch in the OTHER format received the wrong-format body and
    /// parsed it to an empty index — modern pip (which prefers JSON) could
    /// not resolve from a PyPI proxy.
    #[test]
    fn simple_index_dedup_key_is_format_distinct() {
        let html = simple_index_dedup_key_url("flask", SimpleIndexFormat::Html);
        let json = simple_index_dedup_key_url("flask", SimpleIndexFormat::Json);
        assert_ne!(
            html, json,
            "HTML and JSON simple-index dedup keys must differ (cross-format coalescing bug)"
        );
        // The `#<fmt>` fragment is additive — both still key on the
        // normalised project path so same-format requests still coalesce.
        assert!(html.starts_with("/simple/flask/"), "got {html}");
        assert!(json.starts_with("/simple/flask/"), "got {json}");
        assert!(html.ends_with("html"), "got {html}");
        assert!(json.ends_with("json"), "got {json}");
    }

    // ===================================================================
    // Projection-caching: serve cache holds the PROJECTION (both arms);
    // raw to the format-distinct mirror; parse-error fail-closed.
    // ===================================================================

    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{RepositoryFormat, RepositoryType};
    use hort_domain::ports::ephemeral_store::EphemeralStore;
    // `MetadataMirrorStore` (the trait whose `put` the re-projection test
    // calls directly to seed the mirror) is already in scope via
    // `use super::*` (the module-top import).
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    // `read_mirror` is the shared helper hoisted to
    // `hort_http_core::test_support` (the npm / cargo / pypi copies were
    // byte-identical).
    use hort_http_core::test_support::{build_mock_ctx, read_mirror, MockPorts};

    use hort_app::use_cases::test_support::sample_repository;

    fn cap() -> u64 {
        2 * 1024 * 1024
    }

    fn handle() -> metrics_exporter_prometheus::PrometheusHandle {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle()
    }

    fn proxy_pypi_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Pypi;
        r.repo_type = RepositoryType::Proxy;
        r
    }

    fn seed_mapping(mocks: &MockPorts, repo_id: uuid::Uuid) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        let now = Utc::now();
        mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
            id,
            repository_id: repo_id,
            path_prefix: "".into(),
            upstream_url: "https://pypi.org".into(),
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

    const JSON_BODY: &[u8] = br#"{
        "meta": {"api-version": "1.1"},
        "name": "flask",
        "files": [
            {"filename": "flask-3.0.0-py3-none-any.whl",
             "url": "https://files.pythonhosted.org/packages/ab/flask-3.0.0-py3-none-any.whl",
             "hashes": {"sha256": "jsonwheel256"}},
            {"filename": "flask-3.0.0.tar.gz",
             "url": "https://files.pythonhosted.org/packages/cd/flask-3.0.0.tar.gz",
             "hashes": {"sha256": "jsonsdist256"}}
        ]
    }"#;

    const HTML_BODY: &[u8] = br#"<!DOCTYPE html><html><body>
        <a href="https://files.pythonhosted.org/packages/ab/flask-3.0.0-py3-none-any.whl#sha256=htmlwheel256">flask-3.0.0-py3-none-any.whl</a>
        <a href="https://files.pythonhosted.org/packages/cd/flask-3.0.0.tar.gz#sha256=htmlsdist256">flask-3.0.0.tar.gz</a>
        </body></html>"#;

    /// (a) JSON arm: cache miss + valid upstream → the PROJECTION is
    /// cached under the unified format-INDEPENDENT key (NOT the raw body),
    /// and the raw body is mirrored under the format-distinct mirror key.
    #[tokio::test]
    async fn json_arm_caches_projection_and_mirrors_raw() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);
        mocks
            .upstream_proxy
            .insert_metadata("", "/simple/flask/", JSON_BODY.to_vec());

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "flask",
            SimpleIndexFormat::Json,
        )
        .await
        .expect("json arm must succeed");
        assert_eq!(projection.files.len(), 2);
        assert_eq!(projection.files[0].sha256.as_deref(), Some("jsonwheel256"));

        // Redis holds the PROJECTION frame under the unified key (no
        // `:json` suffix), decodes as `CachedPypiProjection`.
        let cache_key = format!("pypi_simple_proj:{mapping_id}:flask");
        let cached = mocks
            .ephemeral_evictable
            .get(&cache_key)
            .await
            .unwrap()
            .expect("projection cache must be populated");
        let env = CachedPypiProjection::decode(&cached).expect("projection frame decode");
        assert_eq!(env.projection.files.len(), 2);

        // The mirror holds the RAW JSON body under the format-distinct key.
        let mkey = mirror_key("pypi", &mapping_id.to_string(), "flask#json");
        let raw = read_mirror(&mocks, &mkey)
            .await
            .expect("mirror raw must be present");
        assert_eq!(
            raw, JSON_BODY,
            "mirror must hold the verbatim raw JSON body"
        );
    }

    /// (a) HTML arm: cache miss + valid upstream → the PROJECTION is
    /// cached under the SAME unified key, raw mirrored under the HTML
    /// format-distinct mirror key.
    #[tokio::test]
    async fn html_arm_caches_projection_and_mirrors_raw() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);
        mocks
            .upstream_proxy
            .insert_metadata("", "/simple/flask/", HTML_BODY.to_vec());

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "flask",
            SimpleIndexFormat::Html,
        )
        .await
        .expect("html arm must succeed");
        assert_eq!(projection.files.len(), 2);
        assert_eq!(projection.files[0].sha256.as_deref(), Some("htmlwheel256"));

        // SAME unified, format-independent cache key as the JSON arm.
        let cache_key = format!("pypi_simple_proj:{mapping_id}:flask");
        let cached = mocks
            .ephemeral_evictable
            .get(&cache_key)
            .await
            .unwrap()
            .expect("projection cache must be populated");
        assert!(CachedPypiProjection::decode(&cached).is_some());

        // The mirror holds the RAW HTML body under the HTML format-distinct
        // key — distinct from the JSON one (the raw bodies differ).
        let mkey = mirror_key("pypi", &mapping_id.to_string(), "flask#html");
        let raw = read_mirror(&mocks, &mkey)
            .await
            .expect("mirror raw must be present");
        assert_eq!(
            raw, HTML_BODY,
            "mirror must hold the verbatim raw HTML body"
        );
    }

    /// Serve renders the correct per-version files from the cached
    /// projection (both arms project to the same shape; render verifies
    /// `projection_to_entries` consumes either projection identically).
    #[tokio::test]
    async fn both_arms_project_to_renderable_entries() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);
        mocks
            .upstream_proxy
            .insert_metadata("", "/simple/flask/", JSON_BODY.to_vec());

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "flask",
            SimpleIndexFormat::Json,
        )
        .await
        .expect("json arm must succeed");

        // The projection groups into one version (3.0.0) with two files.
        let entries = crate::index_source::projection_to_entries(
            projection,
            "flask",
            &std::collections::HashMap::new(),
        );
        assert_eq!(entries.len(), 1, "one version (3.0.0)");
        assert_eq!(entries[0].version, "3.0.0");
        let hort_app::use_cases::index_serve::PerVersionPayload::Pypi(payload) =
            &entries[0].payload
        else {
            unreachable!()
        };
        assert_eq!(payload.files.len(), 2, "wheel + sdist");
    }

    /// A malformed JSON upstream body fails closed: rejects with
    /// `MetadataMalformed` (maps to `parse_error` / 4xx, NOT the
    /// `UpstreamUnavailable` network bucket), and neither Redis nor the
    /// mirror is written.
    #[tokio::test]
    async fn json_arm_malformed_maps_to_parse_error_fail_closed() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);
        mocks
            .upstream_proxy
            .insert_metadata("", "/simple/flask/", b"{ not valid json".to_vec());

        let err = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "flask",
            SimpleIndexFormat::Json,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, IndexFetchError::MetadataMalformed { .. }),
            "malformed JSON must be parse-class, NOT network/unavailable; got {err:?}"
        );
        // Fail-closed: nothing cached, nothing mirrored.
        let cache_key = format!("pypi_simple_proj:{mapping_id}:flask");
        assert!(mocks
            .ephemeral_evictable
            .get(&cache_key)
            .await
            .unwrap()
            .is_none());
        assert!(mocks.metadata_mirror.keys().is_empty());
    }

    /// A JSON body whose single per-file object exceeds the
    /// per-value cap surfaces as the TYPED `VersionObjectTooLarge` variant
    /// (NOT `MetadataMalformed`), driven by the projector's `cap_trip_flag`
    /// rather than a brittle error-string match. Fail-closed: nothing
    /// cached or mirrored. Mirrors npm's typed cap-trip shape.
    #[tokio::test]
    async fn json_arm_per_file_cap_trip_maps_to_version_object_too_large() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);
        // One file object padded well past the small cap below.
        let huge = "x".repeat(8 * 1024);
        let body =
            format!(r#"{{"files":[{{"filename":"flask-3.0.0.whl","url":"u","_pad":"{huge}"}}]}}"#);
        mocks
            .upstream_proxy
            .insert_metadata("", "/simple/flask/", body.into_bytes());

        let err = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            4 * 1024, // small per-value cap so the padded file object trips it
            &repo,
            "flask",
            SimpleIndexFormat::Json,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, IndexFetchError::VersionObjectTooLarge { .. }),
            "per-file cap trip must be the typed VersionObjectTooLarge, \
             NOT MetadataMalformed; got {err:?}"
        );
        // Fail-closed: nothing cached, nothing mirrored.
        let cache_key = format!("pypi_simple_proj:{mapping_id}:flask");
        assert!(mocks
            .ephemeral_evictable
            .get(&cache_key)
            .await
            .unwrap()
            .is_none());
        assert!(mocks.metadata_mirror.keys().is_empty());
    }

    /// A non-UTF-8 HTML upstream body fails closed the same way.
    #[tokio::test]
    async fn html_arm_malformed_maps_to_parse_error_fail_closed() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);
        mocks
            .upstream_proxy
            .insert_metadata("", "/simple/flask/", vec![0xff, 0xfe, 0x00]);

        let err = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "flask",
            SimpleIndexFormat::Html,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, IndexFetchError::MetadataMalformed { .. }),
            "non-UTF-8 HTML must be parse-class; got {err:?}"
        );
        assert!(mocks.metadata_mirror.keys().is_empty());
    }

    /// Fresh-cache hit returns the cached projection with NO upstream
    /// call (proves serve renders the cached projection, no re-fetch /
    /// no re-parse).
    #[tokio::test]
    async fn fresh_hit_serves_cached_projection_without_upstream() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // Seed a fresh projection cache entry directly (no upstream).
        let seeded = PypiSimpleIndexProjection {
            files: vec![hort_formats::pypi::projection::PypiSimpleFile {
                filename: Some("flask-9.9.9-py3-none-any.whl".into()),
                url: None,
                sha256: Some("seeded".into()),
                requires_python: None,
                metadata_sha256: None,
            }],
        };
        let entry = CachedPypiProjection::from_projection(seeded);
        let cache_key = format!("pypi_simple_proj:{mapping_id}:flask");
        ctx.ephemeral_evictable
            .put(&cache_key, entry.encode(), PYPI_SIMPLE_STALE_TTL)
            .await
            .unwrap();
        // NO upstream metadata inserted — a fetch would fail if attempted.

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "flask",
            SimpleIndexFormat::Json,
        )
        .await
        .expect("fresh hit must serve cached projection without upstream");
        assert_eq!(projection.files.len(), 1);
        assert_eq!(
            projection.files[0].filename.as_deref(),
            Some("flask-9.9.9-py3-none-any.whl")
        );
    }

    /// Stale projection in Redis + upstream down → serve the stale
    /// projection (stale-while-error), no error. Mirrors the npm
    /// (`packument.rs`) and cargo (`index_cache.rs`) stale-fallback
    /// acceptance: a genuine upstream OUTAGE (an `Invariant` error, NOT a
    /// `Validation` parse fault) must NOT be surfaced when a decodable
    /// stale projection is in Redis.
    #[tokio::test]
    async fn fetch_stale_projection_served_on_upstream_error() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // Seed a STALE projection (fetched_at far in the past so it is
        // outside the fresh window but the frame is decodable).
        let seeded = PypiSimpleIndexProjection {
            files: vec![hort_formats::pypi::projection::PypiSimpleFile {
                filename: Some("flask-1.2.3-py3-none-any.whl".into()),
                url: None,
                sha256: Some("stale256".into()),
                requires_python: None,
                metadata_sha256: None,
            }],
        };
        let mut entry = CachedPypiProjection::from_projection(seeded);
        entry.fetched_at = Utc::now() - chrono::Duration::seconds(120);
        let cache_key = format!("pypi_simple_proj:{mapping_id}:flask");
        mocks
            .ephemeral_evictable
            .put(&cache_key, entry.encode(), PYPI_SIMPLE_STALE_TTL)
            .await
            .unwrap();

        // Upstream is down (a network-class outage, NOT a parse fault).
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
            "flask",
            SimpleIndexFormat::Json,
        )
        .await
        .expect("stale projection must be served on upstream error");
        assert_eq!(projection.files.len(), 1);
        assert_eq!(projection.files[0].sha256.as_deref(), Some("stale256"));
    }

    /// No stale projection in Redis + upstream down + mirror present →
    /// re-project from the raw mirror and serve (air-gapped / outage
    /// path). Mirrors the npm / cargo stale-fallback acceptance rung. The
    /// mirror key is FORMAT-DISTINCT (`flask#json`), so the JSON projector
    /// is applied to the stored raw body.
    #[tokio::test]
    async fn fetch_reprojects_from_mirror_when_redis_empty_and_upstream_down() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // Seed only the mirror (no Redis projection), under the JSON
        // format-distinct key.
        let mkey = mirror_key("pypi", &mapping_id.to_string(), "flask#json");
        mocks
            .metadata_mirror
            .put(&mkey, Box::new(std::io::Cursor::new(JSON_BODY.to_vec())))
            .await
            .unwrap();

        // Upstream is down (a network-class outage, NOT a parse fault).
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
            "flask",
            SimpleIndexFormat::Json,
        )
        .await
        .expect("mirror re-projection must serve on upstream error");
        assert_eq!(projection.files.len(), 2);
        assert_eq!(projection.files[0].sha256.as_deref(), Some("jsonwheel256"));
    }
}
