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
//! `mirror_key("pypi", mapping_id, "{normalized}")` — one canonical entry
//! per package (#72 Mode 1). The upstream fetch is unified now (JSON
//! preferred, HTML fallback, content-sniffed), so there is only ever one
//! raw body to mirror; stale-while-error re-projection sniffs the
//! mirrored bytes the same way the fresh-fetch path sniffs a freshly-
//! fetched body.
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

/// Cached negotiation result. `Html` covers PEP 503 (`text/html`) and
/// PEP 691 v1+html — both serialise as HTML; the cache is keyed on this
/// enum's `as_str()` so they share an entry.
///
/// `pub` visibility exists for the `hort-formats-upstream` composition
/// seam only — do not consume from outside `hort-http-pypi` in-crate
/// code OR `hort-formats-upstream`. A fourth caller breaks the dep-graph
/// rationale behind the composition seam (see
/// `docs/architecture/how-to/add-a-format-handler.md`).
///
/// **Only a CLIENT-facing (serve-rendering) discriminator now (#72 Mode
/// 1).** It used to also drive which representation hort requested
/// *from upstream* — that coupling was the Mode-1 bug: a client with no
/// (or an unrecognised) `Accept` header defaulted to `Html`, which sent
/// hort down the buffered, 2 MiB-capped [`HtmlSimpleIndexProjector`] path
/// even though the JSON endpoint was smaller and already had a
/// streaming projector. The upstream fetch now always prefers PEP 691
/// JSON (see [`upstream_accept_json_primary`]) and content-sniffs the
/// actual response to pick the projector (see
/// [`sniff_pypi_simple_format`]) — never assumes a representation from
/// what was requested. `SimpleIndexFormat` still selects which
/// builder (`PypiHtmlIndexBuilder` / `PypiJsonIndexBuilder`) renders the
/// cached, representation-independent projection back to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimpleIndexFormat {
    Html,
    Json,
}

impl SimpleIndexFormat {
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

    // `response_content_type` was deleted: the unified
    // `serve::serve_simple_index_unified` handler emits the per-format
    // `Content-Type` inline (it pinned
    // `application/vnd.pypi.simple.v1+json` / `text/html; charset=utf-8`
    // via a literal `match`).
}

/// Accept-header values ALWAYS sent to upstream for the simple-index
/// fetch, regardless of what format the CLIENT asked hort to render
/// (#72 Mode 1). PEP 691 JSON is requested first — a far smaller body
/// than PEP 503 HTML for a package with many releases, and it already
/// has a streaming projector — with `text/html` listed second so a
/// non-PEP-691 upstream (or one that ignores `Accept` outright) still
/// answers instead of a `406`. The response is never assumed to match
/// this preference; see [`sniff_pypi_simple_format`].
fn upstream_accept_json_primary() -> Vec<String> {
    vec![PEP691_JSON_TYPE.into(), "text/html".into()]
}

/// Content-sniff a fetched simple-index body to decide whether it is
/// PEP 691 JSON or PEP 503 HTML (#72 Mode 1) — never trusts what
/// representation was requested, only what was actually received. A
/// non-PEP-691 upstream may answer with HTML despite the JSON-primary
/// `Accept` (see [`upstream_accept_json_primary`]); sniffing keeps that
/// fallback safe even under `PullDedup` coalescing, where a follower may
/// have originally asked for a different client-facing format than
/// whichever request happened to lead. PEP 691's top-level document is
/// always a JSON object (`{`); anything else — typically PEP 503 HTML's
/// `<!DOCTYPE`/`<html` — is treated as HTML, matching the same
/// fallback-to-HTML default [`SimpleIndexFormat::from_accept`] already
/// uses for an unrecognised `Accept` header.
fn sniff_pypi_simple_format(prefix: &[u8]) -> SimpleIndexFormat {
    match prefix.iter().copied().find(|b| !b.is_ascii_whitespace()) {
        Some(b'{') => SimpleIndexFormat::Json,
        _ => SimpleIndexFormat::Html,
    }
}

/// Async wrapper: sniff the format of a [`CachedBodyHandle`]'s body by
/// reading a small prefix off disk. See [`sniff_pypi_simple_format`].
async fn sniff_cached_body_format(path: &std::path::Path) -> DomainResult<SimpleIndexFormat> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| DomainError::Invariant(format!("pypi simple-index sniff open: {e}")))?;
    let mut buf = [0u8; 64];
    let n = file
        .read(&mut buf)
        .await
        .map_err(|e| DomainError::Invariant(format!("pypi simple-index sniff read: {e}")))?;
    Ok(sniff_pypi_simple_format(&buf[..n]))
}

/// Dispatches to the format-appropriate projector after content-sniffing
/// the actual response body (#72 Mode 1) — the `MetadataProjector` this
/// module drives is always this enum, never a bare
/// [`PypiSimpleIndexProjector`] or [`HtmlSimpleIndexProjector`]
/// directly, so a wrong-format body can never reach the wrong parser.
enum PypiSniffedProjector {
    Json(PypiSimpleIndexProjector),
    Html(HtmlSimpleIndexProjector),
}

impl PypiSniffedProjector {
    fn for_format(format: SimpleIndexFormat, per_value_object_max_bytes: u64) -> Self {
        match format {
            SimpleIndexFormat::Json => {
                Self::Json(PypiSimpleIndexProjector::new(per_value_object_max_bytes))
            }
            SimpleIndexFormat::Html => Self::Html(HtmlSimpleIndexProjector::with_default_cap()),
        }
    }

    /// The JSON variant's per-file-object cap-trip flag — `None` for the
    /// HTML variant, which has no per-file-object cap concept (an
    /// over-cap HTML body trips the whole-body bound instead and
    /// surfaces as a generic malformed-body `Validation`).
    fn cap_trip_flag(&self) -> Option<Arc<std::sync::atomic::AtomicBool>> {
        match self {
            Self::Json(p) => Some(p.cap_trip_flag()),
            Self::Html(_) => None,
        }
    }
}

impl MetadataProjector for PypiSniffedProjector {
    type Projection = PypiSimpleIndexProjection;
    fn project<R: std::io::Read>(self, reader: R) -> DomainResult<PypiSimpleIndexProjection> {
        match self {
            Self::Json(p) => p.project(reader),
            Self::Html(p) => p.project(reader),
        }
    }
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
/// re-parse; the raw mirror (one canonical key per package, #72 Mode 1)
/// is the stale-while-error / air-gapped fallback.
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
/// (`pypi_simple_proj:{mapping.id}:{normalized}`). A fresh hit renders
/// from the cached projection with no upstream call and no re-parse.
/// The raw mirror is ALSO one canonical key per package now (issue #72
/// Mode 1) — `mirror_key("pypi", mapping_id, "{normalized}")` — since
/// the upstream fetch is unified rather than client-format-driven;
/// stale-while-error re-projection sniffs the mirrored bytes to pick the
/// matching projector.
///
/// `mirror` is `Option` so the discovery seam (`hort-formats-upstream`,
/// version-listing only) can pass `None` — it does not serve, so it has
/// no mirror and no stale-while-error need. In-crate serve callers pass
/// `Some(ctx.metadata_mirror.as_ref())`.
/// `per_value_object_max_bytes` is the projector per-object cap.
///
/// **The upstream fetch is now format-independent (#72 Mode 1).** It
/// always requests PEP 691 JSON first (see
/// [`upstream_accept_json_primary`]) — smaller body, streaming projector,
/// no whole-body buffering hazard — and content-sniffs the actual
/// response to pick the projector (see [`sniff_pypi_simple_format`]),
/// falling back to the buffered HTML projector only when upstream
/// actually answers with HTML. This function no longer takes a
/// `SimpleIndexFormat` — the client-facing render format
/// (`serve::serve_simple_index_unified`'s concern) has nothing to do
/// with which representation is fetched from upstream.
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
fn simple_index_dedup_key_url(normalized_project: &str) -> String {
    format!("/simple/{normalized_project}/")
}

/// Mirror-key package segment. No longer format-distinct (#72 Mode 1):
/// there is only ever one canonical upstream fetch per package now (JSON
/// preferred, HTML fallback, auto-detected by content), so there is only
/// one raw body to mirror. The stale-while-error re-projection path
/// content-sniffs the mirrored bytes the same way the fresh-fetch path
/// sniffs a freshly-fetched body — see [`project_from_mirror`].
fn simple_index_mirror_package(normalized_project: &str) -> String {
    normalized_project.to_string()
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    skip(resolver, cache, upstream_proxy, pull_dedup, mirror),
    fields(repo_key = %repo.key, project)
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
    // from artifact CAS) — one canonical entry per package (#72 Mode 1).
    let mkey = mirror_key(
        "pypi",
        &mapping.id.to_string(),
        &simple_index_mirror_package(&normalized),
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
    // projection (not the raw body). The dedup key is no longer
    // format-distinct (#72 Mode 1) — there is only one canonical upstream
    // fetch per package now, and content-sniffing (not the requester's
    // preference) picks the projector, so a coalesced follower can never
    // receive a body parsed with the wrong projector.
    let upstream_path = format!("/simple/{normalized}/");
    let dedup_key = DedupKey::metadata("pypi", repo.id, &simple_index_dedup_key_url(&normalized));
    let mapping_for_closure = mapping.clone();
    let upstream_path_for_closure = upstream_path.clone();
    let mkey_for_closure = mkey.clone();
    // Shared cell the closure populates with the JSON projector's
    // cap-trip flag IF the sniffed body turns out to be JSON. `None`
    // after the coalesce means either the body sniffed as HTML (no
    // per-file-object cap concept) or the closure never ran (follower) —
    // in both cases a `Validation` error classifies as a generic
    // malformed body, not a cap trip.
    let json_cap_flag_cell: Arc<std::sync::Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let json_cap_flag_cell_for_closure = Arc::clone(&json_cap_flag_cell);
    let coalesce_result = pull_dedup
        .coalesce_metadata(dedup_key, move || async move {
            let outcome = upstream_proxy
                .fetch_metadata(
                    mapping_for_closure,
                    upstream_path_for_closure,
                    upstream_accept_json_primary(),
                )
                .await
                .map_err(AppError::from)?;
            let handle = outcome.cache_handle.as_ref().ok_or_else(|| {
                AppError::from(DomainError::Invariant(
                    "pypi fetch_metadata returned no cache_handle".to_string(),
                ))
            })?;
            // #72 Mode 1: sniff the ACTUAL response body — never trust
            // what was requested — to pick the projector.
            let sniffed = sniff_cached_body_format(&handle.path)
                .await
                .map_err(AppError::from)?;
            let projector = PypiSniffedProjector::for_format(sniffed, per_value_object_max_bytes);
            if let Some(flag) = projector.cap_trip_flag() {
                *json_cap_flag_cell_for_closure.lock().unwrap() = Some(flag);
            }
            // PASS 1 validate/project (a malformed body / cap-trip ⇒ Err,
            // nothing committed — fail-closed); PASS 2 streams the raw
            // body into the mirror (valid only) iff a mirror was supplied.
            let projection = project_body(handle, projector, mirror, &mkey_for_closure)
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
                let cap_tripped = json_cap_flag_cell
                    .lock()
                    .unwrap()
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
            // re-projecting avoids an upstream re-fetch. The re-projection
            // sniffs the mirrored bytes the same way the fresh-fetch path
            // sniffs a freshly-fetched body.
            if let Some(m) = mirror {
                if let Ok(Some(reader)) = m.get(&mkey).await {
                    match project_from_mirror(reader, per_value_object_max_bytes).await {
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
/// projector (already sniffed by the caller — see
/// [`sniff_cached_body_format`]), optionally mirroring the raw body
/// (PASS 2). When `mirror` is `Some`, drives
/// [`hort_app::project::fetch_and_project`] (validate-before-commit — a
/// malformed body never reaches the mirror); when `None`, drives
/// [`hort_app::project::project_cached`] (discovery seam — no mirror, no
/// stale need).
async fn project_body(
    handle: &hort_domain::ports::upstream_proxy::CachedBodyHandle,
    projector: PypiSniffedProjector,
    mirror: Option<&dyn MetadataMirrorStore>,
    mkey: &str,
) -> DomainResult<PypiSimpleIndexProjection> {
    match mirror {
        Some(m) => hort_app::project::fetch_and_project(handle, projector, m, mkey).await,
        None => hort_app::project::project_cached(handle, projector).await,
    }
}

/// Re-project a raw simple-index body from the metadata mirror through
/// the format-appropriate streaming projector, content-sniffed from the
/// mirrored bytes themselves (#72 Mode 1) — the mirror is no longer
/// format-distinct, so there is nothing else to key the choice on. Used
/// **only** on the stale-while-error / air-gapped fallback path — off
/// the hot serve path, which never reads the mirror (it renders the
/// cached projection). The mirror reader is read into a buffer here and
/// projected via `Cursor`: the sync `MetadataProjector`
/// (`R: std::io::Read`) cannot take an `AsyncRead` directly, and
/// `tokio-util`'s `SyncIoBridge` needs the `io-util` feature (not enabled
/// workspace-wide). A transient buffer on this cold outage path is
/// acceptable — PyPI simple-index bodies are ~110 KB (JSON) to a few MB
/// (HTML fallback, still far under the 2 MiB HTML-arm cap in the common
/// case).
async fn project_from_mirror(
    mut reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    per_value_object_max_bytes: u64,
) -> DomainResult<PypiSimpleIndexProjection> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .await
        .map_err(|e| DomainError::Invariant(format!("pypi mirror read: {e}")))?;
    let sniffed = sniff_pypi_simple_format(&buf);
    tokio::task::spawn_blocking(move || {
        PypiSniffedProjector::for_format(sniffed, per_value_object_max_bytes)
            .project(std::io::Cursor::new(buf))
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
/// for `OnDistTagMove` (via the shared [`fire_hot_path_trigger`](hort_app::use_cases::prefetch_trigger::fire_hot_path_trigger) helper)
/// and, when the served index would otherwise come back empty, also for
/// `TransitiveDeps` (#72 Mode 2 — see below). For each planned version,
/// spawns a background task that fetches the per-version JSON manifest
/// (`/pypi/{name}/{version}/json`) and drives a
/// [`crate::upstream_pull::try_upstream_file_pull`] per distribution
/// file (sdist + N wheels). The quarantine window elapses *off* the
/// next build's critical path. The trigger never blocks the serve.
///
/// (There is deliberately no `OnIndexFetch` trigger — an implicit
/// prefetch on every anonymous index read would let unauthenticated
/// reads drive upstream fetches; see
/// `hort_domain::entities::repository::PrefetchTrigger`. The Mode-2
/// gate below still requires the repository to have opted in to
/// `TransitiveDeps`; it does not fire unconditionally.)
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
/// `pip install` will pick a version hort has not seen).
///
/// **#72 Mode 2 — `ReleasedOnly` cold-package bootstrap.** Under
/// [`IndexMode::ReleasedOnly`](hort_domain::entities::repository::IndexMode::ReleasedOnly),
/// a package Hort has never released any
/// version of serves an EMPTY index (`filter_served_versions` — the
/// served set is hort-held-and-servable, intersected with upstream).
/// Unlike npm (`npm ci` is URL/tarball-driven), pip resolves strictly
/// against the index it's served, so an empty index is fatal — there is
/// no version for pip to ask a tarball for. The shared
/// [`fire_hot_path_trigger`](hort_app::use_cases::prefetch_trigger::fire_hot_path_trigger)
/// call above only ever plans `OnDistTagMove`,
/// which most pypi-proxy configs (e.g. `pypi-public`) do NOT subscribe
/// to — they subscribe to `TransitiveDeps` instead. When the served
/// index would come back empty, this function ALSO attempts to plan
/// under `TransitiveDeps` for the SAME upstream candidate set.
/// `PrefetchUseCase::plan` is a no-op unless the repository actually
/// subscribes to that trigger, so this adds no behaviour for repos that
/// haven't opted in — it just gives `TransitiveDeps`-only subscribers a
/// path to warming a package they've never seen, which `OnDistTagMove`
/// alone could not reach for them. `PullDedup` at the per-file-pull
/// layer already de-duplicates an operator who enables both triggers
/// (they'd otherwise double-plan the same candidate set).
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
    let project_name_owned = project_name.to_string();
    let versions = versions_from_projection(projection, normalized_name);

    // #72 Mode 2: if this index-serve would come back empty AND the
    // repository subscribes to `TransitiveDeps`, plan + spawn under that
    // trigger for the same candidate set `OnDistTagMove` would use. Runs
    // BEFORE the shared helper below so both checks see the identical
    // `versions`/`pkg_status` inputs; order between the two trigger
    // attempts has no behavioural significance (they target the same
    // per-file pulls, deduplicated by `PullDedup`). The gate + planner
    // call is split into `mode2_cold_index_plan` so it is unit-testable
    // without observing the background spawn.
    if let Some(plan) = mode2_cold_index_plan(ctx, repo, normalized_name, &versions, pkg_status) {
        spawn_prefetch_pulls_pypi(
            ctx,
            repo,
            project_name,
            plan,
            PrefetchTrigger::TransitiveDeps,
        );
    }

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

/// #72 Mode 2 gate + plan: returns `Some(plan)` when this index-serve's
/// served set would otherwise come back empty AND the repository has
/// opted in to the `TransitiveDeps` trigger — `None` when the gate
/// doesn't apply (served set non-empty, `TransitiveDeps` not subscribed,
/// or `prefetch_policy.enabled == false`). Split out from
/// [`fire_prefetch_trigger_pypi`] so the decision is unit-testable
/// without observing the background spawn side effect —
/// `PrefetchUseCase::plan` itself does no I/O (see its own module doc),
/// so this function is pure aside from the metrics `plan()` emits.
fn mode2_cold_index_plan(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    normalized_name: &str,
    versions: &[String],
    pkg_status: &[(String, QuarantineStatus)],
) -> Option<PrefetchPlan> {
    if !repo.prefetch_policy.enabled
        || !repo
            .prefetch_policy
            .triggers
            .contains(&PrefetchTrigger::TransitiveDeps)
    {
        return None;
    }
    let upstream_refs: Vec<&str> = versions.iter().map(String::as_str).collect();
    let served = hort_app::use_cases::index_serve_filter::filter_served_versions(
        &upstream_refs,
        pkg_status,
        repo.index_mode,
        &Pep440Ordering,
    );
    if !served.served.is_empty() {
        return None;
    }
    Some(ctx.prefetch_use_case.plan(
        repo,
        normalized_name,
        PrefetchTrigger::TransitiveDeps,
        &upstream_refs,
        pkg_status,
        &Pep440Ordering,
    ))
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

    /// Historical alpha-walk finding (runbook §7.2): the PEP 503 (HTML)
    /// and PEP 691 (JSON) representations used to need format-distinct
    /// dedup/coalescing keys, because the format actually FETCHED used
    /// to be whatever the requesting client asked for, and a follower
    /// coalescing across formats could receive a body parsed with the
    /// WRONG projector. #72 Mode 1 closes that gap at its root instead:
    /// the upstream fetch is now unified (JSON-preferred, HTML fallback,
    /// content-sniffed from the actual response — see
    /// `sniff_pypi_simple_format`) rather than client-driven, so there is
    /// only ever one canonical dedup key per package, and the projector
    /// choice can never disagree with the body it's applied to regardless
    /// of what any given coalescing follower originally asked for.
    #[test]
    fn simple_index_dedup_key_is_format_independent() {
        let key = simple_index_dedup_key_url("flask");
        assert_eq!(key, "/simple/flask/");
    }

    /// Companion to the dedup-key test: the mirror key collapsed the
    /// same way, for the same reason (one canonical raw body per
    /// package now, not one per client-requested format).
    #[test]
    fn simple_index_mirror_package_is_format_independent() {
        assert_eq!(simple_index_mirror_package("flask"), "flask");
    }

    /// #72 Mode 1: content-sniffing picks the projector from the ACTUAL
    /// body, never from what was requested — this is what makes
    /// coalescing safe without format-distinct keys (see the dedup-key
    /// test above). A JSON body sniffs as JSON regardless of leading
    /// whitespace; anything else (typically PEP 503 HTML) sniffs as
    /// HTML — matching `SimpleIndexFormat::from_accept`'s HTML-default
    /// fallback for an unrecognised representation.
    #[test]
    fn sniff_pypi_simple_format_detects_json_and_falls_back_to_html() {
        assert_eq!(
            sniff_pypi_simple_format(b"{\"files\":[]}"),
            SimpleIndexFormat::Json
        );
        assert_eq!(
            sniff_pypi_simple_format(b"   \n\t{\"files\":[]}"),
            SimpleIndexFormat::Json,
            "leading whitespace before the JSON object must not defeat the sniff"
        );
        assert_eq!(
            sniff_pypi_simple_format(b"<!DOCTYPE html><html></html>"),
            SimpleIndexFormat::Html
        );
        assert_eq!(
            sniff_pypi_simple_format(b""),
            SimpleIndexFormat::Html,
            "an empty body has no JSON opener to detect; falls back to HTML like an \
             unrecognised Accept header does"
        );
    }

    // ===================================================================
    // Projection-caching: serve cache holds the PROJECTION (both arms);
    // raw to the unified mirror; parse-error fail-closed.
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

    /// (a) JSON-sniffed arm: cache miss + valid (JSON) upstream body → the
    /// PROJECTION is cached under the unified key (NOT the raw body), and
    /// the raw body is mirrored under the unified mirror key. The upstream
    /// mock ignores the `Accept` we sent (always JSON-preferred now, #72
    /// Mode 1) and just returns the seeded fixture — `sniff_pypi_simple_format`
    /// is what routes this body to the JSON projector, not the request.
    #[tokio::test]
    async fn json_sniffed_arm_caches_projection_and_mirrors_raw() {
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

        // The mirror holds the RAW JSON body under the unified key.
        let mkey = mirror_key("pypi", &mapping_id.to_string(), "flask");
        let raw = read_mirror(&mocks, &mkey)
            .await
            .expect("mirror raw must be present");
        assert_eq!(
            raw, JSON_BODY,
            "mirror must hold the verbatim raw JSON body"
        );
    }

    /// (a) HTML-sniffed arm (fallback path): cache miss + upstream answers
    /// with HTML despite our JSON-preferred `Accept` (#72 Mode 1 — the mock
    /// upstream ignores `Accept` and returns whatever fixture was seeded,
    /// which is exactly the "non-PEP-691 upstream" case this fallback
    /// exists for) → the PROJECTION is cached under the SAME unified key,
    /// raw mirrored under the SAME unified mirror key.
    #[tokio::test]
    async fn html_sniffed_fallback_arm_caches_projection_and_mirrors_raw() {
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

        // The mirror holds the RAW HTML body under the unified key.
        let mkey = mirror_key("pypi", &mapping_id.to_string(), "flask");
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
        )
        .await
        .expect("stale projection must be served on upstream error");
        assert_eq!(projection.files.len(), 1);
        assert_eq!(projection.files[0].sha256.as_deref(), Some("stale256"));
    }

    /// No stale projection in Redis + upstream down + mirror present →
    /// re-project from the raw mirror and serve (air-gapped / outage
    /// path). Mirrors the npm / cargo stale-fallback acceptance rung. The
    /// mirror holds a JSON body under the one canonical key (#72 Mode 1);
    /// `project_from_mirror` sniffs the mirrored bytes to pick the JSON
    /// projector, rather than trusting a passed-in format.
    #[tokio::test]
    async fn fetch_reprojects_from_mirror_when_redis_empty_and_upstream_down() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // Seed only the mirror (no Redis projection), under the one
        // canonical key.
        let mkey = mirror_key("pypi", &mapping_id.to_string(), "flask");
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
        )
        .await
        .expect("mirror re-projection must serve on upstream error");
        assert_eq!(projection.files.len(), 2);
        assert_eq!(projection.files[0].sha256.as_deref(), Some("jsonwheel256"));
    }

    // ===================================================================
    // #72 Mode 1 acceptance: a large index resolves via JSON+streaming,
    // never hits the old 2 MiB HTML-arm cap. Field parity between the
    // JSON and HTML projections for equivalent content.
    // ===================================================================

    /// Regression guard for the exact production failure mode issue #72
    /// fixed: a package whose full HTML simple-index rendering would
    /// exceed `HTML_SIMPLE_INDEX_MAX_BYTES` (2 MiB — e.g. rapidfuzz's real
    /// upstream HTML index is ~5.3 MiB) used to serve ZERO versions,
    /// because hort fetched HTML and the buffered `HtmlSimpleIndexProjector`
    /// hard-rejects any body over that cap. The upstream fetch is now
    /// JSON-preferred (#72 Mode 1) and the JSON projector has no
    /// whole-body cap (only a per-file-object one, sized generously above
    /// any single PEP 691 file entry) — a JSON body far larger than the
    /// old HTML-arm cap resolves cleanly.
    #[tokio::test]
    async fn large_json_index_over_old_html_arm_cap_resolves_successfully() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        // Build a `files[]` array whose serialised JSON comfortably
        // exceeds 2 MiB — an HTML rendering of equivalent content would
        // have been rejected by `HTML_SIMPLE_INDEX_MAX_BYTES`.
        let mut files = String::new();
        for i in 0..20_000u32 {
            if i > 0 {
                files.push(',');
            }
            files.push_str(&format!(
                r#"{{"filename":"rapidfuzz-1.0.{i}-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/{i}/rapidfuzz-1.0.{i}-py3-none-any.whl","hashes":{{"sha256":"{i:0>64}"}}}}"#,
            ));
        }
        let body = format!(r#"{{"files":[{files}]}}"#);
        assert!(
            body.len() > crate::html_projection::HTML_SIMPLE_INDEX_MAX_BYTES as usize,
            "fixture must exceed the old HTML-arm whole-body cap to prove the regression \
             guard is meaningful; got {} bytes",
            body.len()
        );
        mocks
            .upstream_proxy
            .insert_metadata("", "/simple/rapidfuzz/", body.into_bytes());

        let projection = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            cap(),
            &repo,
            "rapidfuzz",
        )
        .await
        .expect("a large JSON index must resolve, not hard-reject");
        assert_eq!(projection.files.len(), 20_000);
    }

    /// #72 Mode 1 field-parity: the JSON and HTML projectors extract the
    /// SAME logical fields from equivalent upstream content — filename,
    /// `hashes.sha256` (ADR 0006, load-bearing), `requires-python`, and
    /// the PEP 658 `dist-info-metadata` hash. `url` is a known, pre-
    /// existing asymmetry (PEP 691 carries a genuine upstream `url`; PEP
    /// 503 HTML anchors don't, so the HTML projector always leaves it
    /// `None`) — not a regression this change introduces. `data-yanked`
    /// is verified ABSENT from both projections — it was never extracted
    /// by either arm before this change, so the JSON-fetch switch
    /// introduces no regression on that field either; adding yanked
    /// support is a distinct, larger feature (a new projection field plus
    /// builder changes) outside this fix's scope.
    #[test]
    fn json_and_html_projectors_extract_equivalent_fields() {
        use hort_domain::ports::upstream_proxy::MetadataProjector;

        let json_body = br#"{"files":[
            {"filename":"parity-1.0.0-py3-none-any.whl",
             "url":"https://files.pythonhosted.org/packages/ab/parity-1.0.0-py3-none-any.whl",
             "hashes":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
             "requires-python":">=3.9",
             "dist-info-metadata":{"sha256":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}}
        ]}"#;
        let html_body = br#"<!DOCTYPE html><html><body>
            <a href="https://files.pythonhosted.org/packages/ab/parity-1.0.0-py3-none-any.whl#sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
               data-requires-python="&gt;=3.9"
               data-dist-info-metadata="sha256=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff">parity-1.0.0-py3-none-any.whl</a>
            </body></html>"#;

        let json_proj = PypiSimpleIndexProjector::new(cap())
            .project(std::io::Cursor::new(json_body.as_slice()))
            .expect("json parity fixture must parse");
        let html_proj = HtmlSimpleIndexProjector::with_default_cap()
            .project(std::io::Cursor::new(html_body.as_slice()))
            .expect("html parity fixture must parse");

        assert_eq!(json_proj.files.len(), 1);
        assert_eq!(html_proj.files.len(), 1);
        let j = &json_proj.files[0];
        let h = &html_proj.files[0];

        assert_eq!(j.filename, h.filename, "filename must match between arms");
        assert_eq!(
            j.sha256, h.sha256,
            "hashes.sha256 (ADR 0006 upstream checksum) must match between arms"
        );
        assert_eq!(
            j.requires_python, h.requires_python,
            "requires-python must match between arms"
        );
        assert_eq!(
            j.metadata_sha256, h.metadata_sha256,
            "PEP 658 dist-info-metadata hash must match between arms"
        );

        // Known, pre-existing asymmetry — not a regression.
        assert!(
            j.url.is_some(),
            "PEP 691 JSON carries a genuine upstream url"
        );
        assert!(
            h.url.is_none(),
            "PEP 503 HTML anchors carry no genuine upstream url field"
        );
    }

    // ===================================================================
    // #72 Mode 2: `ReleasedOnly` cold-index-serve prefetch bootstrap.
    // ===================================================================

    use hort_domain::entities::repository::{IndexMode, PrefetchPolicy};

    fn cold_repo(triggers: Vec<PrefetchTrigger>, index_mode: IndexMode) -> Repository {
        let mut r = proxy_pypi_repo("pypi-public");
        r.index_mode = index_mode;
        r.prefetch_policy = PrefetchPolicy {
            enabled: true,
            triggers,
            depth: 3,
            transitive_depth: 5,
            max_age_days: None,
            max_descendants: PrefetchPolicy::default().max_descendants,
        };
        r
    }

    /// The core Mode 2 fix: a `ReleasedOnly` proxy that has never held any
    /// version of this package (cold — `pkg_status` empty) serves an
    /// EMPTY index. A repo subscribed to `TransitiveDeps` (the trigger
    /// `pypi-public`-shaped configs actually use — NOT `OnDistTagMove`)
    /// must still get a plan for the upstream candidate set.
    #[tokio::test]
    async fn mode2_plans_under_transitive_deps_for_cold_released_only_repo() {
        let (ctx, _mocks) = build_mock_ctx(handle());
        let repo = cold_repo(
            vec![PrefetchTrigger::TransitiveDeps],
            IndexMode::ReleasedOnly,
        );
        let versions = vec!["1.0.0".to_string(), "1.1.0".to_string()];

        let plan = mode2_cold_index_plan(&ctx, &repo, "rapidfuzz", &versions, &[])
            .expect("a cold ReleasedOnly repo subscribed to TransitiveDeps must get a plan");
        assert!(
            !plan.versions.is_empty(),
            "the plan must contain at least one candidate version"
        );
    }

    /// Negative case: the repo subscribes only to `OnDistTagMove`, not
    /// `TransitiveDeps` — Mode 2 must NOT fire (it would otherwise
    /// silently prefetch for a repo that never opted in to the trigger
    /// this gate uses).
    #[tokio::test]
    async fn mode2_does_not_fire_when_transitive_deps_not_subscribed() {
        let (ctx, _mocks) = build_mock_ctx(handle());
        let repo = cold_repo(
            vec![PrefetchTrigger::OnDistTagMove],
            IndexMode::ReleasedOnly,
        );
        let versions = vec!["1.0.0".to_string()];

        assert!(
            mode2_cold_index_plan(&ctx, &repo, "rapidfuzz", &versions, &[]).is_none(),
            "must not plan when the repo hasn't subscribed to TransitiveDeps"
        );
    }

    /// Negative case: the served set is NOT empty (hort already holds a
    /// servable version) — Mode 2 must not re-plan what's already served.
    #[tokio::test]
    async fn mode2_does_not_fire_when_served_set_is_non_empty() {
        let (ctx, _mocks) = build_mock_ctx(handle());
        let repo = cold_repo(
            vec![PrefetchTrigger::TransitiveDeps],
            IndexMode::ReleasedOnly,
        );
        let versions = vec!["1.0.0".to_string()];
        let pkg_status = vec![("1.0.0".to_string(), QuarantineStatus::Released)];

        assert!(
            mode2_cold_index_plan(&ctx, &repo, "rapidfuzz", &versions, &pkg_status).is_none(),
            "must not re-plan a version that is already held and servable"
        );
    }

    /// Negative case: `prefetch_policy.enabled == false` — Mode 2 must
    /// not fire regardless of trigger subscription (mirrors the shared
    /// `fire_hot_path_trigger`'s own disabled-policy early exit).
    #[tokio::test]
    async fn mode2_does_not_fire_when_prefetch_policy_disabled() {
        let (ctx, _mocks) = build_mock_ctx(handle());
        let mut repo = cold_repo(
            vec![PrefetchTrigger::TransitiveDeps],
            IndexMode::ReleasedOnly,
        );
        repo.prefetch_policy.enabled = false;
        let versions = vec!["1.0.0".to_string()];

        assert!(
            mode2_cold_index_plan(&ctx, &repo, "rapidfuzz", &versions, &[]).is_none(),
            "must not plan when prefetch_policy.enabled is false"
        );
    }

    /// Under `IndexMode::IncludePending`, a cold (never-ingested) package
    /// is NOT actually empty-served — upstream's full catalog stays
    /// advertised (the IncludePending trade-off). Mode 2 must not fire
    /// here; there is no empty-index problem to solve under this mode.
    #[tokio::test]
    async fn mode2_does_not_fire_under_include_pending_for_cold_package() {
        let (ctx, _mocks) = build_mock_ctx(handle());
        let repo = cold_repo(
            vec![PrefetchTrigger::TransitiveDeps],
            IndexMode::IncludePending,
        );
        let versions = vec!["1.0.0".to_string()];

        assert!(
            mode2_cold_index_plan(&ctx, &repo, "rapidfuzz", &versions, &[]).is_none(),
            "IncludePending already advertises never-ingested upstream versions; \
             Mode 2's empty-index gate must not apply"
        );
    }
}
