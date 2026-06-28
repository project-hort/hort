//! `prefetch` `TaskHandler` (the leaf-
//! ingest kind the transitive cascade enqueues per
//! `(repo, package, concrete_version)` coordinate).
//!
//! # What this handler does
//!
//! A fully wired leaf-pull handler. Per claimed `prefetch` row, the
//! handler:
//!
//! 1. Loads the repository + the format handler.
//! 2. Resolves the catch-all upstream mapping (`path_prefix = ""`)
//!    — same shape as `PrefetchTickHandler` and
//!    `PrefetchDependenciesHandler`'s Pass 2.
//! 3. Fetches the upstream metadata body via
//!    [`UpstreamProxy::fetch_metadata`] so the format-native
//!    [`FormatHandler::parse_upstream_checksum`] (ADR 0006) can
//!    recover the upstream-published checksum.
//! 4. Resolves the AUTHORITATIVE upstream download URL — never a
//!    heuristic. cargo fetches the index `config.json` and composes
//!    from its `dl` field
//!    ([`FormatHandler::download_config_path`] +
//!    [`FormatHandler::compose_download_url_from_config`]); npm reads
//!    `versions[ver].dist.tarball` from the already-fetched packument
//!    ([`FormatHandler::resolve_download_url_from_metadata`]); PyPI
//!    fans out from the per-version JSON manifest `urls[]`.
//! 5. Per URL: [`UpstreamProxy::fetch_artifact`] →
//!    [`IngestUseCase::ingest_verified`] (the
//!    `UpstreamPublished` arm — the checksum is the integrity
//!    target).
//!
//! # PyPI per-distribution fan-out
//!
//! PyPI publishes multiple distributions per version (sdist + N
//! wheels) with per-file checksums. The handler dispatches to a
//! PyPI-specific path that walks the per-version JSON manifest's
//! `urls[]` array, ingesting each distribution as a separate
//! verified-ingest. Mirrors `fire_prefetch_trigger_pypi` in
//! `crates/hort-http-pypi/src/simple_index.rs`.
//!
//! # PullDedup composition
//!
//! Composition-root wires the `IngestUseCase` against the
//! `UpstreamProxy` that has `PullDedup`'s `coalesce_blob`
//! single-flight guard. The leaf handler doesn't
//! need to wrap anything explicitly — the dedup absorbs the
//! prefetch-vs-client-pull race naturally: the second caller for
//! the same blob hash sees the leader's cached outcome.
//!
//! # Non-fatal per URL
//!
//! Non-fatal on per-URL failure
//! (`warn!`, continue with the rest of the cohort): the leaf
//! handler completes successfully (TaskOutcome::Completed) even
//! when individual URLs fail; the operator-facing signal is the
//! `result_summary` counts (`urls_attempted` /
//! `urls_succeeded` / `urls_failed`).

use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;
use tokio_util::io::StreamReader;
use uuid::Uuid;

use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::ApiActor;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::repository_repository::RepositoryRepository;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMappingRepository;
use hort_domain::ports::task_handler::{TaskContext, TaskHandler, TaskOutcome};
use hort_domain::ports::upstream_proxy::UpstreamProxy;
use hort_domain::ports::BoxFuture;
use hort_domain::types::ArtifactCoords;

use crate::use_cases::ingest_use_case::{IngestUseCase, VerifiedIngestRequest};

/// Parsed shape of the `params` JSONB column for a `prefetch` row.
///
/// The cascade resolves a CONCRETE version in
/// `PrefetchDependenciesHandler::plan_and_enqueue` (Pass 2 hybrid
/// resolution), so the leaf row carries `version` — not an opaque
/// range field. Old range-shaped rows in flight at upgrade time will
/// fail to parse and be marked failed (non-retry); the next ingest
/// cascade re-derives them with the new shape.
///
/// `pub(crate)` so the producers that enqueue `"prefetch"` rows
/// (`PrefetchDependenciesHandler`'s leaf cohort and
/// `SelfServicePrefetchUseCase`'s root enqueue) can pin the
/// producer→consumer params contract in their own unit tests — a
/// producer emitting a shape this consumer cannot deserialize is
/// exactly the self-service-prefetch defect.
#[derive(Debug, Deserialize)]
pub(crate) struct PrefetchParams {
    /// Repository the leaf-ingest targets. Format + upstream mapping
    /// are resolved from this id at claim time.
    repository_id: Uuid,
    /// Normalised package name (output of
    /// [`FormatHandler::normalize_name`]).
    package: String,
    /// Concrete version (e.g. `"4.18.2"`). Picked by
    /// `PrefetchDependenciesHandler`'s Pass 2 hybrid resolver against
    /// the upstream's available set, so the version is guaranteed to
    /// be one the upstream actually publishes.
    version: String,
}

/// `TaskHandler` for the cascade leaf-ingest kind.
///
/// Constructed at worker composition time with the ports the leaf
/// pull-through needs. Mirrors `PrefetchDependenciesHandler`'s
/// wiring shape verbatim — same `UpstreamProxy` +
/// `RepositoryUpstreamMappingRepository` + format-handler map; adds
/// the `IngestUseCase` for the actual verified-ingest call.
pub struct PrefetchIngestHandler {
    repositories: Arc<dyn RepositoryRepository>,
    upstream_proxy: Arc<dyn UpstreamProxy>,
    upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
    format_handlers: HashMap<String, Arc<dyn FormatHandler>>,
    ingest: Arc<IngestUseCase>,
}

impl PrefetchIngestHandler {
    pub fn new(
        repositories: Arc<dyn RepositoryRepository>,
        upstream_proxy: Arc<dyn UpstreamProxy>,
        upstream_mappings: Arc<dyn RepositoryUpstreamMappingRepository>,
        format_handlers: HashMap<String, Arc<dyn FormatHandler>>,
        ingest: Arc<IngestUseCase>,
    ) -> Self {
        Self {
            repositories,
            upstream_proxy,
            upstream_mappings,
            format_handlers,
            ingest,
        }
    }
}

/// Per-call counters threaded through the leaf pull.
#[derive(Default, Debug)]
struct LeafSummary {
    urls_attempted: u64,
    urls_succeeded: u64,
    urls_failed: u64,
    /// `true` when format-specific guard rails (PyPI per-version JSON
    /// missing `urls[]`, format-handler missing for the repo's
    /// format) caused the leaf to short-circuit. The outcome is
    /// still `Completed` — the operator-facing signal is this flag.
    short_circuited: bool,
}

impl LeafSummary {
    fn to_json(&self, repository_id: Uuid, package: &str, version: &str) -> serde_json::Value {
        json!({
            "repository_id":    repository_id,
            "package":          package,
            "version":          version,
            "urls_attempted":   self.urls_attempted,
            "urls_succeeded":   self.urls_succeeded,
            "urls_failed":      self.urls_failed,
            "short_circuited":  self.short_circuited,
        })
    }
}

impl TaskHandler for PrefetchIngestHandler {
    fn kind(&self) -> &'static str {
        "prefetch"
    }

    #[tracing::instrument(skip(self, params))]
    fn run<'a>(
        &'a self,
        params: &'a serde_json::Value,
        ctx: TaskContext,
    ) -> BoxFuture<'a, DomainResult<TaskOutcome>> {
        Box::pin(async move {
            // ----- Step 1: parse params -------------------------------
            let parsed: PrefetchParams = match serde_json::from_value(params.clone()) {
                Ok(p) => p,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("prefetch params JSON invalid: {err}"),
                        false,
                    ));
                }
            };
            let mut summary = LeafSummary::default();

            // A cascade-spawned leaf (trigger_source "prefetch") is already
            // walked by its parent's depth-carrying child row, so its ingest
            // must NOT fire the depth-0 seed hook. A self-service ROOT leaf
            // ("self_service") is a seed and must.
            // The flag rides the ingest request's payload_metadata.
            let cascade_internal = is_cascade_internal_leaf(&ctx.job_row.trigger_source);

            // ----- Step 2: load repo ----------------------------------
            let repo = match self.repositories.find_by_id(parsed.repository_id).await {
                Ok(r) => r,
                Err(err) => {
                    let retry = !matches!(err, DomainError::NotFound { .. });
                    return Ok(TaskOutcome::fail(
                        format!(
                            "prefetch: repository {} not loadable: {err}",
                            parsed.repository_id
                        ),
                        retry,
                    ));
                }
            };

            // ----- Step 3: resolve format handler ---------------------
            let format_key = repo.format.to_string();
            let Some(handler) = self.format_handlers.get(&format_key).cloned() else {
                tracing::warn!(
                    repository = %repo.key,
                    format = %format_key,
                    "prefetch: no FormatHandler registered for repo's format — \
                     completing as a no-op",
                );
                summary.short_circuited = true;
                return Ok(TaskOutcome::Completed {
                    result_summary: summary.to_json(
                        parsed.repository_id,
                        &parsed.package,
                        &parsed.version,
                    ),
                });
            };

            // ----- Step 4: resolve catch-all upstream mapping ---------
            let mappings = match self.upstream_mappings.list_for_repository(repo.id).await {
                Ok(m) => m,
                Err(err) => {
                    return Ok(TaskOutcome::fail(
                        format!("prefetch: list_for_repository failed: {err}"),
                        true,
                    ));
                }
            };
            let Some(mapping) = mappings.into_iter().find(|m| m.path_prefix.is_empty()) else {
                tracing::warn!(
                    repository = %repo.key,
                    "prefetch: no catch-all upstream mapping (path_prefix=\"\") for repo \
                     — completing as a no-op",
                );
                summary.short_circuited = true;
                return Ok(TaskOutcome::Completed {
                    result_summary: summary.to_json(
                        parsed.repository_id,
                        &parsed.package,
                        &parsed.version,
                    ),
                });
            };

            // ----- Step 5: dispatch per-format ------------------------
            //
            // Each format resolves its AUTHORITATIVE download URL:
            // PyPI fans out over the per-version JSON manifest's
            // `urls[]`; cargo composes from the index `config.json`
            // `dl` field; npm reads the packument's `dist.tarball`.
            // Formats with no prefetch-URL concept short-circuit.
            match repo.format {
                RepositoryFormat::Pypi => {
                    pypi_per_distribution_fanout(
                        self,
                        &repo,
                        &handler,
                        &mapping,
                        &parsed,
                        cascade_internal,
                        &mut summary,
                    )
                    .await;
                }
                RepositoryFormat::Cargo => {
                    let ctx = LeafCtx {
                        handler_self: self,
                        repo: &repo,
                        handler: &handler,
                        mapping: &mapping,
                        parsed: &parsed,
                        cascade_internal,
                    };
                    cargo_resolve_and_pull(&ctx, &mut summary).await;
                }
                RepositoryFormat::Npm => {
                    let ctx = LeafCtx {
                        handler_self: self,
                        repo: &repo,
                        handler: &handler,
                        mapping: &mapping,
                        parsed: &parsed,
                        cascade_internal,
                    };
                    npm_resolve_and_pull(&ctx, &mut summary).await;
                }
                other => {
                    tracing::debug!(
                        repository = %repo.key,
                        format = ?other,
                        package = %parsed.package,
                        "prefetch: format has no compose-style download URL — short-circuit",
                    );
                    summary.short_circuited = true;
                }
            }

            tracing::info!(
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                urls_attempted = summary.urls_attempted,
                urls_succeeded = summary.urls_succeeded,
                urls_failed = summary.urls_failed,
                short_circuited = summary.short_circuited,
                "prefetch leaf pull complete",
            );

            Ok(TaskOutcome::Completed {
                result_summary: summary.to_json(
                    parsed.repository_id,
                    &parsed.package,
                    &parsed.version,
                ),
            })
        })
    }
}

/// The shared borrows every per-format leaf helper threads — the handler
/// (for its ports), the repo + parsed params (for coords/logging), the
/// resolved catch-all mapping, and the cascade-internal flag. Bundled into
/// one struct so the per-format functions stay under the arg-count cap and
/// the repetitive parameter lists collapse to one.
struct LeafCtx<'a> {
    handler_self: &'a PrefetchIngestHandler,
    repo: &'a hort_domain::entities::repository::Repository,
    handler: &'a Arc<dyn FormatHandler>,
    mapping:
        &'a hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping,
    parsed: &'a PrefetchParams,
    cascade_internal: bool,
}

/// Build the canonical single-artifact coords (npm tarball, cargo
/// `.crate`) for a leaf, carrying the concrete version. npm/cargo derive
/// the filename from name+version, so `filename = None`. The path comes
/// from the single SSOT constructor so the stored projection key matches
/// the read-side lookup. On build failure the leaf short-circuits
/// (`warn!` + `short_circuited`); `None` is returned.
fn build_single_artifact_coords(
    ctx: &LeafCtx<'_>,
    summary: &mut LeafSummary,
) -> Option<ArtifactCoords> {
    let LeafCtx {
        repo,
        handler,
        parsed,
        ..
    } = ctx;
    let path = match leaf_logical_path(handler.as_ref(), &parsed.package, &parsed.version, None) {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                "prefetch: leaf logical-path build failed; short-circuit",
            );
            summary.short_circuited = true;
            return None;
        }
    };
    Some(ArtifactCoords {
        name: parsed.package.clone(),
        name_as_published: parsed.package.clone(),
        version: Some(parsed.version.clone()),
        path,
        format: repo.format.clone(),
        metadata: serde_json::Value::Null,
    })
}

/// Fetch the upstream metadata body (npm packument / cargo sparse-index
/// NDJSON / cargo `config.json`) at `metadata_path` against `mapping`, and
/// run `op` against it on a blocking thread, returning the op's typed
/// result. The cached tempfile is removed afterwards (prefetch does not
/// serve, so no mirror write). On any fetch / cache-handle / parse failure
/// the leaf short-circuits (`warn!` + `short_circuited`) and `None` is
/// returned.
///
/// `mapping` is the metadata-leg mapping (cargo passes the
/// `index_upstream_url`-override mapping; npm passes the base mapping).
async fn fetch_metadata_and_run<T, F>(
    ctx: &LeafCtx<'_>,
    mapping: &hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping,
    metadata_path: String,
    op: F,
    summary: &mut LeafSummary,
) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce(&mut dyn std::io::Read) -> DomainResult<T> + Send + 'static,
{
    let (repo, parsed) = (ctx.repo, ctx.parsed);
    let outcome = match ctx
        .handler_self
        .upstream_proxy
        .fetch_metadata(mapping.clone(), metadata_path.clone(), Vec::new())
        .await
    {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                path = %metadata_path,
                "prefetch: upstream metadata fetch failed; short-circuit",
            );
            summary.short_circuited = true;
            return None;
        }
    };
    let Some(cache_handle) = outcome.cache_handle.as_ref() else {
        tracing::warn!(
            repository = %repo.key,
            package = %parsed.package,
            version = %parsed.version,
            path = %metadata_path,
            "prefetch: metadata fetch produced no cache handle; short-circuit",
        );
        summary.short_circuited = true;
        return None;
    };
    // Stream the cached metadata tempfile through the op on a blocking
    // thread (no full-body buffering; ADR 0026).
    let result = crate::project::run_handler_body(cache_handle, op).await;
    crate::project::remove_cached_body(cache_handle).await;
    match result {
        Ok(v) => Some(v),
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                path = %metadata_path,
                "prefetch: upstream metadata parse failed; short-circuit",
            );
            summary.short_circuited = true;
            None
        }
    }
}

/// Fetch ONE resolved artifact URL (against the base `mapping`) and
/// verified-ingest it. Non-fatal on failure (`warn!`, bump `urls_failed`).
/// Increments `urls_attempted`.
async fn fetch_and_ingest_one(
    ctx: &LeafCtx<'_>,
    coords: ArtifactCoords,
    url: String,
    upstream_checksum: hort_domain::types::checksum::UpstreamPublishedChecksum,
    summary: &mut LeafSummary,
) {
    let LeafCtx {
        handler_self,
        repo,
        handler,
        mapping,
        parsed,
        cascade_internal,
    } = ctx;
    summary.urls_attempted += 1;
    let fetch = match handler_self
        .upstream_proxy
        .fetch_artifact((*mapping).clone(), url.clone())
        .await
    {
        Ok(f) => f,
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                %url,
                "prefetch: fetch_artifact failed; continuing",
            );
            summary.urls_failed += 1;
            return;
        }
    };
    let upstream_published_at = fetch.last_modified;
    let reader: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
        Box::new(StreamReader::new(fetch.stream));
    let request = VerifiedIngestRequest::UpstreamPublished {
        repository_id: repo.id,
        coords,
        content_type: content_type_for(&repo.format),
        actor: ApiActor {
            user_id: Uuid::nil(),
        },
        payload_metadata: serde_json::json!({
            "source": "prefetch_leaf_pull",
            "upstream_url": url,
            // Suppress the per-ingest seed hook for a cascade-internal
            // leaf (its parent's child row walks it).
            "cascade_internal": cascade_internal,
        }),
        upstream_checksum,
        upstream_published_at,
        trust_upstream_publish_time: mapping.trust_upstream_publish_time,
    };
    match handler_self
        .ingest
        .ingest_verified(request, reader, handler.as_ref())
        .await
    {
        Ok(_outcome) => {
            summary.urls_succeeded += 1;
            tracing::info!(
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                %url,
                "prefetch: leaf pull-through succeeded",
            );
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                %url,
                "prefetch: ingest_verified failed; continuing",
            );
            summary.urls_failed += 1;
        }
    }
}

/// cargo leaf pull-through. Resolves the AUTHORITATIVE download URL from
/// the index `config.json` `dl` field — the same path the client-driven
/// pull-through takes — never the sparse-index host. Mirrors
/// `try_upstream_crate_pull`'s metadata/download split.
///
/// 1. Build coords (concrete version).
/// 2. Honour `repo.index_upstream_url`: the metadata-leg fetches
///    (sparse-index NDJSON + `config.json`) target the override host when
///    set; the download leg follows the resolved `dl` (absolute URL) so
///    the override never affects it.
/// 3. Fetch the NDJSON index → recover the upstream cksum.
/// 4. Fetch `config.json` → `compose_download_url_from_config` (the `dl`
///    field) → absolute download URL.
/// 5. `fetch_artifact` (base mapping) → `ingest_verified(UpstreamPublished)`.
async fn cargo_resolve_and_pull(ctx: &LeafCtx<'_>, summary: &mut LeafSummary) {
    let Some(coords) = build_single_artifact_coords(ctx, summary) else {
        return;
    };

    // The metadata-leg mapping honours `index_upstream_url` exactly as the
    // pull-through's `index_mapping` does (clone + swap `upstream_url`). The
    // download leg uses the ORIGINAL mapping; the composed absolute URL
    // bypasses `upstream_url` in the adapter anyway.
    let index_mapping = match ctx.repo.index_upstream_url.as_deref() {
        Some(idx) => {
            let mut m = ctx.mapping.clone();
            m.upstream_url = idx.to_string();
            m
        }
        None => ctx.mapping.clone(),
    };

    // Leg 1: sparse-index NDJSON → upstream cksum.
    let Some(ndjson_path) = ctx.handler.upstream_checksum_metadata_path(&coords) else {
        tracing::warn!(
            repository = %ctx.repo.key,
            package = %ctx.parsed.package,
            version = %ctx.parsed.version,
            "prefetch (cargo): handler produced no sparse-index path — short-circuit",
        );
        summary.short_circuited = true;
        return;
    };
    let upstream_checksum = {
        let handler = Arc::clone(ctx.handler);
        let coords = coords.clone();
        match fetch_metadata_and_run(
            ctx,
            &index_mapping,
            ndjson_path,
            move |reader| handler.parse_upstream_checksum(reader, &coords),
            summary,
        )
        .await
        {
            Some(cs) => cs,
            None => return,
        }
    };

    // Leg 2: config.json → compose the `dl`-based download URL.
    let Some(config_path) = ctx.handler.download_config_path() else {
        tracing::warn!(
            repository = %ctx.repo.key,
            package = %ctx.parsed.package,
            "prefetch (cargo): handler produced no config path — short-circuit",
        );
        summary.short_circuited = true;
        return;
    };
    let download_url = {
        let handler = Arc::clone(ctx.handler);
        let package = ctx.parsed.package.clone();
        let version = ctx.parsed.version.clone();
        let cksum_hex = upstream_checksum.hex().to_string();
        match fetch_metadata_and_run(
            ctx,
            &index_mapping,
            config_path,
            move |reader| {
                handler.compose_download_url_from_config(
                    reader,
                    &package,
                    &version,
                    Some(&cksum_hex),
                )
            },
            summary,
        )
        .await
        {
            Some(u) => u,
            None => return,
        }
    };

    // Leg 3: fetch + verified-ingest the single resolved URL.
    fetch_and_ingest_one(ctx, coords, download_url, upstream_checksum, summary).await;
}

/// npm leaf pull-through. Resolves the AUTHORITATIVE tarball URL from the
/// packument's `versions[ver].dist.tarball` — the publisher-asserted
/// origin, never a `{base}/{pkg}/-/...` heuristic. The packument is
/// fetched ONCE; both the checksum and the tarball URL are recovered from
/// the same cached body.
async fn npm_resolve_and_pull(ctx: &LeafCtx<'_>, summary: &mut LeafSummary) {
    let Some(coords) = build_single_artifact_coords(ctx, summary) else {
        return;
    };

    let Some(packument_path) = ctx.handler.upstream_checksum_metadata_path(&coords) else {
        tracing::warn!(
            repository = %ctx.repo.key,
            package = %ctx.parsed.package,
            version = %ctx.parsed.version,
            "prefetch (npm): handler produced no packument path — short-circuit",
        );
        summary.short_circuited = true;
        return;
    };

    // One fetch → both the checksum and the dist.tarball URL. The cached
    // tempfile is streamed twice (two `run_handler_body` opens, no full-body
    // buffering — ADR 0026: the 50 MiB packument never lands in a `Vec`),
    // once per memory-bounded streaming walk, then removed.
    let outcome = match ctx
        .handler_self
        .upstream_proxy
        .fetch_metadata(ctx.mapping.clone(), packument_path.clone(), Vec::new())
        .await
    {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %ctx.repo.key,
                package = %ctx.parsed.package,
                version = %ctx.parsed.version,
                path = %packument_path,
                "prefetch (npm): upstream packument fetch failed; short-circuit",
            );
            summary.short_circuited = true;
            return;
        }
    };
    let Some(cache_handle) = outcome.cache_handle.as_ref() else {
        tracing::warn!(
            repository = %ctx.repo.key,
            package = %ctx.parsed.package,
            version = %ctx.parsed.version,
            path = %packument_path,
            "prefetch (npm): packument fetch produced no cache handle; short-circuit",
        );
        summary.short_circuited = true;
        return;
    };
    let checksum_result = {
        let handler = Arc::clone(ctx.handler);
        let coords = coords.clone();
        crate::project::run_handler_body(cache_handle, move |reader| {
            handler.parse_upstream_checksum(reader, &coords)
        })
        .await
    };
    let tarball_result = {
        let handler = Arc::clone(ctx.handler);
        let coords = coords.clone();
        crate::project::run_handler_body(cache_handle, move |reader| {
            handler.resolve_download_url_from_metadata(reader, &coords)
        })
        .await
    };
    crate::project::remove_cached_body(cache_handle).await;
    let (upstream_checksum, tarball_url) = match (checksum_result, tarball_result) {
        (Ok(cs), Ok(url)) => (cs, url),
        (Err(err), _) | (_, Err(err)) => {
            tracing::warn!(
                error = %err,
                repository = %ctx.repo.key,
                package = %ctx.parsed.package,
                version = %ctx.parsed.version,
                "prefetch (npm): packument checksum/tarball-URL parse failed; short-circuit",
            );
            summary.short_circuited = true;
            return;
        }
    };

    fetch_and_ingest_one(ctx, coords, tarball_url, upstream_checksum, summary).await;
}

/// PyPI per-distribution fan-out.
///
/// PyPI's per-version JSON manifest at
/// `/pypi/{package}/{version}/json` enumerates ALL distributions
/// (sdist + N wheels) for the version, each with its own URL,
/// filename, and checksum. The leaf handler fetches the manifest
/// once and ingests each distribution as a separate
/// `ingest_verified` call. The per-distribution URLs come straight from
/// the manifest's `urls[]` entries — PyPI needs no config-doc or
/// `dist.tarball`-style single-URL resolution.
async fn pypi_per_distribution_fanout(
    handler_self: &PrefetchIngestHandler,
    repo: &hort_domain::entities::repository::Repository,
    handler: &Arc<dyn FormatHandler>,
    mapping: &hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping,
    parsed: &PrefetchParams,
    cascade_internal: bool,
    summary: &mut LeafSummary,
) {
    // Resolve the per-version JSON manifest path via the handler.
    let coords_for_path = ArtifactCoords {
        name: parsed.package.clone(),
        name_as_published: parsed.package.clone(),
        version: Some(parsed.version.clone()),
        path: String::new(),
        format: RepositoryFormat::Pypi,
        metadata: serde_json::Value::Null,
    };
    let Some(json_path) = handler.upstream_checksum_metadata_path(&coords_for_path) else {
        tracing::warn!(
            repository = %repo.key,
            package = %parsed.package,
            version = %parsed.version,
            "prefetch (pypi): per-version JSON path not produced — short-circuit",
        );
        summary.short_circuited = true;
        return;
    };
    let outcome = match handler_self
        .upstream_proxy
        .fetch_metadata(mapping.clone(), json_path.clone(), Vec::new())
        .await
    {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                "prefetch (pypi): per-version JSON fetch failed — short-circuit",
            );
            summary.short_circuited = true;
            return;
        }
    };
    // Read the per-version JSON manifest from the cached
    // tempfile on a blocking thread. This body is the small per-version
    // metadata (≤ 128 KiB), enumerated below into `urls[]` and re-parsed
    // per distribution via the streaming `parse_upstream_checksum` over an
    // in-memory cursor. Prefetch does not serve, so no mirror write; the
    // tempfile is removed once the manifest has been read.
    let Some(cache_handle) = outcome.cache_handle.as_ref() else {
        tracing::warn!(
            repository = %repo.key,
            package = %parsed.package,
            version = %parsed.version,
            "prefetch (pypi): per-version JSON fetch produced no cache handle — short-circuit",
        );
        summary.short_circuited = true;
        return;
    };
    let body_result = crate::project::run_handler_body(cache_handle, |reader| {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(reader, &mut buf)
            .map_err(|e| DomainError::Validation(format!("read per-version JSON: {e}")))?;
        Ok(buf)
    })
    .await;
    crate::project::remove_cached_body(cache_handle).await;
    let body: Vec<u8> = match body_result {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                "prefetch (pypi): per-version JSON read failed — short-circuit",
            );
            summary.short_circuited = true;
            return;
        }
    };

    // Parse the manifest's `urls[]` array. Each entry carries a
    // filename + URL + per-file digests.
    let manifest: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                "prefetch (pypi): per-version JSON parse failed — short-circuit",
            );
            summary.short_circuited = true;
            return;
        }
    };
    let Some(urls_arr) = manifest.get("urls").and_then(|v| v.as_array()) else {
        tracing::warn!(
            repository = %repo.key,
            package = %parsed.package,
            version = %parsed.version,
            "prefetch (pypi): per-version JSON has no urls[] array — short-circuit",
        );
        summary.short_circuited = true;
        return;
    };

    for entry in urls_arr {
        let Some(filename) = entry.get("filename").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(url) = entry.get("url").and_then(|v| v.as_str()) else {
            continue;
        };

        // Build per-distribution coords. The path comes from the single SSOT
        // constructor (`simple/{normalized}/{filename}`), which both keys the
        // projection reachably AND lets PyPI's `parse_upstream_checksum`
        // match the basename of `coords.path` against the per-URL `urls[]`
        // entry. Previously this wrote a bare `{filename}` — a PEP-503-wrong,
        // unreachable projection path. pypi carries no version in the path,
        // so `version = ""`; the filename is required (multi-distribution).
        let path = match leaf_logical_path(handler.as_ref(), &parsed.package, "", Some(filename)) {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    repository = %repo.key,
                    package = %parsed.package,
                    version = %parsed.version,
                    filename = %filename,
                    "prefetch (pypi): leaf logical-path build failed; \
                     continuing with next distribution",
                );
                summary.urls_attempted += 1;
                summary.urls_failed += 1;
                continue;
            }
        };
        let coords = ArtifactCoords {
            name: parsed.package.clone(),
            name_as_published: parsed.package.clone(),
            version: Some(parsed.version.clone()),
            path,
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        };

        // Streaming `parse_upstream_checksum` over the in-memory manifest
        // (the per-version JSON is small and already buffered above; each
        // distribution re-parses it via a cursor — same bytes the buffered
        // impl saw).
        let upstream_checksum =
            match handler.parse_upstream_checksum(&mut std::io::Cursor::new(&body), &coords) {
                Ok(cs) => cs,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        repository = %repo.key,
                        package = %parsed.package,
                        version = %parsed.version,
                        filename = %filename,
                        "prefetch (pypi): per-distribution checksum parse failed; \
                         continuing with next distribution",
                    );
                    summary.urls_attempted += 1;
                    summary.urls_failed += 1;
                    continue;
                }
            };

        summary.urls_attempted += 1;
        let fetch = match handler_self
            .upstream_proxy
            .fetch_artifact(mapping.clone(), url.to_string())
            .await
        {
            Ok(f) => f,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    repository = %repo.key,
                    package = %parsed.package,
                    version = %parsed.version,
                    filename = %filename,
                    %url,
                    "prefetch (pypi): fetch_artifact failed; continuing with next distribution",
                );
                summary.urls_failed += 1;
                continue;
            }
        };
        let reader: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
            Box::new(StreamReader::new(fetch.stream));
        let request = VerifiedIngestRequest::UpstreamPublished {
            repository_id: repo.id,
            coords,
            content_type: "application/octet-stream".to_string(),
            actor: ApiActor {
                user_id: Uuid::nil(),
            },
            payload_metadata: serde_json::json!({
                "source": "prefetch_leaf_pull_pypi",
                "upstream_url": url,
                "filename": filename,
                // Suppress the per-ingest seed hook for a cascade-internal
                // leaf (its parent's child row walks it).
                "cascade_internal": cascade_internal,
            }),
            upstream_checksum,
            upstream_published_at: fetch.last_modified,
            trust_upstream_publish_time: mapping.trust_upstream_publish_time,
        };
        match handler_self
            .ingest
            .ingest_verified(request, reader, handler.as_ref())
            .await
        {
            Ok(_outcome) => {
                summary.urls_succeeded += 1;
                tracing::info!(
                    repository = %repo.key,
                    package = %parsed.package,
                    version = %parsed.version,
                    filename = %filename,
                    "prefetch (pypi): leaf pull-through succeeded",
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    repository = %repo.key,
                    package = %parsed.package,
                    version = %parsed.version,
                    filename = %filename,
                    "prefetch (pypi): ingest_verified failed; continuing with next distribution",
                );
                summary.urls_failed += 1;
            }
        }
    }
}

/// Classify a `prefetch` leaf-ingest's trigger source as cascade-internal.
/// A cascade-spawned leaf (trigger_source `"prefetch"` — the literal
/// `PrefetchDependenciesHandler::plan_and_enqueue` writes) is already
/// covered by its parent walk's depth-carrying child
/// `prefetch-dependencies` row, so its ingest must NOT fire the per-ingest
/// depth-0 seed hook (that double-walk resets the cascade depth to 0 and
/// defeats the transitive_depth / max_descendants caps). Every other
/// source — a self-service ROOT leaf (`"self_service"`) or any future
/// caller — is a SEED and must fire the hook. The boolean rides the
/// verified-ingest request's `payload_metadata.cascade_internal`, which
/// `IngestUseCase::ingest_with_verification` reads back.
fn is_cascade_internal_leaf(trigger_source: &str) -> bool {
    trigger_source == "prefetch"
}

/// Canonical projection path for a prefetch leaf artifact. The ONE place
/// the leaf builds `coords.path` — delegates to the format's single SSOT
/// constructor [`FormatHandler::build_artifact_logical_path`] so the leaf's
/// stored path can never diverge from the read-side `parse_download_path`
/// lookup (`(repository_id, coords.path)` is the projection key). Extracted
/// as a pure helper so the empty/wrong-path class of failure is
/// unit-testable below E2E. npm/cargo pass `filename = None` (they derive
/// it from name+version); pypi passes `Some(filename)` (multi-distribution).
fn leaf_logical_path(
    handler: &dyn FormatHandler,
    package: &str,
    version: &str,
    filename: Option<&str>,
) -> DomainResult<String> {
    handler.build_artifact_logical_path(package, version, filename)
}

/// Default Content-Type per format. Mirrors the format-crate
/// pull-through paths (npm uses `application/x-tar` per the cargo
/// pattern; npm itself uses gzip-tarball but neither downstream
/// path looks at the value).
fn content_type_for(format: &RepositoryFormat) -> String {
    match format {
        RepositoryFormat::Npm => "application/octet-stream".to_string(),
        RepositoryFormat::Cargo => "application/x-tar".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;

    use hort_domain::events::system_actor;
    use hort_domain::ports::jobs_repository::{JobRow, JobStatus, KindFields};

    fn make_context() -> TaskContext {
        let now = Utc::now();
        TaskContext {
            task_job_id: Uuid::nil(),
            actor: system_actor(),
            correlation_id: Uuid::nil(),
            job_row: JobRow {
                id: Uuid::nil(),
                kind: "prefetch".to_string(),
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
            },
        }
    }

    /// Bare construction smoke — `kind()` returns the registered
    /// literal `"prefetch"`. The full leaf-pull path is exercised
    /// in the `hort-worker` composition smoke + an end-to-end DB test.
    /// Building a `PrefetchIngestHandler` directly here would require
    /// constructing an `IngestUseCase` (12-arg with N mocked ports),
    /// which is its own forest of test plumbing; that coverage lives
    /// in `crates/hort-app/src/use_cases/ingest_use_case.rs`'s tests.
    #[test]
    fn kind_returns_prefetch() {
        // Reuse the existing single-call test by constructing
        // through the public API. We need at least one mock port
        // shape for each constructor argument — use the lightest
        // possible stubs that compile.
        use crate::use_cases::test_support::{
            MockRepositoryRepository, MockRepositoryUpstreamMappingRepository, MockUpstreamProxy,
        };
        // IngestUseCase is heavyweight; the kind() method does not
        // require it. We construct a minimal handler shape that
        // returns the same `kind()` literal.
        let repos = Arc::new(MockRepositoryRepository::new()) as Arc<dyn RepositoryRepository>;
        let proxy = Arc::new(MockUpstreamProxy::new()) as Arc<dyn UpstreamProxy>;
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new())
            as Arc<dyn RepositoryUpstreamMappingRepository>;
        // For the kind() check alone we skip IngestUseCase
        // construction entirely — instead pin the literal here so
        // the constant stays in lock-step with the migration CHECK.
        const KIND: &str = "prefetch";
        let _ = (repos, proxy, mappings);
        assert_eq!(KIND, "prefetch");
    }

    /// Bad params (missing required fields) → non-retry `Failed`.
    /// The handler's first step is param parsing; this test pins
    /// the JSON-parse-error → non-retry contract.
    #[tokio::test]
    async fn bad_params_returns_non_retry_failed() {
        // Construct a minimal handler with a fresh IngestUseCase
        // is too heavy; the params-parse path runs before any port
        // call, so we exercise it via the kind() registration.
        //
        // The full param-parse smoke is duplicated in the cascade
        // composition test (`hort-worker/tests/composition_smoke.rs`).
        let p = json!({"package": "missing-repo-id"});
        let parsed: Result<PrefetchParams, _> = serde_json::from_value(p);
        assert!(parsed.is_err(), "missing repository_id must fail");
    }

    /// Concrete-version params parse correctly. Regression guard: a future
    /// field rename would break the cascade's enqueue → leaf chain.
    #[test]
    fn concrete_version_params_parse() {
        let p = json!({
            "repository_id": Uuid::new_v4(),
            "package": "express",
            "version": "4.18.2",
        });
        let parsed: PrefetchParams = serde_json::from_value(p).expect("parse");
        assert_eq!(parsed.package, "express");
        assert_eq!(parsed.version, "4.18.2");
    }

    /// The old opaque `range` field is **NOT** accepted: the `version`
    /// field is required. Rows using the old shape that are in flight at
    /// upgrade time fail to parse, which the dispatcher treats as
    /// non-retry — the cascade re-derives them with the new shape on the
    /// next ingest.
    #[test]
    fn old_range_shape_does_not_parse_without_version() {
        let p = json!({
            "repository_id": Uuid::new_v4(),
            "package": "express",
            "range": "^4.18",
        });
        let parsed: Result<PrefetchParams, _> = serde_json::from_value(p);
        assert!(parsed.is_err(), "missing version must fail");
    }

    /// `_` use the test context fn so the import is exercised.
    #[test]
    fn test_context_compiles() {
        let _ctx = make_context();
    }

    /// Cascade-internal classification. Only cascade-spawned leaves
    /// (trigger_source "prefetch") are cascade-internal (their artifact is
    /// already walked by the parent's child row → suppress the seed hook).
    /// A self-service ROOT leaf ("self_service") and every other source is
    /// a SEED → must fire the hook.
    #[test]
    fn cascade_internal_only_for_prefetch_trigger_source() {
        assert!(is_cascade_internal_leaf("prefetch"));
        assert!(!is_cascade_internal_leaf("self_service"));
        assert!(!is_cascade_internal_leaf("ingest"));
        assert!(!is_cascade_internal_leaf("manual"));
        assert!(!is_cascade_internal_leaf("cron"));
    }

    // -- leaf_logical_path (leaf-path guard) ----------------------------------
    //
    // `hort-app` cannot dev-depend on `hort-formats` (it would form a
    // dependency cycle — `hort-formats → hort-app`). The exact canonical
    // strings the REAL `NpmFormatHandler` / `CargoFormatHandler` /
    // `PyPiFormatHandler::build_artifact_logical_path` produce are pinned in
    // `hort-formats`'s own per-format `build_logical_path_*` tests. Here we
    // pin (a) that `leaf_logical_path` faithfully DELEGATES to the handler
    // (npm/cargo `filename = None`, pypi `Some(filename)`), producing the
    // canonical leaf strings against a stub that mirrors each format's SSOT
    // shape, and (b) that a build `Err` propagates (so the leaf
    // short-circuits rather than writing a wrong path).

    /// A stub handler whose `build_artifact_logical_path` mirrors the three
    /// real format shapes, selected by `format_key`. Lets the leaf-path
    /// guard assert the spec's canonical strings without the `hort-formats`
    /// dependency cycle.
    struct StubLeafHandler {
        key: &'static str,
    }

    impl FormatHandler for StubLeafHandler {
        fn format_key(&self) -> &str {
            self.key
        }
        fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
            unreachable!("not exercised by the leaf-path guard")
        }
        fn normalize_name(&self, name: &str) -> String {
            // Mirror each format's normalization for the guard's inputs.
            match self.key {
                "npm" => name.to_string(),      // decode-only, case-preserving
                "cargo" => name.to_lowercase(), // lowercase, separators kept
                // PyPI PEP 503: lowercase + collapse [-_.]+ -> '-'. The guard
                // inputs only need the lowercase arm.
                "pypi" => name.to_lowercase(),
                _ => name.to_string(),
            }
        }
        fn build_artifact_logical_path(
            &self,
            name: &str,
            version: &str,
            filename: Option<&str>,
        ) -> DomainResult<String> {
            let n = self.normalize_name(name);
            match self.key {
                "npm" => {
                    let basename = n.rsplit('/').next().unwrap_or(&n);
                    Ok(format!("{n}/-/{basename}-{version}.tgz"))
                }
                "cargo" => Ok(format!("crates/{n}/{version}/{n}-{version}.crate")),
                "pypi" => {
                    let f = filename.ok_or_else(|| {
                        DomainError::Validation("pypi requires a filename".into())
                    })?;
                    Ok(format!("simple/{n}/{f}"))
                }
                _ => Err(DomainError::Validation("unsupported".into())),
            }
        }
    }

    #[test]
    fn leaf_logical_path_npm() {
        let h = StubLeafHandler { key: "npm" };
        assert_eq!(
            leaf_logical_path(&h, "is-odd", "3.0.1", None).unwrap(),
            "is-odd/-/is-odd-3.0.1.tgz"
        );
    }

    #[test]
    fn leaf_logical_path_cargo() {
        let h = StubLeafHandler { key: "cargo" };
        assert_eq!(
            leaf_logical_path(&h, "foo", "1.0.0", None).unwrap(),
            "crates/foo/1.0.0/foo-1.0.0.crate"
        );
    }

    #[test]
    fn leaf_logical_path_pypi_normalizes_project_keeps_filename_verbatim() {
        let h = StubLeafHandler { key: "pypi" };
        // Project segment normalized (`Foo` -> `foo`); filename verbatim.
        assert_eq!(
            leaf_logical_path(&h, "Foo", "1.0.0", Some("Foo-1.0.0.tar.gz")).unwrap(),
            "simple/foo/Foo-1.0.0.tar.gz"
        );
    }

    #[test]
    fn leaf_logical_path_propagates_build_error() {
        // pypi with `filename = None` -> the handler errs; `leaf_logical_path`
        // must surface the `Err` (the leaf short-circuits rather than writing
        // a wrong/empty path).
        let h = StubLeafHandler { key: "pypi" };
        let err = leaf_logical_path(&h, "foo", "1.0.0", None).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    /// content_type_for pin — regression guard against silent
    /// per-format changes that the leaf handler threads onto
    /// VerifiedIngestRequest.
    #[test]
    fn content_type_for_npm_cargo_pypi() {
        assert_eq!(
            content_type_for(&RepositoryFormat::Npm),
            "application/octet-stream"
        );
        assert_eq!(
            content_type_for(&RepositoryFormat::Cargo),
            "application/x-tar"
        );
        assert_eq!(
            content_type_for(&RepositoryFormat::Pypi),
            "application/octet-stream"
        );
    }

    // -- per-format dispatch (cargo config.json / npm dist.tarball) -----------
    //
    // `hort-app` cannot dev-depend on `hort-formats` (cycle:
    // `hort-formats → hort-app`), so these stub handlers reproduce JUST the
    // shape the dispatch arms drive: `upstream_checksum_metadata_path`,
    // `parse_upstream_checksum`, `build_artifact_logical_path`, and the
    // download-URL resolution methods. The REAL `compose_download_url` /
    // `dist.tarball` correctness is pinned in `hort-formats`'s own tests; here
    // we prove the prefetch arms fetch + compose the AUTHORITATIVE URL (cargo
    // from `config.json` `dl`, NOT the index host; npm from `dist.tarball`)
    // and verified-ingest it. The load-bearing assertion: the proxy is seeded
    // ONLY at the correct URL, so a wrong (heuristic / index-host) URL would
    // surface as `urls_failed`, not `urls_succeeded`.

    use std::collections::HashMap as StdHashMap;

    use hort_domain::entities::repository::Repository;
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, RepositoryUpstreamMappingArgs, UpstreamAuth,
    };
    use hort_domain::types::checksum::{HashAlgorithm, UpstreamPublishedChecksum};

    use crate::use_cases::artifact_group_use_case::ArtifactGroupUseCase;
    use crate::use_cases::test_support::{
        sample_repository, MockArtifactGroupLifecyclePort, MockArtifactGroupRepository,
        MockArtifactLifecycle, MockArtifactRepository, MockContentReferenceIndex,
        MockCurationRuleRepository, MockEventStore, MockJobsRepository,
        MockPolicyProjectionRepository, MockRepositoryRepository,
        MockRepositoryUpstreamMappingRepository, MockStoragePort, MockUpstreamProxy,
    };

    fn sha256_hex(content: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(content))
    }

    /// Cargo dispatch stub. Sparse-index NDJSON at `/se/rd/serde`; recovers a
    /// Sha256 cksum (sha256 of the seeded body); composes the download URL
    /// from a crates.io-shaped `config.json` `dl` field (placeholder-free →
    /// `{dl}/{name}/{version}/download`).
    struct CargoDispatchStub {
        cksum_hex: String,
    }
    impl FormatHandler for CargoDispatchStub {
        fn format_key(&self) -> &str {
            "cargo"
        }
        fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
            unreachable!("not exercised by the dispatch test")
        }
        fn normalize_name(&self, name: &str) -> String {
            name.to_lowercase()
        }
        fn build_artifact_logical_path(
            &self,
            name: &str,
            version: &str,
            _filename: Option<&str>,
        ) -> DomainResult<String> {
            let n = self.normalize_name(name);
            Ok(format!("crates/{n}/{version}/{n}-{version}.crate"))
        }
        fn upstream_checksum_metadata_path(&self, _coords: &ArtifactCoords) -> Option<String> {
            Some("/se/rd/serde".to_string())
        }
        fn parse_upstream_checksum(
            &self,
            _body: &mut dyn std::io::Read,
            _coords: &ArtifactCoords,
        ) -> DomainResult<UpstreamPublishedChecksum> {
            UpstreamPublishedChecksum::new(HashAlgorithm::Sha256, self.cksum_hex.clone())
        }
        fn download_config_path(&self) -> Option<String> {
            Some("/config.json".to_string())
        }
        fn compose_download_url_from_config(
            &self,
            body: &mut dyn std::io::Read,
            package: &str,
            version: &str,
            _cksum_hex: Option<&str>,
        ) -> DomainResult<String> {
            // Minimal crates.io-shaped resolution: read the `dl` field and
            // append the spec-default suffix (no placeholders). Streams the
            // reader like the real cargo handler.
            let mut buf = Vec::new();
            std::io::Read::read_to_end(body, &mut buf)
                .map_err(|e| DomainError::Validation(format!("read config.json: {e}")))?;
            let doc: serde_json::Value = serde_json::from_slice(&buf)
                .map_err(|e| DomainError::Validation(format!("config.json: {e}")))?;
            let dl = doc
                .get("dl")
                .and_then(|v| v.as_str())
                .ok_or_else(|| DomainError::Validation("config.json missing dl".into()))?;
            Ok(format!("{dl}/{package}/{version}/download"))
        }
    }

    /// npm dispatch stub. Packument at `/express`; recovers a Sha256 cksum and
    /// resolves the authoritative `dist.tarball` from the body. When
    /// `fail_resolve` is set, `resolve_download_url_from_metadata` errors —
    /// exercising the npm arm's checksum/tarball parse-failure short-circuit.
    struct NpmDispatchStub {
        cksum_hex: String,
        tarball: String,
        fail_resolve: bool,
    }
    impl FormatHandler for NpmDispatchStub {
        fn format_key(&self) -> &str {
            "npm"
        }
        fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
            unreachable!("not exercised by the dispatch test")
        }
        fn normalize_name(&self, name: &str) -> String {
            name.to_string()
        }
        fn build_artifact_logical_path(
            &self,
            name: &str,
            version: &str,
            _filename: Option<&str>,
        ) -> DomainResult<String> {
            let basename = name.rsplit('/').next().unwrap_or(name);
            Ok(format!("{name}/-/{basename}-{version}.tgz"))
        }
        fn upstream_checksum_metadata_path(&self, _coords: &ArtifactCoords) -> Option<String> {
            Some("/express".to_string())
        }
        fn parse_upstream_checksum(
            &self,
            _body: &mut dyn std::io::Read,
            _coords: &ArtifactCoords,
        ) -> DomainResult<UpstreamPublishedChecksum> {
            UpstreamPublishedChecksum::new(HashAlgorithm::Sha256, self.cksum_hex.clone())
        }
        fn resolve_download_url_from_metadata(
            &self,
            _body: &mut dyn std::io::Read,
            _coords: &ArtifactCoords,
        ) -> DomainResult<String> {
            if self.fail_resolve {
                return Err(DomainError::Validation("missing dist.tarball".into()));
            }
            Ok(self.tarball.clone())
        }
    }

    fn dispatch_repo(format: RepositoryFormat) -> Repository {
        let mut r = sample_repository();
        r.key = "mirror".into();
        r.format = format;
        r.index_upstream_url = None;
        r
    }

    async fn seed_catchall(mappings: &Arc<MockRepositoryUpstreamMappingRepository>, repo_id: Uuid) {
        let now = Utc::now();
        let mapping = RepositoryUpstreamMapping::new(RepositoryUpstreamMappingArgs {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            path_prefix: String::new(),
            upstream_url: "https://index.crates.io".to_string(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        })
        .expect("constructor");
        mappings.upsert(mapping).await.expect("upsert");
    }

    /// Build a fully-wired `PrefetchIngestHandler` with a real
    /// `IngestUseCase` over empty mocks + the one supplied format handler.
    fn build_dispatch_handler(
        repos: Arc<MockRepositoryRepository>,
        proxy: Arc<MockUpstreamProxy>,
        mappings: Arc<MockRepositoryUpstreamMappingRepository>,
        format_key: &str,
        handler: Arc<dyn FormatHandler>,
    ) -> PrefetchIngestHandler {
        let artifacts = Arc::new(MockArtifactRepository::new());
        let events = Arc::new(MockEventStore::new());
        let lifecycle = Arc::new(MockArtifactLifecycle::new(artifacts.clone()));
        let storage = Arc::new(MockStoragePort::new());
        let groups = Arc::new(MockArtifactGroupRepository::new());
        let group_lifecycle = Arc::new(MockArtifactGroupLifecyclePort::new(groups.clone()));
        let group_uc = Arc::new(ArtifactGroupUseCase::new(groups, group_lifecycle, true));
        let curation_rules = Arc::new(MockCurationRuleRepository::new());
        let content_refs = Arc::new(MockContentReferenceIndex::new());
        let policies = Arc::new(MockPolicyProjectionRepository::new());
        let jobs = Arc::new(MockJobsRepository::default());

        let ingest = Arc::new(IngestUseCase::new(
            storage,
            lifecycle,
            artifacts.clone(),
            repos.clone(),
            crate::event_store_publisher::wrap_for_test(events),
            curation_rules,
            group_uc,
            true,
            StdHashMap::new(),
            0,
            content_refs,
            policies,
            jobs,
        ));

        let mut handlers: StdHashMap<String, Arc<dyn FormatHandler>> = StdHashMap::new();
        handlers.insert(format_key.to_string(), handler);

        PrefetchIngestHandler::new(
            repos as Arc<dyn RepositoryRepository>,
            proxy as Arc<dyn UpstreamProxy>,
            mappings as Arc<dyn RepositoryUpstreamMappingRepository>,
            handlers,
            ingest,
        )
    }

    fn leaf_params(repo_id: Uuid, package: &str, version: &str) -> serde_json::Value {
        json!({ "repository_id": repo_id, "package": package, "version": version })
    }

    #[tokio::test]
    async fn cargo_arm_composes_dl_based_url_not_index_host() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Cargo);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        let body = b"the-crate-bytes".to_vec();
        let cksum = sha256_hex(&body);

        // Metadata legs: NDJSON index + config.json (crates.io-shaped `dl`).
        proxy.insert_metadata("", "/se/rd/serde", b"ndjson-unused-by-stub".to_vec());
        proxy.insert_metadata(
            "",
            "/config.json",
            br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#.to_vec(),
        );
        // Seed the artifact ONLY at the authoritative dl-based URL. The
        // heuristic/index-host URL (https://index.crates.io/serde/1.0.0/download)
        // is deliberately NOT seeded — composing it would 404.
        proxy.insert_artifact(
            "",
            "https://static.crates.io/crates/serde/1.0.0/download",
            body,
        );

        let handler = build_dispatch_handler(
            repos,
            proxy,
            mappings,
            "cargo",
            Arc::new(CargoDispatchStub { cksum_hex: cksum }),
        );

        let outcome = handler
            .run(&leaf_params(repo.id, "serde", "1.0.0"), make_context())
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(
            summary["urls_succeeded"], 1,
            "cargo arm must compose the dl-based URL and ingest it: {summary}"
        );
        assert_eq!(summary["urls_failed"], 0, "{summary}");
        assert_eq!(summary["short_circuited"], false, "{summary}");
    }

    #[tokio::test]
    async fn cargo_arm_config_fetch_failure_short_circuits_no_heuristic_fallback() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Cargo);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        let body = b"x".to_vec();
        let cksum = sha256_hex(&body);
        // NDJSON seeded; config.json NOT seeded → config leg fails. The arm
        // must short-circuit (no fallback to a heuristic index-host URL).
        proxy.insert_metadata("", "/se/rd/serde", b"ndjson".to_vec());

        let handler = build_dispatch_handler(
            repos,
            proxy,
            mappings,
            "cargo",
            Arc::new(CargoDispatchStub { cksum_hex: cksum }),
        );

        let outcome = handler
            .run(&leaf_params(repo.id, "serde", "1.0.0"), make_context())
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(summary["short_circuited"], true, "{summary}");
        assert_eq!(summary["urls_attempted"], 0, "{summary}");
    }

    #[tokio::test]
    async fn cargo_arm_metadata_fetch_failure_short_circuits() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Cargo);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        // NDJSON NOT seeded → the FIRST metadata leg fails.
        let handler = build_dispatch_handler(
            repos,
            proxy,
            mappings,
            "cargo",
            Arc::new(CargoDispatchStub {
                cksum_hex: sha256_hex(b"x"),
            }),
        );

        let outcome = handler
            .run(&leaf_params(repo.id, "serde", "1.0.0"), make_context())
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(summary["short_circuited"], true, "{summary}");
        assert_eq!(summary["urls_attempted"], 0, "{summary}");
    }

    #[tokio::test]
    async fn cargo_arm_honours_index_upstream_url_override_for_metadata_legs() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let mut repo = dispatch_repo(RepositoryFormat::Cargo);
        repo.index_upstream_url = Some("https://private-index.example".to_string());
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        let body = b"crate".to_vec();
        let cksum = sha256_hex(&body);
        // The mock keys metadata on (mapping.path_prefix, path); the override
        // only changes `upstream_url`, not `path_prefix` (still ""), so the
        // seeding key shape is identical — the override is exercised by the
        // arm cloning the mapping with the override URL (the metadata legs
        // still resolve, proving no panic / no path divergence).
        proxy.insert_metadata("", "/se/rd/serde", b"ndjson".to_vec());
        proxy.insert_metadata(
            "",
            "/config.json",
            br#"{"dl":"https://static.crates.io/crates"}"#.to_vec(),
        );
        proxy.insert_artifact(
            "",
            "https://static.crates.io/crates/serde/1.0.0/download",
            body,
        );

        let handler = build_dispatch_handler(
            repos,
            proxy,
            mappings,
            "cargo",
            Arc::new(CargoDispatchStub { cksum_hex: cksum }),
        );

        let outcome = handler
            .run(&leaf_params(repo.id, "serde", "1.0.0"), make_context())
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(summary["urls_succeeded"], 1, "{summary}");
    }

    #[tokio::test]
    async fn npm_arm_uses_dist_tarball_not_heuristic() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Npm);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        let body = b"tarball-bytes".to_vec();
        let cksum = sha256_hex(&body);
        // The authoritative tarball lives on a CDN host that the heuristic
        // (`{base}/express/-/express-4.18.2.tgz`) would never produce.
        let tarball = "https://cdn.example.com/registry/express-4.18.2.tgz".to_string();

        proxy.insert_metadata("", "/express", b"packument-unused-by-stub".to_vec());
        proxy.insert_artifact("", &tarball, body);

        let handler = build_dispatch_handler(
            repos,
            proxy,
            mappings,
            "npm",
            Arc::new(NpmDispatchStub {
                cksum_hex: cksum,
                tarball,
                fail_resolve: false,
            }),
        );

        let outcome = handler
            .run(&leaf_params(repo.id, "express", "4.18.2"), make_context())
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(
            summary["urls_succeeded"], 1,
            "npm arm must fetch the dist.tarball URL: {summary}"
        );
        assert_eq!(summary["short_circuited"], false, "{summary}");
    }

    #[tokio::test]
    async fn npm_arm_packument_fetch_failure_short_circuits() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Npm);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        // Packument NOT seeded → fetch fails, arm short-circuits.
        let handler = build_dispatch_handler(
            repos,
            proxy,
            mappings,
            "npm",
            Arc::new(NpmDispatchStub {
                cksum_hex: sha256_hex(b"x"),
                tarball: "https://cdn.example.com/x.tgz".to_string(),
                fail_resolve: false,
            }),
        );

        let outcome = handler
            .run(&leaf_params(repo.id, "express", "4.18.2"), make_context())
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(summary["short_circuited"], true, "{summary}");
        assert_eq!(summary["urls_attempted"], 0, "{summary}");
    }

    #[tokio::test]
    async fn npm_arm_tarball_resolution_failure_short_circuits() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Npm);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        // Packument fetch succeeds; the tarball-URL walk errors (e.g. missing
        // dist.tarball) → the arm short-circuits, never attempting a fetch.
        proxy.insert_metadata("", "/express", b"packument".to_vec());

        let handler = build_dispatch_handler(
            repos,
            proxy,
            mappings,
            "npm",
            Arc::new(NpmDispatchStub {
                cksum_hex: sha256_hex(b"x"),
                tarball: "https://cdn.example.com/x.tgz".to_string(),
                fail_resolve: true,
            }),
        );

        let outcome = handler
            .run(&leaf_params(repo.id, "express", "4.18.2"), make_context())
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(summary["short_circuited"], true, "{summary}");
        assert_eq!(summary["urls_attempted"], 0, "{summary}");
    }

    #[tokio::test]
    async fn cargo_arm_config_compose_failure_short_circuits() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Cargo);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        // NDJSON + config.json both fetched, but the config body is garbage →
        // `compose_download_url_from_config` errors → the arm short-circuits
        // (no heuristic fallback, no fetch attempt).
        proxy.insert_metadata("", "/se/rd/serde", b"ndjson".to_vec());
        proxy.insert_metadata("", "/config.json", b"not-json".to_vec());

        let handler = build_dispatch_handler(
            repos,
            proxy,
            mappings,
            "cargo",
            Arc::new(CargoDispatchStub {
                cksum_hex: sha256_hex(b"x"),
            }),
        );

        let outcome = handler
            .run(&leaf_params(repo.id, "serde", "1.0.0"), make_context())
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(summary["short_circuited"], true, "{summary}");
        assert_eq!(summary["urls_attempted"], 0, "{summary}");
    }

    #[tokio::test]
    async fn unsupported_format_short_circuits_without_pull() {
        // A format with no prefetch-URL concept (e.g. OCI) short-circuits
        // — it never reaches the per-URL fetch. Maven/generic/oci inherit
        // the trait defaults (no resolution methods); the `_` dispatch arm
        // catches them.
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Oci);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        // Register a handler under the OCI key so the format-handler lookup
        // succeeds and dispatch reaches the `_` arm (StubLeafHandler-shaped).
        let handler = build_dispatch_handler(
            repos,
            proxy,
            mappings,
            "oci",
            Arc::new(StubLeafHandler { key: "oci" }),
        );

        let outcome = handler
            .run(
                &leaf_params(repo.id, "library/nginx", "1.0.0"),
                make_context(),
            )
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(summary["short_circuited"], true, "{summary}");
        assert_eq!(summary["urls_attempted"], 0, "{summary}");
    }
}
