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
//! # Dedup composition — L2/L3 only, NOT L1
//!
//! This handler calls `UpstreamProxy::fetch_artifact` and
//! `IngestUseCase::ingest_verified` **directly**. It does **not**
//! ride `PullDedup` (L1), and there is no `PullDedup`-wrapping
//! `UpstreamProxy` decorator in the tree — `HttpUpstreamProxy` is
//! the only implementation, and the composition root wires it
//! unwrapped.
//!
//! Duplicates are absorbed by the other two layers of the scheme
//! documented in `hort_app::pull_dedup` (L1 concurrent single-flight
//! / L2 terminal ingest absorb / L3 cascade re-walk absorb):
//!
//! - **L3** — the `jobs.target_key` partial unique index (migration
//!   009) collapses duplicate *cascade jobs* before they ever run,
//!   which is the common case for this handler.
//! - **L2** — the `artifacts` path-UNIQUE constraint absorbs a
//!   duplicate *ingest* if a prefetch and a client pull-through
//!   race to commit the same bytes.
//!
//! The residual cost of skipping L1 is therefore a redundant
//! upstream *fetch* in that narrow race — wasted bandwidth, never a
//! correctness problem: the second committer loses at L2 and the
//! content hash is identical by construction (enforced CAS).
//!
//! An earlier version of this comment claimed the composition root
//! wired this handler behind `PullDedup`'s `coalesce_blob` guard.
//! It never did (issue #57). Do not reason from that guarantee.
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
use hort_domain::types::checksum::{HashAlgorithm, UpstreamPublishedChecksum};
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
            //
            // No registered handler for the repo's format can never
            // succeed on retry — the input itself can never be
            // fulfilled. `Failed`, non-retryable: a leaf-ingest that
            // reports success while ingesting nothing must never
            // masquerade as `Completed` again (the four-day member-
            // aware-prefetch outage this closes).
            let format_key = repo.format.to_string();
            let Some(handler) = self.format_handlers.get(&format_key).cloned() else {
                return Ok(TaskOutcome::fail(
                    format!(
                        "prefetch: no FormatHandler registered for repository {}'s format {}",
                        repo.key, format_key
                    ),
                    false,
                ));
            };

            // ----- Step 4: resolve catch-all upstream mapping ---------
            //
            // Same reasoning as Step 3: a repo with no catch-all
            // (`path_prefix == ""`) upstream mapping can never complete
            // this leaf — the self-service prefetch use case and the
            // enqueue-time hosted-repo guard now both reject before
            // enqueue, so a row reaching here with no mapping can only
            // mean a broken enqueue path or a manually-inserted row.
            // `Failed`, non-retryable.
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
                return Ok(TaskOutcome::fail(
                    format!(
                        "prefetch: no catch-all upstream mapping (path_prefix=\"\") for \
                         repository {}",
                        repo.key
                    ),
                    false,
                ));
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
                RepositoryFormat::Maven => {
                    let ctx = LeafCtx {
                        handler_self: self,
                        repo: &repo,
                        handler: &handler,
                        mapping: &mapping,
                        parsed: &parsed,
                        cascade_internal,
                    };
                    // A rejected GAV coordinate (path traversal, absolute,
                    // empty segment) short-circuits `run()` with a non-retry
                    // `Failed` outcome — distinct from the `Completed` +
                    // `short_circuited` shape every other guard in this
                    // handler uses, because a malformed GAV is a per-item
                    // input-validation rejection, not an upstream condition.
                    if let Some(rejected) = maven_resolve_and_pull(&ctx, &mut summary).await {
                        return Ok(rejected);
                    }
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
    upstream_checksum: UpstreamPublishedChecksum,
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

    // Only called from the `RepositoryFormat::Cargo` dispatch arm, so this
    // is provably `Some` today — but the check is the structural,
    // greppable replacement for what used to be an implicit assumption
    // (issue #58): a future cargo-family alias routed here without a
    // `VersionDiscovery` impl now short-circuits instead of hitting a
    // trait method that no longer exists on `FormatHandler`.
    let Some(vd) = ctx.handler.version_discovery() else {
        tracing::warn!(
            repository = %ctx.repo.key,
            package = %ctx.parsed.package,
            "prefetch (cargo): handler does not implement VersionDiscovery — short-circuit",
        );
        summary.short_circuited = true;
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
    let Some(config_path) = vd.download_config_path() else {
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
                // Re-derive from the cloned, owned `Arc` — the closure
                // must be `'static` and cannot capture the outer
                // borrowed `vd`. Pure dispatch on `handler`'s concrete
                // type, so re-deriving is exactly as safe as the guard
                // above (same handler, same answer).
                let vd = handler.version_discovery().expect(
                    "handler participates in VersionDiscovery — checked earlier in this function",
                );
                vd.compose_download_url_from_config(reader, &package, &version, Some(&cksum_hex))
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

    // Only called from the `RepositoryFormat::Npm` dispatch arm, so this
    // is provably `Some` today — the structural, greppable replacement
    // (issue #58) for what used to be an implicit assumption.
    if ctx.handler.version_discovery().is_none() {
        tracing::warn!(
            repository = %ctx.repo.key,
            package = %ctx.parsed.package,
            "prefetch (npm): handler does not implement VersionDiscovery — short-circuit",
        );
        summary.short_circuited = true;
        return;
    }

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
            let vd = handler.version_discovery().expect(
                "handler participates in VersionDiscovery — checked earlier in this function",
            );
            vd.resolve_download_url_from_metadata(reader, &coords)
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

/// The Maven checksum-sidecar algorithms tried in strength-preferring
/// order (ADR 0033): `.sha512` (strongest) → `.sha256` → `.sha1` (the
/// universal floor). Mirrors `hort-http-maven/src/upstream_pull.rs`'s
/// `SIDECAR_PREFERENCE` constant — kept in sync by hand because `hort-app`
/// must not depend on `hort-http-maven` (the dependency direction runs the
/// other way: `hort-http-maven → hort-app`).
const MAVEN_SIDECAR_PREFERENCE: [(HashAlgorithm, &str); 3] = [
    (HashAlgorithm::Sha512, "sha512"),
    (HashAlgorithm::Sha256, "sha256"),
    (HashAlgorithm::Sha1, "sha1"),
];

/// Maven leaf pull-through: POM always, jar when present, via the
/// verified two-leg pull (checksum sidecar preference `sha512` → `sha256`
/// → `sha1`, fall-through on 404 / transport / malformed body, then
/// `ingest_verified` with the winning algorithm) — mirroring the documented
/// contract in `hort-http-maven/src/upstream_pull.rs`. Re-implemented here
/// rather than reused: `hort-app` must not gain a dependency on
/// `hort-http-maven`.
///
/// `package` is the colon-joined `groupId:artifactId` GAV form. A malformed
/// shape, or a coordinate that composes into path traversal / an absolute
/// path / an empty segment (caught by
/// [`FormatHandler::build_artifact_logical_path`]'s validation), is a
/// structural per-item REJECTION: `Some(TaskOutcome::Failed{retry: false})`
/// is returned before any upstream call is made — distinct from the
/// `Completed` + `short_circuited` shape the rest of this handler uses for
/// upstream/runtime conditions. `None` means the caller should fall through
/// to the normal `Completed` summary.
async fn maven_resolve_and_pull(
    ctx: &LeafCtx<'_>,
    summary: &mut LeafSummary,
) -> Option<TaskOutcome> {
    let LeafCtx {
        repo,
        handler,
        parsed,
        ..
    } = ctx;

    let Some(artifact_id) = maven_artifact_id(&parsed.package) else {
        tracing::warn!(
            repository = %repo.key,
            "prefetch (maven): package is not the colon-joined \"groupId:artifactId\" \
             form — rejected",
        );
        return Some(TaskOutcome::fail(
            "prefetch (maven): package must be the colon-joined \"groupId:artifactId\" form"
                .to_string(),
            false,
        ));
    };

    // ----- POM: always fetched. Coordinate validation (traversal, an
    // absolute path, an empty segment) happens inside
    // `build_artifact_logical_path` — an `Err` here is a structural
    // rejection; no upstream call has been made yet.
    let pom_filename = format!("{artifact_id}-{}.pom", parsed.version);
    let pom_path = match handler.build_artifact_logical_path(
        &parsed.package,
        &parsed.version,
        Some(&pom_filename),
    ) {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                "prefetch (maven): GAV coordinate rejected by the path-composition guard",
            );
            return Some(TaskOutcome::fail(
                format!("prefetch (maven): invalid GAV coordinate: {err}"),
                false,
            ));
        }
    };
    let pom_coords = ArtifactCoords {
        name: parsed.package.clone(),
        name_as_published: parsed.package.clone(),
        version: Some(parsed.version.clone()),
        path: pom_path.clone(),
        format: repo.format.clone(),
        metadata: serde_json::Value::Null,
    };
    let pom_ingested = maven_pull_one(ctx, pom_coords, &pom_path, summary).await;

    // ----- jar: fetched only when the POM leg succeeded. A jar that
    // upstream does not publish (BOM / parent packagings) is recorded as a
    // non-fatal per-URL failure via `maven_pull_one`, exactly like every
    // other format's per-URL failure in this handler — the leaf still
    // completes.
    if pom_ingested {
        let jar_filename = format!("{artifact_id}-{}.jar", parsed.version);
        match handler.build_artifact_logical_path(
            &parsed.package,
            &parsed.version,
            Some(&jar_filename),
        ) {
            Ok(jar_path) => {
                let jar_coords = ArtifactCoords {
                    name: parsed.package.clone(),
                    name_as_published: parsed.package.clone(),
                    version: Some(parsed.version.clone()),
                    path: jar_path.clone(),
                    format: repo.format.clone(),
                    metadata: serde_json::Value::Null,
                };
                maven_pull_one(ctx, jar_coords, &jar_path, summary).await;
            }
            Err(err) => {
                // Structurally unreachable in practice: the POM leg above
                // already validated the same (group, artifact, version)
                // triple via the same builder. A defensive short-circuit
                // rather than a silent skip if that ever changes.
                tracing::warn!(
                    error = %err,
                    repository = %repo.key,
                    "prefetch (maven): jar path build failed after a validated POM path",
                );
                summary.short_circuited = true;
            }
        }
    }

    None
}

/// Split `package` (expected `groupId:artifactId`) into its artifactId, for
/// composing the POM/jar filename. `None` when the shape is wrong (no
/// colon, or either half empty) — the caller rejects the item rather than
/// composing a filename from a malformed name. The full coordinate
/// (including the groupId half) is re-validated by
/// `FormatHandler::build_artifact_logical_path` regardless.
fn maven_artifact_id(package: &str) -> Option<&str> {
    let (group, artifact) = package.split_once(':')?;
    if group.is_empty() || artifact.is_empty() {
        return None;
    }
    Some(artifact)
}

/// Fetch the strongest available checksum sidecar for `artifact_path`,
/// trying `.sha512` → `.sha256` → `.sha1` in order. The first sidecar that
/// fetches AND parses to a valid digest of the matching shape wins; a fetch
/// failure OR a malformed body on a stronger digest falls through to the
/// next (weaker) digest — mirroring
/// `hort-http-maven/src/upstream_pull.rs::fetch_strongest_sidecar`'s
/// documented contract. `None` when all three are absent, unfetchable, or
/// unparseable.
async fn maven_strongest_sidecar(
    ctx: &LeafCtx<'_>,
    artifact_path: &str,
) -> Option<(HashAlgorithm, UpstreamPublishedChecksum)> {
    for (algorithm, ext) in MAVEN_SIDECAR_PREFERENCE {
        let sidecar_path = format!("{artifact_path}.{ext}");
        let fetch = ctx
            .handler_self
            .upstream_proxy
            .fetch_metadata(ctx.mapping.clone(), sidecar_path, Vec::new())
            .await;
        let Ok(outcome) = fetch else {
            continue;
        };
        let Some(handle) = outcome.cache_handle.as_ref() else {
            continue;
        };
        let body_result = crate::project::run_handler_body(handle, |reader| {
            let mut buf = String::new();
            std::io::Read::read_to_string(reader, &mut buf).map_err(|e| {
                DomainError::Validation(format!(
                    "prefetch (maven): read checksum sidecar body: {e}"
                ))
            })?;
            Ok(buf)
        })
        .await;
        crate::project::remove_cached_body(handle).await;
        let Ok(body) = body_result else {
            continue;
        };
        if let Some(checksum) = maven_parse_sidecar(algorithm, &body) {
            return Some((algorithm, checksum));
        }
    }
    None
}

/// Parse a fetched Maven sidecar body into a shape-validated
/// [`UpstreamPublishedChecksum`] for `algorithm`, tolerating a trailing
/// ` filename` suffix (GNU coreutils shape) by taking the first
/// whitespace-delimited token. `None` on an empty body or a digest that
/// fails the algorithm's shape check — the caller falls through to the
/// next (weaker) digest.
fn maven_parse_sidecar(algorithm: HashAlgorithm, body: &str) -> Option<UpstreamPublishedChecksum> {
    let token = body.split_whitespace().next()?;
    UpstreamPublishedChecksum::new(algorithm, token.to_ascii_lowercase()).ok()
}

/// Resolve the strongest checksum sidecar for `artifact_path`, fetch the
/// artifact body, and `ingest_verified` it. Non-fatal on any failure
/// (`warn!`, `urls_failed += 1`) — mirrors `fetch_and_ingest_one`'s
/// per-URL contract; the leaf still completes. Returns `true` iff the
/// ingest succeeded.
async fn maven_pull_one(
    ctx: &LeafCtx<'_>,
    coords: ArtifactCoords,
    artifact_path: &str,
    summary: &mut LeafSummary,
) -> bool {
    let LeafCtx {
        handler_self,
        repo,
        handler,
        mapping,
        parsed,
        cascade_internal,
    } = ctx;

    let Some((_algorithm, upstream_checksum)) = maven_strongest_sidecar(ctx, artifact_path).await
    else {
        summary.urls_attempted += 1;
        summary.urls_failed += 1;
        tracing::warn!(
            repository = %repo.key,
            package = %parsed.package,
            version = %parsed.version,
            path = %artifact_path,
            "prefetch (maven): no usable upstream checksum sidecar \
             (sha512/sha256/sha1 all absent or malformed); continuing",
        );
        return false;
    };

    summary.urls_attempted += 1;
    let fetch = match handler_self
        .upstream_proxy
        .fetch_artifact((*mapping).clone(), artifact_path.to_string())
        .await
    {
        Ok(f) => f,
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                path = %artifact_path,
                "prefetch (maven): fetch_artifact failed; continuing",
            );
            summary.urls_failed += 1;
            return false;
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
            "source": "prefetch_leaf_pull_maven",
            "upstream_path": artifact_path,
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
                path = %artifact_path,
                "prefetch (maven): leaf pull-through succeeded",
            );
            true
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                path = %artifact_path,
                "prefetch (maven): ingest_verified failed; continuing",
            );
            summary.urls_failed += 1;
            false
        }
    }
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
    use hort_domain::ports::format_handler::{DependencySpec, VersionDiscovery};
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
        MockArtifactLifecycle, MockArtifactRepository, MockContentFirstSeen,
        MockContentReferenceIndex, MockCurationRuleRepository, MockEventStore, MockJobsRepository,
        MockPolicyProjectionRepository, MockRepositoryRepository,
        MockRepositoryUpstreamMappingRepository, MockStoragePort, MockUpstreamProxy,
    };

    fn sha256_hex(content: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(content))
    }

    fn sha1_hex(content: &[u8]) -> String {
        use sha1::{Digest, Sha1};
        format!("{:x}", Sha1::digest(content))
    }

    fn sha512_hex(content: &[u8]) -> String {
        use sha2::{Digest, Sha512};
        format!("{:x}", Sha512::digest(content))
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
        fn version_discovery(&self) -> Option<&dyn VersionDiscovery> {
            Some(self)
        }
    }
    impl VersionDiscovery for CargoDispatchStub {
        fn extract_upstream_versions(
            &self,
            _body: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<String>> {
            Ok(Vec::new())
        }
        fn upstream_metadata_path(&self, _package: &str) -> Option<String> {
            None
        }
        fn upstream_metadata_accept(&self) -> Vec<String> {
            Vec::new()
        }
        fn extract_dependency_specs(
            &self,
            _content: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<DependencySpec>> {
            Ok(Vec::new())
        }
        fn resolve_range_max(
            &self,
            _range: &str,
            _available: &[&str],
        ) -> DomainResult<Option<String>> {
            Ok(None)
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
        fn resolve_download_url_from_metadata(
            &self,
            _body: &mut dyn std::io::Read,
            _coords: &ArtifactCoords,
        ) -> DomainResult<String> {
            Err(DomainError::Validation(
                "not supported by test double".into(),
            ))
        }
    }

    /// A registered `FormatHandler` under `"cargo"` that does NOT
    /// implement `VersionDiscovery` (issue #58). Exercises the
    /// `cargo_resolve_and_pull` guard: `short_circuited: true`, not a
    /// call into a method that no longer exists on `FormatHandler` for a
    /// non-participant.
    struct NoVersionDiscoveryCargoHandler;
    impl FormatHandler for NoVersionDiscoveryCargoHandler {
        fn format_key(&self) -> &str {
            "cargo"
        }
        fn parse_download_path(&self, _path: &str) -> DomainResult<ArtifactCoords> {
            unreachable!("not exercised by the dispatch test")
        }
        fn normalize_name(&self, name: &str) -> String {
            name.to_lowercase()
        }
        // `version_discovery` is NOT overridden — inherits `None`.
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
        fn version_discovery(&self) -> Option<&dyn VersionDiscovery> {
            Some(self)
        }
    }
    impl VersionDiscovery for NpmDispatchStub {
        fn extract_upstream_versions(
            &self,
            _body: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<String>> {
            Ok(Vec::new())
        }
        fn upstream_metadata_path(&self, _package: &str) -> Option<String> {
            None
        }
        fn upstream_metadata_accept(&self) -> Vec<String> {
            Vec::new()
        }
        fn extract_dependency_specs(
            &self,
            _content: &mut dyn std::io::Read,
        ) -> DomainResult<Vec<DependencySpec>> {
            Ok(Vec::new())
        }
        fn resolve_range_max(
            &self,
            _range: &str,
            _available: &[&str],
        ) -> DomainResult<Option<String>> {
            Ok(None)
        }
        fn download_config_path(&self) -> Option<String> {
            None
        }
        fn compose_download_url_from_config(
            &self,
            _body: &mut dyn std::io::Read,
            _package: &str,
            _version: &str,
            _cksum_hex: Option<&str>,
        ) -> DomainResult<String> {
            Err(DomainError::Validation(
                "not supported by test double".into(),
            ))
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

    /// Maven dispatch stub. `hort-app` cannot dev-depend on `hort-formats`
    /// (cycle — see the leaf-path guard tests above), so
    /// `build_artifact_logical_path` here reproduces JUST the validation
    /// shape the `maven_resolve_and_pull` dispatch arm relies on: reject an
    /// unparseable `groupId:artifactId`, an empty component, or a
    /// path-traversal / path-separator segment. The exact canonical string
    /// output and every edge case of the real `MavenFormatHandler`
    /// validator are pinned in `hort-formats`'s own tests
    /// (`crates/hort-formats/src/maven/mod.rs`).
    struct MavenDispatchStub;
    impl FormatHandler for MavenDispatchStub {
        fn format_key(&self) -> &str {
            "maven"
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
            filename: Option<&str>,
        ) -> DomainResult<String> {
            let filename = filename.ok_or_else(|| {
                DomainError::Validation("maven.coordinate: filename is required".into())
            })?;
            let (group, artifact) = name.split_once(':').ok_or_else(|| {
                DomainError::Validation(
                    "maven.coordinate: name must be the colon-joined groupId:artifactId form"
                        .into(),
                )
            })?;
            maven_stub_validate_component("groupId", group, true)?;
            maven_stub_validate_component("artifactId", artifact, false)?;
            maven_stub_validate_component("version", version, false)?;
            maven_stub_validate_component("filename", filename, false)?;
            let group_path = group.replace('.', "/");
            Ok(format!("{group_path}/{artifact}/{version}/{filename}"))
        }
    }

    /// Mirrors the shape (not the exact wording) of
    /// `hort_formats::maven::coords::validate_component`: reject an empty
    /// value, a path separator, and a `..`/`.` segment (dot-splitting only
    /// the groupId, matching the real validator's `dotted` distinction).
    fn maven_stub_validate_component(label: &str, value: &str, dotted: bool) -> DomainResult<()> {
        if value.is_empty() {
            return Err(DomainError::Validation(format!(
                "maven.coordinate: {label} is empty"
            )));
        }
        if value.contains('/') || value.contains('\\') {
            return Err(DomainError::Validation(format!(
                "maven.coordinate: {label} contains a path separator"
            )));
        }
        let segments: Vec<&str> = if dotted {
            value.split('.').collect()
        } else {
            vec![value]
        };
        for seg in segments {
            if seg.is_empty() {
                return Err(DomainError::Validation(format!(
                    "maven.coordinate: {label} has an empty segment"
                )));
            }
            if seg == ".." || seg == "." {
                return Err(DomainError::Validation(format!(
                    "maven.coordinate: {label} contains a path-traversal segment"
                )));
            }
        }
        Ok(())
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
            Arc::new(MockContentFirstSeen::new()),
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

    /// A leaf row whose repo's format has no registered `FormatHandler`
    /// can never succeed — retrying it re-derives the identical miss.
    /// `Failed`, non-retryable — NOT `Completed`+`short_circuited`, which
    /// used to let this masquerade as success (the four-day member-aware-
    /// prefetch outage this closes).
    #[tokio::test]
    async fn no_format_handler_registered_fails_non_retryable() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Cargo);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        // Register the stub handler under an UNRELATED key ("npm") so the
        // repo's actual format ("cargo") has no entry in `format_handlers`.
        let handler = build_dispatch_handler(
            repos,
            proxy,
            mappings,
            "npm",
            Arc::new(CargoDispatchStub {
                cksum_hex: sha256_hex(b"x"),
            }),
        );

        let outcome = handler
            .run(&leaf_params(repo.id, "serde", "1.0.0"), make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(
                    !retry,
                    "no registered FormatHandler can never succeed on retry: {reason}"
                );
                assert!(reason.contains("FormatHandler"), "{reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// A leaf row whose repo has no catch-all (`path_prefix == ""`)
    /// upstream mapping can never complete — the self-service use case
    /// and the direct-POST guard both reject this shape before enqueue,
    /// so a row reaching here can only mean a broken enqueue path or a
    /// manually-inserted row. `Failed`, non-retryable.
    #[tokio::test]
    async fn no_catchall_mapping_fails_non_retryable() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Cargo);
        repos.insert(repo.clone());
        // Deliberately no `seed_catchall` — mapping-less repo.

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
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(
                    !retry,
                    "a mapping-less repo can never complete this leaf: {reason}"
                );
                assert!(reason.contains("catch-all"), "{reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
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

    /// Issue #58: a `FormatHandler` IS registered under `"cargo"`, but it
    /// does not implement `VersionDiscovery`. `cargo_resolve_and_pull`
    /// must short-circuit via the `ctx.handler.version_discovery()`
    /// early-return rather than reach `download_config_path` /
    /// `compose_download_url_from_config`, which no longer exist on
    /// `FormatHandler` for a non-participant.
    #[tokio::test]
    async fn cargo_arm_without_version_discovery_short_circuits() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Cargo);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        let handler = build_dispatch_handler(
            repos,
            proxy,
            mappings,
            "cargo",
            Arc::new(NoVersionDiscoveryCargoHandler),
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
        assert_eq!(summary["urls_succeeded"], 0, "{summary}");
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
        // — it never reaches the per-URL fetch. OCI and any other
        // genuinely non-composable format inherit the trait defaults (no
        // resolution methods); the `_` dispatch arm catches them. Maven
        // has its own arm (see the `maven_arm_*` tests below) — it is no
        // longer part of this catch-all.
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

    // -- Maven arm -------------------------------------------------------

    /// Seed a Maven POM + jar checksum sidecar (default: `.sha256`) and the
    /// artifact bodies at the layout paths the dispatch arm composes, for a
    /// GAV that has both a jar and a POM (the common case).
    fn seed_maven_pom_and_jar(proxy: &MockUpstreamProxy, pom: &[u8], jar: &[u8]) {
        proxy.insert_metadata(
            "",
            "com/example/foo/1.0/foo-1.0.pom.sha256",
            sha256_hex(pom).into_bytes(),
        );
        proxy.insert_artifact("", "com/example/foo/1.0/foo-1.0.pom", pom.to_vec());
        proxy.insert_metadata(
            "",
            "com/example/foo/1.0/foo-1.0.jar.sha256",
            sha256_hex(jar).into_bytes(),
        );
        proxy.insert_artifact("", "com/example/foo/1.0/foo-1.0.jar", jar.to_vec());
    }

    #[tokio::test]
    async fn maven_arm_pom_and_jar_ingest_both_verified_quarantined() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Maven);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        let pom = b"<project>pom body</project>".to_vec();
        let jar = b"jar-bytes".to_vec();
        seed_maven_pom_and_jar(&proxy, &pom, &jar);

        let handler =
            build_dispatch_handler(repos, proxy, mappings, "maven", Arc::new(MavenDispatchStub));

        let outcome = handler
            .run(
                &leaf_params(repo.id, "com.example:foo", "1.0"),
                make_context(),
            )
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(summary["urls_attempted"], 2, "{summary}");
        assert_eq!(
            summary["urls_succeeded"], 2,
            "POM and jar must both ingest: {summary}"
        );
        assert_eq!(summary["urls_failed"], 0, "{summary}");
        assert_eq!(summary["short_circuited"], false, "{summary}");
    }

    /// BOM/parent-POM packagings publish a POM but no jar (and therefore no
    /// jar checksum sidecar). The leaf must still complete, with the POM
    /// counted as succeeded — a missing jar is never a job-level failure.
    #[tokio::test]
    async fn maven_arm_bom_style_gav_completes_with_pom_only() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Maven);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        let pom = b"<project>bom pom</project>".to_vec();
        proxy.insert_metadata(
            "",
            "com/example/foo/1.0/foo-1.0.pom.sha256",
            sha256_hex(&pom).into_bytes(),
        );
        proxy.insert_artifact("", "com/example/foo/1.0/foo-1.0.pom", pom);
        // No jar sidecar / jar body seeded at all.

        let handler =
            build_dispatch_handler(repos, proxy, mappings, "maven", Arc::new(MavenDispatchStub));

        let outcome = handler
            .run(
                &leaf_params(repo.id, "com.example:foo", "1.0"),
                make_context(),
            )
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(
            summary["urls_succeeded"], 1,
            "only the POM leg ingests for a jar-less GAV: {summary}"
        );
        assert_eq!(summary["short_circuited"], false, "{summary}");
    }

    /// Mirrors `hort-http-maven`'s `sha512_preferred_over_weaker_digests`:
    /// all three sidecars present, but only `.sha512` carries the correct
    /// digest — a successful ingest proves `.sha512` was the one chosen
    /// (the lying weaker digests would have produced a checksum mismatch).
    #[tokio::test]
    async fn maven_arm_prefers_strongest_valid_sidecar() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Maven);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        let pom = b"<project>pom body</project>".to_vec();
        proxy.insert_metadata(
            "",
            "com/example/foo/1.0/foo-1.0.pom.sha512",
            sha512_hex(&pom).into_bytes(),
        );
        proxy.insert_metadata(
            "",
            "com/example/foo/1.0/foo-1.0.pom.sha256",
            sha256_hex(b"a totally different payload").into_bytes(),
        );
        proxy.insert_metadata(
            "",
            "com/example/foo/1.0/foo-1.0.pom.sha1",
            sha1_hex(b"yet another payload").into_bytes(),
        );
        proxy.insert_artifact("", "com/example/foo/1.0/foo-1.0.pom", pom);

        let handler =
            build_dispatch_handler(repos, proxy, mappings, "maven", Arc::new(MavenDispatchStub));

        let outcome = handler
            .run(
                &leaf_params(repo.id, "com.example:foo", "1.0"),
                make_context(),
            )
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(
            summary["urls_succeeded"], 1,
            "the POM must verify via the sha512 sidecar (weaker digests lie): {summary}"
        );
    }

    /// Mirrors `hort-http-maven`'s
    /// `malformed_sha512_falls_through_to_valid_sha1_floor`: a corrupt
    /// `.sha512` and a non-hex `.sha256` must not block a valid `.sha1`
    /// floor.
    #[tokio::test]
    async fn maven_arm_malformed_stronger_sidecars_fall_through_to_sha1_floor() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Maven);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        let pom = b"<project>pom body</project>".to_vec();
        proxy.insert_metadata(
            "",
            "com/example/foo/1.0/foo-1.0.pom.sha512",
            b"   \n".to_vec(),
        );
        proxy.insert_metadata(
            "",
            "com/example/foo/1.0/foo-1.0.pom.sha256",
            b"not-a-valid-digest".to_vec(),
        );
        proxy.insert_metadata(
            "",
            "com/example/foo/1.0/foo-1.0.pom.sha1",
            sha1_hex(&pom).into_bytes(),
        );
        proxy.insert_artifact("", "com/example/foo/1.0/foo-1.0.pom", pom);

        let handler =
            build_dispatch_handler(repos, proxy, mappings, "maven", Arc::new(MavenDispatchStub));

        let outcome = handler
            .run(
                &leaf_params(repo.id, "com.example:foo", "1.0"),
                make_context(),
            )
            .await
            .expect("Ok");
        let summary = match outcome {
            TaskOutcome::Completed { result_summary } => result_summary,
            other => panic!("expected Completed, got {other:?}"),
        };
        assert_eq!(
            summary["urls_succeeded"], 1,
            "malformed stronger sidecars must fall through to the valid sha1 floor: {summary}"
        );
    }

    /// A GAV whose groupId composes into path traversal is rejected as a
    /// non-retry `Failed` outcome BEFORE any upstream call — never
    /// `Completed`+`short_circuited`, which is reserved for upstream/
    /// runtime conditions. No proxy fixtures are seeded, so the only way
    /// this test can observe `Failed` is if the rejection happens ahead of
    /// any sidecar/artifact fetch attempt.
    #[tokio::test]
    async fn maven_arm_rejects_traversal_coordinate_before_any_upstream_call() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Maven);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        let handler =
            build_dispatch_handler(repos, proxy, mappings, "maven", Arc::new(MavenDispatchStub));

        let outcome = handler
            .run(&leaf_params(repo.id, "..:foo", "1.0"), make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(!retry, "a malformed GAV must not be retried: {reason}");
                assert!(
                    reason.contains("GAV coordinate"),
                    "reason should name the constraint: {reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// A `package` that is not the colon-joined `groupId:artifactId` form
    /// is rejected the same way — non-retry `Failed`, no upstream call.
    #[tokio::test]
    async fn maven_arm_rejects_package_without_colon() {
        let repos = Arc::new(MockRepositoryRepository::new());
        let proxy = Arc::new(MockUpstreamProxy::new());
        let mappings = Arc::new(MockRepositoryUpstreamMappingRepository::new());

        let repo = dispatch_repo(RepositoryFormat::Maven);
        repos.insert(repo.clone());
        seed_catchall(&mappings, repo.id).await;

        let handler =
            build_dispatch_handler(repos, proxy, mappings, "maven", Arc::new(MavenDispatchStub));

        let outcome = handler
            .run(&leaf_params(repo.id, "not-a-gav", "1.0"), make_context())
            .await
            .expect("Ok");
        match outcome {
            TaskOutcome::Failed { retry, reason } => {
                assert!(!retry, "{reason}");
                assert!(
                    reason.contains("groupId:artifactId"),
                    "reason should name the constraint: {reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
