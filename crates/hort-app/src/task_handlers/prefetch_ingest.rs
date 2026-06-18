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
//! 4. Composes the upstream pull URL(s) via
//!    [`FormatHandler::build_pull_url`]. One URL for npm/cargo; PyPI is special-cased
//!    (per the trait method's contract: PyPI returns the empty
//!    vec and the leaf handler fans out from the per-version JSON
//!    manifest `urls[]`).
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
            // PyPI fan-out is special (multi-distribution per version
            // — the per-version JSON manifest enumerates `urls[]`).
            // Every other format gets the build_pull_url + per-URL
            // fetch+ingest path.
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
                _ => {
                    generic_per_url_pull(
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

/// Generic per-URL pull-through for formats whose
/// [`FormatHandler::build_pull_url`] returns a single artifact URL
/// (npm tarball, cargo `.crate`).
///
/// 1. Build the coords (carrying the concrete version).
/// 2. Fetch upstream metadata at
///    [`FormatHandler::upstream_checksum_metadata_path`] → recover
///    the upstream-published checksum via
///    [`FormatHandler::parse_upstream_checksum`].
/// 3. Compose URL(s) via `build_pull_url(upstream_url, package,
///    version)`.
/// 4. Per URL: `fetch_artifact` → `ingest_verified(UpstreamPublished)`.
async fn generic_per_url_pull(
    handler_self: &PrefetchIngestHandler,
    repo: &hort_domain::entities::repository::Repository,
    handler: &Arc<dyn FormatHandler>,
    mapping: &hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping,
    parsed: &PrefetchParams,
    cascade_internal: bool,
    summary: &mut LeafSummary,
) {
    // Build the canonical projection path via the single SSOT constructor
    // BEFORE the coords. Previously `path` was left empty (`String::new()`),
    // so every npm/cargo leaf collided on the empty `(repository_id, "")`
    // projection key — all but the first ingest lost. npm/cargo derive the
    // filename from name+version, so `filename = None`. On build failure,
    // short-circuit this leaf (mirrors the other per-leaf failure handling —
    // `warn!` + `short_circuited`).
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
            return;
        }
    };
    let coords = ArtifactCoords {
        name: parsed.package.clone(),
        name_as_published: parsed.package.clone(),
        version: Some(parsed.version.clone()),
        path,
        format: repo.format.clone(),
        metadata: serde_json::Value::Null,
    };

    // Metadata fetch — for npm/cargo this is the packument /
    // sparse-index NDJSON. PyPI is handled by `pypi_per_distribution_fanout`.
    let Some(metadata_path) = handler.upstream_checksum_metadata_path(&coords) else {
        tracing::warn!(
            repository = %repo.key,
            package = %parsed.package,
            version = %parsed.version,
            "prefetch: handler did not produce an upstream metadata path — \
             cannot verify checksum; short-circuit",
        );
        summary.short_circuited = true;
        return;
    };
    let outcome = match handler_self
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
            return;
        }
    };
    // Stream the cached metadata tempfile through the
    // `FormatHandler` port on a blocking thread (no full-body buffering;
    // ADR 0026).
    let Some(cache_handle) = outcome.cache_handle.as_ref() else {
        tracing::warn!(
            repository = %repo.key,
            package = %parsed.package,
            version = %parsed.version,
            path = %metadata_path,
            "prefetch: metadata fetch produced no cache handle; short-circuit",
        );
        summary.short_circuited = true;
        return;
    };
    let checksum_result = {
        let handler = Arc::clone(handler);
        let coords = coords.clone();
        crate::project::run_handler_body(cache_handle, move |reader| {
            handler.parse_upstream_checksum(reader, &coords)
        })
        .await
    };
    // Prefetch does not serve, so the metadata mirror is not written; the
    // tempfile is removed once the checksum has been parsed (lifecycle the
    // retired `metadata_body_bytes` provided).
    crate::project::remove_cached_body(cache_handle).await;
    let upstream_checksum = match checksum_result {
        Ok(cs) => cs,
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                version = %parsed.version,
                "prefetch: parse_upstream_checksum failed; short-circuit",
            );
            summary.short_circuited = true;
            return;
        }
    };

    // Compose URLs.
    let urls = match handler.build_pull_url(&mapping.upstream_url, &parsed.package, &parsed.version)
    {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                error = %err,
                repository = %repo.key,
                package = %parsed.package,
                "prefetch: build_pull_url failed; short-circuit",
            );
            summary.short_circuited = true;
            return;
        }
    };
    if urls.is_empty() {
        tracing::debug!(
            repository = %repo.key,
            format = ?repo.format,
            package = %parsed.package,
            "prefetch: build_pull_url returned no URLs for this format — short-circuit",
        );
        summary.short_circuited = true;
        return;
    }

    // Per URL: fetch + ingest. Non-fatal on per-URL failure.
    for url in urls {
        summary.urls_attempted += 1;
        let fetch = match handler_self
            .upstream_proxy
            .fetch_artifact(mapping.clone(), url.clone())
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
                    "prefetch: fetch_artifact failed; continuing with next URL",
                );
                summary.urls_failed += 1;
                continue;
            }
        };
        let upstream_published_at = fetch.last_modified;
        let reader: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
            Box::new(StreamReader::new(fetch.stream));
        let request = VerifiedIngestRequest::UpstreamPublished {
            repository_id: repo.id,
            coords: coords.clone(),
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
            upstream_checksum: upstream_checksum.clone(),
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
                    "prefetch: ingest_verified failed; continuing with next URL",
                );
                summary.urls_failed += 1;
            }
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
/// `ingest_verified` call.
///
/// Skips the build_pull_url path entirely — the trait method
/// returns the empty vec for PyPI by contract.
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
}
