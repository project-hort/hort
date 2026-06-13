//! Cargo `IndexSource` impls for the unified sparse-index pipeline
//! (see `docs/architecture/explanation/index-construction.md`).
//!
//! Mirrors the npm and PyPI shapes. The per-format-internal
//! [`IndexSource`] trait is `pub(crate)` (sources stay in the format
//! HTTP crate because hosted needs `ArtifactUseCase` access and proxy
//! needs the upstream-fetch ports) and has two Cargo implementations:
//!
//! - [`HostedCargoSource`] — reads the local artifact projection via
//!   [`ArtifactUseCase::list_by_raw_name_visible`] (threading the
//!   caller principal so F-25 anti-enumeration applies — denied / no-
//!   rows / missing-repo all collapse to `NotFound` at the unified
//!   handler).
//! - [`ProxyCargoSource`] — drives the upstream-fetch + cache +
//!   dedup + stale-while-error pipeline via
//!   [`crate::index_cache::fetch_raw_with_cache`] (which streams the
//!   body through the projector and returns the small
//!   `Vec<CargoVersionLine>` projection — the raw NDJSON body goes to
//!   the mirror, the projection to Redis; see ADR 0026), then maps
//!   each [`CargoVersionLine`] into one [`VersionEntry`] for the
//!   unified Source → Filter → Builder pipeline. The prefetch trigger
//!   (see `docs/architecture/explanation/prefetch-pipeline.md`) fires
//!   from this source after the fetch, consuming the projection
//!   directly.
//!
//! # Why drive the existing `fetch_raw_with_cache` rather than dial
//! # upstream directly
//!
//! `fetch_raw_with_cache` already implements all the cache-layer
//! invariants the unified handler must preserve byte-for-byte:
//!
//! - cache key format / mapping-id invalidation axis;
//! - `PullDedup` single-flight coalescing;
//! - stale-while-error fallback.
//!
//! The quarantine-aware serve filter previously lived inside the cache
//! helper (`apply_quarantine_filter`); the unified pipeline moved it
//! into `NonServableStatusFilter` + `IndexModeFilter`, applied
//! post-source. The prefetch trigger fires from this source after the
//! raw fetch (`fire_prefetch_trigger_cargo`).
//!
//! # Output of the proxy source
//!
//! [`ProxyCargoSource::fetch`] parses the raw upstream NDJSON line-by-
//! line and produces one [`VersionEntry`] per line, with `status`
//! hydrated from [`ArtifactUseCase::package_version_status`] (`None`
//! when the registry has never seen the version). Each entry's
//! `payload.Cargo` carries the NDJSON-line fields the builder needs.
//!
//! # `truncated` channel
//!
//! [`IndexSourceOutput::truncated`] lets the hosted source propagate
//! the `LimitedList::truncated` flag into a `Warning: 299` header.
//! Cargo mirrors the npm/PyPI shape: hosted sources can be truncated
//! (the paginated read caps at `LIMIT_LIST_MAX_ITEMS`); proxy sources
//! cannot (upstream cargo sparse-index NDJSON is not paginated on the
//! wire). Re-declared here per the design (sources are crate-private;
//! the support type is also crate-private and per-crate-local) —
//! mirrors `IndexSourceOutput` in `hort-http-npm/src/index_source.rs`
//! and `hort-http-pypi/src/index_source.rs`.

use std::sync::Arc;

use async_trait::async_trait;

use hort_app::error::AppError;
use hort_app::use_cases::index_serve::{CargoVersionPayload, PerVersionPayload, VersionEntry};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::Repository;
use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::cargo::projection::CargoVersionLine;
use hort_formats::cargo::CargoFormatHandler;
use hort_http_core::context::AppContext;

use crate::index_cache::IndexFetchError;

/// Output of one [`IndexSource::fetch`] call.
///
/// `truncated` is the channel the hosted source uses to propagate the
/// [`LimitedList::truncated`] flag from
/// [`ArtifactUseCase::list_by_raw_name_visible`]; the unified handler
/// converts it into the `Warning: 299` response header. The proxy
/// source always sets it to `false` (Cargo sparse-index NDJSON is not
/// paginated at the wire layer).
#[derive(Debug)]
pub(crate) struct IndexSourceOutput {
    /// Per-version entries the source produced — fed verbatim into
    /// the [`crate::serve`] handler's filter pipeline.
    pub entries: Vec<VersionEntry>,
    /// True iff the underlying paginated read hit
    /// [`LIMIT_LIST_MAX_ITEMS`](hort_domain::types::LIMIT_LIST_MAX_ITEMS).
    /// The unified handler emits a `Warning: 299` header when this is
    /// true; only the hosted source is paginated.
    pub truncated: bool,
}

/// Per-format index source. Stays `pub(crate)` per design §2.3 —
/// sources are an implementation detail of the format HTTP crate.
#[async_trait]
pub(crate) trait IndexSource: Send + Sync {
    /// Produce per-version entries for `crate_name` on `repo`.
    /// `caller` is threaded for F-25 anti-enumeration (the hosted
    /// source's use-case call requires it).
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        crate_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> Result<IndexSourceOutput, AppError>;
}

// ---------------------------------------------------------------------------
// Hosted
// ---------------------------------------------------------------------------

/// `IndexSource` impl for `RepositoryType::Hosted` (and `Staging` /
/// `Virtual`, which the dispatch site treats as "anything not Proxy").
///
/// Reads the local artifact projection via
/// [`ArtifactUseCase::list_by_raw_name_visible`] (the
/// per-resource-visibility-enforcing entry point — F-25 invariant).
/// Each Artifact row becomes one [`VersionEntry`] whose
/// `payload.Cargo` carries the hosted-emission NDJSON-line fields:
/// `name` from `Artifact.name` (drift-resilience pin), `vers` from
/// `Artifact.version`, `cksum` from `Artifact.sha256_checksum`,
/// `deps = []`, `features = {}`, `yanked = false`, `links / rust_version
/// / v / features2 = None`.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct HostedCargoSource;

#[async_trait]
impl IndexSource for HostedCargoSource {
    #[tracing::instrument(skip(self, ctx, caller), fields(repo_key = %repo.key))]
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        crate_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> Result<IndexSourceOutput, AppError> {
        // `list_by_raw_name_visible` performs the
        // `RepositoryAccessUseCase::resolve(_, actor, Read)` hop
        // before reading rows: invisible / missing repo collapses to
        // `NotFound { entity: "Repository" }` (anti-enumeration); the
        // unified handler maps both arms back into the same 404
        // envelope the hosted serve emitted.
        let handler = CargoFormatHandler;
        let (resolved_repo, artifact_list) = ctx
            .artifact_use_case
            .list_by_raw_name_visible(&repo.key, &handler, crate_name, caller)
            .await?;
        // Defence-in-depth: the use case re-resolved the repo (its
        // visibility predicate is authoritative); the `repo` the
        // unified handler held cannot be a different one in practice,
        // but the assertion documents the invariant.
        debug_assert_eq!(resolved_repo.id, repo.id);
        let truncated = artifact_list.truncated;
        let artifacts = artifact_list.items;

        let mut entries = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            // Versionless rows are not part of the sparse-index; skip.
            let Some(version) = artifact.version.clone() else {
                continue;
            };
            let payload = CargoVersionPayload {
                // Drift-resilience: use the STORED name, not the
                // re-normalised request parameter. Under drift this
                // keeps each entry's `name` consistent with the path
                // where `find_by_path` will actually find it. Mirrors
                // the hosted local-NDJSON path.
                name_as_published: artifact.name.clone(),
                vers: version.clone(),
                cksum: artifact.sha256_checksum.to_string(),
                deps: serde_json::json!([]),
                features: serde_json::json!({}),
                yanked: false,
                links: None,
                rust_version: None,
                v: None,
                features2: None,
            };
            entries.push(VersionEntry {
                version,
                status: Some(artifact.quarantine_status),
                payload: PerVersionPayload::Cargo(payload),
            });
        }

        Ok(IndexSourceOutput { entries, truncated })
    }
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

/// `IndexSource` impl for `RepositoryType::Proxy`.
///
/// Calls the existing [`crate::index_cache::fetch_with_cache`] (which
/// drives the `UpstreamProxy::fetch_metadata` port through the
/// established cache + dedup + stale-while-error + quarantine-filter
/// pipeline, preserving every cache-invariant byte-for-byte), then
/// re-parses the served body into per-version [`VersionEntry`] rows
/// with status hydrated via
/// [`ArtifactUseCase::package_version_status`].
///
/// **No new port shape introduced.** Source adapters reuse the
/// existing surface. The proxy source's only new behaviour is the
/// re-parse step; the upstream-IO path is the existing serve path.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ProxyCargoSource;

#[async_trait]
impl IndexSource for ProxyCargoSource {
    #[tracing::instrument(skip(self, ctx, caller), fields(repo_key = %repo.key))]
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        crate_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> Result<IndexSourceOutput, AppError> {
        // F-25 thread-through — defensive re-resolve. The unified
        // handler performs `RepositoryAccessUseCase::resolve(_, actor,
        // Read)` before invoking the source; we re-resolve here
        // defensively so the F-25 invariant holds even if a future
        // caller bypasses the dispatch hop. Mirrors `ProxyNpmSource`'s
        // same defensive re-resolve.
        let _ = ctx
            .repository_access_use_case
            .resolve(
                &repo.key,
                caller,
                hort_app::use_cases::repository_access::AccessLevel::Read,
            )
            .await?;

        // Drive the existing cache + dedup + stale-while-error pipeline.
        // The helper streams the body through the projector and returns
        // the PROJECTION (`Vec<CargoVersionLine>`); the raw NDJSON went
        // to the mirror (see ADR 0026). Serve maps the projection
        // directly into entries; no `Cursor::project` re-parse here.
        // The helper takes explicit deps to keep
        // `hort-formats-upstream` from needing `Arc<AppContext>` (a
        // construction cycle). In-crate callers pass the corresponding
        // ctx fields by ref (+ `Some(ctx.metadata_mirror.as_ref())`).
        let projection = match crate::index_cache::fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            repo,
            crate_name,
        )
        .await
        {
            Ok(p) => p,
            Err(IndexFetchError::NoUpstream) => {
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::NotFound {
                        entity: "Artifact",
                        id: crate_name.to_string(),
                    },
                ));
            }
            Err(IndexFetchError::UpstreamUnavailable) => {
                return Err(AppError::External(
                    "cargo upstream unavailable; no cached fallback".to_string(),
                ));
            }
            Err(IndexFetchError::MetadataMalformed { cause }) => {
                // A malformed upstream NDJSON body surfaces as
                // `result=parse_error` (a 4xx via the `Validation` →
                // 400 mapping), NEVER the network /
                // `upstream_unavailable` bucket. Fail-closed: nothing
                // was cached or mirrored.
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::Validation(cause),
                ));
            }
            Err(IndexFetchError::Internal(msg)) => {
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::Invariant(msg),
                ));
            }
        };

        // Per-version status hydration — used by
        // `NonServableStatusFilter` + `IndexModeFilter`. A status-query
        // failure degrades to "no status known" (matches the
        // proxy-cache `fetch_with_cache` semantics).
        let handler = CargoFormatHandler;
        let normalized = handler.normalize_name(crate_name);
        let pkg_status = ctx
            .artifact_use_case
            .package_version_status(repo.id, &normalized)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "cargo proxy source: package_version_status failed; degrading to no status");
                Vec::new()
            });

        // Fire the prefetch trigger on every successful fetch. The
        // trigger consumes the already-computed projection directly (no
        // second parse of a raw body, which no longer exists at this
        // layer; see `docs/architecture/explanation/prefetch-pipeline.md`).
        crate::index_cache::fire_prefetch_trigger_cargo(
            ctx,
            repo,
            &normalized,
            &projection,
            &pkg_status,
        );
        let status_map: std::collections::HashMap<
            String,
            hort_domain::entities::artifact::QuarantineStatus,
        > = pkg_status.into_iter().collect();

        let entries = projection_to_entries(projection, &status_map);

        Ok(IndexSourceOutput {
            entries,
            truncated: false,
        })
    }
}

/// Map an already-projected cargo sparse-index
/// `Vec<CargoVersionLine>` into `Vec<VersionEntry>`. Each line becomes
/// one entry with `payload.Cargo` carrying the line's fields. The
/// `status_map` hydrates the entry's `status` field via
/// `(version, status)` lookup; absent → `None` (unknown tier).
///
/// The projection is already computed (the helper
/// `crate::index_cache::fetch_raw_with_cache` streamed the body through
/// `CargoSparseIndexProjector` on the fetch path; serve maps the cached
/// projection with no re-parse). A malformed NDJSON line fails closed
/// *inside* `fetch_and_project` (reject-on-invalid,
/// validate-before-commit) and surfaces as
/// `IndexFetchError::MetadataMalformed` above — it never reaches here
/// as a partially-projected body.
fn projection_to_entries(
    lines: Vec<CargoVersionLine>,
    status_map: &std::collections::HashMap<
        String,
        hort_domain::entities::artifact::QuarantineStatus,
    >,
) -> Vec<VersionEntry> {
    let mut entries: Vec<VersionEntry> = Vec::new();
    for line in lines {
        let status = status_map.get(&line.vers).copied();
        entries.push(VersionEntry {
            version: line.vers.clone(),
            status,
            payload: PerVersionPayload::Cargo(CargoVersionPayload {
                name_as_published: line.name,
                vers: line.vers,
                cksum: line.cksum,
                deps: line.deps,
                features: line.features,
                yanked: line.yanked,
                links: line.links,
                rust_version: line.rust_version,
                v: line.v,
                features2: line.features2,
            }),
        });
    }
    entries
}
