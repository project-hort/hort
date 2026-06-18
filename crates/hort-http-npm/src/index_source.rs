//! npm `IndexSource` impls (see `docs/architecture/explanation/index-construction.md`).
//!
//! This module defines the per-format-internal [`IndexSource`] trait
//! (`pub(crate)` — sources stay in the format HTTP crate because hosted
//! needs `ArtifactUseCase` access and proxy needs the upstream-fetch
//! ports) and its two npm implementations:
//!
//! - [`HostedNpmSource`] — reads the local artifact projection via
//!   [`ArtifactUseCase::list_by_raw_name_visible`] (threading the
//!   caller principal so anti-enumeration applies — denied / no-rows /
//!   missing-repo all collapse to `NotFound` at the unified handler).
//! - [`ProxyNpmSource`] — drives the upstream-fetch, cache, dedup,
//!   and stale-while-error path via
//!   [`crate::packument::fetch_raw_with_cache`] (which streams the body
//!   through the projector and returns the small `NpmProjection` — the
//!   raw body goes to the mirror, the projection to Redis), and
//!   constructs one [`VersionEntry`] per upstream version with status
//!   hydrated from [`ArtifactUseCase::package_version_status`]. The
//!   prefetch trigger also fires from this source on every successful
//!   fetch, consuming the projection directly
//!   (see `docs/architecture/explanation/prefetch-pipeline.md`).
//!
//! Both sources convert their per-version metadata into the spine
//! [`VersionEntry`] (plus [`NpmVersionPayload`]). The post-source
//! filter pipeline (`NonServableStatusFilter` + `IndexModeFilter`)
//! and the builder ([`NpmIndexBuilder`]) are reached through the
//! unified serve handler at `crates/hort-http-npm/src/serve.rs`.
//!
//! # Error shape
//!
//! Both adapters return [`AppError`] — the existing shape — rather
//! than inventing a new error enum. The mapping back to HTTP
//! responses happens at the unified handler:
//! - hosted source's `NotFound { entity: "Repository" }` (invisible
//!   repo / missing repo) → 404 (anti-enumeration);
//! - hosted source returning an empty entry vector → 404 (the
//!   unified handler emits the same `Artifact NotFound` envelope as
//!   the previous `serve_packument`);
//! - proxy source's `UpstreamUnavailable` / `Internal` / `NoUpstream`
//!   → preserved wire mapping (502 / 500 / 404).
//!
//! Note the `truncated` channel: [`IndexSourceOutput`] carries a
//! per-call `truncated: bool` so the hosted source can propagate the
//! [`LimitedList::truncated`] flag the use case returns. The unified
//! handler converts that into the `Warning: 299 - "results
//! truncated at <cap> items"` response header.
//! The proxy source always sets `truncated = false` (npm packuments
//! are 10 MB-capped upstream-side, not paginated — there is no
//! truncation channel to surface).

use std::sync::Arc;

use async_trait::async_trait;

use hort_app::error::AppError;
use hort_app::use_cases::index_serve::{NpmVersionPayload, PerVersionPayload, VersionEntry};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::Repository;
use hort_formats::npm::NpmFormatHandler;
use hort_http_core::context::AppContext;

use crate::packument::PackumentFetchError;

/// Output of one [`IndexSource::fetch`] call.
///
/// `truncated` is the channel the hosted source uses to propagate the
/// [`LimitedList::truncated`] flag from
/// [`ArtifactUseCase::list_by_raw_name_visible`]; the unified handler
/// converts it into the `Warning: 299` response header. The proxy
/// source always sets it to `false` (npm packuments are
/// upstream-capped, not paginated).
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
    /// Canonical package name to embed as the packument's top-level
    /// `name` field. For the hosted source this is the *stored*
    /// canonical name (the npm drift-resilience pin — the stored
    /// form is what the unified handler embeds, not the request
    /// parameter); for the proxy source this is the requested
    /// `pkg_name` (upstream's top-level `name` carries the same
    /// value, no transform needed). Threaded through to the
    /// `BuildContext::package_name`.
    pub canonical_name: String,
}

/// Per-format index source — produces `Vec<VersionEntry>` from either
/// local DB (hosted) or upstream fetch+parse (proxy). Stays
/// Stays `pub(crate)` — sources are an implementation detail of the
/// format HTTP crate.
///
/// Async because the hosted source reads `ArtifactUseCase` (which
/// goes through the storage adapter) and the proxy source dials
/// upstream. Trait-object dispatch (`Box<dyn IndexSource>`) costs
/// one virtual call per request, well below the network and storage
/// round-trips that dominate the serve.
#[async_trait]
pub(crate) trait IndexSource: Send + Sync {
    /// Produce per-version entries for `package_name` on `repo`.
    /// `caller` is threaded for anti-enumeration (the hosted source's
    /// use-case call requires it).
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        package_name: &str,
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
/// per-resource-visibility-enforcing entry point — anti-enumeration
/// invariant). Returns the stored canonical name as
/// [`IndexSourceOutput::canonical_name`] so the unified handler can
/// pin the wire shape to the drift-resilience contract (see ADR 0008):
/// the request-parameter form is *not* echoed back — the stored form
/// is, which is also what the per-version `dist.tarball` URL embeds.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct HostedNpmSource;

#[async_trait]
impl IndexSource for HostedNpmSource {
    #[tracing::instrument(skip(self, ctx, caller), fields(repo_key = %repo.key))]
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        package_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> Result<IndexSourceOutput, AppError> {
        // `list_by_raw_name_visible` performs the
        // `RepositoryAccessUseCase::resolve(_, actor, Read)` hop
        // before reading rows: invisible / missing repo collapses to
        // `NotFound { entity: "Repository" }` (anti-enumeration); the
        // unified handler maps both arms back into the same 404
        // envelope.
        let handler = NpmFormatHandler;
        let (resolved_repo, artifact_list) = ctx
            .artifact_use_case
            .list_by_raw_name_visible(&repo.key, &handler, package_name, caller)
            .await?;
        // Defence-in-depth: the use case re-resolved the repo (its
        // visibility predicate is authoritative); the `repo` the
        // unified handler held cannot be a different one in practice,
        // but the assertion documents the invariant.
        debug_assert_eq!(resolved_repo.id, repo.id);
        let truncated = artifact_list.truncated;
        let artifacts = artifact_list.items;

        // Reflect the stored canonical name in the top-level
        // `name` — drift-resilience rule: the stored form is what
        // the unified handler embeds, not the request parameter
        // (see ADR 0008).
        let canonical_name = artifacts
            .first()
            .map(|a| a.name.clone())
            .unwrap_or_else(|| package_name.to_string());

        let mut entries = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            // Versionless rows are not part of the packument; skip.
            let Some(version) = artifact.version.clone() else {
                continue;
            };
            let filename = artifact
                .path
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_string();
            let shasum = artifact.sha1_checksum.clone().unwrap_or_default();
            // Hosted has no SRI capture path today.
            let payload = NpmVersionPayload {
                name_as_published: artifact.name.clone(),
                tarball_basename: filename,
                integrity: None,
                shasum,
            };
            entries.push(VersionEntry {
                version,
                status: Some(artifact.quarantine_status),
                payload: PerVersionPayload::Npm(payload),
            });
        }

        Ok(IndexSourceOutput {
            entries,
            truncated,
            canonical_name,
        })
    }
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

/// `IndexSource` impl for `RepositoryType::Proxy`.
///
/// Calls [`crate::packument::fetch_with_cache`] (which drives the
/// `UpstreamProxy::fetch_metadata` port through the established
/// cache + dedup + stale-while-error path — preserving upstream
/// verification invariants per ADR 0006), parses the returned packument
/// body, and
/// converts each upstream version into a [`VersionEntry`] with
/// per-version status hydrated via
/// [`ArtifactUseCase::package_version_status`].
///
/// **No new port shape.** Source adapters reuse the existing surface.
/// The proxy source's only behaviour beyond the upstream-IO path
/// (`crate::packument`) is the parse-then-construct step. The unified
/// builder constructs absolute tarball URLs from
/// `NpmVersionPayload::tarball_basename` at build time.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ProxyNpmSource;

#[async_trait]
impl IndexSource for ProxyNpmSource {
    #[tracing::instrument(skip(self, ctx, caller), fields(repo_key = %repo.key))]
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        package_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> Result<IndexSourceOutput, AppError> {
        // Anti-enumeration thread-through: the unified handler resolves
        // the repo before invoking the source; we re-resolve here
        // defensively so the invariant holds even if a future caller
        // bypasses the dispatch hop. The re-resolve is a single in-memory
        // hashmap probe at the mock layer / index lookup at the adapter
        // — sub-millisecond.
        let _ = ctx
            .repository_access_use_case
            .resolve(
                &repo.key,
                caller,
                hort_app::use_cases::repository_access::AccessLevel::Read,
            )
            .await?;

        // The helper takes explicit deps to keep `hort-formats-upstream`
        // from needing `Arc<AppContext>` (composition-cycle constraint).
        // In-crate callers pass the corresponding ctx fields by ref.
        // The helper returns the streamed PROJECTION (the raw body went
        // to the mirror). Serve renders the projection directly; no
        // `Cursor::project` re-parse here.
        let projection = match crate::packument::fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            ctx.upstream_projector_version_object_max_bytes,
            repo,
            package_name,
        )
        .await
        {
            Ok(p) => p,
            Err(PackumentFetchError::NoUpstream) => {
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::NotFound {
                        entity: "Artifact",
                        id: package_name.to_string(),
                    },
                ));
            }
            Err(PackumentFetchError::UpstreamUnavailable) => {
                // Preserve the wire mapping: surface as a typed error
                // the unified handler converts to 502. The most fitting
                // `AppError` variant is `External` (the dispatch site's
                // prior site used a hand-built 502 response; the unified
                // handler is responsible for the mapping, see `serve.rs`).
                return Err(AppError::External(
                    "npm upstream unavailable; no cached fallback".to_string(),
                ));
            }
            Err(PackumentFetchError::UpstreamBodyTooLarge {
                fetch_class,
                bytes_read,
                cap,
            }) => {
                // Surface the honest storage-backstop classification
                // (502 + bytes_read/cap structured body via
                // `ApiError::into_response`) instead of folding into
                // the generic `External("upstream unavailable")` envelope.
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::UpstreamBodyTooLarge {
                        fetch_class,
                        bytes_read,
                        cap,
                    },
                ));
            }
            Err(PackumentFetchError::VersionObjectTooLarge { cause }) => {
                // A per-version-object cap trip fails closed (nothing
                // cached). Emit the `version_object_too_large` metric
                // so the rejection is observable, then surface as
                // `Validation` → 400 (parse-class, NOT the network
                // bucket).
                let repo_label = if ctx.include_repository_label {
                    repo.key.as_str()
                } else {
                    hort_app::metrics::values::REPOSITORY_ALL
                };
                hort_app::metrics::emit_upstream_version_object_too_large("npm", repo_label);
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::Validation(cause),
                ));
            }
            Err(PackumentFetchError::MetadataMalformed { cause }) => {
                // A malformed upstream body surfaces as
                // `result=parse_error` (a 4xx via the `Validation` → 400
                // mapping), NEVER the network / `upstream_unavailable`
                // bucket. Fail-closed: nothing was cached or mirrored.
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::Validation(cause),
                ));
            }
            Err(PackumentFetchError::Internal(msg)) => {
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::Invariant(msg),
                ));
            }
        };

        // Per-version status hydration — used by
        // `NonServableStatusFilter` + `IndexModeFilter`. A status-query
        // failure degrades to "no status known".
        let pkg_status = ctx
            .artifact_use_case
            .package_version_status(repo.id, package_name)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "npm proxy source: package_version_status failed; degrading to no status");
                Vec::new()
            });

        // Fire the prefetch trigger on every successful fetch
        // (fresh-cache-hit, upstream success, and stale-while-error
        // all yield the projection through `fetch_raw_with_cache`).
        // Best-effort; never blocks the serve. The trigger consumes
        // the projection directly (no second parse of a raw body).
        crate::packument::fire_prefetch_trigger_npm(
            ctx,
            repo,
            package_name,
            &projection,
            &pkg_status,
        );

        let status_map: std::collections::HashMap<
            &str,
            hort_domain::entities::artifact::QuarantineStatus,
        > = pkg_status.iter().map(|(v, s)| (v.as_str(), *s)).collect();

        // The projection is already computed (the helper streamed the
        // body through `NpmPackumentProjector` on the ingest path;
        // serve renders the cached projection with no re-parse). A
        // per-version-object cap trip / malformed body fails closed
        // inside `fetch_and_project` (validate-before-commit) and
        // surfaces as a `PackumentFetchError` above — it never
        // reaches here as an empty-then-cached body.
        let mut entries: Vec<VersionEntry> = Vec::new();
        for v in projection.versions {
            // Per-version `name` — validated against the npm allowlist
            // before substitution. A mismatch drops the entry entirely;
            // the unified builder constructs the URL from the payload,
            // so a missing/invalid name has no honest passthrough.
            let name_as_published = match v.name_as_published.as_deref() {
                Some(name) if hort_formats::npm::validate_npm_name(name).is_ok() => {
                    name.to_string()
                }
                other => {
                    tracing::warn!(
                        package = %package_name,
                        version = %v.version,
                        observed_name = %other.unwrap_or("<missing>").chars().take(64).collect::<String>(),
                        "npm proxy source: per-version `name` failed allowlist; dropping entry",
                    );
                    continue;
                }
            };

            // Tarball basename: split on `/-/` per the npm convention
            // (every npm tarball URL uses `.../{pkg}/-/{basename}`).
            let tarball_basename = v
                .tarball
                .as_deref()
                .and_then(|t| t.rsplit_once("/-/").map(|(_, b)| b.to_string()));
            let Some(tarball_basename) = tarball_basename else {
                tracing::debug!(
                    package = %package_name,
                    version = %v.version,
                    "npm proxy source: missing/malformed dist.tarball; dropping entry",
                );
                continue;
            };

            let status = status_map.get(v.version.as_str()).copied();
            entries.push(VersionEntry {
                version: v.version.clone(),
                status,
                payload: PerVersionPayload::Npm(NpmVersionPayload {
                    name_as_published,
                    tarball_basename,
                    integrity: v.integrity,
                    shasum: v.shasum.unwrap_or_default(),
                }),
            });
        }

        Ok(IndexSourceOutput {
            entries,
            truncated: false,
            canonical_name: package_name.to_string(),
        })
    }
}
