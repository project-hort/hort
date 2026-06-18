//! PyPI `IndexSource` impls (see `docs/architecture/how-to/pypi-pull-through.md`
//! and `docs/architecture/explanation/index-construction.md`).
//!
//! The per-format-internal [`IndexSource`] trait is `pub(crate)` (sources
//! stay in the format HTTP crate because hosted needs `ArtifactUseCase`
//! access and proxy needs the upstream-fetch ports) and has two
//! PyPI implementations:
//!
//! - [`HostedPypiSource`] — reads hort's local artifact projection via
//!   [`ArtifactUseCase::list_by_raw_name_visible`] (threading the
//!   caller principal so anti-enumeration applies — denied / no-rows /
//!   missing-repo all collapse to `NotFound` at the unified handler).
//! - [`ProxyPypiSource`] — reuses the existing
//!   [`crate::simple_index::fetch_with_cache`] port — which drives
//!   `UpstreamProxy::fetch_metadata` through the established cache +
//!   dedup + stale-while-error + URL-rewrite + quarantine-filter
//!   pipeline — and then *re-parses* the served body into per-version
//!   `VersionEntry` rows the filter pipeline + builder consume.
//!   Re-parsing post-filter bytes is idempotent
//!   (`NonServableStatusFilter`/`IndexModeFilter` would have dropped
//!   the same entries `fetch_with_cache`'s `apply_quarantine_filter`
//!   already removed); the pass-through keeps every URL-rewrite and
//!   quarantine invariant verbatim and adds zero new port shape.
//!
//! # Why call the existing `fetch_with_cache` rather than rewire the
//! # upstream path
//!
//! `fetch_with_cache` already implements all the invariants the unified
//! handler must preserve byte-for-byte:
//!
//! - cache key format / mapping-id invalidation axis (ADR 0006);
//! - `PullDedup` single-flight coalescing;
//! - quarantine-aware serve filter (per-format-arm — HTML / JSON);
//! - prefetch trigger fire-after-decode placement
//!   (see `docs/architecture/explanation/prefetch-pipeline.md`);
//! - stale-while-error fallback.
//!
//! Replicating those in the proxy source would duplicate ~250 lines
//! of stale-while-error + dedup + URL-rewrite logic. The cost of
//! re-parsing the rewritten body is one regex pass (HTML) or one
//! serde_json::from_slice (JSON) — sub-millisecond.
//!
//! # Output of the proxy source
//!
//! [`ProxyPypiSource::fetch`] returns one [`VersionEntry`] per
//! upstream version (group-by version of the served files), with
//! `status` hydrated from
//! [`ArtifactUseCase::package_version_status`] (`None` when hort has
//! never seen the version). Each entry's `payload.Pypi.files` carries
//! the per-file rows (sdist + N wheels) the builder turns back into
//! `<a>` anchors or `files[]` rows.
//!
//! # `truncated` channel
//!
//! The `IndexSourceOutput.truncated` channel lets the hosted source
//! propagate the `LimitedList::truncated` flag into a `Warning: 299`
//! header. PyPI mirrors that shape: hosted sources can be truncated
//! (the paginated read caps at `LIMIT_LIST_MAX_ITEMS`); proxy sources
//! cannot (upstream simple indices are not paginated on the wire).
//! `IndexSourceOutput` is re-declared here per the crate-private
//! convention (sources are crate-private; the support type is also
//! crate-private and per-crate-local).

use std::sync::Arc;

use async_trait::async_trait;
// `Bytes` is used only by the `#[cfg(test)]` `parse_body_to_entries`
// compat helper (the production serve path renders the cached projection).
#[cfg(test)]
use bytes::Bytes;

use hort_app::error::AppError;
use hort_app::use_cases::index_serve::{
    PerVersionPayload, PypiVersionFile, PypiVersionPayload, VersionEntry,
};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::Repository;
use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::pypi::projection::PypiSimpleIndexProjection;
use hort_formats::pypi::PyPiFormatHandler;
use hort_http_core::context::AppContext;

use crate::simple_index::{IndexFetchError, SimpleIndexFormat};

/// Output of one [`IndexSource::fetch`] call.
///
/// `truncated` is the channel the hosted source uses to propagate the
/// [`LimitedList::truncated`] flag from
/// [`ArtifactUseCase::list_by_raw_name_limited`]; the unified handler
/// converts it into the `Warning: 299` response header. The proxy
/// source always sets it to `false` (PyPI simple indices are not
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
    /// Canonical package name to embed as the served document's
    /// top-level `name` / `<title>`. For the hosted source this is
    /// the *stored* canonical name (the PyPI drift-resilience pin —
    /// the stored form from `artifacts.first().map(|a| a.name)`);
    /// for the proxy source this is the normalised project name.
    /// Threaded through to `BuildContext::package_name`.
    pub canonical_name: String,
}

/// Per-format index source. Stays `pub(crate)` —
/// sources are an implementation detail of the format HTTP crate.
#[async_trait]
pub(crate) trait IndexSource: Send + Sync {
    /// Produce per-version entries for `package_name` on `repo`.
    /// `caller` is threaded for anti-enumeration (the hosted
    /// source's use-case call requires it).
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

/// `IndexSource` impl for hosted / staging / virtual repos.
///
/// Reads the local artifact projection via
/// [`ArtifactUseCase::list_by_raw_name_visible`] (the anti-enumeration-
/// enforcing entry point) and groups artifacts by their
/// `version` field to produce one [`VersionEntry`] per version with
/// `payload.Pypi.files` carrying one [`PypiVersionFile`] per artifact
/// row in that version's group: each artifact row → one `<a>`.
///
/// **Drift-resilience pin** — emits `IndexSourceOutput.canonical_name`
/// as `artifacts.first().map(|a| a.name)` (or the request `package_name`
/// when no artifacts exist), so the unified handler's `BuildContext.
/// package_name` carries the stored form, not the request parameter.
/// Mirrors the npm `HostedNpmSource`'s same rule.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct HostedPypiSource;

#[async_trait]
impl IndexSource for HostedPypiSource {
    #[tracing::instrument(skip(self, ctx, caller), fields(repo_key = %repo.key))]
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        package_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> Result<IndexSourceOutput, AppError> {
        // Anti-enumeration + drift fallback — `list_by_raw_name_visible`
        // resolves visibility first (anonymous/denied/invisible-repo
        // collapses to `NotFound { entity: "Repository" }`), then runs
        // the drift-resilient raw-name listing.
        let handler = PyPiFormatHandler;
        let (resolved_repo, artifact_list) = ctx
            .artifact_use_case
            .list_by_raw_name_visible(&repo.key, &handler, package_name, caller)
            .await?;
        debug_assert_eq!(resolved_repo.id, repo.id);
        let truncated = artifact_list.truncated;
        let artifacts = artifact_list.items;

        // Drift-resilience pin — `artifacts.first().map(|a| a.name)`.
        // When no artifacts exist the unified handler emits a 404 anyway,
        // so the fallback to the request parameter is purely defensive.
        let canonical_name = artifacts
            .first()
            .map(|a| a.name.clone())
            .unwrap_or_else(|| handler.normalize_name(package_name));

        // Batch-fetch metadata once for `requires_python` rendering.
        // Every id was authz'd via `list_by_raw_name_visible` so this
        // is safe to bulk-query directly.
        let ids: Vec<uuid::Uuid> = artifacts.iter().map(|a| a.id).collect();
        let metadata_map = ctx.artifact_use_case.batch_metadata(&ids).await?;

        // Batch-fetch PEP 658 wheel_metadata ContentReference rows for
        // the artifact set in ONE call, not N round-trips.
        // The returned `HashMap<ArtifactId, ContentReference>` is keyed
        // by `source_artifact_id`; artifacts without a matching row are
        // absent (sdists, un-backfilled wheels, or wheels whose
        // `extract_wheel_metadata_bytes` returned None at ingest).
        // The simple-index serve folds an absent row into
        // `PypiVersionFile.metadata_hash = None` → builder omits
        // the PEP 658 advertisement.
        //
        // Goes via `ContentReferenceUseCase` — `ctx.content_references`
        // is `pub(crate)` on AppContext, off-limits to format crates
        // (ADR 0008). The caller's `source_artifact_ids` are already
        // authz'd via `list_by_raw_name_visible`.
        let wheel_metadata_map = ctx
            .content_reference_use_case
            .find_by_sources_and_kind_for_repo(repo.id, &ids, "wheel_metadata")
            .await?;

        // Group by version. PyPI's simple index per-version "entry" is
        // a *list* of files (sdist + wheels), not a single tarball;
        // the artifact rows are flat (one per file), so we group them.
        // A version-less artifact (Versionless row) is skipped — same
        // as npm's hosted source.
        use std::collections::BTreeMap;
        let mut per_version: BTreeMap<
            String,
            (
                hort_domain::entities::artifact::QuarantineStatus,
                Vec<PypiVersionFile>,
            ),
        > = BTreeMap::new();
        for artifact in &artifacts {
            let Some(version) = artifact.version.clone() else {
                continue;
            };
            let filename = artifact
                .path
                .rsplit('/')
                .next()
                .unwrap_or(&artifact.path)
                .to_string();
            let hash_sha256 = Some(artifact.sha256_checksum.to_string());
            let requires_python = metadata_map
                .get(&artifact.id)
                .and_then(|m| m.metadata.get("pkg_info"))
                .and_then(|p| p.get("requires_python"))
                .and_then(|v| v.as_str())
                .map(str::to_string);

            // Populate `metadata_hash` from the batched
            // `wheel_metadata` ContentReference lookup (PEP 658).
            // Absent → `None` → builder omits the PEP 658 attribute
            // / emits `dist-info-metadata: false`. Sdists are
            // structurally absent (the `wheel_metadata` kind is only
            // ever written for `.whl` ingest paths) so they collapse
            // here naturally.
            let metadata_hash = wheel_metadata_map
                .get(&artifact.id)
                .map(|row| row.target_content_hash.clone());

            let file = PypiVersionFile {
                filename,
                hash_sha256,
                requires_python,
                metadata_hash,
            };

            // Multi-file artifacts under the same version inherit the
            // first artifact's quarantine_status — the operator
            // contract is "a version is in or out as a whole", not
            // "per-file". A future per-file status would amend this.
            per_version
                .entry(version)
                .and_modify(|(_status, files)| files.push(file.clone()))
                .or_insert_with(|| (artifact.quarantine_status, vec![file]));
        }

        let mut entries: Vec<VersionEntry> = Vec::with_capacity(per_version.len());
        for (version, (status, files)) in per_version {
            entries.push(VersionEntry {
                version,
                status: Some(status),
                payload: PerVersionPayload::Pypi(PypiVersionPayload { files }),
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
/// Calls the existing [`crate::simple_index::fetch_with_cache`] (which
/// drives `UpstreamProxy::fetch_metadata` through the established
/// cache + dedup + stale-while-error + URL-rewrite + quarantine-filter
/// pipeline — preserving every invariant byte-for-byte), then
/// re-parses the served body into per-version [`VersionEntry`] rows
/// with status hydrated via
/// [`ArtifactUseCase::package_version_status`]. No new port shape.
///
/// **Why re-parse the already-filtered body** — `fetch_with_cache`
/// applies `apply_quarantine_filter` against the same
/// `package_version_status` snapshot the filter pipeline would query.
/// Re-running `NonServableStatusFilter` + `IndexModeFilter` over the
/// post-filter entries is idempotent (the dropped entries are gone;
/// the kept ones survive the same predicate). The unified-pipeline
/// contract is preserved: the builder emits exactly the served set.
///
/// **`format` parameter.** Unlike npm's single packument JSON,
/// PyPI's proxy serve picks HTML / JSON via the request's `Accept`
/// header. The format choice is the handler-tier decision; the proxy
/// source receives the resolved [`SimpleIndexFormat`] and forwards it
/// to `fetch_with_cache`.
pub(crate) struct ProxyPypiSource {
    /// Which simple-index format to fetch + parse. Resolved by the
    /// unified handler from the request's `Accept` header via
    /// `SimpleIndexFormat::from_accept`.
    pub format: SimpleIndexFormat,
}

#[async_trait]
impl IndexSource for ProxyPypiSource {
    #[tracing::instrument(skip(self, ctx, caller), fields(repo_key = %repo.key))]
    async fn fetch(
        &self,
        ctx: &Arc<AppContext>,
        repo: &Repository,
        package_name: &str,
        caller: Option<&CallerPrincipal>,
    ) -> Result<IndexSourceOutput, AppError> {
        // Anti-enumeration thread-through. Re-resolve here defensively
        // so the invariant holds even if a future caller bypasses the
        // dispatch hop. Mirrors `ProxyNpmSource`'s same defensive
        // re-resolve.
        let _ = ctx
            .repository_access_use_case
            .resolve(
                &repo.key,
                caller,
                hort_app::use_cases::repository_access::AccessLevel::Read,
            )
            .await?;

        // Drive the existing cache + dedup + stale-while-error pipeline.
        // The helper streams the upstream body through the
        // format-appropriate projector and returns the small
        // `PypiSimpleIndexProjection` (the raw body went to the
        // mirror, the projection to Redis under the unified, format-
        // independent `pypi_simple_proj:` key). Serve renders the
        // projection directly; no re-parse here.
        //
        // The helper takes explicit deps (rather than `&Arc<AppContext>`)
        // to keep `hort-formats-upstream` from creating a construction
        // cycle. In-crate callers pass the corresponding ctx fields by
        // ref (+ `Some(ctx.metadata_mirror.as_ref())` + the projector cap).
        let projection = match crate::simple_index::fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            ctx.upstream_projector_version_object_max_bytes,
            repo,
            package_name,
            self.format,
        )
        .await
        {
            Ok(p) => p,
            Err(IndexFetchError::NoUpstream) => {
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::NotFound {
                        entity: "Artifact",
                        id: package_name.to_string(),
                    },
                ));
            }
            Err(IndexFetchError::UpstreamUnavailable) => {
                return Err(AppError::External(
                    "pypi upstream unavailable; no cached fallback".to_string(),
                ));
            }
            Err(IndexFetchError::UpstreamBodyTooLarge {
                fetch_class,
                bytes_read,
                cap,
            }) => {
                // Honest storage-backstop classification
                // (ADR 0026: 502 + bytes_read/cap structured body), not
                // the generic "upstream unavailable" envelope.
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::UpstreamBodyTooLarge {
                        fetch_class,
                        bytes_read,
                        cap,
                    },
                ));
            }
            Err(IndexFetchError::VersionObjectTooLarge { cause }) => {
                // A per-file-object cap trip fails closed (nothing cached).
                // Emit the `version_object_too_large` metric so the
                // rejection is observable, then surface as `Validation`
                // → 400 (parse-class, NOT the network bucket).
                // Mirrors npm's typed `VersionObjectTooLarge` arm; the
                // discrimination is the projector's typed `cap_trip_flag`,
                // not a brittle `cause.contains("too large")` substring
                // match.
                let repo_label = if ctx.include_repository_label {
                    repo.key.as_str()
                } else {
                    hort_app::metrics::values::REPOSITORY_ALL
                };
                hort_app::metrics::emit_upstream_version_object_too_large("pypi", repo_label);
                return Err(AppError::Domain(
                    hort_domain::error::DomainError::Validation(cause),
                ));
            }
            Err(IndexFetchError::MetadataMalformed { cause }) => {
                // A malformed upstream body surfaces as `result=parse_error`
                // (a 4xx via the `Validation` → 400 mapping), NEVER
                // the network / `upstream_unavailable` bucket. Fail-closed:
                // nothing was cached or mirrored.
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

        // Per-version status hydration: a status-query failure degrades
        // to "no status known" + WARN.
        let handler = PyPiFormatHandler;
        let normalized = handler.normalize_name(package_name);
        let pkg_status = ctx
            .artifact_use_case
            .package_version_status(repo.id, &normalized)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "pypi proxy source: package_version_status failed; degrading to no status");
                Vec::new()
            });

        // Fire the prefetch trigger on every successful fetch
        // (see `docs/architecture/explanation/prefetch-pipeline.md`).
        // The trigger consumes the already-computed projection directly
        // (no second parse of a raw body, which no longer exists at
        // this layer).
        crate::simple_index::fire_prefetch_trigger_pypi(
            ctx,
            repo,
            package_name,
            &normalized,
            &projection,
            &pkg_status,
        );
        let status_map: std::collections::HashMap<
            String,
            hort_domain::entities::artifact::QuarantineStatus,
        > = pkg_status.into_iter().collect();

        // Map the cached projection into per-version entries. The
        // projection is already computed (the helper streamed the body
        // through the format-appropriate projector on the fetch path;
        // serve maps the cached projection with no re-parse). A
        // malformed/over-cap body fails closed inside `fetch_and_project`
        // and surfaces as `MetadataMalformed` above — it never reaches
        // here as a partially-projected body. The mapping is
        // format-INDEPENDENT (both arms share the same projection).
        let entries = projection_to_entries(projection, &normalized, &status_map);

        Ok(IndexSourceOutput {
            entries,
            truncated: false,
            canonical_name: normalized,
        })
    }
}

/// Map a representation-independent [`PypiSimpleIndexProjection`] into
/// `Vec<VersionEntry>`. Each version groups its files; each file becomes
/// one [`PypiVersionFile`]. The `status_map` hydrates the entry's
/// `status` field via `(version, status)` lookup; absent → `None`
/// the "unknown" tier (status absent means hort has never seen the
/// version from upstream).
///
/// The serve cache holds the projection (produced once by the
/// format-appropriate projector on the fetch path; both the HTML and
/// JSON arms yield this same projection). This mapper is therefore
/// format-INDEPENDENT. The HTML→projection extraction lives in
/// [`crate::html_projection::HtmlSimpleIndexProjector`]; the JSON one
/// in [`hort_formats::pypi::projection::PypiSimpleIndexProjector`].
pub(crate) fn projection_to_entries(
    projection: PypiSimpleIndexProjection,
    normalized_project: &str,
    status_map: &std::collections::HashMap<
        String,
        hort_domain::entities::artifact::QuarantineStatus,
    >,
) -> Vec<VersionEntry> {
    use std::collections::BTreeMap;
    let mut per_version: BTreeMap<String, Vec<PypiVersionFile>> = BTreeMap::new();
    for f in projection.files {
        // Filename is required to derive a version key; fall back to the
        // URL basename (PEP 691 `files[].url`) when the explicit filename
        // is absent.
        let Some(filename) = f.filename.or_else(|| {
            f.url
                .as_ref()
                .and_then(|u| u.rsplit('/').next().map(str::to_string))
        }) else {
            continue;
        };
        // The projection carries `metadata_sha256` as the verbatim hex
        // string (PEP 658 advertisement); parse to a `ContentHash` here.
        // A non-sha256 / unparseable value collapses to `None` → builder
        // emits no advertisement.
        let metadata_hash = f
            .metadata_sha256
            .as_deref()
            .and_then(|hex| hex.parse::<hort_domain::types::ContentHash>().ok());
        let Some(version) = extract_version_from_filename(&filename, normalized_project) else {
            continue;
        };
        per_version
            .entry(version)
            .or_default()
            .push(PypiVersionFile {
                filename,
                hash_sha256: f.sha256,
                requires_python: f.requires_python,
                metadata_hash,
            });
    }

    per_version
        .into_iter()
        .map(|(version, files)| {
            let status = status_map.get(&version).copied();
            VersionEntry {
                version,
                status,
                payload: PerVersionPayload::Pypi(PypiVersionPayload { files }),
            }
        })
        .collect()
}

/// Test-/compat helper: project an in-memory simple-index body (HTML or
/// JSON) through the format-appropriate projector, then map to
/// `Vec<VersionEntry>`. Exercises the SAME body → projection → entries
/// path the production serve path runs (the helper streams via
/// `fetch_and_project`; this drives the projector directly over a
/// `Cursor`). Returns `(entries, cap_tripped)` — `cap_tripped` is `true`
/// when a per-file-object cap trip aborted projection.
///
/// Retained for the in-crate `index_source` / `lib.rs` parser tests that
/// pin the PEP 503 HTML + PEP 691 JSON → entry mapping (incl. PEP 658
/// hash handling). The production path no longer re-parses a raw body —
/// it renders the cached projection via [`projection_to_entries`].
#[cfg(test)]
pub(crate) fn parse_body_to_entries(
    body: &Bytes,
    format: SimpleIndexFormat,
    normalized_project: &str,
    status_map: &std::collections::HashMap<
        String,
        hort_domain::entities::artifact::QuarantineStatus,
    >,
) -> (Vec<VersionEntry>, bool) {
    use hort_domain::ports::upstream_proxy::MetadataProjector;
    const CAP: u64 = 2 * 1024 * 1024;
    let (projection, cap_tripped) = match format {
        SimpleIndexFormat::Json => {
            let projector = hort_formats::pypi::projection::PypiSimpleIndexProjector::new(CAP);
            let flag = projector.cap_trip_flag();
            match projector.project(std::io::Cursor::new(body.as_ref())) {
                Ok(p) => (p, false),
                Err(_) => (
                    PypiSimpleIndexProjection::default(),
                    flag.load(std::sync::atomic::Ordering::Relaxed),
                ),
            }
        }
        SimpleIndexFormat::Html => {
            let projector = crate::html_projection::HtmlSimpleIndexProjector::with_default_cap();
            match projector.project(std::io::Cursor::new(body.as_ref())) {
                Ok(p) => (p, false),
                Err(_) => (PypiSimpleIndexProjection::default(), false),
            }
        }
    };
    (
        projection_to_entries(projection, normalized_project, status_map),
        cap_tripped,
    )
}

/// Best-effort PEP 440 version extraction from a distribution
/// filename. The same logic exists in `simple_index.rs` where it
/// was internal to the filter; re-declared here because the
/// source-adapter is a different module.
fn extract_version_from_filename(filename: &str, _normalized_project: &str) -> Option<String> {
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

// The standalone `html_unescape_attr` was retired along with the
// raw-body `parse_html_to_entries`: the HTML arm now projects to
// `PypiSimpleIndexProjection` via
// `crate::html_projection::HtmlSimpleIndexProjector`, which carries its
// own `html_unescape_attr` for the `requires-python` attribute.
