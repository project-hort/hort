//! PyPI upstream pull-through orchestrator.
//!
//! Three-leg verified pull-through for the PyPI per-version JSON API:
//!
//! 1. Resolve the upstream mapping via [`UpstreamResolver`].
//! 2. Derive `(project_name, version)` from the request filename
//!    (PEP 491 wheel or PEP 625 sdist shape) and fetch the
//!    `/pypi/{normalized}/{version}/json` body via
//!    [`UpstreamProxy::fetch_metadata`]. Not cached at this layer —
//!    the simple-index proxy has its own pull-through cache.
//! 3. Recover the upstream `digests.sha256` via
//!    [`PyPiFormatHandler::parse_upstream_checksum`] and the absolute
//!    file URL via the local URL-extraction helper, then stream the
//!    bytes through [`IngestUseCase::ingest_verified`] as a
//!    `VerifiedIngestRequest::UpstreamPublished(Sha256)`.
//!
//! `try_upstream_file_pull` lives in this inbound-HTTP crate (NOT a
//! use case) — keeps the orchestration close to the route.
//!
//! Wire-mapping ([`UpstreamPullError`] → HTTP status / body) lives
//! alongside the orchestrator in [`map_upstream_pull_error`],
//! mirroring the Cargo precedent at
//! `crates/hort-http-cargo/src/upstream_pull.rs::map_upstream_pull_error`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use bytes::Bytes;
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::pull_dedup::DedupKey;
use hort_app::use_cases::ingest_use_case::{RegisterExistingCasBlobRequest, VerifiedIngestRequest};
use hort_domain::entities::artifact::Artifact;
use hort_domain::entities::repository::{Repository, RepositoryFormat};
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::ApiActor;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::types::checksum::UpstreamPublishedChecksum;
use hort_domain::types::ArtifactCoords;
// The tarball-pull recovers `url`, `digests.sha256`, and `upload_time`
// from the streamed per-version JSON projection rather than re-parsing
// the raw body.
use hort_formats::pypi::projection::{
    PypiVersionFileInfo, PypiVersionJsonProjection, PypiVersionJsonProjector,
};
use hort_formats::pypi::PyPiFormatHandler;
use hort_http_core::context::AppContext;

/// Discriminated failure modes for [`try_upstream_file_pull`]. Wire
/// mapping (HTTP status + envelope body) is performed by the route
/// handler; the orchestrator itself only surfaces *what* went wrong,
/// not *how to render it*.
///
/// `MetadataFetchFailed.stage` is one of the two string literals
/// `"json"` or `"file"` — the wire-map can match on the stage to
/// differentiate `X-Hort-Reason` headers without a second enum dimension.
///
/// The variant list mirrors Cargo's prior art
/// (`crates/hort-http-cargo/src/upstream_pull.rs::UpstreamPullError`),
/// adapted to the two-leg PyPI pipeline. `CurationBlocked` is wired
/// proactively (latent until a curation rule covers a PyPI proxy
/// artifact): when the pre-storage curation gate blocks an upstream
/// pull, `ingest_verified` returns `DomainError::CurationBlocked`, which
/// the orchestrator surfaces as this variant and the wire-map collapses
/// to a 404 byte-identical to a genuine miss — the anti-enumeration
/// contract (`hort_http_core::error`). Without this arm the block would
/// fall through the catch-all to `IngestFailed` → 500, an observable
/// enumeration oracle (LOG-1/LOG-2).
///
/// `ParseError(String)` / `IngestFailed(String)` / `Internal(String)`
/// carry the inner detail for tracing — the wire-map renders
/// a stable client-facing envelope regardless of the specific message,
/// so the inner string is only consumed via `tracing::warn!` here.
/// Same applies to the `err` field of `MetadataFetchFailed`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum UpstreamPullError {
    /// No upstream mapping configured for this repo. Wire to "no
    /// pull-through configured" — typically a 404 since the artifact
    /// is genuinely unknown locally and the repo is not a proxy.
    #[error("no upstream mapping configured")]
    NoUpstreamMapping,

    /// Upstream HTTP fetch failed at one of the two legs.
    /// `stage = "json"` for the per-version JSON body, `"file"` for
    /// the wheel/sdist body.
    #[error("upstream metadata fetch failed at {stage}: {err}")]
    MetadataFetchFailed { stage: &'static str, err: String },

    /// Filename parse failure, malformed JSON body, missing `urls[]`
    /// entry for the requested filename, or `digests.sha256` absent
    /// (md5-only legacy releases). The wire-map renders a single
    /// `upstream-metadata-malformed` envelope regardless of which.
    #[error("upstream metadata parse error: {0}")]
    ParseError(String),

    /// `IngestUseCase::ingest_verified` returned `Conflict` — upstream
    /// bytes hashed differently from the `digests.sha256` advertised in
    /// the JSON body (ADR 0006). The use case already emitted
    /// `ChecksumMismatch` on the repository stream and rolled back the
    /// CAS blob.
    #[error("upstream checksum mismatch")]
    ChecksumMismatch,

    /// `IngestUseCase::ingest_verified` returned `CurationBlocked` — a
    /// curation rule matched the upstream artifact. The ingest use case
    /// already emitted the audit `tracing::info!`. Wire-map collapses
    /// this to 404 (byte-identical to a genuine upstream miss) so an
    /// unauthenticated prober cannot distinguish a curation-blocked
    /// distribution from a non-existent one — the anti-enumeration
    /// contract (`hort_http_core::error`) and the Cargo / OCI prior art.
    #[error("upstream artifact blocked by curation rule")]
    CurationBlocked,

    /// Any other ingest-time error — storage failure, event-store
    /// failure, repo lookup failure after ingest. Wire to 500.
    #[error("ingest failed: {0}")]
    IngestFailed(String),

    /// Internal invariant violated — should not happen in practice
    /// because the version is derived from the filename before the
    /// metadata-path call, but the trait shape's `Option` return
    /// requires us to surface the missing-version case.
    #[error("internal error: {0}")]
    Internal(String),
}

/// On a local cache miss, fetch the requested PyPI distribution from
/// the configured upstream registry, verify it against the upstream
/// `digests.sha256`, and ingest into the local CAS.
///
/// Two-leg orchestration: per-version JSON metadata (uncached) →
/// distribution body (verified-ingest).
///
/// `project_name` is the URL-segment form (already PEP 503 normalised
/// by the caller in `download` — see `simple/{project}/{filename}`).
/// `filename` is the wheel or sdist filename verbatim from the URL.
/// The version is **derived from the filename**, not passed in
/// separately, because the PyPI download URL doesn't carry an explicit
/// version segment (unlike Cargo's `/api/v1/crates/{name}/{version}/download`).
///
/// The `download` handler routes Proxy-repo cache misses here.
#[tracing::instrument(
    skip(ctx),
    fields(repo_key = %repo.key, project_name, filename),
)]
pub(crate) async fn try_upstream_file_pull(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    project_name: &str,
    filename: &str,
) -> Result<Artifact, UpstreamPullError> {
    // 1. Resolve upstream mapping. PyPI has a single upstream mapping
    //    per repo today (no path-prefix routing); the framework call
    //    passes `""` for the path-prefix.
    let Some((mapping, _stripped)) = ctx.upstream_resolver.resolve(repo.id, "") else {
        tracing::warn!("PyPI repository has no upstream mapping configured");
        return Err(UpstreamPullError::NoUpstreamMapping);
    };

    // 2. Derive (project_name, version) from the filename. The version
    //    is the second `-`-separated segment for wheels (PEP 491) and
    //    the right side of the last `-` for sdists (PEP 625).
    let (filename_project, version) = parse_pypi_filename(filename).map_err(|e| {
        tracing::warn!(error = %e, "PyPI filename parse failed");
        UpstreamPullError::ParseError(e.to_string())
    })?;

    // Cross-check: PEP 503-normalising the filename's project segment
    // must agree with the URL's project segment. A mismatch signals a
    // broken upstream URL or a tampering attempt; either way we refuse
    // to fetch.
    let pypi_handler = PyPiFormatHandler;
    let normalized_filename_project = pypi_handler.normalize_name(&filename_project);
    let normalized_project = pypi_handler.normalize_name(project_name);
    if normalized_filename_project != normalized_project {
        tracing::warn!(
            filename_project = %filename_project,
            project_name,
            "PyPI filename project segment does not match URL project after PEP 503 normalisation"
        );
        return Err(UpstreamPullError::ParseError(format!(
            "filename project '{filename_project}' does not match URL project '{project_name}' \
             after PEP 503 normalisation"
        )));
    }

    // Build the coords used for both metadata-path derivation and
    // checksum parsing. `coords.path` MUST contain the filename in its
    // basename position because `parse_upstream_checksum` extracts the
    // basename via `coords.path.rsplit('/').next()` to look up the
    // matching `urls[]` entry. The path comes
    // from the single SSOT constructor, which embeds the PEP 503 NORMALIZED
    // project segment (was the raw `project_name` — a PEP 503 violation
    // that split variant spellings into separate projection rows). pypi
    // carries no version in the path, so `version = ""`; the filename is
    // embedded verbatim.
    let path = pypi_handler
        .build_artifact_logical_path(project_name, "", Some(filename))
        .map_err(|e| UpstreamPullError::ParseError(e.to_string()))?;
    let coords = ArtifactCoords {
        name: normalized_project.clone(),
        // Preserve the URL's project segment as supplied (matches the
        // upload-time `name_as_published` rule).
        name_as_published: project_name.to_string(),
        version: Some(version.clone()),
        path,
        format: RepositoryFormat::Pypi,
        metadata: serde_json::Value::Null,
    };

    // 3. Fetch the per-version JSON body. The handler builds the
    //    canonical `/pypi/{normalised}/{version}/json` path.
    let Some(metadata_path) = pypi_handler.upstream_checksum_metadata_path(&coords) else {
        // Unreachable in practice — the version was derived above.
        // The handler returns None only when coords.version is None.
        return Err(UpstreamPullError::Internal(
            "PyPI handler did not return a metadata path despite a known version".into(),
        ));
    };

    // Wrap the per-version JSON fetch in `PullDedup::coalesce_metadata`
    // so N parallel callers asking for the same `(repo, package, version)`
    // produce ≤ 1 upstream JSON round-trip.
    //
    // The per-version JSON leg streams (no full-body `Vec`) through the
    // `PypiVersionJsonProjector` into a small `PypiVersionJsonProjection`;
    // the requested file's `url`, `digests.sha256`, and
    // `upload_time_iso_8601` are recovered from the matching `urls[]`
    // projection entry. The closure returns the SERIALIZED projection so
    // followers receive the small projection, not the raw per-version JSON
    // body. No mirror write here — the per-version JSON endpoint is the
    // tarball-pull's own (uncached at this layer) leg; the simple-index
    // serve/cache path owns the simple-index mirror.
    let json_dedup_key = DedupKey::metadata("pypi", repo.id, &metadata_path);
    let json_proxy = ctx.upstream_proxy.clone();
    let json_mapping = mapping.clone();
    let json_path_for_closure = metadata_path.clone();
    let json_cap = ctx.upstream_projector_version_object_max_bytes;
    let projection: PypiVersionJsonProjection = match ctx
        .pull_dedup
        .coalesce_metadata(json_dedup_key, move || async move {
            let outcome = json_proxy
                .fetch_metadata(
                    json_mapping,
                    json_path_for_closure,
                    vec!["application/json".into()],
                )
                .await
                .map_err(AppError::from)?;
            let handle = outcome.cache_handle.as_ref().ok_or_else(|| {
                AppError::from(DomainError::Invariant(
                    "pypi per-version fetch_metadata returned no cache_handle".to_string(),
                ))
            })?;
            // Stream-project (no full-body Vec); a malformed body fails
            // closed (Task 5 reject-on-invalid → `Validation`). No mirror
            // (the tarball-pull does not serve the simple index).
            let projection =
                hort_app::project::project_cached(handle, PypiVersionJsonProjector::new(json_cap))
                    .await
                    .map_err(AppError::from)?;
            // Best-effort tempfile cleanup (the consumer owns the
            // lifecycle, mirroring the retired `metadata_body_bytes`).
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
        Ok(json) => serde_json::from_slice(&json).map_err(|e| {
            // A malformed serialized-projection frame is OUR internal
            // (de)serialize fault, not an upstream outage.
            UpstreamPullError::Internal(format!("pypi projection deserialize: {e}"))
        })?,
        // A malformed per-version JSON body surfaces as a leader-side
        // `AppError::Domain(Validation(...))` (fail-closed); classify it
        // as a content `ParseError`, NOT the network / metadata-fetch-
        // failed bucket. A transport/outage failure (incl. follower-side
        // wrapped errors) is everything else.
        Err(AppError::Domain(DomainError::Validation(msg))) => {
            tracing::warn!(cause = %msg, "PyPI upstream per-version JSON malformed (parse_error)");
            return Err(UpstreamPullError::ParseError(msg));
        }
        Err(e) => {
            tracing::warn!(error = %e, "PyPI upstream JSON fetch failed");
            return Err(UpstreamPullError::MetadataFetchFailed {
                stage: "json",
                err: e.to_string(),
            });
        }
    };

    // Locate the requested file's `urls[]` projection entry (exact
    // filename match — wheels/sdists are case-sensitive on disk). A
    // missing entry is the "upstream does not publish this file" content
    // fault, mapped to ParseError (mirrors the raw-body parsers' missing-
    // entry `Validation`).
    let Some(entry) = projection.file_for(filename) else {
        tracing::warn!(filename, "PyPI upstream does not publish this file");
        return Err(UpstreamPullError::ParseError(format!(
            "upstream PyPI does not publish file {filename}"
        )));
    };

    // 4. Recover the upstream sha256 from the projection entry. The
    //    SHA-256 length/hex validation is driven through the SAME audited
    //    `PyPiFormatHandler::parse_upstream_checksum` against a minimal
    //    synthetic body holding only the requested file's `digests.sha256`,
    //    so the verification semantics stay byte-identical and are not
    //    duplicated. A missing sha256 (md5-only legacy release) yields the
    //    same `Validation` the raw parser produced → ParseError.
    let upstream_checksum = match checksum_from_entry(&pypi_handler, entry, &coords) {
        Ok(cs) => cs,
        Err(e) => {
            tracing::warn!(error = %e, "PyPI upstream JSON parse / checksum extraction failed");
            return Err(UpstreamPullError::ParseError(e.to_string()));
        }
    };

    // 5. Recover the absolute file URL from the projection entry.
    //    The `https://` guard is preserved in `url_from_entry` — no
    //    downgrade target is ever promoted to a fetch URL.
    let absolute_url = match url_from_entry(entry, filename) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "PyPI upstream URL extraction failed");
            return Err(UpstreamPullError::ParseError(e.to_string()));
        }
    };

    // 6 + 7. Stream the file bytes via the absolute URL and ingest_verified.
    //    `fetch_artifact` accepts absolute URLs (see `hort_domain::ports::upstream_proxy`)
    //    — required because PyPI publishes files on a different host
    //    (`files.pythonhosted.org`) than the index (`pypi.org`).
    //    `ingest_verified` rehashes while streaming and returns Conflict
    //    on a checksum mismatch — our security primitive against upstream
    //    tampering (see ADR 0006).
    //
    //    Wrap the `fetch_artifact + ingest_verified` pair in
    //    `coalesce_blob` so N parallel callers for the same wheel/sdist
    //    produce ≤ 1 upstream fetch + ≤ 1 CAS write. The dedup key is
    //    the verified upstream `digests.sha256` from the JSON metadata
    //    (pre-known per ADR 0006) so different repos pointing at the
    //    same upstream share a single coalescing window.
    //
    //    `parse_upstream_checksum` rejects md5-only legacy releases as
    //    `Validation` (mapped to `ParseError` above), so by the time
    //    control reaches here `upstream_checksum.hex()` is always a
    //    sha256 — the `digests.sha256` fallback path to
    //    `DedupKey::blob_by_url` (defensive case for private mirrors
    //    with missing digests) is unreachable on the PyPI orchestrator
    //    and therefore not constructed.
    //
    //    Closure-boundary contract: on success the closure returns
    //    `Ok(content_hash)`; on failure `Err(AppError)`. The leader sees
    //    the original `AppError` discriminator (`Domain(Conflict)` for
    //    checksum mismatch); followers observe the cached `Failed`
    //    outcome and surface a wrapped `AppError::External` —
    //    typed-error discrimination is a leader-only concern.
    let blob_dedup_key = DedupKey::blob_by_hash("sha256", upstream_checksum.hex());
    // Capture the upstream-asserted publish timestamp from the projection
    // entry's `upload_time` (parsed at projection time from the filename-
    // matched `urls[i].upload_time_iso_8601`). Best-effort: missing /
    // unparseable → `None`, never an ingest failure.
    let upstream_published_at = entry.upload_time;
    // Capture the serving mapping's `trust_upstream_publish_time` opt-in
    // **before** the `coalesce_blob` closure consumes `mapping`. Threaded
    // into `VerifiedIngestRequest` so `ingest_inner` can gate the
    // publish-anchored quarantine resolution on it.
    let blob_trust_publish_time = mapping.trust_upstream_publish_time;
    let blob_proxy = ctx.upstream_proxy.clone();
    let blob_mapping = mapping.clone();
    let blob_absolute_url = absolute_url;
    let blob_ingest = ctx.ingest_use_case.clone();
    let blob_repo_id = repo.id;
    // Keep a clone for the cross-repo follower-registration
    // fallback below (the closure consumes `blob_coords`).
    let follower_coords = coords.clone();
    let blob_coords = coords;
    let blob_upstream_url = mapping.upstream_url.clone();
    let follower_upstream_url = blob_upstream_url.clone();
    let blob_upstream_checksum = upstream_checksum;
    let blob_handler = pypi_handler;
    let coalesce_blob_result = ctx
        .pull_dedup
        .coalesce_blob(blob_dedup_key, move || async move {
            // `fetch_artifact` returns an `ArtifactFetch` envelope;
            // extract `stream`. The per-file `upload_time_iso_8601` drives
            // `upstream_published_at`; the response header's
            // `Last-Modified` is captured by the adapter for symmetry but
            // not consumed here.
            let fetch = blob_proxy
                .fetch_artifact(blob_mapping, blob_absolute_url)
                .await
                .map_err(AppError::from)?;
            let reader: Box<dyn AsyncRead + Send + Unpin> =
                Box::new(StreamReader::new(fetch.stream));
            let request = VerifiedIngestRequest::UpstreamPublished {
                repository_id: blob_repo_id,
                coords: blob_coords,
                content_type: "application/octet-stream".to_string(),
                actor: ApiActor {
                    user_id: Uuid::nil(),
                },
                payload_metadata: serde_json::json!({
                    "source": "pypi_upstream_pull",
                    "upstream_url": blob_upstream_url,
                }),
                upstream_checksum: blob_upstream_checksum,
                // Per-file upload_time_iso_8601 from the version JSON
                // body, best-effort.
                upstream_published_at,
                // Per-upstream opt-in: when `true` AND
                // `upstream_published_at` is `Some(_)`, `ingest_inner`
                // anchors the quarantine window at
                // `min(upstream_published_at, ingested_at)`.
                trust_upstream_publish_time: blob_trust_publish_time,
            };
            let outcome = blob_ingest
                .ingest_verified(request, reader, &blob_handler)
                .await?;
            Ok(outcome.artifact.sha256_checksum)
        })
        .await;

    let content_hash = match coalesce_blob_result {
        Ok(h) => h,
        // Leader-side failures still carry typed `AppError::Domain`
        // discriminators — preserve the existing wire-mapping. Follower-
        // side errors arrive as `AppError::External("pull-dedup
        // follower: ...")` and route to `IngestFailed` per the design's
        // leader-only-discrimination contract.
        Err(AppError::Domain(DomainError::Conflict(msg))) => {
            tracing::warn!(conflict = %msg, "PyPI upstream checksum mismatch");
            return Err(UpstreamPullError::ChecksumMismatch);
        }
        // Leader-side curation block: a curation rule matched the
        // upstream distribution during `ingest_verified`. Collapse to
        // 404 (byte-identical to a genuine miss) at the wire-map so a
        // probe cannot distinguish a blocked distribution from a
        // non-existent one — mirrors the Cargo prior art and the
        // anti-enumeration contract (`hort_http_core::error`). Must
        // precede the catch-all `Err(e)` arm, which would otherwise
        // route this to a 500.
        Err(AppError::Domain(DomainError::CurationBlocked { .. })) => {
            tracing::warn!("PyPI upstream artifact blocked by curation rule");
            return Err(UpstreamPullError::CurationBlocked);
        }
        Err(e) => {
            // `fetch_artifact` errors and any other ingest-time
            // infrastructure failure converge here. The original
            // pre-coalesce code split `fetch_artifact` failures into
            // `MetadataFetchFailed{stage:"file"}`; preserve that by
            // string-matching the wrapped error message — the upstream
            // HTTP adapter prefixes its errors with "upstream:" (see
            // `MockUpstreamProxy::fetch_artifact` and the production
            // `UpstreamHttpAdapter`).
            let msg = e.to_string();
            if msg.contains("upstream:") || msg.contains("upstream ") {
                tracing::warn!(error = %e, "PyPI upstream file fetch failed");
                return Err(UpstreamPullError::MetadataFetchFailed {
                    stage: "file",
                    err: msg,
                });
            }
            tracing::warn!(error = %e, "PyPI upstream ingest failed");
            return Err(UpstreamPullError::IngestFailed(msg));
        }
    };

    // Post-coalesce read: both leader and follower re-resolve the
    // artifact row by content hash. The leader's `ingest_verified`
    // (inside the closure) wrote the row; the follower reads it. The
    // lookup is per-repo and microsecond-fast.
    //
    // `blob_by_hash` is cross-repo, so a follower that joined a window
    // whose leader ingested into a DIFFERENT repo has no row in
    // `repo.id`. On `None` the follower idempotently registers its OWN
    // per-repo row via `register_existing_cas_blob` (content already
    // CAS-present + upstream-verified; no re-fetch, no re-`storage.put`;
    // same `ArtifactIngested` event the leader's cross-repo dedup emits).
    let artifact = match ctx
        .artifact_use_case
        .find_in_repo_by_hash(repo.id, &content_hash)
        .await
        .map_err(|e| UpstreamPullError::IngestFailed(e.to_string()))?
    {
        Some(a) => a,
        None => {
            ctx.ingest_use_case
                .register_existing_cas_blob(
                    RegisterExistingCasBlobRequest {
                        repository_id: repo.id,
                        coords: follower_coords,
                        content_type: "application/octet-stream".to_string(),
                        actor: ApiActor {
                            user_id: Uuid::nil(),
                        },
                        payload_metadata: serde_json::json!({
                            "source": "pypi_upstream_pull",
                            "upstream_url": follower_upstream_url,
                        }),
                        content_hash: content_hash.clone(),
                        // Upstream pull is not a seed-import cutover;
                        // quarantine is policy-driven through the primary
                        // `ingest_verified` path, not via the follower
                        // register-by-hash shim.
                        seed_import_quarantine_anchor: None,
                    },
                    &PyPiFormatHandler,
                )
                .await
                .map_err(|e| UpstreamPullError::IngestFailed(e.to_string()))?
                .artifact
        }
    };

    tracing::info!(
        artifact_id = %artifact.id,
        algorithm = "sha256",
        "PyPI upstream pull-through completed; ChecksumVerified emitted"
    );
    Ok(artifact)
}

/// Parse a PyPI distribution filename into `(project_name, version)`.
///
/// - **Wheel** (PEP 491) — `{name}-{version}-{python}-{abi}-{platform}.whl`.
///   Splitting on `-` after stripping `.whl` yields exactly 5 segments
///   (or more if the version itself contains `-`, which PEP 491 forbids
///   but we accept defensively); `[0]` is the name and `[1]` is the
///   version.
/// - **Sdist** (PEP 625) — `{name}-{version}.tar.gz` or `{name}-{version}.zip`.
///   After stripping the extension, the LAST `-` separates name from
///   version (the name itself may contain `-` in legacy uploads).
///
/// The PEP 503-normalised cross-check between `project_name` (URL
/// segment) and the filename's name segment is performed in the caller
/// — both feed it the same data in different cases (`Requests` vs
/// `requests`), so normalising before comparing is essential.
//
// `extract_upstream_publish_time` (the raw-body `serde_json::Value`
// walk over `urls[i].upload_time_iso_8601`) was retired: the publish
// timestamp is now parsed at projection time and read off
// `PypiVersionFileInfo.upload_time` (see `hort_formats::pypi::projection`).
// The end-to-end flow is asserted in
// `tarball_pull_threads_upload_time_to_upstream_published_at` below;
// per-field parse behaviour is pinned by the projector's own tests.
fn parse_pypi_filename(filename: &str) -> DomainResult<(String, String)> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        // PEP 491: at least 5 `-`-separated segments.
        let parts: Vec<&str> = stem.split('-').collect();
        if parts.len() < 5 {
            return Err(DomainError::Validation(format!(
                "PyPI wheel filename '{filename}' does not have ≥5 '-'-separated segments \
                 per PEP 491"
            )));
        }
        if parts[0].is_empty() || parts[1].is_empty() {
            return Err(DomainError::Validation(format!(
                "PyPI wheel filename '{filename}' has empty name or version segment"
            )));
        }
        return Ok((parts[0].to_string(), parts[1].to_string()));
    }

    let stem = if let Some(s) = filename.strip_suffix(".tar.gz") {
        s
    } else if let Some(s) = filename.strip_suffix(".zip") {
        s
    } else {
        return Err(DomainError::Validation(format!(
            "PyPI filename '{filename}' is neither a wheel (.whl) nor a recognised sdist \
             (.tar.gz / .zip)"
        )));
    };

    // PEP 625: `name-version`. Split on the LAST `-` — the name itself
    // may contain `-` in legacy uploads.
    let Some(idx) = stem.rfind('-') else {
        return Err(DomainError::Validation(format!(
            "PyPI sdist filename '{filename}' has no '-' separator between name and version"
        )));
    };
    let name = &stem[..idx];
    let version = &stem[idx + 1..];
    if name.is_empty() || version.is_empty() {
        return Err(DomainError::Validation(format!(
            "PyPI sdist filename '{filename}' has empty name or version segment"
        )));
    }
    Ok((name.to_string(), version.to_string()))
}

/// Recover the upstream SHA-256 [`UpstreamPublishedChecksum`] from a
/// per-version JSON projection [`PypiVersionFileInfo`]'s verbatim
/// `digests.sha256` (`entry.sha256`).
///
/// Recover the upstream SHA-256 [`UpstreamPublishedChecksum`] from a
/// [`PypiVersionFileInfo`] entry's `digests.sha256`. To keep the
/// SHA-256 length/hex validation **byte-identical** (and NOT duplicate
/// that security-critical logic), this drives the SAME audited
/// [`PyPiFormatHandler::parse_upstream_checksum`] path against a minimal
/// synthetic per-version JSON body that contains only the requested
/// file's `filename` + `digests.sha256` — the exact fields that path
/// reads. A missing/empty sha256 (md5-only legacy release) yields a
/// body whose `digests` has no `sha256`, so the handler returns the same
/// "publishes no SHA-256 digest" `Validation` the raw parser produced;
/// a malformed sha256 returns the same length/hex `Validation`.
fn checksum_from_entry(
    handler: &PyPiFormatHandler,
    entry: &PypiVersionFileInfo,
    coords: &ArtifactCoords,
) -> DomainResult<UpstreamPublishedChecksum> {
    // `parse_upstream_checksum` reads the filename from
    // `coords.path.rsplit('/').next()` and finds the matching `urls[]`
    // entry; build a single-entry body keyed on that basename. Emit the
    // `digests.sha256` only when present so the handler's "no SHA-256
    // digest" path fires identically when upstream omitted it.
    let filename = coords.path.rsplit('/').next().unwrap_or("");
    let digests = match entry.sha256.as_deref() {
        Some(sha) if !sha.is_empty() => serde_json::json!({ "sha256": sha }),
        _ => serde_json::json!({}),
    };
    let body = serde_json::json!({
        "urls": [ { "filename": filename, "digests": digests } ]
    });
    let bytes = serde_json::to_vec(&body)
        .map_err(|e| DomainError::Invariant(format!("pypi synthetic body serialize: {e}")))?;
    // `parse_upstream_checksum` takes a streaming reader; the synthetic
    // single-entry body is tiny, so a cursor over the in-memory bytes
    // satisfies the port without behaviour change.
    handler.parse_upstream_checksum(&mut std::io::Cursor::new(&bytes), coords)
}

/// Recover the genuine absolute upstream file URL from a per-version JSON
/// projection [`PypiVersionFileInfo`]'s verbatim `url` field. Applies the
/// SAME `https://` guard as the former `extract_upstream_file_url`
/// helper — no downgrade target is ever promoted to a fetch URL.
///
/// A missing URL → "missing url field" `Validation`; a non-https URL →
/// "non-https URL" `Validation`.
fn url_from_entry(entry: &PypiVersionFileInfo, filename: &str) -> DomainResult<String> {
    let url = entry.url.as_deref().ok_or_else(|| {
        DomainError::Validation(format!(
            "upstream PyPI urls[] entry for {filename} is missing a string url field"
        ))
    })?;
    if !url.starts_with("https://") {
        return Err(DomainError::Validation(format!(
            "upstream PyPI returned non-https URL: {url}"
        )));
    }
    Ok(url.to_string())
}

/// Wire-mapping for [`UpstreamPullError`] used by the `download`
/// handler's Proxy-cache-miss branch.
///
/// Mapping rationale (see `docs/architecture/how-to/pypi-pull-through.md`):
///
/// | Variant | Status | `X-Hort-Reason` |
/// |---|---|---|
/// | `NoUpstreamMapping` / `CurationBlocked` | 404 | — |
/// | `ChecksumMismatch` | 502 | `upstream-checksum-mismatch` |
/// | `ParseError` | 502 | `upstream-metadata-malformed` |
/// | `MetadataFetchFailed{stage}` | 502 | `upstream-metadata-fetch-failed-{stage}` |
/// | `IngestFailed` / `Internal` | 500 | — |
///
/// Notes:
///
/// - Status codes and `X-Hort-Reason` headers match Cargo's
///   `crates/hort-http-cargo/src/upstream_pull.rs::map_upstream_pull_error`
///   verbatim where the variant overlaps; the body strings differ
///   slightly to match the PyPI envelope conventions in the backlog.
/// - The body shape (`{"error": "..."}`, `application/json`) mirrors
///   the existing PyPI handler helpers so client-side logging stays
///   uniform across the success / quarantine / pull-through branches.
/// - `Internal` and `IngestFailed` return short stable strings — never
///   the inner message — to match the `ApiError::Repository` /
///   `ApiError::Storage` / `ApiError::EventStore` sanitisation
///   contract in `hort_http_core::error`.
/// - `MetadataFetchFailed` covers both stages today (`"json"` and
///   `"file"`) plus a catch-all 502 with a generic envelope; the
///   catch-all guards against future-leg additions to the orchestrator
///   without forcing a wire-map update in the same PR.
pub(crate) fn map_upstream_pull_error(e: &UpstreamPullError) -> Response {
    match e {
        // `CurationBlocked` collapses to the SAME 404 envelope as a
        // genuine `NoUpstreamMapping` miss (byte-identical body +
        // status, no distinguishing header) so an unauthenticated
        // prober cannot tell a curation-blocked distribution from a
        // non-existent one — the anti-enumeration contract and the
        // Cargo / OCI prior art.
        UpstreamPullError::NoUpstreamMapping | UpstreamPullError::CurationBlocked => {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({"error": "package not found"}).to_string(),
                ))
                .unwrap()
        }
        UpstreamPullError::ChecksumMismatch => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .header("X-Hort-Reason", "upstream-checksum-mismatch")
            .body(Body::from(
                serde_json::json!({"error": "upstream tampering detected"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::ParseError(_) => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .header("X-Hort-Reason", "upstream-metadata-malformed")
            .body(Body::from(
                serde_json::json!({"error": "upstream metadata invalid"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::MetadataFetchFailed { stage, .. } => {
            let body = match *stage {
                "json" => serde_json::json!({"error": "upstream metadata fetch failed"}),
                "file" => serde_json::json!({"error": "upstream file fetch failed"}),
                _ => serde_json::json!({"error": "upstream fetch failed"}),
            };
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("Content-Type", "application/json")
                .header(
                    "X-Hort-Reason",
                    format!("upstream-metadata-fetch-failed-{stage}"),
                )
                .body(Body::from(body.to_string()))
                .unwrap()
        }
        UpstreamPullError::IngestFailed(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"error": "ingest failed"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::Internal(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"error": "internal error"}).to_string(),
            ))
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;
    use uuid::Uuid;

    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::error::DomainError;
    use hort_domain::events::{DomainEvent, StreamId};
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    use hort_http_core::test_support::{build_mock_ctx, MockPorts};

    use super::*;

    /// Minimal PyPI per-version JSON body keyed on (filename, sha256).
    /// Mirrors the structure of `requests_2.31.0.json` but trimmed to
    /// the `urls[]` shape that `parse_upstream_checksum` and
    /// `extract_upstream_file_url` consume.
    fn pypi_json(filename: &str, sha256: &str, url: &str) -> Vec<u8> {
        format!(
            r#"{{"urls":[{{"filename":"{filename}","url":"{url}","digests":{{"sha256":"{sha256}"}}}}]}}"#,
        )
        .into_bytes()
    }

    /// Two-entry JSON body — wheel + sdist for the same version, like
    /// the production `/pypi/{name}/{version}/json` shape.
    fn pypi_json_two(
        wheel_name: &str,
        wheel_sha: &str,
        wheel_url: &str,
        sdist_name: &str,
        sdist_sha: &str,
        sdist_url: &str,
    ) -> Vec<u8> {
        format!(
            r#"{{"urls":[
                {{"filename":"{wheel_name}","url":"{wheel_url}","digests":{{"sha256":"{wheel_sha}"}}}},
                {{"filename":"{sdist_name}","url":"{sdist_url}","digests":{{"sha256":"{sdist_sha}"}}}}
            ]}}"#,
        )
        .into_bytes()
    }

    /// JSON body with only `md5` in `digests` — exercises the
    /// "ParseError surfaces md5-only legacy releases" branch.
    fn pypi_json_md5_only(filename: &str, url: &str) -> Vec<u8> {
        format!(
            r#"{{"urls":[{{"filename":"{filename}","url":"{url}","digests":{{"md5":"deadbeefdeadbeefdeadbeefdeadbeef"}}}}]}}"#,
        )
        .into_bytes()
    }

    fn sha256_hex(content: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(content))
    }

    fn pypi_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Pypi;
        r
    }

    /// Seed an upstream mapping with the given `path_prefix` (use `""`
    /// for the single-upstream catch-all PyPI uses).
    fn seed_mapping(mocks: &MockPorts, repo_id: Uuid, path_prefix: &str) -> Uuid {
        let id = Uuid::new_v4();
        let now = Utc::now();
        mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
            id,
            repository_id: repo_id,
            path_prefix: path_prefix.into(),
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

    fn handle() -> metrics_exporter_prometheus::PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    // -- parse_pypi_filename branches -----------------------------------------

    #[test]
    fn parse_pypi_filename_wheel_happy_path() {
        let (n, v) = parse_pypi_filename("requests-2.31.0-py3-none-any.whl").unwrap();
        assert_eq!(n, "requests");
        assert_eq!(v, "2.31.0");
    }

    #[test]
    fn parse_pypi_filename_sdist_targz_happy_path() {
        let (n, v) = parse_pypi_filename("requests-2.31.0.tar.gz").unwrap();
        assert_eq!(n, "requests");
        assert_eq!(v, "2.31.0");
    }

    #[test]
    fn parse_pypi_filename_sdist_zip_happy_path() {
        let (n, v) = parse_pypi_filename("legacy-pkg-1.0.zip").unwrap();
        // Sdist parses `name = "legacy-pkg"` (last-`-` split) and
        // `version = "1.0"` — the dash inside the name is preserved.
        assert_eq!(n, "legacy-pkg");
        assert_eq!(v, "1.0");
    }

    #[test]
    fn parse_pypi_filename_unknown_extension_rejected() {
        let err = parse_pypi_filename("this-is-not-a-package.unknown").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn parse_pypi_filename_too_few_wheel_segments_rejected() {
        let err = parse_pypi_filename("requests-2.31.0.whl").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn parse_pypi_filename_sdist_no_dash_rejected() {
        let err = parse_pypi_filename("noseparator.tar.gz").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn parse_pypi_filename_empty_wheel_segments_rejected() {
        let err = parse_pypi_filename("--py3-none-any.whl").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn parse_pypi_filename_empty_sdist_segments_rejected() {
        let err = parse_pypi_filename("-1.0.tar.gz").unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    // -- Projection-entry field extractors -----------------------------------
    //
    // These pin the three load-bearing extractions the tarball-pull reads
    // off the per-version JSON projection: `checksum_from_entry` (drives
    // the SAME audited `parse_upstream_checksum`), `url_from_entry` (same
    // `https://` guard as `extract_upstream_file_url`), and
    // `entry.upload_time` (parsed at projection time). The per-field PARSE
    // behaviour (upload_time RFC-3339 / sha256 hex-len / md5-only) lives in
    // the projector's own tests; these assert the consumer-layer contract.

    fn coords_for(filename: &str, version: &str) -> ArtifactCoords {
        ArtifactCoords {
            name: "requests".into(),
            name_as_published: "requests".into(),
            version: Some(version.into()),
            path: format!("simple/requests/{filename}"),
            format: RepositoryFormat::Pypi,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn checksum_from_entry_happy_path_returns_sha256() {
        // A valid 64-hex sha256 round-trips through the audited
        // `parse_upstream_checksum` synthetic-body path.
        let sha = sha256_hex(b"some wheel bytes");
        let entry = PypiVersionFileInfo {
            filename: Some("requests-2.31.0-py3-none-any.whl".into()),
            url: Some("https://files.pythonhosted.org/x/requests-2.31.0-py3-none-any.whl".into()),
            sha256: Some(sha.clone()),
            upload_time: None,
        };
        let coords = coords_for("requests-2.31.0-py3-none-any.whl", "2.31.0");
        let cs = checksum_from_entry(&PyPiFormatHandler, &entry, &coords).unwrap();
        assert_eq!(cs.hex(), sha);
    }

    #[test]
    fn checksum_from_entry_missing_sha256_returns_validation() {
        // md5-only legacy release: `sha256: None` → the same
        // "no SHA-256 digest" `Validation` the raw parser produced.
        let entry = PypiVersionFileInfo {
            filename: Some("legacy-1.0-py3-none-any.whl".into()),
            url: Some("https://h/legacy-1.0-py3-none-any.whl".into()),
            sha256: None,
            upload_time: None,
        };
        let coords = coords_for("legacy-1.0-py3-none-any.whl", "1.0");
        let err = checksum_from_entry(&PyPiFormatHandler, &entry, &coords).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn checksum_from_entry_malformed_sha256_returns_validation() {
        // A short/non-hex sha256 fails the SAME audited length/hex check.
        let entry = PypiVersionFileInfo {
            filename: Some("x-1.0-py3-none-any.whl".into()),
            url: Some("https://h/x-1.0-py3-none-any.whl".into()),
            sha256: Some("not-a-valid-sha".into()),
            upload_time: None,
        };
        let coords = coords_for("x-1.0-py3-none-any.whl", "1.0");
        let err = checksum_from_entry(&PyPiFormatHandler, &entry, &coords).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn url_from_entry_https_passes_non_https_rejected() {
        // The genuine absolute upstream URL passes; the `https://`
        // guard rejects a downgrade target.
        let ok = PypiVersionFileInfo {
            filename: Some("x.whl".into()),
            url: Some("https://files.pythonhosted.org/x/x.whl".into()),
            sha256: Some("aa".into()),
            upload_time: None,
        };
        assert_eq!(
            url_from_entry(&ok, "x.whl").unwrap(),
            "https://files.pythonhosted.org/x/x.whl"
        );
        let http = PypiVersionFileInfo {
            url: Some("http://insecure/x.whl".into()),
            ..ok.clone()
        };
        assert!(matches!(
            url_from_entry(&http, "x.whl"),
            Err(DomainError::Validation(_))
        ));
        let missing = PypiVersionFileInfo {
            url: None,
            ..ok.clone()
        };
        assert!(matches!(
            url_from_entry(&missing, "x.whl"),
            Err(DomainError::Validation(_))
        ));
    }

    // ---- Branch 1: no mapping -----------------------------------------------

    #[tokio::test]
    async fn no_upstream_mapping_returns_no_upstream_mapping() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());

        let err = try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0.tar.gz")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::NoUpstreamMapping),
            "expected NoUpstreamMapping, got {err:?}"
        );
    }

    // ---- Branch 2: filename parse failure -----------------------------------

    #[tokio::test]
    async fn unrecognised_filename_extension_returns_parse_error() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let err = try_upstream_file_pull(
            &ctx,
            &repo,
            "this-is-not-a-package",
            "this-is-not-a-package.unknown",
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::ParseError(_)),
            "expected ParseError for unrecognised extension, got {err:?}"
        );
    }

    #[tokio::test]
    async fn filename_project_normalisation_mismatch_returns_parse_error() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        // URL says `requests`; filename says `numpy`. PEP 503-normalising
        // both still produces a mismatch.
        let err = try_upstream_file_pull(&ctx, &repo, "requests", "numpy-1.0-py3-none-any.whl")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::ParseError(_)),
            "expected ParseError for project mismatch, got {err:?}"
        );
    }

    // ---- Branch 3: metadata fetch failure (json leg) ------------------------

    #[tokio::test]
    async fn json_fetch_fail_returns_metadata_fetch_failed_with_stage_json() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        // Inject a one-shot failure on the next fetch_metadata call.
        // Without the inject, the mock returns `upstream:not_found:...`
        // which still maps to MetadataFetchFailed; the inject lets us
        // assert the stage label cleanly.
        mocks
            .upstream_proxy
            .fail_next_metadata_with(DomainError::Invariant("upstream:network:timeout".into()));

        let err = try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0.tar.gz")
            .await
            .unwrap_err();

        match err {
            UpstreamPullError::MetadataFetchFailed { stage, .. } => {
                assert_eq!(stage, "json");
            }
            other => panic!("expected MetadataFetchFailed{{stage:\"json\"}}, got {other:?}"),
        }
    }

    // ---- Branch 4: metadata parse failure (md5-only) ------------------------

    #[tokio::test]
    async fn md5_only_response_returns_parse_error() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body = pypi_json_md5_only(
            "legacy-1.0-py3-none-any.whl",
            "https://files.pythonhosted.org/packages/abc/legacy-1.0-py3-none-any.whl",
        );
        // PEP 503: legacy → legacy.
        mocks
            .upstream_proxy
            .insert_metadata("", "/pypi/legacy/1.0/json", body);

        let err = try_upstream_file_pull(&ctx, &repo, "legacy", "legacy-1.0-py3-none-any.whl")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::ParseError(_)),
            "expected ParseError for md5-only response, got {err:?}"
        );
    }

    // ---- Branch 5: filename not in upstream urls[] --------------------------

    #[tokio::test]
    async fn filename_not_in_upstream_urls_returns_parse_error() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        // Body has requests-2.31.0.tar.gz but the request asks for
        // a different filename under the same project.
        let body = pypi_json(
            "requests-2.31.0.tar.gz",
            &sha256_hex(b"unused"),
            "https://files.pythonhosted.org/packages/abc/requests-2.31.0.tar.gz",
        );
        // The metadata path is keyed on the version derived from the
        // REQUESTED filename, not the body's filename — so use 2.99.99.
        mocks
            .upstream_proxy
            .insert_metadata("", "/pypi/requests/2.99.99/json", body);

        // requests-2.99.99-py3-none-any.whl asks for a wheel that the
        // body's urls[] doesn't list (only the sdist for 2.31.0 is
        // there). parse_upstream_checksum surfaces the "no entry"
        // branch as Validation, which we map to ParseError.
        let err =
            try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.99.99-py3-none-any.whl")
                .await
                .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::ParseError(_)),
            "expected ParseError for filename-not-in-urls, got {err:?}"
        );
    }

    // ---- Branch 6: file fetch failure ---------------------------------------

    #[tokio::test]
    async fn file_fetch_fail_returns_metadata_fetch_failed_with_stage_file() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body_bytes = b"the actual sdist body".to_vec();
        let sha = sha256_hex(&body_bytes);
        let url = "https://files.pythonhosted.org/packages/abc/requests-2.31.0.tar.gz";
        let json = pypi_json("requests-2.31.0.tar.gz", &sha, url);
        mocks
            .upstream_proxy
            .insert_metadata("", "/pypi/requests/2.31.0/json", json);
        // No insert_artifact → fetch_artifact returns not_found error.

        let err = try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0.tar.gz")
            .await
            .unwrap_err();

        match err {
            UpstreamPullError::MetadataFetchFailed { stage, .. } => {
                assert_eq!(stage, "file");
            }
            other => panic!("expected MetadataFetchFailed{{stage:\"file\"}}, got {other:?}"),
        }
    }

    // ---- Branch 7: checksum mismatch ----------------------------------------

    #[tokio::test]
    async fn ingest_verified_returns_conflict_returns_checksum_mismatch() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        // JSON advertises a sha256 that does NOT match the bytes the
        // proxy will serve. The use case rehashes the streamed bytes
        // and returns Conflict — the mismatch path is the same one
        // pinned by `ingest_verified_protocol_native_mismatch_emits_repository_event_and_rolls_back`
        // in `hort_app::use_cases::ingest_use_case`.
        let actual = b"actual-bytes".to_vec();
        let lying_sha = sha256_hex(b"different-bytes");
        let url = "https://files.pythonhosted.org/packages/abc/requests-2.31.0.tar.gz";
        let json = pypi_json("requests-2.31.0.tar.gz", &lying_sha, url);
        mocks
            .upstream_proxy
            .insert_metadata("", "/pypi/requests/2.31.0/json", json);
        // Mock keys on (path_prefix, path); the path passed to
        // fetch_artifact in the orchestrator IS the absolute URL
        // (path_prefix = "" because that's the mapping's prefix).
        mocks.upstream_proxy.insert_artifact("", url, actual);

        let err = try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0.tar.gz")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::ChecksumMismatch),
            "expected ChecksumMismatch, got {err:?}"
        );
    }

    // ---- Branch 8: ingest_verified other error ------------------------------

    #[tokio::test]
    async fn ingest_verified_internal_error_returns_ingest_failed() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body_bytes = b"the actual sdist body".to_vec();
        let sha = sha256_hex(&body_bytes);
        let url = "https://files.pythonhosted.org/packages/abc/requests-2.31.0.tar.gz";
        let json = pypi_json("requests-2.31.0.tar.gz", &sha, url);
        mocks
            .upstream_proxy
            .insert_metadata("", "/pypi/requests/2.31.0/json", json);
        mocks.upstream_proxy.insert_artifact("", url, body_bytes);

        // Force commit_transition to fail — non-Conflict, non-Curation
        // path. The orchestrator routes it to IngestFailed. Mirrors
        // Cargo's `ingest_verified_internal_error_returns_internal`
        // setup — lifecycle failure is the cleanest "infra exploded
        // after rehash" simulation the mock harness offers.
        mocks
            .lifecycle
            .fail_next_commit(DomainError::Invariant("event store unreachable".into()));

        let err = try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0.tar.gz")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::IngestFailed(_)),
            "expected IngestFailed, got {err:?}"
        );
    }

    // ---- Branch 8b: ingest_verified returns CurationBlocked → 404 -----------

    /// A curation rule blocks the upstream distribution during
    /// `ingest_verified`. The orchestrator must surface
    /// `CurationBlocked` (NOT `IngestFailed`), and the wire-map must
    /// render it as a 404 **byte-identical** (status + headers + body)
    /// to a genuine `NoUpstreamMapping` miss — the anti-enumeration
    /// contract (LOG-1/LOG-2). Mirrors the Cargo
    /// `ingest_verified_returns_curation_blocked_returns_curation_blocked`
    /// test. Latent in production until a curation rule covers a PyPI
    /// proxy artifact; wired proactively for parity.
    #[tokio::test]
    async fn ingest_verified_curation_blocked_returns_404_identical_to_miss() {
        use axum::body::to_bytes;
        use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};

        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        // Valid per-version JSON + matching sdist bytes — the pull
        // reaches `ingest_verified`, where the curation gate fires.
        let body_bytes = b"the actual sdist body".to_vec();
        let sha = sha256_hex(&body_bytes);
        let url = "https://files.pythonhosted.org/packages/abc/requests-2.31.0.tar.gz";
        let json = pypi_json("requests-2.31.0.tar.gz", &sha, url);
        mocks
            .upstream_proxy
            .insert_metadata("", "/pypi/requests/2.31.0/json", json);
        mocks.upstream_proxy.insert_artifact("", url, body_bytes);

        // Curation rule that matches everything in this repo.
        let rule = CurationRule {
            id: Uuid::new_v4(),
            name: "block-all".into(),
            format: None,
            package_pattern: "*".into(),
            action: CurationRuleAction::Block,
            reason: "policy".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
        };
        mocks.curation_rules.set_rules_for_repo(repo.id, vec![rule]);

        let err = try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0.tar.gz")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::CurationBlocked),
            "expected CurationBlocked, got {err:?}"
        );

        // The rendered response must be a 404 byte-identical to a
        // genuine `NoUpstreamMapping` miss — no enumeration oracle.
        let blocked = map_upstream_pull_error(&UpstreamPullError::CurationBlocked);
        let miss = map_upstream_pull_error(&UpstreamPullError::NoUpstreamMapping);
        assert_eq!(blocked.status(), StatusCode::NOT_FOUND);
        assert_eq!(blocked.status(), miss.status());
        assert_eq!(
            blocked.headers(),
            miss.headers(),
            "curation-blocked headers must match a genuine miss"
        );
        let blocked_body = to_bytes(blocked.into_body(), usize::MAX).await.unwrap();
        let miss_body = to_bytes(miss.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            blocked_body, miss_body,
            "curation-blocked body must be byte-identical to a genuine miss"
        );
    }

    // ---- Branch 9: happy path — wheel ---------------------------------------

    #[tokio::test]
    async fn happy_path_wheel_returns_artifact() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body_bytes = b"the actual wheel body".to_vec();
        let sha = sha256_hex(&body_bytes);
        let wheel_url =
            "https://files.pythonhosted.org/packages/abc/requests-2.31.0-py3-none-any.whl";
        let sdist_url = "https://files.pythonhosted.org/packages/def/requests-2.31.0.tar.gz";
        // Two-entry body — wheel is the requested one, sdist is along
        // for the ride to confirm we pick the right entry.
        let json = pypi_json_two(
            "requests-2.31.0-py3-none-any.whl",
            &sha,
            wheel_url,
            "requests-2.31.0.tar.gz",
            &sha256_hex(b"sdist-body-different-sha"),
            sdist_url,
        );
        mocks
            .upstream_proxy
            .insert_metadata("", "/pypi/requests/2.31.0/json", json);
        mocks
            .upstream_proxy
            .insert_artifact("", wheel_url, body_bytes.clone());

        let artifact =
            try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0-py3-none-any.whl")
                .await
                .expect("happy path (wheel) must succeed");

        assert_eq!(artifact.name, "requests");
        assert_eq!(artifact.version.as_deref(), Some("2.31.0"));
        assert_eq!(artifact.size_bytes as usize, body_bytes.len());
        // Load-bearing assertion: the SHA-256 stored on the artifact
        // equals the sha extracted from the JSON — proving
        // ingest_verified actually verified the bytes against the
        // upstream-published value.
        assert_eq!(artifact.sha256_checksum.as_ref(), sha);
    }

    // ---- Branch 10: happy path — sdist --------------------------------------

    #[tokio::test]
    async fn happy_path_sdist_returns_artifact() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body_bytes = b"the actual sdist body".to_vec();
        let sha = sha256_hex(&body_bytes);
        let sdist_url = "https://files.pythonhosted.org/packages/def/requests-2.31.0.tar.gz";
        let json = pypi_json("requests-2.31.0.tar.gz", &sha, sdist_url);
        mocks
            .upstream_proxy
            .insert_metadata("", "/pypi/requests/2.31.0/json", json);
        mocks
            .upstream_proxy
            .insert_artifact("", sdist_url, body_bytes.clone());

        let artifact = try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0.tar.gz")
            .await
            .expect("happy path (sdist) must succeed");

        assert_eq!(artifact.name, "requests");
        assert_eq!(artifact.version.as_deref(), Some("2.31.0"));
        assert_eq!(artifact.size_bytes as usize, body_bytes.len());
        assert_eq!(artifact.sha256_checksum.as_ref(), sha);
    }

    // ---- upload_time → upstream_published_at --------------------------------

    /// End-to-end: the per-version JSON's filename-matched
    /// `upload_time_iso_8601` (read off the projection's
    /// `PypiVersionFileInfo.upload_time`) MUST flow to
    /// `Artifact.upstream_published_at`. The body carries two entries with
    /// distinct timestamps; pulling the wheel must anchor on the WHEEL's
    /// timestamp (filename-matched), not the sdist's — guards against an
    /// "any entry" shortcut surviving a future refactor.
    #[tokio::test]
    async fn tarball_pull_threads_upload_time_to_upstream_published_at() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body_bytes = b"wheel-body-for-i2".to_vec();
        let sha = sha256_hex(&body_bytes);
        let wheel_url =
            "https://files.pythonhosted.org/packages/abc/requests-2.31.0-py3-none-any.whl";
        let sdist_url = "https://files.pythonhosted.org/packages/def/requests-2.31.0.tar.gz";
        let json = format!(
            r#"{{"urls":[
                {{"filename":"requests-2.31.0-py3-none-any.whl","url":"{wheel_url}","digests":{{"sha256":"{sha}"}},"upload_time_iso_8601":"2023-05-22T15:12:42.123456Z"}},
                {{"filename":"requests-2.31.0.tar.gz","url":"{sdist_url}","digests":{{"sha256":"{sdist_sha}"}},"upload_time_iso_8601":"2023-05-22T15:12:50.000000Z"}}
            ]}}"#,
            sdist_sha = sha256_hex(b"sdist-other"),
        )
        .into_bytes();
        mocks
            .upstream_proxy
            .insert_metadata("", "/pypi/requests/2.31.0/json", json);
        mocks
            .upstream_proxy
            .insert_artifact("", wheel_url, body_bytes.clone());

        let artifact =
            try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0-py3-none-any.whl")
                .await
                .expect("happy path with upload_time must succeed");

        let want = chrono::DateTime::parse_from_rfc3339("2023-05-22T15:12:42.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            artifact.upstream_published_at,
            Some(want),
            "the wheel's filename-matched upload_time must reach upstream_published_at"
        );
    }

    // ---- PEP 503 normalisation: URL `My_Package` → upstream `my-package` ----

    #[tokio::test]
    async fn pep503_normalisation_url_uses_normalised_path() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body_bytes = b"my-package wheel body".to_vec();
        let sha = sha256_hex(&body_bytes);
        let wheel_url =
            "https://files.pythonhosted.org/packages/abc/My_Package-1.0-py3-none-any.whl";
        let json = pypi_json("My_Package-1.0-py3-none-any.whl", &sha, wheel_url);
        // The handler builds the path with the PEP 503-normalised name
        // (`my-package`), not the URL-supplied form (`My_Package`).
        mocks
            .upstream_proxy
            .insert_metadata("", "/pypi/my-package/1.0/json", json);
        mocks
            .upstream_proxy
            .insert_artifact("", wheel_url, body_bytes.clone());

        // URL segment `My_Package` and filename `My_Package-1.0...`
        // both PEP 503-normalise to `my-package` — the cross-check
        // passes and the metadata is fetched at the normalised path.
        let artifact =
            try_upstream_file_pull(&ctx, &repo, "My_Package", "My_Package-1.0-py3-none-any.whl")
                .await
                .expect("PEP 503 normalisation path must succeed");

        assert_eq!(artifact.sha256_checksum.as_ref(), sha);
    }

    // ---- Audit invariant — exactly one ChecksumVerified -----------------

    /// Every successful proxy ingest produces exactly one
    /// `ChecksumVerified` event in the artifact's stream.
    ///
    /// Drives a happy-path pull through `try_upstream_file_pull` end-to-end
    /// with `MockPorts`, then introspects `mocks.lifecycle.committed_transitions()`
    /// — the lifecycle port is the single point where `ArtifactIngested +
    /// ChecksumVerified` lands atomically (see
    /// `hort_app::use_cases::ingest_use_case::ingest_verified`). Filter to
    /// the artifact's stream (`StreamId::artifact(artifact.id)`), count
    /// `ChecksumVerified`, and assert exactly one. Also assert no
    /// `ChecksumMismatch` fires anywhere on the success path.
    #[tokio::test]
    async fn successful_pull_emits_exactly_one_checksum_verified_event() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = pypi_repo("pypi-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body_bytes = b"the actual sdist body".to_vec();
        let sha = sha256_hex(&body_bytes);
        let sdist_url = "https://files.pythonhosted.org/packages/def/requests-2.31.0.tar.gz";
        let json = pypi_json("requests-2.31.0.tar.gz", &sha, sdist_url);
        mocks
            .upstream_proxy
            .insert_metadata("", "/pypi/requests/2.31.0/json", json);
        mocks
            .upstream_proxy
            .insert_artifact("", sdist_url, body_bytes.clone());

        let artifact = try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0.tar.gz")
            .await
            .expect("happy path must succeed for the audit invariant");

        // Inspect the lifecycle's recorded transitions — that's where
        // ingest_verified emits ArtifactIngested + ChecksumVerified
        // atomically. Filter to the artifact's stream.
        let artifact_stream = StreamId::artifact(artifact.id);
        let transitions = mocks.lifecycle.committed_transitions();
        let verified_count = transitions
            .iter()
            .filter(|(_a, ev, _m)| ev.stream_id == artifact_stream)
            .flat_map(|(_a, ev, _m)| ev.events.iter())
            .filter(|e| matches!(e.event, DomainEvent::ChecksumVerified(_)))
            .count();
        assert_eq!(
            verified_count, 1,
            "exactly one ChecksumVerified must land on the artifact stream"
        );

        // The happy path must NOT emit ChecksumMismatch anywhere — that
        // variant is reserved for the tampered-bytes path (Branch 7).
        let mismatch_count = transitions
            .iter()
            .flat_map(|(_a, ev, _m)| ev.events.iter())
            .filter(|e| matches!(e.event, DomainEvent::ChecksumMismatch(_)))
            .count();
        // Also check the standalone event store (where ingest_verified
        // appends ChecksumMismatch on failure — never on success).
        let mismatch_count_all = mismatch_count
            + mocks
                .events
                .appended_batches()
                .iter()
                .flat_map(|b| b.events.iter())
                .filter(|e| matches!(e.event, DomainEvent::ChecksumMismatch(_)))
                .count();
        assert_eq!(
            mismatch_count_all, 0,
            "ChecksumMismatch must NOT fire on the happy path"
        );
    }

    // ---- Tracing infrastructure for warn-capture test -------------------

    /// Custom tracing layer that captures emitted events into a shared
    /// vector. Mirrors the pattern in
    /// `crates/hort-http-cargo/src/upstream_pull.rs` — see that
    /// module for the detailed rationale on `Interest::sometimes()`,
    /// per-callsite caching, and the global-passthrough seeding.
    #[derive(Clone, Default)]
    struct CapturingLayer {
        records: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for CapturingLayer
    where
        S: tracing::Subscriber,
    {
        fn register_callsite(
            &self,
            _meta: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn enabled(
            &self,
            _meta: &tracing::Metadata<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) -> bool {
            true
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = MessageVisitor::default();
            event.record(&mut visitor);
            self.records
                .lock()
                .unwrap()
                .push((*event.metadata().level(), visitor.combined));
        }
    }

    #[derive(Default)]
    struct MessageVisitor {
        combined: String,
    }
    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.combined
                .push_str(&format!("{}={:?} ", field.name(), value));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.combined
                .push_str(&format!("{}={} ", field.name(), value));
        }
    }

    /// Serialises tests that install per-thread tracing subscribers.
    /// `tracing` caches per-callsite `Interest` globally; installing one
    /// subscriber on thread A while thread B fires the same callsite
    /// races. The mutex eliminates the race without touching global state.
    static TRACING_TEST_MUTEX: Mutex<()> = Mutex::new(());

    /// Install a global passthrough subscriber (once per process) so the
    /// per-callsite cache is seeded with `Interest::sometimes()` rather
    /// than `Never`. Without this, a no-op subscriber installed by any
    /// earlier test can cache `Never` for our callsites and prevent the
    /// per-thread `set_default` subscriber from ever seeing those events.
    fn install_global_passthrough_subscriber() {
        use std::sync::OnceLock;
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let global_layer = CapturingLayer::default();
            let global_subscriber = Registry::default().with(global_layer);
            let _ = tracing::subscriber::set_global_default(global_subscriber);
        });
    }

    /// Assert that `try_upstream_file_pull` emits a `WARN`-level
    /// tracing event with structured fields when a non-success branch
    /// fires. The `NoUpstreamMapping` branch is the cleanest target —
    /// it short-circuits before any I/O, requires no fixtures beyond an
    /// empty `MockPorts`, and emits a warn at the entry point.
    ///
    /// Uses the same `CapturingLayer` + `TRACING_TEST_MUTEX` +
    /// `install_global_passthrough_subscriber` idiom as the Cargo crate
    /// (`crates/hort-http-cargo/src/upstream_pull.rs::checksum_mismatch_emits_tracing_warn`).
    /// The test is `#[test]` (not `#[tokio::test]`) because the mutex
    /// guard cannot cross an `await` point; a current-thread runtime
    /// drives the async call synchronously inside the guarded scope.
    #[test]
    fn non_success_branch_emits_warn_with_structured_fields() {
        install_global_passthrough_subscriber();
        let _serial = TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let layer = CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            // No upstream mapping seeded → NoUpstreamMapping fires
            // immediately on the resolver miss and emits the
            // entry-point warn.
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = pypi_repo("pypi-mirror");
            mocks.repositories.insert(repo.clone());

            try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0.tar.gz").await
        });

        assert!(
            matches!(result, Err(UpstreamPullError::NoUpstreamMapping)),
            "expected NoUpstreamMapping, got {result:?}"
        );

        let records = captured.lock().unwrap();
        let warn_event = records
            .iter()
            .find(|(lvl, msg)| {
                *lvl == tracing::Level::WARN
                    && (msg.contains("no upstream mapping")
                        || msg.contains("PyPI repository has no upstream mapping"))
            })
            .map(|(_, msg)| msg.clone());
        assert!(
            warn_event.is_some(),
            "expected WARN-level event mentioning the no-upstream-mapping branch; \
             captured: {records:?}"
        );
    }

    // ---- PullDedup wrap-coverage tests --------------------------------------
    //
    // These tests assert that the three wrapped call sites (simple-index
    // `fetch_metadata`, JSON metadata `fetch_metadata`, wheel/sdist
    // `fetch_artifact`+`ingest_verified`) actually emit
    // `hort_pull_dedup_total` metrics. The harness installs a
    // `DebuggingRecorder` via `metrics::with_local_recorder` around a
    // `block_on` driving the async test body. Counter labels are read
    // back via `Snapshotter::snapshot` and matched on `outcome`.

    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use metrics_util::CompositeKey;

    type SnapshotRow = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    /// Capture metrics emitted by the async block. Mirrors the
    /// `pull_dedup.rs::tests::capture` pattern (own current-thread
    /// runtime inside `with_local_recorder` so the recorder is the
    /// thread-local for every spawned task the orchestrator drives).
    fn capture_metrics<F, Fut>(f: F) -> Vec<SnapshotRow>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter: Snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f());
        });
        snapshotter.snapshot().into_vec()
    }

    /// Sum a counter across all label combinations for the given
    /// `outcome`. The two new tests want "did the metric fire ≥ N
    /// times for this outcome regardless of layer/format" assertions
    /// — `layer` differs (in_process vs cluster) depending on
    /// scheduler interleaving and `format` is the literal `"_any"`
    /// for blob-by-hash keys in the pull-through dedup path.
    fn sum_counter_for_outcome(rows: &[SnapshotRow], outcome: &str) -> u64 {
        let mut total = 0u64;
        for (ckey, _u, _d, value) in rows {
            let k = ckey.key();
            if k.name() != "hort_pull_dedup_total" {
                continue;
            }
            let mut hit = false;
            for label in k.labels() {
                if label.key() == "outcome" && label.value() == outcome {
                    hit = true;
                }
            }
            if hit {
                if let DebugValue::Counter(n) = value {
                    total = total.saturating_add(*n);
                }
            }
        }
        total
    }

    /// Concurrent-coalesce test: spawn two `tokio::spawn` requests
    /// against the same wheel artifact. The wrapped `coalesce_blob`
    /// call site at the artifact-fetch leg must route both into a
    /// single coalescing window — exactly one `leader_started`
    /// increment, ≥ 1 `follower_waited_hit` increment.
    ///
    /// Determinism note: on a current-thread runtime the second
    /// `tokio::spawn` cannot run before the first awaits something
    /// inside its closure. The first task's `ingest_verified` path
    /// crosses many await points (CAS write, event-store append,
    /// lifecycle commit) before completing; the second task's
    /// `put_if_absent` therefore lands AFTER the first's, puts it
    /// onto the Layer-A broadcast (or the Layer-B poll loop), and
    /// observes the leader's terminal outcome. `await`ing both join
    /// handles before the metric-snapshot read pins the assertion.
    #[test]
    fn concurrent_blob_callers_coalesce_into_one_leader_started() {
        let snap = capture_metrics(|| async {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = pypi_repo("pypi-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id, "");

            let body_bytes = b"the actual wheel body".to_vec();
            let sha = sha256_hex(&body_bytes);
            let wheel_url =
                "https://files.pythonhosted.org/packages/abc/requests-2.31.0-py3-none-any.whl";
            let json = pypi_json("requests-2.31.0-py3-none-any.whl", &sha, wheel_url);
            mocks
                .upstream_proxy
                .insert_metadata("", "/pypi/requests/2.31.0/json", json);
            mocks
                .upstream_proxy
                .insert_artifact("", wheel_url, body_bytes.clone());

            let ctx_a = ctx.clone();
            let repo_a = repo.clone();
            let h1 = tokio::spawn(async move {
                try_upstream_file_pull(
                    &ctx_a,
                    &repo_a,
                    "requests",
                    "requests-2.31.0-py3-none-any.whl",
                )
                .await
            });
            let ctx_b = ctx.clone();
            let repo_b = repo.clone();
            let h2 = tokio::spawn(async move {
                try_upstream_file_pull(
                    &ctx_b,
                    &repo_b,
                    "requests",
                    "requests-2.31.0-py3-none-any.whl",
                )
                .await
            });

            let r1 = h1.await.unwrap();
            let r2 = h2.await.unwrap();
            // Both callers must see a successful artifact regardless
            // of which one was elected leader vs follower — the
            // post-coalesce `find_in_repo_by_hash` resolves the row
            // the leader's ingest wrote.
            assert!(
                r1.is_ok(),
                "task 1 must succeed (leader OR follower); got {r1:?}"
            );
            assert!(
                r2.is_ok(),
                "task 2 must succeed (leader OR follower); got {r2:?}"
            );
        });

        // The wheel/sdist blob fetch is the load-bearing wrap for this
        // test — the metadata leg (JSON) ALSO coalesces, so
        // `leader_started` for the metadata leg may also fire. We
        // assert the BLOB leg coalesced by counting total
        // leader_started across all formats/layers — at least one
        // blob leader plus at most one metadata leader (JSON). The
        // lower bound is `leader_started >= 1`; the follower
        // assertion is the load-bearing one.
        let leader_started = sum_counter_for_outcome(&snap, "leader_started");
        let follower_waited_hit = sum_counter_for_outcome(&snap, "follower_waited_hit");
        assert!(
            leader_started >= 1,
            "expected ≥1 leader_started across the wrapped call sites; \
             got {leader_started}, snap: {snap:?}"
        );
        assert!(
            follower_waited_hit >= 1,
            "expected ≥1 follower_waited_hit (concurrent coalesce); \
             got {follower_waited_hit}, snap: {snap:?}"
        );
    }

    /// Negative-cache test: the wrapped JSON metadata fetch fails
    /// (transport-level error via `fail_next_metadata_with`). The
    /// leader records the failure under the dedup key with the
    /// configured negative-cache TTL (default 30 s for `NotFound`).
    /// A second call within the TTL window must short-circuit on
    /// `negative_cache_hit` without firing a second `leader_started`.
    #[test]
    fn negative_cache_short_circuits_repeated_failures_within_ttl() {
        let snap = capture_metrics(|| async {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = pypi_repo("pypi-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id, "");

            // First call: stage a one-shot transport failure on the
            // next `fetch_metadata` (the JSON metadata fetch is the
            // first metadata call the orchestrator makes for the
            // download path). The leader records `Failed` under the
            // JSON dedup key.
            mocks
                .upstream_proxy
                .fail_next_metadata_with(DomainError::Invariant("upstream:not_found:json".into()));
            let r1 =
                try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0.tar.gz").await;
            assert!(
                matches!(r1, Err(UpstreamPullError::MetadataFetchFailed { stage, .. }) if stage == "json"),
                "first call must fail with MetadataFetchFailed{{stage:json}}; got {r1:?}"
            );

            // Second call within the negative-cache TTL window: the
            // `fail_next_metadata_with` queue is drained — if the
            // orchestrator re-issued the upstream fetch, it would hit
            // the absent-fixture path (which the mock returns as a
            // fresh `upstream:not_found` Err), counting as
            // `leader_started` again. The negative-cache short-circuit
            // prevents that: the second call must observe the cached
            // `Failed` outcome before any election.
            let r2 =
                try_upstream_file_pull(&ctx, &repo, "requests", "requests-2.31.0.tar.gz").await;
            assert!(
                r2.is_err(),
                "second call must surface the cached failure; got {r2:?}"
            );
        });

        // Assertion: `negative_cache_hit` increments by ≥ 1 (the
        // second call short-circuited). `leader_started` for the JSON
        // metadata key stays at 1 (only the FIRST call elected; the
        // second was a cache hit). The metric snapshot is aggregated
        // across the three wrapped call sites; the first call only
        // reaches the JSON metadata fetch (it errors before the file
        // fetch), so `leader_started` should be exactly 1 across the
        // entire snapshot.
        let negative_cache_hit = sum_counter_for_outcome(&snap, "negative_cache_hit");
        let leader_started = sum_counter_for_outcome(&snap, "leader_started");
        assert!(
            negative_cache_hit >= 1,
            "expected ≥1 negative_cache_hit (second call hits cached \
             failure); got {negative_cache_hit}, snap: {snap:?}"
        );
        assert_eq!(
            leader_started, 1,
            "expected exactly 1 leader_started (only the first call \
             elected; the second short-circuited via negative cache); \
             got {leader_started}, snap: {snap:?}"
        );
    }
}
