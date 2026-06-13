//! npm tarball upstream pull-through orchestrator.
//!
//! Three-leg verified pull-through for the npm registry tarball download:
//!
//! 1. Resolve the upstream mapping via [`UpstreamResolver`].
//! 2. Resolve the per-package packument **projection** through
//!    [`crate::packument::fetch_raw_with_cache`] — the serve-path helper
//!    that owns the `npm_packument_proj:{mapping.id}:{url_encoded_name}`
//!    projection cache (fresh hit → no upstream call) and the miss path
//!    (stream the body through the projector, write the raw to the
//!    [`MetadataMirrorStore`](hort_domain::ports::metadata_mirror_store),
//!    cache the projection). The cache holds the small projection, not
//!    the raw body; the raw lives in the mirror. The projection's
//!    `NpmVersionEntry` for the requested version carries the GENUINE
//!    upstream `dist.tarball` (`entry.tarball`, captured verbatim by
//!    the projector before any serve-time rewrite — F11 / §9.1
//!    invariant I-1) and the verbatim `dist.integrity` SRI
//!    (`entry.integrity` — ADR 0006 / I-3).
//! 3. Recover the upstream `dist.integrity` SHA-512 from `entry.integrity`
//!    via the same audited
//!    [`NpmFormatHandler::parse_upstream_checksum`] decode, and the
//!    absolute tarball URL from `entry.tarball` (with the `https://`
//!    guard).
//! 4. Defence-in-depth filename validation — the basename of the
//!    upstream `dist.tarball` URL must equal the request's `filename`
//!    parameter. Prevents an upstream from substituting a different
//!    tarball into `dist.tarball` than the URL the client asked for.
//! 5. Stream the tarball via [`UpstreamProxy::fetch_artifact`] and
//!    ingest through [`IngestUseCase::ingest_verified`] as a
//!    `VerifiedIngestRequest::UpstreamPublished(Sha512)`. The use case
//!    wraps the stream in `Sha512HashingRead` automatically because the
//!    algorithm on `UpstreamPublishedChecksum` is `Sha512` (ADR 0006).
//!
//! `try_upstream_tarball_pull` lives in this inbound-HTTP crate (NOT a
//! use case) — keeps the orchestration close to the route. Item 5
//! wires the dispatch from `serve_tarball`; this item only lands the
//! orchestrator + its branch tests.
//!
//! Wire-mapping ([`UpstreamPullError`] → HTTP status / body) is deferred
//! to Item 5; the discrimination here only needs to surface the failure
//! modes cleanly. The variant list mirrors the PyPI (17.2) and Cargo
//! (17.1) precedents so the Item 5 wire-map can use the same shape.

use std::sync::Arc;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
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
use hort_formats::npm::projection::NpmVersionEntry;
use hort_formats::npm::NpmFormatHandler;
use hort_http_core::context::AppContext;

use crate::packument::{fetch_raw_with_cache, PackumentFetchError};

/// Discriminated failure modes for [`try_upstream_tarball_pull`]. Wire
/// mapping (HTTP status + envelope body) is performed by Item 5 in the
/// route handler; the orchestrator itself only surfaces *what* went
/// wrong, not *how to render it*.
///
/// The variant list mirrors PyPI (`crates/hort-http-pypi/src/upstream_pull.rs::
/// UpstreamPullError`) so the Item 5 wire-mapping can reuse the same
/// shape. `FilenameMismatch` is the npm-specific defence-in-depth check —
/// the upstream `dist.tarball` basename must agree with the URL filename
/// the client asked for, otherwise an upstream could substitute a
/// different tarball under the legitimate metadata.
///
/// `MetadataMalformed` mirrors PyPI's `ParseError` — both surface the
/// "upstream returned bytes the format handler couldn't parse" branch
/// (npm: dist.integrity missing, malformed SRI, no sha512 entry).
/// `TarballUrlInvalid` is a separate variant because the helper that
/// extracts the URL is independent of the checksum parser (Item 2 design
/// note); a body that parses cleanly for the integrity field but yields
/// no valid `dist.tarball` URL is a distinct failure shape that the
/// wire-map may want to render differently.
#[derive(Debug, thiserror::Error)]
pub(crate) enum UpstreamPullError {
    /// No upstream mapping configured for this repo. Wire to "no
    /// pull-through configured" — typically a 404 since the artifact
    /// is genuinely unknown locally and the repo is not a proxy.
    #[error("no upstream mapping configured")]
    NoUpstream,

    /// Upstream HTTP fetch failed (packument or tarball leg). Carries
    /// the inner error string for tracing — wire-map renders a stable
    /// envelope. The field is named `cause` (not `source`) so thiserror
    /// does NOT treat it as the `Error::source()` chain (which would
    /// require an `Error` type, not a `String`).
    #[error("upstream unavailable: {cause}")]
    UpstreamUnavailable { cause: String },

    /// Packument body parsed cleanly enough to read JSON but
    /// `parse_upstream_checksum` rejected it: missing `dist.integrity`,
    /// malformed SRI, no sha512 entry, or the requested version is
    /// absent from `versions[]`.
    #[error("upstream metadata malformed: {cause}")]
    MetadataMalformed { cause: String },

    /// `dist.integrity` parsed but the `dist.tarball` URL is missing,
    /// non-https, or the version isn't in the packument. Distinct from
    /// `MetadataMalformed` because the URL helper is invoked separately
    /// (Item 2 keeps the two parsers independent).
    #[error("upstream tarball URL invalid: {cause}")]
    TarballUrlInvalid { cause: String },

    /// Defence-in-depth check failed: the basename of the upstream
    /// `dist.tarball` URL does not match the request's `filename`
    /// parameter. Treated as upstream tampering — the client asked for
    /// `foo-1.0.0.tgz`, the upstream said "fetch this URL ending in
    /// `bar-2.0.0.tgz`". Refuse.
    #[error("upstream tarball filename mismatch: expected {expected}, got {actual}")]
    FilenameMismatch { expected: String, actual: String },

    /// `IngestUseCase::ingest_verified` returned `Conflict` — upstream
    /// bytes hashed differently from the SHA-512 advertised in
    /// `dist.integrity`. The use case already emitted `ChecksumMismatch`
    /// on the repository stream and rolled back the CAS blob. The §15
    /// security primitive against upstream tampering.
    #[error("upstream checksum mismatch")]
    ChecksumMismatch,

    /// Any other ingest-time error — storage failure, event-store
    /// failure, repo lookup failure after ingest. Wire to 500.
    #[error("ingest failed: {cause}")]
    IngestFailed { cause: String },

    /// Internal invariant violated — should not happen in practice.
    #[error("internal error: {cause}")]
    Internal { cause: String },
}

/// On a local cache miss, fetch the requested npm tarball from the
/// configured upstream registry, verify it against the upstream
/// `dist.integrity` SHA-512, and ingest into the local CAS.
///
/// `pkg` is the protocol-form name (`express` or `@types/node`).
/// `version` is the resolved version; `filename` is the wire filename
/// the client requested (e.g. `express-4.18.2.tgz`).
///
/// Item 5 wires this from `serve_tarball` — Proxy-repo cache misses
/// route here.
#[tracing::instrument(
    skip(ctx),
    fields(
        format = "npm",
        repository_id = %repo.id,
        pkg,
        version,
        filename,
    ),
)]
pub(crate) async fn try_upstream_tarball_pull(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    pkg: &str,
    version: &str,
    filename: &str,
) -> Result<Artifact, UpstreamPullError> {
    // 1. Resolve upstream mapping. npm has a single upstream mapping
    //    per repo today (no path-prefix routing); the framework call
    //    passes `""` for the path-prefix (mirrors PyPI / Cargo).
    let Some((mapping, _stripped)) = ctx.upstream_resolver.resolve(repo.id, "") else {
        tracing::warn!(
            format = "npm",
            repository_id = %repo.id,
            "npm repository has no upstream mapping configured",
        );
        return Err(UpstreamPullError::NoUpstream);
    };

    // 2. Resolve the packument **projection**. The serve-path helper
    //    `fetch_raw_with_cache` owns the cache (proj cache hit → no
    //    upstream call) and the miss path (stream the body through the
    //    projector, write the raw to the mirror, cache the projection).
    //    The same `coalesce_metadata` dedup key as the serve route means
    //    a packument-via-pull miss and a direct packument miss still
    //    share one coalescing window.
    //
    //    F11 invariant preserved: the projection's `NpmVersionEntry`
    //    carries the GENUINE upstream `dist.tarball` (`entry.tarball`,
    //    captured verbatim by the projector before any serve-time
    //    rewrite) and the verbatim `dist.integrity` SRI
    //    (`entry.integrity`) — exactly what the checksum + URL recovery
    //    below need.
    let projection = match fetch_raw_with_cache(
        ctx.upstream_resolver.as_ref(),
        ctx.ephemeral_evictable.as_ref(),
        ctx.upstream_proxy.as_ref(),
        ctx.pull_dedup.as_ref(),
        Some(ctx.metadata_mirror.as_ref()),
        ctx.upstream_projector_version_object_max_bytes,
        repo,
        pkg,
    )
    .await
    {
        Ok(p) => p,
        Err(PackumentFetchError::NoUpstream) => {
            tracing::warn!(
                format = "npm",
                repository_id = %repo.id,
                "npm repository has no upstream mapping configured",
            );
            return Err(UpstreamPullError::NoUpstream);
        }
        Err(
            e @ (PackumentFetchError::MetadataMalformed { .. }
            | PackumentFetchError::VersionObjectTooLarge { .. }),
        ) => {
            // A malformed / over-cap packument body is a metadata fault
            // (parse-class), not an outage — same `MetadataMalformed`
            // shape the pre-amendment `parse_upstream_checksum` reject
            // produced.
            tracing::warn!(
                cause = %e,
                format = "npm",
                repository_id = %repo.id,
                pkg,
                version,
                "npm upstream packument malformed",
            );
            return Err(UpstreamPullError::MetadataMalformed {
                cause: e.to_string(),
            });
        }
        Err(PackumentFetchError::Internal(cause)) => {
            // A cache-infrastructure failure (ephemeral store get/put,
            // projection (de)serialize) is OUR internal fault, not an
            // upstream outage — surface it as 500, not the 502
            // upstream-unavailable envelope.
            tracing::warn!(
                cause = %cause,
                format = "npm",
                repository_id = %repo.id,
                "npm packument cache infrastructure failure",
            );
            return Err(UpstreamPullError::Internal { cause });
        }
        Err(e) => {
            // UpstreamUnavailable / UpstreamBodyTooLarge fold to
            // UpstreamUnavailable on the tarball-pull path — the
            // pre-amendment metadata-leg failure shape (502 / wire-map).
            tracing::warn!(
                cause = %e,
                format = "npm",
                repository_id = %repo.id,
                leg = "metadata",
                "npm upstream packument fetch failed",
            );
            return Err(UpstreamPullError::UpstreamUnavailable {
                cause: e.to_string(),
            });
        }
    };

    // Locate the requested version in the projection. A missing version
    // is the same "no honest pointer for this version" failure the
    // pre-amendment `parse_upstream_checksum` / `extract_upstream_tarball_url`
    // surfaced when `versions[version]` was absent.
    let Some(entry) = projection.versions.iter().find(|v| v.version == version) else {
        tracing::warn!(
            format = "npm",
            repository_id = %repo.id,
            pkg,
            version,
            "npm upstream packument has no entry for the requested version",
        );
        return Err(UpstreamPullError::MetadataMalformed {
            cause: format!("upstream npm packument has no version {version} for {pkg}"),
        });
    };

    // Build coords for the checksum recovery + the verified-ingest
    // request. Spec 074 §2 — the path is the canonical npm logical path
    // from the single SSOT constructor (`{name}/-/{basename}-{ver}.tgz`),
    // matching the publish-handler's `do_publish` shape and the read-side
    // `parse_download_path`. npm derives the filename from name+version, so
    // `filename = None`. The downstream basename check (below) still
    // asserts the upstream `dist.tarball` basename equals the request
    // `filename`, so a request whose filename diverges from the canonical
    // form is rejected before any fetch.
    let path = NpmFormatHandler
        .build_artifact_logical_path(pkg, version, None)
        .map_err(|e| UpstreamPullError::Internal {
            cause: e.to_string(),
        })?;
    let coords = ArtifactCoords {
        name: pkg.to_string(),
        name_as_published: pkg.to_string(),
        version: Some(version.to_string()),
        path,
        format: RepositoryFormat::Npm,
        metadata: serde_json::Value::Null,
    };

    // 3. Recover the upstream SHA-512 from the projection's verbatim
    //    `dist.integrity` SRI (`entry.integrity`). The decode + validation
    //    is the EXACT audited path `NpmFormatHandler::parse_upstream_checksum`
    //    runs (SRI → sha512 hex → `UpstreamPublishedChecksum::new`); we
    //    drive it through that handler against a minimal synthetic body
    //    holding just the requested version's `dist.integrity` so the
    //    SHA-512 verification semantics are byte-identical and not
    //    duplicated. A missing / legacy / malformed SRI surfaces as the
    //    same `MetadataMalformed` the raw-body parser produced.
    let handler = NpmFormatHandler;
    let upstream_checksum = match checksum_from_entry(&handler, entry, &coords) {
        Ok(cs) => cs,
        Err(e) => {
            tracing::warn!(
                cause = %e,
                format = "npm",
                repository_id = %repo.id,
                pkg,
                version,
                "npm upstream packument checksum parse failed",
            );
            return Err(UpstreamPullError::MetadataMalformed {
                cause: e.to_string(),
            });
        }
    };

    // 4. Recover the absolute tarball URL from the projection's verbatim
    //    `dist.tarball` (`entry.tarball`). Apply the SAME `https://` guard
    //    `extract_upstream_tarball_url` enforced (no downgrade target is
    //    ever promoted to a fetch URL).
    let tarball_url = match tarball_url_from_entry(entry, version) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(
                cause = %e,
                format = "npm",
                repository_id = %repo.id,
                pkg,
                version,
                "npm upstream tarball URL extraction failed",
            );
            return Err(UpstreamPullError::TarballUrlInvalid {
                cause: e.to_string(),
            });
        }
    };

    // 5. Defence-in-depth: the upstream tarball URL's basename must
    //    match the request's filename. Strip any query/fragment first
    //    (npm registries don't use them today, but the rule must
    //    survive a future change), then take the segment after the
    //    final `/`. A mismatch is treated as upstream tampering and
    //    aborts before any byte fetch.
    let actual_basename = tarball_basename(&tarball_url);
    if actual_basename != filename {
        tracing::warn!(
            expected = filename,
            actual = %actual_basename,
            format = "npm",
            repository_id = %repo.id,
            "npm upstream tarball filename does not match request filename; refusing to fetch",
        );
        return Err(UpstreamPullError::FilenameMismatch {
            expected: filename.to_string(),
            actual: actual_basename.into_owned(),
        });
    }

    // 6 + 7. Stream the tarball bytes via the absolute URL and ingest_verified.
    //    `fetch_artifact` accepts absolute URLs (see `hort_domain::ports::upstream_proxy`)
    //    — required because npm tarballs can live on a CDN distinct from the
    //    registry origin (e.g. mirrors). `ingest_verified` wraps the stream in
    //    `Sha512HashingRead` (ADR 0006) because the algorithm on
    //    `UpstreamPublishedChecksum` is `Sha512`; a mismatch returns
    //    Conflict — our security primitive against upstream tampering.
    //
    //    Wrap the `fetch_artifact + ingest_verified` pair in
    //    `coalesce_blob` so N parallel callers for the same tarball
    //    produce ≤ 1 upstream fetch + ≤ 1 CAS write. The dedup key
    //    uses the `dist.integrity` SRI string verbatim (e.g.
    //    `"sha512-abc...="`) rather than the decoded hex — the SRI
    //    string is itself a stable per-tarball identifier, and
    //    base64-to-hex conversion is unnecessary (the verified-rehash
    //    inside `ingest_verified` still decodes the SRI to compare
    //    against the streamed bytes; the dedup key never participates
    //    in that hash check).
    //
    //    Closure-boundary contract: on success the closure returns
    //    `Ok(content_hash)`; on failure `Err(AppError)`. The leader
    //    sees the original `AppError` discriminator (`Domain(Conflict)`
    //    for checksum mismatch); followers observe the cached `Failed`
    //    outcome and surface a wrapped `AppError::External` —
    //    typed-error discrimination is a leader-only concern.
    //
    //    Defensive `blob_by_url` fallback: the projection's verbatim
    //    `entry.integrity` IS the `dist.integrity` SRI (ADR 0026 §9.1
    //    invariant I-3) — the exact value the retired
    //    `extract_integrity_sri` read from the raw body. `None` (a
    //    version that publishes no integrity) falls back to
    //    `blob_by_url`.
    let blob_dedup_key = match entry.integrity.as_deref() {
        Some(sri) => DedupKey::blob_by_hash("sha512", sri),
        None => DedupKey::blob_by_url("npm", repo.id, &tarball_url),
    };
    // The upstream-asserted publish timestamp is the projection's
    // `entry.published_at` (ADR 0026 §9.1 invariant I-2 — the projector
    // parsed `time[<version>]` into it), captured **before** the
    // `coalesce_blob` closure consumes ownership of dependent state.
    // Best-effort: missing / unparseable → `None`, never an ingest
    // failure.
    let upstream_published_at = entry.published_at;
    // Capture the serving mapping's per-upstream opt-in
    // (`trust_upstream_publish_time`) **before** the `coalesce_blob`
    // closure consumes `mapping`. Threaded into `VerifiedIngestRequest`
    // so `ingest_inner` can gate the publish-anchored quarantine
    // resolution on it.
    let blob_trust_publish_time = mapping.trust_upstream_publish_time;
    let blob_proxy = ctx.upstream_proxy.clone();
    let blob_mapping = mapping.clone();
    let blob_tarball_url = tarball_url;
    let blob_ingest = ctx.ingest_use_case.clone();
    let blob_repo_id = repo.id;
    // F-14: keep a clone for the cross-repo follower-registration
    // fallback below (the closure consumes `blob_coords`).
    let follower_coords = coords.clone();
    let blob_coords = coords;
    let blob_upstream_checksum = upstream_checksum;
    let blob_handler = handler;
    let coalesce_blob_result = ctx
        .pull_dedup
        .coalesce_blob(blob_dedup_key, move || async move {
            // `fetch_artifact` returns an `ArtifactFetch` envelope;
            // extract `stream`. The `upstream_published_at` was derived
            // from the packument body's `time[<version>]` field (see
            // above); the response header's `Last-Modified` is captured
            // by the adapter for symmetry but not consumed here.
            let fetch = blob_proxy
                .fetch_artifact(blob_mapping, blob_tarball_url)
                .await
                .map_err(AppError::from)?;
            let reader: Box<dyn AsyncRead + Send + Unpin> =
                Box::new(StreamReader::new(fetch.stream));
            let request = VerifiedIngestRequest::UpstreamPublished {
                repository_id: blob_repo_id,
                coords: blob_coords,
                // npm tarballs are gzipped tar (.tgz). The publish path uses
                // the same string, so direct + proxied artifacts share a row
                // shape.
                content_type: "application/octet-stream".to_string(),
                // Server-initiated ingest: the system-actor sentinel
                // (Uuid::nil) is the established convention from OCI / Cargo /
                // PyPI pull-through (see `actor_to_uploaded_by` in
                // `hort_app::use_cases::ingest_use_case`).
                actor: ApiActor {
                    user_id: Uuid::nil(),
                },
                payload_metadata: serde_json::Value::Null,
                upstream_checksum: blob_upstream_checksum,
                // Packument `time[<version>]`, best-effort.
                upstream_published_at,
                // Serving mapping's per-upstream opt-in.
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
        // leader-only-discrimination contract (§4).
        Err(AppError::Domain(DomainError::Conflict(msg))) => {
            // Audit invariant (design doc §13): the mismatch warn carries
            // `algorithm`, `format`, `repository_id` so an operator can
            // correlate it with the corresponding `ChecksumMismatch` event
            // on the repository stream. NEVER `artifact_id` — no Artifact
            // row was minted on the mismatch path (mint-after-verify).
            tracing::warn!(
                conflict = %msg,
                format = "npm",
                repository_id = %repo.id,
                algorithm = "sha512",
                "npm upstream checksum mismatch",
            );
            return Err(UpstreamPullError::ChecksumMismatch);
        }
        Err(e) => {
            // `fetch_artifact` errors and any other ingest-time
            // infrastructure failure converge here. The original
            // pre-coalesce code split `fetch_artifact` failures into
            // `UpstreamUnavailable`; preserve that by string-matching
            // the wrapped error message — the upstream HTTP adapter
            // prefixes its errors with "upstream:" (see
            // `MockUpstreamProxy::fetch_artifact` and the production
            // `UpstreamHttpAdapter`).
            let msg = e.to_string();
            if msg.contains("upstream:") || msg.contains("upstream ") {
                tracing::warn!(
                    cause = %e,
                    format = "npm",
                    repository_id = %repo.id,
                    leg = "tarball",
                    "npm upstream tarball fetch failed",
                );
                return Err(UpstreamPullError::UpstreamUnavailable { cause: msg });
            }
            tracing::warn!(
                cause = %e,
                format = "npm",
                repository_id = %repo.id,
                "npm upstream ingest failed",
            );
            return Err(UpstreamPullError::IngestFailed { cause: msg });
        }
    };

    // Post-coalesce read: both leader and follower re-resolve the
    // artifact row by content hash. The leader's `ingest_verified`
    // (inside the closure) wrote the row; the follower reads it.
    //
    // F-14 (ADR 0007): `blob_by_hash` is cross-repo, so a follower
    // that joined a window whose leader ingested into a DIFFERENT repo
    // has no row in `repo.id`. On `None` the follower idempotently
    // registers its OWN per-repo row via `register_existing_cas_blob`
    // (content already CAS-present + verified; no re-fetch, no
    // re-`storage.put`; same `ArtifactIngested` event the leader's
    // cross-repo dedup emits).
    let artifact = match ctx
        .artifact_use_case
        .find_in_repo_by_hash(repo.id, &content_hash)
        .await
        .map_err(|e| UpstreamPullError::IngestFailed {
            cause: e.to_string(),
        })? {
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
                        payload_metadata: serde_json::Value::Null,
                        content_hash: content_hash.clone(),
                        // Upstream pull is not a seed-import cutover;
                        // quarantine is policy-driven through the primary
                        // `ingest_verified` path.
                        seed_import_quarantine_anchor: None,
                    },
                    &NpmFormatHandler,
                )
                .await
                .map_err(|e| UpstreamPullError::IngestFailed {
                    cause: e.to_string(),
                })?
                .artifact
        }
    };

    tracing::info!(
        algorithm = "sha512",
        artifact_id = %artifact.id,
        "npm upstream pull-through completed; ChecksumVerified emitted",
    );
    Ok(artifact)
}

/// Recover the upstream SHA-512 [`UpstreamPublishedChecksum`] from a
/// projection [`NpmVersionEntry`]'s verbatim `dist.integrity` SRI
/// (`entry.integrity`).
///
/// Recover the upstream SHA-512 [`UpstreamPublishedChecksum`] from a
/// projection [`NpmVersionEntry`]'s verbatim `dist.integrity` SRI.
///
/// To keep the SHA-512 SRI-decode + length/hex validation
/// **byte-identical** (and NOT duplicate that security-critical logic),
/// this drives the SAME audited [`NpmFormatHandler::parse_upstream_checksum`]
/// path against a minimal synthetic packument body that contains only the
/// requested version's `dist.integrity` — the only field that path reads
/// for the checksum. A missing integrity yields a body whose
/// `dist.integrity` is absent, so the handler returns the same
/// "publishes no dist.integrity" `Validation` the raw parser produced;
/// a malformed SRI returns the same decode-failure `Validation`.
fn checksum_from_entry(
    handler: &NpmFormatHandler,
    entry: &NpmVersionEntry,
    coords: &ArtifactCoords,
) -> DomainResult<UpstreamPublishedChecksum> {
    let version = coords.version.as_deref().unwrap_or_default();
    // Minimal body holding only `versions[version].dist.integrity` — the
    // exact (and only) field `parse_upstream_checksum` reads. Built via
    // `serde_json` so the integrity string is escaped correctly.
    let dist = match entry.integrity.as_deref() {
        Some(sri) => serde_json::json!({ "integrity": sri }),
        None => serde_json::json!({}),
    };
    let body = serde_json::json!({
        "versions": { version: { "dist": dist } }
    });
    let bytes = serde_json::to_vec(&body)
        .map_err(|e| DomainError::Invariant(format!("npm synthetic body serialize: {e}")))?;
    // `parse_upstream_checksum` takes a streaming reader; the synthetic
    // body is tiny, so a cursor over the in-memory bytes satisfies the
    // port without behaviour change.
    handler.parse_upstream_checksum(&mut std::io::Cursor::new(&bytes), coords)
}

/// Recover the genuine upstream tarball URL from a projection
/// [`NpmVersionEntry`]'s verbatim `dist.tarball` (`entry.tarball`),
/// applying the SAME `https://` guard `extract_upstream_tarball_url`
/// enforced (no downgrade target is ever promoted to a fetch URL).
///
/// `entry.tarball` is the genuine upstream URL captured by the
/// projector before any serve-time rewrite (ADR 0026 §9.1 invariant
/// I-1 / F11). A missing URL → the same "missing dist.tarball"
/// `Validation` the raw parser produced.
fn tarball_url_from_entry(entry: &NpmVersionEntry, version: &str) -> DomainResult<String> {
    let tarball = entry.tarball.as_deref().ok_or_else(|| {
        DomainError::Validation(format!(
            "upstream npm version {version} is missing dist.tarball"
        ))
    })?;
    if !tarball.starts_with("https://") {
        return Err(DomainError::Validation(format!(
            "upstream npm returned non-https tarball URL: {tarball}"
        )));
    }
    Ok(tarball.to_string())
}

// The local `url_encode_npm_name` helper was retired: the packument is
// resolved through `crate::packument::fetch_raw_with_cache`, which owns
// the cache-key / mirror-key encoding. The encoding contract is pinned
// by that module's tests; the tarball-pull no longer computes a cache
// key itself.

/// Extract the basename (filename segment) of a tarball URL.
///
/// Strips a `?` or `#` suffix first (npm registries don't use them
/// today, but the rule must survive a future change), then returns the
/// segment after the final `/`. If the URL has no `/`, the entire
/// string is returned (defensive — `extract_upstream_tarball_url`
/// already enforces `https://` so this branch is unreachable in
/// practice). Returns a `Cow` so the common case (URL contains `/`)
/// avoids an allocation; the trim case allocates once.
fn tarball_basename(url: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = match url.find(['?', '#']) {
        Some(idx) => &url[..idx],
        None => url,
    };
    match trimmed.rsplit_once('/') {
        Some((_, basename)) => std::borrow::Cow::Borrowed(basename),
        None => std::borrow::Cow::Borrowed(trimmed),
    }
}

/// Render an [`UpstreamPullError`] as the canonical wire response.
///
/// Mapping (mirrors PyPI's `crates/hort-http-pypi/src/upstream_pull.rs::
/// map_upstream_pull_error` where the variant overlaps; the npm-specific
/// `FilenameMismatch` and `TarballUrlInvalid` slot in alongside):
///
/// | Variant | Status | `X-Hort-Reason` |
/// |---|---|---|
/// | `NoUpstream` | 404 | — |
/// | `UpstreamUnavailable` | 502 | `upstream-unavailable` |
/// | `MetadataMalformed` | 502 | `upstream-metadata-malformed` |
/// | `TarballUrlInvalid` | 502 | `upstream-metadata-malformed` |
/// | `FilenameMismatch` | 502 | `upstream-filename-mismatch` |
/// | `ChecksumMismatch` | 502 | `upstream-checksum-mismatch` |
/// | `IngestFailed` | 500 | — |
/// | `Internal` | 500 | — |
///
/// Notes:
///
/// - `TarballUrlInvalid` shares the `upstream-metadata-malformed` reason
///   with `MetadataMalformed`: from an observability standpoint both are
///   "the upstream returned bytes the format handler couldn't fully
///   resolve into a tarball pointer". The orchestrator keeps the
///   variants distinct because the underlying parsers are independent
///   (Item 2 design note); the wire-map collapses them because
///   downstream alerting groups them together.
/// - The body shape (`{"error": "..."}`, `application/json`) mirrors
///   the existing PyPI / Cargo wire-maps so client-side logging stays
///   uniform across the success / quarantine / pull-through branches.
/// - `Internal` and `IngestFailed` return short stable strings — never
///   the inner message — to match the `ApiError::Repository` /
///   `ApiError::Storage` / `ApiError::EventStore` sanitisation
///   contract in `hort_http_core::error`.
pub(crate) fn map_upstream_pull_error(e: &UpstreamPullError) -> Response {
    match e {
        UpstreamPullError::NoUpstream => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"error": "package not found"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::UpstreamUnavailable { .. } => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .header("X-Hort-Reason", "upstream-unavailable")
            .body(Body::from(
                serde_json::json!({"error": "upstream unavailable"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::MetadataMalformed { .. }
        | UpstreamPullError::TarballUrlInvalid { .. } => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .header("X-Hort-Reason", "upstream-metadata-malformed")
            .body(Body::from(
                serde_json::json!({"error": "upstream metadata invalid"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::FilenameMismatch { .. } => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .header("X-Hort-Reason", "upstream-filename-mismatch")
            .body(Body::from(
                serde_json::json!({"error": "upstream tarball filename mismatch"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::ChecksumMismatch => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .header("X-Hort-Reason", "upstream-checksum-mismatch")
            .body(Body::from(
                serde_json::json!({"error": "upstream tampering detected"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::IngestFailed { .. } => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"error": "ingest failed"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::Internal { .. } => Response::builder()
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
    use base64::Engine as _;
    use bytes::Bytes;
    use chrono::Utc;
    use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
    use sha2::{Digest, Sha512};
    use uuid::Uuid;

    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{Repository, RepositoryFormat, RepositoryType};
    use hort_domain::error::DomainError;
    use hort_domain::events::{DomainEvent, StreamCategory, StreamId};
    use hort_domain::ports::ephemeral_store::EphemeralStore;
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    use hort_domain::types::checksum::HashAlgorithm;
    use hort_http_core::test_support::{build_mock_ctx, MockPorts};

    use super::*;

    fn handle() -> PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    /// `sample_repository` defaults to `Hosted`; promote to `Proxy` so
    /// the orchestrator's `Repository`-shape expectations are realistic
    /// (the field is read for tracing only, but matching production
    /// keeps the test fixture honest).
    fn npm_proxy_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Npm;
        r.repo_type = RepositoryType::Proxy;
        r.upstream_url = Some("https://registry.npmjs.org".into());
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

    /// Compute an SRI string of the form `sha512-<base64>` for the
    /// given bytes. Used to build packument fixtures whose
    /// `dist.integrity` agrees with whatever bytes the artifact-mock
    /// will serve.
    fn sri_sha512(content: &[u8]) -> String {
        let digest = Sha512::digest(content);
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        format!("sha512-{b64}")
    }

    /// Minimal npm packument keyed on `(version, integrity, tarball)`.
    /// Trimmed to the shape `parse_upstream_checksum` and
    /// `extract_upstream_tarball_url` consume.
    fn packument_json(version: &str, integrity: &str, tarball: &str) -> Vec<u8> {
        format!(
            r#"{{"versions":{{"{version}":{{"name":"x","version":"{version}","dist":{{"integrity":"{integrity}","tarball":"{tarball}"}}}}}}}}"#,
        )
        .into_bytes()
    }

    /// Packument with only `dist.shasum` (no `dist.integrity`) — drives
    /// the `MetadataMalformed` legacy path.
    fn packument_legacy_shasum_only(version: &str, tarball: &str, shasum: &str) -> Vec<u8> {
        format!(
            r#"{{"versions":{{"{version}":{{"name":"x","version":"{version}","dist":{{"shasum":"{shasum}","tarball":"{tarball}"}}}}}}}}"#,
        )
        .into_bytes()
    }

    /// Pre-seed a **projection** cache entry by projecting `body` and
    /// storing the `CachedNpmProjection` frame under
    /// `npm_packument_proj:{mapping}:{encoded_name}` — the shape
    /// `try_upstream_tarball_pull` (via `fetch_raw_with_cache`) reads on
    /// a fresh cache hit. Strictly fresh (`fetched_at = now`).
    async fn seed_cache_envelope(
        mocks: &MockPorts,
        mapping_id: Uuid,
        encoded_name: &str,
        body: &[u8],
    ) {
        use crate::packument::CachedNpmProjection;
        use hort_domain::ports::upstream_proxy::MetadataProjector;
        use hort_formats::npm::projection::NpmPackumentProjector;
        let projection = NpmPackumentProjector::new(2 * 1024 * 1024)
            .project(std::io::Cursor::new(body))
            .expect("seed body must project");
        let entry = CachedNpmProjection::from_projection(projection);
        let key = format!("npm_packument_proj:{mapping_id}:{encoded_name}");
        mocks
            .ephemeral_evictable
            .put(&key, entry.encode(), std::time::Duration::from_secs(3600))
            .await
            .unwrap();
    }

    // The `url_encode_npm_name` pinning tests moved out: this module no
    // longer owns the cache/mirror-key encoding (it resolves the
    // packument through `crate::packument::fetch_raw_with_cache`). The
    // encoding contract is pinned by that module's tests.

    // ---- tarball_basename pinning -------------------------------------------

    #[test]
    fn tarball_basename_extracts_last_segment() {
        assert_eq!(
            tarball_basename("https://registry.npmjs.org/express/-/express-4.18.2.tgz"),
            "express-4.18.2.tgz"
        );
    }

    #[test]
    fn tarball_basename_strips_query_string() {
        assert_eq!(
            tarball_basename("https://example.com/path/foo-1.0.0.tgz?token=abc"),
            "foo-1.0.0.tgz"
        );
    }

    #[test]
    fn tarball_basename_strips_fragment() {
        assert_eq!(
            tarball_basename("https://example.com/path/foo-1.0.0.tgz#frag"),
            "foo-1.0.0.tgz"
        );
    }

    // The `extract_upstream_publish_time` unit tests moved out:
    // `time[<version>]` parsing now lives in the projector
    // (`hort_formats::npm::projection`), where a dedicated test pins
    // the same contract. The tarball-pull reads the parsed value off
    // `NpmVersionEntry::published_at`.

    // ---- Branch 1: no mapping -----------------------------------------------

    #[tokio::test]
    async fn try_upstream_tarball_pull_no_upstream_repo_returns_no_upstream() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());

        let err = try_upstream_tarball_pull(&ctx, &repo, "express", "4.18.2", "express-4.18.2.tgz")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::NoUpstream),
            "expected NoUpstream, got {err:?}"
        );
    }

    // ---- Branch 2: 5xx during metadata fetch --------------------------------

    #[tokio::test]
    async fn try_upstream_tarball_pull_upstream_5xx_during_metadata_fetch_returns_unavailable() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        // No metadata seeded → fetch_metadata returns the mock's
        // not_found Invariant. Inject a recognisable error to make the
        // assertion specific.
        mocks
            .upstream_proxy
            .fail_next_metadata_with(DomainError::Invariant("upstream:network:timeout".into()));

        let err = try_upstream_tarball_pull(&ctx, &repo, "express", "4.18.2", "express-4.18.2.tgz")
            .await
            .unwrap_err();

        match err {
            UpstreamPullError::UpstreamUnavailable { cause } => {
                assert!(cause.contains("upstream"), "unexpected cause: {cause}");
            }
            other => panic!("expected UpstreamUnavailable, got {other:?}"),
        }
    }

    // ---- Branch 3: legacy packument (no integrity) → MetadataMalformed ------

    #[tokio::test]
    async fn try_upstream_tarball_pull_legacy_no_integrity_returns_metadata_malformed() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        // Packument with only dist.shasum (SHA-1) — the format
        // handler rejects (design doc §16: SHA-1 fallback NOT
        // accepted).
        let body = packument_legacy_shasum_only(
            "1.0.0",
            "https://registry.npmjs.org/legacy/-/legacy-1.0.0.tgz",
            "0123456789abcdef0123456789abcdef01234567",
        );
        mocks.upstream_proxy.insert_metadata("", "/legacy", body);

        // No artifact seed and no fail_next_artifact_with — the test
        // proves the short-circuit by getting MetadataMalformed before
        // any tarball fetch.
        let err = try_upstream_tarball_pull(&ctx, &repo, "legacy", "1.0.0", "legacy-1.0.0.tgz")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::MetadataMalformed { .. }),
            "expected MetadataMalformed, got {err:?}"
        );
    }

    // ---- Branch 4: 5xx during tarball fetch ---------------------------------

    #[tokio::test]
    async fn try_upstream_tarball_pull_upstream_5xx_during_tarball_fetch_returns_unavailable() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let bytes = b"the actual tarball body".to_vec();
        let sri = sri_sha512(&bytes);
        let url = "https://registry.npmjs.org/express/-/express-4.18.2.tgz";
        let body = packument_json("4.18.2", &sri, url);
        mocks.upstream_proxy.insert_metadata("", "/express", body);
        // No insert_artifact → fetch_artifact returns the mock's
        // not_found Invariant. We expect that to surface as
        // UpstreamUnavailable (not Internal — the error originates
        // from the upstream port, not our own logic).

        let err = try_upstream_tarball_pull(&ctx, &repo, "express", "4.18.2", "express-4.18.2.tgz")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::UpstreamUnavailable { .. }),
            "expected UpstreamUnavailable, got {err:?}"
        );
    }

    // ---- Branch 5: filename mismatch short-circuits before artifact fetch ---

    #[tokio::test]
    async fn try_upstream_tarball_pull_filename_mismatch_short_circuits_before_artifact_fetch() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let bytes = b"unused".to_vec();
        let sri = sri_sha512(&bytes);
        // The packument's `dist.tarball` filename ends in
        // `attacker-9.9.9.tgz`; the request filename is
        // `express-4.18.2.tgz`. The basename check must reject.
        let bad_url = "https://registry.npmjs.org/express/-/attacker-9.9.9.tgz";
        let body = packument_json("4.18.2", &sri, bad_url);
        mocks.upstream_proxy.insert_metadata("", "/express", body);

        // Inject a one-shot artifact failure with a recognisable
        // marker. If the fetch_artifact path were reached, the orchestrator
        // would return UpstreamUnavailable carrying this marker;
        // because the short-circuit fires first, the failure stays
        // un-consumed AND we get FilenameMismatch instead.
        mocks
            .upstream_proxy
            .fail_next_artifact_with(DomainError::Invariant(
                "MARKER:fetch_artifact_must_not_be_called".into(),
            ));

        let err = try_upstream_tarball_pull(&ctx, &repo, "express", "4.18.2", "express-4.18.2.tgz")
            .await
            .unwrap_err();

        match err {
            UpstreamPullError::FilenameMismatch { expected, actual } => {
                assert_eq!(expected, "express-4.18.2.tgz");
                assert_eq!(actual, "attacker-9.9.9.tgz");
            }
            UpstreamPullError::UpstreamUnavailable { cause } if cause.contains("MARKER") => {
                panic!(
                    "fetch_artifact was called even though the basename did not match — \
                     short-circuit broken: {cause}"
                );
            }
            other => panic!("expected FilenameMismatch, got {other:?}"),
        }
    }

    // ---- Branch 6: ingest_verified returns Conflict (mismatch) --------------

    /// Asserts that the stream-wrapping in `ingest_verified` actually
    /// computes SHA-512 (not SHA-256). The packument advertises one
    /// SHA-512; the upstream proxy serves bytes whose SHA-512 differs.
    /// The use case must rehash the streamed bytes with
    /// `Sha512HashingRead`, detect the mismatch, and return Conflict —
    /// surfaced here as `ChecksumMismatch`. The repository-stream
    /// `ChecksumMismatch` event must carry
    /// `algorithm = HashAlgorithm::Sha512` (proves the wrapping was
    /// Sha512, not Sha256). This is the load-bearing SHA-512
    /// verification test (ADR 0006).
    #[tokio::test]
    async fn try_upstream_tarball_pull_tampered_emits_repository_mismatch_with_sha512_algorithm() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let actual_bytes = b"actual-bytes".to_vec();
        // The packument lies: it advertises the SHA-512 of `lying-bytes`,
        // but the proxy serves `actual-bytes`. The use case rehashes
        // and detects.
        let lying_sri = sri_sha512(b"lying-bytes");
        let url = "https://registry.npmjs.org/express/-/express-4.18.2.tgz";
        let body = packument_json("4.18.2", &lying_sri, url);
        mocks.upstream_proxy.insert_metadata("", "/express", body);
        mocks
            .upstream_proxy
            .insert_artifact("", url, actual_bytes.clone());

        let err = try_upstream_tarball_pull(&ctx, &repo, "express", "4.18.2", "express-4.18.2.tgz")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::ChecksumMismatch),
            "expected ChecksumMismatch, got {err:?}"
        );

        // Inspect the repository-stream events: the mismatch must
        // land there (mint-after-verify keeps the artifact stream
        // unborn) AND the algorithm must be Sha512 — proves the
        // stream was wrapped in Sha512HashingRead, not Sha256.
        let batches = mocks.events.appended_batches();
        let mismatch_events: Vec<_> = batches
            .iter()
            .filter(|b| b.stream_id.category == StreamCategory::Repository)
            .flat_map(|b| b.events.iter())
            .filter_map(|e| match &e.event {
                DomainEvent::ChecksumMismatch(m) => Some(m.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            mismatch_events.len(),
            1,
            "exactly one ChecksumMismatch must land on the repository stream"
        );
        let mm = &mismatch_events[0];
        assert_eq!(
            mm.algorithm,
            HashAlgorithm::Sha512,
            "ChecksumMismatch must carry algorithm=Sha512 — proves Sha512HashingRead wrapped the stream"
        );
        assert_eq!(mm.format, "npm");
        assert_eq!(mm.repository_id, repo.id);

        // No ChecksumVerified must fire on the mismatch path.
        let verified_count = batches
            .iter()
            .flat_map(|b| b.events.iter())
            .filter(|e| matches!(e.event, DomainEvent::ChecksumVerified(_)))
            .count();
        assert_eq!(
            verified_count, 0,
            "ChecksumVerified must NOT fire on the mismatch path"
        );
    }

    // ---- Branch 7: happy path — verified ingest -----------------------------

    #[tokio::test]
    async fn try_upstream_tarball_pull_success_emits_verified_event() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let bytes = b"the actual express 4.18.2 tarball".to_vec();
        let sri = sri_sha512(&bytes);
        let url = "https://registry.npmjs.org/express/-/express-4.18.2.tgz";
        let body = packument_json("4.18.2", &sri, url);
        mocks.upstream_proxy.insert_metadata("", "/express", body);
        mocks.upstream_proxy.insert_artifact("", url, bytes.clone());

        let artifact =
            try_upstream_tarball_pull(&ctx, &repo, "express", "4.18.2", "express-4.18.2.tgz")
                .await
                .expect("happy path must succeed");

        assert_eq!(artifact.name, "express");
        assert_eq!(artifact.version.as_deref(), Some("4.18.2"));
        assert_eq!(artifact.size_bytes as usize, bytes.len());

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

        // No ChecksumMismatch on the success path — anywhere.
        let mismatch_count = transitions
            .iter()
            .flat_map(|(_a, ev, _m)| ev.events.iter())
            .filter(|e| matches!(e.event, DomainEvent::ChecksumMismatch(_)))
            .count();
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

    // ---- Branch 8: cached packument bypasses upstream metadata fetch -------

    /// Item 3 owns the cache write semantics; this orchestrator is a
    /// read-only consumer. Pre-seed an envelope, then assert the
    /// happy path completes without seeding any upstream metadata.
    /// The mock's `fetch_metadata` returns a not_found Invariant when
    /// no fixture is present — the only way this test passes is if
    /// `fetch_metadata` is never called.
    #[tokio::test]
    async fn try_upstream_tarball_pull_uses_cached_packument_when_present() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        let bytes = b"cached-path tarball body".to_vec();
        let sri = sri_sha512(&bytes);
        let url = "https://registry.npmjs.org/cached/-/cached-1.0.0.tgz";
        let body = packument_json("1.0.0", &sri, url);
        seed_cache_envelope(&mocks, mapping_id, "cached", &body).await;

        // No insert_metadata for `/cached` — if the orchestrator
        // bypasses the cache, fetch_metadata will return a not_found
        // Invariant and the test will fail with UpstreamUnavailable.
        // Inject a one-shot failure as a tripwire — it would fire
        // only if fetch_metadata is called.
        mocks
            .upstream_proxy
            .fail_next_metadata_with(DomainError::Invariant(
                "MARKER:fetch_metadata_must_not_be_called".into(),
            ));
        mocks.upstream_proxy.insert_artifact("", url, bytes.clone());

        let artifact =
            try_upstream_tarball_pull(&ctx, &repo, "cached", "1.0.0", "cached-1.0.0.tgz")
                .await
                .expect("cached-path happy path must succeed");
        assert_eq!(artifact.name, "cached");
        // F11 regression-companion: the orchestrator fetched the
        // *upstream* host, proven structurally — the `fetch_artifact`
        // mock keys on the literal `url`
        // (`https://registry.npmjs.org/...`), so the ingest succeeding
        // above is only reachable if the orchestrator extracted the
        // genuine upstream `dist.tarball` from the raw cached body. A
        // rewritten local URL would miss the mock and fail the fetch.
    }

    // ---- Branch 8b: F11 regression — writer→reader contract seam -----------

    /// **F11 regression test** — the headline.
    ///
    /// Drives the *real packument writer* (`packument::fetch_raw_with_cache`)
    /// then the *real tarball reader* (`try_upstream_tarball_pull`) — NOT
    /// a hand-seeded cache. A hand-seeded raw cache is green pre-fix and
    /// does not exercise the Item-3 ↔ Item-4 contract seam (the
    /// `:1156` test proves that). This test populates the cache the way
    /// production does: an `npm install` GETs the packument first
    /// (`fetch_raw_with_cache` writes the cache), then GETs the tarball
    /// within the cache window (`try_upstream_tarball_pull` reads it).
    ///
    /// Pre-fix (rewrite-before-cache): the writer cached the *rewritten*
    /// `http://localhost/npm/...` body; the reader fed that local URL to
    /// `extract_upstream_tarball_url`, whose `https://` guard rejected it
    /// → `TarballUrlInvalid` → 502. **RED.**
    ///
    /// Post-fix (Option B — cache raw, rewrite on serve): the writer
    /// caches the raw upstream body; the reader gets the genuine
    /// `https://registry.npmjs.org/...` URL → ingest succeeds. **GREEN.**
    #[tokio::test]
    async fn f11_regression_packument_writer_then_tarball_reader_pulls_through() {
        use crate::packument::fetch_raw_with_cache;

        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // The tarball bytes the upstream serves; the packument's
        // `dist.integrity` must agree (the verified-ingest rehash
        // protects the tarball — that defence is unchanged by F11).
        let tarball_bytes = b"the real lodash 4.17.21 tarball bytes".to_vec();
        let sri = sri_sha512(&tarball_bytes);
        let upstream_url = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
        let packument = packument_json("4.17.21", &sri, upstream_url);

        // Upstream serves both the packument metadata and the tarball.
        mocks
            .upstream_proxy
            .insert_metadata("", "/lodash", packument);
        mocks
            .upstream_proxy
            .insert_artifact("", upstream_url, tarball_bytes.clone());

        // Step 1: the packument GET — the real writer streams the body
        // through the projector, mirrors the raw, and caches the
        // PROJECTION. The projection's `versions[].tarball` is the
        // genuine upstream `https://registry.npmjs.org/...` URL (captured
        // verbatim before any serve-time rewrite).
        let _served = fetch_raw_with_cache(
            ctx.upstream_resolver.as_ref(),
            ctx.ephemeral_evictable.as_ref(),
            ctx.upstream_proxy.as_ref(),
            ctx.pull_dedup.as_ref(),
            Some(ctx.metadata_mirror.as_ref()),
            ctx.upstream_projector_version_object_max_bytes,
            &repo,
            "lodash",
        )
        .await
        .expect("packument fetch_raw_with_cache must succeed");

        // F11 acceptance — the writer cached the projection AND mirrored
        // the raw body under the shared mirror key, so the reader below
        // can resolve the genuine upstream URL from EITHER. Assert the
        // mirror holds exactly the package's raw body under the
        // format-scoped key Tasks 7-9 must match.
        let expected_mirror_key = hort_domain::ports::metadata_mirror_store::mirror_key(
            "npm",
            &mapping_id.to_string(),
            "lodash",
        );
        assert!(
            mocks.metadata_mirror.keys().contains(&expected_mirror_key),
            "F11: the raw body must be mirrored under {expected_mirror_key}; got {:?}",
            mocks.metadata_mirror.keys()
        );

        // Step 2: the tarball GET — the real reader consumes the
        // projection cache the writer just populated, recovering the
        // genuine upstream `dist.tarball` from `entry.tarball`. A
        // rewritten local URL would miss the `fetch_artifact` mock (keyed
        // on the literal upstream URL) and fail the fetch.
        let artifact = try_upstream_tarball_pull(
            &ctx,
            &repo,
            "lodash",
            "4.17.21",
            "lodash-4.17.21.tgz",
        )
        .await
        .expect(
            "F11: tarball pull-through must succeed — the cached projection must carry the \
             genuine upstream `dist.tarball` URL + verbatim `dist.integrity` SRI",
        );

        assert_eq!(artifact.name, "lodash");
        assert_eq!(artifact.version.as_deref(), Some("4.17.21"));
        assert_eq!(artifact.size_bytes as usize, tarball_bytes.len());
    }

    // ---- Branch 9: scoped package URL encoding ------------------------------

    /// Scoped packages encode their `/` as `%2f` in the metadata
    /// fetch path — `@types/node` → `/@types%2fnode`. The mock keys
    /// on the literal path string, so this test pins the encoding
    /// exactly: if the orchestrator emits the wrong shape, the
    /// fixture won't match and fetch_metadata will return not_found.
    #[tokio::test]
    async fn try_upstream_tarball_pull_scoped_package_url_encoding() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let bytes = b"scoped tarball body".to_vec();
        let sri = sri_sha512(&bytes);
        let url = "https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz";
        let body = packument_json("20.0.0", &sri, url);
        // The expected upstream metadata path is /@types%2fnode (the
        // %2f is lowercase per the npm registry convention pinned by
        // url_encode_npm_name).
        mocks
            .upstream_proxy
            .insert_metadata("", "/@types%2fnode", body);
        mocks.upstream_proxy.insert_artifact("", url, bytes.clone());

        let artifact =
            try_upstream_tarball_pull(&ctx, &repo, "@types/node", "20.0.0", "node-20.0.0.tgz")
                .await
                .expect("scoped happy path must succeed");
        assert_eq!(artifact.name, "@types/node");
    }

    // ---- Branch 10: integrity present but dist.tarball missing -------------

    /// `parse_upstream_checksum` succeeds (dist.integrity is valid), but
    /// `extract_upstream_tarball_url` rejects because `dist.tarball` is
    /// absent. Exercises the `TarballUrlInvalid` arm — distinct from
    /// `MetadataMalformed` because the URL helper is run *after* the
    /// checksum parser succeeds.
    #[tokio::test]
    async fn try_upstream_tarball_pull_missing_dist_tarball_returns_tarball_url_invalid() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        // dist.integrity present (valid SHA-512 SRI), dist.tarball absent.
        let sri = sri_sha512(b"unused");
        let body = format!(
            r#"{{"versions":{{"1.0.0":{{"name":"x","version":"1.0.0","dist":{{"integrity":"{sri}"}}}}}}}}"#,
        )
        .into_bytes();
        mocks.upstream_proxy.insert_metadata("", "/x", body);

        let err = try_upstream_tarball_pull(&ctx, &repo, "x", "1.0.0", "x-1.0.0.tgz")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::TarballUrlInvalid { .. }),
            "expected TarballUrlInvalid, got {err:?}"
        );
    }

    // ---- Branch 11: ingest_verified internal error -> IngestFailed ---------

    /// Force `commit_transition` to fail with a non-Conflict error
    /// (event store unreachable). The use case rehashes successfully,
    /// then explodes at the lifecycle commit. The orchestrator must
    /// route this to `IngestFailed` (not `ChecksumMismatch`, not
    /// `Internal`) because it's an ingest-time infrastructure
    /// failure. Mirrors PyPI's
    /// `ingest_verified_internal_error_returns_ingest_failed`.
    #[tokio::test]
    async fn try_upstream_tarball_pull_ingest_internal_error_returns_ingest_failed() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let bytes = b"good tarball body".to_vec();
        let sri = sri_sha512(&bytes);
        let url = "https://registry.npmjs.org/express/-/express-4.18.2.tgz";
        let body = packument_json("4.18.2", &sri, url);
        mocks.upstream_proxy.insert_metadata("", "/express", body);
        mocks.upstream_proxy.insert_artifact("", url, bytes);

        // Force the lifecycle commit to fail. The use case rehashes
        // first (succeeds — bytes match), then attempts to commit and
        // explodes.
        mocks
            .lifecycle
            .fail_next_commit(DomainError::Invariant("event store unreachable".into()));

        let err = try_upstream_tarball_pull(&ctx, &repo, "express", "4.18.2", "express-4.18.2.tgz")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::IngestFailed { .. }),
            "expected IngestFailed, got {err:?}"
        );
    }

    // ---- Branch 12: cache envelope decode failure falls through to fetch ---

    /// A projection-cache row whose bytes are not a valid frame (e.g. a
    /// pre-amendment raw-body entry on a rolling deploy) must be treated
    /// as a miss + tracing warn — NOT a hard error. Guards against
    /// cache-poisoning wedging the proxy.
    #[tokio::test]
    async fn try_upstream_tarball_pull_cache_envelope_garbage_falls_through_to_fetch() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        let mapping_id = seed_mapping(&mocks, repo.id);

        // Seed garbage that isn't a valid projection frame under the
        // amendment's `npm_packument_proj:{mapping_id}:fallback` key.
        let key = format!("npm_packument_proj:{mapping_id}:fallback");
        mocks
            .ephemeral_evictable
            .put(
                &key,
                Bytes::from_static(b"this is not a valid envelope"),
                std::time::Duration::from_secs(60),
            )
            .await
            .unwrap();

        // Seed valid upstream metadata + artifact so the fallthrough
        // succeeds.
        let bytes = b"fallback tarball body".to_vec();
        let sri = sri_sha512(&bytes);
        let url = "https://registry.npmjs.org/fallback/-/fallback-1.0.0.tgz";
        let body = packument_json("1.0.0", &sri, url);
        mocks.upstream_proxy.insert_metadata("", "/fallback", body);
        mocks.upstream_proxy.insert_artifact("", url, bytes.clone());

        let artifact =
            try_upstream_tarball_pull(&ctx, &repo, "fallback", "1.0.0", "fallback-1.0.0.tgz")
                .await
                .expect("garbage cache row must fall through to fetch");
        assert_eq!(artifact.name, "fallback");
    }

    // ---- Item 6: audit invariant — exactly one ChecksumVerified -----------

    /// Every artifact ingested via `ingest_verified` has exactly one
    /// `ChecksumVerified` event in its stream — same append batch as
    /// `ArtifactIngested`. The npm pull-through path uses SHA-512
    /// (ADR 0006): the recorded event must carry
    /// `algorithm = HashAlgorithm::Sha512`, `artifact_id = artifact.id`,
    /// and `upstream_value == computed_value` (success path → both
    /// sides agree).
    ///
    /// Mirrors PyPI's `successful_pull_emits_exactly_one_checksum_verified_event`
    /// (`crates/hort-http-pypi/src/upstream_pull.rs`) with an extra layer of
    /// pinning on the SHA-512 algorithm + the upstream-vs-computed
    /// equality (the PyPI test only counts; this one inspects the event
    /// payload because the SHA-512 wrapping is the load-bearing 17.3
    /// invariant).
    #[tokio::test]
    async fn try_upstream_tarball_pull_success_emits_audit_invariant_checksum_verified_with_sha512()
    {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = npm_proxy_repo("npm-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let bytes = b"audit-invariant tarball body".to_vec();
        let sri = sri_sha512(&bytes);
        let url = "https://registry.npmjs.org/express/-/express-4.18.2.tgz";
        let body = packument_json("4.18.2", &sri, url);
        mocks.upstream_proxy.insert_metadata("", "/express", body);
        mocks.upstream_proxy.insert_artifact("", url, bytes.clone());

        let artifact =
            try_upstream_tarball_pull(&ctx, &repo, "express", "4.18.2", "express-4.18.2.tgz")
                .await
                .expect("happy path must succeed for the audit invariant");

        // The lifecycle port records ArtifactIngested + ChecksumVerified
        // atomically (see `hort_app::use_cases::ingest_use_case::ingest_verified`).
        // Filter to the artifact's stream and pull the typed payload.
        let artifact_stream = StreamId::artifact(artifact.id);
        let transitions = mocks.lifecycle.committed_transitions();
        let verified_events: Vec<_> = transitions
            .iter()
            .filter(|(_a, ev, _m)| ev.stream_id == artifact_stream)
            .flat_map(|(_a, ev, _m)| ev.events.iter())
            .filter_map(|e| match &e.event {
                DomainEvent::ChecksumVerified(v) => Some(v.clone()),
                _ => None,
            })
            .collect();

        assert_eq!(
            verified_events.len(),
            1,
            "exactly one ChecksumVerified must land on the artifact stream"
        );
        let verified = &verified_events[0];
        assert_eq!(
            verified.algorithm,
            HashAlgorithm::Sha512,
            "ChecksumVerified.algorithm must be Sha512 — proves Sha512HashingRead wrapped the stream"
        );
        assert_eq!(
            verified.artifact_id, artifact.id,
            "ChecksumVerified.artifact_id must match the minted artifact's id"
        );
        assert_eq!(
            verified.upstream_value, verified.computed_value,
            "success path → upstream and computed values must agree"
        );
    }

    // ---- Item 6: warn-capture for the security-sensitive branch ----------

    /// Design doc §13 + architect skill (Observability rule "tracing
    /// records what was attempted, including failures that never reach
    /// the event store"): the `ChecksumMismatch` branch is the
    /// security-sensitive site for the npm pull-through path. The warn
    /// must carry `algorithm`, `format`, and `repository_id`, and must
    /// NOT carry `artifact_id` (mint-after-verify — none was minted).
    /// This test installs a per-thread `CapturingLayer` and asserts the
    /// emitted `WARN` event mentions both the `algorithm = sha512` and
    /// `format = npm` fields.
    ///
    /// Uses the same `CapturingLayer` + `TRACING_TEST_MUTEX` +
    /// `install_global_passthrough_subscriber` idiom as
    /// `crates/hort-http-cargo/src/upstream_pull.rs::checksum_mismatch_emits_tracing_warn`.
    /// `#[test]` (not `#[tokio::test]`) because the mutex guard cannot
    /// cross an `await` point — a current-thread runtime drives the async
    /// call synchronously inside the guarded scope.
    #[test]
    fn try_upstream_tarball_pull_checksum_mismatch_emits_warn_with_algorithm_field() {
        use std::sync::OnceLock;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::Registry;

        use std::sync::{Arc, Mutex};

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

        // Seed the per-callsite cache once with `Interest::sometimes()`
        // so the per-thread `set_default` subscriber actually receives
        // events (see Cargo crate's analogous helper).
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let global_layer = CapturingLayer::default();
            let global_subscriber = Registry::default().with(global_layer);
            let _ = tracing::subscriber::set_global_default(global_subscriber);
        });

        // Serialise per-thread subscriber installation across tests in
        // this binary. The mutex guard does NOT cross an await point —
        // we drive the async call via `block_on` inside the guarded
        // scope.
        static TRACING_TEST_MUTEX: Mutex<()> = Mutex::new(());
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
            // Same mismatch fixture as
            // `try_upstream_tarball_pull_tampered_emits_repository_mismatch_with_sha512_algorithm`:
            // the packument lies about the SHA-512.
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = npm_proxy_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let actual_bytes = b"actual-bytes".to_vec();
            let lying_sri = sri_sha512(b"lying-bytes");
            let url = "https://registry.npmjs.org/express/-/express-4.18.2.tgz";
            let body = packument_json("4.18.2", &lying_sri, url);
            mocks.upstream_proxy.insert_metadata("", "/express", body);
            mocks
                .upstream_proxy
                .insert_artifact("", url, actual_bytes.clone());

            try_upstream_tarball_pull(&ctx, &repo, "express", "4.18.2", "express-4.18.2.tgz").await
        });

        assert!(
            matches!(result, Err(UpstreamPullError::ChecksumMismatch)),
            "expected ChecksumMismatch, got {result:?}"
        );

        let records = captured.lock().unwrap();
        // The mismatch warn must carry algorithm=sha512 and format=npm.
        // Both checks are conjunctive on the SAME warn event so we know
        // a single emission carries both fields (rather than two
        // unrelated warns satisfying the predicate disjointly).
        let mismatch_warn = records.iter().find(|(lvl, msg)| {
            *lvl == tracing::Level::WARN
                && msg.contains("npm upstream checksum mismatch")
                && msg.contains("algorithm=")
                && msg.contains("sha512")
                && msg.contains("format=")
                && msg.contains("npm")
        });
        assert!(
            mismatch_warn.is_some(),
            "expected WARN-level event mentioning the checksum mismatch with \
             algorithm=sha512 and format=npm; captured: {records:?}"
        );

        // Audit invariant defence-in-depth: the mismatch warn MUST NOT
        // carry `artifact_id` (mint-after-verify; no Artifact row was
        // minted). The warn message text would surface as
        // `artifact_id=...` in the captured visitor output.
        let leaked_artifact_id = records.iter().any(|(lvl, msg)| {
            *lvl == tracing::Level::WARN
                && msg.contains("npm upstream checksum mismatch")
                && msg.contains("artifact_id=")
        });
        assert!(
            !leaked_artifact_id,
            "checksum mismatch warn must NOT carry artifact_id (mint-after-verify); \
             captured: {records:?}"
        );
    }

    // ---- PullDedup wrap-coverage tests ------------------------------------
    //
    // These tests assert that the three wrapped call sites (packument
    // `fetch_metadata` in `crate::packument`, packument-via-pull
    // `fetch_metadata` here, and tarball `fetch_artifact`+
    // `ingest_verified` here) actually emit `hort_pull_dedup_total`
    // metrics — equivalent evidence to a per-method call-counter on
    // the mock proxy.
    //
    // The harness mirrors `crates/hort-app/src/pull_dedup.rs::tests::capture`:
    // install a `DebuggingRecorder` via `metrics::with_local_recorder`
    // around a `block_on` driving the async test body. Counter labels
    // are read back via `Snapshotter::snapshot` and matched on
    // `outcome`.

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
    /// for blob-by-hash keys.
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
    /// against the same npm tarball. The wrapped `coalesce_blob`
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
            let repo = npm_proxy_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            let bytes = b"the actual express 4.18.2 tarball".to_vec();
            let sri = sri_sha512(&bytes);
            let url = "https://registry.npmjs.org/express/-/express-4.18.2.tgz";
            let body = packument_json("4.18.2", &sri, url);
            mocks.upstream_proxy.insert_metadata("", "/express", body);
            mocks.upstream_proxy.insert_artifact("", url, bytes.clone());

            let ctx_a = ctx.clone();
            let repo_a = repo.clone();
            let h1 = tokio::spawn(async move {
                try_upstream_tarball_pull(
                    &ctx_a,
                    &repo_a,
                    "express",
                    "4.18.2",
                    "express-4.18.2.tgz",
                )
                .await
            });
            let ctx_b = ctx.clone();
            let repo_b = repo.clone();
            let h2 = tokio::spawn(async move {
                try_upstream_tarball_pull(
                    &ctx_b,
                    &repo_b,
                    "express",
                    "4.18.2",
                    "express-4.18.2.tgz",
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

        // The tarball blob fetch is the load-bearing wrap for this
        // test — the metadata leg (packument) ALSO coalesces, so
        // `leader_started` for the metadata leg may also fire. We
        // assert the BLOB leg coalesced by counting total
        // leader_started across all formats/layers — at least one
        // blob leader plus at most one metadata leader (packument).
        // The lower bound is `leader_started >= 1`; the follower
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

    /// Negative-cache test: the wrapped packument `fetch_metadata`
    /// fails (transport-level error via `fail_next_metadata_with`).
    /// The leader records the failure under the dedup key with the
    /// configured negative-cache TTL (default 30 s for `NotFound`).
    /// A second call within the TTL window must short-circuit on
    /// `negative_cache_hit` without firing a second `leader_started`.
    #[test]
    fn negative_cache_short_circuits_repeated_failures_within_ttl() {
        let snap = capture_metrics(|| async {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = npm_proxy_repo("npm-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id);

            // First call: stage a one-shot transport failure on the
            // next `fetch_metadata` (the packument fetch is the first
            // metadata call the orchestrator makes for the tarball
            // download path). The leader records `Failed` under the
            // packument dedup key.
            mocks
                .upstream_proxy
                .fail_next_metadata_with(DomainError::Invariant(
                    "upstream:not_found:packument".into(),
                ));
            let r1 =
                try_upstream_tarball_pull(&ctx, &repo, "express", "4.18.2", "express-4.18.2.tgz")
                    .await;
            assert!(
                matches!(r1, Err(UpstreamPullError::UpstreamUnavailable { .. })),
                "first call must fail with UpstreamUnavailable; got {r1:?}"
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
                try_upstream_tarball_pull(&ctx, &repo, "express", "4.18.2", "express-4.18.2.tgz")
                    .await;
            assert!(
                r2.is_err(),
                "second call must surface the cached failure; got {r2:?}"
            );
        });

        // Assertion: `negative_cache_hit` increments by ≥ 1 (the
        // second call short-circuited). `leader_started` for the
        // packument metadata key stays at 1 (only the FIRST call
        // elected; the second was a cache hit). The metric snapshot
        // is aggregated across the three wrapped call sites; the
        // first call only reaches the packument metadata fetch (it
        // errors before the tarball fetch), so `leader_started`
        // should be exactly 1 across the entire snapshot.
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
