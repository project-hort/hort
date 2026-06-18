//! OCI manifest pull.
//!
//! Wires `GET` + `HEAD /v2/<repo_key>/<name>/manifests/<reference>`.
//! Dispatch on `reference` shape: a `:` (digest form) resolves via
//! [`ArtifactRepository::find_by_path`] directly; anything else is a
//! tag that resolves through [`hort_app::use_cases::ref_use_case::RefUseCase::get`]
//! to a content hash, then the same path lookup.
//!
//!
//! ## `RefTarget::Version` invariant
//!
//! OCI tags are ALWAYS written as `RefTarget::ContentHash` by the
//! manifest PUT handler. A `RefTarget::Version(_)` on an OCI tag lookup is a
//! data-integrity bug (cross-format writer wrote into the shared
//! `mutable_refs` table with the wrong variant). The handler returns
//! `DomainError::Invariant` → 500 INTERNAL and logs the bug; hiding it
//! behind 404 would mask the problem and 400 would blame the client.
//!
//! The cross-format contamination guard is structural: `RefRegistryPort::find`
//! queries by `(repo, namespace, ref_name)`, so a non-OCI writer's
//! `Version` entry under a different `namespace` can't reach this code
//! path. The invariant check defends against the adapter returning the
//! wrong variant for THIS `(repo, name, tag)` only.
//!
//! ## Content negotiation
//!
//! `Accept` header must include the manifest's stored media-type (read
//! from `artifact_metadata.metadata.oci_media_type`, set at push time), `*/*`, or a `<type>/*` subtype-wildcard matching the media-
//! type's type half (e.g. `application/*`). A missing `Accept` header
//! is treated as `*/*` per RFC 9110 §12.5.1. Any other non-matching
//! type returns 406 `MANIFEST_UNKNOWN` with `detail.media_type`. The
//! backlog pins 406 over 404 so clients that hard-code a single
//! `Accept` back off gracefully instead of looping on 404.
//!
//! When the artifact has no metadata row (the artifact pre-dates
//! metadata population), the manifest is served with the default
//! `application/vnd.oci.image.manifest.v1+json` — the common case that
//! covers Docker-style single-image manifests.
//!
//! ## `IndexMode::ReleasedOnly` does NOT apply to OCI
//!
//! An OCI tag is an exact pointer, not a version range. The OCI
//! manifest serve path therefore MUST NOT consult
//! `Repository::index_mode` to filter or substitute the served
//! manifest — doing so re-introduces the `pending_target` /
//! deferred-move behaviour (silent substitution hides the quarantine
//! gate from operators). A quarantined manifest degrades to a visible
//! `503` via [`crate::quarantine::check_quarantine`]; that contract is
//! settled (see ADR 0016).
//!
//! Do NOT add a filter here without updating the architecture docs.
//! The
//! [`crate::prefetch::tests::oci_manifest_serve_path_must_not_consult_index_mode`]
//! test enforces this structurally — a regression that imports
//! `IndexMode` or reads `repo.index_mode` in this file is caught at
//! test time, not after a moved-tag pull has already returned a
//! stand-in manifest in production.

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::metrics::{emit_upstream_checksum, UpstreamChecksumResult};
use hort_app::pull_dedup::DedupKey;
use hort_app::use_cases::ingest_use_case::{RegisterExistingCasBlobRequest, VerifiedIngestRequest};
use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::mutable_ref::RefTarget;
use hort_domain::entities::repository::Repository;
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::types::ContentHash;
use hort_formats::oci::OciFormatHandler;

use super::coords::oci_manifest_coords;
use super::digest::{parse_digest, DigestParse};
use super::error::OciError;
use super::quarantine;
use hort_http_core::body::{stream_blob, DEFAULT_STREAM_CAPACITY};
use hort_http_core::context::AppContext;

/// Default OCI manifest media-type served when the artifact's metadata
/// row is absent or missing the `oci_media_type` field. Matches what
/// Docker clients expect for single-image manifests.
const DEFAULT_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// Serve an OCI manifest by `(repo_key, name, reference)`.
///
/// `reference` is a tag (no `:`) or a digest (`sha256:<hex>`). The
/// dispatcher hands off to this function after
/// [`super::tail::parse_tail`] produces `TailKind::Manifest`. `head =
/// true` strips the body but keeps the header set bit-identical.
pub(super) async fn serve(
    ctx: Arc<AppContext>,
    repo_key: &str,
    name: &str,
    reference: &str,
    headers: &HeaderMap,
    head: bool,
    actor: Option<&CallerPrincipal>,
) -> Response {
    // 1. Resolve + visibility-check repo through the use case.
    //    Missing OR invisible private repo collapses to NAME_UNKNOWN
    //    (anti-enumeration, ADR 0008).
    let repo = match ctx
        .repository_access_use_case
        .resolve(
            repo_key,
            actor,
            hort_app::use_cases::repository_access::AccessLevel::Read,
        )
        .await
    {
        Ok(r) => r,
        Err(AppError::Domain(DomainError::NotFound { .. })) => {
            return OciError::NameUnknown {
                repository: repo_key.to_string(),
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!(
                repo_key = %repo_key,
                error = %e,
                "repo lookup failed during OCI manifest pull"
            );
            return OciError::Internal.into_response();
        }
    };

    // 2. Resolve the manifest hash. Branch on reference shape:
    //    - digest (`sha256:<hex>`): parse, surface DIGEST_INVALID /
    //      UNSUPPORTED on parse failure (no pull-through can fix a
    //      malformed digest). The artifact lookup in step 3 may
    //      still try upstream pull-through if the digest parsed but
    //      no local artifact exists.
    //    - tag: look up via RefUseCase. Three outcomes:
    //        Resolved(hash) → continue with hash.
    //        NotFound       → try upstream pull-through (the new
    //                         path; mirror discovery flow).
    //        Failed(resp)   → surface verbatim. This carries the
    //                         RefTarget::Version 500 (data
    //                         integrity bug — must NOT be masked
    //                         behind a 404 from upstream pull).
    let (hash, prefetched_artifact) = if reference.contains(':') {
        match resolve_digest_reference(reference) {
            Ok(h) => (h, None),
            Err(e) => return *e,
        }
    } else {
        // Tag branch. Validate the tag against the OCI Distribution Spec
        // grammar `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}` BEFORE the
        // `RefUseCase::get` lookup or any upstream pull-through URL
        // construction. The digest branch above is already validated by
        // `parse_digest`; this is its tag-branch sibling. An out-of-grammar
        // tag is a malformed reference — 400 `MANIFEST_INVALID` via the
        // shared `tag_invalid_response` (the same mapping the PUT / DELETE
        // tag branches use); the reason never echoes the offending bytes
        // (log-injection defence; mirrors `validate_oci_name`).
        if let Err(e) = super::tag::validate_oci_tag(reference) {
            return super::tag_invalid_response(e);
        }
        match resolve_tag_reference(&ctx, &repo.id, name, reference).await {
            TagResolveOutcome::Resolved(h) => (h, None),
            TagResolveOutcome::Failed(resp) => return *resp,
            TagResolveOutcome::NotFound => {
                // Tag missing locally → try the upstream.
                match try_upstream_manifest_pull(
                    &ctx,
                    &repo,
                    name,
                    reference,
                    accept_values(headers),
                )
                .await
                {
                    UpstreamManifestPullOutcome::Ingested { artifact, hash, .. } => {
                        (hash, Some(artifact))
                    }
                    other => return upstream_pull_failure_response(&other, reference),
                }
            }
        }
    };

    // 3. Look up the manifest artifact by its path inside THIS repo
    //    via the visibility-aware artifact use case. Repo visibility
    //    has already been confirmed in step 1; we re-use the same
    //    enforcement here to keep the call shape uniform across the
    //    crate (direct port access is a compile error per ADR 0008).
    //
    //    The tag-pull-through branch above already returned the
    //    freshly-ingested `Artifact` — skip the round-trip and use
    //    it directly. Digest-addressed pulls and locally-resolved
    //    tag pulls fall through to the lookup as before.
    let coords = oci_manifest_coords(name, &hash);
    let artifact: Artifact = if let Some(a) = prefetched_artifact {
        *a
    } else {
        match ctx
            .artifact_use_case
            .find_visible_by_path(repo_key, &coords.path, actor)
            .await
        {
            Ok((_repo, a)) => a,
            Err(AppError::Domain(DomainError::NotFound { .. })) => {
                // Digest reference resolved (parsed cleanly) but
                // no local artifact. Try the upstream by digest.
                // The Ingested.hash matches the request digest by
                // construction (`declared_sha256` is set in the
                // IngestRequest); use the returned artifact directly.
                match try_upstream_manifest_pull(
                    &ctx,
                    &repo,
                    name,
                    reference,
                    accept_values(headers),
                )
                .await
                {
                    UpstreamManifestPullOutcome::Ingested { artifact, .. } => *artifact,
                    other => return upstream_pull_failure_response(&other, reference),
                }
            }
            Err(e) => {
                tracing::error!(
                    repo_key = %repo_key,
                    hash = %hash,
                    error = %e,
                    "manifest artifact lookup failed"
                );
                return OciError::Internal.into_response();
            }
        }
    };

    // 4. Quarantine / rejected. Same shape as blob pull: quarantined
    //    → 503 + Retry-After via the shared helper; rejected is hidden
    //    as MANIFEST_UNKNOWN (format-specific envelope, so inline here
    //    rather than in the helper).
    if let Some(resp) = quarantine::check_quarantine(&artifact, repo_key) {
        return resp;
    }
    if matches!(artifact.quarantine_status, QuarantineStatus::Rejected) {
        return OciError::ManifestUnknown {
            reference: reference.to_string(),
        }
        .into_response();
    }

    // 5. Media-type + content negotiation. The stored type comes from
    //    `ArtifactMetadata.metadata.oci_media_type`;
    //    fall back to the OCI v1 single-image default when absent.
    let media_type = resolve_media_type(&ctx, artifact.id).await;
    if !accept_matches(headers, &media_type) {
        // Tracing on the 406 branch: logging both sides of the
        // comparison makes future operator bug-reports self-describing.
        let accept_header = headers
            .get(ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<absent>");
        tracing::warn!(
            repo_key = %repo_key,
            name = %name,
            reference = %reference,
            stored_media_type = %media_type,
            request_accept = %accept_header,
            "OCI manifest accept negotiation failed"
        );
        return OciError::ManifestNotAcceptable { media_type }.into_response();
    }

    // 6. Happy path. HEAD short-circuits the stream but keeps the
    //    header set bit-identical (spec: HEAD-before-GET parity).
    if head {
        return build_response(&artifact, &hash, &media_type, /* body = */ None);
    }

    // Thread the resolved principal for opt-in download-audit attribution
    // (ADR 0020). No per-handler auth code.
    let (_a, stream) = match ctx.artifact_use_case.download(artifact.id, actor).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                artifact_id = %artifact.id,
                error = %e,
                "OCI manifest download failed after lookup"
            );
            return OciError::Internal.into_response();
        }
    };

    build_response(
        &artifact,
        &hash,
        &media_type,
        Some(stream_blob(stream, DEFAULT_STREAM_CAPACITY)),
    )
}

// ---------------------------------------------------------------------------
// Reference resolution
// ---------------------------------------------------------------------------

/// Resolve `reference` to a `ContentHash`. `reference` containing `:`
/// is treated as a digest; anything else is a tag looked up through
/// `RefUseCase::get`. Errors are returned as boxed `Response`s so the
/// `Result` stays small — `http::Response<Body>` is > 128 bytes and
/// `clippy::result_large_err` flags it at workspace level.
fn resolve_digest_reference(reference: &str) -> Result<ContentHash, Box<Response>> {
    match parse_digest(reference) {
        DigestParse::Ok(h) => Ok(h),
        DigestParse::Unsupported { algorithm } => Err(Box::new(
            OciError::Unsupported {
                message: format!("unsupported digest algorithm: {algorithm}"),
            }
            .into_response(),
        )),
        DigestParse::Invalid { message } => Err(Box::new(
            OciError::DigestInvalid { message }.into_response(),
        )),
    }
}

/// Outcome of a tag-reference resolution.
///
/// Splits "tag missing locally" (try upstream pull-through) from
/// "data integrity bug or transport failure" (must surface
/// immediately, the upstream can't recover from these).
pub(super) enum TagResolveOutcome {
    /// Tag → digest mapping found locally with the right variant.
    Resolved(ContentHash),
    /// `RefUseCase::get` returned NotFound. Caller may try the
    /// upstream pull-through path.
    NotFound,
    /// `RefTarget::Version` on an OCI tag (cross-format
    /// contamination), or any other DomainError from the ref
    /// lookup. Pre-built `Response` ready to return verbatim
    /// (typically 500); caller does NOT try upstream.
    Failed(Box<Response>),
}

async fn resolve_tag_reference(
    ctx: &AppContext,
    repo_id: &Uuid,
    name: &str,
    tag: &str,
) -> TagResolveOutcome {
    match ctx.ref_use_case.get(*repo_id, name, tag).await {
        Ok(mref) => match mref.target {
            RefTarget::ContentHash(h) => TagResolveOutcome::Resolved(h),
            RefTarget::Version(v) => {
                // OCI tags are ALWAYS ContentHash — the manifest PUT
                // handler is the only writer for OCI namespaces and
                // it emits ContentHash exclusively. A Version here is
                // a cross-format contamination of the shared
                // `mutable_refs` table and surfaces as 500. This does
                // NOT route to upstream pull-through — masking a
                // data-integrity bug behind a 404 would hide the
                // problem.
                tracing::error!(
                    %repo_id,
                    namespace = %name,
                    tag = %tag,
                    version = %v,
                    "RefTarget::Version on OCI tag lookup — data integrity bug"
                );
                TagResolveOutcome::Failed(Box::new(OciError::Internal.into_response()))
            }
        },
        Err(AppError::Domain(DomainError::NotFound { .. })) => TagResolveOutcome::NotFound,
        Err(e) => {
            tracing::error!(
                %repo_id,
                namespace = %name,
                tag = %tag,
                error = %e,
                "ref lookup failed"
            );
            TagResolveOutcome::Failed(Box::new(OciError::Internal.into_response()))
        }
    }
}

// ---------------------------------------------------------------------------
// Media-type resolution + content negotiation
// ---------------------------------------------------------------------------

/// Fetch the manifest's stored media-type from the
/// `artifact_metadata.metadata.oci_media_type` field. Falls back to
/// [`DEFAULT_MEDIA_TYPE`] when the
/// metadata row is absent or the field is missing — legitimate for
/// artifacts that pre-date the metadata write (migration path) and for
/// the adapter returning an error (we degrade gracefully rather than
/// 500 the pull).
async fn resolve_media_type(ctx: &AppContext, artifact_id: Uuid) -> String {
    // `batch_metadata` collapses the single-id lookup into the
    // trusted-ids contract: the caller has already authz'd the artifact
    // (the manifest serve handler resolved it via `find_visible_by_path` /
    // `find_visible_by_id` upstream, ADR 0008).
    match ctx.artifact_use_case.batch_metadata(&[artifact_id]).await {
        Ok(map) => map
            .get(&artifact_id)
            .and_then(|m| {
                m.metadata
                    .get("oci_media_type")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| DEFAULT_MEDIA_TYPE.to_string()),
        Err(e) => {
            tracing::warn!(
                %artifact_id,
                error = %e,
                "artifact_metadata lookup failed; falling back to default media type"
            );
            DEFAULT_MEDIA_TYPE.to_string()
        }
    }
}

/// Returns `true` if `headers`'s `Accept` matches `media_type`.
///
/// - Missing / empty `Accept` → treated as `*/*` (RFC 9110 §12.5.1).
/// - Any `*/*` entry → accept.
/// - Any `<type>/*` entry whose type half matches `media_type`'s type
///   half → accept (e.g. `application/*` matches
///   `application/vnd.oci.image.manifest.v1+json`). RFC 9110 §12.5.1
///   lists subtype wildcards alongside `*/*` as legitimate media
///   ranges; rejecting them while accepting `*/*` is internally
///   inconsistent.
/// - Any entry exact-matching `media_type` → accept.
/// - Any entry that is the **manifest-pair sibling** of the stored
///   type → accept. See [`is_manifest_pair_sibling`] for the
///   relationship: OCI image manifest ↔ OCI image index, and Docker
///   v2 manifest ↔ Docker v2 manifest list. The leniency exists
///   because Docker Hub / GHCR / Quay / Harbor all serve indexes /
///   lists in response to single-image Accepts, and skopeo / docker
///   / podman / containerd all handle the response correctly. Strict
///   406 here breaks the multi-arch mirror flow for every multi-arch
///   image — see the OCI mirror smoke regression test below.
///
/// Quality-value `Accept` handling (`q=0` to negate) and
/// case-insensitive type/subtype comparison are explicit non-goals.
/// Real OCI clients do not send `q=0` on the manifest media-type, so
/// the omission does not block correctness.
fn accept_matches(headers: &HeaderMap, media_type: &str) -> bool {
    // Gather entries across ALL `Accept` header lines (see `accept_values` —
    // a client may split its `Accept` over multiple header lines). A non-UTF8
    // `Accept` value is a malformed request → no match. Absent `Accept`, or
    // present-but-empty, is treated as `*/*` per RFC 9110 §12.5.1.
    let mut saw_header = false;
    let mut entries: Vec<&str> = Vec::new();
    for value in headers.get_all(ACCEPT) {
        saw_header = true;
        let Ok(s) = value.to_str() else {
            return false;
        };
        for part in s.split(',') {
            let part = part.trim();
            if !part.is_empty() {
                entries.push(part);
            }
        }
    }
    if !saw_header || entries.is_empty() {
        return true;
    }
    // Extract the type half of the stored media-type once. Needed for
    // subtype-wildcard comparison; a malformed stored media-type (no
    // `/`) falls through with `None`, which only the exact-match and
    // `*/*` arms can satisfy — the subtype-wildcard arm can't.
    let media_type_main = media_type.split_once('/').map(|(t, _)| t);
    entries.into_iter().any(|entry| {
        let entry = entry.split(';').next().unwrap_or("").trim();
        if entry == "*/*" || entry == media_type {
            return true;
        }
        // Manifest-pair leniency: an Accept of the single-image type
        // matches a stored index of the same vendor (and vice
        // versa). See `is_manifest_pair_sibling`.
        if is_manifest_pair_sibling(entry, media_type) {
            return true;
        }
        // <type>/* subtype wildcard: accept if the left half matches
        // the stored media-type's left half.
        if let Some((t, s)) = entry.split_once('/') {
            if s == "*" {
                if let Some(mt_main) = media_type_main {
                    return t == mt_main;
                }
            }
        }
        false
    })
}

/// OCI image index media-type (multi-platform wrapper around
/// [`DEFAULT_MEDIA_TYPE`], the single-platform OCI manifest type).
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// Docker v2 single-platform manifest media-type.
const DOCKER_V2_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// Docker v2 multi-platform manifest list media-type.
const DOCKER_V2_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";

/// Returns `true` if `accept_entry` and `stored_media_type` form a
/// valid OCI / Docker manifest-pair (single-platform ↔ multi-
/// platform) within the same vendor. Used by [`accept_matches`] to
/// loosen content negotiation for the practical mirror case.
///
/// The relationships:
/// - OCI image manifest ([`DEFAULT_MEDIA_TYPE`]) ↔ OCI image index
/// - Docker v2 manifest ↔ Docker v2 manifest list
///
/// Cross-vendor pairs (OCI manifest ↔ Docker manifest list, etc.)
/// are NOT siblings — vendor mixing in the same response is a real
/// client compatibility hazard and not what registries do.
fn is_manifest_pair_sibling(accept_entry: &str, stored_media_type: &str) -> bool {
    matches!(
        (accept_entry, stored_media_type),
        (DEFAULT_MEDIA_TYPE, OCI_INDEX)
            | (OCI_INDEX, DEFAULT_MEDIA_TYPE)
            | (DOCKER_V2_MANIFEST, DOCKER_V2_MANIFEST_LIST)
            | (DOCKER_V2_MANIFEST_LIST, DOCKER_V2_MANIFEST)
    )
}

// ---------------------------------------------------------------------------
// Response builder
// ---------------------------------------------------------------------------

fn build_response(
    artifact: &Artifact,
    hash: &ContentHash,
    media_type: &str,
    body: Option<Body>,
) -> Response {
    let mut headers = HeaderMap::new();
    // Content-Type echoes the stored media-type, not a fixed value —
    // an index manifest with `application/vnd.oci.image.index.v1+json`
    // must reach the client with that exact type.
    let content_type = HeaderValue::from_str(media_type)
        // The stored value came from an artifact_metadata row whose
        // content we don't validate at write time. Malformed bytes
        // here would be a write-path bug; fall back to the default
        // rather than 500 the pull.
        .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_MEDIA_TYPE));
    headers.insert(CONTENT_TYPE, content_type);
    // Always emit Content-Length — matches the blob path, and a
    // zero-byte manifest (atypical but representable) would otherwise
    // be chunk-encoded by axum.
    headers.insert(CONTENT_LENGTH, artifact.size_bytes.into());
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&format!("sha256:{}", hash.as_ref()))
            .expect("sha256:<hex> is valid ASCII"),
    );
    let body = body.unwrap_or_else(Body::empty);
    (StatusCode::OK, headers, body).into_response()
}

// ---------------------------------------------------------------------------
// Manifest pull-through
// ---------------------------------------------------------------------------

/// Outcome of [`try_upstream_manifest_pull`]. Each variant maps to a
/// distinct caller response in [`serve`]'s miss arms.
pub(super) enum UpstreamManifestPullOutcome {
    /// Upstream fetch + ingest succeeded. `hash` is the freshly-
    /// ingested manifest's content digest. The media-type the
    /// upstream sent is persisted in the artifact's metadata row
    /// via `payload_metadata.oci_media_type`; `serve`'s step 5
    /// reads it back through `resolve_media_type` — same path the
    /// local PUT writers use.
    Ingested {
        artifact: Box<Artifact>,
        hash: ContentHash,
    },
    /// Repo has no upstream mapping for this name → caller treats as
    /// `MANIFEST_UNKNOWN`.
    NotConfigured,
    /// Upstream returned 404. Caller surfaces as `MANIFEST_UNKNOWN`
    /// — both the local cache and upstream lack the manifest, so
    /// the wire shape is identical to "not found locally".
    UpstreamNotFound,
    /// Pull-through ingest hit a curation rule that blocked the artifact.
    /// Surfaced to the OCI client as `MANIFEST_UNKNOWN` (404) so
    /// `docker pull` / `skopeo copy` see the same envelope as a genuine
    /// upstream miss; without this override the default
    /// `DomainError::CurationBlocked` → 403 mapping would surface a
    /// cryptic 403 mid-pull. The matched rule already logged
    /// `tracing::info!` inside the ingest use case.
    CurationBlocked,
    /// Digest-addressed pull only: upstream returned bytes whose
    /// SHA-256 disagreed with the requested digest. The
    /// `ChecksumMismatch` event already fired inside the ingest use
    /// case; cache write was suppressed.
    ChecksumMismatch,
    /// Upstream returned 5xx / network error / timeout. Surfaces as
    /// `BAD_GATEWAY` so callers can distinguish "we don't have it"
    /// from "upstream is unreachable".
    UpstreamUnavailable,
    /// Tag-mode pull whose upstream response omitted
    /// `Docker-Content-Digest`. Surfaces as `BAD_GATEWAY`. The pre-fix
    /// code self-hashed the received bytes — making
    /// `IngestUseCase::ingest_verified`'s comparison a tautology and
    /// emitting a `ChecksumVerified` event that attested to nothing.
    /// Refusing the pull here keeps `ChecksumVerified` an honest
    /// attestation that an upstream-supplied digest was checked (ADR 0006).
    /// The `hort_upstream_checksum_total{format=oci,result=checksum_missing}`
    /// metric ticks once on this path; no event is appended.
    UpstreamDigestMissing,
    /// The upstream manifest body exceeded the configured storage backstop
    /// (`HORT_UPSTREAM_MANIFEST_CACHE_MAX_SIZE`). Surfaces as `BAD_GATEWAY`
    /// with an honest `bytes_read`/`cap` detail rather than folding into
    /// the generic [`Self::UpstreamUnavailable`] envelope — operators see
    /// the exact numbers they need to size the knob.
    ManifestTooLarge { bytes_read: u64, cap: u64 },
    /// Infrastructure failure (storage, event store, repo lookup
    /// after ingest). Surfaces as 500.
    Internal,
}

/// On local manifest miss, attempt to fetch the manifest from a
/// configured upstream and ingest it locally. Mirror of
/// `try_upstream_blob_pull` in `blobs.rs`.
///
/// `reference` is either a tag (e.g. `3.19`) or a full digest
/// reference (e.g. `sha256:abc…`). For tag references the discovered
/// digest is taken from the upstream's `Docker-Content-Digest`
/// header — REQUIRED, not optional. A tag pull whose upstream omits
/// the header (or supplies an unparseable value) returns
/// [`UpstreamManifestPullOutcome::UpstreamDigestMissing`] (502 to
/// the client) without invoking the ingest pipeline; the pre-fix
/// self-hash fallback produced a tautological `ChecksumVerified` event
/// (ADR 0006). The helper also writes the local `tag → digest` mapping
/// via `RefUseCase::set` on the success path so subsequent pulls of the
/// same tag resolve without an upstream round-trip.
pub(super) async fn try_upstream_manifest_pull(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    name: &str,
    reference: &str,
    accept: Vec<String>,
) -> UpstreamManifestPullOutcome {
    // 1. Resolve the upstream. No mapping → not-configured.
    let Some((mapping, upstream_name)) = ctx.upstream_resolver.resolve(repo.id, name) else {
        return UpstreamManifestPullOutcome::NotConfigured;
    };

    let is_digest_ref = reference.contains(':');
    let mode = if is_digest_ref { "digest" } else { "tag" };
    tracing::info!(
        repo_key = %repo.key,
        upstream_url = %mapping.upstream_url,
        upstream_name = %upstream_name,
        upstream_name_prefix = ?mapping.upstream_name_prefix,
        reference = %reference,
        mode,
        "OCI manifest cache miss — fetching from upstream"
    );

    // Branch the dedup-key shape on whether the reference is a tag
    // (mutable label, digest must be discovered) or a digest (the
    // digest is in the URL itself).
    //
    // - **Tag-ref** (no `:`): use `coalesce_to_hash` keyed on a
    //   metadata key `(format=oci, repo_id, /v2/{name}/manifests/{tag})`.
    //   The leg streams into CAS and broadcasts the resolved digest, not
    //   the manifest bytes (ADR 0026). The manifest path includes the
    //   tag string, so two tags pointing at the same digest do NOT
    //   coalesce — they are separate URLs even though the underlying
    //   content is identical. This is the correct behaviour: the
    //   tag→digest mapping is what we are protecting.
    // - **Digest-ref** (`sha256:...`): use `coalesce_blob` keyed on
    //   `blob_by_hash("sha256", &hex)`. The digest is canonical and
    //   the natural dedup boundary; cross-repo callers asking for the
    //   same bytes share a single window.
    if is_digest_ref {
        try_upstream_manifest_pull_by_digest(
            ctx,
            repo,
            name,
            reference,
            accept,
            mapping,
            upstream_name,
        )
        .await
    } else {
        try_upstream_manifest_pull_by_tag(
            ctx,
            repo,
            name,
            reference,
            accept,
            mapping,
            upstream_name,
        )
        .await
    }
}

/// Digest-ref branch: the digest is part of the URL. Wrap the entire
/// fetch + ingest pair in `coalesce_blob` keyed on the digest hex.
/// Followers re-resolve the artifact row via `find_in_repo_by_hash`
/// after the leader's `ingest_verified` writes it.
async fn try_upstream_manifest_pull_by_digest(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    name: &str,
    reference: &str,
    accept: Vec<String>,
    mapping: hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping,
    upstream_name: String,
) -> UpstreamManifestPullOutcome {
    // Parse the digest reference into a `ContentHash`. A malformed
    // `sha256:` reference is an internal contract violation — `serve`
    // already validated the digest via `parse_digest` before this
    // helper is reached on the digest-ref path.
    let upstream_digest: ContentHash = match reference
        .strip_prefix("sha256:")
        .and_then(|h| h.parse::<ContentHash>().ok())
    {
        Some(h) => h,
        None => return UpstreamManifestPullOutcome::Internal,
    };

    let blob_dedup_key = DedupKey::blob_by_hash("sha256", upstream_digest.as_ref());
    let blob_proxy = ctx.upstream_proxy.clone();
    let blob_ingest = ctx.ingest_use_case.clone();
    let blob_mapping = mapping.clone();
    let blob_upstream_name = upstream_name.clone();
    let blob_reference = reference.to_string();
    let blob_accept = accept;
    let blob_repo_id = repo.id;
    let blob_upstream_url = mapping.upstream_url.clone();
    let blob_upstream_digest = upstream_digest.clone();
    // Capture the serving mapping's per-upstream opt-in
    // (`trust_upstream_publish_time`, ADR 0007) **before** the closure
    // consumes `mapping`. Threaded into `VerifiedIngestRequest` so
    // `ingest_inner` can gate the publish-anchored quarantine resolution.
    let blob_trust_publish_time = mapping.trust_upstream_publish_time;
    let coalesce_result = ctx
        .pull_dedup
        .coalesce_blob(blob_dedup_key, move || async move {
            let fetch = blob_proxy
                .fetch_manifest(
                    blob_mapping,
                    blob_upstream_name.clone(),
                    blob_reference,
                    blob_accept,
                )
                .await
                .map_err(AppError::from)?;
            // `media_type` is `Option<String>` on the outcome; preserve
            // the legacy fallback the adapter applied before.
            let media_type = fetch
                .media_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".to_string());
            // Thread the upstream manifest's `Last-Modified` (if any) onto
            // `Artifact.upstream_published_at`. Without this,
            // `trust_upstream_publish_time = true` (ADR 0007) would
            // release every layer/config blob on its own upstream age
            // while the manifest stayed anchored on `ingested_at` and
            // 503'd `docker pull` after every other artifact in the image
            // already passed quarantine.
            let upstream_published_at = fetch.last_modified;
            // Stream the fetch tempfile into CAS instead of buffering.
            // Open the cached body as a `tokio::fs::File` and
            // hand it to `ingest_verified`, which computes the SHA-256
            // incrementally and verifies it against `upstream_digest`. A
            // `None` cache_handle is the compile-through invariant
            // violation `manifest_body_bytes` used to surface.
            let cache_handle = fetch.cache_handle.as_ref().ok_or_else(|| {
                AppError::from(DomainError::Invariant(
                    "ManifestFetchOutcome.cache_handle is None — compile-through invariant violated"
                        .to_string(),
                ))
            })?;
            let file = tokio::fs::File::open(&cache_handle.path)
                .await
                .map_err(|e| {
                    AppError::from(DomainError::Validation(format!(
                        "failed to open cached manifest body at {}: {e}",
                        cache_handle.path.display()
                    )))
                })?;
            let async_read: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(file);
            let request = VerifiedIngestRequest::ProtocolNative {
                repository_id: blob_repo_id,
                coords: oci_manifest_coords(name, &blob_upstream_digest),
                content_type: media_type.clone(),
                actor: ApiActor {
                    user_id: Uuid::nil(),
                },
                payload_metadata: serde_json::json!({
                    "oci_source": "upstream",
                    "oci_upstream_url": blob_upstream_url,
                    "oci_upstream_name": blob_upstream_name,
                    "oci_media_type": media_type,
                }),
                upstream_digest: blob_upstream_digest,
                upstream_published_at,
                // Serving mapping's opt-in (ADR 0007).
                trust_upstream_publish_time: blob_trust_publish_time,
            };
            let outcome = blob_ingest
                .ingest_verified(request, async_read, &OciFormatHandler)
                .await?;
            // Tempfile is in CAS now — drop it (the lifecycle
            // `manifest_body_bytes` used to own).
            hort_app::project::remove_cached_body(cache_handle).await;
            Ok(outcome.artifact.sha256_checksum)
        })
        .await;

    let content_hash = match map_manifest_pull_error(coalesce_result, repo, reference, &mapping) {
        Ok(h) => h,
        Err(outcome) => return outcome,
    };

    // Post-coalesce read: `find_in_repo_by_hash` recovers the artifact
    // row the leader's ingest wrote. Per-repo scoped per backlog
    // post-coalesce-read note; the leader and follower see identical
    // semantics.
    finalise_manifest_pull(
        ctx,
        repo,
        name,
        reference,
        content_hash,
        /*write_tag=*/ false,
    )
    .await
}

/// Tag-ref branch: the digest is unknown until the upstream returns
/// `Docker-Content-Digest`. Wrap the fetch + ingest + tag-write inside
/// `coalesce_to_hash` (ADR 0026). The closure body runs on the leader,
/// streams the fetch tempfile into CAS, and returns the resolved
/// `ContentHash` (the digest it ingested) — NOT the manifest bytes.
/// Followers join the broadcast and observe the SAME hash; they do NOT
/// re-run the ingest/tag-write and they never receive the manifest bytes.
/// Manifest bytes therefore no longer transit Redis (anti-big-key).
/// Both leader and follower call `find_in_repo_by_hash` after the
/// coalesce via `finalise_manifest_pull`.
///
/// The prefetch-on-tag-move trigger fires LEADER-SIDE inside the closure
/// (it is the only path that holds the manifest bytes — read once from
/// the just-ingested tempfile before cleanup — and it is gated on the
/// leader's successful ingest). Coalesced followers do not re-plan the
/// same prefetch.
async fn try_upstream_manifest_pull_by_tag(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    name: &str,
    tag: &str,
    accept: Vec<String>,
    mapping: hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping,
    upstream_name: String,
) -> UpstreamManifestPullOutcome {
    // Capture the prior held digest for this `(repo, name, tag)` BEFORE
    // the upstream fetch + ingest writes the new one. A subsequent
    // comparison with the upstream-resolved digest is the
    // divergence-detection input to `prefetch::fire_prefetch_trigger_oci`
    // below. A `NotFound` is a first-time tag pull — treated as a "moved
    // from no-digest to a-digest" event (the trigger fires regardless,
    // priming the new image's blobs). Other lookup errors degrade to
    // `None` — prefetch is best-effort.
    let prior_held_digest: Option<ContentHash> =
        match ctx.ref_use_case.get(repo.id, name, tag).await {
            Ok(mref) => match mref.target {
                RefTarget::ContentHash(h) => Some(h),
                // RefTarget::Version on an OCI tag is a data-integrity
                // bug (see `resolve_tag_reference` doc). Treat as "no
                // prior digest" for prefetch purposes; the existing
                // serve flow has already surfaced this as a 500 if
                // the tag was being served.
                RefTarget::Version(_) => None,
            },
            Err(AppError::Domain(DomainError::NotFound { .. })) => None,
            Err(err) => {
                tracing::warn!(
                    repo_key = %repo.key,
                    name = %name,
                    tag = %tag,
                    error = %err,
                    "OCI prefetch: prior-held tag digest lookup failed; \
                     proceeding without divergence detection (non-fatal)"
                );
                None
            }
        };

    // Manifest path includes the tag — distinct tags pointing at the
    // same digest do NOT coalesce; concurrent callers of the SAME tag
    // correctly single-flight. The HTTP path shape mirrors the OCI
    // Distribution Spec wire (`/v2/<name>/manifests/<tag>`).
    //
    // The client's `Accept` is intentionally NOT part of this dedup key,
    // and it no longer needs to be: the upstream manifest fetch
    // (`do_fetch_manifest`) now always advertises the full canonical
    // manifest media-type set regardless of the client's (possibly
    // narrower) `Accept`, so the cached representation is
    // Accept-independent — a multi-arch tag always resolves to its
    // index/list, never to a single-platform manifest a narrow leader
    // happened to request. Narrow clients are negotiated at serve time
    // (`accept_matches` → 406, with manifest-pair leniency), never by
    // changing what gets fetched and stored. This is the deterministic
    // fix that was previously deferred (the prior `Accept`-forwarding
    // behaviour 404'd against strict-content-negotiation registries —
    // Artifact Registry, which backs registry.k8s.io — when the client's
    // first `Accept` type omitted the manifest's real media type).
    let manifest_path = format!("/v2/{name}/manifests/{tag}");
    let meta_dedup_key = DedupKey::metadata("oci", repo.id, &manifest_path);
    let meta_proxy = ctx.upstream_proxy.clone();
    let meta_ingest = ctx.ingest_use_case.clone();
    let meta_ref_use_case = ctx.ref_use_case.clone();
    let meta_mapping = mapping.clone();
    let meta_upstream_name = upstream_name.clone();
    let meta_reference = tag.to_string();
    let meta_accept = accept;
    let meta_repo_id = repo.id;
    let meta_repo_key = repo.key.clone();
    let meta_name = name.to_string();
    let meta_tag = tag.to_string();
    let meta_upstream_url = mapping.upstream_url.clone();
    // Capture the serving mapping's per-upstream opt-in
    // (`trust_upstream_publish_time`, ADR 0007) **before** the closure
    // consumes `mapping`. Threaded into `VerifiedIngestRequest` so
    // `ingest_inner` can gate the publish-anchored quarantine resolution.
    let meta_trust_publish_time = mapping.trust_upstream_publish_time;
    // Captured for the LEADER-side prefetch trigger, which fires inside
    // the closure (the only path holding the manifest bytes after the
    // stream-to-CAS retirement of the bytes-broadcast).
    let meta_ctx = ctx.clone();
    let meta_repo = repo.clone();
    let meta_prior_held_digest = prior_held_digest;

    // The closure returns the resolved `ContentHash` (ADR 0026).
    // Side-effects inside (ingest_verified, ref_use_case.set, the
    // leader-side prefetch trigger) run on the leader exactly once per
    // coalescing window. Followers join via the broadcast, observe the
    // hash, and recover the artifact row via `find_in_repo_by_hash` —
    // they never see the manifest bytes.
    let coalesce_result = ctx
        .pull_dedup
        .coalesce_to_hash(meta_dedup_key, move || async move {
            let fetch = meta_proxy
                .fetch_manifest(
                    meta_mapping,
                    meta_upstream_name.clone(),
                    meta_reference.clone(),
                    meta_accept,
                )
                .await
                .map_err(AppError::from)?;

            // Tag pull. Require the header; parse it strictly (ADR 0006).
            // A tag pull whose upstream omits the header is refused; the
            // pre-fix self-hash fallback made `ChecksumVerified` a
            // tautology. The leader emits the
            // `hort_upstream_checksum_total{result="checksum_missing"}`
            // metric and surfaces an `AppError::External` with a
            // discriminator string the caller maps back to
            // `UpstreamDigestMissing`.
            let upstream_digest: ContentHash = match fetch
                .declared_digest
                .as_deref()
                .and_then(|d| d.strip_prefix("sha256:"))
                .and_then(|h| h.parse::<ContentHash>().ok())
            {
                Some(h) => h,
                None => {
                    tracing::warn!(
                        repo_key = %meta_repo_key,
                        reference = %meta_reference,
                        declared_digest = ?fetch.declared_digest,
                        "OCI tag pull refused: upstream supplied no parseable Docker-Content-Digest"
                    );
                    emit_upstream_checksum(
                        OciFormatHandler.format_key(),
                        UpstreamChecksumResult::ChecksumMissing,
                    );
                    return Err(AppError::External(
                        "upstream:checksum_missing:oci-tag-pull".into(),
                    ));
                }
            };

            let media_type = fetch
                .media_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".to_string());
            // Tag-pull leg: manifest must anchor on its own publish-time
            // hint or `trust_upstream_publish_time = true` (ADR 0007)
            // would 503 pulls after every blob already released.
            let upstream_published_at = fetch.last_modified;
            // Stream the fetch tempfile into CAS instead of buffering.
            // `ingest_verified` computes the SHA-256 incrementally and
            // verifies it against `upstream_digest` (the upstream-declared
            // `Docker-Content-Digest`) — the verification semantics are
            // unchanged; only the byte source moves from a buffered
            // `Cursor` to the tempfile. A `None` cache_handle is the
            // compile-through invariant violation `manifest_body_bytes`
            // used to surface.
            let cache_handle = fetch.cache_handle.as_ref().ok_or_else(|| {
                AppError::from(DomainError::Invariant(
                    "ManifestFetchOutcome.cache_handle is None — compile-through invariant violated"
                        .to_string(),
                ))
            })?;
            let file = tokio::fs::File::open(&cache_handle.path)
                .await
                .map_err(|e| {
                    AppError::from(DomainError::Validation(format!(
                        "failed to open cached manifest body at {}: {e}",
                        cache_handle.path.display()
                    )))
                })?;
            let async_read: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(file);
            let request = VerifiedIngestRequest::ProtocolNative {
                repository_id: meta_repo_id,
                coords: oci_manifest_coords(&meta_name, &upstream_digest),
                content_type: media_type.clone(),
                actor: ApiActor {
                    user_id: Uuid::nil(),
                },
                payload_metadata: serde_json::json!({
                    "oci_source": "upstream",
                    "oci_upstream_url": meta_upstream_url,
                    "oci_upstream_name": meta_upstream_name,
                    "oci_media_type": media_type,
                }),
                upstream_digest: upstream_digest.clone(),
                upstream_published_at,
                // Serving mapping's opt-in (ADR 0007).
                trust_upstream_publish_time: meta_trust_publish_time,
            };
            let ingest_outcome = meta_ingest
                .ingest_verified(request, async_read, &OciFormatHandler)
                .await?;
            let actual_hash = ingest_outcome.artifact.sha256_checksum.clone();

            // Tag → digest mapping write (leader only). A failure
            // here is non-fatal — manifest is in CAS; worst case is
            // a redundant upstream fetch next time. We log
            // `tracing::warn!` but still return success so the
            // coalescing window is recorded as `Success` (next-call
            // negative cache does NOT fire).
            if let Err(err) = meta_ref_use_case
                .set(
                    meta_repo_id,
                    &meta_name,
                    &meta_tag,
                    RefTarget::ContentHash(actual_hash.clone()),
                    ApiActor {
                        user_id: Uuid::nil(),
                    },
                    Some(&meta_repo_key),
                )
                .await
            {
                tracing::warn!(
                    repo_key = %meta_repo_key,
                    tag = %meta_tag,
                    hash = %actual_hash,
                    error = %err,
                    "OCI tag→digest mapping write failed; manifest is in CAS, next tag pull will re-fetch"
                );
            }

            tracing::info!(
                repo_key = %meta_repo_key,
                reference = %meta_tag,
                hash = %actual_hash,
                media_type = %media_type,
                bytes_len = ingest_outcome.artifact.size_bytes,
                "OCI upstream manifest pull-through succeeded"
            );

            // LEADER-SIDE prefetch-on-tag-move trigger. The
            // bytes-broadcast retirement (ADR 0026) means this is the only
            // path that holds the manifest bytes; read them once from the
            // just-ingested tempfile (only when prefetch is enabled and the
            // tag moved — `fire_prefetch_trigger_oci` gates internally)
            // BEFORE the cleanup below. Best-effort and background-spawned;
            // never affects the live response. A tempfile read failure here
            // is non-fatal — the manifest is already in CAS.
            if meta_repo.prefetch_policy.enabled {
                match tokio::fs::read(&cache_handle.path).await {
                    Ok(manifest_bytes) => {
                        crate::prefetch::fire_prefetch_trigger_oci(
                            &meta_ctx,
                            &meta_repo,
                            &meta_name,
                            &meta_tag,
                            &actual_hash,
                            meta_prior_held_digest.as_ref(),
                            &Bytes::from(manifest_bytes),
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            repo_key = %meta_repo_key,
                            tag = %meta_tag,
                            error = %e,
                            "OCI prefetch: failed to re-read manifest tempfile for blob-digest \
                             extraction; skipping prefetch (non-fatal, manifest is in CAS)"
                        );
                    }
                }
            }

            // Tempfile is in CAS now — drop it (the lifecycle
            // `manifest_body_bytes` used to own).
            hort_app::project::remove_cached_body(cache_handle).await;
            Ok(actual_hash)
        })
        .await;

    let content_hash = match map_manifest_tag_pull_error(coalesce_result, repo, tag, &mapping) {
        Ok(h) => h,
        Err(outcome) => return outcome,
    };

    // Both leader and follower resolve the artifact row via the hash
    // (`finalise_manifest_pull` → `find_in_repo_by_hash`). The follower
    // never received the manifest bytes — it has the hash + CAS, which
    // is all it needs. The prefetch trigger already fired leader-side
    // inside the closure above.
    finalise_manifest_pull(
        ctx,
        repo,
        name,
        tag,
        content_hash,
        /*write_tag=*/ false,
    )
    .await
}

/// Map the closure's `Result<_, AppError>` outcome back to the
/// caller-visible `UpstreamManifestPullOutcome` variants. Shared
/// between the digest-ref and tag-ref paths because the typed-error
/// vocabulary is identical: `Conflict` → ChecksumMismatch,
/// `CurationBlocked` → CurationBlocked, "upstream:" prefix → 404 vs
/// 5xx classifier per the original code, anything else → Internal.
fn map_manifest_pull_error(
    coalesce_result: Result<ContentHash, AppError>,
    repo: &Repository,
    reference: &str,
    mapping: &hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping,
) -> Result<ContentHash, UpstreamManifestPullOutcome> {
    match coalesce_result {
        Ok(h) => Ok(h),
        Err(AppError::Domain(DomainError::Conflict(msg))) => {
            tracing::warn!(
                repo_key = %repo.key,
                reference = %reference,
                conflict = %msg,
                "OCI upstream manifest digest disagreed with request — refusing to cache"
            );
            Err(UpstreamManifestPullOutcome::ChecksumMismatch)
        }
        Err(AppError::Domain(DomainError::CurationBlocked { .. })) => {
            Err(UpstreamManifestPullOutcome::CurationBlocked)
        }
        Err(AppError::Domain(DomainError::UpstreamBodyTooLarge {
            bytes_read, cap, ..
        })) => {
            // Honest classification (502 + bytes_read/cap) instead of
            // the generic "upstream unavailable" fold the string-matching
            // `Err(err)` arm below would have applied.
            tracing::warn!(
                repo_key = %repo.key,
                reference = %reference,
                bytes_read,
                cap,
                "OCI upstream manifest body exceeded the configured cache cap"
            );
            Err(UpstreamManifestPullOutcome::ManifestTooLarge { bytes_read, cap })
        }
        Err(err) => {
            // Pre-coalesce code distinguished 404 (`UpstreamNotFound`)
            // from 5xx / network (`UpstreamUnavailable`) by
            // string-matching the rendered error. Followers see
            // `AppError::External("pull-dedup follower: ...")` and
            // route to `Internal` per the leader-only discrimination
            // contract.
            let msg = err.to_string();
            if msg.contains("404") || msg.contains("not_found") {
                tracing::info!(
                    repo_key = %repo.key,
                    upstream_url = %mapping.upstream_url,
                    reference = %reference,
                    "upstream returned not-found for manifest"
                );
                Err(UpstreamManifestPullOutcome::UpstreamNotFound)
            } else if msg.contains("upstream:") || msg.contains("upstream ") {
                tracing::warn!(
                    repo_key = %repo.key,
                    upstream_url = %mapping.upstream_url,
                    reference = %reference,
                    error = %err,
                    "OCI upstream manifest fetch failed"
                );
                Err(UpstreamManifestPullOutcome::UpstreamUnavailable)
            } else {
                tracing::error!(
                    repo_key = %repo.key,
                    reference = %reference,
                    error = %err,
                    "OCI upstream manifest ingest failed"
                );
                Err(UpstreamManifestPullOutcome::Internal)
            }
        }
    }
}

/// Tag-ref variant of [`map_manifest_pull_error`]. Identical to the
/// digest-ref shape — the closure returns a `ContentHash`
/// (hash-broadcast, ADR 0026) just like the digest leg — except the
/// leader signals a missing `Docker-Content-Digest` header via the
/// `"upstream:checksum_missing:oci-tag-pull"` sentinel, which maps to
/// `UpstreamDigestMissing` (ADR 0006).
fn map_manifest_tag_pull_error(
    coalesce_result: Result<ContentHash, AppError>,
    repo: &Repository,
    tag: &str,
    mapping: &hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping,
) -> Result<ContentHash, UpstreamManifestPullOutcome> {
    match coalesce_result {
        Ok(h) => Ok(h),
        Err(AppError::External(msg)) if msg.contains("upstream:checksum_missing:oci-tag-pull") => {
            // Leader-side sentinel for the missing-Docker-Content-Digest
            // case. The leader already emitted the
            // `hort_upstream_checksum_total{result="checksum_missing"}`
            // metric inside the closure. Followers re-emit
            // would double-count, so the metric stays leader-only.
            Err(UpstreamManifestPullOutcome::UpstreamDigestMissing)
        }
        Err(other) => {
            // Reuse the digest-ref classifier — the typed-error
            // vocabulary is identical for every other error shape.
            // The `Err(_)` arm is the only one reachable because
            // `map_manifest_pull_error` returns `Err(_)` for every
            // `Err(_)` input.
            match map_manifest_pull_error(Err(other), repo, tag, mapping) {
                Err(outcome) => Err(outcome),
                Ok(_) => unreachable!(
                    "map_manifest_pull_error returns Err for every Err input by construction"
                ),
            }
        }
    }
}

/// Final post-coalesce step: recover the artifact row via
/// `find_in_repo_by_hash`. Both leader and
/// follower take this path; the leader's `ingest_verified` (inside
/// the closure) wrote the row, the follower reads it.
///
/// `DedupKey::blob_by_hash` is cross-repo (ADR 0026), so a follower
/// that joined a window whose leader ingested into a DIFFERENT repo has
/// no row in `repo.id` — the lookup returns `None`. The manifest bytes
/// are already CAS-present and upstream-verified (ADR 0006, the
/// leader's `ingest_verified` proved the upstream digest); the follower
/// idempotently registers its OWN per-repo manifest row via
/// `register_existing_cas_blob` rather than failing closed. Coords are
/// reconstructed deterministically from `(name, content_hash)` —
/// `oci_manifest_coords` is exactly what the leader's closure used.
/// `DEFAULT_MEDIA_TYPE` is the follower's content_type: the upstream
/// `fetch.media_type` is only observable inside the leader's closure
/// (the follower never made the upstream call — the point of
/// coalescing), and `DEFAULT_MEDIA_TYPE` is the established OCI
/// fallback used elsewhere in this module for an unknown media type.
async fn finalise_manifest_pull(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    name: &str,
    reference: &str,
    content_hash: ContentHash,
    _write_tag: bool,
) -> UpstreamManifestPullOutcome {
    match ctx
        .artifact_use_case
        .find_in_repo_by_hash(repo.id, &content_hash)
        .await
    {
        Ok(Some(artifact)) => UpstreamManifestPullOutcome::Ingested {
            hash: artifact.sha256_checksum.clone(),
            artifact: Box::new(artifact),
        },
        Ok(None) => {
            match ctx
                .ingest_use_case
                .register_existing_cas_blob(
                    RegisterExistingCasBlobRequest {
                        repository_id: repo.id,
                        coords: oci_manifest_coords(name, &content_hash),
                        content_type: DEFAULT_MEDIA_TYPE.to_string(),
                        actor: ApiActor {
                            user_id: Uuid::nil(),
                        },
                        payload_metadata: serde_json::json!({
                            "oci_source": "upstream_coalesced_follower",
                        }),
                        content_hash: content_hash.clone(),
                        // Coalesced-follower path is not a seed-import;
                        // quarantine is policy-driven through the leader's
                        // primary `ingest_verified`.
                        seed_import_quarantine_anchor: None,
                    },
                    &OciFormatHandler,
                )
                .await
            {
                Ok(outcome) => UpstreamManifestPullOutcome::Ingested {
                    hash: outcome.artifact.sha256_checksum.clone(),
                    artifact: Box::new(outcome.artifact),
                },
                Err(err) => {
                    tracing::error!(
                        repo_key = %repo.key,
                        reference = %reference,
                        hash = %content_hash,
                        error = %err,
                        "OCI upstream manifest: cross-repo follower register_existing_cas_blob failed"
                    );
                    UpstreamManifestPullOutcome::Internal
                }
            }
        }
        Err(err) => {
            tracing::error!(
                repo_key = %repo.key,
                reference = %reference,
                hash = %content_hash,
                error = %err,
                "OCI upstream manifest: post-coalesce artifact lookup failed"
            );
            UpstreamManifestPullOutcome::Internal
        }
    }
}

/// Extract the comma-separated values from the request's `Accept`
/// header, with whitespace trimmed and empty values dropped. Used to
/// forward the caller's media-type preferences to the upstream
/// proxy. Empty Vec → adapter falls back to its default Accept set.
fn accept_values(headers: &HeaderMap) -> Vec<String> {
    // Collect entries across ALL `Accept` header lines, not just the first.
    // A client may send its `Accept` as multiple header lines rather than one
    // comma-joined line — Go's `http.Header.Add(...)`-per-media-type does
    // exactly this, and containerd's resolver uses it — so `headers.get`
    // (first value only) would silently drop every type after the first. That
    // narrowing surfaces downstream as an upstream 404 from a strict-content-
    // negotiation registry (Artifact Registry, which backs registry.k8s.io)
    // when the surviving first type omits the manifest's real media type.
    headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Map an [`UpstreamManifestPullOutcome::*`] non-`Ingested` variant
/// to the appropriate OCI error response. `Ingested` is the
/// caller's continue-with-the-data path and is not handled here.
fn upstream_pull_failure_response(
    outcome: &UpstreamManifestPullOutcome,
    reference: &str,
) -> Response {
    match outcome {
        UpstreamManifestPullOutcome::NotConfigured
        | UpstreamManifestPullOutcome::UpstreamNotFound
        | UpstreamManifestPullOutcome::CurationBlocked => OciError::ManifestUnknown {
            reference: reference.to_string(),
        }
        .into_response(),
        UpstreamManifestPullOutcome::ChecksumMismatch => OciError::BadGateway {
            detail: Some(serde_json::json!({
                "reason": "upstream manifest digest did not match request digest",
            })),
        }
        .into_response(),
        UpstreamManifestPullOutcome::UpstreamUnavailable => OciError::BadGateway {
            detail: Some(serde_json::json!({
                "reason": "upstream manifest fetch failed",
            })),
        }
        .into_response(),
        // Tag pull whose upstream omitted `Docker-Content-Digest`. The
        // HTTP envelope surfaces the missing-digest reason in `detail`
        // so operators can distinguish this from generic upstream failure
        // or digest disagreement (ADR 0006).
        UpstreamManifestPullOutcome::UpstreamDigestMissing => OciError::BadGateway {
            detail: Some(serde_json::json!({
                "reason": "upstream did not supply Docker-Content-Digest for tag pull",
            })),
        }
        .into_response(),
        // 502 carrying the exact `bytes_read`/`cap` the operator needs
        // to size `HORT_UPSTREAM_MANIFEST_CACHE_MAX_SIZE`.
        UpstreamManifestPullOutcome::ManifestTooLarge { bytes_read, cap } => OciError::BadGateway {
            detail: Some(serde_json::json!({
                "reason": "upstream manifest too large",
                "bytes_read": bytes_read,
                "cap": cap,
            })),
        }
        .into_response(),
        UpstreamManifestPullOutcome::Internal => OciError::Internal.into_response(),
        UpstreamManifestPullOutcome::Ingested { .. } => {
            unreachable!("Ingested handled by caller")
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::to_bytes;
    use axum::http::{Method, Request};
    use axum::Router;
    use chrono::Utc;
    use tower::ServiceExt;
    use uuid::Uuid;

    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, MockArtifactMetadataRepository, MockArtifactRepository,
        MockRefRegistryPort, MockRepositoryRepository, MockStoragePort,
    };
    use hort_domain::entities::artifact::{ArtifactMetadata, QuarantineStatus};
    use hort_domain::entities::mutable_ref::MutableRef;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use metrics_exporter_prometheus::PrometheusBuilder;

    use hort_http_core::context::AppContext;
    use hort_http_core::test_support::build_mock_ctx;

    // ---------------- Fixtures ----------------

    fn oci_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Oci;
        r
    }

    struct Harness {
        ctx: Arc<AppContext>,
        artifacts: Arc<MockArtifactRepository>,
        repositories: Arc<MockRepositoryRepository>,
        storage: Arc<MockStoragePort>,
        refs: Arc<MockRefRegistryPort>,
        metadata: Arc<MockArtifactMetadataRepository>,
    }

    fn harness() -> Harness {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);
        Harness {
            ctx,
            artifacts: mocks.artifacts,
            repositories: mocks.repositories,
            storage: mocks.storage,
            refs: mocks.refs,
            metadata: mocks.artifact_metadata,
        }
    }

    fn manifest_router(ctx: Arc<AppContext>) -> Router {
        Router::new()
            .route(
                "/v2/:repo_key/*tail",
                axum::routing::get(super::super::get_pull).head(super::super::head_pull),
            )
            .with_state(ctx)
    }

    fn run<F, T>(f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Seed a manifest artifact at `manifests/sha256:<hex>` with content
    /// in CAS and an optional `oci_media_type` in the metadata row.
    ///
    /// Accepts eight arguments because the three mock ports plus the
    /// five per-seed knobs (repo, hex, content, media, status) are all
    /// required — bundling them into a struct for a test helper buys
    /// no clarity and forces each test to name the fields twice.
    #[allow(clippy::too_many_arguments)]
    fn seed_manifest(
        artifacts: &MockArtifactRepository,
        storage: &MockStoragePort,
        metadata: &MockArtifactMetadataRepository,
        repo_id: Uuid,
        hex: &str,
        content: &[u8],
        media_type: Option<&str>,
        status: QuarantineStatus,
    ) -> (Uuid, ContentHash) {
        let hash: ContentHash = hex.parse().unwrap();
        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = repo_id;
        a.path = format!("manifests/sha256:{hex}");
        a.sha256_checksum = hash.clone();
        a.size_bytes = content.len() as i64;
        a.quarantine_status = status;
        if matches!(status, QuarantineStatus::Quarantined) {
            // Anchor stored on the row; the transient computed deadline
            // is what `check_quarantine` reads for `Retry-After`.
            a.quarantine_window_start = Some(Utc::now());
            a.quarantine_deadline = Some(Utc::now() + chrono::Duration::seconds(120));
        }
        let id = a.id;
        artifacts.insert(a);
        storage.insert_content(hash.clone(), content.to_vec());
        if let Some(mt) = media_type {
            let meta = ArtifactMetadata {
                artifact_id: id,
                format: RepositoryFormat::Oci,
                metadata: serde_json::json!({ "oci_media_type": mt }),
                metadata_blob: None,
                properties: serde_json::Value::Object(Default::default()),
            };
            metadata.insert(meta);
        }
        (id, hash)
    }

    fn seed_tag(
        refs: &MockRefRegistryPort,
        repo_id: Uuid,
        name: &str,
        tag: &str,
        hash: &ContentHash,
    ) {
        refs.insert(MutableRef {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            namespace: name.to_string(),
            ref_name: tag.to_string(),
            target: RefTarget::ContentHash(hash.clone()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
    }

    // ---------------- accept_matches ----------------

    #[test]
    fn accept_absent_matches_anything() {
        let headers = HeaderMap::new();
        assert!(accept_matches(&headers, DEFAULT_MEDIA_TYPE));
    }

    #[test]
    fn accept_star_star_matches() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, "*/*".parse().unwrap());
        assert!(accept_matches(&headers, DEFAULT_MEDIA_TYPE));
    }

    #[test]
    fn accept_exact_media_type_matches() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, DEFAULT_MEDIA_TYPE.parse().unwrap());
        assert!(accept_matches(&headers, DEFAULT_MEDIA_TYPE));
    }

    #[test]
    fn accept_list_with_match_matches() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            format!("application/json, {DEFAULT_MEDIA_TYPE}, */*")
                .parse()
                .unwrap(),
        );
        assert!(accept_matches(&headers, DEFAULT_MEDIA_TYPE));
    }

    #[test]
    fn accept_disjoint_list_does_not_match() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, "application/json, text/plain".parse().unwrap());
        assert!(!accept_matches(&headers, DEFAULT_MEDIA_TYPE));
    }

    #[test]
    fn accept_matches_checks_all_header_lines() {
        // A client may split its `Accept` across multiple header lines
        // (Go's `Header.Add` per media type — containerd does this). The
        // matching type is on the SECOND line; `accept_matches` must still
        // match it, not just look at the first line.
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, "application/json".parse().unwrap());
        headers.append(ACCEPT, DEFAULT_MEDIA_TYPE.parse().unwrap());
        assert!(
            accept_matches(&headers, DEFAULT_MEDIA_TYPE),
            "accept_matches must consider every Accept header line, not just the first"
        );
    }

    #[test]
    fn accept_values_collects_all_header_lines() {
        // Regression: `headers.get(ACCEPT)` returned only the first line,
        // silently narrowing a multi-line client `Accept` (the registry.k8s.io
        // / Artifact Registry 404 — the manifest's real type was on a later
        // line). `get_all` must collect every line.
        let index = "application/vnd.oci.image.index.v1+json";
        let list = "application/vnd.docker.distribution.manifest.list.v2+json";
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, index.parse().unwrap());
        headers.append(ACCEPT, list.parse().unwrap());
        let vals = accept_values(&headers);
        assert!(
            vals.iter().any(|v| v == index),
            "first line missing: {vals:?}"
        );
        assert!(
            vals.iter().any(|v| v == list),
            "later Accept lines must be collected, not dropped: {vals:?}"
        );
    }

    #[test]
    fn accept_ignores_q_parameter() {
        // We strip everything after `;` in each entry, so q=0.5 and
        // other parameters don't trip the match.
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            format!("{DEFAULT_MEDIA_TYPE};q=0.8").parse().unwrap(),
        );
        assert!(accept_matches(&headers, DEFAULT_MEDIA_TYPE));
    }

    // ---------------- Happy paths ----------------

    #[test]
    fn get_manifest_by_digest_served_with_stored_media_type() {
        let content = br#"{"schemaVersion":2}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";

        let (status, headers, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_manifest(
                &h.artifacts,
                &h.storage,
                &h.metadata,
                repo_id,
                &hex,
                &content,
                Some(media),
                QuarantineStatus::None,
            );
            let router = manifest_router(h.ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, media)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(CONTENT_TYPE).unwrap().to_str().unwrap(), media,);
        assert_eq!(
            headers
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("sha256:{hex}"),
        );
        assert_eq!(body, content);
    }

    #[test]
    fn get_manifest_by_tag_served_via_ref_lookup() {
        let content = br#"{"schemaVersion":2,"tag":"v1"}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";

        let (status, headers, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let (_id, hash) = seed_manifest(
                &h.artifacts,
                &h.storage,
                &h.metadata,
                repo_id,
                &hex,
                &content,
                Some(media),
                QuarantineStatus::None,
            );
            seed_tag(&h.refs, repo_id, "library/nginx", "v1", &hash);
            let router = manifest_router(h.ctx);
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("sha256:{hex}"),
        );
        assert_eq!(body, content);
    }

    #[test]
    fn head_manifest_returns_empty_body_with_identical_headers() {
        let content = br#"{"schemaVersion":2}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";

        let (status, headers, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_manifest(
                &h.artifacts,
                &h.storage,
                &h.metadata,
                repo_id,
                &hex,
                &content,
                Some(media),
                QuarantineStatus::None,
            );
            let router = manifest_router(h.ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let resp = router
                .oneshot(
                    Request::builder()
                        .method(Method::HEAD)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"");
        assert_eq!(headers.get(CONTENT_TYPE).unwrap().to_str().unwrap(), media,);
        assert_eq!(
            headers
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("sha256:{hex}"),
        );
        // Content-Length matches GET's bit-for-bit — HEAD-before-GET
        // clients rely on this to plan their download.
        assert_eq!(
            headers
                .get(CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            content.len(),
        );
    }

    // ---------------- Missing tag / manifest ----------------

    #[test]
    fn get_manifest_missing_tag_returns_404_manifest_unknown() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = manifest_router(h.ctx);
            let uri = "/v2/myrepo/library/nginx/manifests/nonexistent-tag";
            let resp = router
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
        assert_eq!(
            parsed["errors"][0]["detail"]["reference"],
            "nonexistent-tag"
        );
    }

    #[test]
    fn get_manifest_digest_ref_without_artifact_row_returns_404() {
        let valid_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            // No artifact seeded — find_by_path misses.
            let router = manifest_router(h.ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{valid_hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }

    // ---------------- Tag-grammar rejection (INJ-4) ----------------

    /// Drive several out-of-grammar tags through the full pull dispatch.
    /// Each MUST reject with 400 `MANIFEST_INVALID` BEFORE any ref lookup
    /// or pull-through — no tag/artifact is seeded, so an unvalidated path
    /// would 404 (`get_manifest_missing_tag_returns_404_manifest_unknown`),
    /// not 400. The 400 therefore proves the validator fired pre-lookup.
    /// The response body must NOT echo the offending bytes.
    #[test]
    fn get_manifest_out_of_grammar_tag_rejected_400_before_lookup() {
        // (uri_tag, label) — `uri_tag` is already a single path segment
        // (no `/`, no raw control bytes that the router would reject) so it
        // reaches the manifest dispatcher intact.
        let cases = [
            ("..", "double-dot path traversal"),
            (".leadingdot", "leading dot"),
            ("-leadinghyphen", "leading hyphen"),
            (&"a".repeat(129), "129-byte over-cap tag"),
        ];
        for (uri_tag, label) in cases {
            let (status, body) = run(async {
                let h = harness();
                h.repositories.insert(oci_repo("myrepo"));
                let router = manifest_router(h.ctx);
                let uri = format!("/v2/myrepo/library/nginx/manifests/{uri_tag}");
                let resp = router
                    .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
                (status, body)
            });
            assert_eq!(status, StatusCode::BAD_REQUEST, "case: {label}");
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                parsed["errors"][0]["code"], "MANIFEST_INVALID",
                "case: {label}"
            );
            // The reason is carried in `detail.reason` and must be a
            // deterministic `oci.tag:` string, never the offending bytes.
            let reason = parsed["errors"][0]["detail"]["reason"]
                .as_str()
                .unwrap_or("");
            assert!(
                reason.starts_with("oci.tag: "),
                "case {label}: reason must be tagged `oci.tag:` ({reason})"
            );
        }
    }

    /// A space inside the tag is out-of-grammar; percent-encode it so it
    /// survives URI parsing and reaches the handler as a literal space.
    #[test]
    fn get_manifest_tag_with_space_rejected_400() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = manifest_router(h.ctx);
            // `%20` decodes to a space in the captured path segment.
            let uri = "/v2/myrepo/library/nginx/manifests/foo%20bar";
            let resp = router
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
    }

    /// A valid tag that simply does not exist still returns 404
    /// `MANIFEST_UNKNOWN` — the validator must not reject legal tags.
    /// (Complements `get_manifest_missing_tag_returns_404_manifest_unknown`
    /// with a dotted/underscored/hyphenated tag that exercises the full
    /// trailing alphabet.)
    #[test]
    fn get_manifest_valid_complex_tag_passes_validation_then_404s() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = manifest_router(h.ctx);
            let uri = "/v2/myrepo/library/nginx/manifests/v1.2.3_rc1-build";
            let resp = router
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        // Passed grammar validation, then missed the local ref lookup →
        // 404, NOT 400. Proves a legal tag is not over-rejected.
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }

    // ---------------- 406 Not Acceptable ----------------

    #[test]
    fn mismatched_accept_returns_406_manifest_unknown() {
        let content = br#"{"schemaVersion":2}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";

        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_manifest(
                &h.artifacts,
                &h.storage,
                &h.metadata,
                repo_id,
                &hex,
                &content,
                Some(media),
                QuarantineStatus::None,
            );
            let router = manifest_router(h.ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, "application/json")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
        assert_eq!(
            parsed["errors"][0]["detail"]["media_type"], media,
            "server's stored media-type must echo back in detail"
        );
    }

    // ---------------- RefTarget::Version invariant ----------------

    #[test]
    fn ref_target_version_on_oci_tag_returns_500() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // Inject a malformed ref — RefTarget::Version where
            // OCI requires ContentHash. Simulates cross-format
            // contamination or a writer-side bug.
            h.refs.insert(MutableRef {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                namespace: "library/nginx".into(),
                ref_name: "v1".into(),
                target: RefTarget::Version("1.2.3".into()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
            let router = manifest_router(h.ctx);
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        // 5xx body must never leak internal details.
        hort_http_core::error::assert_no_internal_leakage(status, &body);
    }

    // ---------------- Quarantine / Rejected ----------------

    #[test]
    fn quarantined_manifest_returns_503_with_retry_after() {
        let content = br#"{"schemaVersion":2}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let (status, retry_after, content_type, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_manifest(
                &h.artifacts,
                &h.storage,
                &h.metadata,
                repo_id,
                &hex,
                &content,
                None,
                QuarantineStatus::Quarantined,
            );
            let router = manifest_router(h.ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let retry_after = resp
                .headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap().to_string());
            let content_type = resp
                .headers()
                .get(CONTENT_TYPE)
                .map(|v| v.to_str().unwrap().to_string());
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, retry_after, content_type, body)
        });
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let retry_after = retry_after.expect("Retry-After header missing");
        let secs: i64 = retry_after.parse().unwrap();
        assert!((1..=120).contains(&secs));
        // Assert body shape so a regression to TOOMANYREQUESTS /
        // mis-aligned status+code pair would be caught.
        assert_eq!(content_type.as_deref(), Some("application/json"));
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNAVAILABLE");
        assert!(
            parsed["errors"][0]["detail"]["retry_after_seconds"].is_i64(),
            "detail.retry_after_seconds must be a number"
        );
    }

    #[test]
    fn rejected_manifest_is_hidden_as_404() {
        let content = br#"{"schemaVersion":2}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_manifest(
                &h.artifacts,
                &h.storage,
                &h.metadata,
                repo_id,
                &hex,
                &content,
                None,
                QuarantineStatus::Rejected,
            );
            let router = manifest_router(h.ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }

    // ---------------- Default media type fallback ----------------

    #[test]
    fn missing_metadata_row_falls_back_to_default_media_type() {
        let content = br#"{"schemaVersion":2}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let (status, headers) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // Note: media_type = None → no metadata row seeded.
            seed_manifest(
                &h.artifacts,
                &h.storage,
                &h.metadata,
                repo_id,
                &hex,
                &content,
                None,
                QuarantineStatus::None,
            );
            let router = manifest_router(h.ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            (status, headers)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            DEFAULT_MEDIA_TYPE,
        );
    }

    // -- Subtype wildcard ------------------------------------------------

    #[test]
    fn accept_application_wildcard_matches_manifest_media_type() {
        // `Accept: application/*` is a legitimate RFC 9110 §12.5.1
        // media-range. Rejecting it while accepting `*/*` would be
        // internally inconsistent.
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, "application/*".parse().unwrap());
        assert!(accept_matches(&headers, DEFAULT_MEDIA_TYPE));
    }

    #[test]
    fn accept_image_wildcard_does_not_match_application_type() {
        // `image/*` has the wrong type half for an
        // `application/...` manifest.
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, "image/*".parse().unwrap());
        assert!(!accept_matches(&headers, DEFAULT_MEDIA_TYPE));
    }

    #[test]
    fn get_manifest_with_application_wildcard_accept_serves_200() {
        // End-to-end parity with the accept_matches tests: a GET with
        // `Accept: application/*` against an
        // `application/vnd.oci.image.manifest.v1+json` manifest gets
        // the manifest served, not a 406.
        let content = br#"{"schemaVersion":2}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";
        let (status, content_type) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_manifest(
                &h.artifacts,
                &h.storage,
                &h.metadata,
                repo_id,
                &hex,
                &content,
                Some(media),
                QuarantineStatus::None,
            );
            let router = manifest_router(h.ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, "application/*")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let content_type = resp
                .headers()
                .get(CONTENT_TYPE)
                .map(|v| v.to_str().unwrap().to_string());
            (status, content_type)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some(media));
    }

    /// Visibility regression guard (ADR 0008): anonymous
    /// `GET /v2/<private-repo>/<name>/manifests/<ref>` MUST return
    /// `404 NAME_UNKNOWN` (anti-enumeration). `RepositoryAccessUseCase`
    /// enforces Read at the resolve site and collapses invisible-private
    /// to NotFound.
    #[test]
    fn anonymous_get_on_private_repo_returns_404_name_unknown() {
        use hort_app::rbac::RbacEvaluator;
        use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
        use hort_http_core::test_support::with_repository_access;

        let content = b"private manifest body".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let (status, body) = run(async {
            let h = harness();
            let mut repo = oci_repo("private-repo");
            repo.is_public = false;
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let (_id, hash) = seed_manifest(
                &h.artifacts,
                &h.storage,
                &h.metadata,
                repo_id,
                &hex,
                &content,
                Some("application/vnd.oci.image.manifest.v1+json"),
                QuarantineStatus::None,
            );

            // Flip access use case to Enabled; anonymous = NotFound
            // (ADR 0008). `ctx.repositories` is `pub(crate)` so pull the
            // `Arc<MockRepositoryRepository>` off the harness handle.
            let access = Arc::new(RepositoryAccessUseCase::new(
                h.repositories.clone(),
                RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                    RbacEvaluator::new(Vec::new()),
                ))),
                true,
            ));
            let ctx = with_repository_access(&h.ctx, access);

            let router = manifest_router(ctx);
            // Pull by digest reference; the path's tail-parser routes
            // to manifests::serve.
            let uri = format!(
                "/v2/private-repo/library/nginx/manifests/sha256:{}",
                hash.as_ref()
            );
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "anonymous read on private OCI manifest MUST be 404 (ADR 0008)"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Anti-enumeration: NAME_UNKNOWN (the visible miss collapses
        // at the repo resolve before the manifest lookup ever runs).
        assert_eq!(
            parsed["errors"][0]["code"], "NAME_UNKNOWN",
            "envelope must match the missing-repo case to defeat probing"
        );
    }

    // ---------------------------------------------------------------------
    // Manifest pull-through acceptance tests
    //
    // Cover the six outcomes of `try_upstream_manifest_pull` end-to-end
    // through the public router, mirroring the blob pull-through harness
    // in `blobs.rs::cache_miss_with_upstream_mapping_fetches_and_serves`.
    // ---------------------------------------------------------------------

    const UP_PREFIX: &str = "dockerhub/";
    const UP_URL: &str = "https://registry.example.com";
    const UP_NAME: &str = "library/nginx";

    fn seed_upstream_mapping(mocks: &hort_http_core::test_support::MockPorts, repo_id: Uuid) {
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };
        let now = Utc::now();
        mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            path_prefix: UP_PREFIX.into(),
            upstream_url: UP_URL.into(),
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
    }

    /// Tag pull, no local cache, upstream serves the manifest →
    /// 200 + body, AND the tag→digest mapping is written so a
    /// subsequent local resolve hits the cache.
    #[test]
    fn pull_through_by_tag_ingests_and_writes_tag_mapping() {
        use hort_domain::ports::ref_registry::RefRegistryPort;
        use hort_domain::ports::upstream_proxy::ManifestFetch;

        let content = br#"{"schemaVersion":2,"upstream":"yes"}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";

        let (status, body, mref) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            seed_upstream_mapping(&mocks, repo_id);
            mocks.upstream_proxy.insert_manifest(
                UP_PREFIX,
                UP_NAME,
                "v1",
                ManifestFetch {
                    bytes: content.clone(),
                    media_type: media.into(),
                    declared_digest: Some(format!("sha256:{hex}")),
                    last_modified: None,
                },
            );

            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/v1");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, media)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            // Verify the tag→digest mapping was written via RefUseCase::set.
            let ns = format!("{UP_PREFIX}{UP_NAME}");
            let mref = mocks.refs.find(repo_id, &ns, "v1").await.ok();
            (status, body, mref)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, content);
        let mref = mref.expect("tag→digest mapping must have been written");
        match mref.target {
            RefTarget::ContentHash(h) => assert_eq!(h.as_ref(), hex.as_str()),
            RefTarget::Version(v) => panic!("expected ContentHash, got Version({v})"),
        }
    }

    /// Digest pull, no local cache, upstream serves the manifest →
    /// 200 + body. No tag mapping written (digest pulls bypass
    /// the tag→digest cache write).
    #[test]
    fn pull_through_by_digest_ingests_and_serves() {
        use hort_domain::ports::upstream_proxy::ManifestFetch;

        let content = br#"{"schemaVersion":2,"by":"digest"}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";
        let digest_ref = format!("sha256:{hex}");

        let (status, body) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            seed_upstream_mapping(&mocks, repo_id);
            mocks.upstream_proxy.insert_manifest(
                UP_PREFIX,
                UP_NAME,
                &digest_ref,
                ManifestFetch {
                    bytes: content.clone(),
                    media_type: media.into(),
                    declared_digest: Some(digest_ref.clone()),
                    last_modified: None,
                },
            );

            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/{digest_ref}");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, media)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, content);
    }

    /// Manifest pull-through threads `ManifestFetch.last_modified`
    /// onto the minted `Artifact.upstream_published_at`. Symmetric with
    /// the OCI blob path tested in `blobs.rs`; without this,
    /// `trust_upstream_publish_time = true` would release every
    /// layer/config blob in an image on its own upstream age while the
    /// manifest stayed anchored on `ingested_at` and 503'd `docker pull`
    /// after every other artifact already passed quarantine.
    #[test]
    fn manifest_upstream_published_at_threaded_from_last_modified() {
        use chrono::DateTime;
        use hort_domain::ports::upstream_proxy::ManifestFetch;

        let content = br#"{"schemaVersion":2,"by":"digest-lm"}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";
        let digest_ref = format!("sha256:{hex}");
        let last_modified: DateTime<Utc> = DateTime::parse_from_rfc3339("2024-07-04T18:30:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let recorded_published_at = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            seed_upstream_mapping(&mocks, repo_id);
            mocks.upstream_proxy.insert_manifest(
                UP_PREFIX,
                UP_NAME,
                &digest_ref,
                ManifestFetch {
                    bytes: content.clone(),
                    media_type: media.into(),
                    declared_digest: Some(digest_ref.clone()),
                    last_modified: Some(last_modified),
                },
            );

            let lifecycle = mocks.lifecycle.clone();
            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/{digest_ref}");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, media)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                1,
                "expected exactly one Artifact transition (the manifest ingest)"
            );
            transitions[0].0.upstream_published_at
        });

        assert_eq!(
            recorded_published_at,
            Some(last_modified),
            "OCI manifest Last-Modified must thread onto \
             Artifact.upstream_published_at via VerifiedIngestRequest"
        );
    }

    /// `None` `Last-Modified` on the manifest fetch yields a
    /// `None` artifact hint. Common case (Docker Hub's `Last-Modified`
    /// is often on the blob, not the manifest); must not error or
    /// silently substitute `ingested_at`.
    #[test]
    fn manifest_upstream_published_at_none_when_last_modified_absent() {
        use hort_domain::ports::upstream_proxy::ManifestFetch;

        let content = br#"{"schemaVersion":2,"by":"digest-no-lm"}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";
        let digest_ref = format!("sha256:{hex}");

        let recorded_published_at = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            seed_upstream_mapping(&mocks, repo_id);
            mocks.upstream_proxy.insert_manifest(
                UP_PREFIX,
                UP_NAME,
                &digest_ref,
                ManifestFetch {
                    bytes: content.clone(),
                    media_type: media.into(),
                    declared_digest: Some(digest_ref.clone()),
                    last_modified: None,
                },
            );

            let lifecycle = mocks.lifecycle.clone();
            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/{digest_ref}");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, media)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            transitions[0].0.upstream_published_at
        });

        assert_eq!(
            recorded_published_at, None,
            "absent Last-Modified must yield None, not an ingest failure \
             or a fallback to ingested_at"
        );
    }

    /// No upstream mapping configured → 404 MANIFEST_UNKNOWN
    /// (behaviour for repos without an upstream).
    #[test]
    fn pull_through_not_configured_returns_404_manifest_unknown() {
        let (status, body) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            mocks.repositories.insert(repo);
            // No upstream mapping seeded.
            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/missing-tag");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
        assert_eq!(parsed["errors"][0]["detail"]["reference"], "missing-tag");
    }

    /// Mapping configured, upstream returns "not found" → 404
    /// MANIFEST_UNKNOWN (the upstream confirms absence; same wire
    /// shape as a local-only miss).
    #[test]
    fn pull_through_upstream_not_found_returns_404_manifest_unknown() {
        let (status, body) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            seed_upstream_mapping(&mocks, repo_id);
            // No insert_manifest — mock returns the `upstream:not_found`
            // sentinel that the helper's classifier maps to
            // UpstreamNotFound.
            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/no-such-tag");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }

    /// Digest pull, upstream returns bytes whose SHA-256 disagrees
    /// with the requested digest → 502 BAD_GATEWAY.
    /// `IngestUseCase::ingest` emits `Conflict` because
    /// `declared_sha256` (the requested digest) does not match the
    /// computed hash; the helper collapses that to ChecksumMismatch.
    #[test]
    fn pull_through_checksum_mismatch_returns_502() {
        use hort_domain::ports::upstream_proxy::ManifestFetch;

        // Ask for digest_a but ship body_b. The helper sets
        // declared_sha256 = digest_a; the ingest computes sha256(body_b)
        // and rejects on Conflict.
        let body_a = br#"{"schemaVersion":2,"a":true}"#.to_vec();
        let body_b = br#"{"schemaVersion":2,"b":true}"#.to_vec();
        let hex_a = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&body_a))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";
        let digest_ref = format!("sha256:{hex_a}");

        let (status, body) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            seed_upstream_mapping(&mocks, repo_id);
            mocks.upstream_proxy.insert_manifest(
                UP_PREFIX,
                UP_NAME,
                &digest_ref,
                ManifestFetch {
                    bytes: body_b.clone(),
                    media_type: media.into(),
                    declared_digest: Some(digest_ref.clone()),
                    last_modified: None,
                },
            );

            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/{digest_ref}");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, media)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        assert_eq!(
            parsed["errors"][0]["detail"]["reason"],
            "upstream manifest digest did not match request digest"
        );
    }

    /// Regression guard: skopeo pulls a multi-arch tag like
    /// `alpine:3.19`, the upstream returns
    /// `application/vnd.oci.image.index.v1+json`, the pull-through
    /// ingests it cleanly, and skopeo's request carries the standard
    /// containers/image multi-Accept set (image manifest, image index,
    /// Docker manifest, Docker manifest list). Server MUST serve `200`
    /// with the index body and `Content-Type` echoing the index media
    /// type so docker / skopeo dispatch correctly.
    ///
    /// Previously the pull-through ingested the index but the immediate
    /// serve-back returned 406 `MANIFEST_UNKNOWN` (`manifest media type
    /// not acceptable`). Pin the multi-Accept skopeo flow so a
    /// regression that re-breaks index serving is caught here, not in
    /// the e2e.
    #[test]
    fn pull_through_by_tag_serves_oci_image_index_to_skopeo_multi_accept() {
        use hort_domain::ports::upstream_proxy::ManifestFetch;

        // Synthetic image-index payload — skopeo only inspects the
        // bytes after we serve them back; we just need the SHA-256
        // for the digest header check.
        let content = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let index_media = "application/vnd.oci.image.index.v1+json";
        // The Accept header containers/image (skopeo) sends by default —
        // covers OCI single-image + OCI index + Docker v2 manifest +
        // Docker v2 manifest list.
        let skopeo_accept = "application/vnd.oci.image.manifest.v1+json, \
                             application/vnd.oci.image.index.v1+json, \
                             application/vnd.docker.distribution.manifest.v2+json, \
                             application/vnd.docker.distribution.manifest.list.v2+json";

        let (status, content_type, body) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            seed_upstream_mapping(&mocks, repo_id);
            mocks.upstream_proxy.insert_manifest(
                UP_PREFIX,
                UP_NAME,
                "3.19",
                ManifestFetch {
                    bytes: content.clone(),
                    media_type: index_media.into(),
                    declared_digest: Some(format!("sha256:{hex}")),
                    last_modified: None,
                },
            );

            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/3.19");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, skopeo_accept)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let content_type = resp
                .headers()
                .get(CONTENT_TYPE)
                .map(|v| v.to_str().unwrap().to_string());
            let body = to_bytes(resp.into_body(), 16 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, content_type, body)
        });
        assert_eq!(
            status,
            StatusCode::OK,
            "skopeo's multi-Accept must serve a freshly-ingested image-index without 406"
        );
        assert_eq!(content_type.as_deref(), Some(index_media),
            "Content-Type echo must match the upstream-supplied media type so docker/skopeo dispatch on it correctly");
        assert_eq!(body, content);
    }

    /// Mirror smoke regression: skopeo's default `skopeo copy` (no
    /// `--all`) sends `Accept: application/vnd.oci.image.manifest.v1+json`
    /// only — index types are NOT in the Accept set. Docker Hub's
    /// `alpine:3.19` is multi-arch and the upstream returns an
    /// `application/vnd.oci.image.index.v1+json` regardless. The
    /// pull-through ingests the index correctly. The serve-back must
    /// then return 200 with the index body (Content-Type echoing
    /// the index media-type), not 406, because every real registry
    /// (Docker Hub, GHCR, Quay, Harbor) does the same and every real
    /// client (skopeo, docker, podman, containerd) handles it. A
    /// strict 406 here breaks the mirror use case for every
    /// multi-arch image, which is most of them.
    ///
    /// Cross-vendor symmetry: same expectation for Docker v2
    /// manifest list when the request Accept is just the Docker v2
    /// manifest type.
    #[test]
    fn pull_through_oci_index_served_to_single_manifest_accept() {
        use hort_domain::ports::upstream_proxy::ManifestFetch;

        let content = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let index_media = "application/vnd.oci.image.index.v1+json";
        // The skopeo single-platform copy default — only the
        // single-image manifest type, no index types.
        let single_image_accept = "application/vnd.oci.image.manifest.v1+json";

        let (status, content_type, body) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            seed_upstream_mapping(&mocks, repo_id);
            mocks.upstream_proxy.insert_manifest(
                UP_PREFIX,
                UP_NAME,
                "3.19",
                ManifestFetch {
                    bytes: content.clone(),
                    media_type: index_media.into(),
                    declared_digest: Some(format!("sha256:{hex}")),
                    last_modified: None,
                },
            );

            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/3.19");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, single_image_accept)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let content_type = resp
                .headers()
                .get(CONTENT_TYPE)
                .map(|v| v.to_str().unwrap().to_string());
            let body = to_bytes(resp.into_body(), 16 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, content_type, body)
        });
        assert_eq!(
            status,
            StatusCode::OK,
            "stored OCI image index must be served when client asks for OCI single-image \
             manifest — every real registry does this and the mirror flow is unusable without it"
        );
        assert_eq!(
            content_type.as_deref(),
            Some(index_media),
            "Content-Type must echo the actual stored media-type so docker/skopeo dispatches \
             on it correctly"
        );
        assert_eq!(body, content);
    }

    /// Docker v2 mirror counterpart: stored Docker v2 manifest list,
    /// client Accept is just the Docker v2 single manifest. Same
    /// reasoning as the OCI variant — every real registry serves
    /// the list, every real client handles it.
    #[test]
    fn pull_through_docker_manifest_list_served_to_v2_manifest_accept() {
        use hort_domain::ports::upstream_proxy::ManifestFetch;

        let content = br#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[]}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let list_media = "application/vnd.docker.distribution.manifest.list.v2+json";
        let v2_manifest_accept = "application/vnd.docker.distribution.manifest.v2+json";

        let (status, content_type, body) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            seed_upstream_mapping(&mocks, repo_id);
            mocks.upstream_proxy.insert_manifest(
                UP_PREFIX,
                UP_NAME,
                "latest",
                ManifestFetch {
                    bytes: content.clone(),
                    media_type: list_media.into(),
                    declared_digest: Some(format!("sha256:{hex}")),
                    last_modified: None,
                },
            );

            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/latest");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, v2_manifest_accept)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let content_type = resp
                .headers()
                .get(CONTENT_TYPE)
                .map(|v| v.to_str().unwrap().to_string());
            let body = to_bytes(resp.into_body(), 16 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, content_type, body)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some(list_media));
        assert_eq!(body, content);
    }

    /// Negative regression guard: a request Accept that is genuinely
    /// disjoint from the stored type (e.g. `application/json`) must
    /// still 406. The index/manifest leniency is specific to OCI /
    /// Docker manifest type relationships, not a blanket bypass of
    /// content negotiation.
    #[test]
    fn pull_through_disjoint_accept_still_returns_406() {
        use hort_domain::ports::upstream_proxy::ManifestFetch;

        let content = br#"{"schemaVersion":2}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let (status, body) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            seed_upstream_mapping(&mocks, repo_id);
            mocks.upstream_proxy.insert_manifest(
                UP_PREFIX,
                UP_NAME,
                "v1",
                ManifestFetch {
                    bytes: content.clone(),
                    media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                    declared_digest: Some(format!("sha256:{hex}")),
                    last_modified: None,
                },
            );

            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/v1");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, "application/json")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 16 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, body)
        });
        assert_eq!(
            status,
            StatusCode::NOT_ACCEPTABLE,
            "genuinely disjoint Accept must still 406 — leniency is OCI/Docker manifest-pair \
             specific"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }

    /// Mapping configured, upstream returns a non-404 error (5xx /
    /// network) → 502 BAD_GATEWAY with the
    /// `upstream manifest fetch failed` reason.
    #[test]
    fn pull_through_upstream_unavailable_returns_502() {
        let (status, body) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            seed_upstream_mapping(&mocks, repo_id);
            // Inject a non-`not_found` error so the helper classifies
            // it as UpstreamUnavailable rather than UpstreamNotFound.
            mocks
                .upstream_proxy
                .fail_next_manifest_with(DomainError::Invariant(
                    "upstream:5xx:gateway timeout".into(),
                ));
            let router = manifest_router(ctx);
            let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/some-tag");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        assert_eq!(
            parsed["errors"][0]["detail"]["reason"],
            "upstream manifest fetch failed"
        );
    }

    /// Tag-mode pull whose upstream response omits
    /// `Docker-Content-Digest` MUST be refused with `502 BAD_GATEWAY`
    /// (ADR 0006). The pre-fix code fell back to
    /// `upstream_digest := sha256(received_bytes)`, making the
    /// `IngestUseCase::ingest_verified` comparison a tautology and
    /// emitting `ChecksumVerified` for self-verified content. That
    /// broke the chain of custody — `ChecksumVerified` must only attest
    /// to upstream-supplied digests.
    ///
    /// Acceptance bars enforced here:
    /// 1. Status is 502 Bad Gateway.
    /// 2. NO `ChecksumVerified` event was appended to the event store.
    /// 3. `hort_upstream_checksum_total{format="oci",result="checksum_missing"}`
    ///    ticked exactly once.
    #[test]
    fn pull_through_tag_missing_docker_content_digest_returns_502() {
        use hort_domain::events::DomainEvent;
        use hort_domain::ports::upstream_proxy::ManifestFetch;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let content = br#"{"schemaVersion":2,"naked":"yes"}"#.to_vec();
        let media = "application/vnd.oci.image.manifest.v1+json";

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let (status, body, appended_batches) = metrics::with_local_recorder(&recorder, || {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx(handle);
                let repo = oci_repo("myrepo");
                let repo_id = repo.id;
                mocks.repositories.insert(repo);

                seed_upstream_mapping(&mocks, repo_id);
                // Upstream returns the manifest body but omits
                // Docker-Content-Digest entirely (declared_digest = None).
                // In the pre-fix code this triggered the self-hash
                // fallback; post-fix it MUST be refused with 502 before
                // any ingest event fires.
                mocks.upstream_proxy.insert_manifest(
                    UP_PREFIX,
                    UP_NAME,
                    "v1",
                    ManifestFetch {
                        bytes: content.clone(),
                        media_type: media.into(),
                        declared_digest: None,
                        last_modified: None,
                    },
                );

                let router = manifest_router(ctx);
                let uri = format!("/v2/myrepo/{UP_PREFIX}{UP_NAME}/manifests/v1");
                let resp = router
                    .oneshot(
                        Request::get(&uri)
                            .header(ACCEPT, media)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
                let appended = mocks.events.appended_batches();
                (status, body, appended)
            })
        });

        // Acceptance bar 1: 502 Bad Gateway with the manifest envelope
        // and a `checksum_missing` reason.
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "tag pull whose upstream omits Docker-Content-Digest MUST 502"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        assert_eq!(
            parsed["errors"][0]["detail"]["reason"],
            "upstream did not supply Docker-Content-Digest for tag pull",
            "envelope must name the missing-digest reason so operators can diagnose"
        );

        // Acceptance bar 2: NO ChecksumVerified event landed in the
        // store. The pre-fix code self-hashed the bytes and emitted
        // ChecksumVerified; the audit invariant is that
        // ChecksumVerified only attests to upstream-supplied digests.
        let mut verified_events = 0usize;
        for batch in &appended_batches {
            for ev in &batch.events {
                if matches!(ev.event, DomainEvent::ChecksumVerified(_)) {
                    verified_events += 1;
                }
            }
        }
        assert_eq!(
            verified_events, 0,
            "ChecksumVerified MUST NOT fire when the upstream provided no digest to verify against"
        );

        // Acceptance bar 3: hort_upstream_checksum_total{result="checksum_missing"}
        // ticked exactly once for the OCI format.
        let snapshot = snapshotter.snapshot();
        let entries = snapshot.into_vec();
        let mut found_value: Option<u64> = None;
        for (ck, _, _, dv) in &entries {
            if ck.kind() != MetricKind::Counter || ck.key().name() != "hort_upstream_checksum_total"
            {
                continue;
            }
            let labels: std::collections::HashMap<&str, &str> =
                ck.key().labels().map(|l| (l.key(), l.value())).collect();
            if labels.get("format") == Some(&"oci")
                && labels.get("result") == Some(&"checksum_missing")
            {
                if let DebugValue::Counter(v) = dv {
                    found_value = Some(*v);
                }
            }
        }
        let names: Vec<&str> = entries
            .iter()
            .map(|(ck, _, _, _): &(CompositeKey, _, _, _)| ck.key().name())
            .collect();
        assert_eq!(
            found_value,
            Some(1),
            "hort_upstream_checksum_total{{format=oci,result=checksum_missing}} must tick exactly once; \
             seen metric names: {names:?}"
        );
    }

    // -- DB-error collapse guard ------------------------------------------

    #[test]
    fn get_manifest_returns_500_on_repo_lookup_infra_error() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories
                .fail_next_find_by_key(DomainError::Invariant("simulated pool exhaustion".into()));
            let router = manifest_router(h.ctx);
            let uri = "/v2/myrepo/library/nginx/manifests/some-tag";
            let resp = router
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        hort_http_core::error::assert_no_internal_leakage(status, &body);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "INTERNAL");
    }

    // ---- PullDedup wrap-coverage tests --------------------
    //
    // OCI manifest pull has two distinct dedup-key shapes:
    //
    //  - **Tag-ref** (no `:` in reference): `coalesce_to_hash` keyed on
    //    a metadata key `(format=oci, repo_id, /v2/{name}/manifests/{tag})`
    //    (broadcasts the resolved hash, not the bytes — ADR 0026).
    //  - **Digest-ref** (`sha256:<hex>` in reference): `coalesce_blob`
    //    keyed on `blob_by_hash("sha256", &hex)`.
    //
    // We test the tag-ref shape end-to-end here (concurrent +
    // negative-cache). The digest-ref shape shares the same
    // `coalesce_blob` mechanics as `try_upstream_blob_pull` (covered by
    // `blobs.rs` tests).

    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use metrics_util::CompositeKey;

    type SnapshotRow = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

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

    /// Render `UpstreamManifestPullOutcome`'s variant discriminator
    /// without depending on `Debug` (the `Ingested` variant carries
    /// an `Artifact` row that the production type intentionally does
    /// not derive `Debug` on).
    fn manifest_outcome_variant_name(o: &UpstreamManifestPullOutcome) -> &'static str {
        match o {
            UpstreamManifestPullOutcome::Ingested { .. } => "Ingested",
            UpstreamManifestPullOutcome::NotConfigured => "NotConfigured",
            UpstreamManifestPullOutcome::UpstreamNotFound => "UpstreamNotFound",
            UpstreamManifestPullOutcome::CurationBlocked => "CurationBlocked",
            UpstreamManifestPullOutcome::ChecksumMismatch => "ChecksumMismatch",
            UpstreamManifestPullOutcome::UpstreamUnavailable => "UpstreamUnavailable",
            UpstreamManifestPullOutcome::UpstreamDigestMissing => "UpstreamDigestMissing",
            UpstreamManifestPullOutcome::ManifestTooLarge { .. } => "ManifestTooLarge",
            UpstreamManifestPullOutcome::Internal => "Internal",
        }
    }

    /// Concurrent-coalesce test (tag-ref path): spawn two
    /// `tokio::spawn` requests against the same OCI manifest tag.
    /// The wrapped `coalesce_to_hash` call site at the manifest
    /// fetch leg must route both into a single coalescing window —
    /// exactly one `leader_started` increment, ≥ 1
    /// `follower_waited_hit` increment.
    #[test]
    fn concurrent_manifest_tag_callers_coalesce_into_one_leader_started() {
        use hort_domain::ports::upstream_proxy::ManifestFetch;

        let snap = capture_metrics(|| async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("oci-mirror");
            let repo_id = repo.id;
            mocks.repositories.insert(repo.clone());
            seed_upstream_mapping(&mocks, repo_id);

            let content = br#"{"schemaVersion":2,"coalesce-test":true}"#.to_vec();
            let hex = {
                use sha2::Digest;
                format!("{:x}", sha2::Sha256::digest(&content))
            };
            let media = "application/vnd.oci.image.manifest.v1+json";
            mocks.upstream_proxy.insert_manifest(
                UP_PREFIX,
                UP_NAME,
                "v1",
                ManifestFetch {
                    bytes: content.clone(),
                    media_type: media.into(),
                    declared_digest: Some(format!("sha256:{hex}")),
                    last_modified: None,
                },
            );

            let ctx_a = ctx.clone();
            let repo_a = repo.clone();
            // The resolver matches by `path_prefix` against the
            // requested name; the dispatcher passes the full
            // `<prefix><upstream_name>` (`dockerhub/library/nginx`),
            // not the bare upstream name.
            let full_name = format!("{UP_PREFIX}{UP_NAME}");
            let full_name_a = full_name.clone();
            let h1 = tokio::spawn(async move {
                try_upstream_manifest_pull(
                    &ctx_a,
                    &repo_a,
                    &full_name_a,
                    "v1",
                    vec![media.to_string()],
                )
                .await
            });
            let ctx_b = ctx.clone();
            let repo_b = repo.clone();
            let full_name_b = full_name.clone();
            let h2 = tokio::spawn(async move {
                try_upstream_manifest_pull(
                    &ctx_b,
                    &repo_b,
                    &full_name_b,
                    "v1",
                    vec![media.to_string()],
                )
                .await
            });

            let r1 = h1.await.unwrap();
            let r2 = h2.await.unwrap();
            // Both callers must see Ingested regardless of leader/
            // follower election — the post-coalesce
            // `find_in_repo_by_hash` resolves the row the leader's
            // ingest wrote.
            assert!(
                matches!(r1, UpstreamManifestPullOutcome::Ingested { .. }),
                "task 1 must succeed (leader OR follower) with Ingested; got variant {}",
                manifest_outcome_variant_name(&r1)
            );
            assert!(
                matches!(r2, UpstreamManifestPullOutcome::Ingested { .. }),
                "task 2 must succeed (leader OR follower) with Ingested; got variant {}",
                manifest_outcome_variant_name(&r2)
            );
        });

        let leader_started = sum_counter_for_outcome(&snap, "leader_started");
        let follower_waited_hit = sum_counter_for_outcome(&snap, "follower_waited_hit");
        assert!(
            leader_started >= 1,
            "expected ≥1 leader_started across the wrapped manifest call site; \
             got {leader_started}, snap: {snap:?}"
        );
        assert!(
            follower_waited_hit >= 1,
            "expected ≥1 follower_waited_hit (concurrent coalesce); \
             got {follower_waited_hit}, snap: {snap:?}"
        );
    }

    /// The tag-pull leg broadcasts the resolved content HASH
    /// (`coalesce_to_hash` → `SucceededBlob`), NOT the manifest bytes
    /// (ADR 0026). The terminal dedup record persisted under the manifest
    /// tag's metadata key must be a `succeeded_blob` (hash), never a
    /// `succeeded_metadata` (base64 bytes) — manifest bytes no longer
    /// transit the ephemeral store / Redis. A follower joining that
    /// broadcast resolves the artifact via `find_in_repo_by_hash` with
    /// only the hash + CAS, no bytes.
    #[test]
    fn tag_pull_broadcasts_hash_not_manifest_bytes() {
        use hort_domain::ports::ephemeral_store::EphemeralStore;
        use hort_domain::ports::upstream_proxy::ManifestFetch;

        let content = br#"{"schemaVersion":2,"hash-broadcast":true}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";

        let (outcome_variant, stored_kind) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("oci-mirror");
            let repo_id = repo.id;
            mocks.repositories.insert(repo.clone());
            seed_upstream_mapping(&mocks, repo_id);

            mocks.upstream_proxy.insert_manifest(
                UP_PREFIX,
                UP_NAME,
                "v1",
                ManifestFetch {
                    bytes: content.clone(),
                    media_type: media.into(),
                    declared_digest: Some(format!("sha256:{hex}")),
                    last_modified: None,
                },
            );

            let full_name = format!("{UP_PREFIX}{UP_NAME}");
            let r1 =
                try_upstream_manifest_pull(&ctx, &repo, &full_name, "v1", vec![media.to_string()])
                    .await;

            // Inspect the persisted terminal dedup record under the
            // manifest tag's metadata key. The key shape is the one
            // `DedupKey::metadata("oci", repo_id, "/v2/<name>/manifests/<tag>")`
            // serialises to (`pulldedup:meta:oci:<repo_id>:<path>`).
            let manifest_path = format!("/v2/{full_name}/manifests/v1");
            let dedup_key = format!("pulldedup:meta:oci:{repo_id}:{manifest_path}");
            let stored = mocks
                .ephemeral_evictable
                .get(&dedup_key)
                .await
                .expect("ephemeral get ok")
                .expect("terminal dedup record persisted under the tag's metadata key");
            let parsed: serde_json::Value =
                serde_json::from_slice(&stored).expect("dedup record is JSON");
            let kind = parsed["kind"].as_str().unwrap_or("<none>").to_string();
            (manifest_outcome_variant_name(&r1).to_string(), kind)
        });

        assert_eq!(
            outcome_variant, "Ingested",
            "tag pull must succeed and ingest the manifest"
        );
        assert_eq!(
            stored_kind, "succeeded_blob",
            "tag-pull leg must broadcast the resolved HASH (succeeded_blob), \
             NOT the manifest bytes (succeeded_metadata) — ADR 0026"
        );
    }

    /// Negative-cache test (tag-ref path): the wrapped
    /// `fetch_manifest` fails (transport-level error via
    /// `fail_next_manifest_with`). The leader records the failure
    /// under the manifest's `metadata` dedup key with the
    /// configured negative-cache TTL (default 30 s for `NotFound`).
    /// A second call within the TTL window must short-circuit on
    /// `negative_cache_hit` without firing a second `leader_started`.
    #[test]
    fn negative_cache_short_circuits_repeated_failures_within_ttl() {
        let media = "application/vnd.oci.image.manifest.v1+json";

        let snap = capture_metrics(|| async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("oci-mirror");
            let repo_id = repo.id;
            mocks.repositories.insert(repo.clone());
            seed_upstream_mapping(&mocks, repo_id);

            // First call: stage a one-shot transport failure on the
            // next `fetch_manifest`. The leader records `Failed`
            // under the manifest tag's dedup key.
            mocks
                .upstream_proxy
                .fail_next_manifest_with(DomainError::Invariant(
                    "upstream:not_found:manifest".into(),
                ));
            let full_name = format!("{UP_PREFIX}{UP_NAME}");
            let r1 =
                try_upstream_manifest_pull(&ctx, &repo, &full_name, "v1", vec![media.to_string()])
                    .await;
            assert!(
                matches!(r1, UpstreamManifestPullOutcome::UpstreamNotFound),
                "first call must surface the upstream not_found as UpstreamNotFound; \
                 got variant {}",
                manifest_outcome_variant_name(&r1)
            );

            // Second call within the negative-cache TTL window: the
            // `fail_next_manifest_with` queue is drained — if the
            // orchestrator re-issued the upstream fetch, it would
            // hit the absent-fixture path (which the mock returns
            // as a fresh `upstream:not_found` Err), counting as
            // `leader_started` again. The negative-cache short-
            // circuit prevents that.
            let r2 =
                try_upstream_manifest_pull(&ctx, &repo, &full_name, "v1", vec![media.to_string()])
                    .await;
            assert!(
                !matches!(r2, UpstreamManifestPullOutcome::Ingested { .. }),
                "second call must surface the cached failure (NOT a fresh ingest); \
                 got variant {}",
                manifest_outcome_variant_name(&r2)
            );
        });

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

    /// When the served repo opts in (ADR 0020), an anonymous OCI manifest
    /// pull-by-digest emits exactly one `ArtifactDownloaded` on the
    /// per-(repo, UTC-date) DownloadAudit stream with
    /// `DownloadActor::Anonymous`, never on the artifact aggregate stream.
    /// The manifest handler's `actor` fn param is compile-required by
    /// `ArtifactUseCase::download`.
    #[test]
    fn download_audit_emits_anonymous_when_repo_opted_in() {
        use hort_domain::events::{DomainEvent, DownloadActor, StreamCategory};

        let content = br#"{"schemaVersion":2}"#.to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let media = "application/vnd.oci.image.manifest.v1+json";

        let (status, batches, repo_id) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = oci_repo("oci-audit");
            repo.download_audit_enabled = true;
            let repo_id = repo.id;
            mocks.repositories.insert(repo);
            seed_manifest(
                &mocks.artifacts,
                &mocks.storage,
                &mocks.artifact_metadata,
                repo_id,
                &hex,
                &content,
                Some(media),
                QuarantineStatus::None,
            );
            let events = mocks.events.clone();
            let router = manifest_router(ctx);
            let uri = format!("/v2/oci-audit/library/nginx/manifests/sha256:{hex}");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header(ACCEPT, media)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            (status, events.appended_batches(), repo_id)
        });
        assert_eq!(status, StatusCode::OK);

        let dl: Vec<_> = batches
            .iter()
            .flat_map(|b| b.events.iter().map(move |e| (b, &e.event)))
            .filter(|(_, e)| matches!(e, DomainEvent::ArtifactDownloaded(_)))
            .collect();
        assert_eq!(dl.len(), 1, "exactly one ArtifactDownloaded emitted");
        let (batch, ev) = dl[0];
        assert_eq!(batch.stream_id.category, StreamCategory::DownloadAudit);
        assert_ne!(
            batch.stream_id,
            hort_domain::events::StreamId::artifact(repo_id),
            "never the artifact aggregate stream"
        );
        match ev {
            DomainEvent::ArtifactDownloaded(e) => {
                assert_eq!(e.repository_id, repo_id);
                assert!(
                    matches!(e.actor, DownloadActor::Anonymous),
                    "anonymous oci manifest pull → DownloadActor::Anonymous"
                );
            }
            _ => unreachable!(),
        }
    }
}
