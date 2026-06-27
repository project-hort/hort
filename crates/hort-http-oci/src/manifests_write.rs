//! OCI manifest write path — `PUT` + `DELETE /v2/:repo_key/*name/manifests/:ref`.
//!
//! Deliberately split from [`super::manifests`] (the read path) for
//! review cohesion — the PUT handler composes four use cases
//! ([`IngestUseCase`](hort_app::use_cases::ingest_use_case::IngestUseCase),
//! [`ArtifactGroupUseCase`](hort_app::use_cases::artifact_group_use_case::ArtifactGroupUseCase),
//! [`RefUseCase`](hort_app::use_cases::ref_use_case::RefUseCase), and
//! [`ContentReferenceIndex`](hort_domain::ports::content_reference_index::ContentReferenceIndex))
//! behind a causation-chain contract that the read path doesn't touch,
//! so keeping them in one file would bloat both. The read/write split
//! mirrors the separation in the OCI Distribution Spec read/write surface.
//!
//! # Workflow summary (PUT)
//!
//! 1. Parse `<name>/manifests/<ref>` from the `*tail` capture; reject
//!    malformed shapes as `NAME_UNKNOWN`.
//! 2. Validate `Content-Type` against
//!    [`SUPPORTED_MANIFEST_MEDIA_TYPES`]. Reject outside the allowlist
//!    as `MANIFEST_INVALID` — index / manifest-list media types land on
//!    the same 400 envelope per the index-support deferral.
//! 3. Pre-compute the manifest body's SHA-256 **before** calling
//!    [`IngestUseCase::ingest`]. On a digest-reference PUT the declared
//!    digest is compared against the computed hash via
//!    `declared_sha256`; a mismatch surfaces as
//!    [`AppError::Domain`](hort_app::error::AppError::Domain) with
//!    [`DomainError::Conflict`](hort_domain::error::DomainError::Conflict)
//!    and rolls back the CAS blob — the handler maps it to 400
//!    `MANIFEST_INVALID`. On a tag PUT
//!    the computed hash is used to mint the response's `Location`
//!    header and `Docker-Content-Digest`.
//! 4. Parse the manifest JSON for `config.digest` + `layers[*].digest`.
//!    Resolve each referenced blob through
//!    [`ArtifactRepository::find_by_checksum`]; enforce
//!    `artifact.repository_id == repo` (cross-repo isolation). Any
//!    missing blob returns 400 `MANIFEST_BLOB_UNKNOWN` with a
//!    `detail.blobs` array. The manifest artifact stays committed so
//!    the client's retry-after-pushing-blobs path is idempotent; the
//!    group is NOT created.
//! 5. Attach manifest + config + layers to the group via
//!    [`ArtifactGroupUseCase::add_member`]. Shared per-request
//!    `correlation_id`; every call threads `causation_id =
//!    Some(manifest_event_id)` — the audit-trail contract.
//! 6. Tag-reference PUTs call
//!    [`RefUseCase::set`](hort_app::use_cases::ref_use_case::RefUseCase::set)
//!    with `RefTarget::ContentHash(manifest_digest)`. Digest-reference
//!    PUTs skip this step (digest is self-naming).
//! 7. If the manifest carries `subject.digest`, insert a
//!    [`ContentReference`] row with `kind = "oci_subject"`.
//!
//! Response: 201 + `Location: /v2/<repo_key>/<name>/manifests/<ref>` +
//! `Docker-Content-Digest: sha256:<hex>`. Empty body.
//!
//! # DELETE
//!
//! Tag references route through [`RefUseCase::retire`]; digest
//! references look up the manifest artifact via `find_by_path`, call
//! [`ContentReferenceIndex::delete_by_source`], then remove the
//! artifact via [`ArtifactUseCase::delete`]. CAS blob lifetime is GC's
//! concern — the DELETE handler never touches storage directly.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
#[cfg(test)]
use axum::Router;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::use_cases::ingest_use_case::VerifiedIngestRequest;
use hort_domain::entities::artifact::Artifact;
use hort_domain::entities::mutable_ref::RefTarget;
use hort_domain::error::DomainError;
use hort_domain::events::{Actor, ApiActor};
use hort_domain::ports::content_reference_index::ContentReference;
use hort_domain::types::ContentHash;
use hort_formats::oci::OciFormatHandler;

use hort_http_core::authz::{DeleteRepoAccess, WriteRepoAccess};
use hort_http_core::context::AppContext;
use hort_http_core::limits::BoundedPath;

use super::coords::{oci_group_coords, oci_manifest_coords};
use super::digest::{parse_digest, DigestParse};
use super::error::OciError;
use super::name::validate_oci_name;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Manifest media-types accepted on `PUT`. Anything outside the
/// allowlist is rejected as `MANIFEST_INVALID`.
///
/// Manifest-index / manifest-list media types are in the allowlist
/// (Docker Hub + OCI both accept them on PUT in production), but the
/// JSON parser here only understands the single-image shape
/// (`config`, `layers[]`). An index PUT therefore lands in the allowlist
/// but fails at the JSON-parse step — see [`parse_manifest_blobs`] for
/// the explicit deferral.
const SUPPORTED_MANIFEST_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v1+json",
];

/// Media types that represent multi-manifest indexes / lists. An index
/// push is explicitly deferred — the JSON shape differs from single-image
/// manifests (it carries `manifests[]`, not `config` + `layers[]`), and
/// full index support requires threading manifest-of-manifests membership
/// into the group model. Rejecting the index at parse time keeps the
/// contract clear until the follow-up item lands.
const MANIFEST_INDEX_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

/// Upper bound on the manifest body read into memory before parsing.
/// OCI manifests are typically a few KB; a 1 MiB ceiling accommodates
/// every real-world manifest while capping the memory cost of a
/// pathological client sending megabytes of junk. Exceeding this is a
/// `MANIFEST_INVALID` (not `SIZE_INVALID` — size applies to blobs).
const MANIFEST_BODY_MAX_BYTES: usize = 1024 * 1024;

/// Upper bound on the number of distinct blob references (`config`
/// digest plus `layers[*].digest`) a single manifest may carry.
///
/// The 1 MiB body cap above stops gross OOM, but a packed JSON body
/// can fit ~10k pathologically dense `{"digest":"sha256:..."}` entries
/// within 1 MiB — and every referenced blob triggers a
/// `find_in_repo_by_hash` lookup against
/// the artifact repository in [`resolve_referenced_blobs`]. A real-
/// world OCI image carries tens of layers; 1024 is two orders of
/// magnitude past observed maxima. Exceeding it lands as
/// `MANIFEST_INVALID` per [`parse_manifest_blobs`]'s error envelope.
///
/// The cap is enforced **at parse time** so the resolution loop is
/// never entered for an over-cap manifest. Do NOT move this gate
/// into `resolve_referenced_blobs` — that would defeat the purpose
/// of the cap (the cost the cap protects against is N database
/// lookups, one per referenced blob).
const MAX_BLOB_REFERENCES: usize = 1024;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build a manifest write router for use INSIDE THIS CRATE'S TESTS.
///
/// Production routing flows through [`super::oci_routes_with_config`] →
/// the top-level `/v2/:repo_key/*tail` PUT dispatcher in `lib.rs`, which
/// peeks at the tail shape and forwards to either
/// [`put_manifest_dispatch`] (manifest PUT) or
/// [`super::uploads::put_upload_dispatch`] (blob PUT-finalize). DELETE
/// goes through [`delete_manifest_dispatch`] unconditionally because
/// the only DELETE on the OCI surface is on manifests. Production code
/// never invokes this builder — the test harness uses it to exercise
/// the manifest router in isolation.
#[cfg(test)]
fn router() -> Router<Arc<AppContext>> {
    Router::new().route(
        "/v2/:repo_key/*tail",
        axum::routing::put(put_manifest_dispatch).delete(delete_manifest_dispatch),
    )
}

// ---------------------------------------------------------------------------
// Tail parsing
// ---------------------------------------------------------------------------

/// Parsed `<name>/manifests/<reference>` tail for PUT/DELETE.
///
/// Separate from [`super::tail::TailKind`] because the manifest write
/// path is method-specific — adding a write-only variant to the shared
/// pull tail parser would pollute the GET dispatcher with an
/// unreachable arm.
struct ManifestTail<'a> {
    name: &'a str,
    reference: &'a str,
}

/// Extract `(name, reference)` from the `*tail` capture. The shape is
/// `<name>/manifests/<reference>`; `name` may be multi-segment
/// (`library/nginx`) and `reference` is either a tag (no `:`) or a
/// digest (`sha256:<hex>`). `rsplit_once` matches on the rightmost
/// `/manifests/` — OCI's name grammar reserves the word and forbids it
/// inside a legitimate image name, so the rightmost rule is unambiguous
/// (matches the pull-tail parser's behaviour).
fn parse_manifest_tail(tail: &str) -> Option<ManifestTail<'_>> {
    let (name, reference) = tail.rsplit_once("/manifests/")?;
    if name.is_empty() || reference.is_empty() {
        return None;
    }
    Some(ManifestTail { name, reference })
}

// ---------------------------------------------------------------------------
// PUT dispatch
// ---------------------------------------------------------------------------

/// Entry point for `PUT /v2/:repo_key/*tail`.
///
/// `WriteRepoAccess` runs as a `FromRequestParts` extractor before the
/// body is touched — resolving the repo and running the RBAC check up
/// front means an unauthorised caller never hits the manifest parser
/// (cheap-fail principle). The handler itself is a straight-line
/// composition of the workflow documented at the module head.
pub(crate) async fn put_manifest_dispatch(
    access: WriteRepoAccess,
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, tail)): BoundedPath<(String, String)>,
    request: Request<Body>,
) -> Response {
    let Some(ManifestTail { name, reference }) = parse_manifest_tail(&tail) else {
        return OciError::NameUnknown {
            repository: format!("{repo_key}/{tail}"),
        }
        .into_response();
    };
    // Validate the parsed `<name>` segment against the OCI Distribution
    // Spec name grammar BEFORE any storage, manifest, or upload action.
    // Rejecting on the pre-storage path keeps malformed names out of
    // `Artifact.name`, metric labels, log lines, and the manifest blob
    // CAS commit.
    if let Err(e) = validate_oci_name(name) {
        return super::name_invalid_response(e);
    }
    let name = name.to_string();
    let reference = reference.to_string();

    let repo_id = access.repository.id;
    let actor = ApiActor {
        user_id: access.principal.user_id,
    };

    // Shared per-request correlation_id threaded through every call the
    // handler issues downstream (ingest, add_member × N, ref set,
    // content_references insert). Load-bearing audit contract — see
    // audit-trail contract.
    let correlation_id = Uuid::new_v4();

    // Pull headers + body up front. Body reading is the one
    // unavoidable point of no return; subsequent failures must treat
    // the body as consumed. The 1 MiB cap applies here; axum's
    // `to_bytes` returns an `Err` if the body exceeds the limit — we
    // classify that as `MANIFEST_INVALID` (not `SIZE_INVALID`, which
    // is reserved for blob-upload limits).
    let headers = request.headers().clone();
    let body_bytes = match to_bytes(request.into_body(), MANIFEST_BODY_MAX_BYTES).await {
        Ok(b) => b.to_vec(),
        Err(_) => {
            return OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "manifest body too large or unreadable",
                    "max_bytes": MANIFEST_BODY_MAX_BYTES,
                })),
            }
            .into_response();
        }
    };

    // Content-Type allowlist.
    let media_type = match extract_media_type(&headers) {
        Ok(mt) => mt,
        Err(resp) => return *resp,
    };
    if !SUPPORTED_MANIFEST_MEDIA_TYPES.contains(&media_type.as_str()) {
        return OciError::ManifestInvalid {
            detail: Some(serde_json::json!({
                "reason": "unsupported manifest media type",
                "media_type": media_type,
            })),
        }
        .into_response();
    }

    // Pre-parse the manifest JSON for `subject.digest` (used in
    // `payload_metadata`) and, later, `config.digest` + `layers[*].digest`.
    // Invalid JSON at this step → 400 `MANIFEST_INVALID` per OCI spec
    // (unparseable JSON is an envelope-shape violation, not
    // UNSUPPORTED).
    let parsed_manifest: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "manifest body is not valid JSON",
                    "error": e.to_string(),
                })),
            }
            .into_response();
        }
    };

    // Explicit deferral: the manifest-index / list shape is in the
    // supported media-type allowlist but the JSON parser only handles
    // the single-image shape. Index support is deferred — it needs a
    // follow-up that threads manifest-of-manifests membership into the
    // group model.
    if MANIFEST_INDEX_MEDIA_TYPES.contains(&media_type.as_str()) {
        return OciError::ManifestInvalid {
            detail: Some(serde_json::json!({
                "reason": "manifest list / index not yet supported; push single-image manifests individually",
                "media_type": media_type,
            })),
        }
        .into_response();
    }

    // `subject.digest` may be absent — serde_json returns Null for a
    // missing key path, which we coerce to `None`.
    let subject_digest_str: Option<String> = parsed_manifest
        .get("subject")
        .and_then(|s| s.get("digest"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let artifact_type_opt: Option<String> = parsed_manifest
        .get("artifactType")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // N-5: pre-validate `subject.digest` BEFORE the manifest ingest commits.
    // The previous flow re-parsed the digest just before the
    // ContentReferenceIndex insert at the tail of the handler — by then
    // the manifest artifact + group + ref had already been committed, so
    // a malformed `subject.digest` produced a 500 with the manifest left
    // half-attached. Validating up front keeps the failure on the same
    // pre-commit path as config/layer digest validation: 400
    // MANIFEST_INVALID, no state change.
    let subject_digest_parsed: Option<ContentHash> = match subject_digest_str.as_deref() {
        None => None,
        Some(raw) => match parse_digest(raw) {
            DigestParse::Ok(h) => Some(h),
            DigestParse::Unsupported { algorithm } => {
                return OciError::ManifestInvalid {
                    detail: Some(serde_json::json!({
                        "reason": "subject digest uses unsupported algorithm",
                        "algorithm": algorithm,
                        "field": "subject.digest",
                    })),
                }
                .into_response();
            }
            DigestParse::Invalid { message } => {
                return OciError::ManifestInvalid {
                    detail: Some(serde_json::json!({
                        "reason": "subject digest malformed",
                        "message": message,
                        "field": "subject.digest",
                    })),
                }
                .into_response();
            }
        },
    };

    // Pre-compute the SHA-256 of the manifest body. Doing this before
    // calling `ingest` means (a) `declared_sha256` can be set on both
    // digest-ref AND tag-ref PUTs so mismatches are caught consistently,
    // (b) coords carry the real hash up front (no placeholder rewrite),
    // and (c) the response headers (`Location`,
    // `Docker-Content-Digest`) can be formatted before `ingest` runs
    // so their construction never participates in a partial-failure
    // rollback. Pre-compute is the recommended option in the Item
    // brief's workflow step 5 (a); the cost of a second SHA over a
    // manifest body is negligible (sub-millisecond for typical KB
    // manifests).
    let computed_hash = compute_sha256(&body_bytes);
    let reference_is_digest = reference.contains(':');

    // On a digest-ref PUT, compare the declared digest against the
    // computed one. Mismatch → 400 `MANIFEST_INVALID` BEFORE any state
    // change. A successful parse of the declared digest feeds into
    // `declared_sha256` below so `IngestUseCase::ingest` cannot commit
    // a manifest whose bytes disagree with the client's claim.
    let declared_hash: Option<ContentHash> = if reference_is_digest {
        match parse_digest(&reference) {
            DigestParse::Ok(h) => {
                if h != computed_hash {
                    return OciError::ManifestInvalid {
                        detail: Some(serde_json::json!({
                            "reason": "declared digest does not match manifest content",
                            "declared": format!("sha256:{}", h.as_ref()),
                            "computed": format!("sha256:{}", computed_hash.as_ref()),
                        })),
                    }
                    .into_response();
                }
                Some(h)
            }
            DigestParse::Unsupported { algorithm } => {
                // Well-formed but non-sha256 algorithm. The OCI
                // The spec pins `UNSUPPORTED` for a digest whose
                // algorithm is recognised but can't be processed.
                // This is the ONE path where UNSUPPORTED is correct
                // (vs DIGEST_INVALID).
                return OciError::Unsupported {
                    message: format!("unsupported digest algorithm: {algorithm}"),
                }
                .into_response();
            }
            DigestParse::Invalid { message } => {
                return OciError::ManifestInvalid {
                    detail: Some(serde_json::json!({
                        "reason": "malformed digest reference",
                        "error": message,
                    })),
                }
                .into_response();
            }
        }
    } else {
        // Tag-ref PUT: validate the tag against the OCI grammar (INJ-4 — the
        // same `validate_oci_tag` the GET/serve path uses) BEFORE it becomes
        // a stored ref, via the shared `tag_invalid_response` mapping (400
        // `MANIFEST_INVALID`, non-echoing reason). Mirrors the digest
        // branch's malformed-digest rejection above; rejects before any
        // ingest/state change.
        if let Err(e) = super::tag::validate_oci_tag(&reference) {
            return super::tag_invalid_response(e);
        }
        // Declare the computed hash so the ingest path has a consistent
        // post-storage check. `IngestUseCase::ingest` treats
        // `declared_sha256 = Some(computed)` as a tautology here, but
        // asserting it closes a latent window where a concurrent mutation
        // between compute and commit would slip through.
        Some(computed_hash.clone())
    };

    // Build the ingest request + stream. The body is an in-memory
    // `Vec<u8>` by the time we're here (the 1 MiB cap keeps this
    // cheap); wrap in a `Cursor` to get an `AsyncRead`.
    let manifest_coords = oci_manifest_coords(&name, &computed_hash);
    let payload_metadata = serde_json::json!({
        "oci_media_type": media_type,
        "oci_subject_digest": subject_digest_str,
    });
    // Manifest write: digest from request body (when reference is a
    // digest) or computed from bytes. Either way ProtocolNative is
    // correct because OCI's protocol embeds the digest in the request
    // itself (ADR 0006).
    let upstream_digest = declared_hash.unwrap_or_else(|| computed_hash.clone());
    let stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
        Box::new(std::io::Cursor::new(body_bytes.clone()));

    // Route a pushed cosign **signature** manifest (a *pure* Sigstore-bundle
    // referrer) to the narrow `ingest_signature_manifest` path instead of
    // the generic `ingest_verified` pipeline. Quarantine is an observation
    // window for time-deferred safety uncertainty; a Sigstore signature's
    // validity is deterministic and immediate, so quarantining / scanning /
    // provenance-verifying it is a category error.
    //
    // The exemption is gated on the manifest's declared media types, which a
    // write-authed pusher fully controls — so it is deliberately AIRTIGHT:
    // it fires **only** when the manifest carries a `subject.digest` AND
    // EVERY layer is signature material — either a Sigstore v0.3 bundle
    // (`is_pure_sigstore_bundle`, keyless) OR a cosign `simplesigning` layer
    // (`is_pure_simplesigning`, the keyed `cosign sign --key` shape, ADR 0039
    // §8). A mixed manifest (a signature layer plus a runnable `tar+gzip` layer)
    // does NOT match → it stays on `ingest_verified` and IS scanned. "Exempted"
    // ⟺ "carries no runnable content" — the anti-scan-evasion guard.
    //
    // Both predicates parse the manifest JSON; the body already parsed cleanly
    // above (`parsed_manifest`), so a parse error here is not expected. On the
    // off chance one errors, fail safe → generic path (`unwrap_or(false)`),
    // so the generic path scans/quarantines it — never a wrongful exemption.
    let is_pure_signature = subject_digest_parsed.is_some()
        && (hort_domain::oci::is_pure_sigstore_bundle(&body_bytes).unwrap_or(false)
            || hort_domain::oci::is_pure_simplesigning(&body_bytes).unwrap_or(false));

    // Ingest the manifest bytes. A `Conflict` here is the
    // declared-hash mismatch. The wire mapping
    // (Conflict -> ManifestInvalid) is preserved. The signature path
    // surfaces the same `Conflict` shape on a put-vs-declared mismatch.
    let ingest_result = if is_pure_signature {
        ctx.ingest_use_case
            .ingest_signature_manifest(
                repo_id,
                manifest_coords,
                media_type.clone(),
                actor.clone(),
                payload_metadata,
                upstream_digest,
                stream,
            )
            .await
    } else {
        let ingest_req = VerifiedIngestRequest::ProtocolNative {
            repository_id: repo_id,
            coords: manifest_coords,
            content_type: media_type.clone(),
            actor: actor.clone(),
            payload_metadata,
            upstream_digest,
            upstream_published_at: None,
            // Manifest write is OCI-direct (`PUT /v2/<name>/manifests/<reference>`):
            // no serving `RepositoryUpstreamMapping`, opt-in cannot apply (ADR 0007).
            trust_upstream_publish_time: false,
        };
        ctx.ingest_use_case
            .ingest_verified(ingest_req, stream, &OciFormatHandler)
            .await
    };
    let ingest_outcome = match ingest_result {
        Ok(o) => o,
        Err(AppError::Domain(DomainError::Conflict(_))) => {
            return OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "manifest ingest rejected declared digest",
                })),
            }
            .into_response();
        }
        Err(err) => {
            tracing::error!(error = %err, "OCI manifest ingest failed");
            return OciError::Internal.into_response();
        }
    };

    let manifest_artifact = ingest_outcome.artifact;
    let manifest_event_id = ingest_outcome.ingested_event_id;
    let manifest_digest = computed_hash.clone();

    // Parse config + layer digests. The parser recognises the single-
    // image shape only — an index media type would have been rejected
    // above. A missing / malformed digest inside the blob list lands
    // as `MANIFEST_INVALID`; in the current contract the manifest is
    // already committed, and the client can retry with a corrected
    // manifest (or push the blobs and retry). The partially-attached
    // state is permitted to persist.
    let referenced = match parse_manifest_blobs(&parsed_manifest) {
        Ok(r) => r,
        Err(detail) => {
            tracing::warn!(
                manifest_artifact_id = %manifest_artifact.id,
                "manifest parse failed post-ingest; artifact stays committed for client retry"
            );
            return OciError::ManifestInvalid {
                detail: Some(detail),
            }
            .into_response();
        }
    };

    // Resolve each referenced blob. Cross-repo isolation: a hash that
    // exists in a foreign repo counts as missing — the blob must live in
    // the same repo as the manifest (mount it across explicitly via
    // `POST /v2/.../blobs/uploads/?mount=...&from=...`).
    let (config_artifact, layer_artifacts, missing) =
        match resolve_referenced_blobs(&ctx, repo_id, &referenced).await {
            Ok(t) => t,
            Err(resp) => {
                tracing::error!("infrastructure error during blob resolution");
                return resp;
            }
        };
    if !missing.is_empty() {
        // The manifest artifact stays committed so a client retry after
        // pushing the missing blobs reconciles cleanly.
        // We do NOT create the group on this path.
        //
        // Group-attachment retry path: the manifest stays committed so
        // the client can push missing blobs and retry idempotently.
        tracing::info!(
            manifest_artifact_id = %manifest_artifact.id,
            missing = ?missing,
            "manifest referenced unknown blobs; group attachment deferred until client retry"
        );
        return OciError::ManifestBlobUnknown { blobs: missing }.into_response();
    }
    // Unwrap the resolved config + at-least-empty layer list. A valid
    // single-image manifest has a `config` object with a digest — if
    // `parse_manifest_blobs` accepted it, `resolve_referenced_blobs`
    // returns `Some(config_artifact)` (or one of the `missing` list
    // got populated above).
    let Some(config_artifact) = config_artifact else {
        // Defensive: reachable only if `parse_manifest_blobs` accepted
        // a manifest with no config AND `resolve_referenced_blobs`
        // didn't mark it missing. Current parser rejects missing
        // config, so this branch is an assertion.
        tracing::error!(
            manifest_artifact_id = %manifest_artifact.id,
            "resolve_referenced_blobs returned None config with empty missing list"
        );
        return OciError::Internal.into_response();
    };

    // Attach members to the group. Order: manifest (primary) first,
    // then config, then every layer. The shared `correlation_id` +
    // `causation_id = Some(manifest_event_id)` is the load-bearing
    // audit contract — the causation-integrity test reads the
    // recorded batches and asserts this on every member event.
    let group_coords = oci_group_coords(&name, &manifest_digest);
    let actor_any = Actor::Api(actor.clone());

    if let Err(e) = ctx
        .artifact_group_use_case
        .add_member(
            repo_id,
            group_coords.clone(),
            "manifest".into(),
            manifest_artifact.id,
            /* is_primary = */ true,
            actor_any.clone(),
            correlation_id,
            Some(manifest_event_id),
            Some(&repo_key),
            "oci",
        )
        .await
    {
        tracing::warn!(
            manifest_artifact_id = %manifest_artifact.id,
            stage = "group_attach_manifest",
            error = %e,
            "partial attachment; client retry will reconcile"
        );
        return OciError::Internal.into_response();
    }

    if let Err(e) = ctx
        .artifact_group_use_case
        .add_member(
            repo_id,
            group_coords.clone(),
            "config".into(),
            config_artifact.id,
            /* is_primary = */ false,
            actor_any.clone(),
            correlation_id,
            Some(manifest_event_id),
            Some(&repo_key),
            "oci",
        )
        .await
    {
        tracing::warn!(
            manifest_artifact_id = %manifest_artifact.id,
            stage = "group_attach_config",
            error = %e,
            "partial attachment; client retry will reconcile"
        );
        return OciError::Internal.into_response();
    }

    for layer in &layer_artifacts {
        if let Err(e) = ctx
            .artifact_group_use_case
            .add_member(
                repo_id,
                group_coords.clone(),
                "layer".into(),
                layer.id,
                /* is_primary = */ false,
                actor_any.clone(),
                correlation_id,
                Some(manifest_event_id),
                Some(&repo_key),
                "oci",
            )
            .await
        {
            tracing::warn!(
                manifest_artifact_id = %manifest_artifact.id,
                stage = "group_attach_layer",
                layer_id = %layer.id,
                error = %e,
                "partial attachment; client retry will reconcile"
            );
            return OciError::Internal.into_response();
        }
    }

    // Tag-ref PUT: set the ref. Digest-ref PUT: skip — the digest is
    // self-naming; creating a ref would be redundant.
    if !reference_is_digest {
        if let Err(e) = ctx
            .ref_use_case
            .set(
                repo_id,
                /* namespace */ &name,
                /* ref_name */ &reference,
                RefTarget::ContentHash(manifest_digest.clone()),
                actor.clone(),
                Some(&repo_key),
            )
            .await
        {
            tracing::warn!(
                manifest_artifact_id = %manifest_artifact.id,
                stage = "ref_set",
                error = %e,
                "partial attachment; client retry will reconcile"
            );
            return OciError::Internal.into_response();
        }
    }

    // Insert the content-reference row if the manifest carries
    // `subject.digest`. `ContentReferenceIndex::insert` is upsert-on-
    // PK (see the port docstring) so a client retry with the same
    // manifest simply refreshes the row — no find_by_target
    // pre-check needed here. The digest itself was validated up
    // front via `subject_digest_parsed` (N-5 fix); a None here means
    // the manifest had no `subject` field at all.
    if let Some(subject_hash) = subject_digest_parsed.clone() {
        let reference_row = ContentReference {
            source_artifact_id: manifest_artifact.id,
            target_content_hash: subject_hash,
            kind: "oci_subject".into(),
            metadata: serde_json::json!({
                "artifact_type": artifact_type_opt,
                "media_type": media_type,
            }),
            repository_id: repo_id,
            recorded_at: Utc::now(),
        };
        // Write goes through the use case (ADR 0008). The method is
        // no-authz by contract (caller has already extracted
        // `WriteRepoAccess` for `repo_id`); the use case carries the
        // explicit `repo_id` argument so future audits can grep for
        // cross-repo write confusion at the use-case boundary. The
        // port's idempotent-upsert shape is preserved verbatim.
        if let Err(e) = ctx
            .content_reference_use_case
            .insert_for_repo(repo_id, reference_row)
            .await
        {
            tracing::warn!(
                manifest_artifact_id = %manifest_artifact.id,
                error = %e,
                stage = "content_references_insert",
                "content_references insert failed; referrers index is eventual — operator rebuild is future work"
            );
            return OciError::Internal.into_response();
        }
    }

    created_manifest_response(&repo_key, &name, &reference, &manifest_digest)
}

// ---------------------------------------------------------------------------
// DELETE dispatch
// ---------------------------------------------------------------------------

/// Entry point for `DELETE /v2/:repo_key/*tail`.
///
/// Tag references route through [`RefUseCase::retire`]; digest
/// references delete the artifact + its content-reference rows. The
/// response is 202 (not 200) — OCI clients treat 200 and 202
/// identically here, but the spec prefers 202 for asynchronous cleanup
/// semantics.
///
/// Authorisation runs against [`DeleteRepoAccess`] rather than
/// `WriteRepoAccess`. Destroying a published manifest is the canonical
/// "I'm removing landed content visible to other readers" operation,
/// distinct from publishing (`PUT`-finalize) or cancelling an own-incomplete
/// upload. Operators who declared `permissions: [write]` grants in gitops
/// `PermissionGrant` manifests for OCI repositories must add a parallel
/// `permissions: [delete]` entry (or extend the existing array to
/// `permissions: [write, delete]`) if those roles should be able to delete
/// published manifests; the `admin` role bypasses per-permission
/// grants via the role-name short-circuit in
/// `hort_app::rbac::RbacEvaluator::authorize` (rbac.rs:104) and is
/// therefore unaffected.
pub(crate) async fn delete_manifest_dispatch(
    access: DeleteRepoAccess,
    State(ctx): State<Arc<AppContext>>,
    BoundedPath((repo_key, tail)): BoundedPath<(String, String)>,
) -> Response {
    let Some(ManifestTail { name, reference }) = parse_manifest_tail(&tail) else {
        return OciError::NameUnknown {
            repository: format!("{repo_key}/{tail}"),
        }
        .into_response();
    };
    // Same name-grammar gate as the PUT path — validate the parsed
    // `<name>` against the OCI grammar before any ref retire,
    // content-reference delete, or artifact removal.
    // Closes the audit's "names with control bytes / mixed case
    // flow into find_in_repo_by_hash" finding for the DELETE side.
    if let Err(e) = validate_oci_name(name) {
        return super::name_invalid_response(e);
    }
    let name = name.to_string();
    let reference = reference.to_string();

    let repo_id = access.repository.id;
    let actor = ApiActor {
        user_id: access.principal.user_id,
    };

    if reference.contains(':') {
        delete_by_digest(
            &ctx,
            repo_id,
            &repo_key,
            &name,
            &reference,
            &access.principal,
        )
        .await
    } else {
        // Tag-ref DELETE: validate the tag against the OCI grammar (INJ-4 —
        // same `validate_oci_tag` as the GET/serve and PUT paths) before the
        // `RefUseCase::retire`, via the shared `tag_invalid_response` mapping
        // (400 `MANIFEST_INVALID`, non-echoing reason).
        if let Err(e) = super::tag::validate_oci_tag(&reference) {
            return super::tag_invalid_response(e);
        }
        delete_by_tag(&ctx, repo_id, &repo_key, &name, &reference, actor).await
    }
}

async fn delete_by_tag(
    ctx: &AppContext,
    repo_id: Uuid,
    repo_key: &str,
    name: &str,
    tag: &str,
    actor: ApiActor,
) -> Response {
    match ctx
        .ref_use_case
        .retire(repo_id, name, tag, actor, Some(repo_key))
        .await
    {
        Ok(()) => (StatusCode::ACCEPTED, Body::empty()).into_response(),
        Err(AppError::Domain(DomainError::NotFound { .. })) => OciError::ManifestUnknown {
            reference: tag.to_string(),
        }
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "OCI manifest DELETE tag failed");
            OciError::Internal.into_response()
        }
    }
}

async fn delete_by_digest(
    ctx: &AppContext,
    repo_id: Uuid,
    repo_key: &str,
    name: &str,
    digest_str: &str,
    actor: &hort_domain::entities::caller::CallerPrincipal,
) -> Response {
    let hash = match parse_digest(digest_str) {
        DigestParse::Ok(h) => h,
        DigestParse::Unsupported { algorithm } => {
            return OciError::Unsupported {
                message: format!("unsupported digest algorithm: {algorithm}"),
            }
            .into_response();
        }
        DigestParse::Invalid { .. } => {
            // A malformed digest on DELETE surfaces as 404
            // `MANIFEST_UNKNOWN` — the reference-shape is unusable for
            // a lookup and the spec pins the not-found envelope here.
            return OciError::ManifestUnknown {
                reference: digest_str.to_string(),
            }
            .into_response();
        }
    };
    let coords = oci_manifest_coords(name, &hash);
    // Visibility-aware path lookup (ADR 0008). `WriteRepoAccess`
    // already authorised the caller for Write on this repo (Write
    // implies Read in `RepositoryAccessUseCase::resolve` semantics),
    // so the use case's Read check is redundant for this principal —
    // but routing through it keeps the call shape uniform across the
    // crate and matches the enforcement guarantee.
    let artifact = match ctx
        .artifact_use_case
        .find_visible_by_path(repo_key, &coords.path, Some(actor))
        .await
    {
        Ok((_repo, a)) => a,
        Err(AppError::Domain(DomainError::NotFound { .. })) => {
            return OciError::ManifestUnknown {
                reference: digest_str.to_string(),
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "OCI manifest DELETE find_visible_by_path failed");
            return OciError::Internal.into_response();
        }
    };

    // content_references cleanup. Idempotent — missing entries are
    // `Ok(())` per the port contract. A failure here is logged but
    // does NOT short-circuit the artifact delete: an orphaned
    // reference is less harmful than a half-deleted manifest.
    //
    // Cleanup goes through the use case (ADR 0008). Same no-authz
    // trust contract as `insert_for_repo` above (caller has
    // `WriteRepoAccess`). The explicit `repo_id` keeps the call site
    // semantically scoped even though the underlying port keys delete
    // by `source` alone.
    if let Err(e) = ctx
        .content_reference_use_case
        .delete_by_source_for_repo(repo_id, artifact.id)
        .await
    {
        tracing::warn!(
            manifest_artifact_id = %artifact.id,
            error = %e,
            "content_references delete_by_source failed; proceeding with artifact delete"
        );
    }

    // Artifact lifecycle delete. Uses `ArtifactUseCase::delete`, the
    // landed primitive for artifact removal — it delegates to
    // `ArtifactRepository::delete` which hard-removes the row. The
    // CAS blob is NOT removed (GC concern; multiple artifacts may
    // share CAS bytes).
    if let Err(e) = ctx.artifact_use_case.delete(artifact.id).await {
        tracing::error!(
            manifest_artifact_id = %artifact.id,
            error = %e,
            "OCI manifest DELETE artifact.delete failed"
        );
        return OciError::Internal.into_response();
    }

    (StatusCode::ACCEPTED, Body::empty()).into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Small representation of a referenced blob extracted from manifest
/// JSON. Digest strings are kept raw (with the `sha256:` prefix) so
/// `MANIFEST_BLOB_UNKNOWN.detail.blobs` can echo them back verbatim —
/// clients match on the same form they sent.
#[derive(Debug, Clone)]
struct ReferencedBlob {
    digest_raw: String,
    hash: ContentHash,
    role: BlobRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlobRole {
    Config,
    Layer,
}

/// Parse the single-image manifest shape:
///
/// ```json
/// {
///   "schemaVersion": 2,
///   "config": { "digest": "sha256:...", ... },
///   "layers": [ { "digest": "sha256:...", ... }, ... ]
/// }
/// ```
///
/// Returns the config blob (required) followed by the layer blobs
/// (possibly empty) in manifest order. Order matters only for the
/// `add_member` call sequence — the event stream records it as the
/// audit trail; consumers of the group read unordered.
///
/// Error shape: returns an `Err(serde_json::Value)` carrying the
/// `detail` object for a 400 `MANIFEST_INVALID` so the caller can
/// surface it verbatim. This keeps all manifest-shape validation in
/// one place and avoids leaking parser internals into the handler.
fn parse_manifest_blobs(
    manifest: &serde_json::Value,
) -> Result<Vec<ReferencedBlob>, serde_json::Value> {
    let mut out: Vec<ReferencedBlob> = Vec::new();

    // config.digest — REQUIRED by the single-image shape.
    let config_digest = manifest
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            serde_json::json!({
                "reason": "manifest missing required `config.digest`",
            })
        })?;
    let config_hash = parse_blob_digest(config_digest)?;
    out.push(ReferencedBlob {
        digest_raw: config_digest.to_string(),
        hash: config_hash,
        role: BlobRole::Config,
    });

    // layers[*].digest — OPTIONAL (some manifests are config-only).
    // Each entry must have a well-formed sha256 digest.
    if let Some(layers) = manifest.get("layers").and_then(|v| v.as_array()) {
        for (idx, layer) in layers.iter().enumerate() {
            let layer_digest = layer
                .get("digest")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    serde_json::json!({
                        "reason": format!("layer[{idx}] missing `digest` field"),
                    })
                })?;
            let layer_hash = parse_blob_digest(layer_digest)?;
            out.push(ReferencedBlob {
                digest_raw: layer_digest.to_string(),
                hash: layer_hash,
                role: BlobRole::Layer,
            });
        }
    }

    // Bound the referenced-blob count at parse time so the per-blob
    // lookup loop in `resolve_referenced_blobs` is never entered for
    // an over-cap manifest. Surfaces as `MANIFEST_INVALID` at the
    // call site.
    if out.len() > MAX_BLOB_REFERENCES {
        return Err(serde_json::json!({
            "reason": format!(
                "manifest references {} blobs; max is {}",
                out.len(),
                MAX_BLOB_REFERENCES,
            ),
        }));
    }

    Ok(out)
}

/// Parse a `sha256:<hex>` digest into a `ContentHash`, returning the
/// `serde_json::Value` `detail` payload on failure. Separate from
/// [`parse_digest`] because this one produces the manifest-invalid
/// envelope shape rather than the blob-pull one — the handler-level
/// error codes differ.
fn parse_blob_digest(raw: &str) -> Result<ContentHash, serde_json::Value> {
    match parse_digest(raw) {
        DigestParse::Ok(h) => Ok(h),
        DigestParse::Unsupported { algorithm } => Err(serde_json::json!({
            "reason": format!("unsupported digest algorithm in manifest: {algorithm}"),
            "digest": raw,
        })),
        DigestParse::Invalid { message } => Err(serde_json::json!({
            "reason": format!("malformed digest in manifest: {message}"),
            "digest": raw,
        })),
    }
}

/// Resolve every referenced blob by SHA-256 against the artifact
/// repository, enforcing cross-repo isolation. Returns
/// `(config_opt, layers, missing_digests)` — `missing_digests` carries
/// the raw `sha256:<hex>` strings so the response body can echo the
/// client's form.
///
/// Resolve every referenced blob by SHA-256 against the artifact
/// repository, enforcing cross-repo isolation (ADR 0008). The call
/// uses `find_in_repo_by_hash` which scopes the SQL query to the
/// target repo at the port boundary — the right row is the only
/// candidate and there is no ordering hazard from cross-repo rows
/// sharing the same SHA-256.
async fn resolve_referenced_blobs(
    ctx: &AppContext,
    repo: Uuid,
    refs: &[ReferencedBlob],
) -> Result<(Option<Artifact>, Vec<Artifact>, Vec<String>), Response> {
    let mut config: Option<Artifact> = None;
    let mut layers: Vec<Artifact> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for r in refs {
        let hit = match ctx
            .artifact_use_case
            .find_in_repo_by_hash(repo, &r.hash)
            .await
        {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(error = %e, "find_in_repo_by_hash failed");
                return Err(OciError::Internal.into_response());
            }
        };
        match hit {
            // The use case already enforces `repository_id == repo`
            // at the port boundary; no post-filter needed. Clients
            // cross-mount explicitly via
            // `POST …/blobs/uploads/?mount=<digest>&from=<src_repo>`
            // before pushing the manifest.
            Some(a) => match r.role {
                BlobRole::Config => {
                    if config.is_some() {
                        // Defensive — `parse_manifest_blobs` emits at
                        // most one config; two configs would be a
                        // parser regression.
                        tracing::warn!(
                            "multiple config blobs resolved; keeping first and ignoring extras"
                        );
                    } else {
                        config = Some(a);
                    }
                }
                BlobRole::Layer => layers.push(a),
            },
            None => {
                missing.push(r.digest_raw.clone());
            }
        }
    }

    Ok((config, layers, missing))
}

/// Extract the `Content-Type` header as an owned `String`. Missing or
/// non-ASCII values land as `MANIFEST_INVALID` — the manifest push
/// path requires a valid media-type from the supported allowlist.
fn extract_media_type(headers: &HeaderMap) -> Result<String, Box<Response>> {
    let Some(value) = headers.get(CONTENT_TYPE) else {
        return Err(Box::new(
            OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "missing required Content-Type header",
                })),
            }
            .into_response(),
        ));
    };
    let Ok(s) = value.to_str() else {
        return Err(Box::new(
            OciError::ManifestInvalid {
                detail: Some(serde_json::json!({
                    "reason": "Content-Type header is not valid ASCII",
                })),
            }
            .into_response(),
        ));
    };
    // Strip any `;params` suffix. The allowlist keys on the type/subtype
    // only; `application/vnd.oci.image.manifest.v1+json; charset=utf-8`
    // must round-trip to the same allowlist hit.
    let trimmed = s.split(';').next().unwrap_or("").trim().to_string();
    Ok(trimmed)
}

/// Compute the SHA-256 of the manifest body. The returned
/// [`ContentHash`] parses the lowercase hex — this matches the `ingest`
/// path's `declared_sha256` column, which is also `ContentHash`-typed.
fn compute_sha256(bytes: &[u8]) -> ContentHash {
    let digest = Sha256::digest(bytes);
    let hex = format!("{digest:x}");
    hex.parse()
        .expect("sha2::Sha256::digest produces valid 64-char lowercase hex")
}

/// Build the 201 response for a successful manifest PUT. `Location`
/// echoes the request URL with the client's reference form (tag or
/// digest); `Docker-Content-Digest` carries the computed hash
/// regardless of reference form.
fn created_manifest_response(
    repo_key: &str,
    name: &str,
    reference: &str,
    hash: &ContentHash,
) -> Response {
    let location = format!("/v2/{repo_key}/{name}/manifests/{reference}");
    // `repo_key` / `name` / `reference` come from the request URL
    // captures; CRLF or other non-ASCII bytes in any segment produce
    // an `InvalidHeaderValue` from `from_str`. Routing through the
    // shared helper returns the canonical `NAME_UNKNOWN` 404 envelope
    // instead of panicking (which would degrade to 500 — a DoS
    // primitive).
    let location_header = match super::header_value_or_bad_request(&location) {
        Ok(h) => h,
        Err(resp) => return *resp,
    };
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, location_header);
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&format!("sha256:{}", hash.as_ref()))
            .expect("sha256:<hex> is valid ASCII"),
    );
    (StatusCode::CREATED, headers, Body::empty()).into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::to_bytes;
    use axum::http::Request as HttpRequest;
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt;

    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, MockArtifactGroupLifecyclePort,
        MockArtifactGroupRepository, MockArtifactLifecycle, MockArtifactRepository,
        MockContentReferenceIndex, MockEventStore, MockRefLifecyclePort, MockRefRegistryPort,
        MockRepositoryRepository, MockStoragePort,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::caller::CallerPrincipal;
    use hort_domain::entities::mutable_ref::MutableRef;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::events::DomainEvent;
    use hort_domain::ports::artifact_repository::ArtifactRepository;
    use hort_domain::ports::content_reference_index::ContentReferenceIndex;
    use hort_domain::ports::ref_registry::RefRegistryPort;

    use hort_http_core::test_support::build_mock_ctx;

    // -------------------- Harness --------------------

    struct Harness {
        ctx: Arc<AppContext>,
        artifacts: Arc<MockArtifactRepository>,
        repositories: Arc<MockRepositoryRepository>,
        storage: Arc<MockStoragePort>,
        refs: Arc<MockRefRegistryPort>,
        #[allow(dead_code)]
        ref_lifecycle: Arc<MockRefLifecyclePort>,
        #[allow(dead_code)]
        artifact_groups: Arc<MockArtifactGroupRepository>,
        group_lifecycle: Arc<MockArtifactGroupLifecyclePort>,
        content_references: Arc<MockContentReferenceIndex>,
        lifecycle: Arc<MockArtifactLifecycle>,
        #[allow(dead_code)]
        events: Arc<MockEventStore>,
        // Observe which ingest path ran. A normal / mixed / non-bundle
        // manifest routes via `ingest_verified` → `enqueue_scan` (the
        // seeded HTTP-test policy carries `scan_backends: ["trivy"]`).
        // A pure Sigstore-bundle referrer routes via
        // `ingest_signature_manifest` → NO scan enqueued.
        jobs: Arc<hort_app::use_cases::test_support::MockJobsRepository>,
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
            ref_lifecycle: mocks.ref_lifecycle,
            artifact_groups: mocks.artifact_groups,
            group_lifecycle: mocks.artifact_group_lifecycle,
            content_references: mocks.content_references,
            lifecycle: mocks.lifecycle,
            events: mocks.events,
            jobs: mocks.jobs,
        }
    }

    fn oci_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Oci;
        r
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

    fn test_principal() -> CallerPrincipal {
        CallerPrincipal {
            user_id: Uuid::new_v4(),
            external_id: "test:sub".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            // `claims` is the resolved set from the token (ADR 0012);
            // an empty set is the under-privileged shape these tests
            // start from and override per-case via
            // [`principal_with_claims`].
            claims: Vec::new(),
            token_kind: None,
            issued_at: Utc::now(),
            token_cap: None,
        }
    }

    fn with_principal(mut req: axum::http::Request<Body>) -> axum::http::Request<Body> {
        // Wrap in `AuthenticatedPrincipal` via the test-support helper.
        hort_http_core::middleware::auth::test_support::inject_principal(
            &mut req,
            test_principal(),
        );
        req
    }

    /// Seed a blob artifact at `blobs/sha256:<hex>` with CAS content.
    /// Returns the hash for wiring into manifest JSON.
    fn seed_blob(
        artifacts: &MockArtifactRepository,
        storage: &MockStoragePort,
        repo_id: Uuid,
        content: &[u8],
    ) -> ContentHash {
        let hex = format!("{:x}", Sha256::digest(content));
        let hash: ContentHash = hex.parse().unwrap();
        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = repo_id;
        a.path = format!("blobs/sha256:{hex}");
        a.sha256_checksum = hash.clone();
        a.size_bytes = content.len() as i64;
        artifacts.insert(a);
        storage.insert_content(hash.clone(), content.to_vec());
        hash
    }

    /// Build a minimal single-image manifest JSON pointing at the
    /// supplied config + layer digests. Returns the raw bytes (the
    /// handler computes the SHA of these).
    fn build_manifest_json(config_hash: &ContentHash, layer_hashes: &[ContentHash]) -> Vec<u8> {
        let layers: Vec<serde_json::Value> = layer_hashes
            .iter()
            .map(|h| {
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": format!("sha256:{}", h.as_ref()),
                    "size": 0,
                })
            })
            .collect();
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{}", config_hash.as_ref()),
                "size": 0,
            },
            "layers": layers,
        });
        serde_json::to_vec(&body).unwrap()
    }

    /// Build a manifest with a `subject.digest` reference. Used for
    /// the content_references insert test.
    fn build_manifest_with_subject(
        config_hash: &ContentHash,
        layer_hashes: &[ContentHash],
        subject_hash: &ContentHash,
    ) -> Vec<u8> {
        let layers: Vec<serde_json::Value> = layer_hashes
            .iter()
            .map(|h| {
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": format!("sha256:{}", h.as_ref()),
                    "size": 0,
                })
            })
            .collect();
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": "application/vnd.example.test",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{}", config_hash.as_ref()),
                "size": 0,
            },
            "layers": layers,
            "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{}", subject_hash.as_ref()),
                "size": 0,
            },
        });
        serde_json::to_vec(&body).unwrap()
    }

    /// Construct a PUT request with the right media-type + body.
    fn put_request(uri: &str, body: Vec<u8>) -> axum::http::Request<Body> {
        let req = HttpRequest::put(uri)
            .header(CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from(body))
            .unwrap();
        with_principal(req)
    }

    // -------------------- parse_manifest_tail --------------------

    #[test]
    fn parse_tail_accepts_tag_reference() {
        let t = parse_manifest_tail("library/nginx/manifests/v1").unwrap();
        assert_eq!(t.name, "library/nginx");
        assert_eq!(t.reference, "v1");
    }

    #[test]
    fn parse_tail_accepts_digest_reference() {
        let t = parse_manifest_tail("nginx/manifests/sha256:abc").unwrap();
        assert_eq!(t.name, "nginx");
        assert_eq!(t.reference, "sha256:abc");
    }

    #[test]
    fn parse_tail_rejects_missing_manifests_literal() {
        assert!(parse_manifest_tail("nginx/blobs/sha256:abc").is_none());
    }

    #[test]
    fn parse_tail_rejects_empty_name_or_reference() {
        assert!(parse_manifest_tail("/manifests/v1").is_none());
        assert!(parse_manifest_tail("nginx/manifests/").is_none());
    }

    // -------------------- PUT — happy path --------------------

    #[test]
    fn put_by_tag_commits_ingested_group_and_ref() {
        let (status, headers, group_count, ref_count) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            // Gather assertions from mocks after dispatch.
            let group_count = h.group_lifecycle.commit_call_count();
            let ref_count = h.refs.list(repo_id, "library/nginx").await.unwrap().len();
            // Also prove the manifest artifact got committed.
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let got = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap();
            assert!(got.is_some(), "manifest artifact must be committed");
            (status, headers, group_count, ref_count)
        });
        assert_eq!(status, StatusCode::CREATED);
        let loc = headers.get(LOCATION).unwrap().to_str().unwrap();
        assert_eq!(loc, "/v2/myrepo/library/nginx/manifests/v1");
        let dcd = headers
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            dcd.starts_with("sha256:") && dcd.len() == "sha256:".len() + 64,
            "Docker-Content-Digest shape: {dcd}"
        );
        // Three add_member calls (manifest + config + 1 layer).
        assert_eq!(group_count, 3);
        assert_eq!(ref_count, 1, "ref count for library/nginx namespace");
    }

    /// INJ-4: a PUT to an out-of-grammar tag is rejected 400 `MANIFEST_INVALID`
    /// BEFORE any ingest / ref write — the tag validator runs before the state
    /// change, so a malformed tag can never become a stored ref. The body is a
    /// well-formed manifest over unseeded blobs (never resolved, because the
    /// tag check rejects first); the 400 with an `oci.tag:` reason proves the
    /// validator fired pre-ingest, and `group_count`/`ref_count` staying 0
    /// proves no state change. The response never echoes the offending bytes.
    #[test]
    fn put_manifest_out_of_grammar_tag_rejected_400_before_ingest() {
        let over_cap = "a".repeat(129);
        let cases: [(&str, &str); 4] = [
            ("..", "double-dot path traversal"),
            (".leadingdot", "leading dot"),
            ("-leadinghyphen", "leading hyphen"),
            (&over_cap, "129-byte over-cap tag"),
        ];
        for (uri_tag, label) in cases {
            let (status, body, group_count, ref_count) = run(async {
                let h = harness();
                let repo = oci_repo("myrepo");
                let repo_id = repo.id;
                h.repositories.insert(repo);
                // Well-formed manifest body over UNSEEDED blobs — never
                // resolved, because the tag check rejects before blob
                // resolution / ingest.
                let config_hash: ContentHash =
                    format!("{:x}", Sha256::digest(b"cfg")).parse().unwrap();
                let layer_hash: ContentHash =
                    format!("{:x}", Sha256::digest(b"layer")).parse().unwrap();
                let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));

                let router = router().with_state(h.ctx.clone());
                let uri = format!("/v2/myrepo/library/nginx/manifests/{uri_tag}");
                let resp = router.oneshot(put_request(&uri, body)).await.unwrap();
                let status = resp.status();
                let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
                let group_count = h.group_lifecycle.commit_call_count();
                let ref_count = h.refs.list(repo_id, "library/nginx").await.unwrap().len();
                (status, rbody, group_count, ref_count)
            });
            assert_eq!(status, StatusCode::BAD_REQUEST, "case: {label}");
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                parsed["errors"][0]["code"], "MANIFEST_INVALID",
                "case: {label}"
            );
            let reason = parsed["errors"][0]["detail"]["reason"]
                .as_str()
                .unwrap_or("");
            assert!(
                reason.starts_with("oci.tag: "),
                "case {label}: reason must be tagged `oci.tag:` ({reason})"
            );
            assert_eq!(
                group_count, 0,
                "case {label}: no ingest before tag rejection"
            );
            assert_eq!(
                ref_count, 0,
                "case {label}: no ref written before tag rejection"
            );
        }
    }

    // -------------------- PUT — causation integrity --------------------

    #[test]
    fn put_causation_integrity() {
        // Post-ingest events (group member × 3) MUST all:
        //   (a) carry causation_id = Some(manifest_event_id) —
        //       the event_id minted by the `ArtifactIngested` commit,
        //   (b) share a SINGLE correlation_id (the handler's per-
        //       request UUID).
        //
        // This is the load-bearing audit-trail contract (C1). The
        // ingest use case has its own internal correlation_id (a
        // separate scope — ingest orchestrates its own set of
        // transitions); post-ingest events use the handler's
        // correlation_id, a common ancestor the handler generated
        // up front.
        let (ok, cross_check) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);

            let router = router().with_state(h.ctx.clone());
            router
                .oneshot(put_request("/v2/myrepo/library/nginx/manifests/v1", body))
                .await
                .unwrap();

            // 1. Find the ArtifactIngested event_id via the lifecycle commits.
            let transitions = h.lifecycle.committed_transitions();
            let manifest_event_id = transitions
                .iter()
                .find_map(|(_, batch, _)| {
                    batch
                        .events
                        .iter()
                        .find(|e| matches!(e.event, DomainEvent::ArtifactIngested(_)))
                        .map(|e| e.event_id)
                })
                .expect("ArtifactIngested must have been committed");

            // 2. Walk every group-commit batch. All must share the
            //    SAME correlation_id (proves the handler threaded
            //    one UUID through every call). All must have
            //    causation_id = Some(manifest_event_id).
            let group_commits = h.group_lifecycle.recorded_commits();
            assert!(
                group_commits.len() >= 3,
                "expected at least 3 add_member calls (manifest + config + layer), got {}",
                group_commits.len()
            );
            let handler_correlation_id = group_commits[0].batch.correlation_id;
            let mut violations: Vec<String> = Vec::new();
            for c in &group_commits {
                if c.batch.correlation_id != handler_correlation_id {
                    violations.push(format!(
                        "group batch role={} correlation_id {} != first {}",
                        c.member_role, c.batch.correlation_id, handler_correlation_id
                    ));
                }
                if c.batch.causation_id != Some(manifest_event_id) {
                    violations.push(format!(
                        "group batch role={} causation_id {:?} != Some({})",
                        c.member_role, c.batch.causation_id, manifest_event_id
                    ));
                }
            }

            // Also cross-check: the handler's correlation_id is
            // DIFFERENT from the ingest batch's internal correlation_id
            // (separate orchestration scopes). Not a correctness
            // invariant, but asserting it documents the split.
            let ingest_correlation_id = transitions
                .iter()
                .find_map(|(_, batch, _)| {
                    batch
                        .events
                        .iter()
                        .any(|e| matches!(e.event, DomainEvent::ArtifactIngested(_)))
                        .then_some(batch.correlation_id)
                })
                .unwrap();

            (
                violations,
                (
                    handler_correlation_id,
                    ingest_correlation_id,
                    manifest_event_id,
                ),
            )
        });
        assert!(ok.is_empty(), "causation/correlation violations: {ok:?}");
        // Handler + ingest correlation_ids are distinct scopes.
        assert_ne!(
            cross_check.0, cross_check.1,
            "handler and ingest correlation_ids are independent"
        );
    }

    // -------------------- PUT — idempotence --------------------

    #[test]
    fn put_idempotence_second_put_emits_zero_new_events() {
        // First PUT commits a known set of events; an identical second
        // PUT must NOT emit new domain events. The invariant covers
        // three event families:
        //
        // 1. ArtifactIngested — `IngestUseCase::ingest` dedups on
        //    `(repo, path, hash)` via `find_by_path`. The mock
        //    `MockArtifactLifecycle.committed_transitions()` ticks once
        //    per accepted commit, so a stable count proves the dedup
        //    happened.
        //
        // 2. RefMoved — `RefUseCase::set` short-circuits at the use
        //    case layer when the new target equals the existing
        //    target (see `ref_use_case.rs` "no-op short-circuit").
        //    `MockRefLifecyclePort.recorded_moves()` grows ONLY on
        //    accepted commits, so a stable count proves the
        //    short-circuit fired.
        //
        // 3. ArtifactGroupMemberAdded — adapter-level invariant via
        //    `INSERT ON CONFLICT DO NOTHING` in the postgres adapter
        //    The use case ALWAYS delegates to `commit_member_added`
        //    and the mock's outcome path is
        //    Committed-by-default (it does not model ON CONFLICT). At
        //    the mock-router-test layer we therefore CANNOT assert
        //    "member event count stable" — that's an integration-test
        //    invariant. We DO assert `commit_call_count` grew by
        //    exactly the per-PUT delta (3: manifest + config + layer)
        //    so a regression that drops the delegation entirely would
        //    fail. The "zero new events" property for member-added
        //    must be re-asserted at the postgres adapter level.
        let (
            first_lifecycle,
            second_lifecycle,
            first_moves,
            second_moves,
            first_group_calls,
            second_group_calls,
        ) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";

            let resp1 = router
                .clone()
                .oneshot(put_request(uri, body.clone()))
                .await
                .unwrap();
            assert_eq!(resp1.status(), StatusCode::CREATED);
            let first_lifecycle = h.lifecycle.committed_transitions().len();
            let first_moves = h.ref_lifecycle.recorded_moves().len();
            let first_group_calls = h.group_lifecycle.commit_call_count();

            let resp2 = router.oneshot(put_request(uri, body)).await.unwrap();
            assert_eq!(resp2.status(), StatusCode::CREATED);
            let second_lifecycle = h.lifecycle.committed_transitions().len();
            let second_moves = h.ref_lifecycle.recorded_moves().len();
            let second_group_calls = h.group_lifecycle.commit_call_count();
            (
                first_lifecycle,
                second_lifecycle,
                first_moves,
                second_moves,
                first_group_calls,
                second_group_calls,
            )
        });
        // 1. ArtifactIngested dedup — count unchanged.
        assert_eq!(
            first_lifecycle, second_lifecycle,
            "manifest ArtifactIngested must dedup; lifecycle commits grew from {first_lifecycle} to {second_lifecycle}"
        );
        // 2. RefMoved short-circuit — count unchanged. First PUT
        //    creates the tag (1 move); second PUT with same target
        //    must short-circuit (still 1).
        assert_eq!(
            first_moves, 1,
            "first tag-PUT must create exactly one ref move, got {first_moves}"
        );
        assert_eq!(
            first_moves, second_moves,
            "RefMoved must short-circuit on same-target PUT; recorded_moves grew from {first_moves} to {second_moves}"
        );
        // 3. ArtifactGroupMemberAdded delegation — adapter contract.
        //    Use case always delegates; mock cannot witness ON CONFLICT
        //    DO NOTHING. Assert the per-PUT delegation delta so a
        //    regression that breaks the delegation entirely is caught.
        let group_delta_per_put = 3; // manifest + config + layer
        assert_eq!(
            first_group_calls, group_delta_per_put,
            "first PUT must delegate add_member 3× (manifest + config + layer), got {first_group_calls}"
        );
        assert_eq!(
            second_group_calls,
            2 * group_delta_per_put,
            "second PUT must also delegate 3× (adapter-level ON CONFLICT DO NOTHING is the no-op guard); commit_call_count={second_group_calls}"
        );
    }

    // -------------------- PUT — digest ref --------------------

    #[test]
    fn put_by_digest_does_not_emit_ref_moved() {
        // A digest-reference PUT must NOT create a tag ref. Two
        // independent witnesses for the same invariant:
        //
        // - Projection level (`refs.list().len() == 0`) — proves no
        //   ref row landed.
        // - Lifecycle level (`recorded_moves().len() == 0`) — proves
        //   the use case never even called `move_ref`. This is the
        //   tighter assertion: a future bug that emits a RefMoved
        //   event but rolls back the projection write would slip past
        //   the projection check, but `recorded_moves` would still
        //   tick. Both checks together guard the audit-trail integrity
        //   the OCI spec mandates for digest-self-naming PUTs.
        let (ref_count, recorded_moves_count) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{manifest_hex}");
            let resp = router.oneshot(put_request(&uri, body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            (
                h.refs.list(repo_id, "library/nginx").await.unwrap().len(),
                h.ref_lifecycle.recorded_moves().len(),
            )
        });
        assert_eq!(
            ref_count, 0,
            "digest-reference PUT must not create a ref row"
        );
        assert_eq!(
            recorded_moves_count, 0,
            "digest-reference PUT must not invoke move_ref (no RefMoved event)"
        );
    }

    // -------------------- PUT — mismatched declared digest --------------------

    #[test]
    fn put_by_digest_with_mismatched_declared_returns_400_manifest_invalid() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let body = build_manifest_json(&config_hash, &[]);
            // Use the WRONG digest in the URL — any 64-char hex that
            // isn't the real body's SHA.
            let wrong_hex = "a".repeat(64);
            let router = router().with_state(h.ctx.clone());
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{wrong_hex}");
            let resp = router.oneshot(put_request(&uri, body)).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Must be MANIFEST_INVALID (NOT UNSUPPORTED).
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
    }

    // -------------------- PUT — subject --------------------

    #[test]
    fn put_with_subject_inserts_content_reference() {
        // Every ArtifactIngested also writes a `kind = "primary_content"`
        // refcount row (ADR 0020). So a PUT-with-subject now produces TWO
        // content_references rows: one `oci_subject` (from the OCI write
        // path, asserted here) and one `primary_content` (from the ingest
        // path, covered by dedicated tests in `hort-app::ingest_use_case`).
        // This test counts only `oci_subject` rows so the OCI Referrers
        // contract stays load-bearing without coupling to the ingest-path
        // refcount surface.
        let (status, oci_subject_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"subject-bytes");
            let body = build_manifest_with_subject(&config_hash, &[], &subject_hash);

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();
            // Count `oci_subject` rows specifically — the row pointing
            // at `subject_hash` from the manifest source artifact.
            let oci_subject_rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap()
                .len();
            (status, oci_subject_rows)
        });
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            oci_subject_rows, 1,
            "content_references must carry one oci_subject row after PUT with subject"
        );
    }

    #[test]
    fn put_with_subject_reference_carries_expected_metadata() {
        // Sanity-check the metadata shape stored — the Referrers API
        // depends on `artifact_type` + `media_type` being present on
        // the row so the response body can rebuild the descriptor.
        let (kind, artifact_type_ok, media_type_ok) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"subject-bytes");
            let body = build_manifest_with_subject(&config_hash, &[], &subject_hash);
            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            router.oneshot(put_request(uri, body)).await.unwrap();

            let rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap();
            assert_eq!(rows.len(), 1, "one row per subject");
            let r = &rows[0];
            (
                r.kind.clone(),
                r.metadata.get("artifact_type").is_some(),
                r.metadata.get("media_type").is_some(),
            )
        });
        assert_eq!(kind, "oci_subject");
        assert!(artifact_type_ok, "metadata.artifact_type must be present");
        assert!(media_type_ok, "metadata.media_type must be present");
    }

    // ----------------------------------------------------------------
    // Signature manifest routing: signatures are NOT quarantined —
    // route a pure Sigstore-bundle referrer to the narrow
    // `ingest_signature_manifest` path; everything else stays on
    // `ingest_verified`. The distinguishing observable is the scan-job
    // enqueue: `ingest_verified` enqueues a scan (the seeded HTTP-test
    // policy carries `scan_backends: ["trivy"]`); the narrow path does
    // NOT. The `oci_subject` content-reference write is unchanged on
    // both paths.
    // ----------------------------------------------------------------

    const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

    /// Build a referrer manifest whose layers all carry `layer_media_types`
    /// (in order), with a `subject.digest` pointing at `subject_hash` and a
    /// declared `artifactType`. The config + every layer digest are seeded
    /// blobs so the OCI write path's blob resolution succeeds.
    fn build_referrer_manifest(
        config_hash: &ContentHash,
        layers: &[(&str, &ContentHash)],
        subject_hash: &ContentHash,
        artifact_type: &str,
    ) -> Vec<u8> {
        let layer_values: Vec<serde_json::Value> = layers
            .iter()
            .map(|(mt, h)| {
                serde_json::json!({
                    "mediaType": mt,
                    "digest": format!("sha256:{}", h.as_ref()),
                    "size": 0,
                })
            })
            .collect();
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": artifact_type,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{}", config_hash.as_ref()),
                "size": 0,
            },
            "layers": layer_values,
            "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{}", subject_hash.as_ref()),
                "size": 0,
            },
        });
        serde_json::to_vec(&body).unwrap()
    }

    /// (a) A PUT of a PURE Sigstore-bundle referrer (subject.digest set,
    /// single bundle layer) routes to `ingest_signature_manifest`:
    /// the artifact is status `None`, NO scan job is enqueued, and the
    /// `oci_subject` content-reference row is still written.
    #[test]
    fn put_pure_sigstore_bundle_referrer_is_not_quarantined_or_scanned() {
        let (status, scan_calls, oci_subject_rows, artifact_status) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"sig-config-bytes");
            let bundle_hash =
                seed_blob(&h.artifacts, &h.storage, repo_id, b"the-cosign-bundle-json");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"the-signed-image");
            let body = build_referrer_manifest(
                &config_hash,
                &[(SIGSTORE_BUNDLE_MEDIA_TYPE, &bundle_hash)],
                &subject_hash,
                SIGSTORE_BUNDLE_MEDIA_TYPE,
            );
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/sha256.sig";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();

            let scan_calls = h.jobs.enqueue_scan_calls().len();
            let oci_subject_rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap()
                .len();
            // The committed manifest artifact must be status None.
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let artifact_status = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .map(|a| a.quarantine_status);
            (status, scan_calls, oci_subject_rows, artifact_status)
        });
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            scan_calls, 0,
            "a pure Sigstore-bundle referrer must NOT enqueue a scan job (narrow path)"
        );
        assert_eq!(
            oci_subject_rows, 1,
            "the oci_subject content-reference row must still be written"
        );
        assert_eq!(
            artifact_status,
            Some(QuarantineStatus::None),
            "the signature manifest artifact must be status None (not quarantined)"
        );
    }

    /// (b) THE SECURITY GUARD — a MIXED manifest (one bundle layer + one
    /// runnable `tar+gzip` layer, subject.digest set) is NOT exempted: it
    /// stays on `ingest_verified` and IS scanned. A pusher cannot smuggle a
    /// runnable layer past the scanner by labelling one layer a bundle.
    #[test]
    fn put_mixed_bundle_plus_tar_gzip_referrer_is_still_scanned() {
        let scan_calls = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"mixed-config-bytes");
            let bundle_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"a-real-bundle");
            let malware_hash =
                seed_blob(&h.artifacts, &h.storage, repo_id, b"runnable-malware-layer");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"victim-image");
            let body = build_referrer_manifest(
                &config_hash,
                &[
                    (SIGSTORE_BUNDLE_MEDIA_TYPE, &bundle_hash),
                    ("application/vnd.oci.image.layer.v1.tar+gzip", &malware_hash),
                ],
                &subject_hash,
                SIGSTORE_BUNDLE_MEDIA_TYPE,
            );

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/sha256.sig";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            h.jobs.enqueue_scan_calls().len()
        });
        assert_eq!(
            scan_calls, 1,
            "a MIXED manifest carrying a runnable tar+gzip layer must NOT be exempted — it stays scanned (anti-scan-evasion guard)"
        );
    }

    /// (c) A normal image manifest (NO subject, tar+gzip layers) is
    /// unchanged: it routes via `ingest_verified` and IS scanned.
    #[test]
    fn put_normal_image_manifest_is_scanned_unchanged() {
        let scan_calls = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, std::slice::from_ref(&layer_hash));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            h.jobs.enqueue_scan_calls().len()
        });
        assert_eq!(
            scan_calls, 1,
            "a normal image manifest must stay on ingest_verified and be scanned"
        );
    }

    /// (d) A non-Sigstore referrer (subject.digest set, single SBOM-typed
    /// layer) is NOT exempted — only PURE Sigstore-bundle referrers are.
    /// It stays on `ingest_verified` and IS scanned.
    #[test]
    fn put_non_sigstore_sbom_referrer_is_still_scanned() {
        let (scan_calls, oci_subject_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"sbom-config-bytes");
            let sbom_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"the-spdx-sbom");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"described-image");
            let body = build_referrer_manifest(
                &config_hash,
                &[("application/spdx+json", &sbom_hash)],
                &subject_hash,
                "application/spdx+json",
            );

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/sha256.sbom";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            let scan_calls = h.jobs.enqueue_scan_calls().len();
            // The oci_subject row is still written (the referrer machinery
            // is unchanged) — only the lifecycle treatment differs.
            let oci_subject_rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap()
                .len();
            (scan_calls, oci_subject_rows)
        });
        assert_eq!(
            scan_calls, 1,
            "a non-Sigstore (SBOM) referrer must stay on ingest_verified and be scanned"
        );
        assert_eq!(
            oci_subject_rows, 1,
            "oci_subject row still written for the SBOM referrer"
        );
    }

    /// Idempotency regression guard: pushing the same manifest with the same
    /// `subject.digest` twice must produce exactly ONE `oci_subject`
    /// row. Pins the `(repo, source, kind)` upsert shape against
    /// future PK drift — a regression that flipped the conflict target
    /// to `(repo, source)` (without `kind`) would silently start
    /// replacing the `primary_content` row with the `oci_subject` row
    /// on the second PUT, breaking the refcount projection (ADR 0020).
    #[test]
    fn oci_manifest_put_idempotent_single_oci_subject_row() {
        let (status_first, status_second, oci_subject_rows) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes-idem");
            let subject_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"subject-bytes-idem");
            let body = build_manifest_with_subject(&config_hash, &[], &subject_hash);

            let uri = "/v2/myrepo/library/nginx/manifests/v1";

            // First PUT — establishes both rows (oci_subject + primary_content).
            let r1 = router().with_state(h.ctx.clone());
            let resp1 = r1.oneshot(put_request(uri, body.clone())).await.unwrap();
            let status_first = resp1.status();

            // Second PUT, same manifest body — must upsert the
            // existing `oci_subject` row, not append a new one.
            // Build a fresh router because Service<Request> is consumed
            // by `oneshot`.
            let r2 = router().with_state(h.ctx.clone());
            let resp2 = r2.oneshot(put_request(uri, body)).await.unwrap();
            let status_second = resp2.status();

            // Count `oci_subject` rows pointing at the subject from
            // the manifest source — should be exactly one regardless
            // of how many PUTs landed.
            let rows = h
                .content_references
                .find_by_target(repo_id, &subject_hash, Some("oci_subject"))
                .await
                .unwrap();
            (status_first, status_second, rows.len())
        });
        assert_eq!(status_first, StatusCode::CREATED);
        assert_eq!(status_second, StatusCode::CREATED);
        assert_eq!(
            oci_subject_rows, 1,
            "idempotent re-push must upsert the oci_subject row, not append"
        );
    }

    // -------------------- PUT — malformed subject digest (N-5) --------

    #[test]
    fn put_with_malformed_subject_digest_returns_400_manifest_invalid_pre_ingest() {
        // Subject digest pre-validation runs BEFORE manifest ingest.
        // A malformed `subject.digest` must surface as 400
        // MANIFEST_INVALID with no state change — no manifest artifact
        // committed, no group attached, no content_references row
        // inserted. (Previously this was a 500 returned at the tail of
        // the handler, after the manifest had already been committed,
        // leaving a half-attached state.)
        let (status, body, manifest_present, content_ref_count, lifecycle_commits) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");

            // Construct a manifest body whose subject.digest is a
            // syntactically broken string (no algorithm prefix).
            let body = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": "application/vnd.example.test",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": format!("sha256:{}", config_hash.as_ref()),
                    "size": 0,
                },
                "layers": [],
                "subject": {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "this-is-not-a-valid-digest",
                    "size": 0,
                },
            });
            let body_bytes = serde_json::to_vec(&body).unwrap();
            let manifest_hex = format!("{:x}", Sha256::digest(&body_bytes));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body_bytes)).await.unwrap();
            let status = resp.status();
            let resp_body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();

            // The manifest artifact must NOT be committed — pre-ingest
            // validation rejected the request.
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let manifest_present = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap()
                .is_some();
            let content_ref_count = h.content_references.entry_count();
            let lifecycle_commits = h.lifecycle.committed_transitions().len();
            (
                status,
                resp_body,
                manifest_present,
                content_ref_count,
                lifecycle_commits,
            )
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        let detail = &parsed["errors"][0]["detail"];
        assert_eq!(detail["field"], "subject.digest");
        assert!(
            !manifest_present,
            "malformed subject.digest must reject pre-ingest; manifest artifact must NOT land"
        );
        assert_eq!(
            content_ref_count, 0,
            "no content_references row may be inserted on the rejection path"
        );
        assert_eq!(
            lifecycle_commits, 0,
            "no ArtifactIngested event must be committed on the rejection path"
        );
    }

    #[test]
    fn put_with_unsupported_subject_digest_algo_returns_400_manifest_invalid() {
        // sha512 (or any non-sha256) on subject.digest is treated the
        // same as a malformed digest at this layer — rejected pre-
        // ingest with MANIFEST_INVALID + algorithm in the detail.
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");

            let body = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": format!("sha256:{}", config_hash.as_ref()),
                    "size": 0,
                },
                "layers": [],
                "subject": {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha512:{}", "f".repeat(128)),
                    "size": 0,
                },
            });
            let body_bytes = serde_json::to_vec(&body).unwrap();
            let router = router().with_state(h.ctx.clone());
            let resp = router
                .oneshot(put_request(
                    "/v2/myrepo/library/nginx/manifests/v1",
                    body_bytes,
                ))
                .await
                .unwrap();
            (
                resp.status(),
                to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec(),
            )
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        assert_eq!(parsed["errors"][0]["detail"]["field"], "subject.digest");
        assert_eq!(parsed["errors"][0]["detail"]["algorithm"], "sha512");
    }

    // -------------------- PUT — missing blob --------------------

    #[test]
    fn put_with_missing_blob_returns_400_manifest_blob_unknown() {
        let (status, body, group_count) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // Seed config but NOT the layer.
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_id, b"config-bytes");
            // Build a "missing" layer hash — never seeded.
            let missing_content = b"never-pushed-layer";
            let missing_hex = format!("{:x}", Sha256::digest(missing_content));
            let missing_hash: ContentHash = missing_hex.parse().unwrap();
            let body = build_manifest_json(&config_hash, &[missing_hash]);
            let manifest_hex = format!("{:x}", Sha256::digest(&body));

            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/myrepo/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            // Assert the manifest artifact IS committed — the client
            // retries after pushing the blob.
            let manifest_path = format!("manifests/sha256:{manifest_hex}");
            let found = h
                .artifacts
                .find_by_path(repo_id, &manifest_path)
                .await
                .unwrap();
            assert!(
                found.is_some(),
                "manifest artifact must persist so client retry reconciles"
            );
            // Group must NOT have been created.
            let group_count = h.group_lifecycle.commit_call_count();
            (status, body, group_count)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
        let blobs = parsed["errors"][0]["detail"]["blobs"].as_array().unwrap();
        assert_eq!(blobs.len(), 1);
        assert!(
            blobs[0].as_str().unwrap().starts_with("sha256:"),
            "blobs detail must echo raw sha256:<hex> shape"
        );
        assert_eq!(
            group_count, 0,
            "group must NOT be created on missing-blob path"
        );
    }

    #[test]
    fn put_with_foreign_repo_blob_digest_returns_400_manifest_blob_unknown() {
        // Cross-repo isolation: a blob that exists in repo_B is
        // invisible to repo_A's manifest push. The handler must
        // treat the hit as missing and surface MANIFEST_BLOB_UNKNOWN.
        let status = run(async {
            let h = harness();
            let repo_a = oci_repo("repo-a");
            let repo_b = oci_repo("repo-b");
            let repo_a_id = repo_a.id;
            let repo_b_id = repo_b.id;
            h.repositories.insert(repo_a);
            h.repositories.insert(repo_b);
            // Seed the config in repo_A.
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_a_id, b"config-bytes");
            // Seed the layer ONLY in repo_B.
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_b_id, b"layer-bytes");
            let body = build_manifest_json(&config_hash, &[layer_hash]);

            let router = router().with_state(h.ctx.clone());
            // PUT to repo_A — layer lives in repo_B and must count
            // as missing.
            let uri = "/v2/repo-a/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            resp.status()
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Blob resolution cross-repo isolation regression guard (ADR 0008).
    ///
    /// When the same SHA-256 lives in two repos, a cross-repo
    /// `find_by_checksum` followed by `repository_id == repo` post-filter
    /// returns rows in adapter-defined order — if the foreign-repo row
    /// comes first, the filter spuriously rejects a same-repo-present blob
    /// as `MANIFEST_BLOB_UNKNOWN`. The correct path routes through
    /// `ArtifactUseCase::find_in_repo_by_hash` which scopes the SQL
    /// query to the target repo at the port boundary.
    ///
    /// Test shape: seed identical SHA in repo_a (config + layer) AND
    /// repo_b (layer only — different artifact rows, same hash).
    /// Push the manifest to repo_a. Pre-fix outcome was probabilistic
    /// (depends on adapter ordering); post-fix outcome is always 201.
    #[test]
    fn put_with_same_sha_in_two_repos_resolves_to_target_repo_blob() {
        let (status, body) = run(async {
            let h = harness();

            let repo_a = oci_repo("repo-a");
            let repo_b = oci_repo("repo-b");
            let repo_a_id = repo_a.id;
            let repo_b_id = repo_b.id;
            h.repositories.insert(repo_a);
            h.repositories.insert(repo_b);

            // Seed the config + layer in repo_a (legitimate blobs the
            // manifest references).
            let config_hash = seed_blob(&h.artifacts, &h.storage, repo_a_id, b"config-bytes");
            let layer_hash = seed_blob(&h.artifacts, &h.storage, repo_a_id, b"layer-bytes");

            // Seed an additional row with the SAME layer SHA in
            // repo_b — different artifact id, identical content hash.
            // This is the scenario where pre-fix `find_by_checksum`
            // could return repo_b's row first and incorrectly reject
            // the manifest push to repo_a.
            let mut foreign = sample_artifact(QuarantineStatus::None);
            foreign.repository_id = repo_b_id;
            foreign.path = format!("blobs/sha256:{}", layer_hash.as_ref());
            foreign.sha256_checksum = layer_hash.clone();
            foreign.size_bytes = b"layer-bytes".len() as i64;
            h.artifacts.insert(foreign);

            let body = build_manifest_json(&config_hash, &[layer_hash]);
            let router = router().with_state(h.ctx.clone());
            let uri = "/v2/repo-a/library/nginx/manifests/v1";
            let resp = router.oneshot(put_request(uri, body)).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        // Post-fix: the use case scopes the SHA lookup to repo_a's id
        // at the port boundary, returns the right row, manifest is
        // accepted with 201 Created.
        assert_eq!(
            status,
            StatusCode::CREATED,
            "manifest PUT must succeed when its blobs are present in the target repo, \
             regardless of foreign-repo rows sharing the same SHA-256: body = {}",
            String::from_utf8_lossy(&body)
        );
    }

    // -------------------- PUT — unsupported content-type --------------------

    #[test]
    fn put_unsupported_content_type_returns_400_manifest_invalid() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            h.repositories.insert(repo);
            let router = router().with_state(h.ctx.clone());
            let req = with_principal(
                HttpRequest::put("/v2/myrepo/library/nginx/manifests/v1")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(b"{}".to_vec()))
                    .unwrap(),
            );
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
    }

    // -------------------- PUT — manifest index deferral --------------------

    #[test]
    fn put_manifest_index_returns_400_with_deferred_note() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            h.repositories.insert(repo);
            let router = router().with_state(h.ctx.clone());
            // Minimal valid index JSON — the handler rejects it
            // before full parse thanks to the media-type deferral.
            let index_body = serde_json::json!({
                "schemaVersion": 2,
                "manifests": []
            });
            let req = with_principal(
                HttpRequest::put("/v2/myrepo/library/nginx/manifests/v1")
                    .header(CONTENT_TYPE, "application/vnd.oci.image.index.v1+json")
                    .body(Body::from(serde_json::to_vec(&index_body).unwrap()))
                    .unwrap(),
            );
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_INVALID");
        // Spot-check the deferral reason surfaces in detail.
        let reason = parsed["errors"][0]["detail"]["reason"]
            .as_str()
            .unwrap_or_default();
        assert!(
            reason.contains("not yet supported") || reason.contains("manifest list"),
            "deferral reason must be explicit: {reason}"
        );
    }

    // -------------------- DELETE --------------------

    #[test]
    fn delete_tag_emits_ref_retired_and_returns_202() {
        let (status, post_count) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // Seed a tag ref pointing at some content hash.
            let hash: ContentHash =
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .parse()
                    .unwrap();
            h.refs.insert(MutableRef {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                namespace: "library/nginx".into(),
                ref_name: "v1".into(),
                target: RefTarget::ContentHash(hash),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });

            let router = router().with_state(h.ctx.clone());
            let req = with_principal(
                HttpRequest::delete("/v2/myrepo/library/nginx/manifests/v1")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            // The ref should have been retired (removed from the
            // registry mock).
            let post_count = h.refs.list(repo_id, "library/nginx").await.unwrap().len();
            (status, post_count)
        });
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(post_count, 0, "ref must be retired after DELETE");
    }

    /// INJ-4: a DELETE to an out-of-grammar tag is rejected 400
    /// `MANIFEST_INVALID` before the `RefUseCase::retire`. No ref is seeded,
    /// so an unvalidated path would 404 (`ManifestUnknown`) on the retire
    /// miss; the 400 with an `oci.tag:` reason proves the validator fired
    /// first. The response never echoes the offending bytes.
    #[test]
    fn delete_manifest_out_of_grammar_tag_rejected_400() {
        let over_cap = "a".repeat(129);
        let cases: [(&str, &str); 4] = [
            ("..", "double-dot path traversal"),
            (".leadingdot", "leading dot"),
            ("-leadinghyphen", "leading hyphen"),
            (&over_cap, "129-byte over-cap tag"),
        ];
        for (uri_tag, label) in cases {
            let (status, body) = run(async {
                let h = harness();
                h.repositories.insert(oci_repo("myrepo"));
                let router = router().with_state(h.ctx.clone());
                let uri = format!("/v2/myrepo/library/nginx/manifests/{uri_tag}");
                let req = with_principal(HttpRequest::delete(&uri).body(Body::empty()).unwrap());
                let resp = router.oneshot(req).await.unwrap();
                let status = resp.status();
                let rbody = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
                (status, rbody)
            });
            assert_eq!(status, StatusCode::BAD_REQUEST, "case: {label}");
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                parsed["errors"][0]["code"], "MANIFEST_INVALID",
                "case: {label}"
            );
            let reason = parsed["errors"][0]["detail"]["reason"]
                .as_str()
                .unwrap_or("");
            assert!(
                reason.starts_with("oci.tag: "),
                "case {label}: reason must be tagged `oci.tag:` ({reason})"
            );
        }
    }

    #[test]
    fn delete_digest_removes_artifact_and_content_references() {
        let (status, post_artifact, post_refs) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // Seed a manifest artifact at manifests/sha256:<hex>.
            let content = b"manifest-body-bytes";
            let hex = format!("{:x}", Sha256::digest(content));
            let hash: ContentHash = hex.parse().unwrap();
            let mut a = sample_artifact(QuarantineStatus::None);
            let artifact_id = a.id;
            a.repository_id = repo_id;
            a.path = format!("manifests/sha256:{hex}");
            a.sha256_checksum = hash.clone();
            a.size_bytes = content.len() as i64;
            h.artifacts.insert(a);
            h.storage.insert_content(hash.clone(), content.to_vec());

            // Seed two content_references rows with this artifact as source.
            h.content_references
                .insert(ContentReference {
                    source_artifact_id: artifact_id,
                    target_content_hash: "a".repeat(64).parse().unwrap(),
                    kind: "oci_subject".into(),
                    metadata: serde_json::Value::Null,
                    repository_id: repo_id,
                    recorded_at: Utc::now(),
                })
                .await
                .unwrap();

            let router = router().with_state(h.ctx.clone());
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let req = with_principal(HttpRequest::delete(&uri).body(Body::empty()).unwrap());
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();

            // After DELETE: artifact gone, content_references gone.
            let post_artifact = h
                .artifacts
                .find_by_path(repo_id, &format!("manifests/sha256:{hex}"))
                .await
                .unwrap();
            let post_refs = h.content_references.entry_count();
            (status, post_artifact, post_refs)
        });
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(
            post_artifact.is_none(),
            "artifact row must be deleted after digest DELETE"
        );
        assert_eq!(
            post_refs, 0,
            "content_references rows with this source must be swept"
        );
    }

    #[test]
    fn delete_unknown_tag_returns_404_manifest_unknown() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx.clone());
            let req = with_principal(
                HttpRequest::delete("/v2/myrepo/library/nginx/manifests/never-existed")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }

    #[test]
    fn delete_unknown_digest_returns_404_manifest_unknown() {
        let valid_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = router().with_state(h.ctx.clone());
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{valid_hex}");
            let req = with_principal(HttpRequest::delete(&uri).body(Body::empty()).unwrap());
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }

    // ---------------- Header-injection guard: created_manifest_response ----
    //
    // `created_manifest_response` used to call
    // `HeaderValue::from_str(&location).expect("ASCII by construction")`
    // on a string interpolating `repo_key` / `name` / `reference` from
    // URL captures. CRLF in any of the three would panic, axum would
    // catch the panic and emit a 500 — a DoS primitive. The fix
    // funnels the call through the shared helper that emits 404
    // NAME_UNKNOWN on the failure path.

    fn manifest_sample_hash() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    #[test]
    fn created_manifest_response_with_crlf_in_repo_key_returns_400_not_500() {
        let repo_key_with_crlf = "myrepo\r\nX-Injected: pwn";
        let resp = created_manifest_response(
            repo_key_with_crlf,
            "library/nginx",
            "v1",
            &manifest_sample_hash(),
        );
        assert_ne!(
            resp.status(),
            StatusCode::CREATED,
            "must NOT return 201 with a smuggled header"
        );
        assert_ne!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "must NOT degrade to 500 on URL-capture-induced HeaderValue failure"
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn created_manifest_response_with_clean_ascii_returns_201_with_location() {
        let resp =
            created_manifest_response("myrepo", "library/nginx", "v1", &manifest_sample_hash());
        assert_eq!(resp.status(), StatusCode::CREATED);
        let location = resp
            .headers()
            .get(LOCATION)
            .expect("Location header missing on happy path")
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(location, "/v2/myrepo/library/nginx/manifests/v1");
    }

    // -------------------- parse_manifest_blobs blob-count cap --------------------
    //
    // The 1 MiB body cap stops gross OOM but a manifest body can pack
    // ~10k pathologically dense entries within 1 MiB — each entry
    // triggers a `find_in_repo_by_hash` lookup in
    // `resolve_referenced_blobs`. Cap the blob-reference count at 1024
    // at parse time, before the lookup loop is entered.

    /// Build a manifest JSON with `n` distinct synthetic layer digests
    /// plus one config digest. Total referenced blobs = n + 1.
    /// Digests are unique-by-construction (the index is encoded into
    /// the hex), so the cap counts distinct entries, not deduplicated
    /// hashes.
    fn build_manifest_with_n_layers(n: usize) -> serde_json::Value {
        // Use a stable config hash and unique-per-index layer hashes.
        // 64 hex chars per digest; index encoded as 16-hex prefix.
        let config_digest = format!("sha256:{}", "c".repeat(64));
        let layers: Vec<serde_json::Value> = (0..n)
            .map(|i| {
                let hex = format!("{i:016x}{}", "0".repeat(48));
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": format!("sha256:{hex}"),
                    "size": 0,
                })
            })
            .collect();
        serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": 0,
            },
            "layers": layers,
        })
    }

    #[test]
    fn parse_manifest_blobs_accepts_1023_layers_plus_config() {
        // 1023 layers + 1 config = 1024 referenced blobs, exactly at
        // the cap. Must succeed.
        let manifest = build_manifest_with_n_layers(1023);
        let result = parse_manifest_blobs(&manifest);
        assert!(
            result.is_ok(),
            "1024 referenced blobs (1023 layers + 1 config) must be accepted; got {result:?}"
        );
        let blobs = result.unwrap();
        assert_eq!(blobs.len(), 1024, "must include config + 1023 layers");
    }

    #[test]
    fn parse_manifest_blobs_accepts_1024_layers_when_total_is_1025_fails() {
        // Sanity: 1024 layers + 1 config = 1025 referenced blobs,
        // exactly one over the cap. Must fail.
        let manifest = build_manifest_with_n_layers(1024);
        let result = parse_manifest_blobs(&manifest);
        assert!(
            result.is_err(),
            "1025 referenced blobs (1024 layers + 1 config) must be rejected; got {result:?}"
        );
        let detail = result.unwrap_err();
        let reason = detail
            .get("reason")
            .and_then(|v| v.as_str())
            .expect("error detail must carry `reason`");
        assert!(
            reason.contains("1025") && reason.contains("1024"),
            "reason must surface both the count and the cap; got {reason:?}"
        );
    }

    #[test]
    fn parse_manifest_blobs_rejects_2048_layers() {
        // Far over the cap — proves the check fires regardless of how
        // far over the manifest is.
        let manifest = build_manifest_with_n_layers(2048);
        let result = parse_manifest_blobs(&manifest);
        assert!(result.is_err(), "2049 referenced blobs must be rejected");
        let detail = result.unwrap_err();
        let reason = detail
            .get("reason")
            .and_then(|v| v.as_str())
            .expect("error detail must carry `reason`");
        assert!(
            reason.contains("2049") && reason.contains("1024"),
            "reason must report actual count 2049 and cap 1024; got {reason:?}"
        );
    }

    #[test]
    fn parse_manifest_blobs_small_manifest_unchanged() {
        // Existing happy path — small single-layer manifest stays
        // green. Regression guard: the cap must not interfere with
        // legitimate manifests.
        let manifest = build_manifest_with_n_layers(1);
        let blobs =
            parse_manifest_blobs(&manifest).expect("a single-layer manifest must parse cleanly");
        assert_eq!(blobs.len(), 2, "config + 1 layer = 2 referenced blobs");
    }

    // -------------------------------------------------------------
    // DeleteRepoAccess reclassification regression guard
    // -------------------------------------------------------------
    //
    // Each test drives a real handler under `AuthContext::Enabled`
    // with a tightly-scoped RBAC evaluator and asserts which
    // permission was consulted.
    //
    // Layout:
    //
    //   delete_manifest_dispatch + [read, write] (no delete) → 403
    //   delete_manifest_dispatch + [read, write, delete]     → 202
    //   delete_manifest_dispatch + [admin] (no grants)       → 202
    //   post_upload_dispatch     + [write]                   → 202
    //   put_upload_dispatch      + [write]                   → success
    //
    // The last two are the "stays Write" lock: they prove the upload
    // lifecycle endpoints did NOT get switched to DeleteRepoAccess
    // alongside the manifest-delete endpoint. (The OCI surface has no
    // dedicated cancel-upload handler today — DELETE on a
    // `/blobs/uploads/<uuid>` tail falls through `delete_manifest_dispatch`
    // and 404s at parse time. `post_upload_dispatch` substitutes for
    // cancel as the simplest upload-lifecycle WriteRepoAccess call site.)

    use hort_app::rbac::RbacEvaluator;
    use hort_app::use_cases::authenticate_use_case::AuthenticateUseCase;
    use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
    use hort_app::use_cases::test_support::{MockIdentityProvider, MockUserRepository};
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::rbac::{GrantSubject, Permission, PermissionGrant};
    use hort_domain::ports::identity_provider::IdentityProvider;
    use hort_domain::ports::user_repository::UserRepository;
    use hort_http_core::context::AuthContext;
    use hort_http_core::test_support::{with_auth, with_repository_access};

    /// Build an RBAC evaluator with explicit `(claim_name, permissions)`
    /// pairs scoped to `repo_id`. Uses the `GrantSubject::Claims` grant
    /// set (ADR 0012): a principal whose resolved `claims` contain
    /// `claim_name` matches. A claim with no permissions contributes no
    /// grants (the admin-shortcut test relies on this empty-evaluator
    /// shape).
    fn rbac_with_grants(
        repo_id: Uuid,
        claim_perms: &[(&str, &[Permission])],
    ) -> (RbacEvaluator, Arc<arc_swap::ArcSwap<RbacEvaluator>>) {
        let mut grants: Vec<PermissionGrant> = Vec::new();
        for (name, perms) in claim_perms {
            for p in *perms {
                grants.push(PermissionGrant {
                    id: Uuid::new_v4(),
                    subject: GrantSubject::Claims(vec![(*name).to_string()]),
                    repository_id: Some(repo_id),
                    permission: *p,
                    created_at: Utc::now(),
                    managed_by: ManagedBy::Local,
                    managed_by_digest: None,
                });
            }
        }
        let eval = RbacEvaluator::new(grants);
        let swap = Arc::new(arc_swap::ArcSwap::from_pointee(eval.clone()));
        (eval, swap)
    }

    /// Flip `h.ctx` to `AuthContext::Enabled` carrying the supplied
    /// RBAC evaluator and rebuild the matching `RepositoryAccessUseCase`
    /// so visibility checks downstream observe the same state.
    fn enable_auth_with_rbac(
        h: &Harness,
        rbac_swap: Arc<arc_swap::ArcSwap<RbacEvaluator>>,
    ) -> Arc<AppContext> {
        let idp = Arc::new(MockIdentityProvider::new());
        let users = Arc::new(MockUserRepository::new());
        let authenticate = Arc::new(AuthenticateUseCase::new(
            idp as Arc<dyn IdentityProvider>,
            users as Arc<dyn UserRepository>,
            Vec::new(),
        ));
        let ctx = with_auth(
            &h.ctx,
            AuthContext::Enabled {
                authenticate,
                rbac: rbac_swap.clone(),
                // Tests in this module do not exercise the WWW-Authenticate selector.
                issuer_url: None,
            },
        );
        let access = Arc::new(RepositoryAccessUseCase::new(
            h.repositories.clone(),
            RbacAccess::Enabled(rbac_swap),
            true,
        ));
        with_repository_access(&ctx, access)
    }

    /// Inject a principal carrying the resolved claim set `claims`
    /// into the request (ADR 0012). Mirrors what the
    /// `oci_bearer_auth` middleware does after JIT-resolving a token,
    /// minus the network bits.
    fn with_principal_claims(
        mut req: axum::http::Request<Body>,
        claims: &[&str],
    ) -> axum::http::Request<Body> {
        let mut p = test_principal();
        p.claims = claims.iter().map(|s| (*s).to_string()).collect();
        hort_http_core::middleware::auth::test_support::inject_principal(&mut req, p);
        req
    }

    /// Seed a manifest artifact at `manifests/sha256:<hex>`. Returns
    /// the digest string clients embed in the DELETE URL.
    fn seed_manifest_artifact(h: &Harness, repo_id: Uuid) -> String {
        let content = b"manifest-body-bytes";
        let hex = format!("{:x}", Sha256::digest(content));
        let hash: ContentHash = hex.parse().unwrap();
        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = repo_id;
        a.path = format!("manifests/sha256:{hex}");
        a.sha256_checksum = hash.clone();
        a.size_bytes = content.len() as i64;
        h.artifacts.insert(a);
        h.storage.insert_content(hash, content.to_vec());
        hex
    }

    // ---- delete_manifest_dispatch reclassification ----

    /// Reclassification row: `DELETE /v2/<name>/manifests/<ref>` with
    /// `[read, write]` (no `delete`) MUST 403. Previously the same
    /// principal would have authorised because the handler keyed off
    /// `Permission::Write`. The 403 is the lock that the switch to
    /// `DeleteRepoAccess` actually happened in production code.
    #[test]
    fn reclassify_delete_manifest_with_write_only_returns_403() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let hex = seed_manifest_artifact(&h, repo_id);

            let (_eval, swap) =
                rbac_with_grants(repo_id, &[("dev", &[Permission::Read, Permission::Write])]);
            let ctx = enable_auth_with_rbac(&h, swap);

            let router = router().with_state(ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let req = with_principal_claims(
                HttpRequest::delete(&uri).body(Body::empty()).unwrap(),
                &["dev"],
            );
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "principal with [read, write] but no `delete` grant must be denied"
        );
    }

    /// Reclassification row: `DELETE /v2/<name>/manifests/<ref>` with
    /// `[read, write, delete]` MUST succeed. Pairs with the 403 test
    /// above to lock the boundary at exactly `Permission::Delete`
    /// rather than at any of the broader permissions.
    #[test]
    fn reclassify_delete_manifest_with_delete_grant_returns_202() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let hex = seed_manifest_artifact(&h, repo_id);

            let (_eval, swap) = rbac_with_grants(
                repo_id,
                &[(
                    "deleter",
                    &[Permission::Read, Permission::Write, Permission::Delete],
                )],
            );
            let ctx = enable_auth_with_rbac(&h, swap);

            let router = router().with_state(ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let req = with_principal_claims(
                HttpRequest::delete(&uri).body(Body::empty()).unwrap(),
                &["deleter"],
            );
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "principal with explicit `delete` grant must succeed at manifest delete"
        );
    }

    /// Reclassification row + admin-shortcut lock: an `admin` role
    /// without any explicit `permission_grants` rows succeeds at the
    /// manifest-delete endpoint via the role-name short-circuit in
    /// `RbacEvaluator::authorize` (rbac.rs:104). This pins the
    /// admin role short-circuits without an explicit `delete` grant —
    /// operators do NOT need to add a parallel `delete` grant for
    /// admin roles.
    #[test]
    fn reclassify_delete_manifest_admin_role_short_circuits_without_explicit_grant() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let hex = seed_manifest_artifact(&h, repo_id);

            // EMPTY evaluator — no grants. The admin short-circuit
            // (`claims.contains("admin")`, ADR 0012) ignores it.
            let swap = Arc::new(arc_swap::ArcSwap::from_pointee(RbacEvaluator::new(
                Vec::new(),
            )));
            let ctx = enable_auth_with_rbac(&h, swap);

            let router = router().with_state(ctx);
            let uri = format!("/v2/myrepo/library/nginx/manifests/sha256:{hex}");
            let req = with_principal_claims(
                HttpRequest::delete(&uri).body(Body::empty()).unwrap(),
                &["admin"],
            );
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "admin role bypasses per-permission grants — no explicit delete grant needed"
        );
        // Also assert there's no implicit `_repo_id` warning; the
        // path consumes its own repo_id parameter.
    }

    // ---- "stays Write" reclassification rows ----
    //
    // Drive the upload-lifecycle handlers with a `[write]`-only
    // principal to prove they did NOT get switched to
    // `DeleteRepoAccess` alongside the manifest-delete endpoint.
    // Both paths route through the upload router defined in
    // `super::uploads::router`.

    /// Reclassification row: `POST /v2/<name>/blobs/uploads/`
    /// (initiate) MUST stay `WriteRepoAccess`. A write-only
    /// principal succeeds. Substitute for the cancel-upload row in
    /// the design-doc table — the OCI surface has no dedicated
    /// cancel handler today, so the simplest upload-lifecycle write
    /// op locks the same "stays Write" decision.
    #[test]
    fn reclassify_post_upload_initiate_with_write_only_stays_write_and_succeeds() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);

            let (_eval, swap) = rbac_with_grants(repo_id, &[("dev", &[Permission::Write])]);
            let ctx = enable_auth_with_rbac(&h, swap);

            let router = super::super::uploads::router().with_state(ctx);
            let req = with_principal_claims(
                HttpRequest::post("/v2/myrepo/library/nginx/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
                &["dev"],
            );
            router.oneshot(req).await.unwrap().status()
        });
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "write-only principal must initiate uploads — POST stays WriteRepoAccess"
        );
    }

    /// Reclassification row: `PUT /v2/<name>/blobs/uploads/<uuid>?digest=…`
    /// (finalize) MUST stay `WriteRepoAccess`. A write-only principal
    /// satisfies the extractor; the request fails downstream at the
    /// missing-session lookup with a 404 `BLOB_UPLOAD_UNKNOWN`, NOT a
    /// 403 — proving the authz step admitted the caller.
    ///
    /// We don't seed a real session because the goal is to assert
    /// the extractor decision, not the finalize semantics. A 403
    /// here would mean the wrong extractor wired in.
    #[test]
    fn reclassify_put_upload_finalize_with_write_only_stays_write_and_passes_authz() {
        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);

            let (_eval, swap) = rbac_with_grants(repo_id, &[("dev", &[Permission::Write])]);
            let ctx = enable_auth_with_rbac(&h, swap);

            let router = super::super::uploads::router().with_state(ctx);
            // A random session UUID — no session exists, the finalize
            // path will reject downstream. The extractor decision
            // happens FIRST; if it returned 403 we'd see 403 here.
            let session_id = Uuid::new_v4();
            let valid_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            let uri = format!(
                "/v2/myrepo/library/nginx/blobs/uploads/{session_id}?digest=sha256:{valid_hex}"
            );
            let req = with_principal_claims(
                HttpRequest::put(&uri)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .body(Body::empty())
                    .unwrap(),
                &["dev"],
            );
            router.oneshot(req).await.unwrap().status()
        });
        // Anything OTHER than 403 means the WriteRepoAccess
        // extractor admitted the principal — that's the "stays
        // Write" lock. The downstream finalize logic is free to
        // reject for any other reason (404 BLOB_UPLOAD_UNKNOWN is
        // the most likely).
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "PUT-finalize must stay WriteRepoAccess — write-only principal must NOT be denied"
        );
    }
}
